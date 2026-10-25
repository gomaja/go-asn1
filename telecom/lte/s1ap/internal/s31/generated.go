// Code generated from the pinned S1AP source closure. DO NOT EDIT.

// Package s31 implements the github.com/gomaja/go-asn1/telecom/lte/s1ap root package.
package s31

import (
	fmt "fmt"
	s00 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s00"
	s01 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s01"
	s02 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s02"
	s06 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s06"
	s07 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s07"
	s08 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s08"
	s11 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s11"
	s13 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s13"
	s14 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s14"
	s15 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s15"
	s17 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s17"
	s18 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s18"
	s20 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s20"
	s21 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s21"
	s24 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s24"
	s26 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s26"
	s27 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s27"
	s28 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s28"
	s30 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s30"
	runtime "github.com/gomaja/go-asn1/telecom/lte/s1ap/runtime"
	aper "github.com/gomaja/go-asn1/telecom/lte/s1ap/runtime/aper"
)

// LocationReportIEContainer is the concrete ProtocolIEContainer[LocationReportIEValue].
type LocationReportIEContainer []LocationReportIEField

// LocationReportIEField is the concrete ProtocolIEField[LocationReportIEValue].
type LocationReportIEField struct {
	withoutReplay bool
	replay        aper.Snapshot
	stream        aper.WireSpan
	Id            s00.ProtocolIEID
	Criticality   s00.Criticality
	Value         LocationReportIEValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v LocationReportIEField) WithoutReplay() LocationReportIEField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *LocationReportIEField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *LocationReportIEField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
func (v *LocationReportIEField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolIEField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = LocationReportIEField{}
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
	var zero LocationReportIEValue

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

// UEInformationTransferIEContainer is the concrete ProtocolIEContainer[UEInformationTransferIEValue].
type UEInformationTransferIEContainer []UEInformationTransferIEField

// UEInformationTransferIEField is the concrete ProtocolIEField[UEInformationTransferIEValue].
type UEInformationTransferIEField struct {
	withoutReplay bool
	replay        aper.Snapshot
	stream        aper.WireSpan
	Id            s00.ProtocolIEID
	Criticality   s00.Criticality
	Value         UEInformationTransferIEValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v UEInformationTransferIEField) WithoutReplay() UEInformationTransferIEField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *UEInformationTransferIEField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *UEInformationTransferIEField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
func (v *UEInformationTransferIEField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolIEField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = UEInformationTransferIEField{}
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
	var zero UEInformationTransferIEValue

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
func BridgeConnectionEstablishmentIndicationIEValueCaptureS1APProtocolIEContainer(v *s30.ConnectionEstablishmentIndicationIEContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeConnectionEstablishmentIndicationIEValueCaptureS1APProtocolIEField(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeConnectionEstablishmentIndicationIEValueCompareS1APProtocolIEContainer(v *s30.ConnectionEstablishmentIndicationIEContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeConnectionEstablishmentIndicationIEValueCompareS1APProtocolIEField(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeSupportedTAsItemExtIEsValueCaptureS1APProtocolExtensionContainer(v *s11.SupportedTAsItemExtIEsExtContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeSupportedTAsItemExtIEsValueCaptureS1APProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeSupportedTAsItemExtIEsValueCompareS1APProtocolExtensionContainer(v *s11.SupportedTAsItemExtIEsExtContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeSupportedTAsItemExtIEsValueCompareS1APProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeSynchronisationInformationExtIEsValueCaptureS1APProtocolExtensionContainer(v *s11.SynchronisationInformationExtIEsExtContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeSynchronisationInformationExtIEsValueCaptureS1APProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeSynchronisationInformationExtIEsValueCompareS1APProtocolExtensionContainer(v *s11.SynchronisationInformationExtIEsExtContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeSynchronisationInformationExtIEsValueCompareS1APProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeTABasedMDTExtIEsValueCaptureS1APProtocolExtensionContainer(v *s11.TABasedMDTExtIEsExtContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeTABasedMDTExtIEsValueCaptureS1APProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeTABasedMDTExtIEsValueCompareS1APProtocolExtensionContainer(v *s11.TABasedMDTExtIEsExtContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeTABasedMDTExtIEsValueCompareS1APProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeTABasedQMCExtIEsValueCaptureS1APProtocolExtensionContainer(v *s11.TABasedQMCExtIEsExtContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeTABasedQMCExtIEsValueCaptureS1APProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeTABasedQMCExtIEsValueCompareS1APProtocolExtensionContainer(v *s11.TABasedQMCExtIEsExtContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeTABasedQMCExtIEsValueCompareS1APProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeTAIExtIEsValueCaptureS1APProtocolExtensionContainer(v *s11.TAIExtIEsExtContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeTAIExtIEsValueCaptureS1APProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeTAIExtIEsValueCompareS1APProtocolExtensionContainer(v *s11.TAIExtIEsExtContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeTAIExtIEsValueCompareS1APProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeTAIBasedMDTExtIEsValueCaptureS1APProtocolExtensionContainer(v *s11.TAIBasedMDTExtIEsExtContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeTAIBasedMDTExtIEsValueCaptureS1APProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeTAIBasedMDTExtIEsValueCompareS1APProtocolExtensionContainer(v *s11.TAIBasedMDTExtIEsExtContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeTAIBasedMDTExtIEsValueCompareS1APProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeTAIBasedQMCExtIEsValueCaptureS1APProtocolExtensionContainer(v *s11.TAIBasedQMCExtIEsExtContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeTAIBasedQMCExtIEsValueCaptureS1APProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeTAIBasedQMCExtIEsValueCompareS1APProtocolExtensionContainer(v *s11.TAIBasedQMCExtIEsExtContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeTAIBasedQMCExtIEsValueCompareS1APProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeTAIBroadcastItemExtIEsValueCaptureS1APProtocolExtensionContainer(v *s11.TAIBroadcastItemExtIEsExtContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeTAIBroadcastItemExtIEsValueCaptureS1APProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeTAIBroadcastItemExtIEsValueCompareS1APProtocolExtensionContainer(v *s11.TAIBroadcastItemExtIEsExtContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeTAIBroadcastItemExtIEsValueCompareS1APProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeTAICancelledItemExtIEsValueCaptureS1APProtocolExtensionContainer(v *s11.TAICancelledItemExtIEsExtContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeTAICancelledItemExtIEsValueCaptureS1APProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeTAICancelledItemExtIEsValueCompareS1APProtocolExtensionContainer(v *s11.TAICancelledItemExtIEsExtContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeTAICancelledItemExtIEsValueCompareS1APProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}

// SynchronisationInformationValueCodec is the concrete ValueCodec[SynchronisationInformation].
type SynchronisationInformationValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (SynchronisationInformation,

		error)
	encode func(SynchronisationInformation,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(SynchronisationInformation, aper.DecodeState,

	) (SynchronisationInformation, aper.Snapshot,

	)
	compare func(SynchronisationInformation, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c SynchronisationInformationValueCodec) New(value SynchronisationInformation,

) (SynchronisationInformationAPERValue, error) {
	if c.encode == nil {
		return SynchronisationInformationAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return SynchronisationInformationAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return SynchronisationInformationAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return SynchronisationInformationAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c SynchronisationInformationValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (SynchronisationInformationAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return SynchronisationInformationAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return SynchronisationInformationAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return SynchronisationInformationAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return SynchronisationInformationAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c SynchronisationInformationValueCodec) EncodeAPER(value SynchronisationInformationAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c SynchronisationInformationValueCodec) encodeBudgetValue(value SynchronisationInformation,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c SynchronisationInformationValueCodec) encodeChanged(value SynchronisationInformation,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ConnectionEstablishmentIndicationMMEUES1APIDIEBinding is the concrete IEBinding[MMEUES1APID, ConnectionEstablishmentIndicationIEValue].
type ConnectionEstablishmentIndicationMMEUES1APIDIEBinding struct {
	info   s00.FieldInfo
	codec  s01.MMEUES1APIDValueCodec
	inject func(s00.MMEUES1APID,

	) s30.ConnectionEstablishmentIndicationIEValue

	get func(*s30.ConnectionEstablishmentIndicationIEValue,

	) (*s00.MMEUES1APID,

		bool)
}

// Info returns the source descriptor for this binding.
func (b ConnectionEstablishmentIndicationMMEUES1APIDIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b ConnectionEstablishmentIndicationMMEUES1APIDIEBinding) Codec() s01.MMEUES1APIDValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b ConnectionEstablishmentIndicationMMEUES1APIDIEBinding) New(value s00.MMEUES1APID,

) (s30.ConnectionEstablishmentIndicationIEField, error) {
	if b.inject == nil {
		return s30.ConnectionEstablishmentIndicationIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return s30.ConnectionEstablishmentIndicationIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s01.BridgeMMEUES1APIDValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return s30.ConnectionEstablishmentIndicationIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return s30.ConnectionEstablishmentIndicationIEField{}, aper.OperationError(err, "Value.New")
	}
	return s30.ConnectionEstablishmentIndicationIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b ConnectionEstablishmentIndicationMMEUES1APIDIEBinding) Get(field *s30.ConnectionEstablishmentIndicationIEField) (*s00.MMEUES1APID,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// ConnectionEstablishmentIndicationUERadioCapabilityIEBinding is the concrete IEBinding[UERadioCapability, ConnectionEstablishmentIndicationIEValue].
type ConnectionEstablishmentIndicationUERadioCapabilityIEBinding struct {
	info   s00.FieldInfo
	codec  s02.UERadioCapabilityValueCodec
	inject func(s00.UERadioCapability,

	) s30.ConnectionEstablishmentIndicationIEValue

	get func(*s30.ConnectionEstablishmentIndicationIEValue,

	) (*s00.UERadioCapability,

		bool)
}

// Info returns the source descriptor for this binding.
func (b ConnectionEstablishmentIndicationUERadioCapabilityIEBinding) Info() s00.FieldInfo {
	return b.info
}

// Codec returns the complete value codec for this binding.
func (b ConnectionEstablishmentIndicationUERadioCapabilityIEBinding) Codec() s02.UERadioCapabilityValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b ConnectionEstablishmentIndicationUERadioCapabilityIEBinding) New(value s00.UERadioCapability,

) (s30.ConnectionEstablishmentIndicationIEField, error) {
	if b.inject == nil {
		return s30.ConnectionEstablishmentIndicationIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return s30.ConnectionEstablishmentIndicationIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s02.BridgeUERadioCapabilityValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return s30.ConnectionEstablishmentIndicationIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return s30.ConnectionEstablishmentIndicationIEField{}, aper.OperationError(err, "Value.New")
	}
	return s30.ConnectionEstablishmentIndicationIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b ConnectionEstablishmentIndicationUERadioCapabilityIEBinding) Get(field *s30.ConnectionEstablishmentIndicationIEField) (*s00.UERadioCapability,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// ConnectionEstablishmentIndicationSubscriptionBasedUEDifferentiationInfoIEBinding is the concrete IEBinding[SubscriptionBasedUEDifferentiationInfo, ConnectionEstablishmentIndicationIEValue].
type ConnectionEstablishmentIndicationSubscriptionBasedUEDifferentiationInfoIEBinding struct {
	info   s00.FieldInfo
	codec  SubscriptionBasedUEDifferentiationInfoValueCodec
	inject func(s30.SubscriptionBasedUEDifferentiationInfo,

	) s30.ConnectionEstablishmentIndicationIEValue

	get func(*s30.ConnectionEstablishmentIndicationIEValue,

	) (*s30.SubscriptionBasedUEDifferentiationInfo,

		bool)
}

// Info returns the source descriptor for this binding.
func (b ConnectionEstablishmentIndicationSubscriptionBasedUEDifferentiationInfoIEBinding) Info() s00.FieldInfo {
	return b.info
}

// Codec returns the complete value codec for this binding.
func (b ConnectionEstablishmentIndicationSubscriptionBasedUEDifferentiationInfoIEBinding) Codec() SubscriptionBasedUEDifferentiationInfoValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b ConnectionEstablishmentIndicationSubscriptionBasedUEDifferentiationInfoIEBinding) New(value s30.SubscriptionBasedUEDifferentiationInfo,

) (s30.ConnectionEstablishmentIndicationIEField, error) {
	if b.inject == nil {
		return s30.ConnectionEstablishmentIndicationIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return s30.ConnectionEstablishmentIndicationIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := b.codec.encode(value, false, budget); err != nil {
		return s30.ConnectionEstablishmentIndicationIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return s30.ConnectionEstablishmentIndicationIEField{}, aper.OperationError(err, "Value.New")
	}
	return s30.ConnectionEstablishmentIndicationIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b ConnectionEstablishmentIndicationSubscriptionBasedUEDifferentiationInfoIEBinding) Get(field *s30.ConnectionEstablishmentIndicationIEField) (*s30.SubscriptionBasedUEDifferentiationInfo,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// SubscriptionBasedUEDifferentiationInfoValueCodec is the concrete ValueCodec[SubscriptionBasedUEDifferentiationInfo].
type SubscriptionBasedUEDifferentiationInfoValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (s30.SubscriptionBasedUEDifferentiationInfo,

		error)
	encode func(s30.SubscriptionBasedUEDifferentiationInfo,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(s30.SubscriptionBasedUEDifferentiationInfo, aper.DecodeState,

	) (s30.SubscriptionBasedUEDifferentiationInfo, aper.Snapshot,

	)
	compare func(s30.SubscriptionBasedUEDifferentiationInfo, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c SubscriptionBasedUEDifferentiationInfoValueCodec) New(value s30.SubscriptionBasedUEDifferentiationInfo,

) (SubscriptionBasedUEDifferentiationInfoAPERValue, error) {
	if c.encode == nil {
		return SubscriptionBasedUEDifferentiationInfoAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return SubscriptionBasedUEDifferentiationInfoAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return SubscriptionBasedUEDifferentiationInfoAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return SubscriptionBasedUEDifferentiationInfoAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c SubscriptionBasedUEDifferentiationInfoValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (SubscriptionBasedUEDifferentiationInfoAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return SubscriptionBasedUEDifferentiationInfoAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return SubscriptionBasedUEDifferentiationInfoAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return SubscriptionBasedUEDifferentiationInfoAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return SubscriptionBasedUEDifferentiationInfoAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c SubscriptionBasedUEDifferentiationInfoValueCodec) EncodeAPER(value SubscriptionBasedUEDifferentiationInfoAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c SubscriptionBasedUEDifferentiationInfoValueCodec) encodeBudgetValue(value s30.SubscriptionBasedUEDifferentiationInfo,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c SubscriptionBasedUEDifferentiationInfoValueCodec) encodeChanged(value s30.SubscriptionBasedUEDifferentiationInfo,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ConnectionEstablishmentIndicationUERadioCapabilityIDIEBinding is the concrete IEBinding[UERadioCapabilityID, ConnectionEstablishmentIndicationIEValue].
type ConnectionEstablishmentIndicationUERadioCapabilityIDIEBinding struct {
	info   s00.FieldInfo
	codec  s02.UERadioCapabilityIDValueCodec
	inject func(s00.UERadioCapabilityID,

	) s30.ConnectionEstablishmentIndicationIEValue

	get func(*s30.ConnectionEstablishmentIndicationIEValue,

	) (*s00.UERadioCapabilityID,

		bool)
}

// Info returns the source descriptor for this binding.
func (b ConnectionEstablishmentIndicationUERadioCapabilityIDIEBinding) Info() s00.FieldInfo {
	return b.info
}

// Codec returns the complete value codec for this binding.
func (b ConnectionEstablishmentIndicationUERadioCapabilityIDIEBinding) Codec() s02.UERadioCapabilityIDValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b ConnectionEstablishmentIndicationUERadioCapabilityIDIEBinding) New(value s00.UERadioCapabilityID,

) (s30.ConnectionEstablishmentIndicationIEField, error) {
	if b.inject == nil {
		return s30.ConnectionEstablishmentIndicationIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return s30.ConnectionEstablishmentIndicationIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s02.BridgeUERadioCapabilityIDValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return s30.ConnectionEstablishmentIndicationIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return s30.ConnectionEstablishmentIndicationIEField{}, aper.OperationError(err, "Value.New")
	}
	return s30.ConnectionEstablishmentIndicationIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b ConnectionEstablishmentIndicationUERadioCapabilityIDIEBinding) Get(field *s30.ConnectionEstablishmentIndicationIEField) (*s00.UERadioCapabilityID,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// ConnectionEstablishmentIndicationMaskedIMEISVIEBinding is the concrete IEBinding[MaskedIMEISV, ConnectionEstablishmentIndicationIEValue].
type ConnectionEstablishmentIndicationMaskedIMEISVIEBinding struct {
	info   s00.FieldInfo
	codec  s01.MaskedIMEISVValueCodec
	inject func(s00.MaskedIMEISV,

	) s30.ConnectionEstablishmentIndicationIEValue

	get func(*s30.ConnectionEstablishmentIndicationIEValue,

	) (*s00.MaskedIMEISV,

		bool)
}

// Info returns the source descriptor for this binding.
func (b ConnectionEstablishmentIndicationMaskedIMEISVIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b ConnectionEstablishmentIndicationMaskedIMEISVIEBinding) Codec() s01.MaskedIMEISVValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b ConnectionEstablishmentIndicationMaskedIMEISVIEBinding) New(value s00.MaskedIMEISV,

) (s30.ConnectionEstablishmentIndicationIEField, error) {
	if b.inject == nil {
		return s30.ConnectionEstablishmentIndicationIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return s30.ConnectionEstablishmentIndicationIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s01.BridgeMaskedIMEISVValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return s30.ConnectionEstablishmentIndicationIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return s30.ConnectionEstablishmentIndicationIEField{}, aper.OperationError(err, "Value.New")
	}
	return s30.ConnectionEstablishmentIndicationIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b ConnectionEstablishmentIndicationMaskedIMEISVIEBinding) Get(field *s30.ConnectionEstablishmentIndicationIEField) (*s00.MaskedIMEISV,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// SupportedTAsValueCodec is the concrete ValueCodec[SupportedTAs].
type SupportedTAsValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (SupportedTAs,

		error)
	encode func(SupportedTAs,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(SupportedTAs, aper.DecodeState,

	) (SupportedTAs, aper.Snapshot,

	)
	compare func(SupportedTAs, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c SupportedTAsValueCodec) New(value SupportedTAs,

) (SupportedTAsAPERValue, error) {
	if c.encode == nil {
		return SupportedTAsAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return SupportedTAsAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return SupportedTAsAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return SupportedTAsAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c SupportedTAsValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (SupportedTAsAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return SupportedTAsAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return SupportedTAsAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return SupportedTAsAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return SupportedTAsAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c SupportedTAsValueCodec) EncodeAPER(value SupportedTAsAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c SupportedTAsValueCodec) encodeBudgetValue(value SupportedTAs,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c SupportedTAsValueCodec) encodeChanged(value SupportedTAs,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ConnectedengNBListValueCodec is the concrete ValueCodec[ConnectedengNBList].
type ConnectedengNBListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ConnectedengNBList,

		error)
	encode func(ConnectedengNBList,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ConnectedengNBList, aper.DecodeState,

	) (ConnectedengNBList, aper.Snapshot,

	)
	compare func(ConnectedengNBList, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ConnectedengNBListValueCodec) New(value ConnectedengNBList,

) (ConnectedengNBListAPERValue, error) {
	if c.encode == nil {
		return ConnectedengNBListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ConnectedengNBListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ConnectedengNBListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ConnectedengNBListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ConnectedengNBListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ConnectedengNBListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ConnectedengNBListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ConnectedengNBListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ConnectedengNBListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ConnectedengNBListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ConnectedengNBListValueCodec) EncodeAPER(value ConnectedengNBListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c ConnectedengNBListValueCodec) encodeBudgetValue(value ConnectedengNBList,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ConnectedengNBListValueCodec) encodeChanged(value ConnectedengNBList,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// LocationReportMMEUES1APIDIEBinding is the concrete IEBinding[MMEUES1APID, LocationReportIEValue].
type LocationReportMMEUES1APIDIEBinding struct {
	info   s00.FieldInfo
	codec  s01.MMEUES1APIDValueCodec
	inject func(s00.MMEUES1APID,

	) LocationReportIEValue

	get func(*LocationReportIEValue,

	) (*s00.MMEUES1APID,

		bool)
}

// Info returns the source descriptor for this binding.
func (b LocationReportMMEUES1APIDIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b LocationReportMMEUES1APIDIEBinding) Codec() s01.MMEUES1APIDValueCodec { return b.codec }

// New validates a source value and constructs its bound field.
func (b LocationReportMMEUES1APIDIEBinding) New(value s00.MMEUES1APID,

) (LocationReportIEField, error) {
	if b.inject == nil {
		return LocationReportIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return LocationReportIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s01.BridgeMMEUES1APIDValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return LocationReportIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return LocationReportIEField{}, aper.OperationError(err, "Value.New")
	}
	return LocationReportIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b LocationReportMMEUES1APIDIEBinding) Get(field *LocationReportIEField) (*s00.MMEUES1APID,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// LocationReportENBUES1APIDIEBinding is the concrete IEBinding[ENBUES1APID, LocationReportIEValue].
type LocationReportENBUES1APIDIEBinding struct {
	info   s00.FieldInfo
	codec  s00.ENBUES1APIDValueCodec
	inject func(s00.ENBUES1APID,

	) LocationReportIEValue

	get func(*LocationReportIEValue,

	) (*s00.ENBUES1APID,

		bool)
}

// Info returns the source descriptor for this binding.
func (b LocationReportENBUES1APIDIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b LocationReportENBUES1APIDIEBinding) Codec() s00.ENBUES1APIDValueCodec { return b.codec }

// New validates a source value and constructs its bound field.
func (b LocationReportENBUES1APIDIEBinding) New(value s00.ENBUES1APID,

) (LocationReportIEField, error) {
	if b.inject == nil {
		return LocationReportIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return LocationReportIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s00.BridgeENBUES1APIDValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return LocationReportIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return LocationReportIEField{}, aper.OperationError(err, "Value.New")
	}
	return LocationReportIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b LocationReportENBUES1APIDIEBinding) Get(field *LocationReportIEField) (*s00.ENBUES1APID,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// LocationReportEUTRANCGIIEBinding is the concrete IEBinding[EUTRANCGI, LocationReportIEValue].
type LocationReportEUTRANCGIIEBinding struct {
	info   s00.FieldInfo
	codec  s17.EUTRANCGIValueCodec
	inject func(s17.EUTRANCGI,

	) LocationReportIEValue

	get func(*LocationReportIEValue,

	) (*s17.EUTRANCGI,

		bool)
}

// Info returns the source descriptor for this binding.
func (b LocationReportEUTRANCGIIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b LocationReportEUTRANCGIIEBinding) Codec() s17.EUTRANCGIValueCodec { return b.codec }

// New validates a source value and constructs its bound field.
func (b LocationReportEUTRANCGIIEBinding) New(value s17.EUTRANCGI,

) (LocationReportIEField, error) {
	if b.inject == nil {
		return LocationReportIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return LocationReportIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s17.BridgeEUTRANCGIValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return LocationReportIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return LocationReportIEField{}, aper.OperationError(err, "Value.New")
	}
	return LocationReportIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b LocationReportEUTRANCGIIEBinding) Get(field *LocationReportIEField) (*s17.EUTRANCGI,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// LocationReportRequestTypeIEBinding is the concrete IEBinding[RequestType, LocationReportIEValue].
type LocationReportRequestTypeIEBinding struct {
	info   s00.FieldInfo
	codec  s26.RequestTypeValueCodec
	inject func(s26.RequestType,

	) LocationReportIEValue

	get func(*LocationReportIEValue,

	) (*s26.RequestType,

		bool)
}

// Info returns the source descriptor for this binding.
func (b LocationReportRequestTypeIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b LocationReportRequestTypeIEBinding) Codec() s26.RequestTypeValueCodec { return b.codec }

// New validates a source value and constructs its bound field.
func (b LocationReportRequestTypeIEBinding) New(value s26.RequestType,

) (LocationReportIEField, error) {
	if b.inject == nil {
		return LocationReportIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return LocationReportIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s26.BridgeRequestTypeValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return LocationReportIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return LocationReportIEField{}, aper.OperationError(err, "Value.New")
	}
	return LocationReportIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b LocationReportRequestTypeIEBinding) Get(field *LocationReportIEField) (*s26.RequestType,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// LocationReportPSCellInformationIEBinding is the concrete IEBinding[PSCellInformation, LocationReportIEValue].
type LocationReportPSCellInformationIEBinding struct {
	info   s00.FieldInfo
	codec  s20.PSCellInformationValueCodec
	inject func(s20.PSCellInformation,

	) LocationReportIEValue

	get func(*LocationReportIEValue,

	) (*s20.PSCellInformation,

		bool)
}

// Info returns the source descriptor for this binding.
func (b LocationReportPSCellInformationIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b LocationReportPSCellInformationIEBinding) Codec() s20.PSCellInformationValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b LocationReportPSCellInformationIEBinding) New(value s20.PSCellInformation,

) (LocationReportIEField, error) {
	if b.inject == nil {
		return LocationReportIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return LocationReportIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s20.BridgePSCellInformationValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return LocationReportIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return LocationReportIEField{}, aper.OperationError(err, "Value.New")
	}
	return LocationReportIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b LocationReportPSCellInformationIEBinding) Get(field *LocationReportIEField) (*s20.PSCellInformation,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// LocationReportLTENTNTAIInformationIEBinding is the concrete IEBinding[LTENTNTAIInformation, LocationReportIEValue].
type LocationReportLTENTNTAIInformationIEBinding struct {
	info   s00.FieldInfo
	codec  s18.LTENTNTAIInformationValueCodec
	inject func(s18.LTENTNTAIInformation,

	) LocationReportIEValue

	get func(*LocationReportIEValue,

	) (*s18.LTENTNTAIInformation,

		bool)
}

// Info returns the source descriptor for this binding.
func (b LocationReportLTENTNTAIInformationIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b LocationReportLTENTNTAIInformationIEBinding) Codec() s18.LTENTNTAIInformationValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b LocationReportLTENTNTAIInformationIEBinding) New(value s18.LTENTNTAIInformation,

) (LocationReportIEField, error) {
	if b.inject == nil {
		return LocationReportIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return LocationReportIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s18.BridgeLTENTNTAIInformationValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return LocationReportIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return LocationReportIEField{}, aper.OperationError(err, "Value.New")
	}
	return LocationReportIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b LocationReportLTENTNTAIInformationIEBinding) Get(field *LocationReportIEField) (*s18.LTENTNTAIInformation,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// UEInformationTransferSTMSIIEBinding is the concrete IEBinding[STMSI, UEInformationTransferIEValue].
type UEInformationTransferSTMSIIEBinding struct {
	info   s00.FieldInfo
	codec  s28.STMSIValueCodec
	inject func(s27.STMSI,

	) UEInformationTransferIEValue

	get func(*UEInformationTransferIEValue,

	) (*s27.STMSI,

		bool)
}

// Info returns the source descriptor for this binding.
func (b UEInformationTransferSTMSIIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b UEInformationTransferSTMSIIEBinding) Codec() s28.STMSIValueCodec { return b.codec }

// New validates a source value and constructs its bound field.
func (b UEInformationTransferSTMSIIEBinding) New(value s27.STMSI,

) (UEInformationTransferIEField, error) {
	if b.inject == nil {
		return UEInformationTransferIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return UEInformationTransferIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s28.BridgeSTMSIValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return UEInformationTransferIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return UEInformationTransferIEField{}, aper.OperationError(err, "Value.New")
	}
	return UEInformationTransferIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b UEInformationTransferSTMSIIEBinding) Get(field *UEInformationTransferIEField) (*s27.STMSI,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// UEInformationTransferERABLevelQoSParametersIEBinding is the concrete IEBinding[ERABLevelQoSParameters, UEInformationTransferIEValue].
type UEInformationTransferERABLevelQoSParametersIEBinding struct {
	info   s00.FieldInfo
	codec  s18.ERABLevelQoSParametersValueCodec
	inject func(s18.ERABLevelQoSParameters,

	) UEInformationTransferIEValue

	get func(*UEInformationTransferIEValue,

	) (*s18.ERABLevelQoSParameters,

		bool)
}

// Info returns the source descriptor for this binding.
func (b UEInformationTransferERABLevelQoSParametersIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b UEInformationTransferERABLevelQoSParametersIEBinding) Codec() s18.ERABLevelQoSParametersValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b UEInformationTransferERABLevelQoSParametersIEBinding) New(value s18.ERABLevelQoSParameters,

) (UEInformationTransferIEField, error) {
	if b.inject == nil {
		return UEInformationTransferIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return UEInformationTransferIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s18.BridgeERABLevelQoSParametersValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return UEInformationTransferIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return UEInformationTransferIEField{}, aper.OperationError(err, "Value.New")
	}
	return UEInformationTransferIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b UEInformationTransferERABLevelQoSParametersIEBinding) Get(field *UEInformationTransferIEField) (*s18.ERABLevelQoSParameters,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// UEInformationTransferUERadioCapabilityIEBinding is the concrete IEBinding[UERadioCapability, UEInformationTransferIEValue].
type UEInformationTransferUERadioCapabilityIEBinding struct {
	info   s00.FieldInfo
	codec  s02.UERadioCapabilityValueCodec
	inject func(s00.UERadioCapability,

	) UEInformationTransferIEValue

	get func(*UEInformationTransferIEValue,

	) (*s00.UERadioCapability,

		bool)
}

// Info returns the source descriptor for this binding.
func (b UEInformationTransferUERadioCapabilityIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b UEInformationTransferUERadioCapabilityIEBinding) Codec() s02.UERadioCapabilityValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b UEInformationTransferUERadioCapabilityIEBinding) New(value s00.UERadioCapability,

) (UEInformationTransferIEField, error) {
	if b.inject == nil {
		return UEInformationTransferIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return UEInformationTransferIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s02.BridgeUERadioCapabilityValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return UEInformationTransferIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return UEInformationTransferIEField{}, aper.OperationError(err, "Value.New")
	}
	return UEInformationTransferIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b UEInformationTransferUERadioCapabilityIEBinding) Get(field *UEInformationTransferIEField) (*s00.UERadioCapability,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// UEInformationTransferSubscriptionBasedUEDifferentiationInfoIEBinding is the concrete IEBinding[SubscriptionBasedUEDifferentiationInfo, UEInformationTransferIEValue].
type UEInformationTransferSubscriptionBasedUEDifferentiationInfoIEBinding struct {
	info   s00.FieldInfo
	codec  SubscriptionBasedUEDifferentiationInfoValueCodec
	inject func(s30.SubscriptionBasedUEDifferentiationInfo,

	) UEInformationTransferIEValue

	get func(*UEInformationTransferIEValue,

	) (*s30.SubscriptionBasedUEDifferentiationInfo,

		bool)
}

// Info returns the source descriptor for this binding.
func (b UEInformationTransferSubscriptionBasedUEDifferentiationInfoIEBinding) Info() s00.FieldInfo {
	return b.info
}

// Codec returns the complete value codec for this binding.
func (b UEInformationTransferSubscriptionBasedUEDifferentiationInfoIEBinding) Codec() SubscriptionBasedUEDifferentiationInfoValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b UEInformationTransferSubscriptionBasedUEDifferentiationInfoIEBinding) New(value s30.SubscriptionBasedUEDifferentiationInfo,

) (UEInformationTransferIEField, error) {
	if b.inject == nil {
		return UEInformationTransferIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return UEInformationTransferIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := b.codec.encode(value, false, budget); err != nil {
		return UEInformationTransferIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return UEInformationTransferIEField{}, aper.OperationError(err, "Value.New")
	}
	return UEInformationTransferIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b UEInformationTransferSubscriptionBasedUEDifferentiationInfoIEBinding) Get(field *UEInformationTransferIEField) (*s30.SubscriptionBasedUEDifferentiationInfo,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// UEInformationTransferPendingDataIndicationIEBinding is the concrete IEBinding[PendingDataIndication, UEInformationTransferIEValue].
type UEInformationTransferPendingDataIndicationIEBinding struct {
	info   s00.FieldInfo
	codec  s01.PendingDataIndicationValueCodec
	inject func(s00.PendingDataIndication,

	) UEInformationTransferIEValue

	get func(*UEInformationTransferIEValue,

	) (*s00.PendingDataIndication,

		bool)
}

// Info returns the source descriptor for this binding.
func (b UEInformationTransferPendingDataIndicationIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b UEInformationTransferPendingDataIndicationIEBinding) Codec() s01.PendingDataIndicationValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b UEInformationTransferPendingDataIndicationIEBinding) New(value s00.PendingDataIndication,

) (UEInformationTransferIEField, error) {
	if b.inject == nil {
		return UEInformationTransferIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return UEInformationTransferIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s01.BridgePendingDataIndicationValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return UEInformationTransferIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return UEInformationTransferIEField{}, aper.OperationError(err, "Value.New")
	}
	return UEInformationTransferIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b UEInformationTransferPendingDataIndicationIEBinding) Get(field *UEInformationTransferIEField) (*s00.PendingDataIndication,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// UEInformationTransferMaskedIMEISVIEBinding is the concrete IEBinding[MaskedIMEISV, UEInformationTransferIEValue].
type UEInformationTransferMaskedIMEISVIEBinding struct {
	info   s00.FieldInfo
	codec  s01.MaskedIMEISVValueCodec
	inject func(s00.MaskedIMEISV,

	) UEInformationTransferIEValue

	get func(*UEInformationTransferIEValue,

	) (*s00.MaskedIMEISV,

		bool)
}

// Info returns the source descriptor for this binding.
func (b UEInformationTransferMaskedIMEISVIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b UEInformationTransferMaskedIMEISVIEBinding) Codec() s01.MaskedIMEISVValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b UEInformationTransferMaskedIMEISVIEBinding) New(value s00.MaskedIMEISV,

) (UEInformationTransferIEField, error) {
	if b.inject == nil {
		return UEInformationTransferIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return UEInformationTransferIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s01.BridgeMaskedIMEISVValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return UEInformationTransferIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return UEInformationTransferIEField{}, aper.OperationError(err, "Value.New")
	}
	return UEInformationTransferIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b UEInformationTransferMaskedIMEISVIEBinding) Get(field *UEInformationTransferIEField) (*s00.MaskedIMEISV,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// ConnectedengNBItemValueCodec is the concrete ValueCodec[ConnectedengNBItem].
type ConnectedengNBItemValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ConnectedengNBItem,

		error)
	encode func(ConnectedengNBItem,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ConnectedengNBItem, aper.DecodeState,

	) (ConnectedengNBItem, aper.Snapshot,

	)
	compare func(ConnectedengNBItem, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ConnectedengNBItemValueCodec) New(value ConnectedengNBItem,

) (ConnectedengNBItemAPERValue, error) {
	if c.encode == nil {
		return ConnectedengNBItemAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ConnectedengNBItemAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ConnectedengNBItemAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ConnectedengNBItemAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ConnectedengNBItemValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ConnectedengNBItemAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ConnectedengNBItemAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ConnectedengNBItemAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ConnectedengNBItemAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ConnectedengNBItemAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ConnectedengNBItemValueCodec) EncodeAPER(value ConnectedengNBItemAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c ConnectedengNBItemValueCodec) encodeBudgetValue(value ConnectedengNBItem,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ConnectedengNBItemValueCodec) encodeChanged(value ConnectedengNBItem,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ConnectionEstablishmentIndicationValueCodec is the concrete ValueCodec[ConnectionEstablishmentIndication].
type ConnectionEstablishmentIndicationValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ConnectionEstablishmentIndication,

		error)
	encode func(ConnectionEstablishmentIndication,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ConnectionEstablishmentIndication, aper.DecodeState,

	) (ConnectionEstablishmentIndication, aper.Snapshot,

	)
	compare func(ConnectionEstablishmentIndication, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ConnectionEstablishmentIndicationValueCodec) New(value ConnectionEstablishmentIndication,

) (ConnectionEstablishmentIndicationAPERValue, error) {
	if c.encode == nil {
		return ConnectionEstablishmentIndicationAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ConnectionEstablishmentIndicationAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ConnectionEstablishmentIndicationAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ConnectionEstablishmentIndicationAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ConnectionEstablishmentIndicationValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ConnectionEstablishmentIndicationAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ConnectionEstablishmentIndicationAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ConnectionEstablishmentIndicationAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ConnectionEstablishmentIndicationAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ConnectionEstablishmentIndicationAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ConnectionEstablishmentIndicationValueCodec) EncodeAPER(value ConnectionEstablishmentIndicationAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c ConnectionEstablishmentIndicationValueCodec) encodeBudgetValue(value ConnectionEstablishmentIndication,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ConnectionEstablishmentIndicationValueCodec) encodeChanged(value ConnectionEstablishmentIndication,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ENDCSONTransferTypeValueCodec is the concrete ValueCodec[ENDCSONTransferType].
type ENDCSONTransferTypeValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ENDCSONTransferType,

		error)
	encode func(ENDCSONTransferType,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ENDCSONTransferType, aper.DecodeState,

	) (ENDCSONTransferType, aper.Snapshot,

	)
	compare func(ENDCSONTransferType, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ENDCSONTransferTypeValueCodec) New(value ENDCSONTransferType,

) (ENDCSONTransferTypeAPERValue, error) {
	if c.encode == nil {
		return ENDCSONTransferTypeAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ENDCSONTransferTypeAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ENDCSONTransferTypeAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ENDCSONTransferTypeAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ENDCSONTransferTypeValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ENDCSONTransferTypeAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ENDCSONTransferTypeAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ENDCSONTransferTypeAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ENDCSONTransferTypeAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ENDCSONTransferTypeAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ENDCSONTransferTypeValueCodec) EncodeAPER(value ENDCSONTransferTypeAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c ENDCSONTransferTypeValueCodec) encodeBudgetValue(value ENDCSONTransferType,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ENDCSONTransferTypeValueCodec) encodeChanged(value ENDCSONTransferType,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ENDCSONeNBIdentificationValueCodec is the concrete ValueCodec[ENDCSONeNBIdentification].
type ENDCSONeNBIdentificationValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ENDCSONeNBIdentification,

		error)
	encode func(ENDCSONeNBIdentification,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ENDCSONeNBIdentification, aper.DecodeState,

	) (ENDCSONeNBIdentification, aper.Snapshot,

	)
	compare func(ENDCSONeNBIdentification, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ENDCSONeNBIdentificationValueCodec) New(value ENDCSONeNBIdentification,

) (ENDCSONeNBIdentificationAPERValue, error) {
	if c.encode == nil {
		return ENDCSONeNBIdentificationAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ENDCSONeNBIdentificationAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ENDCSONeNBIdentificationAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ENDCSONeNBIdentificationAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ENDCSONeNBIdentificationValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ENDCSONeNBIdentificationAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ENDCSONeNBIdentificationAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ENDCSONeNBIdentificationAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ENDCSONeNBIdentificationAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ENDCSONeNBIdentificationAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ENDCSONeNBIdentificationValueCodec) EncodeAPER(value ENDCSONeNBIdentificationAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c ENDCSONeNBIdentificationValueCodec) encodeBudgetValue(value ENDCSONeNBIdentification,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ENDCSONeNBIdentificationValueCodec) encodeChanged(value ENDCSONeNBIdentification,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ENDCSONengNBIdentificationValueCodec is the concrete ValueCodec[ENDCSONengNBIdentification].
type ENDCSONengNBIdentificationValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ENDCSONengNBIdentification,

		error)
	encode func(ENDCSONengNBIdentification,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ENDCSONengNBIdentification, aper.DecodeState,

	) (ENDCSONengNBIdentification, aper.Snapshot,

	)
	compare func(ENDCSONengNBIdentification, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ENDCSONengNBIdentificationValueCodec) New(value ENDCSONengNBIdentification,

) (ENDCSONengNBIdentificationAPERValue, error) {
	if c.encode == nil {
		return ENDCSONengNBIdentificationAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ENDCSONengNBIdentificationAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ENDCSONengNBIdentificationAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ENDCSONengNBIdentificationAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ENDCSONengNBIdentificationValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ENDCSONengNBIdentificationAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ENDCSONengNBIdentificationAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ENDCSONengNBIdentificationAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ENDCSONengNBIdentificationAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ENDCSONengNBIdentificationAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ENDCSONengNBIdentificationValueCodec) EncodeAPER(value ENDCSONengNBIdentificationAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c ENDCSONengNBIdentificationValueCodec) encodeBudgetValue(value ENDCSONengNBIdentification,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ENDCSONengNBIdentificationValueCodec) encodeChanged(value ENDCSONengNBIdentification,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ENDCTransferTypeReplyValueCodec is the concrete ValueCodec[ENDCTransferTypeReply].
type ENDCTransferTypeReplyValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ENDCTransferTypeReply,

		error)
	encode func(ENDCTransferTypeReply,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ENDCTransferTypeReply, aper.DecodeState,

	) (ENDCTransferTypeReply, aper.Snapshot,

	)
	compare func(ENDCTransferTypeReply, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ENDCTransferTypeReplyValueCodec) New(value ENDCTransferTypeReply,

) (ENDCTransferTypeReplyAPERValue, error) {
	if c.encode == nil {
		return ENDCTransferTypeReplyAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ENDCTransferTypeReplyAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ENDCTransferTypeReplyAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ENDCTransferTypeReplyAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ENDCTransferTypeReplyValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ENDCTransferTypeReplyAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ENDCTransferTypeReplyAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ENDCTransferTypeReplyAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ENDCTransferTypeReplyAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ENDCTransferTypeReplyAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ENDCTransferTypeReplyValueCodec) EncodeAPER(value ENDCTransferTypeReplyAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c ENDCTransferTypeReplyValueCodec) encodeBudgetValue(value ENDCTransferTypeReply,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ENDCTransferTypeReplyValueCodec) encodeChanged(value ENDCTransferTypeReply,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ENDCTransferTypeRequestValueCodec is the concrete ValueCodec[ENDCTransferTypeRequest].
type ENDCTransferTypeRequestValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ENDCTransferTypeRequest,

		error)
	encode func(ENDCTransferTypeRequest,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ENDCTransferTypeRequest, aper.DecodeState,

	) (ENDCTransferTypeRequest, aper.Snapshot,

	)
	compare func(ENDCTransferTypeRequest, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ENDCTransferTypeRequestValueCodec) New(value ENDCTransferTypeRequest,

) (ENDCTransferTypeRequestAPERValue, error) {
	if c.encode == nil {
		return ENDCTransferTypeRequestAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ENDCTransferTypeRequestAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ENDCTransferTypeRequestAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ENDCTransferTypeRequestAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ENDCTransferTypeRequestValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ENDCTransferTypeRequestAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ENDCTransferTypeRequestAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ENDCTransferTypeRequestAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ENDCTransferTypeRequestAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ENDCTransferTypeRequestAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ENDCTransferTypeRequestValueCodec) EncodeAPER(value ENDCTransferTypeRequestAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c ENDCTransferTypeRequestValueCodec) encodeBudgetValue(value ENDCTransferTypeRequest,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ENDCTransferTypeRequestValueCodec) encodeChanged(value ENDCTransferTypeRequest,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// MMEPagingTargetValueCodec is the concrete ValueCodec[MMEPagingTarget].
type MMEPagingTargetValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (MMEPagingTarget,

		error)
	encode func(MMEPagingTarget,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(MMEPagingTarget, aper.DecodeState,

	) (MMEPagingTarget, aper.Snapshot,

	)
	compare func(MMEPagingTarget, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c MMEPagingTargetValueCodec) New(value MMEPagingTarget,

) (MMEPagingTargetAPERValue, error) {
	if c.encode == nil {
		return MMEPagingTargetAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return MMEPagingTargetAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return MMEPagingTargetAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return MMEPagingTargetAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c MMEPagingTargetValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (MMEPagingTargetAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return MMEPagingTargetAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return MMEPagingTargetAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return MMEPagingTargetAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return MMEPagingTargetAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c MMEPagingTargetValueCodec) EncodeAPER(value MMEPagingTargetAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c MMEPagingTargetValueCodec) encodeBudgetValue(value MMEPagingTarget,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c MMEPagingTargetValueCodec) encodeChanged(value MMEPagingTarget,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// SupportedTAsItemValueCodec is the concrete ValueCodec[SupportedTAsItem].
type SupportedTAsItemValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (SupportedTAsItem,

		error)
	encode func(SupportedTAsItem,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(SupportedTAsItem, aper.DecodeState,

	) (SupportedTAsItem, aper.Snapshot,

	)
	compare func(SupportedTAsItem, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c SupportedTAsItemValueCodec) New(value SupportedTAsItem,

) (SupportedTAsItemAPERValue, error) {
	if c.encode == nil {
		return SupportedTAsItemAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return SupportedTAsItemAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return SupportedTAsItemAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return SupportedTAsItemAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c SupportedTAsItemValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (SupportedTAsItemAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return SupportedTAsItemAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return SupportedTAsItemAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return SupportedTAsItemAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return SupportedTAsItemAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c SupportedTAsItemValueCodec) EncodeAPER(value SupportedTAsItemAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c SupportedTAsItemValueCodec) encodeBudgetValue(value SupportedTAsItem,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c SupportedTAsItemValueCodec) encodeChanged(value SupportedTAsItem,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// TABasedMDTValueCodec is the concrete ValueCodec[TABasedMDT].
type TABasedMDTValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (TABasedMDT,

		error)
	encode func(TABasedMDT,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(TABasedMDT, aper.DecodeState,

	) (TABasedMDT, aper.Snapshot,

	)
	compare func(TABasedMDT, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c TABasedMDTValueCodec) New(value TABasedMDT,

) (TABasedMDTAPERValue, error) {
	if c.encode == nil {
		return TABasedMDTAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return TABasedMDTAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return TABasedMDTAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return TABasedMDTAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c TABasedMDTValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (TABasedMDTAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return TABasedMDTAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return TABasedMDTAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return TABasedMDTAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return TABasedMDTAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c TABasedMDTValueCodec) EncodeAPER(value TABasedMDTAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c TABasedMDTValueCodec) encodeBudgetValue(value TABasedMDT,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c TABasedMDTValueCodec) encodeChanged(value TABasedMDT,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// TABasedQMCValueCodec is the concrete ValueCodec[TABasedQMC].
type TABasedQMCValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (TABasedQMC,

		error)
	encode func(TABasedQMC,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(TABasedQMC, aper.DecodeState,

	) (TABasedQMC, aper.Snapshot,

	)
	compare func(TABasedQMC, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c TABasedQMCValueCodec) New(value TABasedQMC,

) (TABasedQMCAPERValue, error) {
	if c.encode == nil {
		return TABasedQMCAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return TABasedQMCAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return TABasedQMCAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return TABasedQMCAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c TABasedQMCValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (TABasedQMCAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return TABasedQMCAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return TABasedQMCAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return TABasedQMCAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return TABasedQMCAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c TABasedQMCValueCodec) EncodeAPER(value TABasedQMCAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c TABasedQMCValueCodec) encodeBudgetValue(value TABasedQMC,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c TABasedQMCValueCodec) encodeChanged(value TABasedQMC,

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
func BridgeConnectionEstablishmentIndicationIEValueValidateS1APIEContainer(fields s30.ConnectionEstablishmentIndicationIEContainer, rows []s00.FieldInfo, path string, budget *aper.DecodeBudget,

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
		if !s30.BridgeConnectionEstablishmentIndicationIEValueMethodMatchesID(field.Value, field.Id, budget) {
			rule := s30.BridgeConnectionEstablishmentIndicationIEValueMethodRule(field.Value)
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.ValueIDMismatch, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: aper.Path(fmt.Sprintf("%s.id", location.Path))}, Table: func() s00.TableID {
				sealed := s00.TableID{}
				*s00.BridgeTableIDFieldSource(&sealed) = rule.Assignment
				return sealed
			}(), IEID: field.Id, HasIEID: true, Rule: s26.BridgeS1apValidationRule(s00.ValueIDMismatch), RelatedRules: []aper.SourceRule{rule}})
		}
		rank, allowed := byID[field.Id]
		table := func() s00.TableID {
			sealed := s00.TableID{}
			*s00.BridgeTableIDFieldSource(&sealed) = s30.BridgeConnectionEstablishmentIndicationIEValueMethodRule(field.Value).Assignment
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
func BridgeSubscriptionBasedUEDifferentiationInfoExtIEsValueValidateS1APExtensionContainer(fields s11.SubscriptionBasedUEDifferentiationInfoExtIEsExtContainer, rows []s00.FieldInfo, path string, budget *aper.DecodeBudget) s21.ValidationReport {
	bb := aper.NewBudgetBuffer(budget)
	if err := aper.ChargeSlice[s11.SubscriptionBasedUEDifferentiationInfoExtIEsIEField](bb, uint64(len(fields))); err != nil {
		return func() s21.ValidationReport {
			sealed := s21.ValidationReport{}
			*s21.BridgeValidationReportFieldErr(&sealed) = err
			*s21.BridgeValidationReportFieldBudget(&sealed) = budget
			return sealed
		}()
	}
	asIE := make(s11.SubscriptionBasedUEDifferentiationInfoExtIEsIEContainer, len(fields))
	for i := range fields {
		asIE[i].Id = fields[i].Id
		asIE[i].Criticality = fields[i].Criticality
		asIE[i].Value = fields[i].ExtensionValue
	}
	return BridgeSubscriptionBasedUEDifferentiationInfoExtIEsValueValidateS1APIEContainer(asIE, rows, path, budget)
}
func BridgeSupportedTAsItemExtIEsValueValidateS1APExtensionContainer(fields s11.SupportedTAsItemExtIEsExtContainer, rows []s00.FieldInfo, path string, budget *aper.DecodeBudget) s21.ValidationReport {
	bb := aper.NewBudgetBuffer(budget)
	if err := aper.ChargeSlice[s11.SupportedTAsItemExtIEsIEField](bb, uint64(len(fields))); err != nil {
		return func() s21.ValidationReport {
			sealed := s21.ValidationReport{}
			*s21.BridgeValidationReportFieldErr(&sealed) = err
			*s21.BridgeValidationReportFieldBudget(&sealed) = budget
			return sealed
		}()
	}
	asIE := make(s11.SupportedTAsItemExtIEsIEContainer, len(fields))
	for i := range fields {
		asIE[i].Id = fields[i].Id
		asIE[i].Criticality = fields[i].Criticality
		asIE[i].Value = fields[i].ExtensionValue
	}
	return BridgeSupportedTAsItemExtIEsValueValidateS1APIEContainer(asIE, rows, path, budget)
}
func BridgeSynchronisationInformationExtIEsValueValidateS1APExtensionContainer(fields s11.SynchronisationInformationExtIEsExtContainer, rows []s00.FieldInfo, path string, budget *aper.DecodeBudget) s21.ValidationReport {
	bb := aper.NewBudgetBuffer(budget)
	if err := aper.ChargeSlice[s11.SynchronisationInformationExtIEsIEField](bb, uint64(len(fields))); err != nil {
		return func() s21.ValidationReport {
			sealed := s21.ValidationReport{}
			*s21.BridgeValidationReportFieldErr(&sealed) = err
			*s21.BridgeValidationReportFieldBudget(&sealed) = budget
			return sealed
		}()
	}
	asIE := make(s11.SynchronisationInformationExtIEsIEContainer, len(fields))
	for i := range fields {
		asIE[i].Id = fields[i].Id
		asIE[i].Criticality = fields[i].Criticality
		asIE[i].Value = fields[i].ExtensionValue
	}
	return BridgeSynchronisationInformationExtIEsValueValidateS1APIEContainer(asIE, rows, path, budget)
}
func BridgeTABasedMDTExtIEsValueValidateS1APExtensionContainer(fields s11.TABasedMDTExtIEsExtContainer, rows []s00.FieldInfo, path string, budget *aper.DecodeBudget) s21.ValidationReport {
	bb := aper.NewBudgetBuffer(budget)
	if err := aper.ChargeSlice[s11.TABasedMDTExtIEsIEField](bb, uint64(len(fields))); err != nil {
		return func() s21.ValidationReport {
			sealed := s21.ValidationReport{}
			*s21.BridgeValidationReportFieldErr(&sealed) = err
			*s21.BridgeValidationReportFieldBudget(&sealed) = budget
			return sealed
		}()
	}
	asIE := make(s11.TABasedMDTExtIEsIEContainer, len(fields))
	for i := range fields {
		asIE[i].Id = fields[i].Id
		asIE[i].Criticality = fields[i].Criticality
		asIE[i].Value = fields[i].ExtensionValue
	}
	return BridgeTABasedMDTExtIEsValueValidateS1APIEContainer(asIE, rows, path, budget)
}
func BridgeTABasedQMCExtIEsValueValidateS1APExtensionContainer(fields s11.TABasedQMCExtIEsExtContainer, rows []s00.FieldInfo, path string, budget *aper.DecodeBudget) s21.ValidationReport {
	bb := aper.NewBudgetBuffer(budget)
	if err := aper.ChargeSlice[s11.TABasedQMCExtIEsIEField](bb, uint64(len(fields))); err != nil {
		return func() s21.ValidationReport {
			sealed := s21.ValidationReport{}
			*s21.BridgeValidationReportFieldErr(&sealed) = err
			*s21.BridgeValidationReportFieldBudget(&sealed) = budget
			return sealed
		}()
	}
	asIE := make(s11.TABasedQMCExtIEsIEContainer, len(fields))
	for i := range fields {
		asIE[i].Id = fields[i].Id
		asIE[i].Criticality = fields[i].Criticality
		asIE[i].Value = fields[i].ExtensionValue
	}
	return BridgeTABasedQMCExtIEsValueValidateS1APIEContainer(asIE, rows, path, budget)
}
func BridgeTAIBasedMDTExtIEsValueValidateS1APExtensionContainer(fields s11.TAIBasedMDTExtIEsExtContainer, rows []s00.FieldInfo, path string, budget *aper.DecodeBudget) s21.ValidationReport {
	bb := aper.NewBudgetBuffer(budget)
	if err := aper.ChargeSlice[s11.TAIBasedMDTExtIEsIEField](bb, uint64(len(fields))); err != nil {
		return func() s21.ValidationReport {
			sealed := s21.ValidationReport{}
			*s21.BridgeValidationReportFieldErr(&sealed) = err
			*s21.BridgeValidationReportFieldBudget(&sealed) = budget
			return sealed
		}()
	}
	asIE := make(s11.TAIBasedMDTExtIEsIEContainer, len(fields))
	for i := range fields {
		asIE[i].Id = fields[i].Id
		asIE[i].Criticality = fields[i].Criticality
		asIE[i].Value = fields[i].ExtensionValue
	}
	return BridgeTAIBasedMDTExtIEsValueValidateS1APIEContainer(asIE, rows, path, budget)
}
func BridgeTAIBasedQMCExtIEsValueValidateS1APExtensionContainer(fields s11.TAIBasedQMCExtIEsExtContainer, rows []s00.FieldInfo, path string, budget *aper.DecodeBudget) s21.ValidationReport {
	bb := aper.NewBudgetBuffer(budget)
	if err := aper.ChargeSlice[s11.TAIBasedQMCExtIEsIEField](bb, uint64(len(fields))); err != nil {
		return func() s21.ValidationReport {
			sealed := s21.ValidationReport{}
			*s21.BridgeValidationReportFieldErr(&sealed) = err
			*s21.BridgeValidationReportFieldBudget(&sealed) = budget
			return sealed
		}()
	}
	asIE := make(s11.TAIBasedQMCExtIEsIEContainer, len(fields))
	for i := range fields {
		asIE[i].Id = fields[i].Id
		asIE[i].Criticality = fields[i].Criticality
		asIE[i].Value = fields[i].ExtensionValue
	}
	return BridgeTAIBasedQMCExtIEsValueValidateS1APIEContainer(asIE, rows, path, budget)
}
func BridgeTAIBroadcastItemExtIEsValueValidateS1APExtensionContainer(fields s11.TAIBroadcastItemExtIEsExtContainer, rows []s00.FieldInfo, path string, budget *aper.DecodeBudget) s21.ValidationReport {
	bb := aper.NewBudgetBuffer(budget)
	if err := aper.ChargeSlice[s11.TAIBroadcastItemExtIEsIEField](bb, uint64(len(fields))); err != nil {
		return func() s21.ValidationReport {
			sealed := s21.ValidationReport{}
			*s21.BridgeValidationReportFieldErr(&sealed) = err
			*s21.BridgeValidationReportFieldBudget(&sealed) = budget
			return sealed
		}()
	}
	asIE := make(s11.TAIBroadcastItemExtIEsIEContainer, len(fields))
	for i := range fields {
		asIE[i].Id = fields[i].Id
		asIE[i].Criticality = fields[i].Criticality
		asIE[i].Value = fields[i].ExtensionValue
	}
	return BridgeTAIBroadcastItemExtIEsValueValidateS1APIEContainer(asIE, rows, path, budget)
}
func BridgeTAICancelledItemExtIEsValueValidateS1APExtensionContainer(fields s11.TAICancelledItemExtIEsExtContainer, rows []s00.FieldInfo, path string, budget *aper.DecodeBudget) s21.ValidationReport {
	bb := aper.NewBudgetBuffer(budget)
	if err := aper.ChargeSlice[s11.TAICancelledItemExtIEsIEField](bb, uint64(len(fields))); err != nil {
		return func() s21.ValidationReport {
			sealed := s21.ValidationReport{}
			*s21.BridgeValidationReportFieldErr(&sealed) = err
			*s21.BridgeValidationReportFieldBudget(&sealed) = budget
			return sealed
		}()
	}
	asIE := make(s11.TAICancelledItemExtIEsIEContainer, len(fields))
	for i := range fields {
		asIE[i].Id = fields[i].Id
		asIE[i].Criticality = fields[i].Criticality
		asIE[i].Value = fields[i].ExtensionValue
	}
	return BridgeTAICancelledItemExtIEsValueValidateS1APIEContainer(asIE, rows, path, budget)
}
func ConnectionEstablishmentIndicationIEValueERABIEContainerListCodec(table s00.ConnectionEstablishmentIndicationIEValueIETable) ConnectionEstablishmentIndicationIEValueERABIEContainerListValueCodec {
	codec := ConnectionEstablishmentIndicationIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if *s30.BridgeConnectionEstablishmentIndicationIEContainerValueCodecFieldDecode(&codec) == nil {
		return ConnectionEstablishmentIndicationIEValueERABIEContainerListValueCodec{}
	}
	return ConnectionEstablishmentIndicationIEValueERABIEContainerListValueCodec{decode: func(data []byte, options aper.DecodeState) (s30.ConnectionEstablishmentIndicationIEValueERABIEContainerList, error) {
		value, err := (*s30.BridgeConnectionEstablishmentIndicationIEContainerValueCodecFieldDecode(&codec))(data, options)
		return s30.ConnectionEstablishmentIndicationIEValueERABIEContainerList(value), err
	}, encode: func(value s30.ConnectionEstablishmentIndicationIEValueERABIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return (*s30.BridgeConnectionEstablishmentIndicationIEContainerValueCodecFieldEncode(&codec))(s30.ConnectionEstablishmentIndicationIEContainer(value), fresh, budget)
	}, capture: func(v s30.ConnectionEstablishmentIndicationIEValueERABIEContainerList, options aper.DecodeState) (s30.ConnectionEstablishmentIndicationIEValueERABIEContainerList, aper.Snapshot) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeConnectionEstablishmentIndicationIEValueCaptureS1APERABIEContainerList(&v, &s)
		var root aper.Snapshot
		s.End(f, &root, false)
		return v, root
	}, compare: func(v s30.ConnectionEstablishmentIndicationIEValueERABIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
	) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		BridgeConnectionEstablishmentIndicationIEValueCompareS1APERABIEContainerList(&v, &s)
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
func SupportedTAsItemExtIEsValueExtensionFieldTableCodec(table s00.SupportedTAsItemExtIEsValueExtensionTable) s11.SupportedTAsItemExtIEsExtFieldValueCodec {
	if !*s00.BridgeSupportedTAsItemExtIEsValueExtensionTableFieldBound(&table) {
		return s11.SupportedTAsItemExtIEsExtFieldValueCodec{}
	}
	return func() s11.SupportedTAsItemExtIEsExtFieldValueCodec {
		sealed := s11.SupportedTAsItemExtIEsExtFieldValueCodec{}
		*s11.BridgeSupportedTAsItemExtIEsExtFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s11.SupportedTAsItemExtIEsExtField, error) {
			var field s11.SupportedTAsItemExtIEsExtField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s11.BridgeSupportedTAsItemExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, err
			}
			if _, err := aper.CaptureFinalBits(bb, "ProtocolExtensionField"); err != nil {
				return field, err
			}
			return field, nil
		}
		*s11.BridgeSupportedTAsItemExtIEsExtFieldValueCodecFieldEncode(&sealed) = func(field s11.SupportedTAsItemExtIEsExtField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s11.BridgeSupportedTAsItemExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s11.BridgeSupportedTAsItemExtIEsExtFieldValueCodecFieldCapture(&sealed) = func(v s11.SupportedTAsItemExtIEsExtField, options aper.DecodeState) (s11.SupportedTAsItemExtIEsExtField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeSupportedTAsItemExtIEsValueCaptureS1APProtocolExtensionField(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,
				false)
			return v, root
		}
		*s11.BridgeSupportedTAsItemExtIEsExtFieldValueCodecFieldCompare(&sealed) = func(v s11.SupportedTAsItemExtIEsExtField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeSupportedTAsItemExtIEsValueCompareS1APProtocolExtensionField(&v, &s)
			s.End(f, root,

				false)
			return s.Plan(), s.BudgetValue()
		}
		*s11.BridgeSupportedTAsItemExtIEsExtFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}
func SynchronisationInformationExtIEsValueExtensionFieldTableCodec(table s00.SynchronisationInformationExtIEsValueExtensionTable) s11.SynchronisationInformationExtIEsExtFieldValueCodec {
	if !*s00.BridgeSynchronisationInformationExtIEsValueExtensionTableFieldBound(&table) {
		return s11.SynchronisationInformationExtIEsExtFieldValueCodec{}
	}
	return func() s11.SynchronisationInformationExtIEsExtFieldValueCodec {
		sealed := s11.SynchronisationInformationExtIEsExtFieldValueCodec{}
		*s11.BridgeSynchronisationInformationExtIEsExtFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s11.SynchronisationInformationExtIEsExtField, error) {
			var field s11.SynchronisationInformationExtIEsExtField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s11.BridgeSynchronisationInformationExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, err
			}
			if _, err := aper.CaptureFinalBits(bb, "ProtocolExtensionField"); err != nil {
				return field, err
			}
			return field, nil
		}
		*s11.BridgeSynchronisationInformationExtIEsExtFieldValueCodecFieldEncode(&sealed) = func(field s11.SynchronisationInformationExtIEsExtField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s11.BridgeSynchronisationInformationExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s11.BridgeSynchronisationInformationExtIEsExtFieldValueCodecFieldCapture(&sealed) = func(v s11.SynchronisationInformationExtIEsExtField, options aper.DecodeState) (s11.SynchronisationInformationExtIEsExtField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeSynchronisationInformationExtIEsValueCaptureS1APProtocolExtensionField(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,
				false)
			return v, root
		}
		*s11.BridgeSynchronisationInformationExtIEsExtFieldValueCodecFieldCompare(&sealed) = func(v s11.SynchronisationInformationExtIEsExtField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeSynchronisationInformationExtIEsValueCompareS1APProtocolExtensionField(&v, &s)
			s.End(f, root,

				false)
			return s.Plan(), s.BudgetValue()
		}
		*s11.BridgeSynchronisationInformationExtIEsExtFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}
func TABasedMDTExtIEsValueExtensionFieldTableCodec(table s00.TABasedMDTExtIEsValueExtensionTable) s11.TABasedMDTExtIEsExtFieldValueCodec {
	if !*s00.BridgeTABasedMDTExtIEsValueExtensionTableFieldBound(&table) {
		return s11.TABasedMDTExtIEsExtFieldValueCodec{}
	}
	return func() s11.TABasedMDTExtIEsExtFieldValueCodec {
		sealed := s11.TABasedMDTExtIEsExtFieldValueCodec{}
		*s11.BridgeTABasedMDTExtIEsExtFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s11.TABasedMDTExtIEsExtField, error) {
			var field s11.TABasedMDTExtIEsExtField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s11.BridgeTABasedMDTExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, err
			}
			if _, err := aper.CaptureFinalBits(bb, "ProtocolExtensionField"); err != nil {
				return field, err
			}
			return field, nil
		}
		*s11.BridgeTABasedMDTExtIEsExtFieldValueCodecFieldEncode(&sealed) = func(field s11.TABasedMDTExtIEsExtField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s11.BridgeTABasedMDTExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s11.BridgeTABasedMDTExtIEsExtFieldValueCodecFieldCapture(&sealed) = func(v s11.TABasedMDTExtIEsExtField, options aper.DecodeState) (s11.TABasedMDTExtIEsExtField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeTABasedMDTExtIEsValueCaptureS1APProtocolExtensionField(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,
				false)
			return v, root
		}
		*s11.BridgeTABasedMDTExtIEsExtFieldValueCodecFieldCompare(&sealed) = func(v s11.TABasedMDTExtIEsExtField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeTABasedMDTExtIEsValueCompareS1APProtocolExtensionField(&v, &s)
			s.End(f, root,

				false)
			return s.Plan(), s.BudgetValue()
		}
		*s11.BridgeTABasedMDTExtIEsExtFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}
func TABasedQMCExtIEsValueExtensionFieldTableCodec(table s00.TABasedQMCExtIEsValueExtensionTable) s11.TABasedQMCExtIEsExtFieldValueCodec {
	if !*s00.BridgeTABasedQMCExtIEsValueExtensionTableFieldBound(&table) {
		return s11.TABasedQMCExtIEsExtFieldValueCodec{}
	}
	return func() s11.TABasedQMCExtIEsExtFieldValueCodec {
		sealed := s11.TABasedQMCExtIEsExtFieldValueCodec{}
		*s11.BridgeTABasedQMCExtIEsExtFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s11.TABasedQMCExtIEsExtField, error) {
			var field s11.TABasedQMCExtIEsExtField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s11.BridgeTABasedQMCExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, err
			}
			if _, err := aper.CaptureFinalBits(bb, "ProtocolExtensionField"); err != nil {
				return field, err
			}
			return field, nil
		}
		*s11.BridgeTABasedQMCExtIEsExtFieldValueCodecFieldEncode(&sealed) = func(field s11.TABasedQMCExtIEsExtField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s11.BridgeTABasedQMCExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s11.BridgeTABasedQMCExtIEsExtFieldValueCodecFieldCapture(&sealed) = func(v s11.TABasedQMCExtIEsExtField, options aper.DecodeState) (s11.TABasedQMCExtIEsExtField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeTABasedQMCExtIEsValueCaptureS1APProtocolExtensionField(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,
				false)
			return v, root
		}
		*s11.BridgeTABasedQMCExtIEsExtFieldValueCodecFieldCompare(&sealed) = func(v s11.TABasedQMCExtIEsExtField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeTABasedQMCExtIEsValueCompareS1APProtocolExtensionField(&v, &s)
			s.End(f, root,

				false)
			return s.Plan(), s.BudgetValue()
		}
		*s11.BridgeTABasedQMCExtIEsExtFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}
func TAIBasedMDTExtIEsValueExtensionFieldTableCodec(table s00.TAIBasedMDTExtIEsValueExtensionTable) s11.TAIBasedMDTExtIEsExtFieldValueCodec {
	if !*s00.BridgeTAIBasedMDTExtIEsValueExtensionTableFieldBound(&table) {
		return s11.TAIBasedMDTExtIEsExtFieldValueCodec{}
	}
	return func() s11.TAIBasedMDTExtIEsExtFieldValueCodec {
		sealed := s11.TAIBasedMDTExtIEsExtFieldValueCodec{}
		*s11.BridgeTAIBasedMDTExtIEsExtFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s11.TAIBasedMDTExtIEsExtField, error) {
			var field s11.TAIBasedMDTExtIEsExtField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s11.BridgeTAIBasedMDTExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, err
			}
			if _, err := aper.CaptureFinalBits(bb, "ProtocolExtensionField"); err != nil {
				return field, err
			}
			return field, nil
		}
		*s11.BridgeTAIBasedMDTExtIEsExtFieldValueCodecFieldEncode(&sealed) = func(field s11.TAIBasedMDTExtIEsExtField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s11.BridgeTAIBasedMDTExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s11.BridgeTAIBasedMDTExtIEsExtFieldValueCodecFieldCapture(&sealed) = func(v s11.TAIBasedMDTExtIEsExtField, options aper.DecodeState) (s11.TAIBasedMDTExtIEsExtField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeTAIBasedMDTExtIEsValueCaptureS1APProtocolExtensionField(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,
				false)
			return v, root
		}
		*s11.BridgeTAIBasedMDTExtIEsExtFieldValueCodecFieldCompare(&sealed) = func(v s11.TAIBasedMDTExtIEsExtField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeTAIBasedMDTExtIEsValueCompareS1APProtocolExtensionField(&v, &s)
			s.End(f, root,

				false)
			return s.Plan(), s.BudgetValue()
		}
		*s11.BridgeTAIBasedMDTExtIEsExtFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}
func TAIBasedQMCExtIEsValueExtensionFieldTableCodec(table s00.TAIBasedQMCExtIEsValueExtensionTable) s11.TAIBasedQMCExtIEsExtFieldValueCodec {
	if !*s00.BridgeTAIBasedQMCExtIEsValueExtensionTableFieldBound(&table) {
		return s11.TAIBasedQMCExtIEsExtFieldValueCodec{}
	}
	return func() s11.TAIBasedQMCExtIEsExtFieldValueCodec {
		sealed := s11.TAIBasedQMCExtIEsExtFieldValueCodec{}
		*s11.BridgeTAIBasedQMCExtIEsExtFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s11.TAIBasedQMCExtIEsExtField, error) {
			var field s11.TAIBasedQMCExtIEsExtField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s11.BridgeTAIBasedQMCExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, err
			}
			if _, err := aper.CaptureFinalBits(bb, "ProtocolExtensionField"); err != nil {
				return field, err
			}
			return field, nil
		}
		*s11.BridgeTAIBasedQMCExtIEsExtFieldValueCodecFieldEncode(&sealed) = func(field s11.TAIBasedQMCExtIEsExtField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s11.BridgeTAIBasedQMCExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s11.BridgeTAIBasedQMCExtIEsExtFieldValueCodecFieldCapture(&sealed) = func(v s11.TAIBasedQMCExtIEsExtField, options aper.DecodeState) (s11.TAIBasedQMCExtIEsExtField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeTAIBasedQMCExtIEsValueCaptureS1APProtocolExtensionField(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,
				false)
			return v, root
		}
		*s11.BridgeTAIBasedQMCExtIEsExtFieldValueCodecFieldCompare(&sealed) = func(v s11.TAIBasedQMCExtIEsExtField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeTAIBasedQMCExtIEsValueCompareS1APProtocolExtensionField(&v, &s)
			s.End(f, root,

				false)
			return s.Plan(), s.BudgetValue()
		}
		*s11.BridgeTAIBasedQMCExtIEsExtFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}
func TAIBroadcastItemExtIEsValueExtensionFieldTableCodec(table s00.TAIBroadcastItemExtIEsValueExtensionTable) s11.TAIBroadcastItemExtIEsExtFieldValueCodec {
	if !*s00.BridgeTAIBroadcastItemExtIEsValueExtensionTableFieldBound(&table) {
		return s11.TAIBroadcastItemExtIEsExtFieldValueCodec{}
	}
	return func() s11.TAIBroadcastItemExtIEsExtFieldValueCodec {
		sealed := s11.TAIBroadcastItemExtIEsExtFieldValueCodec{}
		*s11.BridgeTAIBroadcastItemExtIEsExtFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s11.TAIBroadcastItemExtIEsExtField, error) {
			var field s11.TAIBroadcastItemExtIEsExtField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s11.BridgeTAIBroadcastItemExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, err
			}
			if _, err := aper.CaptureFinalBits(bb, "ProtocolExtensionField"); err != nil {
				return field, err
			}
			return field, nil
		}
		*s11.BridgeTAIBroadcastItemExtIEsExtFieldValueCodecFieldEncode(&sealed) = func(field s11.TAIBroadcastItemExtIEsExtField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s11.BridgeTAIBroadcastItemExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s11.BridgeTAIBroadcastItemExtIEsExtFieldValueCodecFieldCapture(&sealed) = func(v s11.TAIBroadcastItemExtIEsExtField, options aper.DecodeState) (s11.TAIBroadcastItemExtIEsExtField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeTAIBroadcastItemExtIEsValueCaptureS1APProtocolExtensionField(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,
				false)
			return v, root
		}
		*s11.BridgeTAIBroadcastItemExtIEsExtFieldValueCodecFieldCompare(&sealed) = func(v s11.TAIBroadcastItemExtIEsExtField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeTAIBroadcastItemExtIEsValueCompareS1APProtocolExtensionField(&v, &s)
			s.End(f, root,

				false)
			return s.Plan(), s.BudgetValue()
		}
		*s11.BridgeTAIBroadcastItemExtIEsExtFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}
func TAICancelledItemExtIEsValueExtensionFieldTableCodec(table s00.TAICancelledItemExtIEsValueExtensionTable) s11.TAICancelledItemExtIEsExtFieldValueCodec {
	if !*s00.BridgeTAICancelledItemExtIEsValueExtensionTableFieldBound(&table) {
		return s11.TAICancelledItemExtIEsExtFieldValueCodec{}
	}
	return func() s11.TAICancelledItemExtIEsExtFieldValueCodec {
		sealed := s11.TAICancelledItemExtIEsExtFieldValueCodec{}
		*s11.BridgeTAICancelledItemExtIEsExtFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s11.TAICancelledItemExtIEsExtField, error) {
			var field s11.TAICancelledItemExtIEsExtField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s11.BridgeTAICancelledItemExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, err
			}
			if _, err := aper.CaptureFinalBits(bb, "ProtocolExtensionField"); err != nil {
				return field, err
			}
			return field, nil
		}
		*s11.BridgeTAICancelledItemExtIEsExtFieldValueCodecFieldEncode(&sealed) = func(field s11.TAICancelledItemExtIEsExtField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s11.BridgeTAICancelledItemExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s11.BridgeTAICancelledItemExtIEsExtFieldValueCodecFieldCapture(&sealed) = func(v s11.TAICancelledItemExtIEsExtField, options aper.DecodeState) (s11.TAICancelledItemExtIEsExtField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeTAICancelledItemExtIEsValueCaptureS1APProtocolExtensionField(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,
				false)
			return v, root
		}
		*s11.BridgeTAICancelledItemExtIEsExtFieldValueCodecFieldCompare(&sealed) = func(v s11.TAICancelledItemExtIEsExtField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeTAICancelledItemExtIEsValueCompareS1APProtocolExtensionField(&v, &s)
			s.End(f, root,

				false)
			return s.Plan(), s.BudgetValue()
		}
		*s11.BridgeTAICancelledItemExtIEsExtFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}
func TAIExtIEsValueExtensionFieldTableCodec(table s00.TAIExtIEsValueExtensionTable) s11.TAIExtIEsExtFieldValueCodec {
	if !*s00.BridgeTAIExtIEsValueExtensionTableFieldBound(&table) {
		return s11.TAIExtIEsExtFieldValueCodec{}
	}
	return func() s11.TAIExtIEsExtFieldValueCodec {
		sealed := s11.TAIExtIEsExtFieldValueCodec{}
		*s11.BridgeTAIExtIEsExtFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s11.TAIExtIEsExtField, error) {
			var field s11.TAIExtIEsExtField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s11.BridgeTAIExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, err
			}
			if _, err := aper.CaptureFinalBits(bb, "ProtocolExtensionField"); err != nil {
				return field, err
			}
			return field, nil
		}
		*s11.BridgeTAIExtIEsExtFieldValueCodecFieldEncode(&sealed) = func(field s11.TAIExtIEsExtField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s11.BridgeTAIExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s11.BridgeTAIExtIEsExtFieldValueCodecFieldCapture(&sealed) = func(v s11.TAIExtIEsExtField, options aper.DecodeState) (s11.TAIExtIEsExtField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeTAIExtIEsValueCaptureS1APProtocolExtensionField(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,
				false)
			return v, root
		}
		*s11.BridgeTAIExtIEsExtFieldValueCodecFieldCompare(&sealed) = func(v s11.TAIExtIEsExtField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeTAIExtIEsValueCompareS1APProtocolExtensionField(&v, &s)
			s.End(f, root,

				false)
			return s.Plan(), s.BudgetValue()
		}
		*s11.BridgeTAIExtIEsExtFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}
func SubscriptionBasedUEDifferentiationInfoExtIEsValueExtensionTableCodec(table s00.SubscriptionBasedUEDifferentiationInfoExtIEsValueExtensionTable, bounds aper.ListBounds) s11.SubscriptionBasedUEDifferentiationInfoExtIEsExtContainerValueCodec {
	if !*s00.BridgeSubscriptionBasedUEDifferentiationInfoExtIEsValueExtensionTableFieldBound(&table) {
		return s11.SubscriptionBasedUEDifferentiationInfoExtIEsExtContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s11.SubscriptionBasedUEDifferentiationInfoExtIEsExtContainerValueCodec {
		sealed := s11.SubscriptionBasedUEDifferentiationInfoExtIEsExtContainerValueCodec{}
		*s11.BridgeSubscriptionBasedUEDifferentiationInfoExtIEsExtContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s11.SubscriptionBasedUEDifferentiationInfoExtIEsExtContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s11.SubscriptionBasedUEDifferentiationInfoExtIEsExtContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s11.SubscriptionBasedUEDifferentiationInfoExtIEsExtField
					if err := s11.BridgeSubscriptionBasedUEDifferentiationInfoExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
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
		*s11.BridgeSubscriptionBasedUEDifferentiationInfoExtIEsExtContainerValueCodecFieldEncode(&sealed) = func(fields s11.SubscriptionBasedUEDifferentiationInfoExtIEsExtContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s11.BridgeSubscriptionBasedUEDifferentiationInfoExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
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
		*s11.BridgeSubscriptionBasedUEDifferentiationInfoExtIEsExtContainerValueCodecFieldCapture(&sealed) = func(v s11.SubscriptionBasedUEDifferentiationInfoExtIEsExtContainer, options aper.DecodeState) (s11.SubscriptionBasedUEDifferentiationInfoExtIEsExtContainer, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s30.BridgeSubscriptionBasedUEDifferentiationInfoExtIEsValueCaptureS1APProtocolExtensionContainer(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s11.BridgeSubscriptionBasedUEDifferentiationInfoExtIEsExtContainerValueCodecFieldCompare(&sealed) = func(v s11.SubscriptionBasedUEDifferentiationInfoExtIEsExtContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.
				Begin()
			s30.BridgeSubscriptionBasedUEDifferentiationInfoExtIEsValueCompareS1APProtocolExtensionContainer(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s11.BridgeSubscriptionBasedUEDifferentiationInfoExtIEsExtContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}
func SupportedTAsItemExtIEsValueExtensionTableCodec(table s00.SupportedTAsItemExtIEsValueExtensionTable, bounds aper.ListBounds) s11.SupportedTAsItemExtIEsExtContainerValueCodec {
	if !*s00.BridgeSupportedTAsItemExtIEsValueExtensionTableFieldBound(&table) {
		return s11.SupportedTAsItemExtIEsExtContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s11.SupportedTAsItemExtIEsExtContainerValueCodec {
		sealed := s11.SupportedTAsItemExtIEsExtContainerValueCodec{}
		*s11.BridgeSupportedTAsItemExtIEsExtContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s11.SupportedTAsItemExtIEsExtContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s11.SupportedTAsItemExtIEsExtContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s11.SupportedTAsItemExtIEsExtField
					if err := s11.BridgeSupportedTAsItemExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
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
		*s11.BridgeSupportedTAsItemExtIEsExtContainerValueCodecFieldEncode(&sealed) = func(fields s11.SupportedTAsItemExtIEsExtContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s11.BridgeSupportedTAsItemExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
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
		*s11.BridgeSupportedTAsItemExtIEsExtContainerValueCodecFieldCapture(&sealed) = func(v s11.SupportedTAsItemExtIEsExtContainer, options aper.DecodeState) (s11.SupportedTAsItemExtIEsExtContainer, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeSupportedTAsItemExtIEsValueCaptureS1APProtocolExtensionContainer(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s11.BridgeSupportedTAsItemExtIEsExtContainerValueCodecFieldCompare(&sealed) = func(v s11.SupportedTAsItemExtIEsExtContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.
				Begin()
			BridgeSupportedTAsItemExtIEsValueCompareS1APProtocolExtensionContainer(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s11.BridgeSupportedTAsItemExtIEsExtContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}
func SynchronisationInformationExtIEsValueExtensionTableCodec(table s00.SynchronisationInformationExtIEsValueExtensionTable, bounds aper.ListBounds) s11.SynchronisationInformationExtIEsExtContainerValueCodec {
	if !*s00.BridgeSynchronisationInformationExtIEsValueExtensionTableFieldBound(&table) {
		return s11.SynchronisationInformationExtIEsExtContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s11.SynchronisationInformationExtIEsExtContainerValueCodec {
		sealed := s11.SynchronisationInformationExtIEsExtContainerValueCodec{}
		*s11.BridgeSynchronisationInformationExtIEsExtContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s11.SynchronisationInformationExtIEsExtContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s11.SynchronisationInformationExtIEsExtContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s11.SynchronisationInformationExtIEsExtField
					if err := s11.BridgeSynchronisationInformationExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
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
		*s11.BridgeSynchronisationInformationExtIEsExtContainerValueCodecFieldEncode(&sealed) = func(fields s11.SynchronisationInformationExtIEsExtContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s11.BridgeSynchronisationInformationExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
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
		*s11.BridgeSynchronisationInformationExtIEsExtContainerValueCodecFieldCapture(&sealed) = func(v s11.SynchronisationInformationExtIEsExtContainer, options aper.DecodeState) (s11.SynchronisationInformationExtIEsExtContainer, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeSynchronisationInformationExtIEsValueCaptureS1APProtocolExtensionContainer(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s11.BridgeSynchronisationInformationExtIEsExtContainerValueCodecFieldCompare(&sealed) = func(v s11.SynchronisationInformationExtIEsExtContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.
				Begin()
			BridgeSynchronisationInformationExtIEsValueCompareS1APProtocolExtensionContainer(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s11.BridgeSynchronisationInformationExtIEsExtContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}
func TABasedMDTExtIEsValueExtensionTableCodec(table s00.TABasedMDTExtIEsValueExtensionTable, bounds aper.ListBounds) s11.TABasedMDTExtIEsExtContainerValueCodec {
	if !*s00.BridgeTABasedMDTExtIEsValueExtensionTableFieldBound(&table) {
		return s11.TABasedMDTExtIEsExtContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s11.TABasedMDTExtIEsExtContainerValueCodec {
		sealed := s11.TABasedMDTExtIEsExtContainerValueCodec{}
		*s11.BridgeTABasedMDTExtIEsExtContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s11.TABasedMDTExtIEsExtContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s11.TABasedMDTExtIEsExtContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s11.TABasedMDTExtIEsExtField
					if err := s11.BridgeTABasedMDTExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
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
		*s11.BridgeTABasedMDTExtIEsExtContainerValueCodecFieldEncode(&sealed) = func(fields s11.TABasedMDTExtIEsExtContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s11.BridgeTABasedMDTExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
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
		*s11.BridgeTABasedMDTExtIEsExtContainerValueCodecFieldCapture(&sealed) = func(v s11.TABasedMDTExtIEsExtContainer, options aper.DecodeState) (s11.TABasedMDTExtIEsExtContainer, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeTABasedMDTExtIEsValueCaptureS1APProtocolExtensionContainer(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s11.BridgeTABasedMDTExtIEsExtContainerValueCodecFieldCompare(&sealed) = func(v s11.TABasedMDTExtIEsExtContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.
				Begin()
			BridgeTABasedMDTExtIEsValueCompareS1APProtocolExtensionContainer(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s11.BridgeTABasedMDTExtIEsExtContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}
func TABasedQMCExtIEsValueExtensionTableCodec(table s00.TABasedQMCExtIEsValueExtensionTable, bounds aper.ListBounds) s11.TABasedQMCExtIEsExtContainerValueCodec {
	if !*s00.BridgeTABasedQMCExtIEsValueExtensionTableFieldBound(&table) {
		return s11.TABasedQMCExtIEsExtContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s11.TABasedQMCExtIEsExtContainerValueCodec {
		sealed := s11.TABasedQMCExtIEsExtContainerValueCodec{}
		*s11.BridgeTABasedQMCExtIEsExtContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s11.TABasedQMCExtIEsExtContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s11.TABasedQMCExtIEsExtContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s11.TABasedQMCExtIEsExtField
					if err := s11.BridgeTABasedQMCExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
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
		*s11.BridgeTABasedQMCExtIEsExtContainerValueCodecFieldEncode(&sealed) = func(fields s11.TABasedQMCExtIEsExtContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s11.BridgeTABasedQMCExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
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
		*s11.BridgeTABasedQMCExtIEsExtContainerValueCodecFieldCapture(&sealed) = func(v s11.TABasedQMCExtIEsExtContainer, options aper.DecodeState) (s11.TABasedQMCExtIEsExtContainer, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeTABasedQMCExtIEsValueCaptureS1APProtocolExtensionContainer(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s11.BridgeTABasedQMCExtIEsExtContainerValueCodecFieldCompare(&sealed) = func(v s11.TABasedQMCExtIEsExtContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.
				Begin()
			BridgeTABasedQMCExtIEsValueCompareS1APProtocolExtensionContainer(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s11.BridgeTABasedQMCExtIEsExtContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}
func TAIBasedMDTExtIEsValueExtensionTableCodec(table s00.TAIBasedMDTExtIEsValueExtensionTable, bounds aper.ListBounds) s11.TAIBasedMDTExtIEsExtContainerValueCodec {
	if !*s00.BridgeTAIBasedMDTExtIEsValueExtensionTableFieldBound(&table) {
		return s11.TAIBasedMDTExtIEsExtContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s11.TAIBasedMDTExtIEsExtContainerValueCodec {
		sealed := s11.TAIBasedMDTExtIEsExtContainerValueCodec{}
		*s11.BridgeTAIBasedMDTExtIEsExtContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s11.TAIBasedMDTExtIEsExtContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s11.TAIBasedMDTExtIEsExtContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s11.TAIBasedMDTExtIEsExtField
					if err := s11.BridgeTAIBasedMDTExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
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
		*s11.BridgeTAIBasedMDTExtIEsExtContainerValueCodecFieldEncode(&sealed) = func(fields s11.TAIBasedMDTExtIEsExtContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s11.BridgeTAIBasedMDTExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
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
		*s11.BridgeTAIBasedMDTExtIEsExtContainerValueCodecFieldCapture(&sealed) = func(v s11.TAIBasedMDTExtIEsExtContainer, options aper.DecodeState) (s11.TAIBasedMDTExtIEsExtContainer, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeTAIBasedMDTExtIEsValueCaptureS1APProtocolExtensionContainer(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s11.BridgeTAIBasedMDTExtIEsExtContainerValueCodecFieldCompare(&sealed) = func(v s11.TAIBasedMDTExtIEsExtContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.
				Begin()
			BridgeTAIBasedMDTExtIEsValueCompareS1APProtocolExtensionContainer(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s11.BridgeTAIBasedMDTExtIEsExtContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}
func TAIBasedQMCExtIEsValueExtensionTableCodec(table s00.TAIBasedQMCExtIEsValueExtensionTable, bounds aper.ListBounds) s11.TAIBasedQMCExtIEsExtContainerValueCodec {
	if !*s00.BridgeTAIBasedQMCExtIEsValueExtensionTableFieldBound(&table) {
		return s11.TAIBasedQMCExtIEsExtContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s11.TAIBasedQMCExtIEsExtContainerValueCodec {
		sealed := s11.TAIBasedQMCExtIEsExtContainerValueCodec{}
		*s11.BridgeTAIBasedQMCExtIEsExtContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s11.TAIBasedQMCExtIEsExtContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s11.TAIBasedQMCExtIEsExtContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s11.TAIBasedQMCExtIEsExtField
					if err := s11.BridgeTAIBasedQMCExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
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
		*s11.BridgeTAIBasedQMCExtIEsExtContainerValueCodecFieldEncode(&sealed) = func(fields s11.TAIBasedQMCExtIEsExtContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s11.BridgeTAIBasedQMCExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
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
		*s11.BridgeTAIBasedQMCExtIEsExtContainerValueCodecFieldCapture(&sealed) = func(v s11.TAIBasedQMCExtIEsExtContainer, options aper.DecodeState) (s11.TAIBasedQMCExtIEsExtContainer, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeTAIBasedQMCExtIEsValueCaptureS1APProtocolExtensionContainer(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s11.BridgeTAIBasedQMCExtIEsExtContainerValueCodecFieldCompare(&sealed) = func(v s11.TAIBasedQMCExtIEsExtContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.
				Begin()
			BridgeTAIBasedQMCExtIEsValueCompareS1APProtocolExtensionContainer(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s11.BridgeTAIBasedQMCExtIEsExtContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}
func TAIBroadcastItemExtIEsValueExtensionTableCodec(table s00.TAIBroadcastItemExtIEsValueExtensionTable, bounds aper.ListBounds) s11.TAIBroadcastItemExtIEsExtContainerValueCodec {
	if !*s00.BridgeTAIBroadcastItemExtIEsValueExtensionTableFieldBound(&table) {
		return s11.TAIBroadcastItemExtIEsExtContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s11.TAIBroadcastItemExtIEsExtContainerValueCodec {
		sealed := s11.TAIBroadcastItemExtIEsExtContainerValueCodec{}
		*s11.BridgeTAIBroadcastItemExtIEsExtContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s11.TAIBroadcastItemExtIEsExtContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s11.TAIBroadcastItemExtIEsExtContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s11.TAIBroadcastItemExtIEsExtField
					if err := s11.BridgeTAIBroadcastItemExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
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
		*s11.BridgeTAIBroadcastItemExtIEsExtContainerValueCodecFieldEncode(&sealed) = func(fields s11.TAIBroadcastItemExtIEsExtContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s11.BridgeTAIBroadcastItemExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
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
		*s11.BridgeTAIBroadcastItemExtIEsExtContainerValueCodecFieldCapture(&sealed) = func(v s11.TAIBroadcastItemExtIEsExtContainer, options aper.DecodeState) (s11.TAIBroadcastItemExtIEsExtContainer, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeTAIBroadcastItemExtIEsValueCaptureS1APProtocolExtensionContainer(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s11.BridgeTAIBroadcastItemExtIEsExtContainerValueCodecFieldCompare(&sealed) = func(v s11.TAIBroadcastItemExtIEsExtContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.
				Begin()
			BridgeTAIBroadcastItemExtIEsValueCompareS1APProtocolExtensionContainer(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s11.BridgeTAIBroadcastItemExtIEsExtContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}
func TAICancelledItemExtIEsValueExtensionTableCodec(table s00.TAICancelledItemExtIEsValueExtensionTable, bounds aper.ListBounds) s11.TAICancelledItemExtIEsExtContainerValueCodec {
	if !*s00.BridgeTAICancelledItemExtIEsValueExtensionTableFieldBound(&table) {
		return s11.TAICancelledItemExtIEsExtContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s11.TAICancelledItemExtIEsExtContainerValueCodec {
		sealed := s11.TAICancelledItemExtIEsExtContainerValueCodec{}
		*s11.BridgeTAICancelledItemExtIEsExtContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s11.TAICancelledItemExtIEsExtContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s11.TAICancelledItemExtIEsExtContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s11.TAICancelledItemExtIEsExtField
					if err := s11.BridgeTAICancelledItemExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
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
		*s11.BridgeTAICancelledItemExtIEsExtContainerValueCodecFieldEncode(&sealed) = func(fields s11.TAICancelledItemExtIEsExtContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s11.BridgeTAICancelledItemExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
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
		*s11.BridgeTAICancelledItemExtIEsExtContainerValueCodecFieldCapture(&sealed) = func(v s11.TAICancelledItemExtIEsExtContainer, options aper.DecodeState) (s11.TAICancelledItemExtIEsExtContainer, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeTAICancelledItemExtIEsValueCaptureS1APProtocolExtensionContainer(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s11.BridgeTAICancelledItemExtIEsExtContainerValueCodecFieldCompare(&sealed) = func(v s11.TAICancelledItemExtIEsExtContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.
				Begin()
			BridgeTAICancelledItemExtIEsValueCompareS1APProtocolExtensionContainer(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s11.BridgeTAICancelledItemExtIEsExtContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}
func ConnectionEstablishmentIndicationIEValueIEFieldTableCodec(table s00.ConnectionEstablishmentIndicationIEValueIETable) s30.ConnectionEstablishmentIndicationIEFieldValueCodec {
	if !*s00.BridgeConnectionEstablishmentIndicationIEValueIETableFieldBound(&table) {
		return s30.ConnectionEstablishmentIndicationIEFieldValueCodec{}
	}
	return func() s30.ConnectionEstablishmentIndicationIEFieldValueCodec {
		sealed := s30.ConnectionEstablishmentIndicationIEFieldValueCodec{}
		*s30.BridgeConnectionEstablishmentIndicationIEFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s30.ConnectionEstablishmentIndicationIEField, error) {
			var field s30.ConnectionEstablishmentIndicationIEField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s30.BridgeConnectionEstablishmentIndicationIEFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, err
			}
			if _, err := aper.CaptureFinalBits(bb, "ProtocolIEField"); err != nil {
				return field, err
			}
			return field, nil
		}
		*s30.BridgeConnectionEstablishmentIndicationIEFieldValueCodecFieldEncode(&sealed) = func(field s30.ConnectionEstablishmentIndicationIEField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s30.BridgeConnectionEstablishmentIndicationIEFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s30.BridgeConnectionEstablishmentIndicationIEFieldValueCodecFieldCapture(&sealed) = func(v s30.ConnectionEstablishmentIndicationIEField, options aper.DecodeState) (s30.ConnectionEstablishmentIndicationIEField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeConnectionEstablishmentIndicationIEValueCaptureS1APProtocolIEField(&v,
				&s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v,
				root
		}
		*s30.BridgeConnectionEstablishmentIndicationIEFieldValueCodecFieldCompare(&sealed) = func(v s30.ConnectionEstablishmentIndicationIEField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeConnectionEstablishmentIndicationIEValueCompareS1APProtocolIEField(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s30.BridgeConnectionEstablishmentIndicationIEFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}
func ConnectionEstablishmentIndicationIEValueIETableCodec(table s00.ConnectionEstablishmentIndicationIEValueIETable, bounds aper.ListBounds) s30.ConnectionEstablishmentIndicationIEContainerValueCodec {
	if !*s00.BridgeConnectionEstablishmentIndicationIEValueIETableFieldBound(&table) {
		return s30.ConnectionEstablishmentIndicationIEContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s30.ConnectionEstablishmentIndicationIEContainerValueCodec {
		sealed := s30.ConnectionEstablishmentIndicationIEContainerValueCodec{}
		*s30.BridgeConnectionEstablishmentIndicationIEContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s30.ConnectionEstablishmentIndicationIEContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s30.ConnectionEstablishmentIndicationIEContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s30.ConnectionEstablishmentIndicationIEField
					if err := s30.BridgeConnectionEstablishmentIndicationIEFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
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
		*s30.BridgeConnectionEstablishmentIndicationIEContainerValueCodecFieldEncode(&sealed) = func(fields s30.ConnectionEstablishmentIndicationIEContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s30.BridgeConnectionEstablishmentIndicationIEFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
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
		*s30.BridgeConnectionEstablishmentIndicationIEContainerValueCodecFieldCapture(&sealed) = func(v s30.ConnectionEstablishmentIndicationIEContainer, options aper.DecodeState) (s30.ConnectionEstablishmentIndicationIEContainer, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeConnectionEstablishmentIndicationIEValueCaptureS1APProtocolIEContainer(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s30.BridgeConnectionEstablishmentIndicationIEContainerValueCodecFieldCompare(&sealed) = func(v s30.ConnectionEstablishmentIndicationIEContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeConnectionEstablishmentIndicationIEValueCompareS1APProtocolIEContainer(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s30.BridgeConnectionEstablishmentIndicationIEContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}
func ConnectionEstablishmentIndicationIEValueProtocolErrorIEContainerListCodec(table s00.ConnectionEstablishmentIndicationIEValueIETable) ConnectionEstablishmentIndicationIEValueProtocolErrorIEContainerListValueCodec {
	codec := ConnectionEstablishmentIndicationIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if *s30.BridgeConnectionEstablishmentIndicationIEContainerValueCodecFieldDecode(&codec) == nil {
		return ConnectionEstablishmentIndicationIEValueProtocolErrorIEContainerListValueCodec{}
	}
	return ConnectionEstablishmentIndicationIEValueProtocolErrorIEContainerListValueCodec{decode: func(data []byte, options aper.DecodeState) (ConnectionEstablishmentIndicationIEValueProtocolErrorIEContainerList, error) {
		value, err := (*s30.BridgeConnectionEstablishmentIndicationIEContainerValueCodecFieldDecode(&codec))(data, options)
		return ConnectionEstablishmentIndicationIEValueProtocolErrorIEContainerList(value), err
	}, encode: func(value ConnectionEstablishmentIndicationIEValueProtocolErrorIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return (*s30.BridgeConnectionEstablishmentIndicationIEContainerValueCodecFieldEncode(&codec))(s30.ConnectionEstablishmentIndicationIEContainer(value), fresh, budget)
	}, capture: func(v ConnectionEstablishmentIndicationIEValueProtocolErrorIEContainerList, options aper.DecodeState) (ConnectionEstablishmentIndicationIEValueProtocolErrorIEContainerList, aper.Snapshot,
	) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeConnectionEstablishmentIndicationIEValueCaptureS1APProtocolErrorIEContainerList(&v, &s)
		var root aper.Snapshot

		s.End(f, &root, false)
		return v, root
	}, compare: func(v ConnectionEstablishmentIndicationIEValueProtocolErrorIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

	) {
		s := aper.NewSemanticComparison(root, budget)
		f :=
			s.
				Begin()
		BridgeConnectionEstablishmentIndicationIEValueCompareS1APProtocolErrorIEContainerList(&v, &s)
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
func ConnectionEstablishmentIndicationIEValueProtocolIEContainerListCodec(table s00.ConnectionEstablishmentIndicationIEValueIETable, bounds aper.ListBounds) ConnectionEstablishmentIndicationIEValueProtocolIEContainerListValueCodec {
	codec := ConnectionEstablishmentIndicationIEValueIETableCodec(table, bounds)
	if *s30.BridgeConnectionEstablishmentIndicationIEContainerValueCodecFieldDecode(&codec) == nil {
		return ConnectionEstablishmentIndicationIEValueProtocolIEContainerListValueCodec{}
	}
	return ConnectionEstablishmentIndicationIEValueProtocolIEContainerListValueCodec{decode: func(data []byte, options aper.DecodeState) (ConnectionEstablishmentIndicationIEValueProtocolIEContainerList, error) {
		value, err := (*s30.BridgeConnectionEstablishmentIndicationIEContainerValueCodecFieldDecode(&codec))(data, options)
		return ConnectionEstablishmentIndicationIEValueProtocolIEContainerList(value), err
	}, encode: func(value ConnectionEstablishmentIndicationIEValueProtocolIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return (*s30.BridgeConnectionEstablishmentIndicationIEContainerValueCodecFieldEncode(&codec))(s30.ConnectionEstablishmentIndicationIEContainer(value), fresh, budget)
	}, capture: func(v ConnectionEstablishmentIndicationIEValueProtocolIEContainerList, options aper.DecodeState) (ConnectionEstablishmentIndicationIEValueProtocolIEContainerList, aper.Snapshot,
	) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeConnectionEstablishmentIndicationIEValueCaptureS1APProtocolIEContainerList(&v, &s)
		var root aper.Snapshot
		s.End(
			f,
			&root, false)
		return v, root
	}, compare: func(v ConnectionEstablishmentIndicationIEValueProtocolIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
	) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		BridgeConnectionEstablishmentIndicationIEValueCompareS1APProtocolIEContainerList(&v, &s)
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

// connectionEstablishmentIndicationIEValueProtocolOpenValue is the concrete protocolOpenValue[ConnectionEstablishmentIndicationIEValue].
type ConnectionEstablishmentIndicationIEValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) s30.ConnectionEstablishmentIndicationIEValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (s30.ConnectionEstablishmentIndicationIEValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

func BridgeConnectionEstablishmentIndicationIEValueCaptureS1APProtocolIEField(v *s30.ConnectionEstablishmentIndicationIEField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolIEID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.Value = s30.BridgeConnectionEstablishmentIndicationIEValueMethodCaptureSemantics(v.Value, *s)
	s.End(f, s30.BridgeConnectionEstablishmentIndicationIEFieldFieldReplay(v), *s30.BridgeConnectionEstablishmentIndicationIEFieldFieldWithoutReplay(v))
}
func BridgeConnectionEstablishmentIndicationIEValueCompareS1APProtocolIEField(v *s30.ConnectionEstablishmentIndicationIEField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s02.BridgeCompareS1APProtocolIEID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s30.BridgeConnectionEstablishmentIndicationIEValueMethodCompareSemantics(v.Value, *s)
	s.End(f, *s30.BridgeConnectionEstablishmentIndicationIEFieldFieldReplay(v), *s30.BridgeConnectionEstablishmentIndicationIEFieldFieldWithoutReplay(v))
}

// subscriptionBasedUEDifferentiationInfoExtIEsValueProtocolOpenValue is the concrete protocolOpenValue[SubscriptionBasedUEDifferentiationInfoExtIEsValue].
type SubscriptionBasedUEDifferentiationInfoExtIEsValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) s06.SubscriptionBasedUEDifferentiationInfoExtIEsValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (s06.SubscriptionBasedUEDifferentiationInfoExtIEsValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

// supportedTAsItemExtIEsValueProtocolOpenValue is the concrete protocolOpenValue[SupportedTAsItemExtIEsValue].
type SupportedTAsItemExtIEsValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) s06.SupportedTAsItemExtIEsValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (s06.SupportedTAsItemExtIEsValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

func BridgeSupportedTAsItemExtIEsValueCaptureS1APProtocolExtensionField(v *s11.SupportedTAsItemExtIEsExtField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolExtensionID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.ExtensionValue = s06.BridgeSupportedTAsItemExtIEsValueMethodCaptureSemantics(v.ExtensionValue, *s)
	s.End(f, s11.BridgeSupportedTAsItemExtIEsExtFieldFieldReplay(v), *s11.BridgeSupportedTAsItemExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeSupportedTAsItemExtIEsValueCompareS1APProtocolExtensionField(v *s11.SupportedTAsItemExtIEsExtField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s02.BridgeCompareS1APProtocolExtensionID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s06.BridgeSupportedTAsItemExtIEsValueMethodCompareSemantics(v.ExtensionValue, *s)
	s.End(f, *s11.BridgeSupportedTAsItemExtIEsExtFieldFieldReplay(v), *s11.BridgeSupportedTAsItemExtIEsExtFieldFieldWithoutReplay(v))
}

// synchronisationInformationExtIEsValueProtocolOpenValue is the concrete protocolOpenValue[SynchronisationInformationExtIEsValue].
type SynchronisationInformationExtIEsValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) s06.SynchronisationInformationExtIEsValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (s06.SynchronisationInformationExtIEsValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

func BridgeSynchronisationInformationExtIEsValueCaptureS1APProtocolExtensionField(v *s11.SynchronisationInformationExtIEsExtField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolExtensionID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.ExtensionValue = s06.BridgeSynchronisationInformationExtIEsValueMethodCaptureSemantics(v.ExtensionValue, *s)
	s.End(f, s11.BridgeSynchronisationInformationExtIEsExtFieldFieldReplay(v), *s11.BridgeSynchronisationInformationExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeSynchronisationInformationExtIEsValueCompareS1APProtocolExtensionField(v *s11.SynchronisationInformationExtIEsExtField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s02.BridgeCompareS1APProtocolExtensionID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s06.BridgeSynchronisationInformationExtIEsValueMethodCompareSemantics(v.ExtensionValue, *s)
	s.End(f, *s11.BridgeSynchronisationInformationExtIEsExtFieldFieldReplay(v), *s11.BridgeSynchronisationInformationExtIEsExtFieldFieldWithoutReplay(v))
}

// tABasedMDTExtIEsValueProtocolOpenValue is the concrete protocolOpenValue[TABasedMDTExtIEsValue].
type TABasedMDTExtIEsValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) s06.TABasedMDTExtIEsValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (s06.TABasedMDTExtIEsValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

func BridgeTABasedMDTExtIEsValueCaptureS1APProtocolExtensionField(v *s11.TABasedMDTExtIEsExtField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolExtensionID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.ExtensionValue = s06.BridgeTABasedMDTExtIEsValueMethodCaptureSemantics(v.ExtensionValue, *s)
	s.End(f, s11.BridgeTABasedMDTExtIEsExtFieldFieldReplay(v), *s11.BridgeTABasedMDTExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeTABasedMDTExtIEsValueCompareS1APProtocolExtensionField(v *s11.TABasedMDTExtIEsExtField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s02.BridgeCompareS1APProtocolExtensionID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s06.BridgeTABasedMDTExtIEsValueMethodCompareSemantics(v.ExtensionValue, *s)
	s.End(f, *s11.BridgeTABasedMDTExtIEsExtFieldFieldReplay(v), *s11.BridgeTABasedMDTExtIEsExtFieldFieldWithoutReplay(v))
}

// tABasedQMCExtIEsValueProtocolOpenValue is the concrete protocolOpenValue[TABasedQMCExtIEsValue].
type TABasedQMCExtIEsValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) s06.TABasedQMCExtIEsValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (s06.TABasedQMCExtIEsValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

func BridgeTABasedQMCExtIEsValueCaptureS1APProtocolExtensionField(v *s11.TABasedQMCExtIEsExtField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolExtensionID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.ExtensionValue = s06.BridgeTABasedQMCExtIEsValueMethodCaptureSemantics(v.ExtensionValue, *s)
	s.End(f, s11.BridgeTABasedQMCExtIEsExtFieldFieldReplay(v), *s11.BridgeTABasedQMCExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeTABasedQMCExtIEsValueCompareS1APProtocolExtensionField(v *s11.TABasedQMCExtIEsExtField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s02.BridgeCompareS1APProtocolExtensionID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s06.BridgeTABasedQMCExtIEsValueMethodCompareSemantics(v.ExtensionValue, *s)
	s.End(f, *s11.BridgeTABasedQMCExtIEsExtFieldFieldReplay(v), *s11.BridgeTABasedQMCExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeTAIExtIEsValueCaptureS1APProtocolExtensionField(v *s11.TAIExtIEsExtField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolExtensionID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.ExtensionValue = s06.BridgeTAIExtIEsValueMethodCaptureSemantics(v.ExtensionValue, *s)
	s.End(f, s11.BridgeTAIExtIEsExtFieldFieldReplay(v), *s11.BridgeTAIExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeTAIExtIEsValueCompareS1APProtocolExtensionField(v *s11.TAIExtIEsExtField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s02.BridgeCompareS1APProtocolExtensionID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s06.BridgeTAIExtIEsValueMethodCompareSemantics(v.ExtensionValue, *s)
	s.End(f, *s11.BridgeTAIExtIEsExtFieldFieldReplay(v), *s11.BridgeTAIExtIEsExtFieldFieldWithoutReplay(v))
}

// tAIBasedMDTExtIEsValueProtocolOpenValue is the concrete protocolOpenValue[TAIBasedMDTExtIEsValue].
type TAIBasedMDTExtIEsValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) s06.TAIBasedMDTExtIEsValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (s06.TAIBasedMDTExtIEsValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

func BridgeTAIBasedMDTExtIEsValueCaptureS1APProtocolExtensionField(v *s11.TAIBasedMDTExtIEsExtField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolExtensionID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.ExtensionValue = s06.BridgeTAIBasedMDTExtIEsValueMethodCaptureSemantics(v.ExtensionValue, *s)
	s.End(f, s11.BridgeTAIBasedMDTExtIEsExtFieldFieldReplay(v), *s11.BridgeTAIBasedMDTExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeTAIBasedMDTExtIEsValueCompareS1APProtocolExtensionField(v *s11.TAIBasedMDTExtIEsExtField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s02.BridgeCompareS1APProtocolExtensionID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s06.BridgeTAIBasedMDTExtIEsValueMethodCompareSemantics(v.ExtensionValue, *s)
	s.End(f, *s11.BridgeTAIBasedMDTExtIEsExtFieldFieldReplay(v), *s11.BridgeTAIBasedMDTExtIEsExtFieldFieldWithoutReplay(v))
}

// tAIBasedQMCExtIEsValueProtocolOpenValue is the concrete protocolOpenValue[TAIBasedQMCExtIEsValue].
type TAIBasedQMCExtIEsValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) s06.TAIBasedQMCExtIEsValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (s06.TAIBasedQMCExtIEsValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

func BridgeTAIBasedQMCExtIEsValueCaptureS1APProtocolExtensionField(v *s11.TAIBasedQMCExtIEsExtField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolExtensionID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.ExtensionValue = s06.BridgeTAIBasedQMCExtIEsValueMethodCaptureSemantics(v.ExtensionValue, *s)
	s.End(f, s11.BridgeTAIBasedQMCExtIEsExtFieldFieldReplay(v), *s11.BridgeTAIBasedQMCExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeTAIBasedQMCExtIEsValueCompareS1APProtocolExtensionField(v *s11.TAIBasedQMCExtIEsExtField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s02.BridgeCompareS1APProtocolExtensionID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s06.BridgeTAIBasedQMCExtIEsValueMethodCompareSemantics(v.ExtensionValue, *s)
	s.End(f, *s11.BridgeTAIBasedQMCExtIEsExtFieldFieldReplay(v), *s11.BridgeTAIBasedQMCExtIEsExtFieldFieldWithoutReplay(v))
}

// tAIBroadcastItemExtIEsValueProtocolOpenValue is the concrete protocolOpenValue[TAIBroadcastItemExtIEsValue].
type TAIBroadcastItemExtIEsValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) s06.TAIBroadcastItemExtIEsValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (s06.TAIBroadcastItemExtIEsValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

func BridgeTAIBroadcastItemExtIEsValueCaptureS1APProtocolExtensionField(v *s11.TAIBroadcastItemExtIEsExtField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolExtensionID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.ExtensionValue = s06.BridgeTAIBroadcastItemExtIEsValueMethodCaptureSemantics(v.ExtensionValue, *s)
	s.End(f, s11.BridgeTAIBroadcastItemExtIEsExtFieldFieldReplay(v), *s11.BridgeTAIBroadcastItemExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeTAIBroadcastItemExtIEsValueCompareS1APProtocolExtensionField(v *s11.TAIBroadcastItemExtIEsExtField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s02.BridgeCompareS1APProtocolExtensionID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s06.BridgeTAIBroadcastItemExtIEsValueMethodCompareSemantics(v.ExtensionValue, *s)
	s.End(f, *s11.BridgeTAIBroadcastItemExtIEsExtFieldFieldReplay(v), *s11.BridgeTAIBroadcastItemExtIEsExtFieldFieldWithoutReplay(v))
}

// tAICancelledItemExtIEsValueProtocolOpenValue is the concrete protocolOpenValue[TAICancelledItemExtIEsValue].
type TAICancelledItemExtIEsValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) s06.TAICancelledItemExtIEsValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (s06.TAICancelledItemExtIEsValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

func BridgeTAICancelledItemExtIEsValueCaptureS1APProtocolExtensionField(v *s11.TAICancelledItemExtIEsExtField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolExtensionID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.ExtensionValue = s06.BridgeTAICancelledItemExtIEsValueMethodCaptureSemantics(v.ExtensionValue, *s)
	s.End(f, s11.BridgeTAICancelledItemExtIEsExtFieldFieldReplay(v), *s11.BridgeTAICancelledItemExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeTAICancelledItemExtIEsValueCompareS1APProtocolExtensionField(v *s11.TAICancelledItemExtIEsExtField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s02.BridgeCompareS1APProtocolExtensionID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s06.BridgeTAICancelledItemExtIEsValueMethodCompareSemantics(v.ExtensionValue, *s)
	s.End(f, *s11.BridgeTAICancelledItemExtIEsExtFieldFieldReplay(v), *s11.BridgeTAICancelledItemExtIEsExtFieldFieldWithoutReplay(v))
}

// RecommendedENBItemAPERValue is the concrete APERValue[RecommendedENBItem].
type RecommendedENBItemAPERValue struct {
	context s00.BridgeCodecContext
	Value   RecommendedENBItem

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v RecommendedENBItemAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v RecommendedENBItemAPERValue) WithoutReplay() RecommendedENBItemAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// SynchronisationInformationAPERValue is the concrete APERValue[SynchronisationInformation].
type SynchronisationInformationAPERValue struct {
	context s00.BridgeCodecContext
	Value   SynchronisationInformation

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v SynchronisationInformationAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v SynchronisationInformationAPERValue) WithoutReplay() SynchronisationInformationAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// SubscriptionBasedUEDifferentiationInfoAPERValue is the concrete APERValue[SubscriptionBasedUEDifferentiationInfo].
type SubscriptionBasedUEDifferentiationInfoAPERValue struct {
	context s00.BridgeCodecContext
	Value   s30.SubscriptionBasedUEDifferentiationInfo

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v SubscriptionBasedUEDifferentiationInfoAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v SubscriptionBasedUEDifferentiationInfoAPERValue) WithoutReplay() SubscriptionBasedUEDifferentiationInfoAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// SupportedTAsAPERValue is the concrete APERValue[SupportedTAs].
type SupportedTAsAPERValue struct {
	context s00.BridgeCodecContext
	Value   SupportedTAs

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v SupportedTAsAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v SupportedTAsAPERValue) WithoutReplay() SupportedTAsAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ConnectedengNBListAPERValue is the concrete APERValue[ConnectedengNBList].
type ConnectedengNBListAPERValue struct {
	context s00.BridgeCodecContext
	Value   ConnectedengNBList

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ConnectedengNBListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ConnectedengNBListAPERValue) WithoutReplay() ConnectedengNBListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ConnectedengNBItemAPERValue is the concrete APERValue[ConnectedengNBItem].
type ConnectedengNBItemAPERValue struct {
	context s00.BridgeCodecContext
	Value   ConnectedengNBItem

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ConnectedengNBItemAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ConnectedengNBItemAPERValue) WithoutReplay() ConnectedengNBItemAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ConnectionEstablishmentIndicationAPERValue is the concrete APERValue[ConnectionEstablishmentIndication].
type ConnectionEstablishmentIndicationAPERValue struct {
	context s00.BridgeCodecContext
	Value   ConnectionEstablishmentIndication

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ConnectionEstablishmentIndicationAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ConnectionEstablishmentIndicationAPERValue) WithoutReplay() ConnectionEstablishmentIndicationAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ENDCSONTransferTypeAPERValue is the concrete APERValue[ENDCSONTransferType].
type ENDCSONTransferTypeAPERValue struct {
	context s00.BridgeCodecContext
	Value   ENDCSONTransferType

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ENDCSONTransferTypeAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ENDCSONTransferTypeAPERValue) WithoutReplay() ENDCSONTransferTypeAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ENDCSONeNBIdentificationAPERValue is the concrete APERValue[ENDCSONeNBIdentification].
type ENDCSONeNBIdentificationAPERValue struct {
	context s00.BridgeCodecContext
	Value   ENDCSONeNBIdentification

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ENDCSONeNBIdentificationAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ENDCSONeNBIdentificationAPERValue) WithoutReplay() ENDCSONeNBIdentificationAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ENDCSONengNBIdentificationAPERValue is the concrete APERValue[ENDCSONengNBIdentification].
type ENDCSONengNBIdentificationAPERValue struct {
	context s00.BridgeCodecContext
	Value   ENDCSONengNBIdentification

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ENDCSONengNBIdentificationAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ENDCSONengNBIdentificationAPERValue) WithoutReplay() ENDCSONengNBIdentificationAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ENDCTransferTypeReplyAPERValue is the concrete APERValue[ENDCTransferTypeReply].
type ENDCTransferTypeReplyAPERValue struct {
	context s00.BridgeCodecContext
	Value   ENDCTransferTypeReply

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ENDCTransferTypeReplyAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ENDCTransferTypeReplyAPERValue) WithoutReplay() ENDCTransferTypeReplyAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ENDCTransferTypeRequestAPERValue is the concrete APERValue[ENDCTransferTypeRequest].
type ENDCTransferTypeRequestAPERValue struct {
	context s00.BridgeCodecContext
	Value   ENDCTransferTypeRequest

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ENDCTransferTypeRequestAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ENDCTransferTypeRequestAPERValue) WithoutReplay() ENDCTransferTypeRequestAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// MMEPagingTargetAPERValue is the concrete APERValue[MMEPagingTarget].
type MMEPagingTargetAPERValue struct {
	context s00.BridgeCodecContext
	Value   MMEPagingTarget

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v MMEPagingTargetAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v MMEPagingTargetAPERValue) WithoutReplay() MMEPagingTargetAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// SupportedTAsItemAPERValue is the concrete APERValue[SupportedTAsItem].
type SupportedTAsItemAPERValue struct {
	context s00.BridgeCodecContext
	Value   SupportedTAsItem

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v SupportedTAsItemAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v SupportedTAsItemAPERValue) WithoutReplay() SupportedTAsItemAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// TABasedMDTAPERValue is the concrete APERValue[TABasedMDT].
type TABasedMDTAPERValue struct {
	context s00.BridgeCodecContext
	Value   TABasedMDT

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v TABasedMDTAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v TABasedMDTAPERValue) WithoutReplay() TABasedMDTAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// TABasedQMCAPERValue is the concrete APERValue[TABasedQMC].
type TABasedQMCAPERValue struct {
	context s00.BridgeCodecContext
	Value   TABasedQMC

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v TABasedQMCAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v TABasedQMCAPERValue) WithoutReplay() TABasedQMCAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// TS 36.413 V19.2.0 §§9.3.3–9.3.4 supply the selected object-set order and
// presence. §§10.3.1–10.3.6 define abstract-syntax diagnostics. Unknown IEs do
// not determine the order of known rows.
func BridgeSubscriptionBasedUEDifferentiationInfoExtIEsValueValidateS1APIEContainer(fields s11.SubscriptionBasedUEDifferentiationInfoExtIEsIEContainer, rows []s00.FieldInfo, path string, budget *aper.DecodeBudget,

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
		if !s06.BridgeSubscriptionBasedUEDifferentiationInfoExtIEsValueMethodMatchesID(field.Value, field.Id, budget) {
			rule := s06.BridgeSubscriptionBasedUEDifferentiationInfoExtIEsValueMethodRule(field.Value)
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.ValueIDMismatch, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: aper.Path(fmt.Sprintf("%s.id", location.Path))}, Table: func() s00.TableID {
				sealed := s00.TableID{}
				*s00.BridgeTableIDFieldSource(&sealed) = rule.Assignment
				return sealed
			}(), IEID: field.Id, HasIEID: true, Rule: s26.BridgeS1apValidationRule(s00.ValueIDMismatch), RelatedRules: []aper.SourceRule{rule}})
		}
		rank, allowed := byID[field.Id]
		table := func() s00.TableID {
			sealed := s00.TableID{}
			*s00.BridgeTableIDFieldSource(&sealed) = s06.BridgeSubscriptionBasedUEDifferentiationInfoExtIEsValueMethodRule(field.Value).Assignment
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
func BridgeSupportedTAsItemExtIEsValueValidateS1APIEContainer(fields s11.SupportedTAsItemExtIEsIEContainer, rows []s00.FieldInfo, path string, budget *aper.DecodeBudget,

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
		if !s06.BridgeSupportedTAsItemExtIEsValueMethodMatchesID(field.Value, field.Id, budget) {
			rule := s06.BridgeSupportedTAsItemExtIEsValueMethodRule(field.Value)
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.ValueIDMismatch, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: aper.Path(fmt.Sprintf("%s.id", location.Path))}, Table: func() s00.TableID {
				sealed := s00.TableID{}
				*s00.BridgeTableIDFieldSource(&sealed) = rule.Assignment
				return sealed
			}(), IEID: field.Id, HasIEID: true, Rule: s26.BridgeS1apValidationRule(s00.ValueIDMismatch), RelatedRules: []aper.SourceRule{rule}})
		}
		rank, allowed := byID[field.Id]
		table := func() s00.TableID {
			sealed := s00.TableID{}
			*s00.BridgeTableIDFieldSource(&sealed) = s06.BridgeSupportedTAsItemExtIEsValueMethodRule(field.Value).Assignment
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
func BridgeSynchronisationInformationExtIEsValueValidateS1APIEContainer(fields s11.SynchronisationInformationExtIEsIEContainer, rows []s00.FieldInfo, path string, budget *aper.DecodeBudget,

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
		if !s06.BridgeSynchronisationInformationExtIEsValueMethodMatchesID(field.Value, field.Id, budget) {
			rule := s06.BridgeSynchronisationInformationExtIEsValueMethodRule(field.Value)
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.ValueIDMismatch, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: aper.Path(fmt.Sprintf("%s.id", location.Path))}, Table: func() s00.TableID {
				sealed := s00.TableID{}
				*s00.BridgeTableIDFieldSource(&sealed) = rule.Assignment
				return sealed
			}(), IEID: field.Id, HasIEID: true, Rule: s26.BridgeS1apValidationRule(s00.ValueIDMismatch), RelatedRules: []aper.SourceRule{rule}})
		}
		rank, allowed := byID[field.Id]
		table := func() s00.TableID {
			sealed := s00.TableID{}
			*s00.BridgeTableIDFieldSource(&sealed) = s06.BridgeSynchronisationInformationExtIEsValueMethodRule(field.Value).Assignment
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
func BridgeTABasedMDTExtIEsValueValidateS1APIEContainer(fields s11.TABasedMDTExtIEsIEContainer, rows []s00.FieldInfo, path string, budget *aper.DecodeBudget,

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
		if !s06.BridgeTABasedMDTExtIEsValueMethodMatchesID(field.Value, field.Id, budget) {
			rule := s06.BridgeTABasedMDTExtIEsValueMethodRule(field.Value)
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.ValueIDMismatch, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: aper.Path(fmt.Sprintf("%s.id", location.Path))}, Table: func() s00.TableID {
				sealed := s00.TableID{}
				*s00.BridgeTableIDFieldSource(&sealed) = rule.Assignment
				return sealed
			}(), IEID: field.Id, HasIEID: true, Rule: s26.BridgeS1apValidationRule(s00.ValueIDMismatch), RelatedRules: []aper.SourceRule{rule}})
		}
		rank, allowed := byID[field.Id]
		table := func() s00.TableID {
			sealed := s00.TableID{}
			*s00.BridgeTableIDFieldSource(&sealed) = s06.BridgeTABasedMDTExtIEsValueMethodRule(field.Value).Assignment
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
func BridgeTABasedQMCExtIEsValueValidateS1APIEContainer(fields s11.TABasedQMCExtIEsIEContainer, rows []s00.FieldInfo, path string, budget *aper.DecodeBudget,

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
		if !s06.BridgeTABasedQMCExtIEsValueMethodMatchesID(field.Value, field.Id, budget) {
			rule := s06.BridgeTABasedQMCExtIEsValueMethodRule(field.Value)
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.ValueIDMismatch, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: aper.Path(fmt.Sprintf("%s.id", location.Path))}, Table: func() s00.TableID {
				sealed := s00.TableID{}
				*s00.BridgeTableIDFieldSource(&sealed) = rule.Assignment
				return sealed
			}(), IEID: field.Id, HasIEID: true, Rule: s26.BridgeS1apValidationRule(s00.ValueIDMismatch), RelatedRules: []aper.SourceRule{rule}})
		}
		rank, allowed := byID[field.Id]
		table := func() s00.TableID {
			sealed := s00.TableID{}
			*s00.BridgeTableIDFieldSource(&sealed) = s06.BridgeTABasedQMCExtIEsValueMethodRule(field.Value).Assignment
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
func BridgeTAIBasedMDTExtIEsValueValidateS1APIEContainer(fields s11.TAIBasedMDTExtIEsIEContainer, rows []s00.FieldInfo, path string, budget *aper.DecodeBudget,

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
		if !s06.BridgeTAIBasedMDTExtIEsValueMethodMatchesID(field.Value, field.Id, budget) {
			rule := s06.BridgeTAIBasedMDTExtIEsValueMethodRule(field.Value)
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.ValueIDMismatch, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: aper.Path(fmt.Sprintf("%s.id", location.Path))}, Table: func() s00.TableID {
				sealed := s00.TableID{}
				*s00.BridgeTableIDFieldSource(&sealed) = rule.Assignment
				return sealed
			}(), IEID: field.Id, HasIEID: true, Rule: s26.BridgeS1apValidationRule(s00.ValueIDMismatch), RelatedRules: []aper.SourceRule{rule}})
		}
		rank, allowed := byID[field.Id]
		table := func() s00.TableID {
			sealed := s00.TableID{}
			*s00.BridgeTableIDFieldSource(&sealed) = s06.BridgeTAIBasedMDTExtIEsValueMethodRule(field.Value).Assignment
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
func BridgeTAIBasedQMCExtIEsValueValidateS1APIEContainer(fields s11.TAIBasedQMCExtIEsIEContainer, rows []s00.FieldInfo, path string, budget *aper.DecodeBudget,

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
		if !s06.BridgeTAIBasedQMCExtIEsValueMethodMatchesID(field.Value, field.Id, budget) {
			rule := s06.BridgeTAIBasedQMCExtIEsValueMethodRule(field.Value)
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.ValueIDMismatch, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: aper.Path(fmt.Sprintf("%s.id", location.Path))}, Table: func() s00.TableID {
				sealed := s00.TableID{}
				*s00.BridgeTableIDFieldSource(&sealed) = rule.Assignment
				return sealed
			}(), IEID: field.Id, HasIEID: true, Rule: s26.BridgeS1apValidationRule(s00.ValueIDMismatch), RelatedRules: []aper.SourceRule{rule}})
		}
		rank, allowed := byID[field.Id]
		table := func() s00.TableID {
			sealed := s00.TableID{}
			*s00.BridgeTableIDFieldSource(&sealed) = s06.BridgeTAIBasedQMCExtIEsValueMethodRule(field.Value).Assignment
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
func BridgeTAIBroadcastItemExtIEsValueValidateS1APIEContainer(fields s11.TAIBroadcastItemExtIEsIEContainer, rows []s00.FieldInfo, path string, budget *aper.DecodeBudget,

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
		if !s06.BridgeTAIBroadcastItemExtIEsValueMethodMatchesID(field.Value, field.Id, budget) {
			rule := s06.BridgeTAIBroadcastItemExtIEsValueMethodRule(field.Value)
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.ValueIDMismatch, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: aper.Path(fmt.Sprintf("%s.id", location.Path))}, Table: func() s00.TableID {
				sealed := s00.TableID{}
				*s00.BridgeTableIDFieldSource(&sealed) = rule.Assignment
				return sealed
			}(), IEID: field.Id, HasIEID: true, Rule: s26.BridgeS1apValidationRule(s00.ValueIDMismatch), RelatedRules: []aper.SourceRule{rule}})
		}
		rank, allowed := byID[field.Id]
		table := func() s00.TableID {
			sealed := s00.TableID{}
			*s00.BridgeTableIDFieldSource(&sealed) = s06.BridgeTAIBroadcastItemExtIEsValueMethodRule(field.Value).Assignment
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
func BridgeTAICancelledItemExtIEsValueValidateS1APIEContainer(fields s11.TAICancelledItemExtIEsIEContainer, rows []s00.FieldInfo, path string, budget *aper.DecodeBudget,

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
		if !s06.BridgeTAICancelledItemExtIEsValueMethodMatchesID(field.Value, field.Id, budget) {
			rule := s06.BridgeTAICancelledItemExtIEsValueMethodRule(field.Value)
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.ValueIDMismatch, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: aper.Path(fmt.Sprintf("%s.id", location.Path))}, Table: func() s00.TableID {
				sealed := s00.TableID{}
				*s00.BridgeTableIDFieldSource(&sealed) = rule.Assignment
				return sealed
			}(), IEID: field.Id, HasIEID: true, Rule: s26.BridgeS1apValidationRule(s00.ValueIDMismatch), RelatedRules: []aper.SourceRule{rule}})
		}
		rank, allowed := byID[field.Id]
		table := func() s00.TableID {
			sealed := s00.TableID{}
			*s00.BridgeTableIDFieldSource(&sealed) = s06.BridgeTAICancelledItemExtIEsValueMethodRule(field.Value).Assignment
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

// ConnectionEstablishmentIndicationIEValueERABIEContainerListValueCodec is the concrete ValueCodec[ERABIEContainerList[ConnectionEstablishmentIndicationIEValue]].
type ConnectionEstablishmentIndicationIEValueERABIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (s30.ConnectionEstablishmentIndicationIEValueERABIEContainerList, error)
	encode  func(s30.ConnectionEstablishmentIndicationIEValueERABIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(s30.ConnectionEstablishmentIndicationIEValueERABIEContainerList, aper.DecodeState) (s30.ConnectionEstablishmentIndicationIEValueERABIEContainerList, aper.Snapshot)
	compare func(s30.ConnectionEstablishmentIndicationIEValueERABIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ConnectionEstablishmentIndicationIEValueERABIEContainerListValueCodec) New(value s30.ConnectionEstablishmentIndicationIEValueERABIEContainerList) (s30.ConnectionEstablishmentIndicationIEValueERABIEContainerListAPERValue, error) {
	if c.encode == nil {
		return s30.ConnectionEstablishmentIndicationIEValueERABIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return s30.ConnectionEstablishmentIndicationIEValueERABIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return s30.ConnectionEstablishmentIndicationIEValueERABIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return s30.ConnectionEstablishmentIndicationIEValueERABIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ConnectionEstablishmentIndicationIEValueERABIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (s30.ConnectionEstablishmentIndicationIEValueERABIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return s30.ConnectionEstablishmentIndicationIEValueERABIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return s30.ConnectionEstablishmentIndicationIEValueERABIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return func() s30.ConnectionEstablishmentIndicationIEValueERABIEContainerListAPERValue {
			sealed := s30.ConnectionEstablishmentIndicationIEValueERABIEContainerListAPERValue{Value: value}
			*s30.BridgeConnectionEstablishmentIndicationIEValueERABIEContainerListAPERValueFieldReceived(&sealed) = aper.OriginalWire(data)
			*s30.BridgeConnectionEstablishmentIndicationIEValueERABIEContainerListAPERValueFieldReplay(&sealed) = replay
			*s30.BridgeConnectionEstablishmentIndicationIEValueERABIEContainerListAPERValueFieldContext(&sealed) = c.context
			return sealed
		}(), report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return s30.ConnectionEstablishmentIndicationIEValueERABIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ConnectionEstablishmentIndicationIEValueERABIEContainerListValueCodec) EncodeAPER(value s30.ConnectionEstablishmentIndicationIEValueERABIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := *s30.BridgeConnectionEstablishmentIndicationIEValueERABIEContainerListAPERValueFieldWithoutReplay(&value) || aper.EncodeWithoutReplay(options...)
	if *s30.BridgeConnectionEstablishmentIndicationIEValueERABIEContainerListAPERValueFieldContext(&value) == c.context && !fresh && (*s30.BridgeConnectionEstablishmentIndicationIEValueERABIEContainerListAPERValueFieldReplay(&value)).Present() {
		plan, next := c.compare(value.Value, *s30.BridgeConnectionEstablishmentIndicationIEValueERABIEContainerListAPERValueFieldReplay(&value), budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(*s30.BridgeConnectionEstablishmentIndicationIEValueERABIEContainerListAPERValueFieldReplay(&value)) {
			out, err := aper.CopyReplay(*s30.BridgeConnectionEstablishmentIndicationIEValueERABIEContainerListAPERValueFieldReceived(&value), &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c ConnectionEstablishmentIndicationIEValueERABIEContainerListValueCodec) encodeBudgetValue(value s30.ConnectionEstablishmentIndicationIEValueERABIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ConnectionEstablishmentIndicationIEValueERABIEContainerListValueCodec) encodeChanged(value s30.ConnectionEstablishmentIndicationIEValueERABIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func BridgeConnectionEstablishmentIndicationIEValueCaptureS1APERABIEContainerList(v *s30.ConnectionEstablishmentIndicationIEValueERABIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeConnectionEstablishmentIndicationIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeConnectionEstablishmentIndicationIEValueCompareS1APERABIEContainerList(v *s30.ConnectionEstablishmentIndicationIEValueERABIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeConnectionEstablishmentIndicationIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}

// LocationReportIEValueERABIEContainerListValueCodec is the concrete ValueCodec[ERABIEContainerList[LocationReportIEValue]].
type LocationReportIEValueERABIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (LocationReportIEValueERABIEContainerList, error)
	encode  func(LocationReportIEValueERABIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(LocationReportIEValueERABIEContainerList, aper.DecodeState) (LocationReportIEValueERABIEContainerList, aper.Snapshot)
	compare func(LocationReportIEValueERABIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c LocationReportIEValueERABIEContainerListValueCodec) New(value LocationReportIEValueERABIEContainerList) (LocationReportIEValueERABIEContainerListAPERValue, error) {
	if c.encode == nil {
		return LocationReportIEValueERABIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return LocationReportIEValueERABIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return LocationReportIEValueERABIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return LocationReportIEValueERABIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c LocationReportIEValueERABIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (LocationReportIEValueERABIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return LocationReportIEValueERABIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return LocationReportIEValueERABIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return LocationReportIEValueERABIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return LocationReportIEValueERABIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c LocationReportIEValueERABIEContainerListValueCodec) EncodeAPER(value LocationReportIEValueERABIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c LocationReportIEValueERABIEContainerListValueCodec) encodeBudgetValue(value LocationReportIEValueERABIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c LocationReportIEValueERABIEContainerListValueCodec) encodeChanged(value LocationReportIEValueERABIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// LocationReportIEValueERABIEContainerList is the concrete ERABIEContainerList[LocationReportIEValue].
type LocationReportIEValueERABIEContainerList []LocationReportIEValueProtocolIESingleContainer

// UEInformationTransferIEValueERABIEContainerListValueCodec is the concrete ValueCodec[ERABIEContainerList[UEInformationTransferIEValue]].
type UEInformationTransferIEValueERABIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (UEInformationTransferIEValueERABIEContainerList, error)
	encode  func(UEInformationTransferIEValueERABIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(UEInformationTransferIEValueERABIEContainerList, aper.DecodeState) (UEInformationTransferIEValueERABIEContainerList, aper.Snapshot)
	compare func(UEInformationTransferIEValueERABIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c UEInformationTransferIEValueERABIEContainerListValueCodec) New(value UEInformationTransferIEValueERABIEContainerList) (UEInformationTransferIEValueERABIEContainerListAPERValue, error) {
	if c.encode == nil {
		return UEInformationTransferIEValueERABIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return UEInformationTransferIEValueERABIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return UEInformationTransferIEValueERABIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return UEInformationTransferIEValueERABIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c UEInformationTransferIEValueERABIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (UEInformationTransferIEValueERABIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return UEInformationTransferIEValueERABIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return UEInformationTransferIEValueERABIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return UEInformationTransferIEValueERABIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return UEInformationTransferIEValueERABIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c UEInformationTransferIEValueERABIEContainerListValueCodec) EncodeAPER(value UEInformationTransferIEValueERABIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c UEInformationTransferIEValueERABIEContainerListValueCodec) encodeBudgetValue(value UEInformationTransferIEValueERABIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c UEInformationTransferIEValueERABIEContainerListValueCodec) encodeChanged(value UEInformationTransferIEValueERABIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// UEInformationTransferIEValueERABIEContainerList is the concrete ERABIEContainerList[UEInformationTransferIEValue].
type UEInformationTransferIEValueERABIEContainerList []UEInformationTransferIEValueProtocolIESingleContainer

// LocationReportIEFieldValueCodec is the concrete ValueCodec[ProtocolIEField[LocationReportIEValue]].
type LocationReportIEFieldValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (LocationReportIEField, error)
	encode  func(LocationReportIEField, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(LocationReportIEField, aper.DecodeState) (LocationReportIEField, aper.Snapshot)
	compare func(LocationReportIEField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c LocationReportIEFieldValueCodec) New(value LocationReportIEField) (LocationReportIEFieldAPERValue, error) {
	if c.encode == nil {
		return LocationReportIEFieldAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return LocationReportIEFieldAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return LocationReportIEFieldAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return LocationReportIEFieldAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c LocationReportIEFieldValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (LocationReportIEFieldAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return LocationReportIEFieldAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return LocationReportIEFieldAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return LocationReportIEFieldAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return LocationReportIEFieldAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c LocationReportIEFieldValueCodec) EncodeAPER(value LocationReportIEFieldAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c LocationReportIEFieldValueCodec) encodeBudgetValue(value LocationReportIEField, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c LocationReportIEFieldValueCodec) encodeChanged(value LocationReportIEField, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// UEInformationTransferIEFieldValueCodec is the concrete ValueCodec[ProtocolIEField[UEInformationTransferIEValue]].
type UEInformationTransferIEFieldValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (UEInformationTransferIEField, error)
	encode  func(UEInformationTransferIEField, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(UEInformationTransferIEField, aper.DecodeState) (UEInformationTransferIEField, aper.Snapshot)
	compare func(UEInformationTransferIEField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c UEInformationTransferIEFieldValueCodec) New(value UEInformationTransferIEField) (UEInformationTransferIEFieldAPERValue, error) {
	if c.encode == nil {
		return UEInformationTransferIEFieldAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return UEInformationTransferIEFieldAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return UEInformationTransferIEFieldAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return UEInformationTransferIEFieldAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c UEInformationTransferIEFieldValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (UEInformationTransferIEFieldAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return UEInformationTransferIEFieldAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return UEInformationTransferIEFieldAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return UEInformationTransferIEFieldAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return UEInformationTransferIEFieldAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c UEInformationTransferIEFieldValueCodec) EncodeAPER(value UEInformationTransferIEFieldAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c UEInformationTransferIEFieldValueCodec) encodeBudgetValue(value UEInformationTransferIEField, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c UEInformationTransferIEFieldValueCodec) encodeChanged(value UEInformationTransferIEField, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// LocationReportIEContainerValueCodec is the concrete ValueCodec[ProtocolIEContainer[LocationReportIEValue]].
type LocationReportIEContainerValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (LocationReportIEContainer, error)
	encode  func(LocationReportIEContainer, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(LocationReportIEContainer, aper.DecodeState) (LocationReportIEContainer, aper.Snapshot)
	compare func(LocationReportIEContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c LocationReportIEContainerValueCodec) New(value LocationReportIEContainer) (LocationReportIEContainerAPERValue, error) {
	if c.encode == nil {
		return LocationReportIEContainerAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return LocationReportIEContainerAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return LocationReportIEContainerAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return LocationReportIEContainerAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c LocationReportIEContainerValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (LocationReportIEContainerAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return LocationReportIEContainerAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return LocationReportIEContainerAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return LocationReportIEContainerAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return LocationReportIEContainerAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c LocationReportIEContainerValueCodec) EncodeAPER(value LocationReportIEContainerAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c LocationReportIEContainerValueCodec) encodeBudgetValue(value LocationReportIEContainer, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c LocationReportIEContainerValueCodec) encodeChanged(value LocationReportIEContainer, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// UEInformationTransferIEContainerValueCodec is the concrete ValueCodec[ProtocolIEContainer[UEInformationTransferIEValue]].
type UEInformationTransferIEContainerValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (UEInformationTransferIEContainer, error)
	encode  func(UEInformationTransferIEContainer, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(UEInformationTransferIEContainer, aper.DecodeState) (UEInformationTransferIEContainer, aper.Snapshot)
	compare func(UEInformationTransferIEContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c UEInformationTransferIEContainerValueCodec) New(value UEInformationTransferIEContainer) (UEInformationTransferIEContainerAPERValue, error) {
	if c.encode == nil {
		return UEInformationTransferIEContainerAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return UEInformationTransferIEContainerAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return UEInformationTransferIEContainerAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return UEInformationTransferIEContainerAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c UEInformationTransferIEContainerValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (UEInformationTransferIEContainerAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return UEInformationTransferIEContainerAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return UEInformationTransferIEContainerAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return UEInformationTransferIEContainerAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return UEInformationTransferIEContainerAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c UEInformationTransferIEContainerValueCodec) EncodeAPER(value UEInformationTransferIEContainerAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c UEInformationTransferIEContainerValueCodec) encodeBudgetValue(value UEInformationTransferIEContainer, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c UEInformationTransferIEContainerValueCodec) encodeChanged(value UEInformationTransferIEContainer, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ConnectionEstablishmentIndicationIEValueProtocolErrorIEContainerListValueCodec is the concrete ValueCodec[ProtocolErrorIEContainerList[ConnectionEstablishmentIndicationIEValue]].
type ConnectionEstablishmentIndicationIEValueProtocolErrorIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ConnectionEstablishmentIndicationIEValueProtocolErrorIEContainerList, error)
	encode  func(ConnectionEstablishmentIndicationIEValueProtocolErrorIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ConnectionEstablishmentIndicationIEValueProtocolErrorIEContainerList, aper.DecodeState) (ConnectionEstablishmentIndicationIEValueProtocolErrorIEContainerList, aper.Snapshot)
	compare func(ConnectionEstablishmentIndicationIEValueProtocolErrorIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ConnectionEstablishmentIndicationIEValueProtocolErrorIEContainerListValueCodec) New(value ConnectionEstablishmentIndicationIEValueProtocolErrorIEContainerList) (ConnectionEstablishmentIndicationIEValueProtocolErrorIEContainerListAPERValue, error) {
	if c.encode == nil {
		return ConnectionEstablishmentIndicationIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ConnectionEstablishmentIndicationIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ConnectionEstablishmentIndicationIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ConnectionEstablishmentIndicationIEValueProtocolErrorIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ConnectionEstablishmentIndicationIEValueProtocolErrorIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ConnectionEstablishmentIndicationIEValueProtocolErrorIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ConnectionEstablishmentIndicationIEValueProtocolErrorIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ConnectionEstablishmentIndicationIEValueProtocolErrorIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ConnectionEstablishmentIndicationIEValueProtocolErrorIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ConnectionEstablishmentIndicationIEValueProtocolErrorIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ConnectionEstablishmentIndicationIEValueProtocolErrorIEContainerListValueCodec) EncodeAPER(value ConnectionEstablishmentIndicationIEValueProtocolErrorIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c ConnectionEstablishmentIndicationIEValueProtocolErrorIEContainerListValueCodec) encodeBudgetValue(value ConnectionEstablishmentIndicationIEValueProtocolErrorIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ConnectionEstablishmentIndicationIEValueProtocolErrorIEContainerListValueCodec) encodeChanged(value ConnectionEstablishmentIndicationIEValueProtocolErrorIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ConnectionEstablishmentIndicationIEValueProtocolErrorIEContainerList is the concrete ProtocolErrorIEContainerList[ConnectionEstablishmentIndicationIEValue].
type ConnectionEstablishmentIndicationIEValueProtocolErrorIEContainerList []s30.ConnectionEstablishmentIndicationIEValueProtocolIESingleContainer

func BridgeConnectionEstablishmentIndicationIEValueCaptureS1APProtocolErrorIEContainerList(v *ConnectionEstablishmentIndicationIEValueProtocolErrorIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeConnectionEstablishmentIndicationIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeConnectionEstablishmentIndicationIEValueCompareS1APProtocolErrorIEContainerList(v *ConnectionEstablishmentIndicationIEValueProtocolErrorIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeConnectionEstablishmentIndicationIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}

// LocationReportIEValueProtocolErrorIEContainerListValueCodec is the concrete ValueCodec[ProtocolErrorIEContainerList[LocationReportIEValue]].
type LocationReportIEValueProtocolErrorIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (LocationReportIEValueProtocolErrorIEContainerList, error)
	encode  func(LocationReportIEValueProtocolErrorIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(LocationReportIEValueProtocolErrorIEContainerList, aper.DecodeState) (LocationReportIEValueProtocolErrorIEContainerList, aper.Snapshot)
	compare func(LocationReportIEValueProtocolErrorIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c LocationReportIEValueProtocolErrorIEContainerListValueCodec) New(value LocationReportIEValueProtocolErrorIEContainerList) (LocationReportIEValueProtocolErrorIEContainerListAPERValue, error) {
	if c.encode == nil {
		return LocationReportIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return LocationReportIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return LocationReportIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return LocationReportIEValueProtocolErrorIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c LocationReportIEValueProtocolErrorIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (LocationReportIEValueProtocolErrorIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return LocationReportIEValueProtocolErrorIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return LocationReportIEValueProtocolErrorIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return LocationReportIEValueProtocolErrorIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return LocationReportIEValueProtocolErrorIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c LocationReportIEValueProtocolErrorIEContainerListValueCodec) EncodeAPER(value LocationReportIEValueProtocolErrorIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c LocationReportIEValueProtocolErrorIEContainerListValueCodec) encodeBudgetValue(value LocationReportIEValueProtocolErrorIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c LocationReportIEValueProtocolErrorIEContainerListValueCodec) encodeChanged(value LocationReportIEValueProtocolErrorIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// LocationReportIEValueProtocolErrorIEContainerList is the concrete ProtocolErrorIEContainerList[LocationReportIEValue].
type LocationReportIEValueProtocolErrorIEContainerList []LocationReportIEValueProtocolIESingleContainer

// UEInformationTransferIEValueProtocolErrorIEContainerListValueCodec is the concrete ValueCodec[ProtocolErrorIEContainerList[UEInformationTransferIEValue]].
type UEInformationTransferIEValueProtocolErrorIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (UEInformationTransferIEValueProtocolErrorIEContainerList, error)
	encode  func(UEInformationTransferIEValueProtocolErrorIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(UEInformationTransferIEValueProtocolErrorIEContainerList, aper.DecodeState) (UEInformationTransferIEValueProtocolErrorIEContainerList, aper.Snapshot)
	compare func(UEInformationTransferIEValueProtocolErrorIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c UEInformationTransferIEValueProtocolErrorIEContainerListValueCodec) New(value UEInformationTransferIEValueProtocolErrorIEContainerList) (UEInformationTransferIEValueProtocolErrorIEContainerListAPERValue, error) {
	if c.encode == nil {
		return UEInformationTransferIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return UEInformationTransferIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return UEInformationTransferIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return UEInformationTransferIEValueProtocolErrorIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c UEInformationTransferIEValueProtocolErrorIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (UEInformationTransferIEValueProtocolErrorIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return UEInformationTransferIEValueProtocolErrorIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return UEInformationTransferIEValueProtocolErrorIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return UEInformationTransferIEValueProtocolErrorIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return UEInformationTransferIEValueProtocolErrorIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c UEInformationTransferIEValueProtocolErrorIEContainerListValueCodec) EncodeAPER(value UEInformationTransferIEValueProtocolErrorIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c UEInformationTransferIEValueProtocolErrorIEContainerListValueCodec) encodeBudgetValue(value UEInformationTransferIEValueProtocolErrorIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c UEInformationTransferIEValueProtocolErrorIEContainerListValueCodec) encodeChanged(value UEInformationTransferIEValueProtocolErrorIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// UEInformationTransferIEValueProtocolErrorIEContainerList is the concrete ProtocolErrorIEContainerList[UEInformationTransferIEValue].
type UEInformationTransferIEValueProtocolErrorIEContainerList []UEInformationTransferIEValueProtocolIESingleContainer

// ConnectionEstablishmentIndicationIEValueProtocolIEContainerListValueCodec is the concrete ValueCodec[ProtocolIEContainerList[ConnectionEstablishmentIndicationIEValue]].
type ConnectionEstablishmentIndicationIEValueProtocolIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ConnectionEstablishmentIndicationIEValueProtocolIEContainerList, error)
	encode  func(ConnectionEstablishmentIndicationIEValueProtocolIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ConnectionEstablishmentIndicationIEValueProtocolIEContainerList, aper.DecodeState) (ConnectionEstablishmentIndicationIEValueProtocolIEContainerList, aper.Snapshot)
	compare func(ConnectionEstablishmentIndicationIEValueProtocolIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ConnectionEstablishmentIndicationIEValueProtocolIEContainerListValueCodec) New(value ConnectionEstablishmentIndicationIEValueProtocolIEContainerList) (ConnectionEstablishmentIndicationIEValueProtocolIEContainerListAPERValue, error) {
	if c.encode == nil {
		return ConnectionEstablishmentIndicationIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ConnectionEstablishmentIndicationIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ConnectionEstablishmentIndicationIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ConnectionEstablishmentIndicationIEValueProtocolIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ConnectionEstablishmentIndicationIEValueProtocolIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ConnectionEstablishmentIndicationIEValueProtocolIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ConnectionEstablishmentIndicationIEValueProtocolIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ConnectionEstablishmentIndicationIEValueProtocolIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ConnectionEstablishmentIndicationIEValueProtocolIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ConnectionEstablishmentIndicationIEValueProtocolIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ConnectionEstablishmentIndicationIEValueProtocolIEContainerListValueCodec) EncodeAPER(value ConnectionEstablishmentIndicationIEValueProtocolIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c ConnectionEstablishmentIndicationIEValueProtocolIEContainerListValueCodec) encodeBudgetValue(value ConnectionEstablishmentIndicationIEValueProtocolIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ConnectionEstablishmentIndicationIEValueProtocolIEContainerListValueCodec) encodeChanged(value ConnectionEstablishmentIndicationIEValueProtocolIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ConnectionEstablishmentIndicationIEValueProtocolIEContainerList is the concrete ProtocolIEContainerList[ConnectionEstablishmentIndicationIEValue].
type ConnectionEstablishmentIndicationIEValueProtocolIEContainerList []s30.ConnectionEstablishmentIndicationIEValueProtocolIESingleContainer

func BridgeConnectionEstablishmentIndicationIEValueCaptureS1APProtocolIEContainerList(v *ConnectionEstablishmentIndicationIEValueProtocolIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeConnectionEstablishmentIndicationIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeConnectionEstablishmentIndicationIEValueCompareS1APProtocolIEContainerList(v *ConnectionEstablishmentIndicationIEValueProtocolIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeConnectionEstablishmentIndicationIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}

// LocationReportIEValueProtocolIEContainerListValueCodec is the concrete ValueCodec[ProtocolIEContainerList[LocationReportIEValue]].
type LocationReportIEValueProtocolIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (LocationReportIEValueProtocolIEContainerList, error)
	encode  func(LocationReportIEValueProtocolIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(LocationReportIEValueProtocolIEContainerList, aper.DecodeState) (LocationReportIEValueProtocolIEContainerList, aper.Snapshot)
	compare func(LocationReportIEValueProtocolIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c LocationReportIEValueProtocolIEContainerListValueCodec) New(value LocationReportIEValueProtocolIEContainerList) (LocationReportIEValueProtocolIEContainerListAPERValue, error) {
	if c.encode == nil {
		return LocationReportIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return LocationReportIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return LocationReportIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return LocationReportIEValueProtocolIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c LocationReportIEValueProtocolIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (LocationReportIEValueProtocolIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return LocationReportIEValueProtocolIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return LocationReportIEValueProtocolIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return LocationReportIEValueProtocolIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return LocationReportIEValueProtocolIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c LocationReportIEValueProtocolIEContainerListValueCodec) EncodeAPER(value LocationReportIEValueProtocolIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c LocationReportIEValueProtocolIEContainerListValueCodec) encodeBudgetValue(value LocationReportIEValueProtocolIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c LocationReportIEValueProtocolIEContainerListValueCodec) encodeChanged(value LocationReportIEValueProtocolIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// LocationReportIEValueProtocolIEContainerList is the concrete ProtocolIEContainerList[LocationReportIEValue].
type LocationReportIEValueProtocolIEContainerList []LocationReportIEValueProtocolIESingleContainer

// UEInformationTransferIEValueProtocolIEContainerListValueCodec is the concrete ValueCodec[ProtocolIEContainerList[UEInformationTransferIEValue]].
type UEInformationTransferIEValueProtocolIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (UEInformationTransferIEValueProtocolIEContainerList, error)
	encode  func(UEInformationTransferIEValueProtocolIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(UEInformationTransferIEValueProtocolIEContainerList, aper.DecodeState) (UEInformationTransferIEValueProtocolIEContainerList, aper.Snapshot)
	compare func(UEInformationTransferIEValueProtocolIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c UEInformationTransferIEValueProtocolIEContainerListValueCodec) New(value UEInformationTransferIEValueProtocolIEContainerList) (UEInformationTransferIEValueProtocolIEContainerListAPERValue, error) {
	if c.encode == nil {
		return UEInformationTransferIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return UEInformationTransferIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return UEInformationTransferIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return UEInformationTransferIEValueProtocolIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c UEInformationTransferIEValueProtocolIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (UEInformationTransferIEValueProtocolIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return UEInformationTransferIEValueProtocolIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return UEInformationTransferIEValueProtocolIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return UEInformationTransferIEValueProtocolIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return UEInformationTransferIEValueProtocolIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c UEInformationTransferIEValueProtocolIEContainerListValueCodec) EncodeAPER(value UEInformationTransferIEValueProtocolIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c UEInformationTransferIEValueProtocolIEContainerListValueCodec) encodeBudgetValue(value UEInformationTransferIEValueProtocolIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c UEInformationTransferIEValueProtocolIEContainerListValueCodec) encodeChanged(value UEInformationTransferIEValueProtocolIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// UEInformationTransferIEValueProtocolIEContainerList is the concrete ProtocolIEContainerList[UEInformationTransferIEValue].
type UEInformationTransferIEValueProtocolIEContainerList []UEInformationTransferIEValueProtocolIESingleContainer

func BridgeConnectionEstablishmentIndicationIEValueCaptureS1APProtocolIESingleContainer(v *s30.ConnectionEstablishmentIndicationIEValueProtocolIESingleContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeConnectionEstablishmentIndicationIEValueCaptureS1APProtocolIEField(v, s)
	s.End(f, nil, false)
}
func BridgeConnectionEstablishmentIndicationIEValueCompareS1APProtocolIESingleContainer(v *s30.ConnectionEstablishmentIndicationIEValueProtocolIESingleContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeConnectionEstablishmentIndicationIEValueCompareS1APProtocolIEField(v, s)
	s.End(f, aper.Snapshot{}, false)
}

// LocationReportIEValueERABIEContainerListAPERValue is the concrete APERValue[ERABIEContainerList[LocationReportIEValue]].
type LocationReportIEValueERABIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         LocationReportIEValueERABIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v LocationReportIEValueERABIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v LocationReportIEValueERABIEContainerListAPERValue) WithoutReplay() LocationReportIEValueERABIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// LocationReportIEValueProtocolIESingleContainer is the concrete ProtocolIESingleContainer[LocationReportIEValue].
type LocationReportIEValueProtocolIESingleContainer = LocationReportIEField

// UEInformationTransferIEValueERABIEContainerListAPERValue is the concrete APERValue[ERABIEContainerList[UEInformationTransferIEValue]].
type UEInformationTransferIEValueERABIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         UEInformationTransferIEValueERABIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v UEInformationTransferIEValueERABIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v UEInformationTransferIEValueERABIEContainerListAPERValue) WithoutReplay() UEInformationTransferIEValueERABIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// UEInformationTransferIEValueProtocolIESingleContainer is the concrete ProtocolIESingleContainer[UEInformationTransferIEValue].
type UEInformationTransferIEValueProtocolIESingleContainer = UEInformationTransferIEField

// LocationReportIEFieldAPERValue is the concrete APERValue[ProtocolIEField[LocationReportIEValue]].
type LocationReportIEFieldAPERValue struct {
	context       s00.BridgeCodecContext
	Value         LocationReportIEField
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v LocationReportIEFieldAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v LocationReportIEFieldAPERValue) WithoutReplay() LocationReportIEFieldAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// UEInformationTransferIEFieldAPERValue is the concrete APERValue[ProtocolIEField[UEInformationTransferIEValue]].
type UEInformationTransferIEFieldAPERValue struct {
	context       s00.BridgeCodecContext
	Value         UEInformationTransferIEField
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v UEInformationTransferIEFieldAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v UEInformationTransferIEFieldAPERValue) WithoutReplay() UEInformationTransferIEFieldAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// LocationReportIEContainerAPERValue is the concrete APERValue[ProtocolIEContainer[LocationReportIEValue]].
type LocationReportIEContainerAPERValue struct {
	context       s00.BridgeCodecContext
	Value         LocationReportIEContainer
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v LocationReportIEContainerAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v LocationReportIEContainerAPERValue) WithoutReplay() LocationReportIEContainerAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// UEInformationTransferIEContainerAPERValue is the concrete APERValue[ProtocolIEContainer[UEInformationTransferIEValue]].
type UEInformationTransferIEContainerAPERValue struct {
	context       s00.BridgeCodecContext
	Value         UEInformationTransferIEContainer
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v UEInformationTransferIEContainerAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v UEInformationTransferIEContainerAPERValue) WithoutReplay() UEInformationTransferIEContainerAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ConnectionEstablishmentIndicationIEValueProtocolErrorIEContainerListAPERValue is the concrete APERValue[ProtocolErrorIEContainerList[ConnectionEstablishmentIndicationIEValue]].
type ConnectionEstablishmentIndicationIEValueProtocolErrorIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         ConnectionEstablishmentIndicationIEValueProtocolErrorIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ConnectionEstablishmentIndicationIEValueProtocolErrorIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ConnectionEstablishmentIndicationIEValueProtocolErrorIEContainerListAPERValue) WithoutReplay() ConnectionEstablishmentIndicationIEValueProtocolErrorIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// LocationReportIEValueProtocolErrorIEContainerListAPERValue is the concrete APERValue[ProtocolErrorIEContainerList[LocationReportIEValue]].
type LocationReportIEValueProtocolErrorIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         LocationReportIEValueProtocolErrorIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v LocationReportIEValueProtocolErrorIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v LocationReportIEValueProtocolErrorIEContainerListAPERValue) WithoutReplay() LocationReportIEValueProtocolErrorIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// UEInformationTransferIEValueProtocolErrorIEContainerListAPERValue is the concrete APERValue[ProtocolErrorIEContainerList[UEInformationTransferIEValue]].
type UEInformationTransferIEValueProtocolErrorIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         UEInformationTransferIEValueProtocolErrorIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v UEInformationTransferIEValueProtocolErrorIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v UEInformationTransferIEValueProtocolErrorIEContainerListAPERValue) WithoutReplay() UEInformationTransferIEValueProtocolErrorIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ConnectionEstablishmentIndicationIEValueProtocolIEContainerListAPERValue is the concrete APERValue[ProtocolIEContainerList[ConnectionEstablishmentIndicationIEValue]].
type ConnectionEstablishmentIndicationIEValueProtocolIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         ConnectionEstablishmentIndicationIEValueProtocolIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ConnectionEstablishmentIndicationIEValueProtocolIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ConnectionEstablishmentIndicationIEValueProtocolIEContainerListAPERValue) WithoutReplay() ConnectionEstablishmentIndicationIEValueProtocolIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// LocationReportIEValueProtocolIEContainerListAPERValue is the concrete APERValue[ProtocolIEContainerList[LocationReportIEValue]].
type LocationReportIEValueProtocolIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         LocationReportIEValueProtocolIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v LocationReportIEValueProtocolIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v LocationReportIEValueProtocolIEContainerListAPERValue) WithoutReplay() LocationReportIEValueProtocolIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// UEInformationTransferIEValueProtocolIEContainerListAPERValue is the concrete APERValue[ProtocolIEContainerList[UEInformationTransferIEValue]].
type UEInformationTransferIEValueProtocolIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         UEInformationTransferIEValueProtocolIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v UEInformationTransferIEValueProtocolIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v UEInformationTransferIEValueProtocolIEContainerListAPERValue) WithoutReplay() UEInformationTransferIEValueProtocolIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}
func BridgeCaptureS1APConnectedengNBItem(v *ConnectedengNBItem, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APEnGNBID(&v.EnGNBID, s)
	BridgeCaptureS1APSupportedTAs(&v.SupportedTAs, s)
	s.Bool(v.IEExtensions == nil)
	s13.BridgeConnectedengNBItemExtIEsValueCaptureS1APProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APConnectedengNBItem(v *ConnectedengNBItem, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s02.BridgeCompareS1APEnGNBID(&v.EnGNBID, s)
	BridgeCompareS1APSupportedTAs(&v.SupportedTAs, s)
	s.Bool(v.IEExtensions == nil)
	s13.BridgeConnectedengNBItemExtIEsValueCompareS1APProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APConnectedengNBList(v *ConnectedengNBList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeCaptureS1APConnectedengNBItem(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeCompareS1APConnectedengNBList(v *ConnectedengNBList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeCompareS1APConnectedengNBItem(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCaptureS1APConnectionEstablishmentIndication(v *ConnectionEstablishmentIndication, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeConnectionEstablishmentIndicationIEValueCaptureS1APProtocolIEContainer(&v.ProtocolIEs, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APConnectionEstablishmentIndication(v *ConnectionEstablishmentIndication, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeConnectionEstablishmentIndicationIEValueCompareS1APProtocolIEContainer(&v.ProtocolIEs, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APENDCSONTransferType(v *ENDCSONTransferType, s *aper.SemanticCapture) {
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
	case s00.ENDCSONTransferTypeChoiceRequest:
		{
			f := s.Begin()
			s.Bool(v.Request == nil)
			if v.Request != nil {
				BridgeCaptureS1APENDCTransferTypeRequest(v.Request, s)
			}
			s.End(f, nil, false)
		}
	case s00.ENDCSONTransferTypeChoiceReply:
		{
			f := s.Begin()
			s.Bool(v.Reply == nil)
			if v.Reply != nil {
				BridgeCaptureS1APENDCTransferTypeReply(v.Reply, s)
			}
			s.End(f, nil, false)
		}
	}
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APENDCSONTransferType(v *ENDCSONTransferType, s *aper.SemanticComparison) {
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
	case s00.ENDCSONTransferTypeChoiceRequest:
		{
			f := s.Begin()
			s.Bool(v.Request == nil)
			if v.Request != nil {
				BridgeCompareS1APENDCTransferTypeRequest(v.Request, s)
			}
			s.End(f, aper.Snapshot{}, false)
		}
	case s00.ENDCSONTransferTypeChoiceReply:
		{
			f := s.Begin()
			s.Bool(v.Reply == nil)
			if v.Reply != nil {
				BridgeCompareS1APENDCTransferTypeReply(v.Reply, s)
			}
			s.End(f, aper.Snapshot{}, false)
		}
	}
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APENDCSONeNBIdentification(v *ENDCSONeNBIdentification, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s18.BridgeCaptureS1APGlobalENBID(&v.GlobaleNBID, s)
	BridgeCaptureS1APTAI(&v.SelectedTAI, s)
	s.Bool(v.IEExtensions == nil)
	s13.BridgeENDCSONeNBIdentificationExtIEsValueCaptureS1APProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APENDCSONeNBIdentification(v *ENDCSONeNBIdentification, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s18.BridgeCompareS1APGlobalENBID(&v.GlobaleNBID, s)
	BridgeCompareS1APTAI(&v.SelectedTAI, s)
	s.Bool(v.IEExtensions == nil)
	s13.BridgeENDCSONeNBIdentificationExtIEsValueCompareS1APProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APENDCSONengNBIdentification(v *ENDCSONengNBIdentification, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s18.BridgeCaptureS1APGlobalEnGNBID(&v.GlobalengNBID, s)
	BridgeCaptureS1APTAI(&v.SelectedTAI, s)
	s.Bool(v.IEExtensions == nil)
	s13.BridgeENDCSONengNBIdentificationExtIEsValueCaptureS1APProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APENDCSONengNBIdentification(v *ENDCSONengNBIdentification, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s18.BridgeCompareS1APGlobalEnGNBID(&v.GlobalengNBID, s)
	BridgeCompareS1APTAI(&v.SelectedTAI, s)
	s.Bool(v.IEExtensions == nil)
	s13.BridgeENDCSONengNBIdentificationExtIEsValueCompareS1APProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APENDCTransferTypeReply(v *ENDCTransferTypeReply, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeCaptureS1APENDCSONengNBIdentification(&v.SourceengNB, s)
	BridgeCaptureS1APENDCSONeNBIdentification(&v.TargeteNB, s)
	s.Bool(v.IEExtensions == nil)
	s13.BridgeENDCTransferTypeReplyExtIEsValueCaptureS1APProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APENDCTransferTypeReply(v *ENDCTransferTypeReply, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeCompareS1APENDCSONengNBIdentification(&v.SourceengNB, s)
	BridgeCompareS1APENDCSONeNBIdentification(&v.TargeteNB, s)
	s.Bool(v.IEExtensions == nil)
	s13.BridgeENDCTransferTypeReplyExtIEsValueCompareS1APProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APENDCTransferTypeRequest(v *ENDCTransferTypeRequest, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeCaptureS1APENDCSONeNBIdentification(&v.SourceeNB, s)
	BridgeCaptureS1APENDCSONengNBIdentification(&v.TargetengNB, s)
	{
		f := s.Begin()
		s.Bool(v.TargeteNB == nil)
		if v.TargeteNB != nil {
			BridgeCaptureS1APENDCSONeNBIdentification(v.TargeteNB, s)
		}
		s.End(f, nil, false)
	}
	{
		f := s.Begin()
		s.Bool(v.AssociatedTAI == nil)
		if v.AssociatedTAI != nil {
			BridgeCaptureS1APTAI(v.AssociatedTAI, s)
		}
		s.End(f, nil, false)
	}
	{
		f := s.Begin()
		s.Bool(v.Broadcast5GSTAI == nil)
		if v.Broadcast5GSTAI != nil {
			s18.BridgeCaptureS1APFiveGSTAI(v.Broadcast5GSTAI, s)
		}
		s.End(f, nil, false)
	}
	s.Bool(v.IEExtensions == nil)
	s13.BridgeENDCTransferTypeRequestExtIEsValueCaptureS1APProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APENDCTransferTypeRequest(v *ENDCTransferTypeRequest, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeCompareS1APENDCSONeNBIdentification(&v.SourceeNB, s)
	BridgeCompareS1APENDCSONengNBIdentification(&v.TargetengNB, s)
	{
		f := s.Begin()
		s.Bool(v.TargeteNB == nil)
		if v.TargeteNB != nil {
			BridgeCompareS1APENDCSONeNBIdentification(v.TargeteNB, s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	{
		f := s.Begin()
		s.Bool(v.AssociatedTAI == nil)
		if v.AssociatedTAI != nil {
			BridgeCompareS1APTAI(v.AssociatedTAI, s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	{
		f := s.Begin()
		s.Bool(v.Broadcast5GSTAI == nil)
		if v.Broadcast5GSTAI != nil {
			s18.BridgeCompareS1APFiveGSTAI(v.Broadcast5GSTAI, s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.Bool(v.IEExtensions == nil)
	s13.BridgeENDCTransferTypeRequestExtIEsValueCompareS1APProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APLocationReportIEValue(v *LocationReportIEValue, s *aper.SemanticCapture) {
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
					BridgeCaptureS1APTAI(v.rowTAI, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(98):
			{
				f := s.Begin()
				s.Bool(v.rowRequestType == nil)
				if v.rowRequestType != nil {
					s26.BridgeCaptureS1APRequestType(v.rowRequestType, s)
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
func (v LocationReportIEValue) captureSemantics(s aper.SemanticCapture) LocationReportIEValue {
	BridgeCaptureS1APLocationReportIEValue(&v, &s)
	return v
}
func BridgeCompareS1APLocationReportIEValue(v *LocationReportIEValue, s *aper.SemanticComparison) {
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
					BridgeCompareS1APTAI(v.rowTAI, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(98):
			{
				f := s.Begin()
				s.Bool(v.rowRequestType == nil)
				if v.rowRequestType != nil {
					s26.BridgeCompareS1APRequestType(v.rowRequestType, s)
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
func (v LocationReportIEValue) compareSemantics(s aper.SemanticComparison) aper.SemanticComparison {
	BridgeCompareS1APLocationReportIEValue(&v, &s)
	return s
}
func BridgeCaptureS1APMMEPagingTarget(v *MMEPagingTarget, s *aper.SemanticCapture) {
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
	case s00.MMEPagingTargetChoiceGlobalENBID:
		{
			f := s.Begin()
			s.Bool(v.GlobalENBID == nil)
			if v.GlobalENBID != nil {
				s18.BridgeCaptureS1APGlobalENBID(v.GlobalENBID, s)
			}
			s.End(f, nil, false)
		}
	case s00.MMEPagingTargetChoiceTAI:
		{
			f := s.Begin()
			s.Bool(v.TAI == nil)
			if v.TAI != nil {
				BridgeCaptureS1APTAI(v.TAI, s)
			}
			s.End(f, nil, false)
		}
	}
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APMMEPagingTarget(v *MMEPagingTarget, s *aper.SemanticComparison) {
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
	case s00.MMEPagingTargetChoiceGlobalENBID:
		{
			f := s.Begin()
			s.Bool(v.GlobalENBID == nil)
			if v.GlobalENBID != nil {
				s18.BridgeCompareS1APGlobalENBID(v.GlobalENBID, s)
			}
			s.End(f, aper.Snapshot{}, false)
		}
	case s00.MMEPagingTargetChoiceTAI:
		{
			f := s.Begin()
			s.Bool(v.TAI == nil)
			if v.TAI != nil {
				BridgeCompareS1APTAI(v.TAI, s)
			}
			s.End(f, aper.Snapshot{}, false)
		}
	}
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APRecommendedENBItem(v *RecommendedENBItem, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeCaptureS1APMMEPagingTarget(&v.MMEPagingTarget, s)
	s.Bool(v.IEExtensions == nil)
	s26.BridgeRecommendedENBItemExtIEsValueCaptureS1APProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APRecommendedENBItem(v *RecommendedENBItem, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeCompareS1APMMEPagingTarget(&v.MMEPagingTarget, s)
	s.Bool(v.IEExtensions == nil)
	s26.BridgeRecommendedENBItemExtIEsValueCompareS1APProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APSupportedTAs(v *SupportedTAs, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeCaptureS1APSupportedTAsItem(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeCompareS1APSupportedTAs(v *SupportedTAs, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeCompareS1APSupportedTAsItem(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCaptureS1APSupportedTAsItem(v *SupportedTAsItem, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APTAC(&v.TAC, s)
	s00.BridgeCaptureS1APBPLMNs(&v.BroadcastPLMNs, s)
	s.Bool(v.IEExtensions == nil)
	BridgeSupportedTAsItemExtIEsValueCaptureS1APProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APSupportedTAsItem(v *SupportedTAsItem, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s07.BridgeCompareS1APTAC(&v.TAC, s)
	s07.BridgeCompareS1APBPLMNs(&v.BroadcastPLMNs, s)
	s.Bool(v.IEExtensions == nil)
	BridgeSupportedTAsItemExtIEsValueCompareS1APProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APSynchronisationInformation(v *SynchronisationInformation, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APStratumLevel(&v.SourceStratumLevel, s)
	{
		f := s.Begin()
		s.Bool(v.ListeningSubframePattern == nil)
		if v.ListeningSubframePattern != nil {
			s18.BridgeCaptureS1APListeningSubframePattern(v.ListeningSubframePattern, s)
		}
		s.End(f, nil, false)
	}
	s.Bool(v.AggressoreCGIList == nil)
	s21.BridgeCaptureS1APIEsECGIList(&v.AggressoreCGIList, s)
	s.Bool(v.IEExtensions == nil)
	BridgeSynchronisationInformationExtIEsValueCaptureS1APProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APSynchronisationInformation(v *SynchronisationInformation, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s07.BridgeCompareS1APStratumLevel(&v.SourceStratumLevel, s)
	{
		f := s.Begin()
		s.Bool(v.ListeningSubframePattern == nil)
		if v.ListeningSubframePattern != nil {
			s18.BridgeCompareS1APListeningSubframePattern(v.ListeningSubframePattern, s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.Bool(v.AggressoreCGIList == nil)
	s24.BridgeCompareS1APIEsECGIList(&v.AggressoreCGIList, s)
	s.Bool(v.IEExtensions == nil)
	BridgeSynchronisationInformationExtIEsValueCompareS1APProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APTABasedMDT(v *TABasedMDT, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APTAListforMDT(&v.TAListforMDT, s)
	s.Bool(v.IEExtensions == nil)
	BridgeTABasedMDTExtIEsValueCaptureS1APProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APTABasedMDT(v *TABasedMDT, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s07.BridgeCompareS1APTAListforMDT(&v.TAListforMDT, s)
	s.Bool(v.IEExtensions == nil)
	BridgeTABasedMDTExtIEsValueCompareS1APProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APTABasedQMC(v *TABasedQMC, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APTAListforQMC(&v.TAListforQMC, s)
	s.Bool(v.IEExtensions == nil)
	BridgeTABasedQMCExtIEsValueCaptureS1APProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APTABasedQMC(v *TABasedQMC, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s07.BridgeCompareS1APTAListforQMC(&v.TAListforQMC, s)
	s.Bool(v.IEExtensions == nil)
	BridgeTABasedQMCExtIEsValueCompareS1APProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APTAI(v *TAI, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APPLMNidentity(&v.PLMNidentity, s)
	s00.BridgeCaptureS1APTAC(&v.TAC, s)
	s.Bool(v.IEExtensions == nil)
	BridgeTAIExtIEsValueCaptureS1APProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APTAI(v *TAI, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s07.BridgeCompareS1APPLMNidentity(&v.PLMNidentity, s)
	s07.BridgeCompareS1APTAC(&v.TAC, s)
	s.Bool(v.IEExtensions == nil)
	BridgeTAIExtIEsValueCompareS1APProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APUEInformationTransferIEValue(v *UEInformationTransferIEValue, s *aper.SemanticCapture) {
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
		case s00.ProtocolIEID(96):
			{
				f := s.Begin()
				s.Bool(v.rowSTMSI == nil)
				if v.rowSTMSI != nil {
					s27.BridgeCaptureS1APSTMSI(v.rowSTMSI, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(252):
			{
				f := s.Begin()
				s.Bool(v.rowUELevelQoSParameters == nil)
				if v.rowUELevelQoSParameters != nil {
					s18.BridgeCaptureS1APERABLevelQoSParameters(v.rowUELevelQoSParameters, s)
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
		case s00.ProtocolIEID(278):
			{
				f := s.Begin()
				s.Bool(v.rowSubscriptionBasedUEDifferentiationInfo == nil)
				if v.rowSubscriptionBasedUEDifferentiationInfo != nil {
					s30.BridgeCaptureS1APSubscriptionBasedUEDifferentiationInfo(v.rowSubscriptionBasedUEDifferentiationInfo, s)
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
		case s00.ProtocolIEID(192):
			{
				f := s.Begin()
				s.Bool(v.rowMaskedIMEISV == nil)
				if v.rowMaskedIMEISV != nil {
					s00.BridgeCaptureS1APMaskedIMEISV(v.rowMaskedIMEISV, s)
				}
				s.End(f, nil, false)
			}
		}
	}
	s.End(f, &v.replay, false)
	s.CheckReceived(v.replay, v.received)
}
func (v UEInformationTransferIEValue) captureSemantics(s aper.SemanticCapture) UEInformationTransferIEValue {
	BridgeCaptureS1APUEInformationTransferIEValue(&v, &s)
	return v
}
func BridgeCompareS1APUEInformationTransferIEValue(v *UEInformationTransferIEValue, s *aper.SemanticComparison) {
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
		case s00.ProtocolIEID(96):
			{
				f := s.Begin()
				s.Bool(v.rowSTMSI == nil)
				if v.rowSTMSI != nil {
					s27.BridgeCompareS1APSTMSI(v.rowSTMSI, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(252):
			{
				f := s.Begin()
				s.Bool(v.rowUELevelQoSParameters == nil)
				if v.rowUELevelQoSParameters != nil {
					s18.BridgeCompareS1APERABLevelQoSParameters(v.rowUELevelQoSParameters, s)
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
		case s00.ProtocolIEID(278):
			{
				f := s.Begin()
				s.Bool(v.rowSubscriptionBasedUEDifferentiationInfo == nil)
				if v.rowSubscriptionBasedUEDifferentiationInfo != nil {
					s30.BridgeCompareS1APSubscriptionBasedUEDifferentiationInfo(v.rowSubscriptionBasedUEDifferentiationInfo, s)
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
		case s00.ProtocolIEID(192):
			{
				f := s.Begin()
				s.Bool(v.rowMaskedIMEISV == nil)
				if v.rowMaskedIMEISV != nil {
					s02.BridgeCompareS1APMaskedIMEISV(v.rowMaskedIMEISV, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		}
	}
	s.End(f, v.replay, false)
	s.CheckReceived(v.replay, v.received)
}
func (v UEInformationTransferIEValue) compareSemantics(s aper.SemanticComparison) aper.SemanticComparison {
	BridgeCompareS1APUEInformationTransferIEValue(&v, &s)
	return s
}

type ConnectedengNBList = []ConnectedengNBItem

// ConnectedengNBItem represents the ASN.1 type ConnectedengNBItem (SEQUENCE).
type ConnectedengNBItem struct {
	replay            aper.Snapshot
	stream            aper.WireSpan
	received          bool
	withoutReplay     bool
	receivedAbsolute  bool
	receivedBytes     aper.WireSpan
	receivedLocation  aper.Location
	EnGNBID           s00.EnGNBID                              `asn1:"tag:0,context,implicit"`
	SupportedTAs      SupportedTAs                             `asn1:"tag:1,context,implicit"`
	supportedTAsIndef bool                                     `asn1:"-" json:"-"`
	IEExtensions      s07.ConnectedengNBItemExtIEsExtContainer `asn1:"tag:2,context,implicit,optional" json:"IEExtensions,omitzero"`
	iEExtensionsIndef bool                                     `asn1:"-" json:"-"`
	extCount          int64                                    `asn1:"-" json:"-"`
	extPresent        []bool                                   `asn1:"-" json:"-"`
	extData           [][]byte                                 `asn1:"-" json:"-"`
	perPadding        aper.FinalPadding                        `asn1:"-" json:"-"`
	perExtPadding     []aper.CompletePadding                   `asn1:"-" json:"-"`
	extOrigin         []aper.OpaqueOrigin
	extWire           []aper.WireSpan
}

// ENDCSONTransferType represents the ASN.1 CHOICE type EN-DCSONTransferType.
type ENDCSONTransferType struct {
	replay             aper.Snapshot
	stream             aper.WireSpan
	received           bool
	withoutReplay      bool
	receivedAbsolute   bool
	receivedBytes      aper.WireSpan
	receivedLocation   aper.Location
	Choice             int
	perPadding         aper.CompletePadding     `json:"-"`
	perOpenTypePadding aper.CompletePadding     `json:"-"`
	UnknownExtension   *aper.ChoiceExtension    `json:"UnknownExtension,omitempty"`
	Request            *ENDCTransferTypeRequest `json:"Request,omitempty"`
	Reply              *ENDCTransferTypeReply   `json:"Reply,omitempty"`
}

// ENDCTransferTypeRequest represents the ASN.1 type EN-DCTransferTypeRequest (SEQUENCE).
type ENDCTransferTypeRequest struct {
	replay            aper.Snapshot
	stream            aper.WireSpan
	received          bool
	withoutReplay     bool
	receivedAbsolute  bool
	receivedBytes     aper.WireSpan
	receivedLocation  aper.Location
	SourceeNB         ENDCSONeNBIdentification                      `asn1:"tag:0,context,implicit"`
	TargetengNB       ENDCSONengNBIdentification                    `asn1:"tag:1,context,implicit"`
	TargeteNB         *ENDCSONeNBIdentification                     `asn1:"tag:2,context,implicit,optional" json:"TargeteNB,omitempty"`
	AssociatedTAI     *TAI                                          `asn1:"tag:3,context,implicit,optional" json:"AssociatedTAI,omitempty"`
	Broadcast5GSTAI   *s18.FiveGSTAI                                `asn1:"tag:4,context,implicit,optional" json:"Broadcast5GSTAI,omitempty"`
	IEExtensions      s08.ENDCTransferTypeRequestExtIEsExtContainer `asn1:"tag:5,context,implicit,optional" json:"IEExtensions,omitzero"`
	iEExtensionsIndef bool                                          `asn1:"-" json:"-"`
	extCount          int64                                         `asn1:"-" json:"-"`
	extPresent        []bool                                        `asn1:"-" json:"-"`
	extData           [][]byte                                      `asn1:"-" json:"-"`
	perPadding        aper.FinalPadding                             `asn1:"-" json:"-"`
	perExtPadding     []aper.CompletePadding                        `asn1:"-" json:"-"`
	extOrigin         []aper.OpaqueOrigin
	extWire           []aper.WireSpan
}

// ENDCTransferTypeReply represents the ASN.1 type EN-DCTransferTypeReply (SEQUENCE).
type ENDCTransferTypeReply struct {
	replay            aper.Snapshot
	stream            aper.WireSpan
	received          bool
	withoutReplay     bool
	receivedAbsolute  bool
	receivedBytes     aper.WireSpan
	receivedLocation  aper.Location
	SourceengNB       ENDCSONengNBIdentification                  `asn1:"tag:0,context,implicit"`
	TargeteNB         ENDCSONeNBIdentification                    `asn1:"tag:1,context,implicit"`
	IEExtensions      s08.ENDCTransferTypeReplyExtIEsExtContainer `asn1:"tag:2,context,implicit,optional" json:"IEExtensions,omitzero"`
	iEExtensionsIndef bool                                        `asn1:"-" json:"-"`
	extCount          int64                                       `asn1:"-" json:"-"`
	extPresent        []bool                                      `asn1:"-" json:"-"`
	extData           [][]byte                                    `asn1:"-" json:"-"`
	perPadding        aper.FinalPadding                           `asn1:"-" json:"-"`
	perExtPadding     []aper.CompletePadding                      `asn1:"-" json:"-"`
	extOrigin         []aper.OpaqueOrigin
	extWire           []aper.WireSpan
}

// ENDCSONeNBIdentification represents the ASN.1 type EN-DCSONeNBIdentification (SEQUENCE).
type ENDCSONeNBIdentification struct {
	replay            aper.Snapshot
	stream            aper.WireSpan
	received          bool
	withoutReplay     bool
	receivedAbsolute  bool
	receivedBytes     aper.WireSpan
	receivedLocation  aper.Location
	GlobaleNBID       s18.GlobalENBID                                `asn1:"tag:0,context,implicit"`
	SelectedTAI       TAI                                            `asn1:"tag:1,context,implicit"`
	IEExtensions      s08.ENDCSONeNBIdentificationExtIEsExtContainer `asn1:"tag:2,context,implicit,optional" json:"IEExtensions,omitzero"`
	iEExtensionsIndef bool                                           `asn1:"-" json:"-"`
	extCount          int64                                          `asn1:"-" json:"-"`
	extPresent        []bool                                         `asn1:"-" json:"-"`
	extData           [][]byte                                       `asn1:"-" json:"-"`
	perPadding        aper.FinalPadding                              `asn1:"-" json:"-"`
	perExtPadding     []aper.CompletePadding                         `asn1:"-" json:"-"`
	extOrigin         []aper.OpaqueOrigin
	extWire           []aper.WireSpan
}

// ENDCSONengNBIdentification represents the ASN.1 type EN-DCSONengNBIdentification (SEQUENCE).
type ENDCSONengNBIdentification struct {
	replay            aper.Snapshot
	stream            aper.WireSpan
	received          bool
	withoutReplay     bool
	receivedAbsolute  bool
	receivedBytes     aper.WireSpan
	receivedLocation  aper.Location
	GlobalengNBID     s18.GlobalEnGNBID                                `asn1:"tag:0,context,implicit"`
	SelectedTAI       TAI                                              `asn1:"tag:1,context,implicit"`
	IEExtensions      s08.ENDCSONengNBIdentificationExtIEsExtContainer `asn1:"tag:2,context,implicit,optional" json:"IEExtensions,omitzero"`
	iEExtensionsIndef bool                                             `asn1:"-" json:"-"`
	extCount          int64                                            `asn1:"-" json:"-"`
	extPresent        []bool                                           `asn1:"-" json:"-"`
	extData           [][]byte                                         `asn1:"-" json:"-"`
	perPadding        aper.FinalPadding                                `asn1:"-" json:"-"`
	perExtPadding     []aper.CompletePadding                           `asn1:"-" json:"-"`
	extOrigin         []aper.OpaqueOrigin
	extWire           []aper.WireSpan
}

// MMEPagingTarget represents the ASN.1 CHOICE type MMEPagingTarget.
type MMEPagingTarget struct {
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
	GlobalENBID        *s18.GlobalENBID      `json:"GlobalENBID,omitempty"`
	TAI                *TAI                  `json:"TAI,omitempty"`
}

// RecommendedENBItem represents the ASN.1 type RecommendedENBItem (SEQUENCE).
type RecommendedENBItem struct {
	replay            aper.Snapshot
	stream            aper.WireSpan
	received          bool
	withoutReplay     bool
	receivedAbsolute  bool
	receivedBytes     aper.WireSpan
	receivedLocation  aper.Location
	MMEPagingTarget   MMEPagingTarget                          `asn1:"tag:0,context,explicit"`
	IEExtensions      s11.RecommendedENBItemExtIEsExtContainer `asn1:"tag:1,context,implicit,optional" json:"IEExtensions,omitzero"`
	iEExtensionsIndef bool                                     `asn1:"-" json:"-"`
	extCount          int64                                    `asn1:"-" json:"-"`
	extPresent        []bool                                   `asn1:"-" json:"-"`
	extData           [][]byte                                 `asn1:"-" json:"-"`
	perPadding        aper.FinalPadding                        `asn1:"-" json:"-"`
	perExtPadding     []aper.CompletePadding                   `asn1:"-" json:"-"`
	extOrigin         []aper.OpaqueOrigin
	extWire           []aper.WireSpan
}

// SynchronisationInformation represents the ASN.1 type SynchronisationInformation (SEQUENCE).
type SynchronisationInformation struct {
	replay                   aper.Snapshot
	stream                   aper.WireSpan
	received                 bool
	withoutReplay            bool
	receivedAbsolute         bool
	receivedBytes            aper.WireSpan
	receivedLocation         aper.Location
	SourceStratumLevel       s00.StratumLevel                                 `asn1:"tag:0,context,implicit,optional" json:"SourceStratumLevel,omitzero"`
	ListeningSubframePattern *s18.ListeningSubframePattern                    `asn1:"tag:1,context,implicit,optional" json:"ListeningSubframePattern,omitempty"`
	AggressoreCGIList        s18.IEsECGIList                                  `asn1:"tag:2,context,implicit,optional" json:"AggressoreCGIList,omitzero"`
	aggressoreCGIListIndef   bool                                             `asn1:"-" json:"-"`
	IEExtensions             s11.SynchronisationInformationExtIEsExtContainer `asn1:"tag:3,context,implicit,optional" json:"IEExtensions,omitzero"`
	iEExtensionsIndef        bool                                             `asn1:"-" json:"-"`
	extCount                 int64                                            `asn1:"-" json:"-"`
	extPresent               []bool                                           `asn1:"-" json:"-"`
	extData                  [][]byte                                         `asn1:"-" json:"-"`
	perPadding               aper.FinalPadding                                `asn1:"-" json:"-"`
	perExtPadding            []aper.CompletePadding                           `asn1:"-" json:"-"`
	extOrigin                []aper.OpaqueOrigin
	extWire                  []aper.WireSpan
}
type SupportedTAs = []SupportedTAsItem

// SupportedTAsItem represents the ASN.1 type SupportedTAs-Item (SEQUENCE).
type SupportedTAsItem struct {
	replay              aper.Snapshot
	stream              aper.WireSpan
	received            bool
	withoutReplay       bool
	receivedAbsolute    bool
	receivedBytes       aper.WireSpan
	receivedLocation    aper.Location
	TAC                 s00.TAC                                `asn1:"tag:0,context,implicit"`
	BroadcastPLMNs      s00.BPLMNs                             `asn1:"tag:1,context,implicit"`
	broadcastPLMNsIndef bool                                   `asn1:"-" json:"-"`
	IEExtensions        s11.SupportedTAsItemExtIEsExtContainer `asn1:"tag:2,context,implicit,optional" json:"IEExtensions,omitzero"`
	iEExtensionsIndef   bool                                   `asn1:"-" json:"-"`
	extCount            int64                                  `asn1:"-" json:"-"`
	extPresent          []bool                                 `asn1:"-" json:"-"`
	extData             [][]byte                               `asn1:"-" json:"-"`
	perPadding          aper.FinalPadding                      `asn1:"-" json:"-"`
	perExtPadding       []aper.CompletePadding                 `asn1:"-" json:"-"`
	extOrigin           []aper.OpaqueOrigin
	extWire             []aper.WireSpan
}

// TAI represents the ASN.1 type TAI (SEQUENCE).
type TAI struct {
	replay            aper.Snapshot
	stream            aper.WireSpan
	received          bool
	withoutReplay     bool
	receivedAbsolute  bool
	receivedBytes     aper.WireSpan
	receivedLocation  aper.Location
	PLMNidentity      s00.PLMNidentity          `asn1:"tag:0,context,implicit"`
	TAC               s00.TAC                   `asn1:"tag:1,context,implicit"`
	IEExtensions      s11.TAIExtIEsExtContainer `asn1:"tag:2,context,implicit,optional" json:"IEExtensions,omitzero"`
	iEExtensionsIndef bool                      `asn1:"-" json:"-"`
	extCount          int64                     `asn1:"-" json:"-"`
	extPresent        []bool                    `asn1:"-" json:"-"`
	extData           [][]byte                  `asn1:"-" json:"-"`
	perPadding        aper.FinalPadding         `asn1:"-" json:"-"`
	perExtPadding     []aper.CompletePadding    `asn1:"-" json:"-"`
	extOrigin         []aper.OpaqueOrigin
	extWire           []aper.WireSpan
}

// TABasedMDT represents the ASN.1 type TABasedMDT (SEQUENCE).
type TABasedMDT struct {
	replay            aper.Snapshot
	stream            aper.WireSpan
	received          bool
	withoutReplay     bool
	receivedAbsolute  bool
	receivedBytes     aper.WireSpan
	receivedLocation  aper.Location
	TAListforMDT      s00.TAListforMDT                 `asn1:"tag:0,context,implicit"`
	tAListforMDTIndef bool                             `asn1:"-" json:"-"`
	IEExtensions      s11.TABasedMDTExtIEsExtContainer `asn1:"tag:1,context,implicit,optional" json:"IEExtensions,omitzero"`
	iEExtensionsIndef bool                             `asn1:"-" json:"-"`
	extCount          int64                            `asn1:"-" json:"-"`
	extPresent        []bool                           `asn1:"-" json:"-"`
	extData           [][]byte                         `asn1:"-" json:"-"`
	perPadding        aper.FinalPadding                `asn1:"-" json:"-"`
	perExtPadding     []aper.CompletePadding           `asn1:"-" json:"-"`
	extOrigin         []aper.OpaqueOrigin
	extWire           []aper.WireSpan
}

// TABasedQMC represents the ASN.1 type TABasedQMC (SEQUENCE).
type TABasedQMC struct {
	replay            aper.Snapshot
	stream            aper.WireSpan
	received          bool
	withoutReplay     bool
	receivedAbsolute  bool
	receivedBytes     aper.WireSpan
	receivedLocation  aper.Location
	TAListforQMC      s00.TAListforQMC                 `asn1:"tag:0,context,implicit"`
	tAListforQMCIndef bool                             `asn1:"-" json:"-"`
	IEExtensions      s11.TABasedQMCExtIEsExtContainer `asn1:"tag:1,context,implicit,optional" json:"IEExtensions,omitzero"`
	iEExtensionsIndef bool                             `asn1:"-" json:"-"`
	extCount          int64                            `asn1:"-" json:"-"`
	extPresent        []bool                           `asn1:"-" json:"-"`
	extData           [][]byte                         `asn1:"-" json:"-"`
	perPadding        aper.FinalPadding                `asn1:"-" json:"-"`
	perExtPadding     []aper.CompletePadding           `asn1:"-" json:"-"`
	extOrigin         []aper.OpaqueOrigin
	extWire           []aper.WireSpan
}
type BridgeAsn1cAPERConnectedengNBListListValue struct{ Value ConnectedengNBList }

// MarshalAPERConnectedengNBListTo appends a ConnectedengNBList list to bb.
func BridgeMarshalAPERConnectedengNBListTo(list ConnectedengNBList, bb *aper.BitBuffer, fresh ...bool) error {
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()

	v := BridgeAsn1cAPERConnectedengNBListListValue{Value: list}
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

// MarshalAPER encodes ConnectedengNBItem to APER format.
func (v *ConnectedengNBItem) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *ConnectedengNBItem) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
	if err := aper.EncodeBitStringAlignedExt(bb, v.EnGNBID.Bytes, v.EnGNBID.BitLength, 22, 32, true, true); err != nil {
		return fmt.Errorf("encoding en-gNB-ID: %w", err)
	}
	if err := aper.EncodeCollection(bb, int64(len(v.SupportedTAs)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 256, HasUpper: true}, true, func(fragmentOffset_supportedtas, fragmentLength_supportedtas int64) error {
		// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
		if fragmentOffset_supportedtas < 0 || fragmentOffset_supportedtas > int64(len(v.SupportedTAs)) || fragmentLength_supportedtas < 0 || fragmentLength_supportedtas > int64(len(v.SupportedTAs[fragmentOffset_supportedtas:])) {
			return fmt.Errorf("collection fragment outside value")
		}
		for _, elem := range v.SupportedTAs[fragmentOffset_supportedtas : fragmentOffset_supportedtas+fragmentLength_supportedtas] {
			if err := elem.marshalAPERTo(bb, len(fresh) != 0 && fresh[0]); err != nil {
				return fmt.Errorf("encoding supportedTAs element: %w", err)
			}
		}
		return nil
	}); err != nil {
		return fmt.Errorf("encoding supportedTAs: %w", err)
	}
	if v.IEExtensions != nil {
		if err := aper.EncodeCollection(bb, int64(len(v.IEExtensions)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
			if fragmentOffset_ieextensions < 0 || fragmentOffset_ieextensions > int64(len(v.IEExtensions)) || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(len(v.IEExtensions[fragmentOffset_ieextensions:])) {
				return fmt.Errorf("collection fragment outside value")
			}
			for _, elem := range v.IEExtensions[fragmentOffset_ieextensions : fragmentOffset_ieextensions+fragmentLength_ieextensions] {
				if err := s07.BridgeConnectedengNBItemExtIEsExtFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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

// UnmarshalAPER decodes ConnectedengNBItem from APER format.
func (v *ConnectedengNBItem) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes ConnectedengNBItem with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *ConnectedengNBItem) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "ConnectedengNBItem")
	}
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "ConnectedengNBItem")
	}
	padding, err := aper.CaptureFinalBits(bb, "ConnectedengNBItem")
	if err != nil {
		return runtime.WrapDecodePath(err, "ConnectedengNBItem")
	}
	v.perPadding = padding.WithRecords(v.perPadding)
	return nil
}
func (v *ConnectedengNBItem) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = ConnectedengNBItem{}
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
	bsBytes_engnbid, bsBitLen_engnbid, err := aper.DecodeBitStringAlignedExt(bb, 22, 32, true, true)
	if err != nil {
		return runtime.WrapDecodePath(err, "EnGNBID")
	}
	v.EnGNBID = runtime.BitString{Bytes: bsBytes_engnbid, BitLength: bsBitLen_engnbid}
	toleranceMark_supportedtas := bb.EnterComponent("SupportedTAs")
	v.SupportedTAs = make(SupportedTAs, 0)
	_, errCollection_supportedtas := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 256, HasUpper: true}, true, func(fragmentOffset_supportedtas, fragmentLength_supportedtas int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1128
		if fragmentOffset_supportedtas < 0 || fragmentLength_supportedtas < 0 || fragmentLength_supportedtas > int64(^uint(0)>>1) || fragmentOffset_supportedtas > int64(^uint(0)>>1)-fragmentLength_supportedtas {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_supportedtas; i++ {
			var elem SupportedTAsItem
			elementMark := bb.EnterIndex(fragmentOffset_supportedtas + i)
			if err := elem.unmarshalAPERFrom(bb); err != nil {
				return runtime.WrapDecodePath(err, fmt.Sprintf("SupportedTAs[%d]", fragmentOffset_supportedtas+i))
			}
			bb.LeaveComponent(elementMark)
			if next, err := aper.AppendValues(bb, v.SupportedTAs, elem); err != nil {
				return err
			} else {
				v.SupportedTAs = next
			}
		}
		return nil
	})
	if errCollection_supportedtas != nil {
		return runtime.WrapDecodePath(errCollection_supportedtas, "SupportedTAs")
	}
	bb.LeaveComponent(toleranceMark_supportedtas)
	if opt_ieextensions {
		tmp_ieextensions := make(s07.ConnectedengNBItemExtIEsExtContainer, 0)
		_, errCollection_ieextensions := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1128
			if fragmentOffset_ieextensions < 0 || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(^uint(0)>>1) || fragmentOffset_ieextensions > int64(^uint(0)>>1)-fragmentLength_ieextensions {
				return fmt.Errorf("collection fragment count out of range")
			}
			for i := int64(0); i < fragmentLength_ieextensions; i++ {
				var elem s07.ConnectedengNBItemExtIEsExtField
				if err := s07.BridgeConnectedengNBItemExtIEsExtFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
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

// MarshalAPER encodes ENDCSONTransferType to APER format.
func (v *ENDCSONTransferType) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.perPadding)
}
func (v *ENDCSONTransferType) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
			return fmt.Errorf("%s known choice %d and unknown extension are both selected", "ENDCSONTransferType:", v.Choice)
		}
		if v.UnknownExtension.Index() < 0 {
			return fmt.Errorf("%s extension index %d must be non-negative", "ENDCSONTransferType:", v.UnknownExtension.Index())
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
		return fmt.Errorf("%s choice %d must be positive", "ENDCSONTransferType:", v.Choice)
	}
	isExtension := v.Choice > 2
	if err := aper.EncodeBoolean(bb, isExtension); err != nil {
		return err
	}
	if isExtension {
		return fmt.Errorf("%s extension choice %d not supported", "ENDCSONTransferType:", v.Choice)
	}
	// arithmetic pattern APER_CHOICE_ROOT_ENCODE: choice index fits the emitted representation; gen/codegen_aper.go:149
	if v.Choice < 1 {
		return fmt.Errorf("choice index outside root")
	}
	if err := aper.EncodeConstrainedWholeNumberAligned(bb, int64(v.Choice-1), 0, 1); err != nil {
		return err
	}
	switch v.Choice {
	case s00.ENDCSONTransferTypeChoiceRequest:
		if v.Request == nil {
			return fmt.Errorf("choice alternative request is nil")
		}
		if err := v.Request.marshalAPERTo(bb, len(fresh) != 0 && fresh[0]); err != nil {
			return fmt.Errorf("encoding request: %w", err)
		}
	case s00.ENDCSONTransferTypeChoiceReply:
		if v.Reply == nil {
			return fmt.Errorf("choice alternative reply is nil")
		}
		if err := v.Reply.marshalAPERTo(bb, len(fresh) != 0 && fresh[0]); err != nil {
			return fmt.Errorf("encoding reply: %w", err)
		}
	default:
		return fmt.Errorf("unknown ENDCSONTransferType choice %d", v.Choice)
	}
	return nil
}

// UnmarshalAPER decodes ENDCSONTransferType from APER format.
func (v *ENDCSONTransferType) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes ENDCSONTransferType with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *ENDCSONTransferType) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "ENDCSONTransferType")
	}
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "ENDCSONTransferType")
	}
	padding, err := aper.CaptureFinalBits(bb, "ENDCSONTransferType")
	if err != nil {
		return runtime.WrapDecodePath(err, "ENDCSONTransferType")
	}
	v.perPadding = padding.Padding()
	return nil
}
func (v *ENDCSONTransferType) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = ENDCSONTransferType{}
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
	case s00.ENDCSONTransferTypeChoiceRequest:
		toleranceMark_request := bb.EnterComponent("Request")
		var dec_request ENDCTransferTypeRequest
		if err := dec_request.unmarshalAPERFrom(bb); err != nil {
			return runtime.WrapDecodePath(err, "Request")
		}
		if err := aper.ChargeValue(bb, dec_request); err != nil {
			return err
		}
		v.Request = &dec_request
		bb.LeaveComponent(toleranceMark_request)
	case s00.ENDCSONTransferTypeChoiceReply:
		toleranceMark_reply := bb.EnterComponent("Reply")
		var dec_reply ENDCTransferTypeReply
		if err := dec_reply.unmarshalAPERFrom(bb); err != nil {
			return runtime.WrapDecodePath(err, "Reply")
		}
		if err := aper.ChargeValue(bb, dec_reply); err != nil {
			return err
		}
		v.Reply = &dec_reply
		bb.LeaveComponent(toleranceMark_reply)
	}
	v.stream = bb.CaptureWireSpan(replayStart)

	return nil
}

// MarshalAPER encodes ENDCTransferTypeRequest to APER format.
func (v *ENDCTransferTypeRequest) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *ENDCTransferTypeRequest) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
	if err := aper.EncodeBoolean(bb, v.TargeteNB != nil); err != nil {
		return err
	}
	if err := aper.EncodeBoolean(bb, v.AssociatedTAI != nil); err != nil {
		return err
	}
	if err := aper.EncodeBoolean(bb, v.Broadcast5GSTAI != nil); err != nil {
		return err
	}
	if err := aper.EncodeBoolean(bb, v.IEExtensions != nil); err != nil {
		return err
	}
	if err := v.SourceeNB.marshalAPERTo(bb, len(fresh) != 0 && fresh[0]); err != nil {
		return fmt.Errorf("encoding sourceeNB: %w", err)
	}
	if err := v.TargetengNB.marshalAPERTo(bb, len(fresh) != 0 && fresh[0]); err != nil {
		return fmt.Errorf("encoding targetengNB: %w", err)
	}
	if v.TargeteNB != nil {
		if err := v.TargeteNB.marshalAPERTo(bb, len(fresh) != 0 && fresh[0]); err != nil {
			return fmt.Errorf("encoding targeteNB: %w", err)
		}
	}
	if v.AssociatedTAI != nil {
		if err := v.AssociatedTAI.marshalAPERTo(bb, len(fresh) != 0 && fresh[0]); err != nil {
			return fmt.Errorf("encoding associatedTAI: %w", err)
		}
	}
	if v.Broadcast5GSTAI != nil {
		if err := s18.BridgeFiveGSTAIMethodMarshalAPERTo(v.Broadcast5GSTAI, bb, len(fresh) != 0 && fresh[0]); err != nil {
			return fmt.Errorf("encoding broadcast5GSTAI: %w", err)
		}
	}
	if v.IEExtensions != nil {
		if err := aper.EncodeCollection(bb, int64(len(v.IEExtensions)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
			if fragmentOffset_ieextensions < 0 || fragmentOffset_ieextensions > int64(len(v.IEExtensions)) || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(len(v.IEExtensions[fragmentOffset_ieextensions:])) {
				return fmt.Errorf("collection fragment outside value")
			}
			for _, elem := range v.IEExtensions[fragmentOffset_ieextensions : fragmentOffset_ieextensions+fragmentLength_ieextensions] {
				if err := s08.BridgeENDCTransferTypeRequestExtIEsExtFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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

// UnmarshalAPER decodes ENDCTransferTypeRequest from APER format.
func (v *ENDCTransferTypeRequest) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes ENDCTransferTypeRequest with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *ENDCTransferTypeRequest) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "ENDCTransferTypeRequest")
	}
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "ENDCTransferTypeRequest")
	}
	padding, err := aper.CaptureFinalBits(bb, "ENDCTransferTypeRequest")
	if err != nil {
		return runtime.WrapDecodePath(err, "ENDCTransferTypeRequest")
	}
	v.perPadding = padding.WithRecords(v.perPadding)
	return nil
}
func (v *ENDCTransferTypeRequest) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = ENDCTransferTypeRequest{}
	extAdditions := aper.BeginExtensionAdditions(bb)
	hasExtensions, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	// Read preamble bitmap for optional root fields
	opt_targetenb, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	opt_associatedtai, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	opt_broadcast5gstai, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	opt_ieextensions, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	toleranceMark_sourceenb := bb.EnterComponent("SourceeNB")
	if err := v.SourceeNB.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "SourceeNB")
	}
	bb.LeaveComponent(toleranceMark_sourceenb)
	toleranceMark_targetengnb := bb.EnterComponent("TargetengNB")
	if err := v.TargetengNB.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "TargetengNB")
	}
	bb.LeaveComponent(toleranceMark_targetengnb)
	if opt_targetenb {
		toleranceMark_targetenb := bb.EnterComponent("TargeteNB")
		var dec_targetenb ENDCSONeNBIdentification
		if err := dec_targetenb.unmarshalAPERFrom(bb); err != nil {
			return runtime.WrapDecodePath(err, "TargeteNB")
		}
		if err := aper.ChargeValue(bb, dec_targetenb); err != nil {
			return err
		}
		v.TargeteNB = &dec_targetenb
		bb.LeaveComponent(toleranceMark_targetenb)
	}
	if opt_associatedtai {
		toleranceMark_associatedtai := bb.EnterComponent("AssociatedTAI")
		var dec_associatedtai TAI
		if err := dec_associatedtai.unmarshalAPERFrom(bb); err != nil {
			return runtime.WrapDecodePath(err, "AssociatedTAI")
		}
		if err := aper.ChargeValue(bb, dec_associatedtai); err != nil {
			return err
		}
		v.AssociatedTAI = &dec_associatedtai
		bb.LeaveComponent(toleranceMark_associatedtai)
	}
	if opt_broadcast5gstai {
		toleranceMark_broadcast5gstai := bb.EnterComponent("Broadcast5GSTAI")
		var dec_broadcast5gstai s18.FiveGSTAI
		if err := s18.BridgeFiveGSTAIMethodUnmarshalAPERFrom(&dec_broadcast5gstai, bb); err != nil {
			return runtime.WrapDecodePath(err, "Broadcast5GSTAI")
		}
		if err := aper.ChargeValue(bb, dec_broadcast5gstai); err != nil {
			return err
		}
		v.Broadcast5GSTAI = &dec_broadcast5gstai
		bb.LeaveComponent(toleranceMark_broadcast5gstai)
	}
	if opt_ieextensions {
		tmp_ieextensions := make(s08.ENDCTransferTypeRequestExtIEsExtContainer, 0)
		_, errCollection_ieextensions := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1128
			if fragmentOffset_ieextensions < 0 || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(^uint(0)>>1) || fragmentOffset_ieextensions > int64(^uint(0)>>1)-fragmentLength_ieextensions {
				return fmt.Errorf("collection fragment count out of range")
			}
			for i := int64(0); i < fragmentLength_ieextensions; i++ {
				var elem s08.ENDCTransferTypeRequestExtIEsExtField
				if err := s08.BridgeENDCTransferTypeRequestExtIEsExtFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
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

// MarshalAPER encodes ENDCTransferTypeReply to APER format.
func (v *ENDCTransferTypeReply) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *ENDCTransferTypeReply) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
	if err := v.SourceengNB.marshalAPERTo(bb, len(fresh) != 0 && fresh[0]); err != nil {
		return fmt.Errorf("encoding sourceengNB: %w", err)
	}
	if err := v.TargeteNB.marshalAPERTo(bb, len(fresh) != 0 && fresh[0]); err != nil {
		return fmt.Errorf("encoding targeteNB: %w", err)
	}
	if v.IEExtensions != nil {
		if err := aper.EncodeCollection(bb, int64(len(v.IEExtensions)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
			if fragmentOffset_ieextensions < 0 || fragmentOffset_ieextensions > int64(len(v.IEExtensions)) || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(len(v.IEExtensions[fragmentOffset_ieextensions:])) {
				return fmt.Errorf("collection fragment outside value")
			}
			for _, elem := range v.IEExtensions[fragmentOffset_ieextensions : fragmentOffset_ieextensions+fragmentLength_ieextensions] {
				if err := s08.BridgeENDCTransferTypeReplyExtIEsExtFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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

// UnmarshalAPER decodes ENDCTransferTypeReply from APER format.
func (v *ENDCTransferTypeReply) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes ENDCTransferTypeReply with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *ENDCTransferTypeReply) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "ENDCTransferTypeReply")
	}
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "ENDCTransferTypeReply")
	}
	padding, err := aper.CaptureFinalBits(bb, "ENDCTransferTypeReply")
	if err != nil {
		return runtime.WrapDecodePath(err, "ENDCTransferTypeReply")
	}
	v.perPadding = padding.WithRecords(v.perPadding)
	return nil
}
func (v *ENDCTransferTypeReply) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = ENDCTransferTypeReply{}
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
	toleranceMark_sourceengnb := bb.EnterComponent("SourceengNB")
	if err := v.SourceengNB.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "SourceengNB")
	}
	bb.LeaveComponent(toleranceMark_sourceengnb)
	toleranceMark_targetenb := bb.EnterComponent("TargeteNB")
	if err := v.TargeteNB.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "TargeteNB")
	}
	bb.LeaveComponent(toleranceMark_targetenb)
	if opt_ieextensions {
		tmp_ieextensions := make(s08.ENDCTransferTypeReplyExtIEsExtContainer, 0)
		_, errCollection_ieextensions := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1128
			if fragmentOffset_ieextensions < 0 || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(^uint(0)>>1) || fragmentOffset_ieextensions > int64(^uint(0)>>1)-fragmentLength_ieextensions {
				return fmt.Errorf("collection fragment count out of range")
			}
			for i := int64(0); i < fragmentLength_ieextensions; i++ {
				var elem s08.ENDCTransferTypeReplyExtIEsExtField
				if err := s08.BridgeENDCTransferTypeReplyExtIEsExtFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
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

// MarshalAPER encodes ENDCSONeNBIdentification to APER format.
func (v *ENDCSONeNBIdentification) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *ENDCSONeNBIdentification) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
	if err := s18.BridgeGlobalENBIDMethodMarshalAPERTo(&v.GlobaleNBID, bb, len(fresh) != 0 && fresh[0]); err != nil {
		return fmt.Errorf("encoding globaleNBID: %w", err)
	}
	if err := v.SelectedTAI.marshalAPERTo(bb, len(fresh) != 0 && fresh[0]); err != nil {
		return fmt.Errorf("encoding selectedTAI: %w", err)
	}
	if v.IEExtensions != nil {
		if err := aper.EncodeCollection(bb, int64(len(v.IEExtensions)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
			if fragmentOffset_ieextensions < 0 || fragmentOffset_ieextensions > int64(len(v.IEExtensions)) || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(len(v.IEExtensions[fragmentOffset_ieextensions:])) {
				return fmt.Errorf("collection fragment outside value")
			}
			for _, elem := range v.IEExtensions[fragmentOffset_ieextensions : fragmentOffset_ieextensions+fragmentLength_ieextensions] {
				if err := s08.BridgeENDCSONeNBIdentificationExtIEsExtFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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

// UnmarshalAPER decodes ENDCSONeNBIdentification from APER format.
func (v *ENDCSONeNBIdentification) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes ENDCSONeNBIdentification with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *ENDCSONeNBIdentification) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "ENDCSONeNBIdentification")
	}
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "ENDCSONeNBIdentification")
	}
	padding, err := aper.CaptureFinalBits(bb, "ENDCSONeNBIdentification")
	if err != nil {
		return runtime.WrapDecodePath(err, "ENDCSONeNBIdentification")
	}
	v.perPadding = padding.WithRecords(v.perPadding)
	return nil
}
func (v *ENDCSONeNBIdentification) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = ENDCSONeNBIdentification{}
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
	toleranceMark_globalenbid := bb.EnterComponent("GlobaleNBID")
	if err := s18.BridgeGlobalENBIDMethodUnmarshalAPERFrom(&v.GlobaleNBID, bb); err != nil {
		return runtime.WrapDecodePath(err, "GlobaleNBID")
	}
	bb.LeaveComponent(toleranceMark_globalenbid)
	toleranceMark_selectedtai := bb.EnterComponent("SelectedTAI")
	if err := v.SelectedTAI.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "SelectedTAI")
	}
	bb.LeaveComponent(toleranceMark_selectedtai)
	if opt_ieextensions {
		tmp_ieextensions := make(s08.ENDCSONeNBIdentificationExtIEsExtContainer, 0)
		_, errCollection_ieextensions := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1128
			if fragmentOffset_ieextensions < 0 || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(^uint(0)>>1) || fragmentOffset_ieextensions > int64(^uint(0)>>1)-fragmentLength_ieextensions {
				return fmt.Errorf("collection fragment count out of range")
			}
			for i := int64(0); i < fragmentLength_ieextensions; i++ {
				var elem s08.ENDCSONeNBIdentificationExtIEsExtField
				if err := s08.BridgeENDCSONeNBIdentificationExtIEsExtFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
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

// MarshalAPER encodes ENDCSONengNBIdentification to APER format.
func (v *ENDCSONengNBIdentification) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *ENDCSONengNBIdentification) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
	if err := s18.BridgeGlobalEnGNBIDMethodMarshalAPERTo(&v.GlobalengNBID, bb, len(fresh) != 0 && fresh[0]); err != nil {
		return fmt.Errorf("encoding globalengNBID: %w", err)
	}
	if err := v.SelectedTAI.marshalAPERTo(bb, len(fresh) != 0 && fresh[0]); err != nil {
		return fmt.Errorf("encoding selectedTAI: %w", err)
	}
	if v.IEExtensions != nil {
		if err := aper.EncodeCollection(bb, int64(len(v.IEExtensions)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
			if fragmentOffset_ieextensions < 0 || fragmentOffset_ieextensions > int64(len(v.IEExtensions)) || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(len(v.IEExtensions[fragmentOffset_ieextensions:])) {
				return fmt.Errorf("collection fragment outside value")
			}
			for _, elem := range v.IEExtensions[fragmentOffset_ieextensions : fragmentOffset_ieextensions+fragmentLength_ieextensions] {
				if err := s08.BridgeENDCSONengNBIdentificationExtIEsExtFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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

// UnmarshalAPER decodes ENDCSONengNBIdentification from APER format.
func (v *ENDCSONengNBIdentification) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes ENDCSONengNBIdentification with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *ENDCSONengNBIdentification) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "ENDCSONengNBIdentification")
	}
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "ENDCSONengNBIdentification")
	}
	padding, err := aper.CaptureFinalBits(bb, "ENDCSONengNBIdentification")
	if err != nil {
		return runtime.WrapDecodePath(err, "ENDCSONengNBIdentification")
	}
	v.perPadding = padding.WithRecords(v.perPadding)
	return nil
}
func (v *ENDCSONengNBIdentification) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = ENDCSONengNBIdentification{}
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
	toleranceMark_globalengnbid := bb.EnterComponent("GlobalengNBID")
	if err := s18.BridgeGlobalEnGNBIDMethodUnmarshalAPERFrom(&v.GlobalengNBID, bb); err != nil {
		return runtime.WrapDecodePath(err, "GlobalengNBID")
	}
	bb.LeaveComponent(toleranceMark_globalengnbid)
	toleranceMark_selectedtai := bb.EnterComponent("SelectedTAI")
	if err := v.SelectedTAI.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "SelectedTAI")
	}
	bb.LeaveComponent(toleranceMark_selectedtai)
	if opt_ieextensions {
		tmp_ieextensions := make(s08.ENDCSONengNBIdentificationExtIEsExtContainer, 0)
		_, errCollection_ieextensions := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1128
			if fragmentOffset_ieextensions < 0 || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(^uint(0)>>1) || fragmentOffset_ieextensions > int64(^uint(0)>>1)-fragmentLength_ieextensions {
				return fmt.Errorf("collection fragment count out of range")
			}
			for i := int64(0); i < fragmentLength_ieextensions; i++ {
				var elem s08.ENDCSONengNBIdentificationExtIEsExtField
				if err := s08.BridgeENDCSONengNBIdentificationExtIEsExtFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
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

// MarshalAPER encodes MMEPagingTarget to APER format.
func (v *MMEPagingTarget) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.perPadding)
}
func (v *MMEPagingTarget) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
			return fmt.Errorf("%s known choice %d and unknown extension are both selected", "MMEPagingTarget:", v.Choice)
		}
		if v.UnknownExtension.Index() < 0 {
			return fmt.Errorf("%s extension index %d must be non-negative", "MMEPagingTarget:", v.UnknownExtension.Index())
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
		return fmt.Errorf("%s choice %d must be positive", "MMEPagingTarget:", v.Choice)
	}
	isExtension := v.Choice > 2
	if err := aper.EncodeBoolean(bb, isExtension); err != nil {
		return err
	}
	if isExtension {
		return fmt.Errorf("%s extension choice %d not supported", "MMEPagingTarget:", v.Choice)
	}
	// arithmetic pattern APER_CHOICE_ROOT_ENCODE: choice index fits the emitted representation; gen/codegen_aper.go:149
	if v.Choice < 1 {
		return fmt.Errorf("choice index outside root")
	}
	if err := aper.EncodeConstrainedWholeNumberAligned(bb, int64(v.Choice-1), 0, 1); err != nil {
		return err
	}
	switch v.Choice {
	case s00.MMEPagingTargetChoiceGlobalENBID:
		if v.GlobalENBID == nil {
			return fmt.Errorf("choice alternative global-ENB-ID is nil")
		}
		if err := s18.BridgeGlobalENBIDMethodMarshalAPERTo(v.GlobalENBID, bb, len(fresh) != 0 && fresh[0]); err != nil {
			return fmt.Errorf("encoding global-ENB-ID: %w", err)
		}
	case s00.MMEPagingTargetChoiceTAI:
		if v.TAI == nil {
			return fmt.Errorf("choice alternative tAI is nil")
		}
		if err := v.TAI.marshalAPERTo(bb, len(fresh) != 0 && fresh[0]); err != nil {
			return fmt.Errorf("encoding tAI: %w", err)
		}
	default:
		return fmt.Errorf("unknown MMEPagingTarget choice %d", v.Choice)
	}
	return nil
}

// UnmarshalAPER decodes MMEPagingTarget from APER format.
func (v *MMEPagingTarget) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes MMEPagingTarget with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *MMEPagingTarget) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "MMEPagingTarget")
	}
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "MMEPagingTarget")
	}
	padding, err := aper.CaptureFinalBits(bb, "MMEPagingTarget")
	if err != nil {
		return runtime.WrapDecodePath(err, "MMEPagingTarget")
	}
	v.perPadding = padding.Padding()
	return nil
}
func (v *MMEPagingTarget) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = MMEPagingTarget{}
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
	case s00.MMEPagingTargetChoiceGlobalENBID:
		toleranceMark_globalenbid := bb.EnterComponent("GlobalENBID")
		var dec_globalenbid s18.GlobalENBID
		if err := s18.BridgeGlobalENBIDMethodUnmarshalAPERFrom(&dec_globalenbid, bb); err != nil {
			return runtime.WrapDecodePath(err, "GlobalENBID")
		}
		if err := aper.ChargeValue(bb, dec_globalenbid); err != nil {
			return err
		}
		v.GlobalENBID = &dec_globalenbid
		bb.LeaveComponent(toleranceMark_globalenbid)
	case s00.MMEPagingTargetChoiceTAI:
		toleranceMark_tai := bb.EnterComponent("TAI")
		var dec_tai TAI
		if err := dec_tai.unmarshalAPERFrom(bb); err != nil {
			return runtime.WrapDecodePath(err, "TAI")
		}
		if err := aper.ChargeValue(bb, dec_tai); err != nil {
			return err
		}
		v.TAI = &dec_tai
		bb.LeaveComponent(toleranceMark_tai)
	}
	v.stream = bb.CaptureWireSpan(replayStart)

	return nil
}

// MarshalAPER encodes RecommendedENBItem to APER format.
func (v *RecommendedENBItem) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *RecommendedENBItem) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
	if err := v.MMEPagingTarget.marshalAPERTo(bb, len(fresh) != 0 && fresh[0]); err != nil {
		return fmt.Errorf("encoding mMEPagingTarget: %w", err)
	}
	if v.IEExtensions != nil {
		if err := aper.EncodeCollection(bb, int64(len(v.IEExtensions)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
			if fragmentOffset_ieextensions < 0 || fragmentOffset_ieextensions > int64(len(v.IEExtensions)) || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(len(v.IEExtensions[fragmentOffset_ieextensions:])) {
				return fmt.Errorf("collection fragment outside value")
			}
			for _, elem := range v.IEExtensions[fragmentOffset_ieextensions : fragmentOffset_ieextensions+fragmentLength_ieextensions] {
				if err := s11.BridgeRecommendedENBItemExtIEsExtFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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

// UnmarshalAPER decodes RecommendedENBItem from APER format.
func (v *RecommendedENBItem) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes RecommendedENBItem with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *RecommendedENBItem) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "RecommendedENBItem")
	}
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "RecommendedENBItem")
	}
	padding, err := aper.CaptureFinalBits(bb, "RecommendedENBItem")
	if err != nil {
		return runtime.WrapDecodePath(err, "RecommendedENBItem")
	}
	v.perPadding = padding.WithRecords(v.perPadding)
	return nil
}
func (v *RecommendedENBItem) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = RecommendedENBItem{}
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
	toleranceMark_mmepagingtarget := bb.EnterComponent("MMEPagingTarget")
	if err := v.MMEPagingTarget.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "MMEPagingTarget")
	}
	bb.LeaveComponent(toleranceMark_mmepagingtarget)
	if opt_ieextensions {
		tmp_ieextensions := make(s11.RecommendedENBItemExtIEsExtContainer, 0)
		_, errCollection_ieextensions := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1128
			if fragmentOffset_ieextensions < 0 || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(^uint(0)>>1) || fragmentOffset_ieextensions > int64(^uint(0)>>1)-fragmentLength_ieextensions {
				return fmt.Errorf("collection fragment count out of range")
			}
			for i := int64(0); i < fragmentLength_ieextensions; i++ {
				var elem s11.RecommendedENBItemExtIEsExtField
				if err := s11.BridgeRecommendedENBItemExtIEsExtFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
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

// MarshalAPER encodes SynchronisationInformation to APER format.
func (v *SynchronisationInformation) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *SynchronisationInformation) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
	if err := aper.EncodeBoolean(bb, v.SourceStratumLevel != nil); err != nil {
		return err
	}
	if err := aper.EncodeBoolean(bb, v.ListeningSubframePattern != nil); err != nil {
		return err
	}
	if err := aper.EncodeBoolean(bb, v.AggressoreCGIList != nil); err != nil {
		return err
	}
	if err := aper.EncodeBoolean(bb, v.IEExtensions != nil); err != nil {
		return err
	}
	if v.SourceStratumLevel != nil {
		if err := aper.EncodeIntegerBigBoundsAligned(bb, v.SourceStratumLevel, s00.BridgeAsn1IntegerBound0, s00.BridgeAsn1IntegerBound9, true); err != nil {
			return fmt.Errorf("encoding sourceStratumLevel: %w", err)
		}
	}
	if v.ListeningSubframePattern != nil {
		if err := s18.BridgeListeningSubframePatternMethodMarshalAPERTo(v.ListeningSubframePattern, bb, len(fresh) != 0 && fresh[0]); err != nil {
			return fmt.Errorf("encoding listeningSubframePattern: %w", err)
		}
	}
	if v.AggressoreCGIList != nil {
		if err := aper.EncodeCollection(bb, int64(len(v.AggressoreCGIList)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 256, HasUpper: true}, true, func(fragmentOffset_aggressorecgilist, fragmentLength_aggressorecgilist int64) error {
			// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
			if fragmentOffset_aggressorecgilist < 0 || fragmentOffset_aggressorecgilist > int64(len(v.AggressoreCGIList)) || fragmentLength_aggressorecgilist < 0 || fragmentLength_aggressorecgilist > int64(len(v.AggressoreCGIList[fragmentOffset_aggressorecgilist:])) {
				return fmt.Errorf("collection fragment outside value")
			}
			for _, elem := range v.AggressoreCGIList[fragmentOffset_aggressorecgilist : fragmentOffset_aggressorecgilist+fragmentLength_aggressorecgilist] {
				if err := s17.BridgeEUTRANCGIMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
					return fmt.Errorf("encoding aggressoreCGI-List element: %w", err)
				}
			}
			return nil
		}); err != nil {
			return fmt.Errorf("encoding aggressoreCGI-List: %w", err)
		}
	}
	if v.IEExtensions != nil {
		if err := aper.EncodeCollection(bb, int64(len(v.IEExtensions)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
			if fragmentOffset_ieextensions < 0 || fragmentOffset_ieextensions > int64(len(v.IEExtensions)) || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(len(v.IEExtensions[fragmentOffset_ieextensions:])) {
				return fmt.Errorf("collection fragment outside value")
			}
			for _, elem := range v.IEExtensions[fragmentOffset_ieextensions : fragmentOffset_ieextensions+fragmentLength_ieextensions] {
				if err := s11.BridgeSynchronisationInformationExtIEsExtFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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

// UnmarshalAPER decodes SynchronisationInformation from APER format.
func (v *SynchronisationInformation) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes SynchronisationInformation with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *SynchronisationInformation) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "SynchronisationInformation")
	}
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "SynchronisationInformation")
	}
	padding, err := aper.CaptureFinalBits(bb, "SynchronisationInformation")
	if err != nil {
		return runtime.WrapDecodePath(err, "SynchronisationInformation")
	}
	v.perPadding = padding.WithRecords(v.perPadding)
	return nil
}
func (v *SynchronisationInformation) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = SynchronisationInformation{}
	extAdditions := aper.BeginExtensionAdditions(bb)
	hasExtensions, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	// Read preamble bitmap for optional root fields
	opt_sourcestratumlevel, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	opt_listeningsubframepattern, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	opt_aggressorecgilist, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	opt_ieextensions, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	if opt_sourcestratumlevel {
		val_sourcestratumlevel, err := aper.DecodeIntegerBigBoundsAligned(bb, s00.BridgeAsn1IntegerBound0, s00.BridgeAsn1IntegerBound9, true)
		if err != nil {
			return runtime.WrapDecodePath(err, "SourceStratumLevel")
		}
		v.SourceStratumLevel = val_sourcestratumlevel
	}
	if opt_listeningsubframepattern {
		toleranceMark_listeningsubframepattern := bb.EnterComponent("ListeningSubframePattern")
		var dec_listeningsubframepattern s18.ListeningSubframePattern
		if err := s18.BridgeListeningSubframePatternMethodUnmarshalAPERFrom(&dec_listeningsubframepattern, bb); err != nil {
			return runtime.WrapDecodePath(err, "ListeningSubframePattern")
		}
		if err := aper.ChargeValue(bb, dec_listeningsubframepattern); err != nil {
			return err
		}
		v.ListeningSubframePattern = &dec_listeningsubframepattern
		bb.LeaveComponent(toleranceMark_listeningsubframepattern)
	}
	if opt_aggressorecgilist {
		toleranceMark_aggressorecgilist := bb.EnterComponent("AggressoreCGIList")
		tmp_aggressorecgilist := make(s18.IEsECGIList, 0)
		_, errCollection_aggressorecgilist := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 256, HasUpper: true}, true, func(fragmentOffset_aggressorecgilist, fragmentLength_aggressorecgilist int64) error {
			// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1128
			if fragmentOffset_aggressorecgilist < 0 || fragmentLength_aggressorecgilist < 0 || fragmentLength_aggressorecgilist > int64(^uint(0)>>1) || fragmentOffset_aggressorecgilist > int64(^uint(0)>>1)-fragmentLength_aggressorecgilist {
				return fmt.Errorf("collection fragment count out of range")
			}
			for i := int64(0); i < fragmentLength_aggressorecgilist; i++ {
				var elem s17.EUTRANCGI
				elementMark := bb.EnterIndex(fragmentOffset_aggressorecgilist + i)
				if err := s17.BridgeEUTRANCGIMethodUnmarshalAPERFrom(&elem, bb); err != nil {
					return runtime.WrapDecodePath(err, fmt.Sprintf("AggressoreCGIList[%d]", fragmentOffset_aggressorecgilist+i))
				}
				bb.LeaveComponent(elementMark)
				if next, err := aper.AppendValues(bb, tmp_aggressorecgilist, elem); err != nil {
					return err
				} else {
					tmp_aggressorecgilist = next
				}
			}
			return nil
		})
		if errCollection_aggressorecgilist != nil {
			return runtime.WrapDecodePath(errCollection_aggressorecgilist, "AggressoreCGIList")
		}
		v.AggressoreCGIList = tmp_aggressorecgilist
		bb.LeaveComponent(toleranceMark_aggressorecgilist)
	}
	if opt_ieextensions {
		tmp_ieextensions := make(s11.SynchronisationInformationExtIEsExtContainer, 0)
		_, errCollection_ieextensions := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1128
			if fragmentOffset_ieextensions < 0 || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(^uint(0)>>1) || fragmentOffset_ieextensions > int64(^uint(0)>>1)-fragmentLength_ieextensions {
				return fmt.Errorf("collection fragment count out of range")
			}
			for i := int64(0); i < fragmentLength_ieextensions; i++ {
				var elem s11.SynchronisationInformationExtIEsExtField
				if err := s11.BridgeSynchronisationInformationExtIEsExtFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
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

type BridgeAsn1cAPERSupportedTAsListValue struct{ Value SupportedTAs }

// MarshalAPERSupportedTAsTo appends a SupportedTAs list to bb.
func BridgeMarshalAPERSupportedTAsTo(list SupportedTAs, bb *aper.BitBuffer, fresh ...bool) error {
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()

	v := BridgeAsn1cAPERSupportedTAsListValue{Value: list}
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

// MarshalAPER encodes SupportedTAsItem to APER format.
func (v *SupportedTAsItem) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *SupportedTAsItem) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
	if err := aper.EncodeOctetStringAligned(bb, []byte(v.TAC), 2, 2, true); err != nil {
		return fmt.Errorf("encoding tAC: %w", err)
	}
	if err := aper.EncodeCollection(bb, int64(len(v.BroadcastPLMNs)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 6, HasUpper: true}, true, func(fragmentOffset_broadcastplmns, fragmentLength_broadcastplmns int64) error {
		// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
		if fragmentOffset_broadcastplmns < 0 || fragmentOffset_broadcastplmns > int64(len(v.BroadcastPLMNs)) || fragmentLength_broadcastplmns < 0 || fragmentLength_broadcastplmns > int64(len(v.BroadcastPLMNs[fragmentOffset_broadcastplmns:])) {
			return fmt.Errorf("collection fragment outside value")
		}
		for _, elem := range v.BroadcastPLMNs[fragmentOffset_broadcastplmns : fragmentOffset_broadcastplmns+fragmentLength_broadcastplmns] {
			if err := aper.EncodeOctetStringAligned(bb, []byte(elem), 3, 3, true); err != nil {
				return fmt.Errorf("encoding broadcastPLMNs element: %w", err)
			}
		}
		return nil
	}); err != nil {
		return fmt.Errorf("encoding broadcastPLMNs: %w", err)
	}
	if v.IEExtensions != nil {
		if err := aper.EncodeCollection(bb, int64(len(v.IEExtensions)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
			if fragmentOffset_ieextensions < 0 || fragmentOffset_ieextensions > int64(len(v.IEExtensions)) || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(len(v.IEExtensions[fragmentOffset_ieextensions:])) {
				return fmt.Errorf("collection fragment outside value")
			}
			for _, elem := range v.IEExtensions[fragmentOffset_ieextensions : fragmentOffset_ieextensions+fragmentLength_ieextensions] {
				if err := s11.BridgeSupportedTAsItemExtIEsExtFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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

// UnmarshalAPER decodes SupportedTAsItem from APER format.
func (v *SupportedTAsItem) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes SupportedTAsItem with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *SupportedTAsItem) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "SupportedTAsItem")
	}
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "SupportedTAsItem")
	}
	padding, err := aper.CaptureFinalBits(bb, "SupportedTAsItem")
	if err != nil {
		return runtime.WrapDecodePath(err, "SupportedTAsItem")
	}
	v.perPadding = padding.WithRecords(v.perPadding)
	return nil
}
func (v *SupportedTAsItem) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = SupportedTAsItem{}
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
	val_tac, err := aper.DecodeOctetStringAligned(bb, 2, 2, true)
	if err != nil {
		return runtime.WrapDecodePath(err, "TAC")
	}
	v.TAC = s00.TAC(val_tac)
	v.BroadcastPLMNs = make(s00.BPLMNs, 0)
	_, errCollection_broadcastplmns := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 6, HasUpper: true}, true, func(fragmentOffset_broadcastplmns, fragmentLength_broadcastplmns int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_5: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1191
		if fragmentOffset_broadcastplmns < 0 || fragmentLength_broadcastplmns < 0 || fragmentLength_broadcastplmns > int64(^uint(0)>>1) || fragmentOffset_broadcastplmns > int64(^uint(0)>>1)-fragmentLength_broadcastplmns {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_broadcastplmns; i++ {
			val, err := aper.DecodeOctetStringAligned(bb, 3, 3, true)
			if err != nil {
				return runtime.WrapDecodePath(err, fmt.Sprintf("BroadcastPLMNs[%d]", fragmentOffset_broadcastplmns+i))
			}
			if next, err := aper.AppendValues(bb, v.BroadcastPLMNs, val); err != nil {
				return err
			} else {
				v.BroadcastPLMNs = next
			}
		}
		return nil
	})
	if errCollection_broadcastplmns != nil {
		return runtime.WrapDecodePath(errCollection_broadcastplmns, "BroadcastPLMNs")
	}
	if opt_ieextensions {
		tmp_ieextensions := make(s11.SupportedTAsItemExtIEsExtContainer, 0)
		_, errCollection_ieextensions := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1128
			if fragmentOffset_ieextensions < 0 || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(^uint(0)>>1) || fragmentOffset_ieextensions > int64(^uint(0)>>1)-fragmentLength_ieextensions {
				return fmt.Errorf("collection fragment count out of range")
			}
			for i := int64(0); i < fragmentLength_ieextensions; i++ {
				var elem s11.SupportedTAsItemExtIEsExtField
				if err := s11.BridgeSupportedTAsItemExtIEsExtFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
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

// MarshalAPER encodes TAI to APER format.
func (v *TAI) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *TAI) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
	if err := aper.EncodeOctetStringAligned(bb, []byte(v.PLMNidentity), 3, 3, true); err != nil {
		return fmt.Errorf("encoding pLMNidentity: %w", err)
	}
	if err := aper.EncodeOctetStringAligned(bb, []byte(v.TAC), 2, 2, true); err != nil {
		return fmt.Errorf("encoding tAC: %w", err)
	}
	if v.IEExtensions != nil {
		if err := aper.EncodeCollection(bb, int64(len(v.IEExtensions)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
			if fragmentOffset_ieextensions < 0 || fragmentOffset_ieextensions > int64(len(v.IEExtensions)) || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(len(v.IEExtensions[fragmentOffset_ieextensions:])) {
				return fmt.Errorf("collection fragment outside value")
			}
			for _, elem := range v.IEExtensions[fragmentOffset_ieextensions : fragmentOffset_ieextensions+fragmentLength_ieextensions] {
				if err := s11.BridgeTAIExtIEsExtFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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

// UnmarshalAPER decodes TAI from APER format.
func (v *TAI) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes TAI with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *TAI) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "TAI")
	}
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "TAI")
	}
	padding, err := aper.CaptureFinalBits(bb, "TAI")
	if err != nil {
		return runtime.WrapDecodePath(err, "TAI")
	}
	v.perPadding = padding.WithRecords(v.perPadding)
	return nil
}
func (v *TAI) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = TAI{}
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
	val_plmnidentity, err := aper.DecodeOctetStringAligned(bb, 3, 3, true)
	if err != nil {
		return runtime.WrapDecodePath(err, "PLMNidentity")
	}
	v.PLMNidentity = s00.PLMNidentity(val_plmnidentity)
	val_tac, err := aper.DecodeOctetStringAligned(bb, 2, 2, true)
	if err != nil {
		return runtime.WrapDecodePath(err, "TAC")
	}
	v.TAC = s00.TAC(val_tac)
	if opt_ieextensions {
		tmp_ieextensions := make(s11.TAIExtIEsExtContainer, 0)
		_, errCollection_ieextensions := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1128
			if fragmentOffset_ieextensions < 0 || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(^uint(0)>>1) || fragmentOffset_ieextensions > int64(^uint(0)>>1)-fragmentLength_ieextensions {
				return fmt.Errorf("collection fragment count out of range")
			}
			for i := int64(0); i < fragmentLength_ieextensions; i++ {
				var elem s11.TAIExtIEsExtField
				if err := s11.BridgeTAIExtIEsExtFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
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

// MarshalAPER encodes TABasedMDT to APER format.
func (v *TABasedMDT) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *TABasedMDT) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
	if err := aper.EncodeCollection(bb, int64(len(v.TAListforMDT)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 8, HasUpper: true}, true, func(fragmentOffset_talistformdt, fragmentLength_talistformdt int64) error {
		// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
		if fragmentOffset_talistformdt < 0 || fragmentOffset_talistformdt > int64(len(v.TAListforMDT)) || fragmentLength_talistformdt < 0 || fragmentLength_talistformdt > int64(len(v.TAListforMDT[fragmentOffset_talistformdt:])) {
			return fmt.Errorf("collection fragment outside value")
		}
		for _, elem := range v.TAListforMDT[fragmentOffset_talistformdt : fragmentOffset_talistformdt+fragmentLength_talistformdt] {
			if err := aper.EncodeOctetStringAligned(bb, []byte(elem), 2, 2, true); err != nil {
				return fmt.Errorf("encoding tAListforMDT element: %w", err)
			}
		}
		return nil
	}); err != nil {
		return fmt.Errorf("encoding tAListforMDT: %w", err)
	}
	if v.IEExtensions != nil {
		if err := aper.EncodeCollection(bb, int64(len(v.IEExtensions)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
			if fragmentOffset_ieextensions < 0 || fragmentOffset_ieextensions > int64(len(v.IEExtensions)) || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(len(v.IEExtensions[fragmentOffset_ieextensions:])) {
				return fmt.Errorf("collection fragment outside value")
			}
			for _, elem := range v.IEExtensions[fragmentOffset_ieextensions : fragmentOffset_ieextensions+fragmentLength_ieextensions] {
				if err := s11.BridgeTABasedMDTExtIEsExtFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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

// UnmarshalAPER decodes TABasedMDT from APER format.
func (v *TABasedMDT) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes TABasedMDT with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *TABasedMDT) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "TABasedMDT")
	}
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "TABasedMDT")
	}
	padding, err := aper.CaptureFinalBits(bb, "TABasedMDT")
	if err != nil {
		return runtime.WrapDecodePath(err, "TABasedMDT")
	}
	v.perPadding = padding.WithRecords(v.perPadding)
	return nil
}
func (v *TABasedMDT) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = TABasedMDT{}
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
	v.TAListforMDT = make(s00.TAListforMDT, 0)
	_, errCollection_talistformdt := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 8, HasUpper: true}, true, func(fragmentOffset_talistformdt, fragmentLength_talistformdt int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_5: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1191
		if fragmentOffset_talistformdt < 0 || fragmentLength_talistformdt < 0 || fragmentLength_talistformdt > int64(^uint(0)>>1) || fragmentOffset_talistformdt > int64(^uint(0)>>1)-fragmentLength_talistformdt {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_talistformdt; i++ {
			val, err := aper.DecodeOctetStringAligned(bb, 2, 2, true)
			if err != nil {
				return runtime.WrapDecodePath(err, fmt.Sprintf("TAListforMDT[%d]", fragmentOffset_talistformdt+i))
			}
			if next, err := aper.AppendValues(bb, v.TAListforMDT, val); err != nil {
				return err
			} else {
				v.TAListforMDT = next
			}
		}
		return nil
	})
	if errCollection_talistformdt != nil {
		return runtime.WrapDecodePath(errCollection_talistformdt, "TAListforMDT")
	}
	if opt_ieextensions {
		tmp_ieextensions := make(s11.TABasedMDTExtIEsExtContainer, 0)
		_, errCollection_ieextensions := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1128
			if fragmentOffset_ieextensions < 0 || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(^uint(0)>>1) || fragmentOffset_ieextensions > int64(^uint(0)>>1)-fragmentLength_ieextensions {
				return fmt.Errorf("collection fragment count out of range")
			}
			for i := int64(0); i < fragmentLength_ieextensions; i++ {
				var elem s11.TABasedMDTExtIEsExtField
				if err := s11.BridgeTABasedMDTExtIEsExtFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
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

// MarshalAPER encodes TABasedQMC to APER format.
func (v *TABasedQMC) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *TABasedQMC) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
	if err := aper.EncodeCollection(bb, int64(len(v.TAListforQMC)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 8, HasUpper: true}, true, func(fragmentOffset_talistforqmc, fragmentLength_talistforqmc int64) error {
		// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
		if fragmentOffset_talistforqmc < 0 || fragmentOffset_talistforqmc > int64(len(v.TAListforQMC)) || fragmentLength_talistforqmc < 0 || fragmentLength_talistforqmc > int64(len(v.TAListforQMC[fragmentOffset_talistforqmc:])) {
			return fmt.Errorf("collection fragment outside value")
		}
		for _, elem := range v.TAListforQMC[fragmentOffset_talistforqmc : fragmentOffset_talistforqmc+fragmentLength_talistforqmc] {
			if err := aper.EncodeOctetStringAligned(bb, []byte(elem), 2, 2, true); err != nil {
				return fmt.Errorf("encoding tAListforQMC element: %w", err)
			}
		}
		return nil
	}); err != nil {
		return fmt.Errorf("encoding tAListforQMC: %w", err)
	}
	if v.IEExtensions != nil {
		if err := aper.EncodeCollection(bb, int64(len(v.IEExtensions)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
			if fragmentOffset_ieextensions < 0 || fragmentOffset_ieextensions > int64(len(v.IEExtensions)) || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(len(v.IEExtensions[fragmentOffset_ieextensions:])) {
				return fmt.Errorf("collection fragment outside value")
			}
			for _, elem := range v.IEExtensions[fragmentOffset_ieextensions : fragmentOffset_ieextensions+fragmentLength_ieextensions] {
				if err := s11.BridgeTABasedQMCExtIEsExtFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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

// UnmarshalAPER decodes TABasedQMC from APER format.
func (v *TABasedQMC) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes TABasedQMC with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *TABasedQMC) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "TABasedQMC")
	}
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "TABasedQMC")
	}
	padding, err := aper.CaptureFinalBits(bb, "TABasedQMC")
	if err != nil {
		return runtime.WrapDecodePath(err, "TABasedQMC")
	}
	v.perPadding = padding.WithRecords(v.perPadding)
	return nil
}
func (v *TABasedQMC) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = TABasedQMC{}
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
	v.TAListforQMC = make(s00.TAListforQMC, 0)
	_, errCollection_talistforqmc := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 8, HasUpper: true}, true, func(fragmentOffset_talistforqmc, fragmentLength_talistforqmc int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_5: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1191
		if fragmentOffset_talistforqmc < 0 || fragmentLength_talistforqmc < 0 || fragmentLength_talistforqmc > int64(^uint(0)>>1) || fragmentOffset_talistforqmc > int64(^uint(0)>>1)-fragmentLength_talistforqmc {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_talistforqmc; i++ {
			val, err := aper.DecodeOctetStringAligned(bb, 2, 2, true)
			if err != nil {
				return runtime.WrapDecodePath(err, fmt.Sprintf("TAListforQMC[%d]", fragmentOffset_talistforqmc+i))
			}
			if next, err := aper.AppendValues(bb, v.TAListforQMC, val); err != nil {
				return err
			} else {
				v.TAListforQMC = next
			}
		}
		return nil
	})
	if errCollection_talistforqmc != nil {
		return runtime.WrapDecodePath(errCollection_talistforqmc, "TAListforQMC")
	}
	if opt_ieextensions {
		tmp_ieextensions := make(s11.TABasedQMCExtIEsExtContainer, 0)
		_, errCollection_ieextensions := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1128
			if fragmentOffset_ieextensions < 0 || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(^uint(0)>>1) || fragmentOffset_ieextensions > int64(^uint(0)>>1)-fragmentLength_ieextensions {
				return fmt.Errorf("collection fragment count out of range")
			}
			for i := int64(0); i < fragmentLength_ieextensions; i++ {
				var elem s11.TABasedQMCExtIEsExtField
				if err := s11.BridgeTABasedQMCExtIEsExtFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
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
func (v *ConnectedengNBItem) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s14.BridgeReceivedFormAt(v.received, v.receivedBytes, "ConnectedengNBItem", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "ConnectedengNBItem", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v ConnectedengNBItem) WithoutReplay() ConnectedengNBItem {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero ConnectedengNBItem
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *ENDCSONTransferType) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s14.BridgeReceivedFormAt(v.received, v.receivedBytes, "ENDCSONTransferType", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "ENDCSONTransferType", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v ENDCSONTransferType) WithoutReplay() ENDCSONTransferType {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero ENDCSONTransferType
	v.perPadding = zero.perPadding
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *ENDCSONeNBIdentification) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s14.BridgeReceivedFormAt(v.received, v.receivedBytes, "ENDCSONeNBIdentification", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "ENDCSONeNBIdentification", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v ENDCSONeNBIdentification) WithoutReplay() ENDCSONeNBIdentification {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero ENDCSONeNBIdentification
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *ENDCSONengNBIdentification) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s14.BridgeReceivedFormAt(v.received, v.receivedBytes, "ENDCSONengNBIdentification", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "ENDCSONengNBIdentification", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v ENDCSONengNBIdentification) WithoutReplay() ENDCSONengNBIdentification {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero ENDCSONengNBIdentification
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *ENDCTransferTypeReply) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s14.BridgeReceivedFormAt(v.received, v.receivedBytes, "ENDCTransferTypeReply", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "ENDCTransferTypeReply", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v ENDCTransferTypeReply) WithoutReplay() ENDCTransferTypeReply {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero ENDCTransferTypeReply
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *ENDCTransferTypeRequest) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s14.BridgeReceivedFormAt(v.received, v.receivedBytes, "ENDCTransferTypeRequest", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "ENDCTransferTypeRequest", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v ENDCTransferTypeRequest) WithoutReplay() ENDCTransferTypeRequest {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero ENDCTransferTypeRequest
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *MMEPagingTarget) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s14.BridgeReceivedFormAt(v.received, v.receivedBytes, "MMEPagingTarget", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "MMEPagingTarget", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v MMEPagingTarget) WithoutReplay() MMEPagingTarget {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero MMEPagingTarget
	v.perPadding = zero.perPadding
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *RecommendedENBItem) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s14.BridgeReceivedFormAt(v.received, v.receivedBytes, "RecommendedENBItem", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "RecommendedENBItem", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v RecommendedENBItem) WithoutReplay() RecommendedENBItem {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero RecommendedENBItem
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *SupportedTAsItem) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s14.BridgeReceivedFormAt(v.received, v.receivedBytes, "SupportedTAsItem", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "SupportedTAsItem", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v SupportedTAsItem) WithoutReplay() SupportedTAsItem {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero SupportedTAsItem
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *SynchronisationInformation) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s14.BridgeReceivedFormAt(v.received, v.receivedBytes, "SynchronisationInformation", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "SynchronisationInformation", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v SynchronisationInformation) WithoutReplay() SynchronisationInformation {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero SynchronisationInformation
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *TABasedMDT) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s14.BridgeReceivedFormAt(v.received, v.receivedBytes, "TABasedMDT", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "TABasedMDT", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v TABasedMDT) WithoutReplay() TABasedMDT {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero TABasedMDT
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *TABasedQMC) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s14.BridgeReceivedFormAt(v.received, v.receivedBytes, "TABasedQMC", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "TABasedQMC", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v TABasedQMC) WithoutReplay() TABasedQMC {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero TABasedQMC
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *TAI) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s14.BridgeReceivedFormAt(v.received, v.receivedBytes, "TAI", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "TAI", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v TAI) WithoutReplay() TAI {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero TAI
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// Extensions returns owned unknown sequence additions.
func (v *ConnectedengNBItem) Extensions() []aper.SequenceExtension {
	if v == nil {
		return nil
	}
	views := aper.SequenceExtensionViews(v.extPresent, aper.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *ConnectedengNBItem) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("ConnectedengNBItem.Extensions[%d]", index))
	}
	if err := aper.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("ConnectedengNBItem.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *ConnectedengNBItem) RemoveExtension(index uint64) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("ConnectedengNBItem.Extensions[%d]", index))
	}
	if err := aper.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("ConnectedengNBItem.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// Extensions returns owned unknown sequence additions.
func (v *ENDCSONeNBIdentification) Extensions() []aper.SequenceExtension {
	if v == nil {
		return nil
	}
	views := aper.SequenceExtensionViews(v.extPresent, aper.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *ENDCSONeNBIdentification) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("ENDCSONeNBIdentification.Extensions[%d]", index))
	}
	if err := aper.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("ENDCSONeNBIdentification.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *ENDCSONeNBIdentification) RemoveExtension(index uint64) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("ENDCSONeNBIdentification.Extensions[%d]", index))
	}
	if err := aper.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("ENDCSONeNBIdentification.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// Extensions returns owned unknown sequence additions.
func (v *ENDCSONengNBIdentification) Extensions() []aper.SequenceExtension {
	if v == nil {
		return nil
	}
	views := aper.SequenceExtensionViews(v.extPresent, aper.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *ENDCSONengNBIdentification) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("ENDCSONengNBIdentification.Extensions[%d]", index))
	}
	if err := aper.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("ENDCSONengNBIdentification.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *ENDCSONengNBIdentification) RemoveExtension(index uint64) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("ENDCSONengNBIdentification.Extensions[%d]", index))
	}
	if err := aper.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("ENDCSONengNBIdentification.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// Extensions returns owned unknown sequence additions.
func (v *ENDCTransferTypeReply) Extensions() []aper.SequenceExtension {
	if v == nil {
		return nil
	}
	views := aper.SequenceExtensionViews(v.extPresent, aper.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *ENDCTransferTypeReply) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("ENDCTransferTypeReply.Extensions[%d]", index))
	}
	if err := aper.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("ENDCTransferTypeReply.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *ENDCTransferTypeReply) RemoveExtension(index uint64) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("ENDCTransferTypeReply.Extensions[%d]", index))
	}
	if err := aper.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("ENDCTransferTypeReply.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// Extensions returns owned unknown sequence additions.
func (v *ENDCTransferTypeRequest) Extensions() []aper.SequenceExtension {
	if v == nil {
		return nil
	}
	views := aper.SequenceExtensionViews(v.extPresent, aper.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *ENDCTransferTypeRequest) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("ENDCTransferTypeRequest.Extensions[%d]", index))
	}
	if err := aper.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("ENDCTransferTypeRequest.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *ENDCTransferTypeRequest) RemoveExtension(index uint64) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("ENDCTransferTypeRequest.Extensions[%d]", index))
	}
	if err := aper.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("ENDCTransferTypeRequest.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// Extensions returns owned unknown sequence additions.
func (v *RecommendedENBItem) Extensions() []aper.SequenceExtension {
	if v == nil {
		return nil
	}
	views := aper.SequenceExtensionViews(v.extPresent, aper.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *RecommendedENBItem) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("RecommendedENBItem.Extensions[%d]", index))
	}
	if err := aper.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("RecommendedENBItem.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *RecommendedENBItem) RemoveExtension(index uint64) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("RecommendedENBItem.Extensions[%d]", index))
	}
	if err := aper.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("RecommendedENBItem.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// Extensions returns owned unknown sequence additions.
func (v *SupportedTAsItem) Extensions() []aper.SequenceExtension {
	if v == nil {
		return nil
	}
	views := aper.SequenceExtensionViews(v.extPresent, aper.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *SupportedTAsItem) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("SupportedTAsItem.Extensions[%d]", index))
	}
	if err := aper.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("SupportedTAsItem.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *SupportedTAsItem) RemoveExtension(index uint64) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("SupportedTAsItem.Extensions[%d]", index))
	}
	if err := aper.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("SupportedTAsItem.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// Extensions returns owned unknown sequence additions.
func (v *SynchronisationInformation) Extensions() []aper.SequenceExtension {
	if v == nil {
		return nil
	}
	views := aper.SequenceExtensionViews(v.extPresent, aper.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *SynchronisationInformation) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("SynchronisationInformation.Extensions[%d]", index))
	}
	if err := aper.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("SynchronisationInformation.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *SynchronisationInformation) RemoveExtension(index uint64) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("SynchronisationInformation.Extensions[%d]", index))
	}
	if err := aper.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("SynchronisationInformation.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// Extensions returns owned unknown sequence additions.
func (v *TABasedMDT) Extensions() []aper.SequenceExtension {
	if v == nil {
		return nil
	}
	views := aper.SequenceExtensionViews(v.extPresent, aper.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *TABasedMDT) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("TABasedMDT.Extensions[%d]", index))
	}
	if err := aper.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("TABasedMDT.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *TABasedMDT) RemoveExtension(index uint64) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("TABasedMDT.Extensions[%d]", index))
	}
	if err := aper.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("TABasedMDT.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// Extensions returns owned unknown sequence additions.
func (v *TABasedQMC) Extensions() []aper.SequenceExtension {
	if v == nil {
		return nil
	}
	views := aper.SequenceExtensionViews(v.extPresent, aper.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *TABasedQMC) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("TABasedQMC.Extensions[%d]", index))
	}
	if err := aper.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("TABasedQMC.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *TABasedQMC) RemoveExtension(index uint64) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("TABasedQMC.Extensions[%d]", index))
	}
	if err := aper.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("TABasedQMC.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// Extensions returns owned unknown sequence additions.
func (v *TAI) Extensions() []aper.SequenceExtension {
	if v == nil {
		return nil
	}
	views := aper.SequenceExtensionViews(v.extPresent, aper.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *TAI) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("TAI.Extensions[%d]", index))
	}
	if err := aper.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("TAI.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *TAI) RemoveExtension(index uint64) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("TAI.Extensions[%d]", index))
	}
	if err := aper.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("TAI.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// MarshalAPER encodes a complete value using one per-call change plan.
func (v *ConnectedengNBItem) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "ConnectedengNBItem")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *ConnectedengNBItem) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "ConnectedengNBItem")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APConnectedengNBItem(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "ConnectedengNBItem")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "ConnectedengNBItem")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *ConnectedengNBItem) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "ConnectedengNBItem")
}
func (v *ConnectedengNBItem) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "ConnectedengNBItem")
}
func (v *ConnectedengNBItem) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APConnectedengNBItem(v, &s)
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
func (v *ConnectedengNBItem) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *ConnectedengNBItem) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
func (v *ENDCSONTransferType) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "ENDCSONTransferType")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *ENDCSONTransferType) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "ENDCSONTransferType")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APENDCSONTransferType(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "ENDCSONTransferType")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "ENDCSONTransferType")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *ENDCSONTransferType) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "ENDCSONTransferType")
}
func (v *ENDCSONTransferType) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "ENDCSONTransferType")
}
func (v *ENDCSONTransferType) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APENDCSONTransferType(v, &s)
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
func (v *ENDCSONTransferType) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *ENDCSONTransferType) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
func (v *ENDCSONeNBIdentification) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "ENDCSONeNBIdentification")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *ENDCSONeNBIdentification) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "ENDCSONeNBIdentification")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APENDCSONeNBIdentification(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "ENDCSONeNBIdentification")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "ENDCSONeNBIdentification")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *ENDCSONeNBIdentification) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "ENDCSONeNBIdentification")
}
func (v *ENDCSONeNBIdentification) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "ENDCSONeNBIdentification")
}
func (v *ENDCSONeNBIdentification) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APENDCSONeNBIdentification(v, &s)
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
func (v *ENDCSONeNBIdentification) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *ENDCSONeNBIdentification) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
func (v *ENDCSONengNBIdentification) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "ENDCSONengNBIdentification")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *ENDCSONengNBIdentification) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "ENDCSONengNBIdentification")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APENDCSONengNBIdentification(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "ENDCSONengNBIdentification")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "ENDCSONengNBIdentification")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *ENDCSONengNBIdentification) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "ENDCSONengNBIdentification")
}
func (v *ENDCSONengNBIdentification) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "ENDCSONengNBIdentification")
}
func (v *ENDCSONengNBIdentification) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APENDCSONengNBIdentification(v, &s)
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
func (v *ENDCSONengNBIdentification) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *ENDCSONengNBIdentification) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
func (v *ENDCTransferTypeReply) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "ENDCTransferTypeReply")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *ENDCTransferTypeReply) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "ENDCTransferTypeReply")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APENDCTransferTypeReply(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "ENDCTransferTypeReply")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "ENDCTransferTypeReply")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *ENDCTransferTypeReply) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "ENDCTransferTypeReply")
}
func (v *ENDCTransferTypeReply) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "ENDCTransferTypeReply")
}
func (v *ENDCTransferTypeReply) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APENDCTransferTypeReply(v, &s)
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
func (v *ENDCTransferTypeReply) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *ENDCTransferTypeReply) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
func (v *ENDCTransferTypeRequest) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "ENDCTransferTypeRequest")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *ENDCTransferTypeRequest) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "ENDCTransferTypeRequest")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APENDCTransferTypeRequest(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "ENDCTransferTypeRequest")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "ENDCTransferTypeRequest")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *ENDCTransferTypeRequest) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "ENDCTransferTypeRequest")
}
func (v *ENDCTransferTypeRequest) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "ENDCTransferTypeRequest")
}
func (v *ENDCTransferTypeRequest) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APENDCTransferTypeRequest(v, &s)
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
func (v *ENDCTransferTypeRequest) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *ENDCTransferTypeRequest) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
func (v *MMEPagingTarget) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "MMEPagingTarget")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *MMEPagingTarget) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "MMEPagingTarget")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APMMEPagingTarget(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "MMEPagingTarget")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "MMEPagingTarget")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *MMEPagingTarget) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "MMEPagingTarget")
}
func (v *MMEPagingTarget) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "MMEPagingTarget")
}
func (v *MMEPagingTarget) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APMMEPagingTarget(v, &s)
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
func (v *MMEPagingTarget) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *MMEPagingTarget) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
func (v *RecommendedENBItem) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "RecommendedENBItem")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *RecommendedENBItem) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "RecommendedENBItem")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APRecommendedENBItem(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "RecommendedENBItem")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "RecommendedENBItem")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *RecommendedENBItem) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "RecommendedENBItem")
}
func (v *RecommendedENBItem) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "RecommendedENBItem")
}
func (v *RecommendedENBItem) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APRecommendedENBItem(v, &s)
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
func (v *RecommendedENBItem) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *RecommendedENBItem) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
func (v *SupportedTAsItem) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "SupportedTAsItem")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *SupportedTAsItem) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "SupportedTAsItem")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APSupportedTAsItem(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "SupportedTAsItem")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "SupportedTAsItem")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *SupportedTAsItem) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "SupportedTAsItem")
}
func (v *SupportedTAsItem) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "SupportedTAsItem")
}
func (v *SupportedTAsItem) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APSupportedTAsItem(v, &s)
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
func (v *SupportedTAsItem) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *SupportedTAsItem) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
func (v *SynchronisationInformation) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "SynchronisationInformation")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *SynchronisationInformation) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "SynchronisationInformation")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APSynchronisationInformation(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "SynchronisationInformation")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "SynchronisationInformation")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *SynchronisationInformation) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "SynchronisationInformation")
}
func (v *SynchronisationInformation) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "SynchronisationInformation")
}
func (v *SynchronisationInformation) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APSynchronisationInformation(v, &s)
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
func (v *SynchronisationInformation) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *SynchronisationInformation) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
func (v *TABasedMDT) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "TABasedMDT")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *TABasedMDT) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "TABasedMDT")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APTABasedMDT(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "TABasedMDT")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "TABasedMDT")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *TABasedMDT) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "TABasedMDT")
}
func (v *TABasedMDT) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "TABasedMDT")
}
func (v *TABasedMDT) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APTABasedMDT(v, &s)
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
func (v *TABasedMDT) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *TABasedMDT) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
func (v *TABasedQMC) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "TABasedQMC")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *TABasedQMC) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "TABasedQMC")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APTABasedQMC(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "TABasedQMC")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "TABasedQMC")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *TABasedQMC) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "TABasedQMC")
}
func (v *TABasedQMC) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "TABasedQMC")
}
func (v *TABasedQMC) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APTABasedQMC(v, &s)
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
func (v *TABasedQMC) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *TABasedQMC) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
func (v *TAI) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "TAI")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *TAI) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "TAI")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APTAI(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "TAI")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "TAI")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *TAI) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "TAI")
}
func (v *TAI) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "TAI")
}
func (v *TAI) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APTAI(v, &s)
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
func (v *TAI) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *TAI) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
func (v *ConnectedengNBItem) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "ConnectedengNBItem")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded ConnectedengNBItem
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APConnectedengNBItem(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = ConnectedengNBItem{}
		return report, aper.OperationError(err, "ConnectedengNBItem")
	}
	*v = decoded
	return report, aper.OperationError(nil, "ConnectedengNBItem")
}

// UnmarshalAPER decodes one complete value and returns its report.
func (v *ENDCSONTransferType) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "ENDCSONTransferType")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded ENDCSONTransferType
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APENDCSONTransferType(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = ENDCSONTransferType{}
		return report, aper.OperationError(err, "ENDCSONTransferType")
	}
	*v = decoded
	return report, aper.OperationError(nil, "ENDCSONTransferType")
}

// UnmarshalAPER decodes one complete value and returns its report.
func (v *ENDCSONeNBIdentification) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "ENDCSONeNBIdentification")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded ENDCSONeNBIdentification
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APENDCSONeNBIdentification(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = ENDCSONeNBIdentification{}
		return report, aper.OperationError(err, "ENDCSONeNBIdentification")
	}
	*v = decoded
	return report, aper.OperationError(nil, "ENDCSONeNBIdentification")
}

// UnmarshalAPER decodes one complete value and returns its report.
func (v *ENDCSONengNBIdentification) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "ENDCSONengNBIdentification")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded ENDCSONengNBIdentification
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APENDCSONengNBIdentification(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = ENDCSONengNBIdentification{}
		return report, aper.OperationError(err, "ENDCSONengNBIdentification")
	}
	*v = decoded
	return report, aper.OperationError(nil, "ENDCSONengNBIdentification")
}

// UnmarshalAPER decodes one complete value and returns its report.
func (v *ENDCTransferTypeReply) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "ENDCTransferTypeReply")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded ENDCTransferTypeReply
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APENDCTransferTypeReply(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = ENDCTransferTypeReply{}
		return report, aper.OperationError(err, "ENDCTransferTypeReply")
	}
	*v = decoded
	return report, aper.OperationError(nil, "ENDCTransferTypeReply")
}

// UnmarshalAPER decodes one complete value and returns its report.
func (v *ENDCTransferTypeRequest) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "ENDCTransferTypeRequest")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded ENDCTransferTypeRequest
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APENDCTransferTypeRequest(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = ENDCTransferTypeRequest{}
		return report, aper.OperationError(err, "ENDCTransferTypeRequest")
	}
	*v = decoded
	return report, aper.OperationError(nil, "ENDCTransferTypeRequest")
}

// UnmarshalAPER decodes one complete value and returns its report.
func (v *MMEPagingTarget) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "MMEPagingTarget")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded MMEPagingTarget
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APMMEPagingTarget(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = MMEPagingTarget{}
		return report, aper.OperationError(err, "MMEPagingTarget")
	}
	*v = decoded
	return report, aper.OperationError(nil, "MMEPagingTarget")
}

// UnmarshalAPER decodes one complete value and returns its report.
func (v *RecommendedENBItem) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "RecommendedENBItem")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded RecommendedENBItem
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APRecommendedENBItem(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = RecommendedENBItem{}
		return report, aper.OperationError(err, "RecommendedENBItem")
	}
	*v = decoded
	return report, aper.OperationError(nil, "RecommendedENBItem")
}

// UnmarshalAPER decodes one complete value and returns its report.
func (v *SupportedTAsItem) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "SupportedTAsItem")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded SupportedTAsItem
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APSupportedTAsItem(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = SupportedTAsItem{}
		return report, aper.OperationError(err, "SupportedTAsItem")
	}
	*v = decoded
	return report, aper.OperationError(nil, "SupportedTAsItem")
}

// UnmarshalAPER decodes one complete value and returns its report.
func (v *SynchronisationInformation) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "SynchronisationInformation")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded SynchronisationInformation
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APSynchronisationInformation(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = SynchronisationInformation{}
		return report, aper.OperationError(err, "SynchronisationInformation")
	}
	*v = decoded
	return report, aper.OperationError(nil, "SynchronisationInformation")
}

// UnmarshalAPER decodes one complete value and returns its report.
func (v *TABasedMDT) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "TABasedMDT")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded TABasedMDT
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APTABasedMDT(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = TABasedMDT{}
		return report, aper.OperationError(err, "TABasedMDT")
	}
	*v = decoded
	return report, aper.OperationError(nil, "TABasedMDT")
}

// UnmarshalAPER decodes one complete value and returns its report.
func (v *TABasedQMC) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "TABasedQMC")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded TABasedQMC
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APTABasedQMC(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = TABasedQMC{}
		return report, aper.OperationError(err, "TABasedQMC")
	}
	*v = decoded
	return report, aper.OperationError(nil, "TABasedQMC")
}

// UnmarshalAPER decodes one complete value and returns its report.
func (v *TAI) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "TAI")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded TAI
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APTAI(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = TAI{}
		return report, aper.OperationError(err, "TAI")
	}
	*v = decoded
	return report, aper.OperationError(nil, "TAI")
}

// NewENDCSONTransferTypeUnknownExtension builds a checked, owned unknown CHOICE alternative.
func NewENDCSONTransferTypeUnknownExtension(index uint64, contents []byte, options ...aper.BuildOption) (ENDCSONTransferType, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return ENDCSONTransferType{}, aper.OperationError(err, "ENDCSONTransferTypeUnknownExtension")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), aper.ChoiceExtension{}); err != nil {
		return ENDCSONTransferType{}, aper.OperationError(err, "ENDCSONTransferTypeUnknownExtension")
	}
	extension, err := aper.BuildChoiceExtension(index, contents, budget)
	if err != nil {
		return ENDCSONTransferType{}, aper.OperationError(err, "ENDCSONTransferTypeUnknownExtension")
	}
	value := ENDCSONTransferType{UnknownExtension: &extension}
	if _, err := value.marshalAPERBudget(budget, false); err != nil {
		return ENDCSONTransferType{}, aper.OperationError(err, "ENDCSONTransferTypeUnknownExtension")
	}
	return value, aper.OperationError(nil, "ENDCSONTransferTypeUnknownExtension")
}

// NewMMEPagingTargetUnknownExtension builds a checked, owned unknown CHOICE alternative.
func NewMMEPagingTargetUnknownExtension(index uint64, contents []byte, options ...aper.BuildOption) (MMEPagingTarget, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return MMEPagingTarget{}, aper.OperationError(err, "MMEPagingTargetUnknownExtension")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), aper.ChoiceExtension{}); err != nil {
		return MMEPagingTarget{}, aper.OperationError(err, "MMEPagingTargetUnknownExtension")
	}
	extension, err := aper.BuildChoiceExtension(index, contents, budget)
	if err != nil {
		return MMEPagingTarget{}, aper.OperationError(err, "MMEPagingTargetUnknownExtension")
	}
	value := MMEPagingTarget{UnknownExtension: &extension}
	if _, err := value.marshalAPERBudget(budget, false); err != nil {
		return MMEPagingTarget{}, aper.OperationError(err, "MMEPagingTargetUnknownExtension")
	}
	return value, aper.OperationError(nil, "MMEPagingTargetUnknownExtension")
}

// ConnectionEstablishmentIndication represents the ASN.1 type ConnectionEstablishmentIndication (SEQUENCE).
type ConnectionEstablishmentIndication struct {
	replay           aper.Snapshot
	stream           aper.WireSpan
	received         bool
	withoutReplay    bool
	receivedAbsolute bool
	receivedBytes    aper.WireSpan
	receivedLocation aper.Location
	ProtocolIEs      s30.ConnectionEstablishmentIndicationIEContainer `asn1:"tag:0,context,implicit"`
	protocolIEsIndef bool                                             `asn1:"-" json:"-"`
	extCount         int64                                            `asn1:"-" json:"-"`
	extPresent       []bool                                           `asn1:"-" json:"-"`
	extData          [][]byte                                         `asn1:"-" json:"-"`
	perPadding       aper.FinalPadding                                `asn1:"-" json:"-"`
	perExtPadding    []aper.CompletePadding                           `asn1:"-" json:"-"`
	extOrigin        []aper.OpaqueOrigin
	extWire          []aper.WireSpan
}

// MarshalAPER encodes ConnectionEstablishmentIndication to APER format.
func (v *ConnectionEstablishmentIndication) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *ConnectionEstablishmentIndication) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
			if err := s30.BridgeConnectionEstablishmentIndicationIEFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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

// UnmarshalAPER decodes ConnectionEstablishmentIndication from APER format.
func (v *ConnectionEstablishmentIndication) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes ConnectionEstablishmentIndication with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *ConnectionEstablishmentIndication) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "ConnectionEstablishmentIndication")
	}
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "ConnectionEstablishmentIndication")
	}
	padding, err := aper.CaptureFinalBits(bb, "ConnectionEstablishmentIndication")
	if err != nil {
		return runtime.WrapDecodePath(err, "ConnectionEstablishmentIndication")
	}
	v.perPadding = padding.WithRecords(v.perPadding)
	return nil
}
func (v *ConnectionEstablishmentIndication) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = ConnectionEstablishmentIndication{}
	extAdditions := aper.BeginExtensionAdditions(bb)
	hasExtensions, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	v.ProtocolIEs = make(s30.ConnectionEstablishmentIndicationIEContainer, 0)
	_, errCollection_protocolies := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1128
		if fragmentOffset_protocolies < 0 || fragmentLength_protocolies < 0 || fragmentLength_protocolies > int64(^uint(0)>>1) || fragmentOffset_protocolies > int64(^uint(0)>>1)-fragmentLength_protocolies {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_protocolies; i++ {
			var elem s30.ConnectionEstablishmentIndicationIEField
			if err := s30.BridgeConnectionEstablishmentIndicationIEFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
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
func (v *ConnectionEstablishmentIndication) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s14.BridgeReceivedFormAt(v.received, v.receivedBytes, "ConnectionEstablishmentIndication", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "ConnectionEstablishmentIndication", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v ConnectionEstablishmentIndication) WithoutReplay() ConnectionEstablishmentIndication {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero ConnectionEstablishmentIndication
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// Extensions returns owned unknown sequence additions.
func (v *ConnectionEstablishmentIndication) Extensions() []aper.SequenceExtension {
	if v == nil {
		return nil
	}
	views := aper.SequenceExtensionViews(v.extPresent, aper.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *ConnectionEstablishmentIndication) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("ConnectionEstablishmentIndication.Extensions[%d]", index))
	}
	if err := aper.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("ConnectionEstablishmentIndication.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *ConnectionEstablishmentIndication) RemoveExtension(index uint64) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("ConnectionEstablishmentIndication.Extensions[%d]", index))
	}
	if err := aper.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("ConnectionEstablishmentIndication.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// MarshalAPER encodes a complete value using one per-call change plan.
func (v *ConnectionEstablishmentIndication) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "ConnectionEstablishmentIndication")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *ConnectionEstablishmentIndication) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "ConnectionEstablishmentIndication")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APConnectionEstablishmentIndication(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "ConnectionEstablishmentIndication")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "ConnectionEstablishmentIndication")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *ConnectionEstablishmentIndication) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "ConnectionEstablishmentIndication")
}
func (v *ConnectionEstablishmentIndication) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "ConnectionEstablishmentIndication")
}
func (v *ConnectionEstablishmentIndication) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APConnectionEstablishmentIndication(v, &s)
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
func (v *ConnectionEstablishmentIndication) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *ConnectionEstablishmentIndication) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
func (v *ConnectionEstablishmentIndication) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "ConnectionEstablishmentIndication")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded ConnectionEstablishmentIndication
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APConnectionEstablishmentIndication(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = ConnectionEstablishmentIndication{}
		return report, aper.OperationError(err, "ConnectionEstablishmentIndication")
	}
	*v = decoded
	return report, aper.OperationError(nil, "ConnectionEstablishmentIndication")
}

type LocationReportIEValue struct {
	id                      s00.ProtocolIEID
	received                aper.WireSpan
	replay                  aper.Snapshot
	opaque                  aper.OpaqueOpenType
	isOpaque                bool
	rowMMEUES1APID          *s00.MMEUES1APID
	rowENBUES1APID          *s00.ENBUES1APID
	rowEUTRANCGI            *s17.EUTRANCGI
	rowTAI                  *TAI
	rowRequestType          *s26.RequestType
	rowPSCellInformation    *s20.PSCellInformation
	rowLTENTNTAIInformation *s18.LTENTNTAIInformation
}

func (v LocationReportIEValue) matchesID(id s00.ProtocolIEID, _ ...*aper.DecodeBudget) bool {
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
	case s00.ProtocolIEID(98):
		return v.rowRequestType != nil
	case s00.ProtocolIEID(288):
		return v.rowPSCellInformation != nil
	case s00.ProtocolIEID(339):
		return v.rowLTENTNTAIInformation != nil
	}
	return false
}

// Opaque returns the retained opaque open value of LocationReportIEValue and reports whether the opaque alternative is selected.
func (v *LocationReportIEValue) Opaque() (aper.OpaqueOpenType, bool) {
	if v == nil || !v.isOpaque {
		return aper.OpaqueOpenType{}, false
	}
	return v.opaque, true
}
func (LocationReportIEValue) rule() aper.SourceRule {
	return aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "LocationReportIEs"}}
}
func (LocationReportIEValue) reason(id s00.ProtocolIEID) aper.OpaqueReason {
	switch id {
	case s00.ProtocolIEID(0):
		return aper.UnknownSelector
	case s00.ProtocolIEID(8):
		return aper.UnknownSelector
	case s00.ProtocolIEID(100):
		return aper.UnknownSelector
	case s00.ProtocolIEID(67):
		return aper.UnknownSelector
	case s00.ProtocolIEID(98):
		return aper.UnknownSelector
	case s00.ProtocolIEID(288):
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

// AsMMEUES1APID returns the selected MMEUES1APID value of LocationReportIEValue and reports whether that alternative is active.
func (v *LocationReportIEValue) AsMMEUES1APID() (*s00.MMEUES1APID, bool) {
	if v == nil || v.id != s00.ProtocolIEID(0) || v.rowMMEUES1APID == nil {
		return nil, false
	}
	return v.rowMMEUES1APID, true
}

// AsENBUES1APID returns the selected ENBUES1APID value of LocationReportIEValue and reports whether that alternative is active.
func (v *LocationReportIEValue) AsENBUES1APID() (*s00.ENBUES1APID, bool) {
	if v == nil || v.id != s00.ProtocolIEID(8) || v.rowENBUES1APID == nil {
		return nil, false
	}
	return v.rowENBUES1APID, true
}

// AsEUTRANCGI returns the selected EUTRANCGI value of LocationReportIEValue and reports whether that alternative is active.
func (v *LocationReportIEValue) AsEUTRANCGI() (*s17.EUTRANCGI, bool) {
	if v == nil || v.id != s00.ProtocolIEID(100) || v.rowEUTRANCGI == nil {
		return nil, false
	}
	return v.rowEUTRANCGI, true
}

// AsTAI returns the selected TAI value of LocationReportIEValue and reports whether that alternative is active.
func (v *LocationReportIEValue) AsTAI() (*TAI, bool) {
	if v == nil || v.id != s00.ProtocolIEID(67) || v.rowTAI == nil {
		return nil, false
	}
	return v.rowTAI, true
}

// AsRequestType returns the selected RequestType value of LocationReportIEValue and reports whether that alternative is active.
func (v *LocationReportIEValue) AsRequestType() (*s26.RequestType, bool) {
	if v == nil || v.id != s00.ProtocolIEID(98) || v.rowRequestType == nil {
		return nil, false
	}
	return v.rowRequestType, true
}

// AsPSCellInformation returns the selected PSCellInformation value of LocationReportIEValue and reports whether that alternative is active.
func (v *LocationReportIEValue) AsPSCellInformation() (*s20.PSCellInformation, bool) {
	if v == nil || v.id != s00.ProtocolIEID(288) || v.rowPSCellInformation == nil {
		return nil, false
	}
	return v.rowPSCellInformation, true
}

// AsLTENTNTAIInformation returns the selected LTENTNTAIInformation value of LocationReportIEValue and reports whether that alternative is active.
func (v *LocationReportIEValue) AsLTENTNTAIInformation() (*s18.LTENTNTAIInformation, bool) {
	if v == nil || v.id != s00.ProtocolIEID(339) || v.rowLTENTNTAIInformation == nil {
		return nil, false
	}
	return v.rowLTENTNTAIInformation, true
}
func (v LocationReportIEValue) decode(id s00.ProtocolIEID, raw aper.OpaqueOpenType) (LocationReportIEValue, error) {
	out := LocationReportIEValue{id: id}
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
		var value TAI
		child := scope
		if err := value.unmarshalAPERFrom(child); err != nil {
			return out, fmt.Errorf("%s %w", "TAI:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "TAI")
		if err != nil {
			return out, err
		}
		value.perPadding = padding
		value.received = true
		raw.RetainContents(&value.receivedBytes)
		value.receivedLocation = raw.ContentLocation()
		out.rowTAI = &value
		raw.RetainContents(&out.received)
	case s00.ProtocolIEID(98):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		var value s26.RequestType
		child := scope
		if err := s26.BridgeRequestTypeMethodUnmarshalAPERFrom(&value, child); err != nil {
			return out, fmt.Errorf("%s %w", "RequestType:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "RequestType")
		if err != nil {
			return out, err
		}
		*s26.BridgeRequestTypeFieldPerPadding(&value) = padding
		*s26.BridgeRequestTypeFieldReceived(&value) = true
		raw.RetainContents(s26.BridgeRequestTypeFieldReceivedBytes(&value))
		*s26.BridgeRequestTypeFieldReceivedLocation(&value) = raw.ContentLocation()
		out.rowRequestType = &value
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
func (v LocationReportIEValue) encode() ([]byte, error) { return v.encodeFresh(false, nil) }
func (v LocationReportIEValue) encodeFresh(fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
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
			return nil, fmt.Errorf("%s missing value", "LocationReportIEs.id-MME-UE-S1AP-ID:")
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
			return nil, fmt.Errorf("%s missing value", "LocationReportIEs.id-eNB-UE-S1AP-ID:")
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
			return nil, fmt.Errorf("%s missing value", "LocationReportIEs.id-EUTRAN-CGI:")
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
			return nil, fmt.Errorf("%s missing value", "LocationReportIEs.id-TAI:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		candidate, err := v.rowTAI.marshalAPERBudget(budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	case s00.ProtocolIEID(98):
		if v.rowRequestType == nil {
			return nil, fmt.Errorf("%s missing value", "LocationReportIEs.id-RequestType:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		candidate, err := s26.BridgeRequestTypeMethodMarshalAPERBudget(v.rowRequestType, budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	case s00.ProtocolIEID(288):
		if v.rowPSCellInformation == nil {
			return nil, fmt.Errorf("%s missing value", "LocationReportIEs.id-PSCellInformation:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		candidate, err := s20.BridgePSCellInformationMethodMarshalAPERBudget(v.rowPSCellInformation, budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	case s00.ProtocolIEID(339):
		if v.rowLTENTNTAIInformation == nil {
			return nil, fmt.Errorf("%s missing value", "LocationReportIEs.id-LTE-NTN-TAI-Information:")
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
		return nil, fmt.Errorf("%s id %d has no value", "LocationReportIEValue:", v.id)
	}
}

type UEInformationTransferIEValue struct {
	id                                        s00.ProtocolIEID
	received                                  aper.WireSpan
	replay                                    aper.Snapshot
	opaque                                    aper.OpaqueOpenType
	isOpaque                                  bool
	rowSTMSI                                  *s27.STMSI
	rowUELevelQoSParameters                   *s18.ERABLevelQoSParameters
	rowUERadioCapability                      *s00.UERadioCapability
	rowSubscriptionBasedUEDifferentiationInfo *s30.SubscriptionBasedUEDifferentiationInfo
	rowPendingDataIndication                  *s00.PendingDataIndication
	rowMaskedIMEISV                           *s00.MaskedIMEISV
}

func (v UEInformationTransferIEValue) matchesID(id s00.ProtocolIEID, _ ...*aper.DecodeBudget) bool {
	if v.id != id {
		return false
	}
	if v.isOpaque {
		return true
	}
	switch id {
	case s00.ProtocolIEID(96):
		return v.rowSTMSI != nil
	case s00.ProtocolIEID(252):
		return v.rowUELevelQoSParameters != nil
	case s00.ProtocolIEID(74):
		return v.rowUERadioCapability != nil
	case s00.ProtocolIEID(278):
		return v.rowSubscriptionBasedUEDifferentiationInfo != nil
	case s00.ProtocolIEID(283):
		return v.rowPendingDataIndication != nil
	case s00.ProtocolIEID(192):
		return v.rowMaskedIMEISV != nil
	}
	return false
}

// Opaque returns the retained opaque open value of UEInformationTransferIEValue and reports whether the opaque alternative is selected.
func (v *UEInformationTransferIEValue) Opaque() (aper.OpaqueOpenType, bool) {
	if v == nil || !v.isOpaque {
		return aper.OpaqueOpenType{}, false
	}
	return v.opaque, true
}
func (UEInformationTransferIEValue) rule() aper.SourceRule {
	return aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "UEInformationTransferIEs"}}
}
func (UEInformationTransferIEValue) reason(id s00.ProtocolIEID) aper.OpaqueReason {
	switch id {
	case s00.ProtocolIEID(96):
		return aper.UnknownSelector
	case s00.ProtocolIEID(252):
		return aper.UnknownSelector
	case s00.ProtocolIEID(74):
		return aper.UnknownSelector
	case s00.ProtocolIEID(278):
		return aper.UnknownSelector
	case s00.ProtocolIEID(283):
		return aper.UnknownSelector
	case s00.ProtocolIEID(192):
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
	case s00.ProtocolIEID(280):
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

// AsSTMSI returns the selected STMSI value of UEInformationTransferIEValue and reports whether that alternative is active.
func (v *UEInformationTransferIEValue) AsSTMSI() (*s27.STMSI, bool) {
	if v == nil || v.id != s00.ProtocolIEID(96) || v.rowSTMSI == nil {
		return nil, false
	}
	return v.rowSTMSI, true
}

// AsUELevelQoSParameters returns the selected UELevelQoSParameters value of UEInformationTransferIEValue and reports whether that alternative is active.
func (v *UEInformationTransferIEValue) AsUELevelQoSParameters() (*s18.ERABLevelQoSParameters, bool) {
	if v == nil || v.id != s00.ProtocolIEID(252) || v.rowUELevelQoSParameters == nil {
		return nil, false
	}
	return v.rowUELevelQoSParameters, true
}

// AsUERadioCapability returns the selected UERadioCapability value of UEInformationTransferIEValue and reports whether that alternative is active.
func (v *UEInformationTransferIEValue) AsUERadioCapability() (*s00.UERadioCapability, bool) {
	if v == nil || v.id != s00.ProtocolIEID(74) || v.rowUERadioCapability == nil {
		return nil, false
	}
	return v.rowUERadioCapability, true
}

// AsSubscriptionBasedUEDifferentiationInfo returns the selected SubscriptionBasedUEDifferentiationInfo value of UEInformationTransferIEValue and reports whether that alternative is active.
func (v *UEInformationTransferIEValue) AsSubscriptionBasedUEDifferentiationInfo() (*s30.SubscriptionBasedUEDifferentiationInfo, bool) {
	if v == nil || v.id != s00.ProtocolIEID(278) || v.rowSubscriptionBasedUEDifferentiationInfo == nil {
		return nil, false
	}
	return v.rowSubscriptionBasedUEDifferentiationInfo, true
}

// AsPendingDataIndication returns the selected PendingDataIndication value of UEInformationTransferIEValue and reports whether that alternative is active.
func (v *UEInformationTransferIEValue) AsPendingDataIndication() (*s00.PendingDataIndication, bool) {
	if v == nil || v.id != s00.ProtocolIEID(283) || v.rowPendingDataIndication == nil {
		return nil, false
	}
	return v.rowPendingDataIndication, true
}

// AsMaskedIMEISV returns the selected MaskedIMEISV value of UEInformationTransferIEValue and reports whether that alternative is active.
func (v *UEInformationTransferIEValue) AsMaskedIMEISV() (*s00.MaskedIMEISV, bool) {
	if v == nil || v.id != s00.ProtocolIEID(192) || v.rowMaskedIMEISV == nil {
		return nil, false
	}
	return v.rowMaskedIMEISV, true
}
func (v UEInformationTransferIEValue) decode(id s00.ProtocolIEID, raw aper.OpaqueOpenType) (UEInformationTransferIEValue, error) {
	out := UEInformationTransferIEValue{id: id}
	switch id {
	case s00.ProtocolIEID(96):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		var value s27.STMSI
		child := scope
		if err := s27.BridgeSTMSIMethodUnmarshalAPERFrom(&value, child); err != nil {
			return out, fmt.Errorf("%s %w", "STMSI:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "STMSI")
		if err != nil {
			return out, err
		}
		*s27.BridgeSTMSIFieldPerPadding(&value) = padding
		*s27.BridgeSTMSIFieldReceived(&value) = true
		raw.RetainContents(s27.BridgeSTMSIFieldReceivedBytes(&value))
		*s27.BridgeSTMSIFieldReceivedLocation(&value) = raw.ContentLocation()
		out.rowSTMSI = &value
		raw.RetainContents(&out.received)
	case s00.ProtocolIEID(252):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		var value s18.ERABLevelQoSParameters
		child := scope
		if err := s18.BridgeERABLevelQoSParametersMethodUnmarshalAPERFrom(&value, child); err != nil {
			return out, fmt.Errorf("%s %w", "UELevelQoSParameters:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "ERABLevelQoSParameters")
		if err != nil {
			return out, err
		}
		*s18.BridgeERABLevelQoSParametersFieldPerPadding(&value) = padding
		*s18.BridgeERABLevelQoSParametersFieldReceived(&value) = true
		raw.RetainContents(s18.BridgeERABLevelQoSParametersFieldReceivedBytes(&value))
		*s18.BridgeERABLevelQoSParametersFieldReceivedLocation(&value) = raw.ContentLocation()
		out.rowUELevelQoSParameters = &value
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
	default:
		if err := raw.Observe(aper.UnknownIE); err != nil {
			return out, err
		}
		out.opaque = raw.Detached()
		out.isOpaque = true
	}
	return out, nil
}
func (v UEInformationTransferIEValue) encode() ([]byte, error) { return v.encodeFresh(false, nil) }
func (v UEInformationTransferIEValue) encodeFresh(fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
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
	case s00.ProtocolIEID(96):
		if v.rowSTMSI == nil {
			return nil, fmt.Errorf("%s missing value", "UEInformationTransferIEs.id-S-TMSI:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		candidate, err := s27.BridgeSTMSIMethodMarshalAPERBudget(v.rowSTMSI, budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	case s00.ProtocolIEID(252):
		if v.rowUELevelQoSParameters == nil {
			return nil, fmt.Errorf("%s missing value", "UEInformationTransferIEs.id-UE-Level-QoS-Parameters:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		candidate, err := s18.BridgeERABLevelQoSParametersMethodMarshalAPERBudget(v.rowUELevelQoSParameters, budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	case s00.ProtocolIEID(74):
		if v.rowUERadioCapability == nil {
			return nil, fmt.Errorf("%s missing value", "UEInformationTransferIEs.id-UERadioCapability:")
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
	case s00.ProtocolIEID(278):
		if v.rowSubscriptionBasedUEDifferentiationInfo == nil {
			return nil, fmt.Errorf("%s missing value", "UEInformationTransferIEs.id-Subscription-Based-UE-DifferentiationInfo:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		candidate, err := s30.BridgeSubscriptionBasedUEDifferentiationInfoMethodMarshalAPERBudget(v.rowSubscriptionBasedUEDifferentiationInfo, budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	case s00.ProtocolIEID(283):
		if v.rowPendingDataIndication == nil {
			return nil, fmt.Errorf("%s missing value", "UEInformationTransferIEs.id-PendingDataIndication:")
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
	case s00.ProtocolIEID(192):
		if v.rowMaskedIMEISV == nil {
			return nil, fmt.Errorf("%s missing value", "UEInformationTransferIEs.id-Masked-IMEISV:")
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
	default:
		return nil, fmt.Errorf("%s id %d has no value", "UEInformationTransferIEValue:", v.id)
	}
}

type ConnectionEstablishmentIndicationIETable struct{}

func ConnectionEstablishmentIndicationIEs() ConnectionEstablishmentIndicationIETable {
	return ConnectionEstablishmentIndicationIETable{}
}

// ID returns the ASN.1 object-set identity of ConnectionEstablishmentIndicationIETable.
func (ConnectionEstablishmentIndicationIETable) ID() s00.TableID {
	return func() s00.TableID {
		sealed := s00.TableID{}
		*s00.BridgeTableIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "ConnectionEstablishmentIndicationIEs"}
		return sealed
	}()
}

// Table returns the ASN.1 object-set table described by ConnectionEstablishmentIndicationIETable.
func (ConnectionEstablishmentIndicationIETable) Table() s00.ConnectionEstablishmentIndicationIEValueIETable {
	return func() s00.ConnectionEstablishmentIndicationIEValueIETable {
		sealed := s00.ConnectionEstablishmentIndicationIEValueIETable{}
		*s00.BridgeConnectionEstablishmentIndicationIEValueIETableFieldBound(&sealed) = true
		return sealed
	}()
}
func (ConnectionEstablishmentIndicationIETable) infoMMEUES1APID() s00.FieldInfo {
	return s00.FieldInfo{Table: ConnectionEstablishmentIndicationIEs().ID(), ID: s00.ProtocolIEID(0), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceMandatory, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "MME-UE-S1AP-ID"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "ConnectionEstablishmentIndicationIEs", Row: "id-MME-UE-S1AP-ID"}}}
}

// MMEUES1APID returns the typed binding for the MMEUES1APID row of ConnectionEstablishmentIndicationIETable.
func (t ConnectionEstablishmentIndicationIETable) MMEUES1APID() ConnectionEstablishmentIndicationMMEUES1APIDIEBinding {
	return ConnectionEstablishmentIndicationMMEUES1APIDIEBinding{info: t.infoMMEUES1APID(), codec: func() s01.MMEUES1APIDValueCodec {
		sealed := s01.MMEUES1APIDValueCodec{}
		*s01.BridgeMMEUES1APIDValueCodecFieldPath(&sealed) = "MMEUES1APID"
		*s01.BridgeMMEUES1APIDValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.MMEUES1APID, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s00.MMEUES1APID
				return empty, err
			}
			var zero s30.ConnectionEstablishmentIndicationIEValue
			decoded, err := s30.BridgeConnectionEstablishmentIndicationIEValueMethodDecode(zero, s00.ProtocolIEID(0), raw)
			if err != nil {
				var empty s00.MMEUES1APID
				return empty, err
			}
			value, ok := decoded.AsMMEUES1APID()
			if !ok {
				var empty s00.MMEUES1APID
				return empty, fmt.Errorf("binding ConnectionEstablishmentIndicationIEs.id-MME-UE-S1AP-ID: no selected value")
			}
			return *value, nil
		}
		*s01.BridgeMMEUES1APIDValueCodecFieldEncode(&sealed) = func(value s00.MMEUES1APID, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return s30.BridgeConnectionEstablishmentIndicationIEValueMethodEncodeFresh((func() s30.ConnectionEstablishmentIndicationIEValue {
				sealed := s30.ConnectionEstablishmentIndicationIEValue{}
				*s30.BridgeConnectionEstablishmentIndicationIEValueFieldId(&sealed) = s00.ProtocolIEID(0)
				*s30.BridgeConnectionEstablishmentIndicationIEValueFieldRowMMEUES1APID(&sealed) = &value
				return sealed
			}()), fresh, budget)
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
		inject: func(value s00.MMEUES1APID) s30.ConnectionEstablishmentIndicationIEValue {
			return func() s30.ConnectionEstablishmentIndicationIEValue {
				sealed := s30.ConnectionEstablishmentIndicationIEValue{}
				*s30.BridgeConnectionEstablishmentIndicationIEValueFieldId(&sealed) = s00.ProtocolIEID(0)
				*s30.BridgeConnectionEstablishmentIndicationIEValueFieldRowMMEUES1APID(&sealed) = &value
				return sealed
			}()
		}, get: func(value *s30.ConnectionEstablishmentIndicationIEValue) (*s00.MMEUES1APID, bool) {
			return value.AsMMEUES1APID()
		}}
}
func (ConnectionEstablishmentIndicationIETable) infoENBUES1APID() s00.FieldInfo {
	return s00.FieldInfo{Table: ConnectionEstablishmentIndicationIEs().ID(), ID: s00.ProtocolIEID(8), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceMandatory, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "ENB-UE-S1AP-ID"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "ConnectionEstablishmentIndicationIEs", Row: "id-eNB-UE-S1AP-ID"}}}
}

// ENBUES1APID returns the typed binding for the ENBUES1APID row of ConnectionEstablishmentIndicationIETable.
func (t ConnectionEstablishmentIndicationIETable) ENBUES1APID() s30.ConnectionEstablishmentIndicationENBUES1APIDIEBinding {
	return func() s30.ConnectionEstablishmentIndicationENBUES1APIDIEBinding {
		sealed := s30.ConnectionEstablishmentIndicationENBUES1APIDIEBinding{}
		*s30.BridgeConnectionEstablishmentIndicationENBUES1APIDIEBindingFieldInfo(&sealed) = t.infoENBUES1APID()
		*s30.BridgeConnectionEstablishmentIndicationENBUES1APIDIEBindingFieldCodec(&sealed) = func() s00.ENBUES1APIDValueCodec {
			sealed := s00.ENBUES1APIDValueCodec{}
			*s00.BridgeENBUES1APIDValueCodecFieldPath(&sealed) = "ENBUES1APID"
			*s00.BridgeENBUES1APIDValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.ENBUES1APID, error) {
				raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
				if err != nil {
					var empty s00.ENBUES1APID
					return empty, err
				}
				var zero s30.ConnectionEstablishmentIndicationIEValue
				decoded, err := s30.BridgeConnectionEstablishmentIndicationIEValueMethodDecode(zero, s00.ProtocolIEID(8), raw)
				if err != nil {
					var empty s00.ENBUES1APID
					return empty, err
				}
				value, ok := decoded.AsENBUES1APID()
				if !ok {
					var empty s00.ENBUES1APID
					return empty, fmt.Errorf("binding ConnectionEstablishmentIndicationIEs.id-eNB-UE-S1AP-ID: no selected value")
				}
				return *value, nil
			}
			*s00.BridgeENBUES1APIDValueCodecFieldEncode(&sealed) = func(value s00.ENBUES1APID, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
				return s30.BridgeConnectionEstablishmentIndicationIEValueMethodEncodeFresh((func() s30.ConnectionEstablishmentIndicationIEValue {
					sealed := s30.ConnectionEstablishmentIndicationIEValue{}
					*s30.BridgeConnectionEstablishmentIndicationIEValueFieldId(&sealed) = s00.ProtocolIEID(8)
					*s30.BridgeConnectionEstablishmentIndicationIEValueFieldRowENBUES1APID(&sealed) = &value
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
		*s30.BridgeConnectionEstablishmentIndicationENBUES1APIDIEBindingFieldInject(&sealed) = func(value s00.ENBUES1APID) s30.ConnectionEstablishmentIndicationIEValue {
			return func() s30.ConnectionEstablishmentIndicationIEValue {
				sealed := s30.ConnectionEstablishmentIndicationIEValue{}
				*s30.BridgeConnectionEstablishmentIndicationIEValueFieldId(&sealed) = s00.ProtocolIEID(8)
				*s30.BridgeConnectionEstablishmentIndicationIEValueFieldRowENBUES1APID(&sealed) = &value
				return sealed
			}()
		}
		*s30.BridgeConnectionEstablishmentIndicationENBUES1APIDIEBindingFieldGet(&sealed) = func(value *s30.ConnectionEstablishmentIndicationIEValue) (*s00.ENBUES1APID, bool) {
			return value.AsENBUES1APID()
		}
		return sealed
	}()
}
func (ConnectionEstablishmentIndicationIETable) infoUERadioCapability() s00.FieldInfo {
	return s00.FieldInfo{Table: ConnectionEstablishmentIndicationIEs().ID(), ID: s00.ProtocolIEID(74), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "UERadioCapability"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "ConnectionEstablishmentIndicationIEs", Row: "id-UERadioCapability"}}}
}

// UERadioCapability returns the typed binding for the UERadioCapability row of ConnectionEstablishmentIndicationIETable.
func (t ConnectionEstablishmentIndicationIETable) UERadioCapability() ConnectionEstablishmentIndicationUERadioCapabilityIEBinding {
	return ConnectionEstablishmentIndicationUERadioCapabilityIEBinding{info: t.infoUERadioCapability(), codec: func() s02.UERadioCapabilityValueCodec {
		sealed := s02.UERadioCapabilityValueCodec{}
		*s02.BridgeUERadioCapabilityValueCodecFieldPath(&sealed) = "UERadioCapability"
		*s02.BridgeUERadioCapabilityValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.UERadioCapability, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s00.UERadioCapability
				return empty, err
			}
			var zero s30.ConnectionEstablishmentIndicationIEValue
			decoded, err := s30.BridgeConnectionEstablishmentIndicationIEValueMethodDecode(zero, s00.ProtocolIEID(74), raw)
			if err != nil {
				var empty s00.UERadioCapability
				return empty, err
			}
			value, ok := decoded.AsUERadioCapability()
			if !ok {
				var empty s00.UERadioCapability
				return empty, fmt.Errorf("binding ConnectionEstablishmentIndicationIEs.id-UERadioCapability: no selected value")
			}
			return *value, nil
		}
		*s02.BridgeUERadioCapabilityValueCodecFieldEncode(&sealed) = func(value s00.UERadioCapability, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return s30.BridgeConnectionEstablishmentIndicationIEValueMethodEncodeFresh((func() s30.ConnectionEstablishmentIndicationIEValue {
				sealed := s30.ConnectionEstablishmentIndicationIEValue{}
				*s30.BridgeConnectionEstablishmentIndicationIEValueFieldId(&sealed) = s00.ProtocolIEID(74)
				*s30.BridgeConnectionEstablishmentIndicationIEValueFieldRowUERadioCapability(&sealed) = &value
				return sealed
			}()), fresh, budget)
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
		inject: func(value s00.UERadioCapability) s30.ConnectionEstablishmentIndicationIEValue {
			return func() s30.ConnectionEstablishmentIndicationIEValue {
				sealed := s30.ConnectionEstablishmentIndicationIEValue{}
				*s30.BridgeConnectionEstablishmentIndicationIEValueFieldId(&sealed) = s00.ProtocolIEID(74)
				*s30.BridgeConnectionEstablishmentIndicationIEValueFieldRowUERadioCapability(&sealed) = &value
				return sealed
			}()
		}, get: func(value *s30.ConnectionEstablishmentIndicationIEValue) (*s00.UERadioCapability, bool) {
			return value.AsUERadioCapability()
		}}
}
func (ConnectionEstablishmentIndicationIETable) infoEnhancedCoverageRestricted() s00.FieldInfo {
	return s00.FieldInfo{Table: ConnectionEstablishmentIndicationIEs().ID(), ID: s00.ProtocolIEID(251), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "EnhancedCoverageRestricted"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "ConnectionEstablishmentIndicationIEs", Row: "id-EnhancedCoverageRestricted"}}}
}

// EnhancedCoverageRestricted returns the typed binding for the EnhancedCoverageRestricted row of ConnectionEstablishmentIndicationIETable.
func (t ConnectionEstablishmentIndicationIETable) EnhancedCoverageRestricted() s30.ConnectionEstablishmentIndicationEnhancedCoverageRestrictedIEBinding {
	return func() s30.ConnectionEstablishmentIndicationEnhancedCoverageRestrictedIEBinding {
		sealed := s30.ConnectionEstablishmentIndicationEnhancedCoverageRestrictedIEBinding{}
		*s30.BridgeConnectionEstablishmentIndicationEnhancedCoverageRestrictedIEBindingFieldInfo(&sealed) = t.infoEnhancedCoverageRestricted()
		*s30.BridgeConnectionEstablishmentIndicationEnhancedCoverageRestrictedIEBindingFieldCodec(&sealed) = func() s00.EnhancedCoverageRestrictedValueCodec {
			sealed := s00.EnhancedCoverageRestrictedValueCodec{}
			*s00.BridgeEnhancedCoverageRestrictedValueCodecFieldPath(&sealed) = "EnhancedCoverageRestricted"
			*s00.BridgeEnhancedCoverageRestrictedValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.EnhancedCoverageRestricted, error) {
				raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
				if err != nil {
					var empty s00.EnhancedCoverageRestricted
					return empty, err
				}
				var zero s30.ConnectionEstablishmentIndicationIEValue
				decoded, err := s30.BridgeConnectionEstablishmentIndicationIEValueMethodDecode(zero, s00.ProtocolIEID(251), raw)
				if err != nil {
					var empty s00.EnhancedCoverageRestricted
					return empty, err
				}
				value, ok := decoded.AsEnhancedCoverageRestricted()
				if !ok {
					var empty s00.EnhancedCoverageRestricted
					return empty, fmt.Errorf("binding ConnectionEstablishmentIndicationIEs.id-EnhancedCoverageRestricted: no selected value")
				}
				return *value, nil
			}
			*s00.BridgeEnhancedCoverageRestrictedValueCodecFieldEncode(&sealed) = func(value s00.EnhancedCoverageRestricted, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
				return s30.BridgeConnectionEstablishmentIndicationIEValueMethodEncodeFresh((func() s30.ConnectionEstablishmentIndicationIEValue {
					sealed := s30.ConnectionEstablishmentIndicationIEValue{}
					*s30.BridgeConnectionEstablishmentIndicationIEValueFieldId(&sealed) = s00.ProtocolIEID(251)
					*s30.BridgeConnectionEstablishmentIndicationIEValueFieldRowEnhancedCoverageRestricted(&sealed) = &value
					return sealed
				}()), fresh, budget)
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
		}()
		*s30.BridgeConnectionEstablishmentIndicationEnhancedCoverageRestrictedIEBindingFieldInject(&sealed) = func(value s00.EnhancedCoverageRestricted) s30.ConnectionEstablishmentIndicationIEValue {
			return func() s30.ConnectionEstablishmentIndicationIEValue {
				sealed := s30.ConnectionEstablishmentIndicationIEValue{}
				*s30.BridgeConnectionEstablishmentIndicationIEValueFieldId(&sealed) = s00.ProtocolIEID(251)
				*s30.BridgeConnectionEstablishmentIndicationIEValueFieldRowEnhancedCoverageRestricted(&sealed) = &value
				return sealed
			}()
		}
		*s30.BridgeConnectionEstablishmentIndicationEnhancedCoverageRestrictedIEBindingFieldGet(&sealed) = func(value *s30.ConnectionEstablishmentIndicationIEValue) (*s00.EnhancedCoverageRestricted, bool) {
			return value.AsEnhancedCoverageRestricted()
		}
		return sealed
	}()
}
func (ConnectionEstablishmentIndicationIETable) infoDLCPSecurityInformation() s00.FieldInfo {
	return s00.FieldInfo{Table: ConnectionEstablishmentIndicationIEs().ID(), ID: s00.ProtocolIEID(253), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "DL-CP-SecurityInformation"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "ConnectionEstablishmentIndicationIEs", Row: "id-DL-CP-SecurityInformation"}}}
}

// DLCPSecurityInformation returns the typed binding for the DLCPSecurityInformation row of ConnectionEstablishmentIndicationIETable.
func (t ConnectionEstablishmentIndicationIETable) DLCPSecurityInformation() s30.ConnectionEstablishmentIndicationDLCPSecurityInformationIEBinding {
	return func() s30.ConnectionEstablishmentIndicationDLCPSecurityInformationIEBinding {
		sealed := s30.ConnectionEstablishmentIndicationDLCPSecurityInformationIEBinding{}
		*s30.BridgeConnectionEstablishmentIndicationDLCPSecurityInformationIEBindingFieldInfo(&sealed) = t.infoDLCPSecurityInformation()
		*s30.BridgeConnectionEstablishmentIndicationDLCPSecurityInformationIEBindingFieldCodec(&sealed) = func() s15.DLCPSecurityInformationValueCodec {
			sealed := s15.DLCPSecurityInformationValueCodec{}
			*s15.BridgeDLCPSecurityInformationValueCodecFieldPath(&sealed) = "DLCPSecurityInformation"
			*s15.BridgeDLCPSecurityInformationValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s15.DLCPSecurityInformation, error) {
				raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
				if err != nil {
					var empty s15.DLCPSecurityInformation
					return empty, err
				}
				var zero s30.ConnectionEstablishmentIndicationIEValue
				decoded, err := s30.BridgeConnectionEstablishmentIndicationIEValueMethodDecode(zero, s00.ProtocolIEID(253), raw)
				if err != nil {
					var empty s15.DLCPSecurityInformation
					return empty, err
				}
				value, ok := decoded.AsDLCPSecurityInformation()
				if !ok {
					var empty s15.DLCPSecurityInformation
					return empty, fmt.Errorf("binding ConnectionEstablishmentIndicationIEs.id-DL-CP-SecurityInformation: no selected value")
				}
				return *value, nil
			}
			*s15.BridgeDLCPSecurityInformationValueCodecFieldEncode(&sealed) = func(value s15.DLCPSecurityInformation, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
				return s30.BridgeConnectionEstablishmentIndicationIEValueMethodEncodeFresh((func() s30.ConnectionEstablishmentIndicationIEValue {
					sealed := s30.ConnectionEstablishmentIndicationIEValue{}
					*s30.BridgeConnectionEstablishmentIndicationIEValueFieldId(&sealed) = s00.ProtocolIEID(253)
					*s30.BridgeConnectionEstablishmentIndicationIEValueFieldRowDLCPSecurityInformation(&sealed) = &value
					return sealed
				}()), fresh, budget)
			}
			*s15.BridgeDLCPSecurityInformationValueCodecFieldCapture(&sealed) = func(v s15.DLCPSecurityInformation, options aper.DecodeState) (s15.DLCPSecurityInformation, aper.Snapshot) {
				s := aper.SemanticCaptureFor(options)
				f := s.Begin()
				s15.BridgeCaptureS1APDLCPSecurityInformation(&v, &s)
				var root aper.Snapshot
				s.End(f, &root,

					false,
				)
				return v, root
			}
			*s15.BridgeDLCPSecurityInformationValueCodecFieldCompare(&sealed) = func(v s15.DLCPSecurityInformation, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

			) {
				s := aper.NewSemanticComparison(root, budget)
				f := s.Begin()
				s15.BridgeCompareS1APDLCPSecurityInformation(&v, &s)
				s.End(f, root,
					false,
				)
				return s.Plan(), s.BudgetValue()
			}
			*s15.BridgeDLCPSecurityInformationValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
				sealed := s00.BridgeCodecContext{}
				*s00.BridgecodecContextFieldSource(&sealed) = "source-value:DLCPSecurityInformation"
				*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
				return sealed
			}()
			return sealed
		}()
		*s30.BridgeConnectionEstablishmentIndicationDLCPSecurityInformationIEBindingFieldInject(&sealed) = func(value s15.DLCPSecurityInformation) s30.ConnectionEstablishmentIndicationIEValue {
			return func() s30.ConnectionEstablishmentIndicationIEValue {
				sealed := s30.ConnectionEstablishmentIndicationIEValue{}
				*s30.BridgeConnectionEstablishmentIndicationIEValueFieldId(&sealed) = s00.ProtocolIEID(253)
				*s30.BridgeConnectionEstablishmentIndicationIEValueFieldRowDLCPSecurityInformation(&sealed) = &value
				return sealed
			}()
		}
		*s30.BridgeConnectionEstablishmentIndicationDLCPSecurityInformationIEBindingFieldGet(&sealed) = func(value *s30.ConnectionEstablishmentIndicationIEValue) (*s15.DLCPSecurityInformation, bool) {
			return value.AsDLCPSecurityInformation()
		}
		return sealed
	}()
}
func (ConnectionEstablishmentIndicationIETable) infoCEModeBRestricted() s00.FieldInfo {
	return s00.FieldInfo{Table: ConnectionEstablishmentIndicationIEs().ID(), ID: s00.ProtocolIEID(271), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "CE-ModeBRestricted"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "ConnectionEstablishmentIndicationIEs", Row: "id-CE-ModeBRestricted"}}}
}

// CEModeBRestricted returns the typed binding for the CEModeBRestricted row of ConnectionEstablishmentIndicationIETable.
func (t ConnectionEstablishmentIndicationIETable) CEModeBRestricted() s30.ConnectionEstablishmentIndicationCEModeBRestrictedIEBinding {
	return func() s30.ConnectionEstablishmentIndicationCEModeBRestrictedIEBinding {
		sealed := s30.ConnectionEstablishmentIndicationCEModeBRestrictedIEBinding{}
		*s30.BridgeConnectionEstablishmentIndicationCEModeBRestrictedIEBindingFieldInfo(&sealed) = t.infoCEModeBRestricted()
		*s30.BridgeConnectionEstablishmentIndicationCEModeBRestrictedIEBindingFieldCodec(&sealed) = func() s00.CEModeBRestrictedValueCodec {
			sealed := s00.CEModeBRestrictedValueCodec{}
			*s00.BridgeCEModeBRestrictedValueCodecFieldPath(&sealed) = "CEModeBRestricted"
			*s00.BridgeCEModeBRestrictedValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.CEModeBRestricted, error) {
				raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
				if err != nil {
					var empty s00.CEModeBRestricted
					return empty, err
				}
				var zero s30.ConnectionEstablishmentIndicationIEValue
				decoded, err := s30.BridgeConnectionEstablishmentIndicationIEValueMethodDecode(zero, s00.ProtocolIEID(271), raw)
				if err != nil {
					var empty s00.CEModeBRestricted
					return empty, err
				}
				value, ok := decoded.AsCEModeBRestricted()
				if !ok {
					var empty s00.CEModeBRestricted
					return empty, fmt.Errorf("binding ConnectionEstablishmentIndicationIEs.id-CE-ModeBRestricted: no selected value")
				}
				return *value, nil
			}
			*s00.BridgeCEModeBRestrictedValueCodecFieldEncode(&sealed) = func(value s00.CEModeBRestricted, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
				return s30.BridgeConnectionEstablishmentIndicationIEValueMethodEncodeFresh((func() s30.ConnectionEstablishmentIndicationIEValue {
					sealed := s30.ConnectionEstablishmentIndicationIEValue{}
					*s30.BridgeConnectionEstablishmentIndicationIEValueFieldId(&sealed) = s00.ProtocolIEID(271)
					*s30.BridgeConnectionEstablishmentIndicationIEValueFieldRowCEModeBRestricted(&sealed) = &value
					return sealed
				}()), fresh, budget)
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
		}()
		*s30.BridgeConnectionEstablishmentIndicationCEModeBRestrictedIEBindingFieldInject(&sealed) = func(value s00.CEModeBRestricted) s30.ConnectionEstablishmentIndicationIEValue {
			return func() s30.ConnectionEstablishmentIndicationIEValue {
				sealed := s30.ConnectionEstablishmentIndicationIEValue{}
				*s30.BridgeConnectionEstablishmentIndicationIEValueFieldId(&sealed) = s00.ProtocolIEID(271)
				*s30.BridgeConnectionEstablishmentIndicationIEValueFieldRowCEModeBRestricted(&sealed) = &value
				return sealed
			}()
		}
		*s30.BridgeConnectionEstablishmentIndicationCEModeBRestrictedIEBindingFieldGet(&sealed) = func(value *s30.ConnectionEstablishmentIndicationIEValue) (*s00.CEModeBRestricted, bool) {
			return value.AsCEModeBRestricted()
		}
		return sealed
	}()
}
func (ConnectionEstablishmentIndicationIETable) infoEndIndication() s00.FieldInfo {
	return s00.FieldInfo{Table: ConnectionEstablishmentIndicationIEs().ID(), ID: s00.ProtocolIEID(280), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "EndIndication"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "ConnectionEstablishmentIndicationIEs", Row: "id-EndIndication"}}}
}

// EndIndication returns the typed binding for the EndIndication row of ConnectionEstablishmentIndicationIETable.
func (t ConnectionEstablishmentIndicationIETable) EndIndication() s30.ConnectionEstablishmentIndicationEndIndicationIEBinding {
	return func() s30.ConnectionEstablishmentIndicationEndIndicationIEBinding {
		sealed := s30.ConnectionEstablishmentIndicationEndIndicationIEBinding{}
		*s30.BridgeConnectionEstablishmentIndicationEndIndicationIEBindingFieldInfo(&sealed) = t.infoEndIndication()
		*s30.BridgeConnectionEstablishmentIndicationEndIndicationIEBindingFieldCodec(&sealed) = func() s00.EndIndicationValueCodec {
			sealed := s00.EndIndicationValueCodec{}
			*s00.BridgeEndIndicationValueCodecFieldPath(&sealed) = "EndIndication"
			*s00.BridgeEndIndicationValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.EndIndication, error) {
				raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
				if err != nil {
					var empty s00.EndIndication
					return empty, err
				}
				var zero s30.ConnectionEstablishmentIndicationIEValue
				decoded, err := s30.BridgeConnectionEstablishmentIndicationIEValueMethodDecode(zero, s00.ProtocolIEID(280), raw)
				if err != nil {
					var empty s00.EndIndication
					return empty, err
				}
				value, ok := decoded.AsEndIndication()
				if !ok {
					var empty s00.EndIndication
					return empty, fmt.Errorf("binding ConnectionEstablishmentIndicationIEs.id-EndIndication: no selected value")
				}
				return *value, nil
			}
			*s00.BridgeEndIndicationValueCodecFieldEncode(&sealed) = func(value s00.EndIndication, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
				return s30.BridgeConnectionEstablishmentIndicationIEValueMethodEncodeFresh((func() s30.ConnectionEstablishmentIndicationIEValue {
					sealed := s30.ConnectionEstablishmentIndicationIEValue{}
					*s30.BridgeConnectionEstablishmentIndicationIEValueFieldId(&sealed) = s00.ProtocolIEID(280)
					*s30.BridgeConnectionEstablishmentIndicationIEValueFieldRowEndIndication(&sealed) = &value
					return sealed
				}()), fresh, budget)
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
		}()
		*s30.BridgeConnectionEstablishmentIndicationEndIndicationIEBindingFieldInject(&sealed) = func(value s00.EndIndication) s30.ConnectionEstablishmentIndicationIEValue {
			return func() s30.ConnectionEstablishmentIndicationIEValue {
				sealed := s30.ConnectionEstablishmentIndicationIEValue{}
				*s30.BridgeConnectionEstablishmentIndicationIEValueFieldId(&sealed) = s00.ProtocolIEID(280)
				*s30.BridgeConnectionEstablishmentIndicationIEValueFieldRowEndIndication(&sealed) = &value
				return sealed
			}()
		}
		*s30.BridgeConnectionEstablishmentIndicationEndIndicationIEBindingFieldGet(&sealed) = func(value *s30.ConnectionEstablishmentIndicationIEValue) (*s00.EndIndication, bool) {
			return value.AsEndIndication()
		}
		return sealed
	}()
}
func (ConnectionEstablishmentIndicationIETable) infoSubscriptionBasedUEDifferentiationInfo() s00.FieldInfo {
	return s00.FieldInfo{Table: ConnectionEstablishmentIndicationIEs().ID(), ID: s00.ProtocolIEID(278), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "Subscription-Based-UE-DifferentiationInfo"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "ConnectionEstablishmentIndicationIEs", Row: "id-Subscription-Based-UE-DifferentiationInfo"}}}
}

// SubscriptionBasedUEDifferentiationInfo returns the typed binding for the SubscriptionBasedUEDifferentiationInfo row of ConnectionEstablishmentIndicationIETable.
func (t ConnectionEstablishmentIndicationIETable) SubscriptionBasedUEDifferentiationInfo() ConnectionEstablishmentIndicationSubscriptionBasedUEDifferentiationInfoIEBinding {
	return ConnectionEstablishmentIndicationSubscriptionBasedUEDifferentiationInfoIEBinding{info: t.infoSubscriptionBasedUEDifferentiationInfo(), codec: SubscriptionBasedUEDifferentiationInfoValueCodec{path: "SubscriptionBasedUEDifferentiationInfo",
		decode: func(data []byte, options aper.DecodeState) (s30.SubscriptionBasedUEDifferentiationInfo, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s30.SubscriptionBasedUEDifferentiationInfo
				return empty, err
			}
			var zero s30.ConnectionEstablishmentIndicationIEValue
			decoded, err := s30.BridgeConnectionEstablishmentIndicationIEValueMethodDecode(zero, s00.ProtocolIEID(278), raw)
			if err != nil {
				var empty s30.SubscriptionBasedUEDifferentiationInfo
				return empty, err
			}
			value, ok := decoded.AsSubscriptionBasedUEDifferentiationInfo()
			if !ok {
				var empty s30.SubscriptionBasedUEDifferentiationInfo
				return empty, fmt.Errorf("binding ConnectionEstablishmentIndicationIEs.id-Subscription-Based-UE-DifferentiationInfo: no selected value")
			}
			return *value, nil
		},
		encode: func(value s30.SubscriptionBasedUEDifferentiationInfo, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return s30.BridgeConnectionEstablishmentIndicationIEValueMethodEncodeFresh((func() s30.ConnectionEstablishmentIndicationIEValue {
				sealed := s30.ConnectionEstablishmentIndicationIEValue{}
				*s30.BridgeConnectionEstablishmentIndicationIEValueFieldId(&sealed) = s00.ProtocolIEID(278)
				*s30.BridgeConnectionEstablishmentIndicationIEValueFieldRowSubscriptionBasedUEDifferentiationInfo(&sealed) = &value
				return sealed
			}()), fresh, budget)
		}, capture: func(v s30.SubscriptionBasedUEDifferentiationInfo, options aper.DecodeState) (s30.SubscriptionBasedUEDifferentiationInfo, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s30.BridgeCaptureS1APSubscriptionBasedUEDifferentiationInfo(
				&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}, compare: func(v s30.SubscriptionBasedUEDifferentiationInfo, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s30.BridgeCompareS1APSubscriptionBasedUEDifferentiationInfo(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.
				BudgetValue()
		}, context: func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:SubscriptionBasedUEDifferentiationInfo"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}(),
	}, inject: func(value s30.SubscriptionBasedUEDifferentiationInfo) s30.ConnectionEstablishmentIndicationIEValue {
		return func() s30.ConnectionEstablishmentIndicationIEValue {
			sealed := s30.ConnectionEstablishmentIndicationIEValue{}
			*s30.BridgeConnectionEstablishmentIndicationIEValueFieldId(&sealed) = s00.ProtocolIEID(278)
			*s30.BridgeConnectionEstablishmentIndicationIEValueFieldRowSubscriptionBasedUEDifferentiationInfo(&sealed) = &value
			return sealed
		}()
	}, get: func(value *s30.ConnectionEstablishmentIndicationIEValue) (*s30.SubscriptionBasedUEDifferentiationInfo, bool) {
		return value.AsSubscriptionBasedUEDifferentiationInfo()
	}}
}
func (ConnectionEstablishmentIndicationIETable) infoUELevelQoSParameters() s00.FieldInfo {
	return s00.FieldInfo{Table: ConnectionEstablishmentIndicationIEs().ID(), ID: s00.ProtocolIEID(252), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "E-RABLevelQoSParameters"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "ConnectionEstablishmentIndicationIEs", Row: "id-UE-Level-QoS-Parameters"}}}
}

// UELevelQoSParameters returns the typed binding for the UELevelQoSParameters row of ConnectionEstablishmentIndicationIETable.
func (t ConnectionEstablishmentIndicationIETable) UELevelQoSParameters() s30.ConnectionEstablishmentIndicationERABLevelQoSParametersIEBinding {
	return func() s30.ConnectionEstablishmentIndicationERABLevelQoSParametersIEBinding {
		sealed := s30.ConnectionEstablishmentIndicationERABLevelQoSParametersIEBinding{}
		*s30.BridgeConnectionEstablishmentIndicationERABLevelQoSParametersIEBindingFieldInfo(&sealed) = t.infoUELevelQoSParameters()
		*s30.BridgeConnectionEstablishmentIndicationERABLevelQoSParametersIEBindingFieldCodec(&sealed) = func() s18.ERABLevelQoSParametersValueCodec {
			sealed := s18.ERABLevelQoSParametersValueCodec{}
			*s18.BridgeERABLevelQoSParametersValueCodecFieldPath(&sealed) = "ERABLevelQoSParameters"
			*s18.BridgeERABLevelQoSParametersValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s18.ERABLevelQoSParameters, error) {
				raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
				if err != nil {
					var empty s18.ERABLevelQoSParameters
					return empty, err
				}
				var zero s30.ConnectionEstablishmentIndicationIEValue
				decoded, err := s30.BridgeConnectionEstablishmentIndicationIEValueMethodDecode(zero, s00.ProtocolIEID(252), raw)
				if err != nil {
					var empty s18.ERABLevelQoSParameters
					return empty, err
				}
				value, ok := decoded.AsUELevelQoSParameters()
				if !ok {
					var empty s18.ERABLevelQoSParameters
					return empty, fmt.Errorf("binding ConnectionEstablishmentIndicationIEs.id-UE-Level-QoS-Parameters: no selected value")
				}
				return *value, nil
			}
			*s18.BridgeERABLevelQoSParametersValueCodecFieldEncode(&sealed) = func(value s18.ERABLevelQoSParameters, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
				return s30.BridgeConnectionEstablishmentIndicationIEValueMethodEncodeFresh((func() s30.ConnectionEstablishmentIndicationIEValue {
					sealed := s30.ConnectionEstablishmentIndicationIEValue{}
					*s30.BridgeConnectionEstablishmentIndicationIEValueFieldId(&sealed) = s00.ProtocolIEID(252)
					*s30.BridgeConnectionEstablishmentIndicationIEValueFieldRowUELevelQoSParameters(&sealed) = &value
					return sealed
				}()), fresh, budget)
			}
			*s18.BridgeERABLevelQoSParametersValueCodecFieldCapture(&sealed) = func(v s18.ERABLevelQoSParameters, options aper.DecodeState) (s18.ERABLevelQoSParameters, aper.Snapshot,

			) {
				s := aper.SemanticCaptureFor(options)
				f := s.Begin()
				s18.BridgeCaptureS1APERABLevelQoSParameters(&v, &s)
				var root aper.Snapshot
				s.End(f, &root, false)
				return v, root
			}
			*s18.BridgeERABLevelQoSParametersValueCodecFieldCompare(&sealed) = func(v s18.ERABLevelQoSParameters, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

			) {
				s := aper.NewSemanticComparison(root, budget)
				f := s.Begin()
				s18.BridgeCompareS1APERABLevelQoSParameters(&v, &s)
				s.End(f, root, false)
				return s.Plan(), s.BudgetValue()
			}
			*s18.BridgeERABLevelQoSParametersValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
				sealed := s00.BridgeCodecContext{}
				*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ERABLevelQoSParameters"
				*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
				return sealed
			}()
			return sealed
		}()
		*s30.BridgeConnectionEstablishmentIndicationERABLevelQoSParametersIEBindingFieldInject(&sealed) = func(value s18.ERABLevelQoSParameters) s30.ConnectionEstablishmentIndicationIEValue {
			return func() s30.ConnectionEstablishmentIndicationIEValue {
				sealed := s30.ConnectionEstablishmentIndicationIEValue{}
				*s30.BridgeConnectionEstablishmentIndicationIEValueFieldId(&sealed) = s00.ProtocolIEID(252)
				*s30.BridgeConnectionEstablishmentIndicationIEValueFieldRowUELevelQoSParameters(&sealed) = &value
				return sealed
			}()
		}
		*s30.BridgeConnectionEstablishmentIndicationERABLevelQoSParametersIEBindingFieldGet(&sealed) = func(value *s30.ConnectionEstablishmentIndicationIEValue) (*s18.ERABLevelQoSParameters, bool) {
			return value.AsUELevelQoSParameters()
		}
		return sealed
	}()
}
func (ConnectionEstablishmentIndicationIETable) infoUERadioCapabilityID() s00.FieldInfo {
	return s00.FieldInfo{Table: ConnectionEstablishmentIndicationIEs().ID(), ID: s00.ProtocolIEID(314), Criticality: s00.CriticalityReject, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "UERadioCapabilityID"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "ConnectionEstablishmentIndicationIEs", Row: "id-UERadioCapabilityID"}}}
}

// UERadioCapabilityID returns the typed binding for the UERadioCapabilityID row of ConnectionEstablishmentIndicationIETable.
func (t ConnectionEstablishmentIndicationIETable) UERadioCapabilityID() ConnectionEstablishmentIndicationUERadioCapabilityIDIEBinding {
	return ConnectionEstablishmentIndicationUERadioCapabilityIDIEBinding{info: t.infoUERadioCapabilityID(), codec: func() s02.UERadioCapabilityIDValueCodec {
		sealed := s02.UERadioCapabilityIDValueCodec{}
		*s02.BridgeUERadioCapabilityIDValueCodecFieldPath(&sealed) = "UERadioCapabilityID"
		*s02.BridgeUERadioCapabilityIDValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.UERadioCapabilityID, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s00.UERadioCapabilityID
				return empty, err
			}
			var zero s30.ConnectionEstablishmentIndicationIEValue
			decoded, err := s30.BridgeConnectionEstablishmentIndicationIEValueMethodDecode(zero, s00.ProtocolIEID(314), raw)
			if err != nil {
				var empty s00.UERadioCapabilityID
				return empty, err
			}
			value, ok := decoded.AsUERadioCapabilityID()
			if !ok {
				var empty s00.UERadioCapabilityID
				return empty, fmt.Errorf("binding ConnectionEstablishmentIndicationIEs.id-UERadioCapabilityID: no selected value")
			}
			return *value, nil
		}
		*s02.BridgeUERadioCapabilityIDValueCodecFieldEncode(&sealed) = func(value s00.UERadioCapabilityID, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return s30.BridgeConnectionEstablishmentIndicationIEValueMethodEncodeFresh((func() s30.ConnectionEstablishmentIndicationIEValue {
				sealed := s30.ConnectionEstablishmentIndicationIEValue{}
				*s30.BridgeConnectionEstablishmentIndicationIEValueFieldId(&sealed) = s00.ProtocolIEID(314)
				*s30.BridgeConnectionEstablishmentIndicationIEValueFieldRowUERadioCapabilityID(&sealed) = &value
				return sealed
			}()), fresh, budget)
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
		inject: func(value s00.UERadioCapabilityID) s30.ConnectionEstablishmentIndicationIEValue {
			return func() s30.ConnectionEstablishmentIndicationIEValue {
				sealed := s30.ConnectionEstablishmentIndicationIEValue{}
				*s30.BridgeConnectionEstablishmentIndicationIEValueFieldId(&sealed) = s00.ProtocolIEID(314)
				*s30.BridgeConnectionEstablishmentIndicationIEValueFieldRowUERadioCapabilityID(&sealed) = &value
				return sealed
			}()
		}, get: func(value *s30.ConnectionEstablishmentIndicationIEValue) (*s00.UERadioCapabilityID, bool) {
			return value.AsUERadioCapabilityID()
		}}
}
func (ConnectionEstablishmentIndicationIETable) infoMaskedIMEISV() s00.FieldInfo {
	return s00.FieldInfo{Table: ConnectionEstablishmentIndicationIEs().ID(), ID: s00.ProtocolIEID(192), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "Masked-IMEISV"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "ConnectionEstablishmentIndicationIEs", Row: "id-Masked-IMEISV"}}}
}

// MaskedIMEISV returns the typed binding for the MaskedIMEISV row of ConnectionEstablishmentIndicationIETable.
func (t ConnectionEstablishmentIndicationIETable) MaskedIMEISV() ConnectionEstablishmentIndicationMaskedIMEISVIEBinding {
	return ConnectionEstablishmentIndicationMaskedIMEISVIEBinding{info: t.infoMaskedIMEISV(), codec: func() s01.MaskedIMEISVValueCodec {
		sealed := s01.MaskedIMEISVValueCodec{}
		*s01.BridgeMaskedIMEISVValueCodecFieldPath(&sealed) = "MaskedIMEISV"
		*s01.BridgeMaskedIMEISVValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.MaskedIMEISV, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s00.MaskedIMEISV
				return empty, err
			}
			var zero s30.ConnectionEstablishmentIndicationIEValue
			decoded, err := s30.BridgeConnectionEstablishmentIndicationIEValueMethodDecode(zero, s00.ProtocolIEID(192), raw)
			if err != nil {
				var empty s00.MaskedIMEISV
				return empty, err
			}
			value, ok := decoded.AsMaskedIMEISV()
			if !ok {
				var empty s00.MaskedIMEISV
				return empty, fmt.Errorf("binding ConnectionEstablishmentIndicationIEs.id-Masked-IMEISV: no selected value")
			}
			return *value, nil
		}
		*s01.BridgeMaskedIMEISVValueCodecFieldEncode(&sealed) = func(value s00.MaskedIMEISV, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return s30.BridgeConnectionEstablishmentIndicationIEValueMethodEncodeFresh((func() s30.ConnectionEstablishmentIndicationIEValue {
				sealed := s30.ConnectionEstablishmentIndicationIEValue{}
				*s30.BridgeConnectionEstablishmentIndicationIEValueFieldId(&sealed) = s00.ProtocolIEID(192)
				*s30.BridgeConnectionEstablishmentIndicationIEValueFieldRowMaskedIMEISV(&sealed) = &value
				return sealed
			}()), fresh, budget)
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
		inject: func(value s00.MaskedIMEISV) s30.ConnectionEstablishmentIndicationIEValue {
			return func() s30.ConnectionEstablishmentIndicationIEValue {
				sealed := s30.ConnectionEstablishmentIndicationIEValue{}
				*s30.BridgeConnectionEstablishmentIndicationIEValueFieldId(&sealed) = s00.ProtocolIEID(192)
				*s30.BridgeConnectionEstablishmentIndicationIEValueFieldRowMaskedIMEISV(&sealed) = &value
				return sealed
			}()
		}, get: func(value *s30.ConnectionEstablishmentIndicationIEValue) (*s00.MaskedIMEISV, bool) {
			return value.AsMaskedIMEISV()
		}}
}
func (ConnectionEstablishmentIndicationIETable) infoCoarseUELocation() s00.FieldInfo {
	return s00.FieldInfo{Table: ConnectionEstablishmentIndicationIEs().ID(), ID: s00.ProtocolIEID(354), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "CoarseUELocation"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "ConnectionEstablishmentIndicationIEs", Row: "id-CoarseUELocation"}}}
}

// CoarseUELocation returns the typed binding for the CoarseUELocation row of ConnectionEstablishmentIndicationIETable.
func (t ConnectionEstablishmentIndicationIETable) CoarseUELocation() s30.ConnectionEstablishmentIndicationCoarseUELocationIEBinding {
	return func() s30.ConnectionEstablishmentIndicationCoarseUELocationIEBinding {
		sealed := s30.ConnectionEstablishmentIndicationCoarseUELocationIEBinding{}
		*s30.BridgeConnectionEstablishmentIndicationCoarseUELocationIEBindingFieldInfo(&sealed) = t.infoCoarseUELocation()
		*s30.BridgeConnectionEstablishmentIndicationCoarseUELocationIEBindingFieldCodec(&sealed) = func() s00.CoarseUELocationValueCodec {
			sealed := s00.CoarseUELocationValueCodec{}
			*s00.BridgeCoarseUELocationValueCodecFieldPath(&sealed) = "CoarseUELocation"
			*s00.BridgeCoarseUELocationValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.CoarseUELocation, error) {
				raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
				if err != nil {
					var empty s00.CoarseUELocation
					return empty, err
				}
				var zero s30.ConnectionEstablishmentIndicationIEValue
				decoded, err := s30.BridgeConnectionEstablishmentIndicationIEValueMethodDecode(zero, s00.ProtocolIEID(354), raw)
				if err != nil {
					var empty s00.CoarseUELocation
					return empty, err
				}
				value, ok := decoded.AsCoarseUELocation()
				if !ok {
					var empty s00.CoarseUELocation
					return empty, fmt.Errorf("binding ConnectionEstablishmentIndicationIEs.id-CoarseUELocation: no selected value")
				}
				return *value, nil
			}
			*s00.BridgeCoarseUELocationValueCodecFieldEncode(&sealed) = func(value s00.CoarseUELocation, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
				return s30.BridgeConnectionEstablishmentIndicationIEValueMethodEncodeFresh((func() s30.ConnectionEstablishmentIndicationIEValue {
					sealed := s30.ConnectionEstablishmentIndicationIEValue{}
					*s30.BridgeConnectionEstablishmentIndicationIEValueFieldId(&sealed) = s00.ProtocolIEID(354)
					*s30.BridgeConnectionEstablishmentIndicationIEValueFieldRowCoarseUELocation(&sealed) = &value
					return sealed
				}()), fresh, budget)
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
		}()
		*s30.BridgeConnectionEstablishmentIndicationCoarseUELocationIEBindingFieldInject(&sealed) = func(value s00.CoarseUELocation) s30.ConnectionEstablishmentIndicationIEValue {
			return func() s30.ConnectionEstablishmentIndicationIEValue {
				sealed := s30.ConnectionEstablishmentIndicationIEValue{}
				*s30.BridgeConnectionEstablishmentIndicationIEValueFieldId(&sealed) = s00.ProtocolIEID(354)
				*s30.BridgeConnectionEstablishmentIndicationIEValueFieldRowCoarseUELocation(&sealed) = &value
				return sealed
			}()
		}
		*s30.BridgeConnectionEstablishmentIndicationCoarseUELocationIEBindingFieldGet(&sealed) = func(value *s30.ConnectionEstablishmentIndicationIEValue) (*s00.CoarseUELocation, bool) {
			return value.AsCoarseUELocation()
		}
		return sealed
	}()
}

// NewOpaque constructs an owned opaque field for an identifier without a typed row in ConnectionEstablishmentIndicationIETable.
func (t ConnectionEstablishmentIndicationIETable) NewOpaque(id s00.ProtocolIEID, criticality s00.Criticality, data []byte) (s30.ConnectionEstablishmentIndicationIEField, error) {
	if id < 0 || id > 65535 || criticality < 0 || criticality > 2 {
		return s30.ConnectionEstablishmentIndicationIEField{}, aper.OperationError(fmt.Errorf("invalid opaque IE selector or criticality"), "Opaque")
	}
	switch id {
	case s00.ProtocolIEID(0):
		return s30.ConnectionEstablishmentIndicationIEField{}, aper.OperationError(fmt.Errorf("known IE id-MME-UE-S1AP-ID requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(8):
		return s30.ConnectionEstablishmentIndicationIEField{}, aper.OperationError(fmt.Errorf("known IE id-eNB-UE-S1AP-ID requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(74):
		return s30.ConnectionEstablishmentIndicationIEField{}, aper.OperationError(fmt.Errorf("known IE id-UERadioCapability requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(251):
		return s30.ConnectionEstablishmentIndicationIEField{}, aper.OperationError(fmt.Errorf("known IE id-EnhancedCoverageRestricted requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(253):
		return s30.ConnectionEstablishmentIndicationIEField{}, aper.OperationError(fmt.Errorf("known IE id-DL-CP-SecurityInformation requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(271):
		return s30.ConnectionEstablishmentIndicationIEField{}, aper.OperationError(fmt.Errorf("known IE id-CE-ModeBRestricted requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(280):
		return s30.ConnectionEstablishmentIndicationIEField{}, aper.OperationError(fmt.Errorf("known IE id-EndIndication requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(278):
		return s30.ConnectionEstablishmentIndicationIEField{}, aper.OperationError(fmt.Errorf("known IE id-Subscription-Based-UE-DifferentiationInfo requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(252):
		return s30.ConnectionEstablishmentIndicationIEField{}, aper.OperationError(fmt.Errorf("known IE id-UE-Level-QoS-Parameters requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(314):
		return s30.ConnectionEstablishmentIndicationIEField{}, aper.OperationError(fmt.Errorf("known IE id-UERadioCapabilityID requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(192):
		return s30.ConnectionEstablishmentIndicationIEField{}, aper.OperationError(fmt.Errorf("known IE id-Masked-IMEISV requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(354):
		return s30.ConnectionEstablishmentIndicationIEField{}, aper.OperationError(fmt.Errorf("known IE id-CoarseUELocation requires its typed binding"), "Opaque")
	default:
		budget, err := aper.BuildBudget()
		if err != nil {
			return s30.ConnectionEstablishmentIndicationIEField{}, aper.OperationError(err, "Opaque")
		}
		opaque, err := aper.BuildOpaqueOpenType(data, budget)
		if err != nil {
			return s30.ConnectionEstablishmentIndicationIEField{}, aper.OperationError(err, "Opaque")
		}
		return s30.ConnectionEstablishmentIndicationIEField{Id: id, Criticality: criticality, Value: func() s30.ConnectionEstablishmentIndicationIEValue {
			sealed := s30.ConnectionEstablishmentIndicationIEValue{}
			*s30.BridgeConnectionEstablishmentIndicationIEValueFieldId(&sealed) = id
			*s30.BridgeConnectionEstablishmentIndicationIEValueFieldOpaque(&sealed) = opaque
			*s30.BridgeConnectionEstablishmentIndicationIEValueFieldIsOpaque(&sealed) = true
			return sealed
		}()}, aper.OperationError(nil, "Opaque")
	}
}

type UEInformationTransferIETable struct{}

func UEInformationTransferIEs() UEInformationTransferIETable { return UEInformationTransferIETable{} }

// ID returns the ASN.1 object-set identity of UEInformationTransferIETable.
func (UEInformationTransferIETable) ID() s00.TableID {
	return func() s00.TableID {
		sealed := s00.TableID{}
		*s00.BridgeTableIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "UEInformationTransferIEs"}
		return sealed
	}()
}

// Table returns the ASN.1 object-set table described by UEInformationTransferIETable.
func (UEInformationTransferIETable) Table() s00.UEInformationTransferIEValueIETable {
	return func() s00.UEInformationTransferIEValueIETable {
		sealed := s00.UEInformationTransferIEValueIETable{}
		*s00.BridgeUEInformationTransferIEValueIETableFieldBound(&sealed) = true
		return sealed
	}()
}
func (UEInformationTransferIETable) infoSTMSI() s00.FieldInfo {
	return s00.FieldInfo{Table: UEInformationTransferIEs().ID(), ID: s00.ProtocolIEID(96), Criticality: s00.CriticalityReject, Presence: s00.PresenceMandatory, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "S-TMSI"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "UEInformationTransferIEs", Row: "id-S-TMSI"}}}
}

// STMSI returns the typed binding for the STMSI row of UEInformationTransferIETable.
func (t UEInformationTransferIETable) STMSI() UEInformationTransferSTMSIIEBinding {
	return UEInformationTransferSTMSIIEBinding{info: t.infoSTMSI(), codec: func() s28.STMSIValueCodec {
		sealed := s28.STMSIValueCodec{}
		*s28.BridgeSTMSIValueCodecFieldPath(&sealed) = "STMSI"
		*s28.BridgeSTMSIValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s27.STMSI, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s27.STMSI
				return empty, err
			}
			var zero UEInformationTransferIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(96), raw)
			if err != nil {
				var empty s27.STMSI
				return empty, err
			}
			value, ok := decoded.AsSTMSI()
			if !ok {
				var empty s27.STMSI
				return empty, fmt.Errorf("binding UEInformationTransferIEs.id-S-TMSI: no selected value")
			}
			return *value, nil
		}
		*s28.BridgeSTMSIValueCodecFieldEncode(&sealed) = func(value s27.STMSI, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (UEInformationTransferIEValue{id: s00.ProtocolIEID(96), rowSTMSI: &value}).encodeFresh(fresh, budget)
		}
		*s28.BridgeSTMSIValueCodecFieldCapture(&sealed) = func(v s27.STMSI, options aper.DecodeState) (s27.STMSI, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s27.BridgeCaptureS1APSTMSI(&v, &s)
			var root aper.Snapshot
			s.End(f,
				&root, false)
			return v, root
		}
		*s28.BridgeSTMSIValueCodecFieldCompare(&sealed) = func(v s27.STMSI, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s27.BridgeCompareS1APSTMSI(&v, &s)
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
		inject: func(value s27.STMSI) UEInformationTransferIEValue {
			return UEInformationTransferIEValue{id: s00.ProtocolIEID(96), rowSTMSI: &value}
		}, get: func(value *UEInformationTransferIEValue) (*s27.STMSI, bool) { return value.AsSTMSI() }}
}
func (UEInformationTransferIETable) infoUELevelQoSParameters() s00.FieldInfo {
	return s00.FieldInfo{Table: UEInformationTransferIEs().ID(), ID: s00.ProtocolIEID(252), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "E-RABLevelQoSParameters"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "UEInformationTransferIEs", Row: "id-UE-Level-QoS-Parameters"}}}
}

// UELevelQoSParameters returns the typed binding for the UELevelQoSParameters row of UEInformationTransferIETable.
func (t UEInformationTransferIETable) UELevelQoSParameters() UEInformationTransferERABLevelQoSParametersIEBinding {
	return UEInformationTransferERABLevelQoSParametersIEBinding{info: t.infoUELevelQoSParameters(), codec: func() s18.ERABLevelQoSParametersValueCodec {
		sealed := s18.ERABLevelQoSParametersValueCodec{}
		*s18.BridgeERABLevelQoSParametersValueCodecFieldPath(&sealed) = "ERABLevelQoSParameters"
		*s18.BridgeERABLevelQoSParametersValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s18.ERABLevelQoSParameters, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s18.ERABLevelQoSParameters
				return empty, err
			}
			var zero UEInformationTransferIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(252), raw)
			if err != nil {
				var empty s18.ERABLevelQoSParameters
				return empty, err
			}
			value, ok := decoded.AsUELevelQoSParameters()
			if !ok {
				var empty s18.ERABLevelQoSParameters
				return empty, fmt.Errorf("binding UEInformationTransferIEs.id-UE-Level-QoS-Parameters: no selected value")
			}
			return *value, nil
		}
		*s18.BridgeERABLevelQoSParametersValueCodecFieldEncode(&sealed) = func(value s18.ERABLevelQoSParameters, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (UEInformationTransferIEValue{id: s00.ProtocolIEID(252), rowUELevelQoSParameters: &value}).encodeFresh(fresh, budget)
		}
		*s18.BridgeERABLevelQoSParametersValueCodecFieldCapture(&sealed) = func(v s18.ERABLevelQoSParameters, options aper.DecodeState) (s18.ERABLevelQoSParameters, aper.Snapshot,

		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s18.BridgeCaptureS1APERABLevelQoSParameters(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s18.BridgeERABLevelQoSParametersValueCodecFieldCompare(&sealed) = func(v s18.ERABLevelQoSParameters, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s18.BridgeCompareS1APERABLevelQoSParameters(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s18.BridgeERABLevelQoSParametersValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ERABLevelQoSParameters"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s18.ERABLevelQoSParameters) UEInformationTransferIEValue {
			return UEInformationTransferIEValue{id: s00.ProtocolIEID(252), rowUELevelQoSParameters: &value}
		}, get: func(value *UEInformationTransferIEValue) (*s18.ERABLevelQoSParameters, bool) {
			return value.AsUELevelQoSParameters()
		}}
}
func (UEInformationTransferIETable) infoUERadioCapability() s00.FieldInfo {
	return s00.FieldInfo{Table: UEInformationTransferIEs().ID(), ID: s00.ProtocolIEID(74), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "UERadioCapability"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "UEInformationTransferIEs", Row: "id-UERadioCapability"}}}
}

// UERadioCapability returns the typed binding for the UERadioCapability row of UEInformationTransferIETable.
func (t UEInformationTransferIETable) UERadioCapability() UEInformationTransferUERadioCapabilityIEBinding {
	return UEInformationTransferUERadioCapabilityIEBinding{info: t.infoUERadioCapability(), codec: func() s02.UERadioCapabilityValueCodec {
		sealed := s02.UERadioCapabilityValueCodec{}
		*s02.BridgeUERadioCapabilityValueCodecFieldPath(&sealed) = "UERadioCapability"
		*s02.BridgeUERadioCapabilityValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.UERadioCapability, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s00.UERadioCapability
				return empty, err
			}
			var zero UEInformationTransferIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(74), raw)
			if err != nil {
				var empty s00.UERadioCapability
				return empty, err
			}
			value, ok := decoded.AsUERadioCapability()
			if !ok {
				var empty s00.UERadioCapability
				return empty, fmt.Errorf("binding UEInformationTransferIEs.id-UERadioCapability: no selected value")
			}
			return *value, nil
		}
		*s02.BridgeUERadioCapabilityValueCodecFieldEncode(&sealed) = func(value s00.UERadioCapability, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (UEInformationTransferIEValue{id: s00.ProtocolIEID(74), rowUERadioCapability: &value}).encodeFresh(fresh, budget)
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
		inject: func(value s00.UERadioCapability) UEInformationTransferIEValue {
			return UEInformationTransferIEValue{id: s00.ProtocolIEID(74), rowUERadioCapability: &value}
		}, get: func(value *UEInformationTransferIEValue) (*s00.UERadioCapability, bool) {
			return value.AsUERadioCapability()
		}}
}
func (UEInformationTransferIETable) infoSubscriptionBasedUEDifferentiationInfo() s00.FieldInfo {
	return s00.FieldInfo{Table: UEInformationTransferIEs().ID(), ID: s00.ProtocolIEID(278), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "Subscription-Based-UE-DifferentiationInfo"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "UEInformationTransferIEs", Row: "id-Subscription-Based-UE-DifferentiationInfo"}}}
}

// SubscriptionBasedUEDifferentiationInfo returns the typed binding for the SubscriptionBasedUEDifferentiationInfo row of UEInformationTransferIETable.
func (t UEInformationTransferIETable) SubscriptionBasedUEDifferentiationInfo() UEInformationTransferSubscriptionBasedUEDifferentiationInfoIEBinding {
	return UEInformationTransferSubscriptionBasedUEDifferentiationInfoIEBinding{info: t.infoSubscriptionBasedUEDifferentiationInfo(), codec: SubscriptionBasedUEDifferentiationInfoValueCodec{path: "SubscriptionBasedUEDifferentiationInfo",
		decode: func(data []byte, options aper.DecodeState) (s30.SubscriptionBasedUEDifferentiationInfo, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s30.SubscriptionBasedUEDifferentiationInfo
				return empty, err
			}
			var zero UEInformationTransferIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(278), raw)
			if err != nil {
				var empty s30.SubscriptionBasedUEDifferentiationInfo
				return empty, err
			}
			value, ok := decoded.AsSubscriptionBasedUEDifferentiationInfo()
			if !ok {
				var empty s30.SubscriptionBasedUEDifferentiationInfo
				return empty, fmt.Errorf("binding UEInformationTransferIEs.id-Subscription-Based-UE-DifferentiationInfo: no selected value")
			}
			return *value, nil
		},
		encode: func(value s30.SubscriptionBasedUEDifferentiationInfo, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (UEInformationTransferIEValue{id: s00.ProtocolIEID(278), rowSubscriptionBasedUEDifferentiationInfo: &value}).encodeFresh(fresh, budget)
		}, capture: func(v s30.SubscriptionBasedUEDifferentiationInfo, options aper.DecodeState) (s30.SubscriptionBasedUEDifferentiationInfo, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s30.BridgeCaptureS1APSubscriptionBasedUEDifferentiationInfo(
				&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}, compare: func(v s30.SubscriptionBasedUEDifferentiationInfo, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s30.BridgeCompareS1APSubscriptionBasedUEDifferentiationInfo(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.
				BudgetValue()
		}, context: func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:SubscriptionBasedUEDifferentiationInfo"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}(),
	}, inject: func(value s30.SubscriptionBasedUEDifferentiationInfo) UEInformationTransferIEValue {
		return UEInformationTransferIEValue{id: s00.ProtocolIEID(278), rowSubscriptionBasedUEDifferentiationInfo: &value}
	}, get: func(value *UEInformationTransferIEValue) (*s30.SubscriptionBasedUEDifferentiationInfo, bool) {
		return value.AsSubscriptionBasedUEDifferentiationInfo()
	}}
}
func (UEInformationTransferIETable) infoPendingDataIndication() s00.FieldInfo {
	return s00.FieldInfo{Table: UEInformationTransferIEs().ID(), ID: s00.ProtocolIEID(283), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "PendingDataIndication"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "UEInformationTransferIEs", Row: "id-PendingDataIndication"}}}
}

// PendingDataIndication returns the typed binding for the PendingDataIndication row of UEInformationTransferIETable.
func (t UEInformationTransferIETable) PendingDataIndication() UEInformationTransferPendingDataIndicationIEBinding {
	return UEInformationTransferPendingDataIndicationIEBinding{info: t.infoPendingDataIndication(), codec: func() s01.PendingDataIndicationValueCodec {
		sealed := s01.PendingDataIndicationValueCodec{}
		*s01.BridgePendingDataIndicationValueCodecFieldPath(&sealed) = "PendingDataIndication"
		*s01.BridgePendingDataIndicationValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.PendingDataIndication, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s00.PendingDataIndication
				return empty, err
			}
			var zero UEInformationTransferIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(283), raw)
			if err != nil {
				var empty s00.PendingDataIndication
				return empty, err
			}
			value, ok := decoded.AsPendingDataIndication()
			if !ok {
				var empty s00.PendingDataIndication
				return empty, fmt.Errorf("binding UEInformationTransferIEs.id-PendingDataIndication: no selected value")
			}
			return *value, nil
		}
		*s01.BridgePendingDataIndicationValueCodecFieldEncode(&sealed) = func(value s00.PendingDataIndication, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (UEInformationTransferIEValue{id: s00.ProtocolIEID(283), rowPendingDataIndication: &value}).encodeFresh(fresh, budget)
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
		inject: func(value s00.PendingDataIndication) UEInformationTransferIEValue {
			return UEInformationTransferIEValue{id: s00.ProtocolIEID(283), rowPendingDataIndication: &value}
		}, get: func(value *UEInformationTransferIEValue) (*s00.PendingDataIndication, bool) {
			return value.AsPendingDataIndication()
		}}
}
func (UEInformationTransferIETable) infoMaskedIMEISV() s00.FieldInfo {
	return s00.FieldInfo{Table: UEInformationTransferIEs().ID(), ID: s00.ProtocolIEID(192), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "Masked-IMEISV"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "UEInformationTransferIEs", Row: "id-Masked-IMEISV"}}}
}

// MaskedIMEISV returns the typed binding for the MaskedIMEISV row of UEInformationTransferIETable.
func (t UEInformationTransferIETable) MaskedIMEISV() UEInformationTransferMaskedIMEISVIEBinding {
	return UEInformationTransferMaskedIMEISVIEBinding{info: t.infoMaskedIMEISV(), codec: func() s01.MaskedIMEISVValueCodec {
		sealed := s01.MaskedIMEISVValueCodec{}
		*s01.BridgeMaskedIMEISVValueCodecFieldPath(&sealed) = "MaskedIMEISV"
		*s01.BridgeMaskedIMEISVValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.MaskedIMEISV, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s00.MaskedIMEISV
				return empty, err
			}
			var zero UEInformationTransferIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(192), raw)
			if err != nil {
				var empty s00.MaskedIMEISV
				return empty, err
			}
			value, ok := decoded.AsMaskedIMEISV()
			if !ok {
				var empty s00.MaskedIMEISV
				return empty, fmt.Errorf("binding UEInformationTransferIEs.id-Masked-IMEISV: no selected value")
			}
			return *value, nil
		}
		*s01.BridgeMaskedIMEISVValueCodecFieldEncode(&sealed) = func(value s00.MaskedIMEISV, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (UEInformationTransferIEValue{id: s00.ProtocolIEID(192), rowMaskedIMEISV: &value}).encodeFresh(fresh, budget)
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
		inject: func(value s00.MaskedIMEISV) UEInformationTransferIEValue {
			return UEInformationTransferIEValue{id: s00.ProtocolIEID(192), rowMaskedIMEISV: &value}
		}, get: func(value *UEInformationTransferIEValue) (*s00.MaskedIMEISV, bool) { return value.AsMaskedIMEISV() }}
}

// NewOpaque constructs an owned opaque field for an identifier without a typed row in UEInformationTransferIETable.
func (t UEInformationTransferIETable) NewOpaque(id s00.ProtocolIEID, criticality s00.Criticality, data []byte) (UEInformationTransferIEField, error) {
	if id < 0 || id > 65535 || criticality < 0 || criticality > 2 {
		return UEInformationTransferIEField{}, aper.OperationError(fmt.Errorf("invalid opaque IE selector or criticality"), "Opaque")
	}
	switch id {
	case s00.ProtocolIEID(96):
		return UEInformationTransferIEField{}, aper.OperationError(fmt.Errorf("known IE id-S-TMSI requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(252):
		return UEInformationTransferIEField{}, aper.OperationError(fmt.Errorf("known IE id-UE-Level-QoS-Parameters requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(74):
		return UEInformationTransferIEField{}, aper.OperationError(fmt.Errorf("known IE id-UERadioCapability requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(278):
		return UEInformationTransferIEField{}, aper.OperationError(fmt.Errorf("known IE id-Subscription-Based-UE-DifferentiationInfo requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(283):
		return UEInformationTransferIEField{}, aper.OperationError(fmt.Errorf("known IE id-PendingDataIndication requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(192):
		return UEInformationTransferIEField{}, aper.OperationError(fmt.Errorf("known IE id-Masked-IMEISV requires its typed binding"), "Opaque")
	default:
		budget, err := aper.BuildBudget()
		if err != nil {
			return UEInformationTransferIEField{}, aper.OperationError(err, "Opaque")
		}
		opaque, err := aper.BuildOpaqueOpenType(data, budget)
		if err != nil {
			return UEInformationTransferIEField{}, aper.OperationError(err, "Opaque")
		}
		return UEInformationTransferIEField{Id: id, Criticality: criticality, Value: UEInformationTransferIEValue{id: id, opaque: opaque, isOpaque: true}}, aper.OperationError(nil, "Opaque")
	}
}

// CEModeBRestrictedCodec binds the complete APER value type.
func CEModeBRestrictedCodec() s00.CEModeBRestrictedValueCodec {
	return ConnectionEstablishmentIndicationIEs().CEModeBRestricted().Codec()
}

// CoarseUELocationCodec binds the complete APER value type.
func CoarseUELocationCodec() s00.CoarseUELocationValueCodec {
	return ConnectionEstablishmentIndicationIEs().CoarseUELocation().Codec()
}

// ConnectedengNBItemCodec binds the complete source value type.
func ConnectedengNBItemCodec() ConnectedengNBItemValueCodec {
	return ConnectedengNBItemValueCodec{path: "ConnectedengNBItem", decode: func(data []byte, options aper.DecodeState) (ConnectedengNBItem, error) {
		var value ConnectedengNBItem
		if err := value.unmarshalAPERWithOptions(data, options); err != nil {
			return ConnectedengNBItem{}, err
		}
		value.received = true
		value.receivedAbsolute = true
		value.receivedBytes = aper.OriginalWire(data)
		return value, nil
	}, encode: func(value ConnectedengNBItem, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return (&value).marshalAPERBudget(budget, fresh)
	}, capture: func(v ConnectedengNBItem, options aper.DecodeState) (ConnectedengNBItem, aper.Snapshot) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeCaptureS1APConnectedengNBItem(&v, &s)
		var root aper.Snapshot
		s.End(f, &root, false)
		return v,

			root
	}, compare: func(v ConnectedengNBItem, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
	) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		BridgeCompareS1APConnectedengNBItem(&v, &s)
		s.End(f, root, false)
		return s.Plan(), s.BudgetValue()
	}, context: func() s00.BridgeCodecContext {
		sealed := s00.BridgeCodecContext{}
		*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ConnectedengNBItem"
		*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
		return sealed
	}(),
	}
}

// DLCPSecurityInformationCodec binds the complete APER value type.
func DLCPSecurityInformationCodec() s15.DLCPSecurityInformationValueCodec {
	return ConnectionEstablishmentIndicationIEs().DLCPSecurityInformation().Codec()
}

// ENDCSONTransferTypeCodec binds the complete source value type.
func ENDCSONTransferTypeCodec() ENDCSONTransferTypeValueCodec {
	return ENDCSONTransferTypeValueCodec{path: "ENDCSONTransferType", decode: func(data []byte, options aper.DecodeState) (ENDCSONTransferType, error) {
		var value ENDCSONTransferType
		if err := value.unmarshalAPERWithOptions(data, options); err != nil {
			return ENDCSONTransferType{}, err
		}
		value.received = true
		value.receivedAbsolute = true
		value.receivedBytes = aper.OriginalWire(data)
		return value, nil
	}, encode: func(value ENDCSONTransferType, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return (&value).marshalAPERBudget(budget, fresh)
	}, capture: func(v ENDCSONTransferType, options aper.DecodeState) (ENDCSONTransferType, aper.Snapshot,
	) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeCaptureS1APENDCSONTransferType(&v, &s)
		var root aper.Snapshot
		s.End(f, &root, false)
		return v, root
	}, compare: func(v ENDCSONTransferType, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
	) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		BridgeCompareS1APENDCSONTransferType(&v, &s)
		s.End(f, root, false)
		return s.Plan(), s.BudgetValue()
	}, context: func() s00.BridgeCodecContext {
		sealed := s00.BridgeCodecContext{}
		*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ENDCSONTransferType"
		*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
		return sealed
	}(),
	}
}

// ENDCSONeNBIdentificationCodec binds the complete source value type.
func ENDCSONeNBIdentificationCodec() ENDCSONeNBIdentificationValueCodec {
	return ENDCSONeNBIdentificationValueCodec{path: "ENDCSONeNBIdentification", decode: func(data []byte, options aper.DecodeState) (ENDCSONeNBIdentification, error) {
		var value ENDCSONeNBIdentification
		if err := value.unmarshalAPERWithOptions(data, options); err != nil {
			return ENDCSONeNBIdentification{}, err
		}
		value.received = true
		value.receivedAbsolute = true
		value.receivedBytes = aper.OriginalWire(data)
		return value, nil
	}, encode: func(value ENDCSONeNBIdentification, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return (&value).marshalAPERBudget(budget, fresh)
	}, capture: func(v ENDCSONeNBIdentification, options aper.DecodeState) (ENDCSONeNBIdentification, aper.Snapshot) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeCaptureS1APENDCSONeNBIdentification(&v, &s)
		var root aper.Snapshot
		s.End(f, &root,

			false)
		return v, root
	}, compare: func(v ENDCSONeNBIdentification, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

	) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		BridgeCompareS1APENDCSONeNBIdentification(&v, &s)
		s.End(f, root,

			false,
		)
		return s.Plan(), s.BudgetValue()
	}, context: func() s00.BridgeCodecContext {
		sealed := s00.BridgeCodecContext{}
		*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ENDCSONeNBIdentification"
		*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
		return sealed
	}(),
	}
}

// ENDCSONengNBIdentificationCodec binds the complete source value type.
func ENDCSONengNBIdentificationCodec() ENDCSONengNBIdentificationValueCodec {
	return ENDCSONengNBIdentificationValueCodec{path: "ENDCSONengNBIdentification", decode: func(data []byte, options aper.DecodeState) (ENDCSONengNBIdentification, error) {
		var value ENDCSONengNBIdentification
		if err := value.unmarshalAPERWithOptions(data, options); err != nil {
			return ENDCSONengNBIdentification{}, err
		}
		value.received = true
		value.receivedAbsolute = true
		value.receivedBytes = aper.OriginalWire(data)
		return value, nil
	}, encode: func(value ENDCSONengNBIdentification, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return (&value).marshalAPERBudget(budget, fresh)
	}, capture: func(v ENDCSONengNBIdentification, options aper.DecodeState) (ENDCSONengNBIdentification, aper.Snapshot,
	) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeCaptureS1APENDCSONengNBIdentification(&v, &s)
		var root aper.Snapshot
		s.End(
			f, &root, false)
		return v, root
	}, compare: func(v ENDCSONengNBIdentification, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
	) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		BridgeCompareS1APENDCSONengNBIdentification(&v, &s)
		s.End(f,
			root,

			false)
		return s.Plan(), s.BudgetValue()
	}, context: func() s00.BridgeCodecContext {
		sealed := s00.BridgeCodecContext{}
		*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ENDCSONengNBIdentification"
		*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
		return sealed
	}(),
	}
}

// ENDCTransferTypeReplyCodec binds the complete source value type.
func ENDCTransferTypeReplyCodec() ENDCTransferTypeReplyValueCodec {
	return ENDCTransferTypeReplyValueCodec{path: "ENDCTransferTypeReply", decode: func(data []byte, options aper.DecodeState) (ENDCTransferTypeReply, error) {
		var value ENDCTransferTypeReply
		if err := value.unmarshalAPERWithOptions(data, options); err != nil {
			return ENDCTransferTypeReply{}, err
		}
		value.received = true
		value.receivedAbsolute = true
		value.receivedBytes = aper.OriginalWire(data)
		return value, nil
	}, encode: func(value ENDCTransferTypeReply, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return (&value).marshalAPERBudget(budget, fresh)
	}, capture: func(v ENDCTransferTypeReply, options aper.DecodeState) (ENDCTransferTypeReply, aper.Snapshot,
	) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeCaptureS1APENDCTransferTypeReply(&v, &s)
		var root aper.Snapshot
		s.End(f, &root, false)

		return v, root
	}, compare: func(v ENDCTransferTypeReply, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

	) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		BridgeCompareS1APENDCTransferTypeReply(&v, &s)
		s.End(f, root, false)

		return s.Plan(), s.BudgetValue()
	}, context: func() s00.BridgeCodecContext {
		sealed := s00.BridgeCodecContext{}
		*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ENDCTransferTypeReply"
		*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
		return sealed
	}(),
	}
}

// ENDCTransferTypeRequestCodec binds the complete source value type.
func ENDCTransferTypeRequestCodec() ENDCTransferTypeRequestValueCodec {
	return ENDCTransferTypeRequestValueCodec{path: "ENDCTransferTypeRequest", decode: func(data []byte, options aper.DecodeState) (ENDCTransferTypeRequest, error) {
		var value ENDCTransferTypeRequest
		if err := value.unmarshalAPERWithOptions(data, options); err != nil {
			return ENDCTransferTypeRequest{}, err
		}
		value.received = true
		value.receivedAbsolute = true
		value.receivedBytes = aper.OriginalWire(data)
		return value, nil
	}, encode: func(value ENDCTransferTypeRequest, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return (&value).marshalAPERBudget(budget, fresh)
	}, capture: func(v ENDCTransferTypeRequest, options aper.DecodeState) (ENDCTransferTypeRequest, aper.Snapshot) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeCaptureS1APENDCTransferTypeRequest(&v, &s)
		var root aper.Snapshot
		s.End(f, &root,

			false,
		)
		return v, root
	}, compare: func(v ENDCTransferTypeRequest, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

	) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		BridgeCompareS1APENDCTransferTypeRequest(&v, &s)
		s.End(f, root,
			false,
		)
		return s.Plan(), s.BudgetValue()
	}, context: func() s00.BridgeCodecContext {
		sealed := s00.BridgeCodecContext{}
		*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ENDCTransferTypeRequest"
		*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
		return sealed
	}(),
	}
}

// ERABLevelQoSParametersCodec binds the complete APER value type.
func ERABLevelQoSParametersCodec() s18.ERABLevelQoSParametersValueCodec {
	return ConnectionEstablishmentIndicationIEs().UELevelQoSParameters().Codec()
}

// EndIndicationCodec binds the complete APER value type.
func EndIndicationCodec() s00.EndIndicationValueCodec {
	return ConnectionEstablishmentIndicationIEs().EndIndication().Codec()
}

// EnhancedCoverageRestrictedCodec binds the complete APER value type.
func EnhancedCoverageRestrictedCodec() s00.EnhancedCoverageRestrictedValueCodec {
	return ConnectionEstablishmentIndicationIEs().EnhancedCoverageRestricted().Codec()
}

// MMEPagingTargetCodec binds the complete source value type.
func MMEPagingTargetCodec() MMEPagingTargetValueCodec {
	return MMEPagingTargetValueCodec{path: "MMEPagingTarget", decode: func(data []byte, options aper.DecodeState) (MMEPagingTarget, error) {
		var value MMEPagingTarget
		if err := value.unmarshalAPERWithOptions(data, options); err != nil {
			return MMEPagingTarget{}, err
		}
		value.received = true
		value.receivedAbsolute = true
		value.receivedBytes = aper.OriginalWire(data)
		return value, nil
	}, encode: func(value MMEPagingTarget, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return (&value).marshalAPERBudget(budget, fresh)
	}, capture: func(v MMEPagingTarget, options aper.DecodeState) (MMEPagingTarget, aper.Snapshot) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeCaptureS1APMMEPagingTarget(&v, &s)
		var root aper.Snapshot
		s.End(f, &root, false)
		return v, root
	}, compare: func(v MMEPagingTarget, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		BridgeCompareS1APMMEPagingTarget(&v, &s)
		s.End(f, root, false)
		return s.
			Plan(), s.BudgetValue()
	}, context: func() s00.BridgeCodecContext {
		sealed := s00.BridgeCodecContext{}
		*s00.BridgecodecContextFieldSource(&sealed) = "source-value:MMEPagingTarget"
		*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
		return sealed
	}(),
	}
}

// MaskedIMEISVCodec binds the complete APER value type.
func MaskedIMEISVCodec() s01.MaskedIMEISVValueCodec {
	return ConnectionEstablishmentIndicationIEs().MaskedIMEISV().Codec()
}

// SubscriptionBasedUEDifferentiationInfoCodec binds the complete APER value type.
func SubscriptionBasedUEDifferentiationInfoCodec() SubscriptionBasedUEDifferentiationInfoValueCodec {
	return ConnectionEstablishmentIndicationIEs().SubscriptionBasedUEDifferentiationInfo().Codec()
}

// SupportedTAsItemCodec binds the complete source value type.
func SupportedTAsItemCodec() SupportedTAsItemValueCodec {
	return SupportedTAsItemValueCodec{path: "SupportedTAsItem", decode: func(data []byte, options aper.DecodeState) (SupportedTAsItem, error) {
		var value SupportedTAsItem
		if err := value.unmarshalAPERWithOptions(data, options); err != nil {
			return SupportedTAsItem{}, err
		}
		value.received = true
		value.receivedAbsolute = true
		value.receivedBytes = aper.OriginalWire(data)
		return value, nil
	}, encode: func(value SupportedTAsItem, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return (&value).marshalAPERBudget(budget, fresh)
	}, capture: func(v SupportedTAsItem, options aper.DecodeState) (SupportedTAsItem, aper.Snapshot) {
		s := aper.SemanticCaptureFor(
			options)
		f := s.Begin()
		BridgeCaptureS1APSupportedTAsItem(&v, &s)
		var root aper.Snapshot
		s.End(f, &root, false)
		return v, root
	}, compare: func(v SupportedTAsItem, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		BridgeCompareS1APSupportedTAsItem(&v, &s)
		s.End(f, root, false)
		return s.
			Plan(), s.BudgetValue()
	}, context: func() s00.BridgeCodecContext {
		sealed := s00.BridgeCodecContext{}
		*s00.BridgecodecContextFieldSource(&sealed) = "source-value:SupportedTAsItem"
		*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
		return sealed
	}(),
	}
}

// TABasedMDTCodec binds the complete source value type.
func TABasedMDTCodec() TABasedMDTValueCodec {
	return TABasedMDTValueCodec{path: "TABasedMDT", decode: func(data []byte, options aper.DecodeState) (TABasedMDT, error) {
		var value TABasedMDT
		if err := value.unmarshalAPERWithOptions(data, options); err != nil {
			return TABasedMDT{}, err
		}
		value.received = true
		value.receivedAbsolute = true
		value.receivedBytes = aper.OriginalWire(data)
		return value, nil
	}, encode: func(value TABasedMDT, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return (&value).marshalAPERBudget(budget, fresh)
	}, capture: func(v TABasedMDT, options aper.DecodeState) (TABasedMDT, aper.Snapshot) {
		s := aper.SemanticCaptureFor(options)
		f :=
			s.Begin()
		BridgeCaptureS1APTABasedMDT(&v, &s)
		var root aper.Snapshot
		s.End(f, &root, false)
		return v, root
	}, compare: func(v TABasedMDT, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

	) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		BridgeCompareS1APTABasedMDT(&v, &s)
		s.End(f, root, false)
		return s.Plan(), s.BudgetValue()
	}, context: func() s00.BridgeCodecContext {
		sealed := s00.BridgeCodecContext{}
		*s00.BridgecodecContextFieldSource(&sealed) = "source-value:TABasedMDT"
		*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
		return sealed
	}(),
	}
}

// TABasedQMCCodec binds the complete source value type.
func TABasedQMCCodec() TABasedQMCValueCodec {
	return TABasedQMCValueCodec{path: "TABasedQMC", decode: func(data []byte, options aper.DecodeState) (TABasedQMC, error) {
		var value TABasedQMC
		if err := value.unmarshalAPERWithOptions(data, options); err != nil {
			return TABasedQMC{}, err
		}
		value.received = true
		value.receivedAbsolute = true
		value.receivedBytes = aper.OriginalWire(data)
		return value, nil
	}, encode: func(value TABasedQMC, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return (&value).marshalAPERBudget(budget, fresh)
	}, capture: func(v TABasedQMC, options aper.DecodeState) (TABasedQMC, aper.Snapshot) {
		s := aper.SemanticCaptureFor(options)
		f :=
			s.Begin()
		BridgeCaptureS1APTABasedQMC(&v, &s)
		var root aper.Snapshot
		s.End(f, &root, false)
		return v, root
	}, compare: func(v TABasedQMC, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

	) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		BridgeCompareS1APTABasedQMC(&v, &s)
		s.End(f, root, false)
		return s.Plan(), s.BudgetValue()
	}, context: func() s00.BridgeCodecContext {
		sealed := s00.BridgeCodecContext{}
		*s00.BridgecodecContextFieldSource(&sealed) = "source-value:TABasedQMC"
		*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
		return sealed
	}(),
	}
}

// UERadioCapabilityCodec binds the complete APER value type.
func UERadioCapabilityCodec() s02.UERadioCapabilityValueCodec {
	return ConnectionEstablishmentIndicationIEs().UERadioCapability().Codec()
}

// UERadioCapabilityIDCodec binds the complete APER value type.
func UERadioCapabilityIDCodec() s02.UERadioCapabilityIDValueCodec {
	return ConnectionEstablishmentIndicationIEs().UERadioCapabilityID().Codec()
}
func BridgeConnectedengNBItemAPERValueFieldContext(v *ConnectedengNBItemAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeConnectedengNBItemAPERValueFieldReceived(v *ConnectedengNBItemAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeConnectedengNBItemAPERValueFieldReplay(v *ConnectedengNBItemAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeConnectedengNBItemAPERValueFieldWithoutReplay(v *ConnectedengNBItemAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeConnectedengNBItemFieldExtCount(v *ConnectedengNBItem) *int64   { return &v.extCount }
func BridgeConnectedengNBItemFieldExtData(v *ConnectedengNBItem) *[][]byte { return &v.extData }
func BridgeConnectedengNBItemFieldExtOrigin(v *ConnectedengNBItem) *[]aper.OpaqueOrigin {
	return &v.extOrigin
}
func BridgeConnectedengNBItemFieldExtPresent(v *ConnectedengNBItem) *[]bool       { return &v.extPresent }
func BridgeConnectedengNBItemFieldExtWire(v *ConnectedengNBItem) *[]aper.WireSpan { return &v.extWire }
func BridgeConnectedengNBItemFieldIEExtensionsIndef(v *ConnectedengNBItem) *bool {
	return &v.iEExtensionsIndef
}
func BridgeConnectedengNBItemFieldPerExtPadding(v *ConnectedengNBItem) *[]aper.CompletePadding {
	return &v.perExtPadding
}
func BridgeConnectedengNBItemFieldPerPadding(v *ConnectedengNBItem) *aper.FinalPadding {
	return &v.perPadding
}
func BridgeConnectedengNBItemFieldReceived(v *ConnectedengNBItem) *bool { return &v.received }
func BridgeConnectedengNBItemFieldReceivedAbsolute(v *ConnectedengNBItem) *bool {
	return &v.receivedAbsolute
}
func BridgeConnectedengNBItemFieldReceivedBytes(v *ConnectedengNBItem) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeConnectedengNBItemFieldReceivedLocation(v *ConnectedengNBItem) *aper.Location {
	return &v.receivedLocation
}
func BridgeConnectedengNBItemFieldReplay(v *ConnectedengNBItem) *aper.Snapshot { return &v.replay }
func BridgeConnectedengNBItemFieldStream(v *ConnectedengNBItem) *aper.WireSpan { return &v.stream }
func BridgeConnectedengNBItemFieldSupportedTAsIndef(v *ConnectedengNBItem) *bool {
	return &v.supportedTAsIndef
}
func BridgeConnectedengNBItemFieldWithoutReplay(v *ConnectedengNBItem) *bool { return &v.withoutReplay }
func BridgeConnectedengNBItemMethodMarshalAPERBudget(v *ConnectedengNBItem, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeConnectedengNBItemMethodMarshalAPERBudgetValue(v *ConnectedengNBItem, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudgetValue(a0, a1)
}
func BridgeConnectedengNBItemMethodMarshalAPERChanged(v *ConnectedengNBItem, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeConnectedengNBItemMethodMarshalAPERChangedValue(v *ConnectedengNBItem, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeConnectedengNBItemMethodMarshalAPERLegacy(v *ConnectedengNBItem) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeConnectedengNBItemMethodMarshalAPERNewValue(v *ConnectedengNBItem, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERNewValue(a0, a1)
}
func BridgeConnectedengNBItemMethodMarshalAPERPlanned(v *ConnectedengNBItem, a0 *aper.DecodeBudget, a1 bool, a2 *aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1, a2)
}
func BridgeConnectedengNBItemMethodMarshalAPERTo(v *ConnectedengNBItem, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeConnectedengNBItemMethodUnmarshalAPERFrom(v *ConnectedengNBItem, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeConnectedengNBItemMethodUnmarshalAPERLegacy(v *ConnectedengNBItem, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeConnectedengNBItemMethodUnmarshalAPERWithOptions(v *ConnectedengNBItem, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeConnectedengNBItemValueCodecFieldCapture(v *ConnectedengNBItemValueCodec) *func(ConnectedengNBItem, aper.DecodeState) (ConnectedengNBItem, aper.Snapshot) {
	return &v.capture
}
func BridgeConnectedengNBItemValueCodecFieldCompare(v *ConnectedengNBItemValueCodec) *func(ConnectedengNBItem, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeConnectedengNBItemValueCodecFieldContext(v *ConnectedengNBItemValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeConnectedengNBItemValueCodecFieldDecode(v *ConnectedengNBItemValueCodec) *func([]byte, aper.DecodeState) (ConnectedengNBItem, error) {
	return &v.decode
}
func BridgeConnectedengNBItemValueCodecFieldEncode(v *ConnectedengNBItemValueCodec) *func(ConnectedengNBItem, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeConnectedengNBItemValueCodecFieldPath(v *ConnectedengNBItemValueCodec) *aper.Path {
	return &v.path
}
func BridgeConnectedengNBItemValueCodecMethodEncodeBudgetValue(v ConnectedengNBItemValueCodec, a0 ConnectedengNBItem, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeConnectedengNBItemValueCodecMethodEncodeChanged(v ConnectedengNBItemValueCodec, a0 ConnectedengNBItem, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeConnectedengNBListAPERValueFieldContext(v *ConnectedengNBListAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeConnectedengNBListAPERValueFieldReceived(v *ConnectedengNBListAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeConnectedengNBListAPERValueFieldReplay(v *ConnectedengNBListAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeConnectedengNBListAPERValueFieldWithoutReplay(v *ConnectedengNBListAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeConnectedengNBListValueCodecFieldCapture(v *ConnectedengNBListValueCodec) *func(ConnectedengNBList, aper.DecodeState) (ConnectedengNBList, aper.Snapshot) {
	return &v.capture
}
func BridgeConnectedengNBListValueCodecFieldCompare(v *ConnectedengNBListValueCodec) *func(ConnectedengNBList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeConnectedengNBListValueCodecFieldContext(v *ConnectedengNBListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeConnectedengNBListValueCodecFieldDecode(v *ConnectedengNBListValueCodec) *func([]byte, aper.DecodeState) (ConnectedengNBList, error) {
	return &v.decode
}
func BridgeConnectedengNBListValueCodecFieldEncode(v *ConnectedengNBListValueCodec) *func(ConnectedengNBList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeConnectedengNBListValueCodecFieldPath(v *ConnectedengNBListValueCodec) *aper.Path {
	return &v.path
}
func BridgeConnectedengNBListValueCodecMethodEncodeBudgetValue(v ConnectedengNBListValueCodec, a0 ConnectedengNBList, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeConnectedengNBListValueCodecMethodEncodeChanged(v ConnectedengNBListValueCodec, a0 ConnectedengNBList, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeConnectionEstablishmentIndicationAPERValueFieldContext(v *ConnectionEstablishmentIndicationAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeConnectionEstablishmentIndicationAPERValueFieldReceived(v *ConnectionEstablishmentIndicationAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeConnectionEstablishmentIndicationAPERValueFieldReplay(v *ConnectionEstablishmentIndicationAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeConnectionEstablishmentIndicationAPERValueFieldWithoutReplay(v *ConnectionEstablishmentIndicationAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeConnectionEstablishmentIndicationFieldExtCount(v *ConnectionEstablishmentIndication) *int64 {
	return &v.extCount
}
func BridgeConnectionEstablishmentIndicationFieldExtData(v *ConnectionEstablishmentIndication) *[][]byte {
	return &v.extData
}
func BridgeConnectionEstablishmentIndicationFieldExtOrigin(v *ConnectionEstablishmentIndication) *[]aper.OpaqueOrigin {
	return &v.extOrigin
}
func BridgeConnectionEstablishmentIndicationFieldExtPresent(v *ConnectionEstablishmentIndication) *[]bool {
	return &v.extPresent
}
func BridgeConnectionEstablishmentIndicationFieldExtWire(v *ConnectionEstablishmentIndication) *[]aper.WireSpan {
	return &v.extWire
}
func BridgeConnectionEstablishmentIndicationFieldPerExtPadding(v *ConnectionEstablishmentIndication) *[]aper.CompletePadding {
	return &v.perExtPadding
}
func BridgeConnectionEstablishmentIndicationFieldPerPadding(v *ConnectionEstablishmentIndication) *aper.FinalPadding {
	return &v.perPadding
}
func BridgeConnectionEstablishmentIndicationFieldProtocolIEsIndef(v *ConnectionEstablishmentIndication) *bool {
	return &v.protocolIEsIndef
}
func BridgeConnectionEstablishmentIndicationFieldReceived(v *ConnectionEstablishmentIndication) *bool {
	return &v.received
}
func BridgeConnectionEstablishmentIndicationFieldReceivedAbsolute(v *ConnectionEstablishmentIndication) *bool {
	return &v.receivedAbsolute
}
func BridgeConnectionEstablishmentIndicationFieldReceivedBytes(v *ConnectionEstablishmentIndication) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeConnectionEstablishmentIndicationFieldReceivedLocation(v *ConnectionEstablishmentIndication) *aper.Location {
	return &v.receivedLocation
}
func BridgeConnectionEstablishmentIndicationFieldReplay(v *ConnectionEstablishmentIndication) *aper.Snapshot {
	return &v.replay
}
func BridgeConnectionEstablishmentIndicationFieldStream(v *ConnectionEstablishmentIndication) *aper.WireSpan {
	return &v.stream
}
func BridgeConnectionEstablishmentIndicationFieldWithoutReplay(v *ConnectionEstablishmentIndication) *bool {
	return &v.withoutReplay
}
func BridgeConnectionEstablishmentIndicationIETableMethodInfoCEModeBRestricted(v ConnectionEstablishmentIndicationIETable) s00.FieldInfo {
	return v.infoCEModeBRestricted()
}
func BridgeConnectionEstablishmentIndicationIETableMethodInfoCoarseUELocation(v ConnectionEstablishmentIndicationIETable) s00.FieldInfo {
	return v.infoCoarseUELocation()
}
func BridgeConnectionEstablishmentIndicationIETableMethodInfoDLCPSecurityInformation(v ConnectionEstablishmentIndicationIETable) s00.FieldInfo {
	return v.infoDLCPSecurityInformation()
}
func BridgeConnectionEstablishmentIndicationIETableMethodInfoENBUES1APID(v ConnectionEstablishmentIndicationIETable) s00.FieldInfo {
	return v.infoENBUES1APID()
}
func BridgeConnectionEstablishmentIndicationIETableMethodInfoEndIndication(v ConnectionEstablishmentIndicationIETable) s00.FieldInfo {
	return v.infoEndIndication()
}
func BridgeConnectionEstablishmentIndicationIETableMethodInfoEnhancedCoverageRestricted(v ConnectionEstablishmentIndicationIETable) s00.FieldInfo {
	return v.infoEnhancedCoverageRestricted()
}
func BridgeConnectionEstablishmentIndicationIETableMethodInfoMMEUES1APID(v ConnectionEstablishmentIndicationIETable) s00.FieldInfo {
	return v.infoMMEUES1APID()
}
func BridgeConnectionEstablishmentIndicationIETableMethodInfoMaskedIMEISV(v ConnectionEstablishmentIndicationIETable) s00.FieldInfo {
	return v.infoMaskedIMEISV()
}
func BridgeConnectionEstablishmentIndicationIETableMethodInfoSubscriptionBasedUEDifferentiationInfo(v ConnectionEstablishmentIndicationIETable) s00.FieldInfo {
	return v.infoSubscriptionBasedUEDifferentiationInfo()
}
func BridgeConnectionEstablishmentIndicationIETableMethodInfoUELevelQoSParameters(v ConnectionEstablishmentIndicationIETable) s00.FieldInfo {
	return v.infoUELevelQoSParameters()
}
func BridgeConnectionEstablishmentIndicationIETableMethodInfoUERadioCapability(v ConnectionEstablishmentIndicationIETable) s00.FieldInfo {
	return v.infoUERadioCapability()
}
func BridgeConnectionEstablishmentIndicationIETableMethodInfoUERadioCapabilityID(v ConnectionEstablishmentIndicationIETable) s00.FieldInfo {
	return v.infoUERadioCapabilityID()
}
func BridgeConnectionEstablishmentIndicationIEValueERABIEContainerListValueCodecFieldCapture(v *ConnectionEstablishmentIndicationIEValueERABIEContainerListValueCodec) *func(s30.ConnectionEstablishmentIndicationIEValueERABIEContainerList, aper.DecodeState) (s30.ConnectionEstablishmentIndicationIEValueERABIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgeConnectionEstablishmentIndicationIEValueERABIEContainerListValueCodecFieldCompare(v *ConnectionEstablishmentIndicationIEValueERABIEContainerListValueCodec) *func(s30.ConnectionEstablishmentIndicationIEValueERABIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeConnectionEstablishmentIndicationIEValueERABIEContainerListValueCodecFieldContext(v *ConnectionEstablishmentIndicationIEValueERABIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeConnectionEstablishmentIndicationIEValueERABIEContainerListValueCodecFieldDecode(v *ConnectionEstablishmentIndicationIEValueERABIEContainerListValueCodec) *func([]byte, aper.DecodeState) (s30.ConnectionEstablishmentIndicationIEValueERABIEContainerList, error) {
	return &v.decode
}
func BridgeConnectionEstablishmentIndicationIEValueERABIEContainerListValueCodecFieldEncode(v *ConnectionEstablishmentIndicationIEValueERABIEContainerListValueCodec) *func(s30.ConnectionEstablishmentIndicationIEValueERABIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeConnectionEstablishmentIndicationIEValueERABIEContainerListValueCodecFieldPath(v *ConnectionEstablishmentIndicationIEValueERABIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgeConnectionEstablishmentIndicationIEValueERABIEContainerListValueCodecMethodEncodeBudgetValue(v ConnectionEstablishmentIndicationIEValueERABIEContainerListValueCodec, a0 s30.ConnectionEstablishmentIndicationIEValueERABIEContainerList, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeConnectionEstablishmentIndicationIEValueERABIEContainerListValueCodecMethodEncodeChanged(v ConnectionEstablishmentIndicationIEValueERABIEContainerListValueCodec, a0 s30.ConnectionEstablishmentIndicationIEValueERABIEContainerList, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeConnectionEstablishmentIndicationIEValueProtocolErrorIEContainerListAPERValueFieldContext(v *ConnectionEstablishmentIndicationIEValueProtocolErrorIEContainerListAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeConnectionEstablishmentIndicationIEValueProtocolErrorIEContainerListAPERValueFieldReceived(v *ConnectionEstablishmentIndicationIEValueProtocolErrorIEContainerListAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeConnectionEstablishmentIndicationIEValueProtocolErrorIEContainerListAPERValueFieldReplay(v *ConnectionEstablishmentIndicationIEValueProtocolErrorIEContainerListAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeConnectionEstablishmentIndicationIEValueProtocolErrorIEContainerListAPERValueFieldWithoutReplay(v *ConnectionEstablishmentIndicationIEValueProtocolErrorIEContainerListAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeConnectionEstablishmentIndicationIEValueProtocolErrorIEContainerListValueCodecFieldCapture(v *ConnectionEstablishmentIndicationIEValueProtocolErrorIEContainerListValueCodec) *func(ConnectionEstablishmentIndicationIEValueProtocolErrorIEContainerList, aper.DecodeState) (ConnectionEstablishmentIndicationIEValueProtocolErrorIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgeConnectionEstablishmentIndicationIEValueProtocolErrorIEContainerListValueCodecFieldCompare(v *ConnectionEstablishmentIndicationIEValueProtocolErrorIEContainerListValueCodec) *func(ConnectionEstablishmentIndicationIEValueProtocolErrorIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeConnectionEstablishmentIndicationIEValueProtocolErrorIEContainerListValueCodecFieldContext(v *ConnectionEstablishmentIndicationIEValueProtocolErrorIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeConnectionEstablishmentIndicationIEValueProtocolErrorIEContainerListValueCodecFieldDecode(v *ConnectionEstablishmentIndicationIEValueProtocolErrorIEContainerListValueCodec) *func([]byte, aper.DecodeState) (ConnectionEstablishmentIndicationIEValueProtocolErrorIEContainerList, error) {
	return &v.decode
}
func BridgeConnectionEstablishmentIndicationIEValueProtocolErrorIEContainerListValueCodecFieldEncode(v *ConnectionEstablishmentIndicationIEValueProtocolErrorIEContainerListValueCodec) *func(ConnectionEstablishmentIndicationIEValueProtocolErrorIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeConnectionEstablishmentIndicationIEValueProtocolErrorIEContainerListValueCodecFieldPath(v *ConnectionEstablishmentIndicationIEValueProtocolErrorIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgeConnectionEstablishmentIndicationIEValueProtocolErrorIEContainerListValueCodecMethodEncodeBudgetValue(v ConnectionEstablishmentIndicationIEValueProtocolErrorIEContainerListValueCodec, a0 ConnectionEstablishmentIndicationIEValueProtocolErrorIEContainerList, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeConnectionEstablishmentIndicationIEValueProtocolErrorIEContainerListValueCodecMethodEncodeChanged(v ConnectionEstablishmentIndicationIEValueProtocolErrorIEContainerListValueCodec, a0 ConnectionEstablishmentIndicationIEValueProtocolErrorIEContainerList, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeConnectionEstablishmentIndicationIEValueProtocolIEContainerListAPERValueFieldContext(v *ConnectionEstablishmentIndicationIEValueProtocolIEContainerListAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeConnectionEstablishmentIndicationIEValueProtocolIEContainerListAPERValueFieldReceived(v *ConnectionEstablishmentIndicationIEValueProtocolIEContainerListAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeConnectionEstablishmentIndicationIEValueProtocolIEContainerListAPERValueFieldReplay(v *ConnectionEstablishmentIndicationIEValueProtocolIEContainerListAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeConnectionEstablishmentIndicationIEValueProtocolIEContainerListAPERValueFieldWithoutReplay(v *ConnectionEstablishmentIndicationIEValueProtocolIEContainerListAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeConnectionEstablishmentIndicationIEValueProtocolIEContainerListValueCodecFieldCapture(v *ConnectionEstablishmentIndicationIEValueProtocolIEContainerListValueCodec) *func(ConnectionEstablishmentIndicationIEValueProtocolIEContainerList, aper.DecodeState) (ConnectionEstablishmentIndicationIEValueProtocolIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgeConnectionEstablishmentIndicationIEValueProtocolIEContainerListValueCodecFieldCompare(v *ConnectionEstablishmentIndicationIEValueProtocolIEContainerListValueCodec) *func(ConnectionEstablishmentIndicationIEValueProtocolIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeConnectionEstablishmentIndicationIEValueProtocolIEContainerListValueCodecFieldContext(v *ConnectionEstablishmentIndicationIEValueProtocolIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeConnectionEstablishmentIndicationIEValueProtocolIEContainerListValueCodecFieldDecode(v *ConnectionEstablishmentIndicationIEValueProtocolIEContainerListValueCodec) *func([]byte, aper.DecodeState) (ConnectionEstablishmentIndicationIEValueProtocolIEContainerList, error) {
	return &v.decode
}
func BridgeConnectionEstablishmentIndicationIEValueProtocolIEContainerListValueCodecFieldEncode(v *ConnectionEstablishmentIndicationIEValueProtocolIEContainerListValueCodec) *func(ConnectionEstablishmentIndicationIEValueProtocolIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeConnectionEstablishmentIndicationIEValueProtocolIEContainerListValueCodecFieldPath(v *ConnectionEstablishmentIndicationIEValueProtocolIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgeConnectionEstablishmentIndicationIEValueProtocolIEContainerListValueCodecMethodEncodeBudgetValue(v ConnectionEstablishmentIndicationIEValueProtocolIEContainerListValueCodec, a0 ConnectionEstablishmentIndicationIEValueProtocolIEContainerList, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeConnectionEstablishmentIndicationIEValueProtocolIEContainerListValueCodecMethodEncodeChanged(v ConnectionEstablishmentIndicationIEValueProtocolIEContainerListValueCodec, a0 ConnectionEstablishmentIndicationIEValueProtocolIEContainerList, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeConnectionEstablishmentIndicationMMEUES1APIDIEBindingFieldCodec(v *ConnectionEstablishmentIndicationMMEUES1APIDIEBinding) *s01.MMEUES1APIDValueCodec {
	return &v.codec
}
func BridgeConnectionEstablishmentIndicationMMEUES1APIDIEBindingFieldGet(v *ConnectionEstablishmentIndicationMMEUES1APIDIEBinding) *func(*s30.ConnectionEstablishmentIndicationIEValue) (*s00.MMEUES1APID, bool) {
	return &v.get
}
func BridgeConnectionEstablishmentIndicationMMEUES1APIDIEBindingFieldInfo(v *ConnectionEstablishmentIndicationMMEUES1APIDIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeConnectionEstablishmentIndicationMMEUES1APIDIEBindingFieldInject(v *ConnectionEstablishmentIndicationMMEUES1APIDIEBinding) *func(s00.MMEUES1APID) s30.ConnectionEstablishmentIndicationIEValue {
	return &v.inject
}
func BridgeConnectionEstablishmentIndicationMaskedIMEISVIEBindingFieldCodec(v *ConnectionEstablishmentIndicationMaskedIMEISVIEBinding) *s01.MaskedIMEISVValueCodec {
	return &v.codec
}
func BridgeConnectionEstablishmentIndicationMaskedIMEISVIEBindingFieldGet(v *ConnectionEstablishmentIndicationMaskedIMEISVIEBinding) *func(*s30.ConnectionEstablishmentIndicationIEValue) (*s00.MaskedIMEISV, bool) {
	return &v.get
}
func BridgeConnectionEstablishmentIndicationMaskedIMEISVIEBindingFieldInfo(v *ConnectionEstablishmentIndicationMaskedIMEISVIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeConnectionEstablishmentIndicationMaskedIMEISVIEBindingFieldInject(v *ConnectionEstablishmentIndicationMaskedIMEISVIEBinding) *func(s00.MaskedIMEISV) s30.ConnectionEstablishmentIndicationIEValue {
	return &v.inject
}
func BridgeConnectionEstablishmentIndicationMethodMarshalAPERBudget(v *ConnectionEstablishmentIndication, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeConnectionEstablishmentIndicationMethodMarshalAPERBudgetValue(v *ConnectionEstablishmentIndication, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudgetValue(a0, a1)
}
func BridgeConnectionEstablishmentIndicationMethodMarshalAPERChanged(v *ConnectionEstablishmentIndication, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeConnectionEstablishmentIndicationMethodMarshalAPERChangedValue(v *ConnectionEstablishmentIndication, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeConnectionEstablishmentIndicationMethodMarshalAPERLegacy(v *ConnectionEstablishmentIndication) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeConnectionEstablishmentIndicationMethodMarshalAPERNewValue(v *ConnectionEstablishmentIndication, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERNewValue(a0, a1)
}
func BridgeConnectionEstablishmentIndicationMethodMarshalAPERPlanned(v *ConnectionEstablishmentIndication, a0 *aper.DecodeBudget, a1 bool, a2 *aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1, a2)
}
func BridgeConnectionEstablishmentIndicationMethodMarshalAPERTo(v *ConnectionEstablishmentIndication, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeConnectionEstablishmentIndicationMethodUnmarshalAPERFrom(v *ConnectionEstablishmentIndication, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeConnectionEstablishmentIndicationMethodUnmarshalAPERLegacy(v *ConnectionEstablishmentIndication, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeConnectionEstablishmentIndicationMethodUnmarshalAPERWithOptions(v *ConnectionEstablishmentIndication, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeConnectionEstablishmentIndicationSubscriptionBasedUEDifferentiationInfoIEBindingFieldCodec(v *ConnectionEstablishmentIndicationSubscriptionBasedUEDifferentiationInfoIEBinding) *SubscriptionBasedUEDifferentiationInfoValueCodec {
	return &v.codec
}
func BridgeConnectionEstablishmentIndicationSubscriptionBasedUEDifferentiationInfoIEBindingFieldGet(v *ConnectionEstablishmentIndicationSubscriptionBasedUEDifferentiationInfoIEBinding) *func(*s30.ConnectionEstablishmentIndicationIEValue) (*s30.SubscriptionBasedUEDifferentiationInfo, bool) {
	return &v.get
}
func BridgeConnectionEstablishmentIndicationSubscriptionBasedUEDifferentiationInfoIEBindingFieldInfo(v *ConnectionEstablishmentIndicationSubscriptionBasedUEDifferentiationInfoIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeConnectionEstablishmentIndicationSubscriptionBasedUEDifferentiationInfoIEBindingFieldInject(v *ConnectionEstablishmentIndicationSubscriptionBasedUEDifferentiationInfoIEBinding) *func(s30.SubscriptionBasedUEDifferentiationInfo) s30.ConnectionEstablishmentIndicationIEValue {
	return &v.inject
}
func BridgeConnectionEstablishmentIndicationUERadioCapabilityIDIEBindingFieldCodec(v *ConnectionEstablishmentIndicationUERadioCapabilityIDIEBinding) *s02.UERadioCapabilityIDValueCodec {
	return &v.codec
}
func BridgeConnectionEstablishmentIndicationUERadioCapabilityIDIEBindingFieldGet(v *ConnectionEstablishmentIndicationUERadioCapabilityIDIEBinding) *func(*s30.ConnectionEstablishmentIndicationIEValue) (*s00.UERadioCapabilityID, bool) {
	return &v.get
}
func BridgeConnectionEstablishmentIndicationUERadioCapabilityIDIEBindingFieldInfo(v *ConnectionEstablishmentIndicationUERadioCapabilityIDIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeConnectionEstablishmentIndicationUERadioCapabilityIDIEBindingFieldInject(v *ConnectionEstablishmentIndicationUERadioCapabilityIDIEBinding) *func(s00.UERadioCapabilityID) s30.ConnectionEstablishmentIndicationIEValue {
	return &v.inject
}
func BridgeConnectionEstablishmentIndicationUERadioCapabilityIEBindingFieldCodec(v *ConnectionEstablishmentIndicationUERadioCapabilityIEBinding) *s02.UERadioCapabilityValueCodec {
	return &v.codec
}
func BridgeConnectionEstablishmentIndicationUERadioCapabilityIEBindingFieldGet(v *ConnectionEstablishmentIndicationUERadioCapabilityIEBinding) *func(*s30.ConnectionEstablishmentIndicationIEValue) (*s00.UERadioCapability, bool) {
	return &v.get
}
func BridgeConnectionEstablishmentIndicationUERadioCapabilityIEBindingFieldInfo(v *ConnectionEstablishmentIndicationUERadioCapabilityIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeConnectionEstablishmentIndicationUERadioCapabilityIEBindingFieldInject(v *ConnectionEstablishmentIndicationUERadioCapabilityIEBinding) *func(s00.UERadioCapability) s30.ConnectionEstablishmentIndicationIEValue {
	return &v.inject
}
func BridgeConnectionEstablishmentIndicationValueCodecFieldCapture(v *ConnectionEstablishmentIndicationValueCodec) *func(ConnectionEstablishmentIndication, aper.DecodeState) (ConnectionEstablishmentIndication, aper.Snapshot) {
	return &v.capture
}
func BridgeConnectionEstablishmentIndicationValueCodecFieldCompare(v *ConnectionEstablishmentIndicationValueCodec) *func(ConnectionEstablishmentIndication, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeConnectionEstablishmentIndicationValueCodecFieldContext(v *ConnectionEstablishmentIndicationValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeConnectionEstablishmentIndicationValueCodecFieldDecode(v *ConnectionEstablishmentIndicationValueCodec) *func([]byte, aper.DecodeState) (ConnectionEstablishmentIndication, error) {
	return &v.decode
}
func BridgeConnectionEstablishmentIndicationValueCodecFieldEncode(v *ConnectionEstablishmentIndicationValueCodec) *func(ConnectionEstablishmentIndication, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeConnectionEstablishmentIndicationValueCodecFieldPath(v *ConnectionEstablishmentIndicationValueCodec) *aper.Path {
	return &v.path
}
func BridgeConnectionEstablishmentIndicationValueCodecMethodEncodeBudgetValue(v ConnectionEstablishmentIndicationValueCodec, a0 ConnectionEstablishmentIndication, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeConnectionEstablishmentIndicationValueCodecMethodEncodeChanged(v ConnectionEstablishmentIndicationValueCodec, a0 ConnectionEstablishmentIndication, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeENDCSONTransferTypeAPERValueFieldContext(v *ENDCSONTransferTypeAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeENDCSONTransferTypeAPERValueFieldReceived(v *ENDCSONTransferTypeAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeENDCSONTransferTypeAPERValueFieldReplay(v *ENDCSONTransferTypeAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeENDCSONTransferTypeAPERValueFieldWithoutReplay(v *ENDCSONTransferTypeAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeENDCSONTransferTypeFieldPerOpenTypePadding(v *ENDCSONTransferType) *aper.CompletePadding {
	return &v.perOpenTypePadding
}
func BridgeENDCSONTransferTypeFieldPerPadding(v *ENDCSONTransferType) *aper.CompletePadding {
	return &v.perPadding
}
func BridgeENDCSONTransferTypeFieldReceived(v *ENDCSONTransferType) *bool { return &v.received }
func BridgeENDCSONTransferTypeFieldReceivedAbsolute(v *ENDCSONTransferType) *bool {
	return &v.receivedAbsolute
}
func BridgeENDCSONTransferTypeFieldReceivedBytes(v *ENDCSONTransferType) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeENDCSONTransferTypeFieldReceivedLocation(v *ENDCSONTransferType) *aper.Location {
	return &v.receivedLocation
}
func BridgeENDCSONTransferTypeFieldReplay(v *ENDCSONTransferType) *aper.Snapshot { return &v.replay }
func BridgeENDCSONTransferTypeFieldStream(v *ENDCSONTransferType) *aper.WireSpan { return &v.stream }
func BridgeENDCSONTransferTypeFieldWithoutReplay(v *ENDCSONTransferType) *bool {
	return &v.withoutReplay
}
func BridgeENDCSONTransferTypeMethodMarshalAPERBudget(v *ENDCSONTransferType, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeENDCSONTransferTypeMethodMarshalAPERBudgetValue(v *ENDCSONTransferType, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudgetValue(a0, a1)
}
func BridgeENDCSONTransferTypeMethodMarshalAPERChanged(v *ENDCSONTransferType, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeENDCSONTransferTypeMethodMarshalAPERChangedValue(v *ENDCSONTransferType, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeENDCSONTransferTypeMethodMarshalAPERLegacy(v *ENDCSONTransferType) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeENDCSONTransferTypeMethodMarshalAPERNewValue(v *ENDCSONTransferType, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERNewValue(a0, a1)
}
func BridgeENDCSONTransferTypeMethodMarshalAPERPlanned(v *ENDCSONTransferType, a0 *aper.DecodeBudget, a1 bool, a2 *aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1, a2)
}
func BridgeENDCSONTransferTypeMethodMarshalAPERTo(v *ENDCSONTransferType, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeENDCSONTransferTypeMethodUnmarshalAPERFrom(v *ENDCSONTransferType, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeENDCSONTransferTypeMethodUnmarshalAPERLegacy(v *ENDCSONTransferType, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeENDCSONTransferTypeMethodUnmarshalAPERWithOptions(v *ENDCSONTransferType, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeENDCSONTransferTypeValueCodecFieldCapture(v *ENDCSONTransferTypeValueCodec) *func(ENDCSONTransferType, aper.DecodeState) (ENDCSONTransferType, aper.Snapshot) {
	return &v.capture
}
func BridgeENDCSONTransferTypeValueCodecFieldCompare(v *ENDCSONTransferTypeValueCodec) *func(ENDCSONTransferType, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeENDCSONTransferTypeValueCodecFieldContext(v *ENDCSONTransferTypeValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeENDCSONTransferTypeValueCodecFieldDecode(v *ENDCSONTransferTypeValueCodec) *func([]byte, aper.DecodeState) (ENDCSONTransferType, error) {
	return &v.decode
}
func BridgeENDCSONTransferTypeValueCodecFieldEncode(v *ENDCSONTransferTypeValueCodec) *func(ENDCSONTransferType, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeENDCSONTransferTypeValueCodecFieldPath(v *ENDCSONTransferTypeValueCodec) *aper.Path {
	return &v.path
}
func BridgeENDCSONTransferTypeValueCodecMethodEncodeBudgetValue(v ENDCSONTransferTypeValueCodec, a0 ENDCSONTransferType, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeENDCSONTransferTypeValueCodecMethodEncodeChanged(v ENDCSONTransferTypeValueCodec, a0 ENDCSONTransferType, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeENDCSONeNBIdentificationAPERValueFieldContext(v *ENDCSONeNBIdentificationAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeENDCSONeNBIdentificationAPERValueFieldReceived(v *ENDCSONeNBIdentificationAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeENDCSONeNBIdentificationAPERValueFieldReplay(v *ENDCSONeNBIdentificationAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeENDCSONeNBIdentificationAPERValueFieldWithoutReplay(v *ENDCSONeNBIdentificationAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeENDCSONeNBIdentificationFieldExtCount(v *ENDCSONeNBIdentification) *int64 {
	return &v.extCount
}
func BridgeENDCSONeNBIdentificationFieldExtData(v *ENDCSONeNBIdentification) *[][]byte {
	return &v.extData
}
func BridgeENDCSONeNBIdentificationFieldExtOrigin(v *ENDCSONeNBIdentification) *[]aper.OpaqueOrigin {
	return &v.extOrigin
}
func BridgeENDCSONeNBIdentificationFieldExtPresent(v *ENDCSONeNBIdentification) *[]bool {
	return &v.extPresent
}
func BridgeENDCSONeNBIdentificationFieldExtWire(v *ENDCSONeNBIdentification) *[]aper.WireSpan {
	return &v.extWire
}
func BridgeENDCSONeNBIdentificationFieldIEExtensionsIndef(v *ENDCSONeNBIdentification) *bool {
	return &v.iEExtensionsIndef
}
func BridgeENDCSONeNBIdentificationFieldPerExtPadding(v *ENDCSONeNBIdentification) *[]aper.CompletePadding {
	return &v.perExtPadding
}
func BridgeENDCSONeNBIdentificationFieldPerPadding(v *ENDCSONeNBIdentification) *aper.FinalPadding {
	return &v.perPadding
}
func BridgeENDCSONeNBIdentificationFieldReceived(v *ENDCSONeNBIdentification) *bool {
	return &v.received
}
func BridgeENDCSONeNBIdentificationFieldReceivedAbsolute(v *ENDCSONeNBIdentification) *bool {
	return &v.receivedAbsolute
}
func BridgeENDCSONeNBIdentificationFieldReceivedBytes(v *ENDCSONeNBIdentification) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeENDCSONeNBIdentificationFieldReceivedLocation(v *ENDCSONeNBIdentification) *aper.Location {
	return &v.receivedLocation
}
func BridgeENDCSONeNBIdentificationFieldReplay(v *ENDCSONeNBIdentification) *aper.Snapshot {
	return &v.replay
}
func BridgeENDCSONeNBIdentificationFieldStream(v *ENDCSONeNBIdentification) *aper.WireSpan {
	return &v.stream
}
func BridgeENDCSONeNBIdentificationFieldWithoutReplay(v *ENDCSONeNBIdentification) *bool {
	return &v.withoutReplay
}
func BridgeENDCSONeNBIdentificationMethodMarshalAPERBudget(v *ENDCSONeNBIdentification, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeENDCSONeNBIdentificationMethodMarshalAPERBudgetValue(v *ENDCSONeNBIdentification, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudgetValue(a0, a1)
}
func BridgeENDCSONeNBIdentificationMethodMarshalAPERChanged(v *ENDCSONeNBIdentification, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeENDCSONeNBIdentificationMethodMarshalAPERChangedValue(v *ENDCSONeNBIdentification, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeENDCSONeNBIdentificationMethodMarshalAPERLegacy(v *ENDCSONeNBIdentification) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeENDCSONeNBIdentificationMethodMarshalAPERNewValue(v *ENDCSONeNBIdentification, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERNewValue(a0, a1)
}
func BridgeENDCSONeNBIdentificationMethodMarshalAPERPlanned(v *ENDCSONeNBIdentification, a0 *aper.DecodeBudget, a1 bool, a2 *aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1, a2)
}
func BridgeENDCSONeNBIdentificationMethodMarshalAPERTo(v *ENDCSONeNBIdentification, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeENDCSONeNBIdentificationMethodUnmarshalAPERFrom(v *ENDCSONeNBIdentification, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeENDCSONeNBIdentificationMethodUnmarshalAPERLegacy(v *ENDCSONeNBIdentification, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeENDCSONeNBIdentificationMethodUnmarshalAPERWithOptions(v *ENDCSONeNBIdentification, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeENDCSONeNBIdentificationValueCodecFieldCapture(v *ENDCSONeNBIdentificationValueCodec) *func(ENDCSONeNBIdentification, aper.DecodeState) (ENDCSONeNBIdentification, aper.Snapshot) {
	return &v.capture
}
func BridgeENDCSONeNBIdentificationValueCodecFieldCompare(v *ENDCSONeNBIdentificationValueCodec) *func(ENDCSONeNBIdentification, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeENDCSONeNBIdentificationValueCodecFieldContext(v *ENDCSONeNBIdentificationValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeENDCSONeNBIdentificationValueCodecFieldDecode(v *ENDCSONeNBIdentificationValueCodec) *func([]byte, aper.DecodeState) (ENDCSONeNBIdentification, error) {
	return &v.decode
}
func BridgeENDCSONeNBIdentificationValueCodecFieldEncode(v *ENDCSONeNBIdentificationValueCodec) *func(ENDCSONeNBIdentification, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeENDCSONeNBIdentificationValueCodecFieldPath(v *ENDCSONeNBIdentificationValueCodec) *aper.Path {
	return &v.path
}
func BridgeENDCSONeNBIdentificationValueCodecMethodEncodeBudgetValue(v ENDCSONeNBIdentificationValueCodec, a0 ENDCSONeNBIdentification, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeENDCSONeNBIdentificationValueCodecMethodEncodeChanged(v ENDCSONeNBIdentificationValueCodec, a0 ENDCSONeNBIdentification, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeENDCSONengNBIdentificationAPERValueFieldContext(v *ENDCSONengNBIdentificationAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeENDCSONengNBIdentificationAPERValueFieldReceived(v *ENDCSONengNBIdentificationAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeENDCSONengNBIdentificationAPERValueFieldReplay(v *ENDCSONengNBIdentificationAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeENDCSONengNBIdentificationAPERValueFieldWithoutReplay(v *ENDCSONengNBIdentificationAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeENDCSONengNBIdentificationFieldExtCount(v *ENDCSONengNBIdentification) *int64 {
	return &v.extCount
}
func BridgeENDCSONengNBIdentificationFieldExtData(v *ENDCSONengNBIdentification) *[][]byte {
	return &v.extData
}
func BridgeENDCSONengNBIdentificationFieldExtOrigin(v *ENDCSONengNBIdentification) *[]aper.OpaqueOrigin {
	return &v.extOrigin
}
func BridgeENDCSONengNBIdentificationFieldExtPresent(v *ENDCSONengNBIdentification) *[]bool {
	return &v.extPresent
}
func BridgeENDCSONengNBIdentificationFieldExtWire(v *ENDCSONengNBIdentification) *[]aper.WireSpan {
	return &v.extWire
}
func BridgeENDCSONengNBIdentificationFieldIEExtensionsIndef(v *ENDCSONengNBIdentification) *bool {
	return &v.iEExtensionsIndef
}
func BridgeENDCSONengNBIdentificationFieldPerExtPadding(v *ENDCSONengNBIdentification) *[]aper.CompletePadding {
	return &v.perExtPadding
}
func BridgeENDCSONengNBIdentificationFieldPerPadding(v *ENDCSONengNBIdentification) *aper.FinalPadding {
	return &v.perPadding
}
func BridgeENDCSONengNBIdentificationFieldReceived(v *ENDCSONengNBIdentification) *bool {
	return &v.received
}
func BridgeENDCSONengNBIdentificationFieldReceivedAbsolute(v *ENDCSONengNBIdentification) *bool {
	return &v.receivedAbsolute
}
func BridgeENDCSONengNBIdentificationFieldReceivedBytes(v *ENDCSONengNBIdentification) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeENDCSONengNBIdentificationFieldReceivedLocation(v *ENDCSONengNBIdentification) *aper.Location {
	return &v.receivedLocation
}
func BridgeENDCSONengNBIdentificationFieldReplay(v *ENDCSONengNBIdentification) *aper.Snapshot {
	return &v.replay
}
func BridgeENDCSONengNBIdentificationFieldStream(v *ENDCSONengNBIdentification) *aper.WireSpan {
	return &v.stream
}
func BridgeENDCSONengNBIdentificationFieldWithoutReplay(v *ENDCSONengNBIdentification) *bool {
	return &v.withoutReplay
}
func BridgeENDCSONengNBIdentificationMethodMarshalAPERBudget(v *ENDCSONengNBIdentification, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeENDCSONengNBIdentificationMethodMarshalAPERBudgetValue(v *ENDCSONengNBIdentification, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudgetValue(a0, a1)
}
func BridgeENDCSONengNBIdentificationMethodMarshalAPERChanged(v *ENDCSONengNBIdentification, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeENDCSONengNBIdentificationMethodMarshalAPERChangedValue(v *ENDCSONengNBIdentification, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeENDCSONengNBIdentificationMethodMarshalAPERLegacy(v *ENDCSONengNBIdentification) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeENDCSONengNBIdentificationMethodMarshalAPERNewValue(v *ENDCSONengNBIdentification, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERNewValue(a0, a1)
}
func BridgeENDCSONengNBIdentificationMethodMarshalAPERPlanned(v *ENDCSONengNBIdentification, a0 *aper.DecodeBudget, a1 bool, a2 *aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1, a2)
}
func BridgeENDCSONengNBIdentificationMethodMarshalAPERTo(v *ENDCSONengNBIdentification, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeENDCSONengNBIdentificationMethodUnmarshalAPERFrom(v *ENDCSONengNBIdentification, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeENDCSONengNBIdentificationMethodUnmarshalAPERLegacy(v *ENDCSONengNBIdentification, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeENDCSONengNBIdentificationMethodUnmarshalAPERWithOptions(v *ENDCSONengNBIdentification, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeENDCSONengNBIdentificationValueCodecFieldCapture(v *ENDCSONengNBIdentificationValueCodec) *func(ENDCSONengNBIdentification, aper.DecodeState) (ENDCSONengNBIdentification, aper.Snapshot) {
	return &v.capture
}
func BridgeENDCSONengNBIdentificationValueCodecFieldCompare(v *ENDCSONengNBIdentificationValueCodec) *func(ENDCSONengNBIdentification, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeENDCSONengNBIdentificationValueCodecFieldContext(v *ENDCSONengNBIdentificationValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeENDCSONengNBIdentificationValueCodecFieldDecode(v *ENDCSONengNBIdentificationValueCodec) *func([]byte, aper.DecodeState) (ENDCSONengNBIdentification, error) {
	return &v.decode
}
func BridgeENDCSONengNBIdentificationValueCodecFieldEncode(v *ENDCSONengNBIdentificationValueCodec) *func(ENDCSONengNBIdentification, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeENDCSONengNBIdentificationValueCodecFieldPath(v *ENDCSONengNBIdentificationValueCodec) *aper.Path {
	return &v.path
}
func BridgeENDCSONengNBIdentificationValueCodecMethodEncodeBudgetValue(v ENDCSONengNBIdentificationValueCodec, a0 ENDCSONengNBIdentification, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeENDCSONengNBIdentificationValueCodecMethodEncodeChanged(v ENDCSONengNBIdentificationValueCodec, a0 ENDCSONengNBIdentification, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeENDCTransferTypeReplyAPERValueFieldContext(v *ENDCTransferTypeReplyAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeENDCTransferTypeReplyAPERValueFieldReceived(v *ENDCTransferTypeReplyAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeENDCTransferTypeReplyAPERValueFieldReplay(v *ENDCTransferTypeReplyAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeENDCTransferTypeReplyAPERValueFieldWithoutReplay(v *ENDCTransferTypeReplyAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeENDCTransferTypeReplyFieldExtCount(v *ENDCTransferTypeReply) *int64   { return &v.extCount }
func BridgeENDCTransferTypeReplyFieldExtData(v *ENDCTransferTypeReply) *[][]byte { return &v.extData }
func BridgeENDCTransferTypeReplyFieldExtOrigin(v *ENDCTransferTypeReply) *[]aper.OpaqueOrigin {
	return &v.extOrigin
}
func BridgeENDCTransferTypeReplyFieldExtPresent(v *ENDCTransferTypeReply) *[]bool {
	return &v.extPresent
}
func BridgeENDCTransferTypeReplyFieldExtWire(v *ENDCTransferTypeReply) *[]aper.WireSpan {
	return &v.extWire
}
func BridgeENDCTransferTypeReplyFieldIEExtensionsIndef(v *ENDCTransferTypeReply) *bool {
	return &v.iEExtensionsIndef
}
func BridgeENDCTransferTypeReplyFieldPerExtPadding(v *ENDCTransferTypeReply) *[]aper.CompletePadding {
	return &v.perExtPadding
}
func BridgeENDCTransferTypeReplyFieldPerPadding(v *ENDCTransferTypeReply) *aper.FinalPadding {
	return &v.perPadding
}
func BridgeENDCTransferTypeReplyFieldReceived(v *ENDCTransferTypeReply) *bool { return &v.received }
func BridgeENDCTransferTypeReplyFieldReceivedAbsolute(v *ENDCTransferTypeReply) *bool {
	return &v.receivedAbsolute
}
func BridgeENDCTransferTypeReplyFieldReceivedBytes(v *ENDCTransferTypeReply) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeENDCTransferTypeReplyFieldReceivedLocation(v *ENDCTransferTypeReply) *aper.Location {
	return &v.receivedLocation
}
func BridgeENDCTransferTypeReplyFieldReplay(v *ENDCTransferTypeReply) *aper.Snapshot {
	return &v.replay
}
func BridgeENDCTransferTypeReplyFieldStream(v *ENDCTransferTypeReply) *aper.WireSpan {
	return &v.stream
}
func BridgeENDCTransferTypeReplyFieldWithoutReplay(v *ENDCTransferTypeReply) *bool {
	return &v.withoutReplay
}
func BridgeENDCTransferTypeReplyMethodMarshalAPERBudget(v *ENDCTransferTypeReply, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeENDCTransferTypeReplyMethodMarshalAPERBudgetValue(v *ENDCTransferTypeReply, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudgetValue(a0, a1)
}
func BridgeENDCTransferTypeReplyMethodMarshalAPERChanged(v *ENDCTransferTypeReply, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeENDCTransferTypeReplyMethodMarshalAPERChangedValue(v *ENDCTransferTypeReply, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeENDCTransferTypeReplyMethodMarshalAPERLegacy(v *ENDCTransferTypeReply) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeENDCTransferTypeReplyMethodMarshalAPERNewValue(v *ENDCTransferTypeReply, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERNewValue(a0, a1)
}
func BridgeENDCTransferTypeReplyMethodMarshalAPERPlanned(v *ENDCTransferTypeReply, a0 *aper.DecodeBudget, a1 bool, a2 *aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1, a2)
}
func BridgeENDCTransferTypeReplyMethodMarshalAPERTo(v *ENDCTransferTypeReply, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeENDCTransferTypeReplyMethodUnmarshalAPERFrom(v *ENDCTransferTypeReply, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeENDCTransferTypeReplyMethodUnmarshalAPERLegacy(v *ENDCTransferTypeReply, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeENDCTransferTypeReplyMethodUnmarshalAPERWithOptions(v *ENDCTransferTypeReply, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeENDCTransferTypeReplyValueCodecFieldCapture(v *ENDCTransferTypeReplyValueCodec) *func(ENDCTransferTypeReply, aper.DecodeState) (ENDCTransferTypeReply, aper.Snapshot) {
	return &v.capture
}
func BridgeENDCTransferTypeReplyValueCodecFieldCompare(v *ENDCTransferTypeReplyValueCodec) *func(ENDCTransferTypeReply, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeENDCTransferTypeReplyValueCodecFieldContext(v *ENDCTransferTypeReplyValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeENDCTransferTypeReplyValueCodecFieldDecode(v *ENDCTransferTypeReplyValueCodec) *func([]byte, aper.DecodeState) (ENDCTransferTypeReply, error) {
	return &v.decode
}
func BridgeENDCTransferTypeReplyValueCodecFieldEncode(v *ENDCTransferTypeReplyValueCodec) *func(ENDCTransferTypeReply, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeENDCTransferTypeReplyValueCodecFieldPath(v *ENDCTransferTypeReplyValueCodec) *aper.Path {
	return &v.path
}
func BridgeENDCTransferTypeReplyValueCodecMethodEncodeBudgetValue(v ENDCTransferTypeReplyValueCodec, a0 ENDCTransferTypeReply, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeENDCTransferTypeReplyValueCodecMethodEncodeChanged(v ENDCTransferTypeReplyValueCodec, a0 ENDCTransferTypeReply, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeENDCTransferTypeRequestAPERValueFieldContext(v *ENDCTransferTypeRequestAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeENDCTransferTypeRequestAPERValueFieldReceived(v *ENDCTransferTypeRequestAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeENDCTransferTypeRequestAPERValueFieldReplay(v *ENDCTransferTypeRequestAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeENDCTransferTypeRequestAPERValueFieldWithoutReplay(v *ENDCTransferTypeRequestAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeENDCTransferTypeRequestFieldExtCount(v *ENDCTransferTypeRequest) *int64 {
	return &v.extCount
}
func BridgeENDCTransferTypeRequestFieldExtData(v *ENDCTransferTypeRequest) *[][]byte {
	return &v.extData
}
func BridgeENDCTransferTypeRequestFieldExtOrigin(v *ENDCTransferTypeRequest) *[]aper.OpaqueOrigin {
	return &v.extOrigin
}
func BridgeENDCTransferTypeRequestFieldExtPresent(v *ENDCTransferTypeRequest) *[]bool {
	return &v.extPresent
}
func BridgeENDCTransferTypeRequestFieldExtWire(v *ENDCTransferTypeRequest) *[]aper.WireSpan {
	return &v.extWire
}
func BridgeENDCTransferTypeRequestFieldIEExtensionsIndef(v *ENDCTransferTypeRequest) *bool {
	return &v.iEExtensionsIndef
}
func BridgeENDCTransferTypeRequestFieldPerExtPadding(v *ENDCTransferTypeRequest) *[]aper.CompletePadding {
	return &v.perExtPadding
}
func BridgeENDCTransferTypeRequestFieldPerPadding(v *ENDCTransferTypeRequest) *aper.FinalPadding {
	return &v.perPadding
}
func BridgeENDCTransferTypeRequestFieldReceived(v *ENDCTransferTypeRequest) *bool { return &v.received }
func BridgeENDCTransferTypeRequestFieldReceivedAbsolute(v *ENDCTransferTypeRequest) *bool {
	return &v.receivedAbsolute
}
func BridgeENDCTransferTypeRequestFieldReceivedBytes(v *ENDCTransferTypeRequest) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeENDCTransferTypeRequestFieldReceivedLocation(v *ENDCTransferTypeRequest) *aper.Location {
	return &v.receivedLocation
}
func BridgeENDCTransferTypeRequestFieldReplay(v *ENDCTransferTypeRequest) *aper.Snapshot {
	return &v.replay
}
func BridgeENDCTransferTypeRequestFieldStream(v *ENDCTransferTypeRequest) *aper.WireSpan {
	return &v.stream
}
func BridgeENDCTransferTypeRequestFieldWithoutReplay(v *ENDCTransferTypeRequest) *bool {
	return &v.withoutReplay
}
func BridgeENDCTransferTypeRequestMethodMarshalAPERBudget(v *ENDCTransferTypeRequest, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeENDCTransferTypeRequestMethodMarshalAPERBudgetValue(v *ENDCTransferTypeRequest, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudgetValue(a0, a1)
}
func BridgeENDCTransferTypeRequestMethodMarshalAPERChanged(v *ENDCTransferTypeRequest, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeENDCTransferTypeRequestMethodMarshalAPERChangedValue(v *ENDCTransferTypeRequest, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeENDCTransferTypeRequestMethodMarshalAPERLegacy(v *ENDCTransferTypeRequest) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeENDCTransferTypeRequestMethodMarshalAPERNewValue(v *ENDCTransferTypeRequest, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERNewValue(a0, a1)
}
func BridgeENDCTransferTypeRequestMethodMarshalAPERPlanned(v *ENDCTransferTypeRequest, a0 *aper.DecodeBudget, a1 bool, a2 *aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1, a2)
}
func BridgeENDCTransferTypeRequestMethodMarshalAPERTo(v *ENDCTransferTypeRequest, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeENDCTransferTypeRequestMethodUnmarshalAPERFrom(v *ENDCTransferTypeRequest, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeENDCTransferTypeRequestMethodUnmarshalAPERLegacy(v *ENDCTransferTypeRequest, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeENDCTransferTypeRequestMethodUnmarshalAPERWithOptions(v *ENDCTransferTypeRequest, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeENDCTransferTypeRequestValueCodecFieldCapture(v *ENDCTransferTypeRequestValueCodec) *func(ENDCTransferTypeRequest, aper.DecodeState) (ENDCTransferTypeRequest, aper.Snapshot) {
	return &v.capture
}
func BridgeENDCTransferTypeRequestValueCodecFieldCompare(v *ENDCTransferTypeRequestValueCodec) *func(ENDCTransferTypeRequest, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeENDCTransferTypeRequestValueCodecFieldContext(v *ENDCTransferTypeRequestValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeENDCTransferTypeRequestValueCodecFieldDecode(v *ENDCTransferTypeRequestValueCodec) *func([]byte, aper.DecodeState) (ENDCTransferTypeRequest, error) {
	return &v.decode
}
func BridgeENDCTransferTypeRequestValueCodecFieldEncode(v *ENDCTransferTypeRequestValueCodec) *func(ENDCTransferTypeRequest, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeENDCTransferTypeRequestValueCodecFieldPath(v *ENDCTransferTypeRequestValueCodec) *aper.Path {
	return &v.path
}
func BridgeENDCTransferTypeRequestValueCodecMethodEncodeBudgetValue(v ENDCTransferTypeRequestValueCodec, a0 ENDCTransferTypeRequest, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeENDCTransferTypeRequestValueCodecMethodEncodeChanged(v ENDCTransferTypeRequestValueCodec, a0 ENDCTransferTypeRequest, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeLocationReportENBUES1APIDIEBindingFieldCodec(v *LocationReportENBUES1APIDIEBinding) *s00.ENBUES1APIDValueCodec {
	return &v.codec
}
func BridgeLocationReportENBUES1APIDIEBindingFieldGet(v *LocationReportENBUES1APIDIEBinding) *func(*LocationReportIEValue) (*s00.ENBUES1APID, bool) {
	return &v.get
}
func BridgeLocationReportENBUES1APIDIEBindingFieldInfo(v *LocationReportENBUES1APIDIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeLocationReportENBUES1APIDIEBindingFieldInject(v *LocationReportENBUES1APIDIEBinding) *func(s00.ENBUES1APID) LocationReportIEValue {
	return &v.inject
}
func BridgeLocationReportEUTRANCGIIEBindingFieldCodec(v *LocationReportEUTRANCGIIEBinding) *s17.EUTRANCGIValueCodec {
	return &v.codec
}
func BridgeLocationReportEUTRANCGIIEBindingFieldGet(v *LocationReportEUTRANCGIIEBinding) *func(*LocationReportIEValue) (*s17.EUTRANCGI, bool) {
	return &v.get
}
func BridgeLocationReportEUTRANCGIIEBindingFieldInfo(v *LocationReportEUTRANCGIIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeLocationReportEUTRANCGIIEBindingFieldInject(v *LocationReportEUTRANCGIIEBinding) *func(s17.EUTRANCGI) LocationReportIEValue {
	return &v.inject
}
func BridgeLocationReportIEContainerAPERValueFieldContext(v *LocationReportIEContainerAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeLocationReportIEContainerAPERValueFieldReceived(v *LocationReportIEContainerAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeLocationReportIEContainerAPERValueFieldReplay(v *LocationReportIEContainerAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeLocationReportIEContainerAPERValueFieldWithoutReplay(v *LocationReportIEContainerAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeLocationReportIEContainerValueCodecFieldCapture(v *LocationReportIEContainerValueCodec) *func(LocationReportIEContainer, aper.DecodeState) (LocationReportIEContainer, aper.Snapshot) {
	return &v.capture
}
func BridgeLocationReportIEContainerValueCodecFieldCompare(v *LocationReportIEContainerValueCodec) *func(LocationReportIEContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeLocationReportIEContainerValueCodecFieldContext(v *LocationReportIEContainerValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeLocationReportIEContainerValueCodecFieldDecode(v *LocationReportIEContainerValueCodec) *func([]byte, aper.DecodeState) (LocationReportIEContainer, error) {
	return &v.decode
}
func BridgeLocationReportIEContainerValueCodecFieldEncode(v *LocationReportIEContainerValueCodec) *func(LocationReportIEContainer, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeLocationReportIEContainerValueCodecFieldPath(v *LocationReportIEContainerValueCodec) *aper.Path {
	return &v.path
}
func BridgeLocationReportIEContainerValueCodecMethodEncodeBudgetValue(v LocationReportIEContainerValueCodec, a0 LocationReportIEContainer, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeLocationReportIEContainerValueCodecMethodEncodeChanged(v LocationReportIEContainerValueCodec, a0 LocationReportIEContainer, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeLocationReportIEFieldAPERValueFieldContext(v *LocationReportIEFieldAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeLocationReportIEFieldAPERValueFieldReceived(v *LocationReportIEFieldAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeLocationReportIEFieldAPERValueFieldReplay(v *LocationReportIEFieldAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeLocationReportIEFieldAPERValueFieldWithoutReplay(v *LocationReportIEFieldAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeLocationReportIEFieldFieldReceived(v *LocationReportIEField) *aper.CompletePadding {
	return &v.received
}
func BridgeLocationReportIEFieldFieldReplay(v *LocationReportIEField) *aper.Snapshot {
	return &v.replay
}
func BridgeLocationReportIEFieldFieldStream(v *LocationReportIEField) *aper.WireSpan {
	return &v.stream
}
func BridgeLocationReportIEFieldFieldWithoutReplay(v *LocationReportIEField) *bool {
	return &v.withoutReplay
}
func BridgeLocationReportIEFieldMethodMarshalAPERTo(v *LocationReportIEField, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeLocationReportIEFieldMethodUnmarshalAPERFrom(v *LocationReportIEField, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeLocationReportIEFieldValueCodecFieldCapture(v *LocationReportIEFieldValueCodec) *func(LocationReportIEField, aper.DecodeState) (LocationReportIEField, aper.Snapshot) {
	return &v.capture
}
func BridgeLocationReportIEFieldValueCodecFieldCompare(v *LocationReportIEFieldValueCodec) *func(LocationReportIEField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeLocationReportIEFieldValueCodecFieldContext(v *LocationReportIEFieldValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeLocationReportIEFieldValueCodecFieldDecode(v *LocationReportIEFieldValueCodec) *func([]byte, aper.DecodeState) (LocationReportIEField, error) {
	return &v.decode
}
func BridgeLocationReportIEFieldValueCodecFieldEncode(v *LocationReportIEFieldValueCodec) *func(LocationReportIEField, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeLocationReportIEFieldValueCodecFieldPath(v *LocationReportIEFieldValueCodec) *aper.Path {
	return &v.path
}
func BridgeLocationReportIEFieldValueCodecMethodEncodeBudgetValue(v LocationReportIEFieldValueCodec, a0 LocationReportIEField, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeLocationReportIEFieldValueCodecMethodEncodeChanged(v LocationReportIEFieldValueCodec, a0 LocationReportIEField, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeLocationReportIEValueERABIEContainerListAPERValueFieldContext(v *LocationReportIEValueERABIEContainerListAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeLocationReportIEValueERABIEContainerListAPERValueFieldReceived(v *LocationReportIEValueERABIEContainerListAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeLocationReportIEValueERABIEContainerListAPERValueFieldReplay(v *LocationReportIEValueERABIEContainerListAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeLocationReportIEValueERABIEContainerListAPERValueFieldWithoutReplay(v *LocationReportIEValueERABIEContainerListAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeLocationReportIEValueERABIEContainerListValueCodecFieldCapture(v *LocationReportIEValueERABIEContainerListValueCodec) *func(LocationReportIEValueERABIEContainerList, aper.DecodeState) (LocationReportIEValueERABIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgeLocationReportIEValueERABIEContainerListValueCodecFieldCompare(v *LocationReportIEValueERABIEContainerListValueCodec) *func(LocationReportIEValueERABIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeLocationReportIEValueERABIEContainerListValueCodecFieldContext(v *LocationReportIEValueERABIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeLocationReportIEValueERABIEContainerListValueCodecFieldDecode(v *LocationReportIEValueERABIEContainerListValueCodec) *func([]byte, aper.DecodeState) (LocationReportIEValueERABIEContainerList, error) {
	return &v.decode
}
func BridgeLocationReportIEValueERABIEContainerListValueCodecFieldEncode(v *LocationReportIEValueERABIEContainerListValueCodec) *func(LocationReportIEValueERABIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeLocationReportIEValueERABIEContainerListValueCodecFieldPath(v *LocationReportIEValueERABIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgeLocationReportIEValueERABIEContainerListValueCodecMethodEncodeBudgetValue(v LocationReportIEValueERABIEContainerListValueCodec, a0 LocationReportIEValueERABIEContainerList, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeLocationReportIEValueERABIEContainerListValueCodecMethodEncodeChanged(v LocationReportIEValueERABIEContainerListValueCodec, a0 LocationReportIEValueERABIEContainerList, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeLocationReportIEValueFieldId(v *LocationReportIEValue) *s00.ProtocolIEID { return &v.id }
func BridgeLocationReportIEValueFieldIsOpaque(v *LocationReportIEValue) *bool       { return &v.isOpaque }
func BridgeLocationReportIEValueFieldOpaque(v *LocationReportIEValue) *aper.OpaqueOpenType {
	return &v.opaque
}
func BridgeLocationReportIEValueFieldReceived(v *LocationReportIEValue) *aper.WireSpan {
	return &v.received
}
func BridgeLocationReportIEValueFieldReplay(v *LocationReportIEValue) *aper.Snapshot {
	return &v.replay
}
func BridgeLocationReportIEValueFieldRowENBUES1APID(v *LocationReportIEValue) **s00.ENBUES1APID {
	return &v.rowENBUES1APID
}
func BridgeLocationReportIEValueFieldRowEUTRANCGI(v *LocationReportIEValue) **s17.EUTRANCGI {
	return &v.rowEUTRANCGI
}
func BridgeLocationReportIEValueFieldRowLTENTNTAIInformation(v *LocationReportIEValue) **s18.LTENTNTAIInformation {
	return &v.rowLTENTNTAIInformation
}
func BridgeLocationReportIEValueFieldRowMMEUES1APID(v *LocationReportIEValue) **s00.MMEUES1APID {
	return &v.rowMMEUES1APID
}
func BridgeLocationReportIEValueFieldRowPSCellInformation(v *LocationReportIEValue) **s20.PSCellInformation {
	return &v.rowPSCellInformation
}
func BridgeLocationReportIEValueFieldRowRequestType(v *LocationReportIEValue) **s26.RequestType {
	return &v.rowRequestType
}
func BridgeLocationReportIEValueFieldRowTAI(v *LocationReportIEValue) **TAI { return &v.rowTAI }
func BridgeLocationReportIEValueMethodCaptureSemantics(v LocationReportIEValue, a0 aper.SemanticCapture) LocationReportIEValue {
	return v.captureSemantics(a0)
}
func BridgeLocationReportIEValueMethodCompareSemantics(v LocationReportIEValue, a0 aper.SemanticComparison) aper.SemanticComparison {
	return v.compareSemantics(a0)
}
func BridgeLocationReportIEValueMethodDecode(v LocationReportIEValue, a0 s00.ProtocolIEID, a1 aper.OpaqueOpenType) (LocationReportIEValue, error) {
	return v.decode(a0, a1)
}
func BridgeLocationReportIEValueMethodEncode(v LocationReportIEValue) ([]byte, error) {
	return v.encode()
}
func BridgeLocationReportIEValueMethodEncodeFresh(v LocationReportIEValue, a0 bool, a1 *aper.DecodeBudget) ([]byte, error) {
	return v.encodeFresh(a0, a1)
}
func BridgeLocationReportIEValueMethodMatchesID(v LocationReportIEValue, a0 s00.ProtocolIEID, a1 ...*aper.DecodeBudget) bool {
	return v.matchesID(a0, a1...)
}
func BridgeLocationReportIEValueMethodReason(v LocationReportIEValue, a0 s00.ProtocolIEID) aper.OpaqueReason {
	return v.reason(a0)
}
func BridgeLocationReportIEValueMethodRule(v LocationReportIEValue) aper.SourceRule { return v.rule() }
func BridgeLocationReportIEValueProtocolErrorIEContainerListAPERValueFieldContext(v *LocationReportIEValueProtocolErrorIEContainerListAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeLocationReportIEValueProtocolErrorIEContainerListAPERValueFieldReceived(v *LocationReportIEValueProtocolErrorIEContainerListAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeLocationReportIEValueProtocolErrorIEContainerListAPERValueFieldReplay(v *LocationReportIEValueProtocolErrorIEContainerListAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeLocationReportIEValueProtocolErrorIEContainerListAPERValueFieldWithoutReplay(v *LocationReportIEValueProtocolErrorIEContainerListAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeLocationReportIEValueProtocolErrorIEContainerListValueCodecFieldCapture(v *LocationReportIEValueProtocolErrorIEContainerListValueCodec) *func(LocationReportIEValueProtocolErrorIEContainerList, aper.DecodeState) (LocationReportIEValueProtocolErrorIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgeLocationReportIEValueProtocolErrorIEContainerListValueCodecFieldCompare(v *LocationReportIEValueProtocolErrorIEContainerListValueCodec) *func(LocationReportIEValueProtocolErrorIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeLocationReportIEValueProtocolErrorIEContainerListValueCodecFieldContext(v *LocationReportIEValueProtocolErrorIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeLocationReportIEValueProtocolErrorIEContainerListValueCodecFieldDecode(v *LocationReportIEValueProtocolErrorIEContainerListValueCodec) *func([]byte, aper.DecodeState) (LocationReportIEValueProtocolErrorIEContainerList, error) {
	return &v.decode
}
func BridgeLocationReportIEValueProtocolErrorIEContainerListValueCodecFieldEncode(v *LocationReportIEValueProtocolErrorIEContainerListValueCodec) *func(LocationReportIEValueProtocolErrorIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeLocationReportIEValueProtocolErrorIEContainerListValueCodecFieldPath(v *LocationReportIEValueProtocolErrorIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgeLocationReportIEValueProtocolErrorIEContainerListValueCodecMethodEncodeBudgetValue(v LocationReportIEValueProtocolErrorIEContainerListValueCodec, a0 LocationReportIEValueProtocolErrorIEContainerList, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeLocationReportIEValueProtocolErrorIEContainerListValueCodecMethodEncodeChanged(v LocationReportIEValueProtocolErrorIEContainerListValueCodec, a0 LocationReportIEValueProtocolErrorIEContainerList, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeLocationReportIEValueProtocolIEContainerListAPERValueFieldContext(v *LocationReportIEValueProtocolIEContainerListAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeLocationReportIEValueProtocolIEContainerListAPERValueFieldReceived(v *LocationReportIEValueProtocolIEContainerListAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeLocationReportIEValueProtocolIEContainerListAPERValueFieldReplay(v *LocationReportIEValueProtocolIEContainerListAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeLocationReportIEValueProtocolIEContainerListAPERValueFieldWithoutReplay(v *LocationReportIEValueProtocolIEContainerListAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeLocationReportIEValueProtocolIEContainerListValueCodecFieldCapture(v *LocationReportIEValueProtocolIEContainerListValueCodec) *func(LocationReportIEValueProtocolIEContainerList, aper.DecodeState) (LocationReportIEValueProtocolIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgeLocationReportIEValueProtocolIEContainerListValueCodecFieldCompare(v *LocationReportIEValueProtocolIEContainerListValueCodec) *func(LocationReportIEValueProtocolIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeLocationReportIEValueProtocolIEContainerListValueCodecFieldContext(v *LocationReportIEValueProtocolIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeLocationReportIEValueProtocolIEContainerListValueCodecFieldDecode(v *LocationReportIEValueProtocolIEContainerListValueCodec) *func([]byte, aper.DecodeState) (LocationReportIEValueProtocolIEContainerList, error) {
	return &v.decode
}
func BridgeLocationReportIEValueProtocolIEContainerListValueCodecFieldEncode(v *LocationReportIEValueProtocolIEContainerListValueCodec) *func(LocationReportIEValueProtocolIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeLocationReportIEValueProtocolIEContainerListValueCodecFieldPath(v *LocationReportIEValueProtocolIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgeLocationReportIEValueProtocolIEContainerListValueCodecMethodEncodeBudgetValue(v LocationReportIEValueProtocolIEContainerListValueCodec, a0 LocationReportIEValueProtocolIEContainerList, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeLocationReportIEValueProtocolIEContainerListValueCodecMethodEncodeChanged(v LocationReportIEValueProtocolIEContainerListValueCodec, a0 LocationReportIEValueProtocolIEContainerList, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeLocationReportLTENTNTAIInformationIEBindingFieldCodec(v *LocationReportLTENTNTAIInformationIEBinding) *s18.LTENTNTAIInformationValueCodec {
	return &v.codec
}
func BridgeLocationReportLTENTNTAIInformationIEBindingFieldGet(v *LocationReportLTENTNTAIInformationIEBinding) *func(*LocationReportIEValue) (*s18.LTENTNTAIInformation, bool) {
	return &v.get
}
func BridgeLocationReportLTENTNTAIInformationIEBindingFieldInfo(v *LocationReportLTENTNTAIInformationIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeLocationReportLTENTNTAIInformationIEBindingFieldInject(v *LocationReportLTENTNTAIInformationIEBinding) *func(s18.LTENTNTAIInformation) LocationReportIEValue {
	return &v.inject
}
func BridgeLocationReportMMEUES1APIDIEBindingFieldCodec(v *LocationReportMMEUES1APIDIEBinding) *s01.MMEUES1APIDValueCodec {
	return &v.codec
}
func BridgeLocationReportMMEUES1APIDIEBindingFieldGet(v *LocationReportMMEUES1APIDIEBinding) *func(*LocationReportIEValue) (*s00.MMEUES1APID, bool) {
	return &v.get
}
func BridgeLocationReportMMEUES1APIDIEBindingFieldInfo(v *LocationReportMMEUES1APIDIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeLocationReportMMEUES1APIDIEBindingFieldInject(v *LocationReportMMEUES1APIDIEBinding) *func(s00.MMEUES1APID) LocationReportIEValue {
	return &v.inject
}
func BridgeLocationReportPSCellInformationIEBindingFieldCodec(v *LocationReportPSCellInformationIEBinding) *s20.PSCellInformationValueCodec {
	return &v.codec
}
func BridgeLocationReportPSCellInformationIEBindingFieldGet(v *LocationReportPSCellInformationIEBinding) *func(*LocationReportIEValue) (*s20.PSCellInformation, bool) {
	return &v.get
}
func BridgeLocationReportPSCellInformationIEBindingFieldInfo(v *LocationReportPSCellInformationIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeLocationReportPSCellInformationIEBindingFieldInject(v *LocationReportPSCellInformationIEBinding) *func(s20.PSCellInformation) LocationReportIEValue {
	return &v.inject
}
func BridgeLocationReportRequestTypeIEBindingFieldCodec(v *LocationReportRequestTypeIEBinding) *s26.RequestTypeValueCodec {
	return &v.codec
}
func BridgeLocationReportRequestTypeIEBindingFieldGet(v *LocationReportRequestTypeIEBinding) *func(*LocationReportIEValue) (*s26.RequestType, bool) {
	return &v.get
}
func BridgeLocationReportRequestTypeIEBindingFieldInfo(v *LocationReportRequestTypeIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeLocationReportRequestTypeIEBindingFieldInject(v *LocationReportRequestTypeIEBinding) *func(s26.RequestType) LocationReportIEValue {
	return &v.inject
}
func BridgeMMEPagingTargetAPERValueFieldContext(v *MMEPagingTargetAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeMMEPagingTargetAPERValueFieldReceived(v *MMEPagingTargetAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeMMEPagingTargetAPERValueFieldReplay(v *MMEPagingTargetAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeMMEPagingTargetAPERValueFieldWithoutReplay(v *MMEPagingTargetAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeMMEPagingTargetFieldPerOpenTypePadding(v *MMEPagingTarget) *aper.CompletePadding {
	return &v.perOpenTypePadding
}
func BridgeMMEPagingTargetFieldPerPadding(v *MMEPagingTarget) *aper.CompletePadding {
	return &v.perPadding
}
func BridgeMMEPagingTargetFieldReceived(v *MMEPagingTarget) *bool         { return &v.received }
func BridgeMMEPagingTargetFieldReceivedAbsolute(v *MMEPagingTarget) *bool { return &v.receivedAbsolute }
func BridgeMMEPagingTargetFieldReceivedBytes(v *MMEPagingTarget) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeMMEPagingTargetFieldReceivedLocation(v *MMEPagingTarget) *aper.Location {
	return &v.receivedLocation
}
func BridgeMMEPagingTargetFieldReplay(v *MMEPagingTarget) *aper.Snapshot { return &v.replay }
func BridgeMMEPagingTargetFieldStream(v *MMEPagingTarget) *aper.WireSpan { return &v.stream }
func BridgeMMEPagingTargetFieldWithoutReplay(v *MMEPagingTarget) *bool   { return &v.withoutReplay }
func BridgeMMEPagingTargetMethodMarshalAPERBudget(v *MMEPagingTarget, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeMMEPagingTargetMethodMarshalAPERBudgetValue(v *MMEPagingTarget, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudgetValue(a0, a1)
}
func BridgeMMEPagingTargetMethodMarshalAPERChanged(v *MMEPagingTarget, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeMMEPagingTargetMethodMarshalAPERChangedValue(v *MMEPagingTarget, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeMMEPagingTargetMethodMarshalAPERLegacy(v *MMEPagingTarget) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeMMEPagingTargetMethodMarshalAPERNewValue(v *MMEPagingTarget, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERNewValue(a0, a1)
}
func BridgeMMEPagingTargetMethodMarshalAPERPlanned(v *MMEPagingTarget, a0 *aper.DecodeBudget, a1 bool, a2 *aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1, a2)
}
func BridgeMMEPagingTargetMethodMarshalAPERTo(v *MMEPagingTarget, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeMMEPagingTargetMethodUnmarshalAPERFrom(v *MMEPagingTarget, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeMMEPagingTargetMethodUnmarshalAPERLegacy(v *MMEPagingTarget, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeMMEPagingTargetMethodUnmarshalAPERWithOptions(v *MMEPagingTarget, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeMMEPagingTargetValueCodecFieldCapture(v *MMEPagingTargetValueCodec) *func(MMEPagingTarget, aper.DecodeState) (MMEPagingTarget, aper.Snapshot) {
	return &v.capture
}
func BridgeMMEPagingTargetValueCodecFieldCompare(v *MMEPagingTargetValueCodec) *func(MMEPagingTarget, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeMMEPagingTargetValueCodecFieldContext(v *MMEPagingTargetValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeMMEPagingTargetValueCodecFieldDecode(v *MMEPagingTargetValueCodec) *func([]byte, aper.DecodeState) (MMEPagingTarget, error) {
	return &v.decode
}
func BridgeMMEPagingTargetValueCodecFieldEncode(v *MMEPagingTargetValueCodec) *func(MMEPagingTarget, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeMMEPagingTargetValueCodecFieldPath(v *MMEPagingTargetValueCodec) *aper.Path {
	return &v.path
}
func BridgeMMEPagingTargetValueCodecMethodEncodeBudgetValue(v MMEPagingTargetValueCodec, a0 MMEPagingTarget, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeMMEPagingTargetValueCodecMethodEncodeChanged(v MMEPagingTargetValueCodec, a0 MMEPagingTarget, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeRecommendedENBItemAPERValueFieldContext(v *RecommendedENBItemAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeRecommendedENBItemAPERValueFieldReceived(v *RecommendedENBItemAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeRecommendedENBItemAPERValueFieldReplay(v *RecommendedENBItemAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeRecommendedENBItemAPERValueFieldWithoutReplay(v *RecommendedENBItemAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeRecommendedENBItemFieldExtCount(v *RecommendedENBItem) *int64   { return &v.extCount }
func BridgeRecommendedENBItemFieldExtData(v *RecommendedENBItem) *[][]byte { return &v.extData }
func BridgeRecommendedENBItemFieldExtOrigin(v *RecommendedENBItem) *[]aper.OpaqueOrigin {
	return &v.extOrigin
}
func BridgeRecommendedENBItemFieldExtPresent(v *RecommendedENBItem) *[]bool       { return &v.extPresent }
func BridgeRecommendedENBItemFieldExtWire(v *RecommendedENBItem) *[]aper.WireSpan { return &v.extWire }
func BridgeRecommendedENBItemFieldIEExtensionsIndef(v *RecommendedENBItem) *bool {
	return &v.iEExtensionsIndef
}
func BridgeRecommendedENBItemFieldPerExtPadding(v *RecommendedENBItem) *[]aper.CompletePadding {
	return &v.perExtPadding
}
func BridgeRecommendedENBItemFieldPerPadding(v *RecommendedENBItem) *aper.FinalPadding {
	return &v.perPadding
}
func BridgeRecommendedENBItemFieldReceived(v *RecommendedENBItem) *bool { return &v.received }
func BridgeRecommendedENBItemFieldReceivedAbsolute(v *RecommendedENBItem) *bool {
	return &v.receivedAbsolute
}
func BridgeRecommendedENBItemFieldReceivedBytes(v *RecommendedENBItem) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeRecommendedENBItemFieldReceivedLocation(v *RecommendedENBItem) *aper.Location {
	return &v.receivedLocation
}
func BridgeRecommendedENBItemFieldReplay(v *RecommendedENBItem) *aper.Snapshot { return &v.replay }
func BridgeRecommendedENBItemFieldStream(v *RecommendedENBItem) *aper.WireSpan { return &v.stream }
func BridgeRecommendedENBItemFieldWithoutReplay(v *RecommendedENBItem) *bool   { return &v.withoutReplay }
func BridgeRecommendedENBItemMethodMarshalAPERBudget(v *RecommendedENBItem, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeRecommendedENBItemMethodMarshalAPERBudgetValue(v *RecommendedENBItem, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudgetValue(a0, a1)
}
func BridgeRecommendedENBItemMethodMarshalAPERChanged(v *RecommendedENBItem, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeRecommendedENBItemMethodMarshalAPERChangedValue(v *RecommendedENBItem, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeRecommendedENBItemMethodMarshalAPERLegacy(v *RecommendedENBItem) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeRecommendedENBItemMethodMarshalAPERNewValue(v *RecommendedENBItem, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERNewValue(a0, a1)
}
func BridgeRecommendedENBItemMethodMarshalAPERPlanned(v *RecommendedENBItem, a0 *aper.DecodeBudget, a1 bool, a2 *aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1, a2)
}
func BridgeRecommendedENBItemMethodMarshalAPERTo(v *RecommendedENBItem, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeRecommendedENBItemMethodUnmarshalAPERFrom(v *RecommendedENBItem, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeRecommendedENBItemMethodUnmarshalAPERLegacy(v *RecommendedENBItem, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeRecommendedENBItemMethodUnmarshalAPERWithOptions(v *RecommendedENBItem, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeSubscriptionBasedUEDifferentiationInfoAPERValueFieldContext(v *SubscriptionBasedUEDifferentiationInfoAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeSubscriptionBasedUEDifferentiationInfoAPERValueFieldReceived(v *SubscriptionBasedUEDifferentiationInfoAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeSubscriptionBasedUEDifferentiationInfoAPERValueFieldReplay(v *SubscriptionBasedUEDifferentiationInfoAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeSubscriptionBasedUEDifferentiationInfoAPERValueFieldWithoutReplay(v *SubscriptionBasedUEDifferentiationInfoAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeSubscriptionBasedUEDifferentiationInfoValueCodecFieldCapture(v *SubscriptionBasedUEDifferentiationInfoValueCodec) *func(s30.SubscriptionBasedUEDifferentiationInfo, aper.DecodeState) (s30.SubscriptionBasedUEDifferentiationInfo, aper.Snapshot) {
	return &v.capture
}
func BridgeSubscriptionBasedUEDifferentiationInfoValueCodecFieldCompare(v *SubscriptionBasedUEDifferentiationInfoValueCodec) *func(s30.SubscriptionBasedUEDifferentiationInfo, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeSubscriptionBasedUEDifferentiationInfoValueCodecFieldContext(v *SubscriptionBasedUEDifferentiationInfoValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeSubscriptionBasedUEDifferentiationInfoValueCodecFieldDecode(v *SubscriptionBasedUEDifferentiationInfoValueCodec) *func([]byte, aper.DecodeState) (s30.SubscriptionBasedUEDifferentiationInfo, error) {
	return &v.decode
}
func BridgeSubscriptionBasedUEDifferentiationInfoValueCodecFieldEncode(v *SubscriptionBasedUEDifferentiationInfoValueCodec) *func(s30.SubscriptionBasedUEDifferentiationInfo, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeSubscriptionBasedUEDifferentiationInfoValueCodecFieldPath(v *SubscriptionBasedUEDifferentiationInfoValueCodec) *aper.Path {
	return &v.path
}
func BridgeSubscriptionBasedUEDifferentiationInfoValueCodecMethodEncodeBudgetValue(v SubscriptionBasedUEDifferentiationInfoValueCodec, a0 s30.SubscriptionBasedUEDifferentiationInfo, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeSubscriptionBasedUEDifferentiationInfoValueCodecMethodEncodeChanged(v SubscriptionBasedUEDifferentiationInfoValueCodec, a0 s30.SubscriptionBasedUEDifferentiationInfo, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeSupportedTAsAPERValueFieldContext(v *SupportedTAsAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeSupportedTAsAPERValueFieldReceived(v *SupportedTAsAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeSupportedTAsAPERValueFieldReplay(v *SupportedTAsAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeSupportedTAsAPERValueFieldWithoutReplay(v *SupportedTAsAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeSupportedTAsItemAPERValueFieldContext(v *SupportedTAsItemAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeSupportedTAsItemAPERValueFieldReceived(v *SupportedTAsItemAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeSupportedTAsItemAPERValueFieldReplay(v *SupportedTAsItemAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeSupportedTAsItemAPERValueFieldWithoutReplay(v *SupportedTAsItemAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeSupportedTAsItemFieldBroadcastPLMNsIndef(v *SupportedTAsItem) *bool {
	return &v.broadcastPLMNsIndef
}
func BridgeSupportedTAsItemFieldExtCount(v *SupportedTAsItem) *int64   { return &v.extCount }
func BridgeSupportedTAsItemFieldExtData(v *SupportedTAsItem) *[][]byte { return &v.extData }
func BridgeSupportedTAsItemFieldExtOrigin(v *SupportedTAsItem) *[]aper.OpaqueOrigin {
	return &v.extOrigin
}
func BridgeSupportedTAsItemFieldExtPresent(v *SupportedTAsItem) *[]bool       { return &v.extPresent }
func BridgeSupportedTAsItemFieldExtWire(v *SupportedTAsItem) *[]aper.WireSpan { return &v.extWire }
func BridgeSupportedTAsItemFieldIEExtensionsIndef(v *SupportedTAsItem) *bool {
	return &v.iEExtensionsIndef
}
func BridgeSupportedTAsItemFieldPerExtPadding(v *SupportedTAsItem) *[]aper.CompletePadding {
	return &v.perExtPadding
}
func BridgeSupportedTAsItemFieldPerPadding(v *SupportedTAsItem) *aper.FinalPadding {
	return &v.perPadding
}
func BridgeSupportedTAsItemFieldReceived(v *SupportedTAsItem) *bool { return &v.received }
func BridgeSupportedTAsItemFieldReceivedAbsolute(v *SupportedTAsItem) *bool {
	return &v.receivedAbsolute
}
func BridgeSupportedTAsItemFieldReceivedBytes(v *SupportedTAsItem) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeSupportedTAsItemFieldReceivedLocation(v *SupportedTAsItem) *aper.Location {
	return &v.receivedLocation
}
func BridgeSupportedTAsItemFieldReplay(v *SupportedTAsItem) *aper.Snapshot { return &v.replay }
func BridgeSupportedTAsItemFieldStream(v *SupportedTAsItem) *aper.WireSpan { return &v.stream }
func BridgeSupportedTAsItemFieldWithoutReplay(v *SupportedTAsItem) *bool   { return &v.withoutReplay }
func BridgeSupportedTAsItemMethodMarshalAPERBudget(v *SupportedTAsItem, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeSupportedTAsItemMethodMarshalAPERBudgetValue(v *SupportedTAsItem, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudgetValue(a0, a1)
}
func BridgeSupportedTAsItemMethodMarshalAPERChanged(v *SupportedTAsItem, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeSupportedTAsItemMethodMarshalAPERChangedValue(v *SupportedTAsItem, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeSupportedTAsItemMethodMarshalAPERLegacy(v *SupportedTAsItem) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeSupportedTAsItemMethodMarshalAPERNewValue(v *SupportedTAsItem, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERNewValue(a0, a1)
}
func BridgeSupportedTAsItemMethodMarshalAPERPlanned(v *SupportedTAsItem, a0 *aper.DecodeBudget, a1 bool, a2 *aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1, a2)
}
func BridgeSupportedTAsItemMethodMarshalAPERTo(v *SupportedTAsItem, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeSupportedTAsItemMethodUnmarshalAPERFrom(v *SupportedTAsItem, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeSupportedTAsItemMethodUnmarshalAPERLegacy(v *SupportedTAsItem, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeSupportedTAsItemMethodUnmarshalAPERWithOptions(v *SupportedTAsItem, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeSupportedTAsItemValueCodecFieldCapture(v *SupportedTAsItemValueCodec) *func(SupportedTAsItem, aper.DecodeState) (SupportedTAsItem, aper.Snapshot) {
	return &v.capture
}
func BridgeSupportedTAsItemValueCodecFieldCompare(v *SupportedTAsItemValueCodec) *func(SupportedTAsItem, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeSupportedTAsItemValueCodecFieldContext(v *SupportedTAsItemValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeSupportedTAsItemValueCodecFieldDecode(v *SupportedTAsItemValueCodec) *func([]byte, aper.DecodeState) (SupportedTAsItem, error) {
	return &v.decode
}
func BridgeSupportedTAsItemValueCodecFieldEncode(v *SupportedTAsItemValueCodec) *func(SupportedTAsItem, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeSupportedTAsItemValueCodecFieldPath(v *SupportedTAsItemValueCodec) *aper.Path {
	return &v.path
}
func BridgeSupportedTAsItemValueCodecMethodEncodeBudgetValue(v SupportedTAsItemValueCodec, a0 SupportedTAsItem, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeSupportedTAsItemValueCodecMethodEncodeChanged(v SupportedTAsItemValueCodec, a0 SupportedTAsItem, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeSupportedTAsValueCodecFieldCapture(v *SupportedTAsValueCodec) *func(SupportedTAs, aper.DecodeState) (SupportedTAs, aper.Snapshot) {
	return &v.capture
}
func BridgeSupportedTAsValueCodecFieldCompare(v *SupportedTAsValueCodec) *func(SupportedTAs, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeSupportedTAsValueCodecFieldContext(v *SupportedTAsValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeSupportedTAsValueCodecFieldDecode(v *SupportedTAsValueCodec) *func([]byte, aper.DecodeState) (SupportedTAs, error) {
	return &v.decode
}
func BridgeSupportedTAsValueCodecFieldEncode(v *SupportedTAsValueCodec) *func(SupportedTAs, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeSupportedTAsValueCodecFieldPath(v *SupportedTAsValueCodec) *aper.Path { return &v.path }
func BridgeSupportedTAsValueCodecMethodEncodeBudgetValue(v SupportedTAsValueCodec, a0 SupportedTAs, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeSupportedTAsValueCodecMethodEncodeChanged(v SupportedTAsValueCodec, a0 SupportedTAs, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeSynchronisationInformationAPERValueFieldContext(v *SynchronisationInformationAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeSynchronisationInformationAPERValueFieldReceived(v *SynchronisationInformationAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeSynchronisationInformationAPERValueFieldReplay(v *SynchronisationInformationAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeSynchronisationInformationAPERValueFieldWithoutReplay(v *SynchronisationInformationAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeSynchronisationInformationFieldAggressoreCGIListIndef(v *SynchronisationInformation) *bool {
	return &v.aggressoreCGIListIndef
}
func BridgeSynchronisationInformationFieldExtCount(v *SynchronisationInformation) *int64 {
	return &v.extCount
}
func BridgeSynchronisationInformationFieldExtData(v *SynchronisationInformation) *[][]byte {
	return &v.extData
}
func BridgeSynchronisationInformationFieldExtOrigin(v *SynchronisationInformation) *[]aper.OpaqueOrigin {
	return &v.extOrigin
}
func BridgeSynchronisationInformationFieldExtPresent(v *SynchronisationInformation) *[]bool {
	return &v.extPresent
}
func BridgeSynchronisationInformationFieldExtWire(v *SynchronisationInformation) *[]aper.WireSpan {
	return &v.extWire
}
func BridgeSynchronisationInformationFieldIEExtensionsIndef(v *SynchronisationInformation) *bool {
	return &v.iEExtensionsIndef
}
func BridgeSynchronisationInformationFieldPerExtPadding(v *SynchronisationInformation) *[]aper.CompletePadding {
	return &v.perExtPadding
}
func BridgeSynchronisationInformationFieldPerPadding(v *SynchronisationInformation) *aper.FinalPadding {
	return &v.perPadding
}
func BridgeSynchronisationInformationFieldReceived(v *SynchronisationInformation) *bool {
	return &v.received
}
func BridgeSynchronisationInformationFieldReceivedAbsolute(v *SynchronisationInformation) *bool {
	return &v.receivedAbsolute
}
func BridgeSynchronisationInformationFieldReceivedBytes(v *SynchronisationInformation) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeSynchronisationInformationFieldReceivedLocation(v *SynchronisationInformation) *aper.Location {
	return &v.receivedLocation
}
func BridgeSynchronisationInformationFieldReplay(v *SynchronisationInformation) *aper.Snapshot {
	return &v.replay
}
func BridgeSynchronisationInformationFieldStream(v *SynchronisationInformation) *aper.WireSpan {
	return &v.stream
}
func BridgeSynchronisationInformationFieldWithoutReplay(v *SynchronisationInformation) *bool {
	return &v.withoutReplay
}
func BridgeSynchronisationInformationMethodMarshalAPERBudget(v *SynchronisationInformation, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeSynchronisationInformationMethodMarshalAPERBudgetValue(v *SynchronisationInformation, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudgetValue(a0, a1)
}
func BridgeSynchronisationInformationMethodMarshalAPERChanged(v *SynchronisationInformation, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeSynchronisationInformationMethodMarshalAPERChangedValue(v *SynchronisationInformation, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeSynchronisationInformationMethodMarshalAPERLegacy(v *SynchronisationInformation) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeSynchronisationInformationMethodMarshalAPERNewValue(v *SynchronisationInformation, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERNewValue(a0, a1)
}
func BridgeSynchronisationInformationMethodMarshalAPERPlanned(v *SynchronisationInformation, a0 *aper.DecodeBudget, a1 bool, a2 *aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1, a2)
}
func BridgeSynchronisationInformationMethodMarshalAPERTo(v *SynchronisationInformation, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeSynchronisationInformationMethodUnmarshalAPERFrom(v *SynchronisationInformation, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeSynchronisationInformationMethodUnmarshalAPERLegacy(v *SynchronisationInformation, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeSynchronisationInformationMethodUnmarshalAPERWithOptions(v *SynchronisationInformation, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeSynchronisationInformationValueCodecFieldCapture(v *SynchronisationInformationValueCodec) *func(SynchronisationInformation, aper.DecodeState) (SynchronisationInformation, aper.Snapshot) {
	return &v.capture
}
func BridgeSynchronisationInformationValueCodecFieldCompare(v *SynchronisationInformationValueCodec) *func(SynchronisationInformation, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeSynchronisationInformationValueCodecFieldContext(v *SynchronisationInformationValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeSynchronisationInformationValueCodecFieldDecode(v *SynchronisationInformationValueCodec) *func([]byte, aper.DecodeState) (SynchronisationInformation, error) {
	return &v.decode
}
func BridgeSynchronisationInformationValueCodecFieldEncode(v *SynchronisationInformationValueCodec) *func(SynchronisationInformation, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeSynchronisationInformationValueCodecFieldPath(v *SynchronisationInformationValueCodec) *aper.Path {
	return &v.path
}
func BridgeSynchronisationInformationValueCodecMethodEncodeBudgetValue(v SynchronisationInformationValueCodec, a0 SynchronisationInformation, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeSynchronisationInformationValueCodecMethodEncodeChanged(v SynchronisationInformationValueCodec, a0 SynchronisationInformation, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeTABasedMDTAPERValueFieldContext(v *TABasedMDTAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeTABasedMDTAPERValueFieldReceived(v *TABasedMDTAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeTABasedMDTAPERValueFieldReplay(v *TABasedMDTAPERValue) *aper.Snapshot { return &v.replay }
func BridgeTABasedMDTAPERValueFieldWithoutReplay(v *TABasedMDTAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeTABasedMDTFieldExtCount(v *TABasedMDT) *int64                { return &v.extCount }
func BridgeTABasedMDTFieldExtData(v *TABasedMDT) *[][]byte              { return &v.extData }
func BridgeTABasedMDTFieldExtOrigin(v *TABasedMDT) *[]aper.OpaqueOrigin { return &v.extOrigin }
func BridgeTABasedMDTFieldExtPresent(v *TABasedMDT) *[]bool             { return &v.extPresent }
func BridgeTABasedMDTFieldExtWire(v *TABasedMDT) *[]aper.WireSpan       { return &v.extWire }
func BridgeTABasedMDTFieldIEExtensionsIndef(v *TABasedMDT) *bool        { return &v.iEExtensionsIndef }
func BridgeTABasedMDTFieldPerExtPadding(v *TABasedMDT) *[]aper.CompletePadding {
	return &v.perExtPadding
}
func BridgeTABasedMDTFieldPerPadding(v *TABasedMDT) *aper.FinalPadding   { return &v.perPadding }
func BridgeTABasedMDTFieldReceived(v *TABasedMDT) *bool                  { return &v.received }
func BridgeTABasedMDTFieldReceivedAbsolute(v *TABasedMDT) *bool          { return &v.receivedAbsolute }
func BridgeTABasedMDTFieldReceivedBytes(v *TABasedMDT) *aper.WireSpan    { return &v.receivedBytes }
func BridgeTABasedMDTFieldReceivedLocation(v *TABasedMDT) *aper.Location { return &v.receivedLocation }
func BridgeTABasedMDTFieldReplay(v *TABasedMDT) *aper.Snapshot           { return &v.replay }
func BridgeTABasedMDTFieldStream(v *TABasedMDT) *aper.WireSpan           { return &v.stream }
func BridgeTABasedMDTFieldTAListforMDTIndef(v *TABasedMDT) *bool         { return &v.tAListforMDTIndef }
func BridgeTABasedMDTFieldWithoutReplay(v *TABasedMDT) *bool             { return &v.withoutReplay }
func BridgeTABasedMDTMethodMarshalAPERBudget(v *TABasedMDT, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeTABasedMDTMethodMarshalAPERBudgetValue(v *TABasedMDT, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudgetValue(a0, a1)
}
func BridgeTABasedMDTMethodMarshalAPERChanged(v *TABasedMDT, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeTABasedMDTMethodMarshalAPERChangedValue(v *TABasedMDT, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeTABasedMDTMethodMarshalAPERLegacy(v *TABasedMDT) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeTABasedMDTMethodMarshalAPERNewValue(v *TABasedMDT, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERNewValue(a0, a1)
}
func BridgeTABasedMDTMethodMarshalAPERPlanned(v *TABasedMDT, a0 *aper.DecodeBudget, a1 bool, a2 *aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1, a2)
}
func BridgeTABasedMDTMethodMarshalAPERTo(v *TABasedMDT, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeTABasedMDTMethodUnmarshalAPERFrom(v *TABasedMDT, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeTABasedMDTMethodUnmarshalAPERLegacy(v *TABasedMDT, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeTABasedMDTMethodUnmarshalAPERWithOptions(v *TABasedMDT, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeTABasedMDTValueCodecFieldCapture(v *TABasedMDTValueCodec) *func(TABasedMDT, aper.DecodeState) (TABasedMDT, aper.Snapshot) {
	return &v.capture
}
func BridgeTABasedMDTValueCodecFieldCompare(v *TABasedMDTValueCodec) *func(TABasedMDT, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeTABasedMDTValueCodecFieldContext(v *TABasedMDTValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeTABasedMDTValueCodecFieldDecode(v *TABasedMDTValueCodec) *func([]byte, aper.DecodeState) (TABasedMDT, error) {
	return &v.decode
}
func BridgeTABasedMDTValueCodecFieldEncode(v *TABasedMDTValueCodec) *func(TABasedMDT, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeTABasedMDTValueCodecFieldPath(v *TABasedMDTValueCodec) *aper.Path { return &v.path }
func BridgeTABasedMDTValueCodecMethodEncodeBudgetValue(v TABasedMDTValueCodec, a0 TABasedMDT, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeTABasedMDTValueCodecMethodEncodeChanged(v TABasedMDTValueCodec, a0 TABasedMDT, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeTABasedQMCAPERValueFieldContext(v *TABasedQMCAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeTABasedQMCAPERValueFieldReceived(v *TABasedQMCAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeTABasedQMCAPERValueFieldReplay(v *TABasedQMCAPERValue) *aper.Snapshot { return &v.replay }
func BridgeTABasedQMCAPERValueFieldWithoutReplay(v *TABasedQMCAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeTABasedQMCFieldExtCount(v *TABasedQMC) *int64                { return &v.extCount }
func BridgeTABasedQMCFieldExtData(v *TABasedQMC) *[][]byte              { return &v.extData }
func BridgeTABasedQMCFieldExtOrigin(v *TABasedQMC) *[]aper.OpaqueOrigin { return &v.extOrigin }
func BridgeTABasedQMCFieldExtPresent(v *TABasedQMC) *[]bool             { return &v.extPresent }
func BridgeTABasedQMCFieldExtWire(v *TABasedQMC) *[]aper.WireSpan       { return &v.extWire }
func BridgeTABasedQMCFieldIEExtensionsIndef(v *TABasedQMC) *bool        { return &v.iEExtensionsIndef }
func BridgeTABasedQMCFieldPerExtPadding(v *TABasedQMC) *[]aper.CompletePadding {
	return &v.perExtPadding
}
func BridgeTABasedQMCFieldPerPadding(v *TABasedQMC) *aper.FinalPadding   { return &v.perPadding }
func BridgeTABasedQMCFieldReceived(v *TABasedQMC) *bool                  { return &v.received }
func BridgeTABasedQMCFieldReceivedAbsolute(v *TABasedQMC) *bool          { return &v.receivedAbsolute }
func BridgeTABasedQMCFieldReceivedBytes(v *TABasedQMC) *aper.WireSpan    { return &v.receivedBytes }
func BridgeTABasedQMCFieldReceivedLocation(v *TABasedQMC) *aper.Location { return &v.receivedLocation }
func BridgeTABasedQMCFieldReplay(v *TABasedQMC) *aper.Snapshot           { return &v.replay }
func BridgeTABasedQMCFieldStream(v *TABasedQMC) *aper.WireSpan           { return &v.stream }
func BridgeTABasedQMCFieldTAListforQMCIndef(v *TABasedQMC) *bool         { return &v.tAListforQMCIndef }
func BridgeTABasedQMCFieldWithoutReplay(v *TABasedQMC) *bool             { return &v.withoutReplay }
func BridgeTABasedQMCMethodMarshalAPERBudget(v *TABasedQMC, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeTABasedQMCMethodMarshalAPERBudgetValue(v *TABasedQMC, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudgetValue(a0, a1)
}
func BridgeTABasedQMCMethodMarshalAPERChanged(v *TABasedQMC, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeTABasedQMCMethodMarshalAPERChangedValue(v *TABasedQMC, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeTABasedQMCMethodMarshalAPERLegacy(v *TABasedQMC) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeTABasedQMCMethodMarshalAPERNewValue(v *TABasedQMC, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERNewValue(a0, a1)
}
func BridgeTABasedQMCMethodMarshalAPERPlanned(v *TABasedQMC, a0 *aper.DecodeBudget, a1 bool, a2 *aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1, a2)
}
func BridgeTABasedQMCMethodMarshalAPERTo(v *TABasedQMC, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeTABasedQMCMethodUnmarshalAPERFrom(v *TABasedQMC, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeTABasedQMCMethodUnmarshalAPERLegacy(v *TABasedQMC, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeTABasedQMCMethodUnmarshalAPERWithOptions(v *TABasedQMC, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeTABasedQMCValueCodecFieldCapture(v *TABasedQMCValueCodec) *func(TABasedQMC, aper.DecodeState) (TABasedQMC, aper.Snapshot) {
	return &v.capture
}
func BridgeTABasedQMCValueCodecFieldCompare(v *TABasedQMCValueCodec) *func(TABasedQMC, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeTABasedQMCValueCodecFieldContext(v *TABasedQMCValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeTABasedQMCValueCodecFieldDecode(v *TABasedQMCValueCodec) *func([]byte, aper.DecodeState) (TABasedQMC, error) {
	return &v.decode
}
func BridgeTABasedQMCValueCodecFieldEncode(v *TABasedQMCValueCodec) *func(TABasedQMC, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeTABasedQMCValueCodecFieldPath(v *TABasedQMCValueCodec) *aper.Path { return &v.path }
func BridgeTABasedQMCValueCodecMethodEncodeBudgetValue(v TABasedQMCValueCodec, a0 TABasedQMC, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeTABasedQMCValueCodecMethodEncodeChanged(v TABasedQMCValueCodec, a0 TABasedQMC, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeTAIFieldExtCount(v *TAI) *int64                       { return &v.extCount }
func BridgeTAIFieldExtData(v *TAI) *[][]byte                     { return &v.extData }
func BridgeTAIFieldExtOrigin(v *TAI) *[]aper.OpaqueOrigin        { return &v.extOrigin }
func BridgeTAIFieldExtPresent(v *TAI) *[]bool                    { return &v.extPresent }
func BridgeTAIFieldExtWire(v *TAI) *[]aper.WireSpan              { return &v.extWire }
func BridgeTAIFieldIEExtensionsIndef(v *TAI) *bool               { return &v.iEExtensionsIndef }
func BridgeTAIFieldPerExtPadding(v *TAI) *[]aper.CompletePadding { return &v.perExtPadding }
func BridgeTAIFieldPerPadding(v *TAI) *aper.FinalPadding         { return &v.perPadding }
func BridgeTAIFieldReceived(v *TAI) *bool                        { return &v.received }
func BridgeTAIFieldReceivedAbsolute(v *TAI) *bool                { return &v.receivedAbsolute }
func BridgeTAIFieldReceivedBytes(v *TAI) *aper.WireSpan          { return &v.receivedBytes }
func BridgeTAIFieldReceivedLocation(v *TAI) *aper.Location       { return &v.receivedLocation }
func BridgeTAIFieldReplay(v *TAI) *aper.Snapshot                 { return &v.replay }
func BridgeTAIFieldStream(v *TAI) *aper.WireSpan                 { return &v.stream }
func BridgeTAIFieldWithoutReplay(v *TAI) *bool                   { return &v.withoutReplay }
func BridgeTAIMethodMarshalAPERBudget(v *TAI, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeTAIMethodMarshalAPERBudgetValue(v *TAI, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudgetValue(a0, a1)
}
func BridgeTAIMethodMarshalAPERChanged(v *TAI, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeTAIMethodMarshalAPERChangedValue(v *TAI, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeTAIMethodMarshalAPERLegacy(v *TAI) ([]byte, error) { return v.marshalAPERLegacy() }
func BridgeTAIMethodMarshalAPERNewValue(v *TAI, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERNewValue(a0, a1)
}
func BridgeTAIMethodMarshalAPERPlanned(v *TAI, a0 *aper.DecodeBudget, a1 bool, a2 *aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1, a2)
}
func BridgeTAIMethodMarshalAPERTo(v *TAI, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeTAIMethodUnmarshalAPERFrom(v *TAI, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeTAIMethodUnmarshalAPERLegacy(v *TAI, a0 []byte) error { return v.unmarshalAPERLegacy(a0) }
func BridgeTAIMethodUnmarshalAPERWithOptions(v *TAI, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeUEInformationTransferERABLevelQoSParametersIEBindingFieldCodec(v *UEInformationTransferERABLevelQoSParametersIEBinding) *s18.ERABLevelQoSParametersValueCodec {
	return &v.codec
}
func BridgeUEInformationTransferERABLevelQoSParametersIEBindingFieldGet(v *UEInformationTransferERABLevelQoSParametersIEBinding) *func(*UEInformationTransferIEValue) (*s18.ERABLevelQoSParameters, bool) {
	return &v.get
}
func BridgeUEInformationTransferERABLevelQoSParametersIEBindingFieldInfo(v *UEInformationTransferERABLevelQoSParametersIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeUEInformationTransferERABLevelQoSParametersIEBindingFieldInject(v *UEInformationTransferERABLevelQoSParametersIEBinding) *func(s18.ERABLevelQoSParameters) UEInformationTransferIEValue {
	return &v.inject
}
func BridgeUEInformationTransferIEContainerAPERValueFieldContext(v *UEInformationTransferIEContainerAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeUEInformationTransferIEContainerAPERValueFieldReceived(v *UEInformationTransferIEContainerAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeUEInformationTransferIEContainerAPERValueFieldReplay(v *UEInformationTransferIEContainerAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeUEInformationTransferIEContainerAPERValueFieldWithoutReplay(v *UEInformationTransferIEContainerAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeUEInformationTransferIEContainerValueCodecFieldCapture(v *UEInformationTransferIEContainerValueCodec) *func(UEInformationTransferIEContainer, aper.DecodeState) (UEInformationTransferIEContainer, aper.Snapshot) {
	return &v.capture
}
func BridgeUEInformationTransferIEContainerValueCodecFieldCompare(v *UEInformationTransferIEContainerValueCodec) *func(UEInformationTransferIEContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeUEInformationTransferIEContainerValueCodecFieldContext(v *UEInformationTransferIEContainerValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeUEInformationTransferIEContainerValueCodecFieldDecode(v *UEInformationTransferIEContainerValueCodec) *func([]byte, aper.DecodeState) (UEInformationTransferIEContainer, error) {
	return &v.decode
}
func BridgeUEInformationTransferIEContainerValueCodecFieldEncode(v *UEInformationTransferIEContainerValueCodec) *func(UEInformationTransferIEContainer, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeUEInformationTransferIEContainerValueCodecFieldPath(v *UEInformationTransferIEContainerValueCodec) *aper.Path {
	return &v.path
}
func BridgeUEInformationTransferIEContainerValueCodecMethodEncodeBudgetValue(v UEInformationTransferIEContainerValueCodec, a0 UEInformationTransferIEContainer, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeUEInformationTransferIEContainerValueCodecMethodEncodeChanged(v UEInformationTransferIEContainerValueCodec, a0 UEInformationTransferIEContainer, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeUEInformationTransferIEFieldAPERValueFieldContext(v *UEInformationTransferIEFieldAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeUEInformationTransferIEFieldAPERValueFieldReceived(v *UEInformationTransferIEFieldAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeUEInformationTransferIEFieldAPERValueFieldReplay(v *UEInformationTransferIEFieldAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeUEInformationTransferIEFieldAPERValueFieldWithoutReplay(v *UEInformationTransferIEFieldAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeUEInformationTransferIEFieldFieldReceived(v *UEInformationTransferIEField) *aper.CompletePadding {
	return &v.received
}
func BridgeUEInformationTransferIEFieldFieldReplay(v *UEInformationTransferIEField) *aper.Snapshot {
	return &v.replay
}
func BridgeUEInformationTransferIEFieldFieldStream(v *UEInformationTransferIEField) *aper.WireSpan {
	return &v.stream
}
func BridgeUEInformationTransferIEFieldFieldWithoutReplay(v *UEInformationTransferIEField) *bool {
	return &v.withoutReplay
}
func BridgeUEInformationTransferIEFieldMethodMarshalAPERTo(v *UEInformationTransferIEField, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeUEInformationTransferIEFieldMethodUnmarshalAPERFrom(v *UEInformationTransferIEField, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeUEInformationTransferIEFieldValueCodecFieldCapture(v *UEInformationTransferIEFieldValueCodec) *func(UEInformationTransferIEField, aper.DecodeState) (UEInformationTransferIEField, aper.Snapshot) {
	return &v.capture
}
func BridgeUEInformationTransferIEFieldValueCodecFieldCompare(v *UEInformationTransferIEFieldValueCodec) *func(UEInformationTransferIEField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeUEInformationTransferIEFieldValueCodecFieldContext(v *UEInformationTransferIEFieldValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeUEInformationTransferIEFieldValueCodecFieldDecode(v *UEInformationTransferIEFieldValueCodec) *func([]byte, aper.DecodeState) (UEInformationTransferIEField, error) {
	return &v.decode
}
func BridgeUEInformationTransferIEFieldValueCodecFieldEncode(v *UEInformationTransferIEFieldValueCodec) *func(UEInformationTransferIEField, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeUEInformationTransferIEFieldValueCodecFieldPath(v *UEInformationTransferIEFieldValueCodec) *aper.Path {
	return &v.path
}
func BridgeUEInformationTransferIEFieldValueCodecMethodEncodeBudgetValue(v UEInformationTransferIEFieldValueCodec, a0 UEInformationTransferIEField, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeUEInformationTransferIEFieldValueCodecMethodEncodeChanged(v UEInformationTransferIEFieldValueCodec, a0 UEInformationTransferIEField, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeUEInformationTransferIETableMethodInfoMaskedIMEISV(v UEInformationTransferIETable) s00.FieldInfo {
	return v.infoMaskedIMEISV()
}
func BridgeUEInformationTransferIETableMethodInfoPendingDataIndication(v UEInformationTransferIETable) s00.FieldInfo {
	return v.infoPendingDataIndication()
}
func BridgeUEInformationTransferIETableMethodInfoSTMSI(v UEInformationTransferIETable) s00.FieldInfo {
	return v.infoSTMSI()
}
func BridgeUEInformationTransferIETableMethodInfoSubscriptionBasedUEDifferentiationInfo(v UEInformationTransferIETable) s00.FieldInfo {
	return v.infoSubscriptionBasedUEDifferentiationInfo()
}
func BridgeUEInformationTransferIETableMethodInfoUELevelQoSParameters(v UEInformationTransferIETable) s00.FieldInfo {
	return v.infoUELevelQoSParameters()
}
func BridgeUEInformationTransferIETableMethodInfoUERadioCapability(v UEInformationTransferIETable) s00.FieldInfo {
	return v.infoUERadioCapability()
}
func BridgeUEInformationTransferIEValueERABIEContainerListAPERValueFieldContext(v *UEInformationTransferIEValueERABIEContainerListAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeUEInformationTransferIEValueERABIEContainerListAPERValueFieldReceived(v *UEInformationTransferIEValueERABIEContainerListAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeUEInformationTransferIEValueERABIEContainerListAPERValueFieldReplay(v *UEInformationTransferIEValueERABIEContainerListAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeUEInformationTransferIEValueERABIEContainerListAPERValueFieldWithoutReplay(v *UEInformationTransferIEValueERABIEContainerListAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeUEInformationTransferIEValueERABIEContainerListValueCodecFieldCapture(v *UEInformationTransferIEValueERABIEContainerListValueCodec) *func(UEInformationTransferIEValueERABIEContainerList, aper.DecodeState) (UEInformationTransferIEValueERABIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgeUEInformationTransferIEValueERABIEContainerListValueCodecFieldCompare(v *UEInformationTransferIEValueERABIEContainerListValueCodec) *func(UEInformationTransferIEValueERABIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeUEInformationTransferIEValueERABIEContainerListValueCodecFieldContext(v *UEInformationTransferIEValueERABIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeUEInformationTransferIEValueERABIEContainerListValueCodecFieldDecode(v *UEInformationTransferIEValueERABIEContainerListValueCodec) *func([]byte, aper.DecodeState) (UEInformationTransferIEValueERABIEContainerList, error) {
	return &v.decode
}
func BridgeUEInformationTransferIEValueERABIEContainerListValueCodecFieldEncode(v *UEInformationTransferIEValueERABIEContainerListValueCodec) *func(UEInformationTransferIEValueERABIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeUEInformationTransferIEValueERABIEContainerListValueCodecFieldPath(v *UEInformationTransferIEValueERABIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgeUEInformationTransferIEValueERABIEContainerListValueCodecMethodEncodeBudgetValue(v UEInformationTransferIEValueERABIEContainerListValueCodec, a0 UEInformationTransferIEValueERABIEContainerList, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeUEInformationTransferIEValueERABIEContainerListValueCodecMethodEncodeChanged(v UEInformationTransferIEValueERABIEContainerListValueCodec, a0 UEInformationTransferIEValueERABIEContainerList, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeUEInformationTransferIEValueFieldId(v *UEInformationTransferIEValue) *s00.ProtocolIEID {
	return &v.id
}
func BridgeUEInformationTransferIEValueFieldIsOpaque(v *UEInformationTransferIEValue) *bool {
	return &v.isOpaque
}
func BridgeUEInformationTransferIEValueFieldOpaque(v *UEInformationTransferIEValue) *aper.OpaqueOpenType {
	return &v.opaque
}
func BridgeUEInformationTransferIEValueFieldReceived(v *UEInformationTransferIEValue) *aper.WireSpan {
	return &v.received
}
func BridgeUEInformationTransferIEValueFieldReplay(v *UEInformationTransferIEValue) *aper.Snapshot {
	return &v.replay
}
func BridgeUEInformationTransferIEValueFieldRowMaskedIMEISV(v *UEInformationTransferIEValue) **s00.MaskedIMEISV {
	return &v.rowMaskedIMEISV
}
func BridgeUEInformationTransferIEValueFieldRowPendingDataIndication(v *UEInformationTransferIEValue) **s00.PendingDataIndication {
	return &v.rowPendingDataIndication
}
func BridgeUEInformationTransferIEValueFieldRowSTMSI(v *UEInformationTransferIEValue) **s27.STMSI {
	return &v.rowSTMSI
}
func BridgeUEInformationTransferIEValueFieldRowSubscriptionBasedUEDifferentiationInfo(v *UEInformationTransferIEValue) **s30.SubscriptionBasedUEDifferentiationInfo {
	return &v.rowSubscriptionBasedUEDifferentiationInfo
}
func BridgeUEInformationTransferIEValueFieldRowUELevelQoSParameters(v *UEInformationTransferIEValue) **s18.ERABLevelQoSParameters {
	return &v.rowUELevelQoSParameters
}
func BridgeUEInformationTransferIEValueFieldRowUERadioCapability(v *UEInformationTransferIEValue) **s00.UERadioCapability {
	return &v.rowUERadioCapability
}
func BridgeUEInformationTransferIEValueMethodCaptureSemantics(v UEInformationTransferIEValue, a0 aper.SemanticCapture) UEInformationTransferIEValue {
	return v.captureSemantics(a0)
}
func BridgeUEInformationTransferIEValueMethodCompareSemantics(v UEInformationTransferIEValue, a0 aper.SemanticComparison) aper.SemanticComparison {
	return v.compareSemantics(a0)
}
func BridgeUEInformationTransferIEValueMethodDecode(v UEInformationTransferIEValue, a0 s00.ProtocolIEID, a1 aper.OpaqueOpenType) (UEInformationTransferIEValue, error) {
	return v.decode(a0, a1)
}
func BridgeUEInformationTransferIEValueMethodEncode(v UEInformationTransferIEValue) ([]byte, error) {
	return v.encode()
}
func BridgeUEInformationTransferIEValueMethodEncodeFresh(v UEInformationTransferIEValue, a0 bool, a1 *aper.DecodeBudget) ([]byte, error) {
	return v.encodeFresh(a0, a1)
}
func BridgeUEInformationTransferIEValueMethodMatchesID(v UEInformationTransferIEValue, a0 s00.ProtocolIEID, a1 ...*aper.DecodeBudget) bool {
	return v.matchesID(a0, a1...)
}
func BridgeUEInformationTransferIEValueMethodReason(v UEInformationTransferIEValue, a0 s00.ProtocolIEID) aper.OpaqueReason {
	return v.reason(a0)
}
func BridgeUEInformationTransferIEValueMethodRule(v UEInformationTransferIEValue) aper.SourceRule {
	return v.rule()
}
func BridgeUEInformationTransferIEValueProtocolErrorIEContainerListAPERValueFieldContext(v *UEInformationTransferIEValueProtocolErrorIEContainerListAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeUEInformationTransferIEValueProtocolErrorIEContainerListAPERValueFieldReceived(v *UEInformationTransferIEValueProtocolErrorIEContainerListAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeUEInformationTransferIEValueProtocolErrorIEContainerListAPERValueFieldReplay(v *UEInformationTransferIEValueProtocolErrorIEContainerListAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeUEInformationTransferIEValueProtocolErrorIEContainerListAPERValueFieldWithoutReplay(v *UEInformationTransferIEValueProtocolErrorIEContainerListAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeUEInformationTransferIEValueProtocolErrorIEContainerListValueCodecFieldCapture(v *UEInformationTransferIEValueProtocolErrorIEContainerListValueCodec) *func(UEInformationTransferIEValueProtocolErrorIEContainerList, aper.DecodeState) (UEInformationTransferIEValueProtocolErrorIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgeUEInformationTransferIEValueProtocolErrorIEContainerListValueCodecFieldCompare(v *UEInformationTransferIEValueProtocolErrorIEContainerListValueCodec) *func(UEInformationTransferIEValueProtocolErrorIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeUEInformationTransferIEValueProtocolErrorIEContainerListValueCodecFieldContext(v *UEInformationTransferIEValueProtocolErrorIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeUEInformationTransferIEValueProtocolErrorIEContainerListValueCodecFieldDecode(v *UEInformationTransferIEValueProtocolErrorIEContainerListValueCodec) *func([]byte, aper.DecodeState) (UEInformationTransferIEValueProtocolErrorIEContainerList, error) {
	return &v.decode
}
func BridgeUEInformationTransferIEValueProtocolErrorIEContainerListValueCodecFieldEncode(v *UEInformationTransferIEValueProtocolErrorIEContainerListValueCodec) *func(UEInformationTransferIEValueProtocolErrorIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeUEInformationTransferIEValueProtocolErrorIEContainerListValueCodecFieldPath(v *UEInformationTransferIEValueProtocolErrorIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgeUEInformationTransferIEValueProtocolErrorIEContainerListValueCodecMethodEncodeBudgetValue(v UEInformationTransferIEValueProtocolErrorIEContainerListValueCodec, a0 UEInformationTransferIEValueProtocolErrorIEContainerList, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeUEInformationTransferIEValueProtocolErrorIEContainerListValueCodecMethodEncodeChanged(v UEInformationTransferIEValueProtocolErrorIEContainerListValueCodec, a0 UEInformationTransferIEValueProtocolErrorIEContainerList, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeUEInformationTransferIEValueProtocolIEContainerListAPERValueFieldContext(v *UEInformationTransferIEValueProtocolIEContainerListAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeUEInformationTransferIEValueProtocolIEContainerListAPERValueFieldReceived(v *UEInformationTransferIEValueProtocolIEContainerListAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeUEInformationTransferIEValueProtocolIEContainerListAPERValueFieldReplay(v *UEInformationTransferIEValueProtocolIEContainerListAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeUEInformationTransferIEValueProtocolIEContainerListAPERValueFieldWithoutReplay(v *UEInformationTransferIEValueProtocolIEContainerListAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeUEInformationTransferIEValueProtocolIEContainerListValueCodecFieldCapture(v *UEInformationTransferIEValueProtocolIEContainerListValueCodec) *func(UEInformationTransferIEValueProtocolIEContainerList, aper.DecodeState) (UEInformationTransferIEValueProtocolIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgeUEInformationTransferIEValueProtocolIEContainerListValueCodecFieldCompare(v *UEInformationTransferIEValueProtocolIEContainerListValueCodec) *func(UEInformationTransferIEValueProtocolIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeUEInformationTransferIEValueProtocolIEContainerListValueCodecFieldContext(v *UEInformationTransferIEValueProtocolIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeUEInformationTransferIEValueProtocolIEContainerListValueCodecFieldDecode(v *UEInformationTransferIEValueProtocolIEContainerListValueCodec) *func([]byte, aper.DecodeState) (UEInformationTransferIEValueProtocolIEContainerList, error) {
	return &v.decode
}
func BridgeUEInformationTransferIEValueProtocolIEContainerListValueCodecFieldEncode(v *UEInformationTransferIEValueProtocolIEContainerListValueCodec) *func(UEInformationTransferIEValueProtocolIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeUEInformationTransferIEValueProtocolIEContainerListValueCodecFieldPath(v *UEInformationTransferIEValueProtocolIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgeUEInformationTransferIEValueProtocolIEContainerListValueCodecMethodEncodeBudgetValue(v UEInformationTransferIEValueProtocolIEContainerListValueCodec, a0 UEInformationTransferIEValueProtocolIEContainerList, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeUEInformationTransferIEValueProtocolIEContainerListValueCodecMethodEncodeChanged(v UEInformationTransferIEValueProtocolIEContainerListValueCodec, a0 UEInformationTransferIEValueProtocolIEContainerList, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeUEInformationTransferMaskedIMEISVIEBindingFieldCodec(v *UEInformationTransferMaskedIMEISVIEBinding) *s01.MaskedIMEISVValueCodec {
	return &v.codec
}
func BridgeUEInformationTransferMaskedIMEISVIEBindingFieldGet(v *UEInformationTransferMaskedIMEISVIEBinding) *func(*UEInformationTransferIEValue) (*s00.MaskedIMEISV, bool) {
	return &v.get
}
func BridgeUEInformationTransferMaskedIMEISVIEBindingFieldInfo(v *UEInformationTransferMaskedIMEISVIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeUEInformationTransferMaskedIMEISVIEBindingFieldInject(v *UEInformationTransferMaskedIMEISVIEBinding) *func(s00.MaskedIMEISV) UEInformationTransferIEValue {
	return &v.inject
}
func BridgeUEInformationTransferPendingDataIndicationIEBindingFieldCodec(v *UEInformationTransferPendingDataIndicationIEBinding) *s01.PendingDataIndicationValueCodec {
	return &v.codec
}
func BridgeUEInformationTransferPendingDataIndicationIEBindingFieldGet(v *UEInformationTransferPendingDataIndicationIEBinding) *func(*UEInformationTransferIEValue) (*s00.PendingDataIndication, bool) {
	return &v.get
}
func BridgeUEInformationTransferPendingDataIndicationIEBindingFieldInfo(v *UEInformationTransferPendingDataIndicationIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeUEInformationTransferPendingDataIndicationIEBindingFieldInject(v *UEInformationTransferPendingDataIndicationIEBinding) *func(s00.PendingDataIndication) UEInformationTransferIEValue {
	return &v.inject
}
func BridgeUEInformationTransferSTMSIIEBindingFieldCodec(v *UEInformationTransferSTMSIIEBinding) *s28.STMSIValueCodec {
	return &v.codec
}
func BridgeUEInformationTransferSTMSIIEBindingFieldGet(v *UEInformationTransferSTMSIIEBinding) *func(*UEInformationTransferIEValue) (*s27.STMSI, bool) {
	return &v.get
}
func BridgeUEInformationTransferSTMSIIEBindingFieldInfo(v *UEInformationTransferSTMSIIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeUEInformationTransferSTMSIIEBindingFieldInject(v *UEInformationTransferSTMSIIEBinding) *func(s27.STMSI) UEInformationTransferIEValue {
	return &v.inject
}
func BridgeUEInformationTransferSubscriptionBasedUEDifferentiationInfoIEBindingFieldCodec(v *UEInformationTransferSubscriptionBasedUEDifferentiationInfoIEBinding) *SubscriptionBasedUEDifferentiationInfoValueCodec {
	return &v.codec
}
func BridgeUEInformationTransferSubscriptionBasedUEDifferentiationInfoIEBindingFieldGet(v *UEInformationTransferSubscriptionBasedUEDifferentiationInfoIEBinding) *func(*UEInformationTransferIEValue) (*s30.SubscriptionBasedUEDifferentiationInfo, bool) {
	return &v.get
}
func BridgeUEInformationTransferSubscriptionBasedUEDifferentiationInfoIEBindingFieldInfo(v *UEInformationTransferSubscriptionBasedUEDifferentiationInfoIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeUEInformationTransferSubscriptionBasedUEDifferentiationInfoIEBindingFieldInject(v *UEInformationTransferSubscriptionBasedUEDifferentiationInfoIEBinding) *func(s30.SubscriptionBasedUEDifferentiationInfo) UEInformationTransferIEValue {
	return &v.inject
}
func BridgeUEInformationTransferUERadioCapabilityIEBindingFieldCodec(v *UEInformationTransferUERadioCapabilityIEBinding) *s02.UERadioCapabilityValueCodec {
	return &v.codec
}
func BridgeUEInformationTransferUERadioCapabilityIEBindingFieldGet(v *UEInformationTransferUERadioCapabilityIEBinding) *func(*UEInformationTransferIEValue) (*s00.UERadioCapability, bool) {
	return &v.get
}
func BridgeUEInformationTransferUERadioCapabilityIEBindingFieldInfo(v *UEInformationTransferUERadioCapabilityIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeUEInformationTransferUERadioCapabilityIEBindingFieldInject(v *UEInformationTransferUERadioCapabilityIEBinding) *func(s00.UERadioCapability) UEInformationTransferIEValue {
	return &v.inject
}
