// Code generated from the pinned S1AP source closure. DO NOT EDIT.

// Package s28 implements the github.com/gomaja/go-asn1/telecom/lte/s1ap root package.
package s28

import (
	fmt "fmt"
	s00 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s00"
	s01 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s01"
	s02 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s02"
	s05 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s05"
	s06 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s06"
	s07 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s07"
	s11 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s11"
	s13 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s13"
	s14 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s14"
	s17 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s17"
	s21 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s21"
	s22 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s22"
	s25 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s25"
	s26 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s26"
	s27 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s27"
	runtime "github.com/gomaja/go-asn1/telecom/lte/s1ap/runtime"
	aper "github.com/gomaja/go-asn1/telecom/lte/s1ap/runtime/aper"
	big "math/big"
)

// ErrorIndicationIEContainer is the concrete ProtocolIEContainer[ErrorIndicationIEValue].
type ErrorIndicationIEContainer []ErrorIndicationIEField

// ErrorIndicationIEField is the concrete ProtocolIEField[ErrorIndicationIEValue].
type ErrorIndicationIEField struct {
	withoutReplay bool
	replay        aper.Snapshot
	stream        aper.WireSpan
	Id            s00.ProtocolIEID
	Criticality   s00.Criticality
	Value         ErrorIndicationIEValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ErrorIndicationIEField) WithoutReplay() ErrorIndicationIEField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *ErrorIndicationIEField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *ErrorIndicationIEField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
func (v *ErrorIndicationIEField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolIEField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = ErrorIndicationIEField{}
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
	var zero ErrorIndicationIEValue

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

// UEContextSuspendResponseIEContainer is the concrete ProtocolIEContainer[UEContextSuspendResponseIEValue].
type UEContextSuspendResponseIEContainer []UEContextSuspendResponseIEField

// UEContextSuspendResponseIEField is the concrete ProtocolIEField[UEContextSuspendResponseIEValue].
type UEContextSuspendResponseIEField struct {
	withoutReplay bool
	replay        aper.Snapshot
	stream        aper.WireSpan
	Id            s00.ProtocolIEID
	Criticality   s00.Criticality
	Value         UEContextSuspendResponseIEValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v UEContextSuspendResponseIEField) WithoutReplay() UEContextSuspendResponseIEField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *UEContextSuspendResponseIEField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *UEContextSuspendResponseIEField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
func (v *UEContextSuspendResponseIEField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolIEField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = UEContextSuspendResponseIEField{}
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
	var zero UEContextSuspendResponseIEValue

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

// RetrieveUEInformationIEContainer is the concrete ProtocolIEContainer[RetrieveUEInformationIEValue].
type RetrieveUEInformationIEContainer []RetrieveUEInformationIEField

// RetrieveUEInformationIEField is the concrete ProtocolIEField[RetrieveUEInformationIEValue].
type RetrieveUEInformationIEField struct {
	withoutReplay bool
	replay        aper.Snapshot
	stream        aper.WireSpan
	Id            s00.ProtocolIEID
	Criticality   s00.Criticality
	Value         RetrieveUEInformationIEValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v RetrieveUEInformationIEField) WithoutReplay() RetrieveUEInformationIEField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *RetrieveUEInformationIEField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *RetrieveUEInformationIEField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
func (v *RetrieveUEInformationIEField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolIEField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = RetrieveUEInformationIEField{}
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
	var zero RetrieveUEInformationIEValue

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
func BridgeErrorIndicationIEValueCaptureS1APProtocolIEContainer(v *ErrorIndicationIEContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeErrorIndicationIEValueCaptureS1APProtocolIEField(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeErrorIndicationIEValueCompareS1APProtocolIEContainer(v *ErrorIndicationIEContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeErrorIndicationIEValueCompareS1APProtocolIEField(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeRetrieveUEInformationIEValueCaptureS1APProtocolIEContainer(v *RetrieveUEInformationIEContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeRetrieveUEInformationIEValueCaptureS1APProtocolIEField(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeRetrieveUEInformationIEValueCompareS1APProtocolIEContainer(v *RetrieveUEInformationIEContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeRetrieveUEInformationIEValueCompareS1APProtocolIEField(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeScheduledCommunicationTimeExtIEsValueCaptureS1APProtocolExtensionContainer(v *s11.ScheduledCommunicationTimeExtIEsExtContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeScheduledCommunicationTimeExtIEsValueCaptureS1APProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeScheduledCommunicationTimeExtIEsValueCompareS1APProtocolExtensionContainer(v *s11.ScheduledCommunicationTimeExtIEsExtContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeScheduledCommunicationTimeExtIEsValueCompareS1APProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeSecondaryRATDataUsageReportItemExtIEsValueCaptureS1APProtocolExtensionContainer(v *s11.SecondaryRATDataUsageReportItemExtIEsExtContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeSecondaryRATDataUsageReportItemExtIEsValueCaptureS1APProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeSecondaryRATDataUsageReportItemExtIEsValueCompareS1APProtocolExtensionContainer(v *s11.SecondaryRATDataUsageReportItemExtIEsExtContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeSecondaryRATDataUsageReportItemExtIEsValueCompareS1APProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeSecondaryRATDataUsageReportItemIEValueCaptureS1APProtocolIESingleContainer(v *SecondaryRATDataUsageReportItemIEValueProtocolIESingleContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeSecondaryRATDataUsageReportItemIEValueCaptureS1APProtocolIEField(v, s)
	s.End(f, nil, false)
}
func BridgeSecondaryRATDataUsageReportItemIEValueCompareS1APProtocolIESingleContainer(v *SecondaryRATDataUsageReportItemIEValueProtocolIESingleContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeSecondaryRATDataUsageReportItemIEValueCompareS1APProtocolIEField(v, s)
	s.End(f, aper.Snapshot{}, false)
}
func BridgeSecurityContextExtIEsValueCaptureS1APProtocolExtensionContainer(v *s11.SecurityContextExtIEsExtContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeSecurityContextExtIEsValueCaptureS1APProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeSecurityContextExtIEsValueCompareS1APProtocolExtensionContainer(v *s11.SecurityContextExtIEsExtContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeSecurityContextExtIEsValueCompareS1APProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeSecurityIndicationExtIEsValueCaptureS1APProtocolExtensionContainer(v *s11.SecurityIndicationExtIEsExtContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeSecurityIndicationExtIEsValueCaptureS1APProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeSecurityIndicationExtIEsValueCompareS1APProtocolExtensionContainer(v *s11.SecurityIndicationExtIEsExtContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeSecurityIndicationExtIEsValueCompareS1APProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}

// ERABInformationListItemExtIEsExtContainer is the concrete ProtocolExtensionContainer[ERABInformationListItemExtIEsValue].
type ERABInformationListItemExtIEsExtContainer []ERABInformationListItemExtIEsExtField

// SecondaryRATDataUsageReportItemIEValueProtocolIESingleContainer is the concrete ProtocolIESingleContainer[SecondaryRATDataUsageReportItemIEValue].
type SecondaryRATDataUsageReportItemIEValueProtocolIESingleContainer = SecondaryRATDataUsageReportItemIEField

// ERABInformationListItemExtIEsExtField is the concrete ProtocolExtensionField[ERABInformationListItemExtIEsValue].
type ERABInformationListItemExtIEsExtField struct {
	withoutReplay  bool
	replay         aper.Snapshot
	stream         aper.WireSpan
	Id             s00.ProtocolExtensionID
	Criticality    s00.Criticality
	ExtensionValue ERABInformationListItemExtIEsValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ERABInformationListItemExtIEsExtField) WithoutReplay() ERABInformationListItemExtIEsExtField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *ERABInformationListItemExtIEsExtField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *ERABInformationListItemExtIEsExtField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
func (v *ERABInformationListItemExtIEsExtField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolExtensionField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = ERABInformationListItemExtIEsExtField{}
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
	var zero ERABInformationListItemExtIEsValue

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

// ERABToBeSetupItemBearerSUReqExtIEsExtContainer is the concrete ProtocolExtensionContainer[ERABToBeSetupItemBearerSUReqExtIEsValue].
type ERABToBeSetupItemBearerSUReqExtIEsExtContainer []ERABToBeSetupItemBearerSUReqExtIEsExtField

// ERABToBeSetupItemCtxtSUReqExtIEsExtContainer is the concrete ProtocolExtensionContainer[ERABToBeSetupItemCtxtSUReqExtIEsValue].
type ERABToBeSetupItemCtxtSUReqExtIEsExtContainer []ERABToBeSetupItemCtxtSUReqExtIEsExtField

// ERABToBeSetupItemBearerSUReqExtIEsExtField is the concrete ProtocolExtensionField[ERABToBeSetupItemBearerSUReqExtIEsValue].
type ERABToBeSetupItemBearerSUReqExtIEsExtField struct {
	withoutReplay  bool
	replay         aper.Snapshot
	stream         aper.WireSpan
	Id             s00.ProtocolExtensionID
	Criticality    s00.Criticality
	ExtensionValue ERABToBeSetupItemBearerSUReqExtIEsValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ERABToBeSetupItemBearerSUReqExtIEsExtField) WithoutReplay() ERABToBeSetupItemBearerSUReqExtIEsExtField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *ERABToBeSetupItemBearerSUReqExtIEsExtField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *ERABToBeSetupItemBearerSUReqExtIEsExtField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
func (v *ERABToBeSetupItemBearerSUReqExtIEsExtField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolExtensionField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = ERABToBeSetupItemBearerSUReqExtIEsExtField{}
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
	var zero ERABToBeSetupItemBearerSUReqExtIEsValue

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

// ERABToBeSetupItemCtxtSUReqExtIEsExtField is the concrete ProtocolExtensionField[ERABToBeSetupItemCtxtSUReqExtIEsValue].
type ERABToBeSetupItemCtxtSUReqExtIEsExtField struct {
	withoutReplay  bool
	replay         aper.Snapshot
	stream         aper.WireSpan
	Id             s00.ProtocolExtensionID
	Criticality    s00.Criticality
	ExtensionValue ERABToBeSetupItemCtxtSUReqExtIEsValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ERABToBeSetupItemCtxtSUReqExtIEsExtField) WithoutReplay() ERABToBeSetupItemCtxtSUReqExtIEsExtField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *ERABToBeSetupItemCtxtSUReqExtIEsExtField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *ERABToBeSetupItemCtxtSUReqExtIEsExtField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
func (v *ERABToBeSetupItemCtxtSUReqExtIEsExtField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolExtensionField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = ERABToBeSetupItemCtxtSUReqExtIEsExtField{}
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
	var zero ERABToBeSetupItemCtxtSUReqExtIEsValue

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

// ERABInformationListItemExtIEsDAPSRequestInfoExtBinding is the concrete ExtensionBinding[DAPSRequestInfo, ERABInformationListItemExtIEsValue].
type ERABInformationListItemExtIEsDAPSRequestInfoExtBinding struct {
	info   s00.ExtensionInfo
	codec  s14.DAPSRequestInfoValueCodec
	inject func(s14.DAPSRequestInfo,

	) ERABInformationListItemExtIEsValue

	get func(*ERABInformationListItemExtIEsValue,

	) (*s14.DAPSRequestInfo,

		bool)
}

// Info returns the source descriptor for this binding.
func (b ERABInformationListItemExtIEsDAPSRequestInfoExtBinding) Info() s00.ExtensionInfo {
	return b.info
}

// Codec returns the complete value codec for this binding.
func (b ERABInformationListItemExtIEsDAPSRequestInfoExtBinding) Codec() s14.DAPSRequestInfoValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b ERABInformationListItemExtIEsDAPSRequestInfoExtBinding) New(value s14.DAPSRequestInfo,

) (ERABInformationListItemExtIEsExtField, error) {
	if b.inject == nil {
		return ERABInformationListItemExtIEsExtField{}, aper.OperationError(fmt.Errorf("unbound extension binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ERABInformationListItemExtIEsExtField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s14.BridgeDAPSRequestInfoValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return ERABInformationListItemExtIEsExtField{}, aper.OperationError(fmt.Errorf("extension %d: %w", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return ERABInformationListItemExtIEsExtField{}, aper.OperationError(err, "Value.New")
	}
	return ERABInformationListItemExtIEsExtField{Id: b.info.ID, Criticality: b.info.Criticality, ExtensionValue: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b ERABInformationListItemExtIEsDAPSRequestInfoExtBinding) Get(field *ERABInformationListItemExtIEsExtField) (*s14.DAPSRequestInfo,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.ExtensionValue)
}

// ERABInformationListItemExtIEsTransportLayerAddressExtBinding is the concrete ExtensionBinding[TransportLayerAddress, ERABInformationListItemExtIEsValue].
type ERABInformationListItemExtIEsTransportLayerAddressExtBinding struct {
	info   s00.ExtensionInfo
	codec  s02.TransportLayerAddressValueCodec
	inject func(s00.TransportLayerAddress,

	) ERABInformationListItemExtIEsValue

	get func(*ERABInformationListItemExtIEsValue,

	) (*s00.TransportLayerAddress,

		bool)
}

// Info returns the source descriptor for this binding.
func (b ERABInformationListItemExtIEsTransportLayerAddressExtBinding) Info() s00.ExtensionInfo {
	return b.info
}

// Codec returns the complete value codec for this binding.
func (b ERABInformationListItemExtIEsTransportLayerAddressExtBinding) Codec() s02.TransportLayerAddressValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b ERABInformationListItemExtIEsTransportLayerAddressExtBinding) New(value s00.TransportLayerAddress,

) (ERABInformationListItemExtIEsExtField, error) {
	if b.inject == nil {
		return ERABInformationListItemExtIEsExtField{}, aper.OperationError(fmt.Errorf("unbound extension binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ERABInformationListItemExtIEsExtField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s02.BridgeTransportLayerAddressValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return ERABInformationListItemExtIEsExtField{}, aper.OperationError(fmt.Errorf("extension %d: %w", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return ERABInformationListItemExtIEsExtField{}, aper.OperationError(err, "Value.New")
	}
	return ERABInformationListItemExtIEsExtField{Id: b.info.ID, Criticality: b.info.Criticality, ExtensionValue: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b ERABInformationListItemExtIEsTransportLayerAddressExtBinding) Get(field *ERABInformationListItemExtIEsExtField) (*s00.TransportLayerAddress,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.ExtensionValue)
}

// SecondaryRATDataUsageReportItemSecondaryRATDataUsageReportItemIEBinding is the concrete IEBinding[SecondaryRATDataUsageReportItem, SecondaryRATDataUsageReportItemIEValue].
type SecondaryRATDataUsageReportItemSecondaryRATDataUsageReportItemIEBinding struct {
	info   s00.FieldInfo
	codec  SecondaryRATDataUsageReportItemValueCodec
	inject func(SecondaryRATDataUsageReportItem,

	) SecondaryRATDataUsageReportItemIEValue

	get func(*SecondaryRATDataUsageReportItemIEValue,

	) (*SecondaryRATDataUsageReportItem,

		bool)
}

// Info returns the source descriptor for this binding.
func (b SecondaryRATDataUsageReportItemSecondaryRATDataUsageReportItemIEBinding) Info() s00.FieldInfo {
	return b.info
}

// Codec returns the complete value codec for this binding.
func (b SecondaryRATDataUsageReportItemSecondaryRATDataUsageReportItemIEBinding) Codec() SecondaryRATDataUsageReportItemValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b SecondaryRATDataUsageReportItemSecondaryRATDataUsageReportItemIEBinding) New(value SecondaryRATDataUsageReportItem,

) (SecondaryRATDataUsageReportItemIEField, error) {
	if b.inject == nil {
		return SecondaryRATDataUsageReportItemIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return SecondaryRATDataUsageReportItemIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := b.codec.encode(value, false, budget); err != nil {
		return SecondaryRATDataUsageReportItemIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return SecondaryRATDataUsageReportItemIEField{}, aper.OperationError(err, "Value.New")
	}
	return SecondaryRATDataUsageReportItemIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b SecondaryRATDataUsageReportItemSecondaryRATDataUsageReportItemIEBinding) Get(field *SecondaryRATDataUsageReportItemIEField) (*SecondaryRATDataUsageReportItem,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// SecondaryRATDataUsageReportItemValueCodec is the concrete ValueCodec[SecondaryRATDataUsageReportItem].
type SecondaryRATDataUsageReportItemValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (SecondaryRATDataUsageReportItem,

		error)
	encode func(SecondaryRATDataUsageReportItem,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(SecondaryRATDataUsageReportItem, aper.DecodeState,

	) (SecondaryRATDataUsageReportItem, aper.Snapshot,

	)
	compare func(SecondaryRATDataUsageReportItem, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c SecondaryRATDataUsageReportItemValueCodec) New(value SecondaryRATDataUsageReportItem,

) (SecondaryRATDataUsageReportItemAPERValue, error) {
	if c.encode == nil {
		return SecondaryRATDataUsageReportItemAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return SecondaryRATDataUsageReportItemAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return SecondaryRATDataUsageReportItemAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return SecondaryRATDataUsageReportItemAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c SecondaryRATDataUsageReportItemValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (SecondaryRATDataUsageReportItemAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return SecondaryRATDataUsageReportItemAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return SecondaryRATDataUsageReportItemAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return SecondaryRATDataUsageReportItemAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return SecondaryRATDataUsageReportItemAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c SecondaryRATDataUsageReportItemValueCodec) EncodeAPER(value SecondaryRATDataUsageReportItemAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c SecondaryRATDataUsageReportItemValueCodec) encodeBudgetValue(value SecondaryRATDataUsageReportItem,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c SecondaryRATDataUsageReportItemValueCodec) encodeChanged(value SecondaryRATDataUsageReportItem,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// SecondaryRATDataUsageReportItemIEField is the concrete ProtocolIEField[SecondaryRATDataUsageReportItemIEValue].
type SecondaryRATDataUsageReportItemIEField struct {
	withoutReplay bool
	replay        aper.Snapshot
	stream        aper.WireSpan
	Id            s00.ProtocolIEID
	Criticality   s00.Criticality
	Value         SecondaryRATDataUsageReportItemIEValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v SecondaryRATDataUsageReportItemIEField) WithoutReplay() SecondaryRATDataUsageReportItemIEField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *SecondaryRATDataUsageReportItemIEField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *SecondaryRATDataUsageReportItemIEField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
func (v *SecondaryRATDataUsageReportItemIEField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolIEField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = SecondaryRATDataUsageReportItemIEField{}
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
	var zero SecondaryRATDataUsageReportItemIEValue

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

// SecondaryRATDataUsageReportListValueCodec is the concrete ValueCodec[SecondaryRATDataUsageReportList].
type SecondaryRATDataUsageReportListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (SecondaryRATDataUsageReportList,

		error)
	encode func(SecondaryRATDataUsageReportList,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(SecondaryRATDataUsageReportList, aper.DecodeState,

	) (SecondaryRATDataUsageReportList, aper.Snapshot,

	)
	compare func(SecondaryRATDataUsageReportList, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c SecondaryRATDataUsageReportListValueCodec) New(value SecondaryRATDataUsageReportList,

) (SecondaryRATDataUsageReportListAPERValue, error) {
	if c.encode == nil {
		return SecondaryRATDataUsageReportListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return SecondaryRATDataUsageReportListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return SecondaryRATDataUsageReportListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return SecondaryRATDataUsageReportListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c SecondaryRATDataUsageReportListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (SecondaryRATDataUsageReportListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return SecondaryRATDataUsageReportListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return SecondaryRATDataUsageReportListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return SecondaryRATDataUsageReportListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return SecondaryRATDataUsageReportListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c SecondaryRATDataUsageReportListValueCodec) EncodeAPER(value SecondaryRATDataUsageReportListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c SecondaryRATDataUsageReportListValueCodec) encodeBudgetValue(value SecondaryRATDataUsageReportList,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c SecondaryRATDataUsageReportListValueCodec) encodeChanged(value SecondaryRATDataUsageReportList,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ERABToBeSetupItemBearerSUReqExtIEsCorrelationIDExtBinding is the concrete ExtensionBinding[CorrelationID, ERABToBeSetupItemBearerSUReqExtIEsValue].
type ERABToBeSetupItemBearerSUReqExtIEsCorrelationIDExtBinding struct {
	info   s00.ExtensionInfo
	codec  s00.CorrelationIDValueCodec
	inject func(s00.CorrelationID,

	) ERABToBeSetupItemBearerSUReqExtIEsValue

	get func(*ERABToBeSetupItemBearerSUReqExtIEsValue,

	) (*s00.CorrelationID,

		bool)
}

// Info returns the source descriptor for this binding.
func (b ERABToBeSetupItemBearerSUReqExtIEsCorrelationIDExtBinding) Info() s00.ExtensionInfo {
	return b.info
}

// Codec returns the complete value codec for this binding.
func (b ERABToBeSetupItemBearerSUReqExtIEsCorrelationIDExtBinding) Codec() s00.CorrelationIDValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b ERABToBeSetupItemBearerSUReqExtIEsCorrelationIDExtBinding) New(value s00.CorrelationID,

) (ERABToBeSetupItemBearerSUReqExtIEsExtField, error) {
	if b.inject == nil {
		return ERABToBeSetupItemBearerSUReqExtIEsExtField{}, aper.OperationError(fmt.Errorf("unbound extension binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ERABToBeSetupItemBearerSUReqExtIEsExtField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s00.BridgeCorrelationIDValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return ERABToBeSetupItemBearerSUReqExtIEsExtField{}, aper.OperationError(fmt.Errorf("extension %d: %w", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return ERABToBeSetupItemBearerSUReqExtIEsExtField{}, aper.OperationError(err, "Value.New")
	}
	return ERABToBeSetupItemBearerSUReqExtIEsExtField{Id: b.info.ID, Criticality: b.info.Criticality, ExtensionValue: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b ERABToBeSetupItemBearerSUReqExtIEsCorrelationIDExtBinding) Get(field *ERABToBeSetupItemBearerSUReqExtIEsExtField) (*s00.CorrelationID,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.ExtensionValue)
}

// ERABToBeSetupItemBearerSUReqExtIEsBearerTypeExtBinding is the concrete ExtensionBinding[BearerType, ERABToBeSetupItemBearerSUReqExtIEsValue].
type ERABToBeSetupItemBearerSUReqExtIEsBearerTypeExtBinding struct {
	info   s00.ExtensionInfo
	codec  s00.BearerTypeValueCodec
	inject func(s00.BearerType,

	) ERABToBeSetupItemBearerSUReqExtIEsValue

	get func(*ERABToBeSetupItemBearerSUReqExtIEsValue,

	) (*s00.BearerType,

		bool)
}

// Info returns the source descriptor for this binding.
func (b ERABToBeSetupItemBearerSUReqExtIEsBearerTypeExtBinding) Info() s00.ExtensionInfo {
	return b.info
}

// Codec returns the complete value codec for this binding.
func (b ERABToBeSetupItemBearerSUReqExtIEsBearerTypeExtBinding) Codec() s00.BearerTypeValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b ERABToBeSetupItemBearerSUReqExtIEsBearerTypeExtBinding) New(value s00.BearerType,

) (ERABToBeSetupItemBearerSUReqExtIEsExtField, error) {
	if b.inject == nil {
		return ERABToBeSetupItemBearerSUReqExtIEsExtField{}, aper.OperationError(fmt.Errorf("unbound extension binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ERABToBeSetupItemBearerSUReqExtIEsExtField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s00.BridgeBearerTypeValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return ERABToBeSetupItemBearerSUReqExtIEsExtField{}, aper.OperationError(fmt.Errorf("extension %d: %w", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return ERABToBeSetupItemBearerSUReqExtIEsExtField{}, aper.OperationError(err, "Value.New")
	}
	return ERABToBeSetupItemBearerSUReqExtIEsExtField{Id: b.info.ID, Criticality: b.info.Criticality, ExtensionValue: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b ERABToBeSetupItemBearerSUReqExtIEsBearerTypeExtBinding) Get(field *ERABToBeSetupItemBearerSUReqExtIEsExtField) (*s00.BearerType,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.ExtensionValue)
}

// ERABToBeSetupItemBearerSUReqExtIEsEthernetTypeExtBinding is the concrete ExtensionBinding[EthernetType, ERABToBeSetupItemBearerSUReqExtIEsValue].
type ERABToBeSetupItemBearerSUReqExtIEsEthernetTypeExtBinding struct {
	info   s00.ExtensionInfo
	codec  s00.EthernetTypeValueCodec
	inject func(s00.EthernetType,

	) ERABToBeSetupItemBearerSUReqExtIEsValue

	get func(*ERABToBeSetupItemBearerSUReqExtIEsValue,

	) (*s00.EthernetType,

		bool)
}

// Info returns the source descriptor for this binding.
func (b ERABToBeSetupItemBearerSUReqExtIEsEthernetTypeExtBinding) Info() s00.ExtensionInfo {
	return b.info
}

// Codec returns the complete value codec for this binding.
func (b ERABToBeSetupItemBearerSUReqExtIEsEthernetTypeExtBinding) Codec() s00.EthernetTypeValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b ERABToBeSetupItemBearerSUReqExtIEsEthernetTypeExtBinding) New(value s00.EthernetType,

) (ERABToBeSetupItemBearerSUReqExtIEsExtField, error) {
	if b.inject == nil {
		return ERABToBeSetupItemBearerSUReqExtIEsExtField{}, aper.OperationError(fmt.Errorf("unbound extension binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ERABToBeSetupItemBearerSUReqExtIEsExtField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s00.BridgeEthernetTypeValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return ERABToBeSetupItemBearerSUReqExtIEsExtField{}, aper.OperationError(fmt.Errorf("extension %d: %w", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return ERABToBeSetupItemBearerSUReqExtIEsExtField{}, aper.OperationError(err, "Value.New")
	}
	return ERABToBeSetupItemBearerSUReqExtIEsExtField{Id: b.info.ID, Criticality: b.info.Criticality, ExtensionValue: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b ERABToBeSetupItemBearerSUReqExtIEsEthernetTypeExtBinding) Get(field *ERABToBeSetupItemBearerSUReqExtIEsExtField) (*s00.EthernetType,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.ExtensionValue)
}

// ERABToBeSetupItemCtxtSUReqExtIEsCorrelationIDExtBinding is the concrete ExtensionBinding[CorrelationID, ERABToBeSetupItemCtxtSUReqExtIEsValue].
type ERABToBeSetupItemCtxtSUReqExtIEsCorrelationIDExtBinding struct {
	info   s00.ExtensionInfo
	codec  s00.CorrelationIDValueCodec
	inject func(s00.CorrelationID,

	) ERABToBeSetupItemCtxtSUReqExtIEsValue

	get func(*ERABToBeSetupItemCtxtSUReqExtIEsValue,

	) (*s00.CorrelationID,

		bool)
}

// Info returns the source descriptor for this binding.
func (b ERABToBeSetupItemCtxtSUReqExtIEsCorrelationIDExtBinding) Info() s00.ExtensionInfo {
	return b.info
}

// Codec returns the complete value codec for this binding.
func (b ERABToBeSetupItemCtxtSUReqExtIEsCorrelationIDExtBinding) Codec() s00.CorrelationIDValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b ERABToBeSetupItemCtxtSUReqExtIEsCorrelationIDExtBinding) New(value s00.CorrelationID,

) (ERABToBeSetupItemCtxtSUReqExtIEsExtField, error) {
	if b.inject == nil {
		return ERABToBeSetupItemCtxtSUReqExtIEsExtField{}, aper.OperationError(fmt.Errorf("unbound extension binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ERABToBeSetupItemCtxtSUReqExtIEsExtField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s00.BridgeCorrelationIDValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return ERABToBeSetupItemCtxtSUReqExtIEsExtField{}, aper.OperationError(fmt.Errorf("extension %d: %w", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return ERABToBeSetupItemCtxtSUReqExtIEsExtField{}, aper.OperationError(err, "Value.New")
	}
	return ERABToBeSetupItemCtxtSUReqExtIEsExtField{Id: b.info.ID, Criticality: b.info.Criticality, ExtensionValue: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b ERABToBeSetupItemCtxtSUReqExtIEsCorrelationIDExtBinding) Get(field *ERABToBeSetupItemCtxtSUReqExtIEsExtField) (*s00.CorrelationID,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.ExtensionValue)
}

// ERABToBeSetupItemCtxtSUReqExtIEsBearerTypeExtBinding is the concrete ExtensionBinding[BearerType, ERABToBeSetupItemCtxtSUReqExtIEsValue].
type ERABToBeSetupItemCtxtSUReqExtIEsBearerTypeExtBinding struct {
	info   s00.ExtensionInfo
	codec  s00.BearerTypeValueCodec
	inject func(s00.BearerType,

	) ERABToBeSetupItemCtxtSUReqExtIEsValue

	get func(*ERABToBeSetupItemCtxtSUReqExtIEsValue,

	) (*s00.BearerType,

		bool)
}

// Info returns the source descriptor for this binding.
func (b ERABToBeSetupItemCtxtSUReqExtIEsBearerTypeExtBinding) Info() s00.ExtensionInfo {
	return b.info
}

// Codec returns the complete value codec for this binding.
func (b ERABToBeSetupItemCtxtSUReqExtIEsBearerTypeExtBinding) Codec() s00.BearerTypeValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b ERABToBeSetupItemCtxtSUReqExtIEsBearerTypeExtBinding) New(value s00.BearerType,

) (ERABToBeSetupItemCtxtSUReqExtIEsExtField, error) {
	if b.inject == nil {
		return ERABToBeSetupItemCtxtSUReqExtIEsExtField{}, aper.OperationError(fmt.Errorf("unbound extension binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ERABToBeSetupItemCtxtSUReqExtIEsExtField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s00.BridgeBearerTypeValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return ERABToBeSetupItemCtxtSUReqExtIEsExtField{}, aper.OperationError(fmt.Errorf("extension %d: %w", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return ERABToBeSetupItemCtxtSUReqExtIEsExtField{}, aper.OperationError(err, "Value.New")
	}
	return ERABToBeSetupItemCtxtSUReqExtIEsExtField{Id: b.info.ID, Criticality: b.info.Criticality, ExtensionValue: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b ERABToBeSetupItemCtxtSUReqExtIEsBearerTypeExtBinding) Get(field *ERABToBeSetupItemCtxtSUReqExtIEsExtField) (*s00.BearerType,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.ExtensionValue)
}

// ERABToBeSetupItemCtxtSUReqExtIEsEthernetTypeExtBinding is the concrete ExtensionBinding[EthernetType, ERABToBeSetupItemCtxtSUReqExtIEsValue].
type ERABToBeSetupItemCtxtSUReqExtIEsEthernetTypeExtBinding struct {
	info   s00.ExtensionInfo
	codec  s00.EthernetTypeValueCodec
	inject func(s00.EthernetType,

	) ERABToBeSetupItemCtxtSUReqExtIEsValue

	get func(*ERABToBeSetupItemCtxtSUReqExtIEsValue,

	) (*s00.EthernetType,

		bool)
}

// Info returns the source descriptor for this binding.
func (b ERABToBeSetupItemCtxtSUReqExtIEsEthernetTypeExtBinding) Info() s00.ExtensionInfo {
	return b.info
}

// Codec returns the complete value codec for this binding.
func (b ERABToBeSetupItemCtxtSUReqExtIEsEthernetTypeExtBinding) Codec() s00.EthernetTypeValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b ERABToBeSetupItemCtxtSUReqExtIEsEthernetTypeExtBinding) New(value s00.EthernetType,

) (ERABToBeSetupItemCtxtSUReqExtIEsExtField, error) {
	if b.inject == nil {
		return ERABToBeSetupItemCtxtSUReqExtIEsExtField{}, aper.OperationError(fmt.Errorf("unbound extension binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ERABToBeSetupItemCtxtSUReqExtIEsExtField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s00.BridgeEthernetTypeValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return ERABToBeSetupItemCtxtSUReqExtIEsExtField{}, aper.OperationError(fmt.Errorf("extension %d: %w", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return ERABToBeSetupItemCtxtSUReqExtIEsExtField{}, aper.OperationError(err, "Value.New")
	}
	return ERABToBeSetupItemCtxtSUReqExtIEsExtField{Id: b.info.ID, Criticality: b.info.Criticality, ExtensionValue: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b ERABToBeSetupItemCtxtSUReqExtIEsEthernetTypeExtBinding) Get(field *ERABToBeSetupItemCtxtSUReqExtIEsExtField) (*s00.EthernetType,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.ExtensionValue)
}

// STMSIValueCodec is the concrete ValueCodec[STMSI].
type STMSIValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (s27.STMSI,

		error)
	encode func(s27.STMSI,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(s27.STMSI, aper.DecodeState,

	) (s27.STMSI, aper.Snapshot,

	)
	compare func(s27.STMSI, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c STMSIValueCodec) New(value s27.STMSI,

) (STMSIAPERValue, error) {
	if c.encode == nil {
		return STMSIAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return STMSIAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return STMSIAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return STMSIAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c STMSIValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (STMSIAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return STMSIAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return STMSIAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return STMSIAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return STMSIAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c STMSIValueCodec) EncodeAPER(value STMSIAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c STMSIValueCodec) encodeBudgetValue(value s27.STMSI,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c STMSIValueCodec) encodeChanged(value s27.STMSI,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ErrorIndicationMMEUES1APIDIEBinding is the concrete IEBinding[MMEUES1APID, ErrorIndicationIEValue].
type ErrorIndicationMMEUES1APIDIEBinding struct {
	info   s00.FieldInfo
	codec  s01.MMEUES1APIDValueCodec
	inject func(s00.MMEUES1APID,

	) ErrorIndicationIEValue

	get func(*ErrorIndicationIEValue,

	) (*s00.MMEUES1APID,

		bool)
}

// Info returns the source descriptor for this binding.
func (b ErrorIndicationMMEUES1APIDIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b ErrorIndicationMMEUES1APIDIEBinding) Codec() s01.MMEUES1APIDValueCodec { return b.codec }

// New validates a source value and constructs its bound field.
func (b ErrorIndicationMMEUES1APIDIEBinding) New(value s00.MMEUES1APID,

) (ErrorIndicationIEField, error) {
	if b.inject == nil {
		return ErrorIndicationIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ErrorIndicationIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s01.BridgeMMEUES1APIDValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return ErrorIndicationIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return ErrorIndicationIEField{}, aper.OperationError(err, "Value.New")
	}
	return ErrorIndicationIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b ErrorIndicationMMEUES1APIDIEBinding) Get(field *ErrorIndicationIEField) (*s00.MMEUES1APID,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// ErrorIndicationENBUES1APIDIEBinding is the concrete IEBinding[ENBUES1APID, ErrorIndicationIEValue].
type ErrorIndicationENBUES1APIDIEBinding struct {
	info   s00.FieldInfo
	codec  s00.ENBUES1APIDValueCodec
	inject func(s00.ENBUES1APID,

	) ErrorIndicationIEValue

	get func(*ErrorIndicationIEValue,

	) (*s00.ENBUES1APID,

		bool)
}

// Info returns the source descriptor for this binding.
func (b ErrorIndicationENBUES1APIDIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b ErrorIndicationENBUES1APIDIEBinding) Codec() s00.ENBUES1APIDValueCodec { return b.codec }

// New validates a source value and constructs its bound field.
func (b ErrorIndicationENBUES1APIDIEBinding) New(value s00.ENBUES1APID,

) (ErrorIndicationIEField, error) {
	if b.inject == nil {
		return ErrorIndicationIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ErrorIndicationIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s00.BridgeENBUES1APIDValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return ErrorIndicationIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return ErrorIndicationIEField{}, aper.OperationError(err, "Value.New")
	}
	return ErrorIndicationIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b ErrorIndicationENBUES1APIDIEBinding) Get(field *ErrorIndicationIEField) (*s00.ENBUES1APID,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// ErrorIndicationCauseIEBinding is the concrete IEBinding[Cause, ErrorIndicationIEValue].
type ErrorIndicationCauseIEBinding struct {
	info   s00.FieldInfo
	codec  s14.CauseValueCodec
	inject func(s14.Cause,

	) ErrorIndicationIEValue

	get func(*ErrorIndicationIEValue,

	) (*s14.Cause,

		bool)
}

// Info returns the source descriptor for this binding.
func (b ErrorIndicationCauseIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b ErrorIndicationCauseIEBinding) Codec() s14.CauseValueCodec { return b.codec }

// New validates a source value and constructs its bound field.
func (b ErrorIndicationCauseIEBinding) New(value s14.Cause,

) (ErrorIndicationIEField, error) {
	if b.inject == nil {
		return ErrorIndicationIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ErrorIndicationIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s14.BridgeCauseValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return ErrorIndicationIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return ErrorIndicationIEField{}, aper.OperationError(err, "Value.New")
	}
	return ErrorIndicationIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b ErrorIndicationCauseIEBinding) Get(field *ErrorIndicationIEField) (*s14.Cause,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// ErrorIndicationCriticalityDiagnosticsIEBinding is the concrete IEBinding[CriticalityDiagnostics, ErrorIndicationIEValue].
type ErrorIndicationCriticalityDiagnosticsIEBinding struct {
	info   s00.FieldInfo
	codec  s22.CriticalityDiagnosticsValueCodec
	inject func(s22.CriticalityDiagnostics,

	) ErrorIndicationIEValue

	get func(*ErrorIndicationIEValue,

	) (*s22.CriticalityDiagnostics,

		bool)
}

// Info returns the source descriptor for this binding.
func (b ErrorIndicationCriticalityDiagnosticsIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b ErrorIndicationCriticalityDiagnosticsIEBinding) Codec() s22.CriticalityDiagnosticsValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b ErrorIndicationCriticalityDiagnosticsIEBinding) New(value s22.CriticalityDiagnostics,

) (ErrorIndicationIEField, error) {
	if b.inject == nil {
		return ErrorIndicationIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ErrorIndicationIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s22.BridgeCriticalityDiagnosticsValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return ErrorIndicationIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return ErrorIndicationIEField{}, aper.OperationError(err, "Value.New")
	}
	return ErrorIndicationIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b ErrorIndicationCriticalityDiagnosticsIEBinding) Get(field *ErrorIndicationIEField) (*s22.CriticalityDiagnostics,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// ErrorIndicationSTMSIIEBinding is the concrete IEBinding[STMSI, ErrorIndicationIEValue].
type ErrorIndicationSTMSIIEBinding struct {
	info   s00.FieldInfo
	codec  STMSIValueCodec
	inject func(s27.STMSI,

	) ErrorIndicationIEValue

	get func(*ErrorIndicationIEValue,

	) (*s27.STMSI,

		bool)
}

// Info returns the source descriptor for this binding.
func (b ErrorIndicationSTMSIIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b ErrorIndicationSTMSIIEBinding) Codec() STMSIValueCodec { return b.codec }

// New validates a source value and constructs its bound field.
func (b ErrorIndicationSTMSIIEBinding) New(value s27.STMSI,

) (ErrorIndicationIEField, error) {
	if b.inject == nil {
		return ErrorIndicationIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ErrorIndicationIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := b.codec.encode(value, false, budget); err != nil {
		return ErrorIndicationIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return ErrorIndicationIEField{}, aper.OperationError(err, "Value.New")
	}
	return ErrorIndicationIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b ErrorIndicationSTMSIIEBinding) Get(field *ErrorIndicationIEField) (*s27.STMSI,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// SecurityContextValueCodec is the concrete ValueCodec[SecurityContext].
type SecurityContextValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (SecurityContext,

		error)
	encode func(SecurityContext,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(SecurityContext, aper.DecodeState,

	) (SecurityContext, aper.Snapshot,

	)
	compare func(SecurityContext, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c SecurityContextValueCodec) New(value SecurityContext,

) (SecurityContextAPERValue, error) {
	if c.encode == nil {
		return SecurityContextAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return SecurityContextAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return SecurityContextAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return SecurityContextAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c SecurityContextValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (SecurityContextAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return SecurityContextAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return SecurityContextAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return SecurityContextAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return SecurityContextAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c SecurityContextValueCodec) EncodeAPER(value SecurityContextAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c SecurityContextValueCodec) encodeBudgetValue(value SecurityContext,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c SecurityContextValueCodec) encodeChanged(value SecurityContext,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// UEPagingIDValueCodec is the concrete ValueCodec[UEPagingID].
type UEPagingIDValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (UEPagingID,

		error)
	encode func(UEPagingID,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(UEPagingID, aper.DecodeState,

	) (UEPagingID, aper.Snapshot,

	)
	compare func(UEPagingID, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c UEPagingIDValueCodec) New(value UEPagingID,

) (UEPagingIDAPERValue, error) {
	if c.encode == nil {
		return UEPagingIDAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return UEPagingIDAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return UEPagingIDAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return UEPagingIDAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c UEPagingIDValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (UEPagingIDAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return UEPagingIDAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return UEPagingIDAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return UEPagingIDAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return UEPagingIDAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c UEPagingIDValueCodec) EncodeAPER(value UEPagingIDAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c UEPagingIDValueCodec) encodeBudgetValue(value UEPagingID,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c UEPagingIDValueCodec) encodeChanged(value UEPagingID,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// RetrieveUEInformationSTMSIIEBinding is the concrete IEBinding[STMSI, RetrieveUEInformationIEValue].
type RetrieveUEInformationSTMSIIEBinding struct {
	info   s00.FieldInfo
	codec  STMSIValueCodec
	inject func(s27.STMSI,

	) RetrieveUEInformationIEValue

	get func(*RetrieveUEInformationIEValue,

	) (*s27.STMSI,

		bool)
}

// Info returns the source descriptor for this binding.
func (b RetrieveUEInformationSTMSIIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b RetrieveUEInformationSTMSIIEBinding) Codec() STMSIValueCodec { return b.codec }

// New validates a source value and constructs its bound field.
func (b RetrieveUEInformationSTMSIIEBinding) New(value s27.STMSI,

) (RetrieveUEInformationIEField, error) {
	if b.inject == nil {
		return RetrieveUEInformationIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return RetrieveUEInformationIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := b.codec.encode(value, false, budget); err != nil {
		return RetrieveUEInformationIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return RetrieveUEInformationIEField{}, aper.OperationError(err, "Value.New")
	}
	return RetrieveUEInformationIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b RetrieveUEInformationSTMSIIEBinding) Get(field *RetrieveUEInformationIEField) (*s27.STMSI,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// UEContextSuspendResponseMMEUES1APIDIEBinding is the concrete IEBinding[MMEUES1APID, UEContextSuspendResponseIEValue].
type UEContextSuspendResponseMMEUES1APIDIEBinding struct {
	info   s00.FieldInfo
	codec  s01.MMEUES1APIDValueCodec
	inject func(s00.MMEUES1APID,

	) UEContextSuspendResponseIEValue

	get func(*UEContextSuspendResponseIEValue,

	) (*s00.MMEUES1APID,

		bool)
}

// Info returns the source descriptor for this binding.
func (b UEContextSuspendResponseMMEUES1APIDIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b UEContextSuspendResponseMMEUES1APIDIEBinding) Codec() s01.MMEUES1APIDValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b UEContextSuspendResponseMMEUES1APIDIEBinding) New(value s00.MMEUES1APID,

) (UEContextSuspendResponseIEField, error) {
	if b.inject == nil {
		return UEContextSuspendResponseIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return UEContextSuspendResponseIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s01.BridgeMMEUES1APIDValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return UEContextSuspendResponseIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return UEContextSuspendResponseIEField{}, aper.OperationError(err, "Value.New")
	}
	return UEContextSuspendResponseIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b UEContextSuspendResponseMMEUES1APIDIEBinding) Get(field *UEContextSuspendResponseIEField) (*s00.MMEUES1APID,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// UEContextSuspendResponseENBUES1APIDIEBinding is the concrete IEBinding[ENBUES1APID, UEContextSuspendResponseIEValue].
type UEContextSuspendResponseENBUES1APIDIEBinding struct {
	info   s00.FieldInfo
	codec  s00.ENBUES1APIDValueCodec
	inject func(s00.ENBUES1APID,

	) UEContextSuspendResponseIEValue

	get func(*UEContextSuspendResponseIEValue,

	) (*s00.ENBUES1APID,

		bool)
}

// Info returns the source descriptor for this binding.
func (b UEContextSuspendResponseENBUES1APIDIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b UEContextSuspendResponseENBUES1APIDIEBinding) Codec() s00.ENBUES1APIDValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b UEContextSuspendResponseENBUES1APIDIEBinding) New(value s00.ENBUES1APID,

) (UEContextSuspendResponseIEField, error) {
	if b.inject == nil {
		return UEContextSuspendResponseIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return UEContextSuspendResponseIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s00.BridgeENBUES1APIDValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return UEContextSuspendResponseIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return UEContextSuspendResponseIEField{}, aper.OperationError(err, "Value.New")
	}
	return UEContextSuspendResponseIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b UEContextSuspendResponseENBUES1APIDIEBinding) Get(field *UEContextSuspendResponseIEField) (*s00.ENBUES1APID,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// UEContextSuspendResponseCriticalityDiagnosticsIEBinding is the concrete IEBinding[CriticalityDiagnostics, UEContextSuspendResponseIEValue].
type UEContextSuspendResponseCriticalityDiagnosticsIEBinding struct {
	info   s00.FieldInfo
	codec  s22.CriticalityDiagnosticsValueCodec
	inject func(s22.CriticalityDiagnostics,

	) UEContextSuspendResponseIEValue

	get func(*UEContextSuspendResponseIEValue,

	) (*s22.CriticalityDiagnostics,

		bool)
}

// Info returns the source descriptor for this binding.
func (b UEContextSuspendResponseCriticalityDiagnosticsIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b UEContextSuspendResponseCriticalityDiagnosticsIEBinding) Codec() s22.CriticalityDiagnosticsValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b UEContextSuspendResponseCriticalityDiagnosticsIEBinding) New(value s22.CriticalityDiagnostics,

) (UEContextSuspendResponseIEField, error) {
	if b.inject == nil {
		return UEContextSuspendResponseIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return UEContextSuspendResponseIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s22.BridgeCriticalityDiagnosticsValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return UEContextSuspendResponseIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return UEContextSuspendResponseIEField{}, aper.OperationError(err, "Value.New")
	}
	return UEContextSuspendResponseIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b UEContextSuspendResponseCriticalityDiagnosticsIEBinding) Get(field *UEContextSuspendResponseIEField) (*s22.CriticalityDiagnostics,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// UEContextSuspendResponseSecurityContextIEBinding is the concrete IEBinding[SecurityContext, UEContextSuspendResponseIEValue].
type UEContextSuspendResponseSecurityContextIEBinding struct {
	info   s00.FieldInfo
	codec  SecurityContextValueCodec
	inject func(SecurityContext,

	) UEContextSuspendResponseIEValue

	get func(*UEContextSuspendResponseIEValue,

	) (*SecurityContext,

		bool)
}

// Info returns the source descriptor for this binding.
func (b UEContextSuspendResponseSecurityContextIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b UEContextSuspendResponseSecurityContextIEBinding) Codec() SecurityContextValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b UEContextSuspendResponseSecurityContextIEBinding) New(value SecurityContext,

) (UEContextSuspendResponseIEField, error) {
	if b.inject == nil {
		return UEContextSuspendResponseIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return UEContextSuspendResponseIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := b.codec.encode(value, false, budget); err != nil {
		return UEContextSuspendResponseIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return UEContextSuspendResponseIEField{}, aper.OperationError(err, "Value.New")
	}
	return UEContextSuspendResponseIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b UEContextSuspendResponseSecurityContextIEBinding) Get(field *UEContextSuspendResponseIEField) (*SecurityContext,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// ErrorIndicationValueCodec is the concrete ValueCodec[ErrorIndication].
type ErrorIndicationValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ErrorIndication,

		error)
	encode func(ErrorIndication,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ErrorIndication, aper.DecodeState,

	) (ErrorIndication, aper.Snapshot,

	)
	compare func(ErrorIndication, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ErrorIndicationValueCodec) New(value ErrorIndication,

) (ErrorIndicationAPERValue, error) {
	if c.encode == nil {
		return ErrorIndicationAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ErrorIndicationAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ErrorIndicationAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ErrorIndicationAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ErrorIndicationValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ErrorIndicationAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ErrorIndicationAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ErrorIndicationAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ErrorIndicationAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ErrorIndicationAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ErrorIndicationValueCodec) EncodeAPER(value ErrorIndicationAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c ErrorIndicationValueCodec) encodeBudgetValue(value ErrorIndication,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ErrorIndicationValueCodec) encodeChanged(value ErrorIndication,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// RetrieveUEInformationValueCodec is the concrete ValueCodec[RetrieveUEInformation].
type RetrieveUEInformationValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (RetrieveUEInformation,

		error)
	encode func(RetrieveUEInformation,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(RetrieveUEInformation, aper.DecodeState,

	) (RetrieveUEInformation, aper.Snapshot,

	)
	compare func(RetrieveUEInformation, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c RetrieveUEInformationValueCodec) New(value RetrieveUEInformation,

) (RetrieveUEInformationAPERValue, error) {
	if c.encode == nil {
		return RetrieveUEInformationAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return RetrieveUEInformationAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return RetrieveUEInformationAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return RetrieveUEInformationAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c RetrieveUEInformationValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (RetrieveUEInformationAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return RetrieveUEInformationAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return RetrieveUEInformationAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return RetrieveUEInformationAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return RetrieveUEInformationAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c RetrieveUEInformationValueCodec) EncodeAPER(value RetrieveUEInformationAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c RetrieveUEInformationValueCodec) encodeBudgetValue(value RetrieveUEInformation,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c RetrieveUEInformationValueCodec) encodeChanged(value RetrieveUEInformation,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ScheduledCommunicationTimeValueCodec is the concrete ValueCodec[ScheduledCommunicationTime].
type ScheduledCommunicationTimeValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ScheduledCommunicationTime,

		error)
	encode func(ScheduledCommunicationTime,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ScheduledCommunicationTime, aper.DecodeState,

	) (ScheduledCommunicationTime, aper.Snapshot,

	)
	compare func(ScheduledCommunicationTime, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ScheduledCommunicationTimeValueCodec) New(value ScheduledCommunicationTime,

) (ScheduledCommunicationTimeAPERValue, error) {
	if c.encode == nil {
		return ScheduledCommunicationTimeAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ScheduledCommunicationTimeAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ScheduledCommunicationTimeAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ScheduledCommunicationTimeAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ScheduledCommunicationTimeValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ScheduledCommunicationTimeAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ScheduledCommunicationTimeAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ScheduledCommunicationTimeAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ScheduledCommunicationTimeAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ScheduledCommunicationTimeAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ScheduledCommunicationTimeValueCodec) EncodeAPER(value ScheduledCommunicationTimeAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c ScheduledCommunicationTimeValueCodec) encodeBudgetValue(value ScheduledCommunicationTime,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ScheduledCommunicationTimeValueCodec) encodeChanged(value ScheduledCommunicationTime,

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
func BridgeErrorIndicationIEValueValidateS1APIEContainer(fields ErrorIndicationIEContainer, rows []s00.FieldInfo, path string, budget *aper.DecodeBudget,

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
func BridgeRetrieveUEInformationIEValueValidateS1APIEContainer(fields RetrieveUEInformationIEContainer, rows []s00.FieldInfo, path string, budget *aper.DecodeBudget,

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
func BridgeSTMSIExtIEsValueValidateS1APExtensionContainer(fields s11.STMSIExtIEsExtContainer, rows []s00.FieldInfo, path string, budget *aper.DecodeBudget) s21.ValidationReport {
	bb := aper.NewBudgetBuffer(budget)
	if err := aper.ChargeSlice[s11.STMSIExtIEsIEField](bb, uint64(len(fields))); err != nil {
		return func() s21.ValidationReport {
			sealed := s21.ValidationReport{}
			*s21.BridgeValidationReportFieldErr(&sealed) = err
			*s21.BridgeValidationReportFieldBudget(&sealed) = budget
			return sealed
		}()
	}
	asIE := make(s11.STMSIExtIEsIEContainer, len(fields))
	for i := range fields {
		asIE[i].Id = fields[i].Id
		asIE[i].Criticality = fields[i].Criticality
		asIE[i].Value = fields[i].ExtensionValue
	}
	return BridgeSTMSIExtIEsValueValidateS1APIEContainer(asIE, rows, path, budget)
}
func BridgeScheduledCommunicationTimeExtIEsValueValidateS1APExtensionContainer(fields s11.ScheduledCommunicationTimeExtIEsExtContainer, rows []s00.FieldInfo, path string, budget *aper.DecodeBudget) s21.ValidationReport {
	bb := aper.NewBudgetBuffer(budget)
	if err := aper.ChargeSlice[s11.ScheduledCommunicationTimeExtIEsIEField](bb, uint64(len(fields))); err != nil {
		return func() s21.ValidationReport {
			sealed := s21.ValidationReport{}
			*s21.BridgeValidationReportFieldErr(&sealed) = err
			*s21.BridgeValidationReportFieldBudget(&sealed) = budget
			return sealed
		}()
	}
	asIE := make(s11.ScheduledCommunicationTimeExtIEsIEContainer, len(fields))
	for i := range fields {
		asIE[i].Id = fields[i].Id
		asIE[i].Criticality = fields[i].Criticality
		asIE[i].Value = fields[i].ExtensionValue
	}
	return BridgeScheduledCommunicationTimeExtIEsValueValidateS1APIEContainer(asIE, rows, path, budget)
}
func BridgeSecondaryRATDataUsageReportItemExtIEsValueValidateS1APExtensionContainer(fields s11.SecondaryRATDataUsageReportItemExtIEsExtContainer, rows []s00.FieldInfo, path string, budget *aper.DecodeBudget) s21.ValidationReport {
	bb := aper.NewBudgetBuffer(budget)
	if err := aper.ChargeSlice[s11.SecondaryRATDataUsageReportItemExtIEsIEField](bb, uint64(len(fields))); err != nil {
		return func() s21.ValidationReport {
			sealed := s21.ValidationReport{}
			*s21.BridgeValidationReportFieldErr(&sealed) = err
			*s21.BridgeValidationReportFieldBudget(&sealed) = budget
			return sealed
		}()
	}
	asIE := make(s11.SecondaryRATDataUsageReportItemExtIEsIEContainer, len(fields))
	for i := range fields {
		asIE[i].Id = fields[i].Id
		asIE[i].Criticality = fields[i].Criticality
		asIE[i].Value = fields[i].ExtensionValue
	}
	return BridgeSecondaryRATDataUsageReportItemExtIEsValueValidateS1APIEContainer(asIE, rows, path, budget)
}

// TS 36.413 V19.2.0 §§9.3.3–9.3.4 supply the selected object-set order and
// presence. §§10.3.1–10.3.6 define abstract-syntax diagnostics. Unknown IEs do
// not determine the order of known rows.
func BridgeSecondaryRATDataUsageReportItemIEValueValidateS1APIEContainer(fields SecondaryRATDataUsageReportItemIEContainer, rows []s00.FieldInfo, path string, budget *aper.DecodeBudget,

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

// SecondaryRATDataUsageReportItemIEContainer is the concrete ProtocolIEContainer[SecondaryRATDataUsageReportItemIEValue].
type SecondaryRATDataUsageReportItemIEContainer []SecondaryRATDataUsageReportItemIEField

func BridgeSecurityContextExtIEsValueValidateS1APExtensionContainer(fields s11.SecurityContextExtIEsExtContainer, rows []s00.FieldInfo, path string, budget *aper.DecodeBudget) s21.ValidationReport {
	bb := aper.NewBudgetBuffer(budget)
	if err := aper.ChargeSlice[s11.SecurityContextExtIEsIEField](bb, uint64(len(fields))); err != nil {
		return func() s21.ValidationReport {
			sealed := s21.ValidationReport{}
			*s21.BridgeValidationReportFieldErr(&sealed) = err
			*s21.BridgeValidationReportFieldBudget(&sealed) = budget
			return sealed
		}()
	}
	asIE := make(s11.SecurityContextExtIEsIEContainer, len(fields))
	for i := range fields {
		asIE[i].Id = fields[i].Id
		asIE[i].Criticality = fields[i].Criticality
		asIE[i].Value = fields[i].ExtensionValue
	}
	return BridgeSecurityContextExtIEsValueValidateS1APIEContainer(asIE, rows, path, budget)
}
func ErrorIndicationIEValueERABIEContainerListCodec(table s00.ErrorIndicationIEValueIETable) ErrorIndicationIEValueERABIEContainerListValueCodec {
	codec := ErrorIndicationIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if codec.decode == nil {
		return ErrorIndicationIEValueERABIEContainerListValueCodec{}
	}
	return ErrorIndicationIEValueERABIEContainerListValueCodec{decode: func(data []byte, options aper.DecodeState) (ErrorIndicationIEValueERABIEContainerList, error) {
		value, err := codec.decode(data, options)
		return ErrorIndicationIEValueERABIEContainerList(value), err
	}, encode: func(value ErrorIndicationIEValueERABIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return codec.encode(ErrorIndicationIEContainer(value), fresh, budget)
	}, capture: func(v ErrorIndicationIEValueERABIEContainerList, options aper.DecodeState) (ErrorIndicationIEValueERABIEContainerList, aper.Snapshot) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeErrorIndicationIEValueCaptureS1APERABIEContainerList(&v, &s)
		var root aper.Snapshot
		s.End(f, &root, false)
		return v, root
	}, compare: func(v ErrorIndicationIEValueERABIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
	) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		BridgeErrorIndicationIEValueCompareS1APERABIEContainerList(&v, &s)
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
func RetrieveUEInformationIEValueERABIEContainerListCodec(table s00.RetrieveUEInformationIEValueIETable) RetrieveUEInformationIEValueERABIEContainerListValueCodec {
	codec := RetrieveUEInformationIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if codec.decode == nil {
		return RetrieveUEInformationIEValueERABIEContainerListValueCodec{}
	}
	return RetrieveUEInformationIEValueERABIEContainerListValueCodec{decode: func(data []byte, options aper.DecodeState) (RetrieveUEInformationIEValueERABIEContainerList, error) {
		value, err := codec.decode(data, options)
		return RetrieveUEInformationIEValueERABIEContainerList(value), err
	}, encode: func(value RetrieveUEInformationIEValueERABIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return codec.encode(RetrieveUEInformationIEContainer(value), fresh, budget)
	}, capture: func(v RetrieveUEInformationIEValueERABIEContainerList, options aper.DecodeState) (RetrieveUEInformationIEValueERABIEContainerList, aper.Snapshot) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeRetrieveUEInformationIEValueCaptureS1APERABIEContainerList(&v, &s)
		var root aper.Snapshot
		s.End(f, &root, false)
		return v, root
	}, compare: func(v RetrieveUEInformationIEValueERABIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
	) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		BridgeRetrieveUEInformationIEValueCompareS1APERABIEContainerList(&v, &s)
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
func SecondaryRATDataUsageReportItemIEValueERABIEContainerListCodec(table s00.SecondaryRATDataUsageReportItemIEValueIETable) SecondaryRATDataUsageReportItemIEValueERABIEContainerListValueCodec {
	codec := SecondaryRATDataUsageReportItemIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if codec.decode == nil {
		return SecondaryRATDataUsageReportItemIEValueERABIEContainerListValueCodec{}
	}
	return SecondaryRATDataUsageReportItemIEValueERABIEContainerListValueCodec{decode: func(data []byte, options aper.DecodeState) (SecondaryRATDataUsageReportItemIEValueERABIEContainerList, error) {
		value, err := codec.decode(data, options)
		return SecondaryRATDataUsageReportItemIEValueERABIEContainerList(value), err
	}, encode: func(value SecondaryRATDataUsageReportItemIEValueERABIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return codec.encode(SecondaryRATDataUsageReportItemIEContainer(value), fresh, budget)
	}, capture: func(v SecondaryRATDataUsageReportItemIEValueERABIEContainerList, options aper.DecodeState) (SecondaryRATDataUsageReportItemIEValueERABIEContainerList, aper.Snapshot) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeSecondaryRATDataUsageReportItemIEValueCaptureS1APERABIEContainerList(&v, &s)
		var root aper.Snapshot
		s.End(f, &root, false)
		return v, root
	}, compare: func(v SecondaryRATDataUsageReportItemIEValueERABIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
	) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		BridgeSecondaryRATDataUsageReportItemIEValueCompareS1APERABIEContainerList(&v, &s)
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
func ScheduledCommunicationTimeExtIEsValueExtensionFieldTableCodec(table s00.ScheduledCommunicationTimeExtIEsValueExtensionTable) s11.ScheduledCommunicationTimeExtIEsExtFieldValueCodec {
	if !*s00.BridgeScheduledCommunicationTimeExtIEsValueExtensionTableFieldBound(&table) {
		return s11.ScheduledCommunicationTimeExtIEsExtFieldValueCodec{}
	}
	return func() s11.ScheduledCommunicationTimeExtIEsExtFieldValueCodec {
		sealed := s11.ScheduledCommunicationTimeExtIEsExtFieldValueCodec{}
		*s11.BridgeScheduledCommunicationTimeExtIEsExtFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s11.ScheduledCommunicationTimeExtIEsExtField, error) {
			var field s11.ScheduledCommunicationTimeExtIEsExtField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s11.BridgeScheduledCommunicationTimeExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, err
			}
			if _, err := aper.CaptureFinalBits(bb, "ProtocolExtensionField"); err != nil {
				return field, err
			}
			return field, nil
		}
		*s11.BridgeScheduledCommunicationTimeExtIEsExtFieldValueCodecFieldEncode(&sealed) = func(field s11.ScheduledCommunicationTimeExtIEsExtField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s11.BridgeScheduledCommunicationTimeExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s11.BridgeScheduledCommunicationTimeExtIEsExtFieldValueCodecFieldCapture(&sealed) = func(v s11.ScheduledCommunicationTimeExtIEsExtField, options aper.DecodeState) (s11.ScheduledCommunicationTimeExtIEsExtField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeScheduledCommunicationTimeExtIEsValueCaptureS1APProtocolExtensionField(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,
				false)
			return v, root
		}
		*s11.BridgeScheduledCommunicationTimeExtIEsExtFieldValueCodecFieldCompare(&sealed) = func(v s11.ScheduledCommunicationTimeExtIEsExtField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeScheduledCommunicationTimeExtIEsValueCompareS1APProtocolExtensionField(&v, &s)
			s.End(f, root,

				false)
			return s.Plan(), s.BudgetValue()
		}
		*s11.BridgeScheduledCommunicationTimeExtIEsExtFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}
func SecondaryRATDataUsageReportItemExtIEsValueExtensionFieldTableCodec(table s00.SecondaryRATDataUsageReportItemExtIEsValueExtensionTable) s11.SecondaryRATDataUsageReportItemExtIEsExtFieldValueCodec {
	if !*s00.BridgeSecondaryRATDataUsageReportItemExtIEsValueExtensionTableFieldBound(&table) {
		return s11.SecondaryRATDataUsageReportItemExtIEsExtFieldValueCodec{}
	}
	return func() s11.SecondaryRATDataUsageReportItemExtIEsExtFieldValueCodec {
		sealed := s11.SecondaryRATDataUsageReportItemExtIEsExtFieldValueCodec{}
		*s11.BridgeSecondaryRATDataUsageReportItemExtIEsExtFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s11.SecondaryRATDataUsageReportItemExtIEsExtField, error) {
			var field s11.SecondaryRATDataUsageReportItemExtIEsExtField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s11.BridgeSecondaryRATDataUsageReportItemExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, err
			}
			if _, err := aper.CaptureFinalBits(bb, "ProtocolExtensionField"); err != nil {
				return field, err
			}
			return field, nil
		}
		*s11.BridgeSecondaryRATDataUsageReportItemExtIEsExtFieldValueCodecFieldEncode(&sealed) = func(field s11.SecondaryRATDataUsageReportItemExtIEsExtField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s11.BridgeSecondaryRATDataUsageReportItemExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s11.BridgeSecondaryRATDataUsageReportItemExtIEsExtFieldValueCodecFieldCapture(&sealed) = func(v s11.SecondaryRATDataUsageReportItemExtIEsExtField, options aper.DecodeState) (s11.SecondaryRATDataUsageReportItemExtIEsExtField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeSecondaryRATDataUsageReportItemExtIEsValueCaptureS1APProtocolExtensionField(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,
				false)
			return v, root
		}
		*s11.BridgeSecondaryRATDataUsageReportItemExtIEsExtFieldValueCodecFieldCompare(&sealed) = func(v s11.SecondaryRATDataUsageReportItemExtIEsExtField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeSecondaryRATDataUsageReportItemExtIEsValueCompareS1APProtocolExtensionField(&v, &s)
			s.End(f, root,

				false)
			return s.Plan(), s.BudgetValue()
		}
		*s11.BridgeSecondaryRATDataUsageReportItemExtIEsExtFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}
func SecurityContextExtIEsValueExtensionFieldTableCodec(table s00.SecurityContextExtIEsValueExtensionTable) s11.SecurityContextExtIEsExtFieldValueCodec {
	if !*s00.BridgeSecurityContextExtIEsValueExtensionTableFieldBound(&table) {
		return s11.SecurityContextExtIEsExtFieldValueCodec{}
	}
	return func() s11.SecurityContextExtIEsExtFieldValueCodec {
		sealed := s11.SecurityContextExtIEsExtFieldValueCodec{}
		*s11.BridgeSecurityContextExtIEsExtFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s11.SecurityContextExtIEsExtField, error) {
			var field s11.SecurityContextExtIEsExtField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s11.BridgeSecurityContextExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, err
			}
			if _, err := aper.CaptureFinalBits(bb, "ProtocolExtensionField"); err != nil {
				return field, err
			}
			return field, nil
		}
		*s11.BridgeSecurityContextExtIEsExtFieldValueCodecFieldEncode(&sealed) = func(field s11.SecurityContextExtIEsExtField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s11.BridgeSecurityContextExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s11.BridgeSecurityContextExtIEsExtFieldValueCodecFieldCapture(&sealed) = func(v s11.SecurityContextExtIEsExtField, options aper.DecodeState) (s11.SecurityContextExtIEsExtField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeSecurityContextExtIEsValueCaptureS1APProtocolExtensionField(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,
				false)
			return v, root
		}
		*s11.BridgeSecurityContextExtIEsExtFieldValueCodecFieldCompare(&sealed) = func(v s11.SecurityContextExtIEsExtField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeSecurityContextExtIEsValueCompareS1APProtocolExtensionField(&v, &s)
			s.End(f, root,

				false)
			return s.Plan(), s.BudgetValue()
		}
		*s11.BridgeSecurityContextExtIEsExtFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}
func SecurityIndicationExtIEsValueExtensionFieldTableCodec(table s00.SecurityIndicationExtIEsValueExtensionTable) s11.SecurityIndicationExtIEsExtFieldValueCodec {
	if !*s00.BridgeSecurityIndicationExtIEsValueExtensionTableFieldBound(&table) {
		return s11.SecurityIndicationExtIEsExtFieldValueCodec{}
	}
	return func() s11.SecurityIndicationExtIEsExtFieldValueCodec {
		sealed := s11.SecurityIndicationExtIEsExtFieldValueCodec{}
		*s11.BridgeSecurityIndicationExtIEsExtFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s11.SecurityIndicationExtIEsExtField, error) {
			var field s11.SecurityIndicationExtIEsExtField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s11.BridgeSecurityIndicationExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, err
			}
			if _, err := aper.CaptureFinalBits(bb, "ProtocolExtensionField"); err != nil {
				return field, err
			}
			return field, nil
		}
		*s11.BridgeSecurityIndicationExtIEsExtFieldValueCodecFieldEncode(&sealed) = func(field s11.SecurityIndicationExtIEsExtField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s11.BridgeSecurityIndicationExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s11.BridgeSecurityIndicationExtIEsExtFieldValueCodecFieldCapture(&sealed) = func(v s11.SecurityIndicationExtIEsExtField, options aper.DecodeState) (s11.SecurityIndicationExtIEsExtField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeSecurityIndicationExtIEsValueCaptureS1APProtocolExtensionField(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,
				false)
			return v, root
		}
		*s11.BridgeSecurityIndicationExtIEsExtFieldValueCodecFieldCompare(&sealed) = func(v s11.SecurityIndicationExtIEsExtField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeSecurityIndicationExtIEsValueCompareS1APProtocolExtensionField(&v, &s)
			s.End(f, root,

				false)
			return s.Plan(), s.BudgetValue()
		}
		*s11.BridgeSecurityIndicationExtIEsExtFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}
func STMSIExtIEsValueExtensionTableCodec(table s00.STMSIExtIEsValueExtensionTable, bounds aper.ListBounds) s11.STMSIExtIEsExtContainerValueCodec {
	if !*s00.BridgeSTMSIExtIEsValueExtensionTableFieldBound(&table) {
		return s11.STMSIExtIEsExtContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s11.STMSIExtIEsExtContainerValueCodec {
		sealed := s11.STMSIExtIEsExtContainerValueCodec{}
		*s11.BridgeSTMSIExtIEsExtContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s11.STMSIExtIEsExtContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s11.STMSIExtIEsExtContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s11.STMSIExtIEsExtField
					if err := s11.BridgeSTMSIExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
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
		*s11.BridgeSTMSIExtIEsExtContainerValueCodecFieldEncode(&sealed) = func(fields s11.STMSIExtIEsExtContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s11.BridgeSTMSIExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
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
		*s11.BridgeSTMSIExtIEsExtContainerValueCodecFieldCapture(&sealed) = func(v s11.STMSIExtIEsExtContainer, options aper.DecodeState) (s11.STMSIExtIEsExtContainer, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s27.BridgeSTMSIExtIEsValueCaptureS1APProtocolExtensionContainer(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s11.BridgeSTMSIExtIEsExtContainerValueCodecFieldCompare(&sealed) = func(v s11.STMSIExtIEsExtContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.
				Begin()
			s27.BridgeSTMSIExtIEsValueCompareS1APProtocolExtensionContainer(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s11.BridgeSTMSIExtIEsExtContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}
func ScheduledCommunicationTimeExtIEsValueExtensionTableCodec(table s00.ScheduledCommunicationTimeExtIEsValueExtensionTable, bounds aper.ListBounds) s11.ScheduledCommunicationTimeExtIEsExtContainerValueCodec {
	if !*s00.BridgeScheduledCommunicationTimeExtIEsValueExtensionTableFieldBound(&table) {
		return s11.ScheduledCommunicationTimeExtIEsExtContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s11.ScheduledCommunicationTimeExtIEsExtContainerValueCodec {
		sealed := s11.ScheduledCommunicationTimeExtIEsExtContainerValueCodec{}
		*s11.BridgeScheduledCommunicationTimeExtIEsExtContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s11.ScheduledCommunicationTimeExtIEsExtContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s11.ScheduledCommunicationTimeExtIEsExtContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s11.ScheduledCommunicationTimeExtIEsExtField
					if err := s11.BridgeScheduledCommunicationTimeExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
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
		*s11.BridgeScheduledCommunicationTimeExtIEsExtContainerValueCodecFieldEncode(&sealed) = func(fields s11.ScheduledCommunicationTimeExtIEsExtContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s11.BridgeScheduledCommunicationTimeExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
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
		*s11.BridgeScheduledCommunicationTimeExtIEsExtContainerValueCodecFieldCapture(&sealed) = func(v s11.ScheduledCommunicationTimeExtIEsExtContainer, options aper.DecodeState) (s11.ScheduledCommunicationTimeExtIEsExtContainer, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeScheduledCommunicationTimeExtIEsValueCaptureS1APProtocolExtensionContainer(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s11.BridgeScheduledCommunicationTimeExtIEsExtContainerValueCodecFieldCompare(&sealed) = func(v s11.ScheduledCommunicationTimeExtIEsExtContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.
				Begin()
			BridgeScheduledCommunicationTimeExtIEsValueCompareS1APProtocolExtensionContainer(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s11.BridgeScheduledCommunicationTimeExtIEsExtContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}
func SecondaryRATDataUsageReportItemExtIEsValueExtensionTableCodec(table s00.SecondaryRATDataUsageReportItemExtIEsValueExtensionTable, bounds aper.ListBounds) s11.SecondaryRATDataUsageReportItemExtIEsExtContainerValueCodec {
	if !*s00.BridgeSecondaryRATDataUsageReportItemExtIEsValueExtensionTableFieldBound(&table) {
		return s11.SecondaryRATDataUsageReportItemExtIEsExtContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s11.SecondaryRATDataUsageReportItemExtIEsExtContainerValueCodec {
		sealed := s11.SecondaryRATDataUsageReportItemExtIEsExtContainerValueCodec{}
		*s11.BridgeSecondaryRATDataUsageReportItemExtIEsExtContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s11.SecondaryRATDataUsageReportItemExtIEsExtContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s11.SecondaryRATDataUsageReportItemExtIEsExtContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s11.SecondaryRATDataUsageReportItemExtIEsExtField
					if err := s11.BridgeSecondaryRATDataUsageReportItemExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
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
		*s11.BridgeSecondaryRATDataUsageReportItemExtIEsExtContainerValueCodecFieldEncode(&sealed) = func(fields s11.SecondaryRATDataUsageReportItemExtIEsExtContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s11.BridgeSecondaryRATDataUsageReportItemExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
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
		*s11.BridgeSecondaryRATDataUsageReportItemExtIEsExtContainerValueCodecFieldCapture(&sealed) = func(v s11.SecondaryRATDataUsageReportItemExtIEsExtContainer, options aper.DecodeState) (s11.SecondaryRATDataUsageReportItemExtIEsExtContainer, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeSecondaryRATDataUsageReportItemExtIEsValueCaptureS1APProtocolExtensionContainer(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s11.BridgeSecondaryRATDataUsageReportItemExtIEsExtContainerValueCodecFieldCompare(&sealed) = func(v s11.SecondaryRATDataUsageReportItemExtIEsExtContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.
				Begin()
			BridgeSecondaryRATDataUsageReportItemExtIEsValueCompareS1APProtocolExtensionContainer(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s11.BridgeSecondaryRATDataUsageReportItemExtIEsExtContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}
func SecurityContextExtIEsValueExtensionTableCodec(table s00.SecurityContextExtIEsValueExtensionTable, bounds aper.ListBounds) s11.SecurityContextExtIEsExtContainerValueCodec {
	if !*s00.BridgeSecurityContextExtIEsValueExtensionTableFieldBound(&table) {
		return s11.SecurityContextExtIEsExtContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s11.SecurityContextExtIEsExtContainerValueCodec {
		sealed := s11.SecurityContextExtIEsExtContainerValueCodec{}
		*s11.BridgeSecurityContextExtIEsExtContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s11.SecurityContextExtIEsExtContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s11.SecurityContextExtIEsExtContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s11.SecurityContextExtIEsExtField
					if err := s11.BridgeSecurityContextExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
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
		*s11.BridgeSecurityContextExtIEsExtContainerValueCodecFieldEncode(&sealed) = func(fields s11.SecurityContextExtIEsExtContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s11.BridgeSecurityContextExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
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
		*s11.BridgeSecurityContextExtIEsExtContainerValueCodecFieldCapture(&sealed) = func(v s11.SecurityContextExtIEsExtContainer, options aper.DecodeState) (s11.SecurityContextExtIEsExtContainer, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeSecurityContextExtIEsValueCaptureS1APProtocolExtensionContainer(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s11.BridgeSecurityContextExtIEsExtContainerValueCodecFieldCompare(&sealed) = func(v s11.SecurityContextExtIEsExtContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.
				Begin()
			BridgeSecurityContextExtIEsValueCompareS1APProtocolExtensionContainer(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s11.BridgeSecurityContextExtIEsExtContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}
func ErrorIndicationIEValueIEFieldTableCodec(table s00.ErrorIndicationIEValueIETable) ErrorIndicationIEFieldValueCodec {
	if !*s00.BridgeErrorIndicationIEValueIETableFieldBound(&table) {
		return ErrorIndicationIEFieldValueCodec{}
	}
	return ErrorIndicationIEFieldValueCodec{decode: func(data []byte, options aper.DecodeState) (ErrorIndicationIEField, error) {
		var field ErrorIndicationIEField
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
	}, encode: func(field ErrorIndicationIEField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		bb := aper.NewBudgetBuffer(budget)
		if err := field.marshalAPERTo(bb, fresh); err != nil {
			return nil, err
		}
		return bb.CompleteBytes(), nil
	}, capture: func(v ErrorIndicationIEField, options aper.DecodeState) (ErrorIndicationIEField, aper.Snapshot,
	) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeErrorIndicationIEValueCaptureS1APProtocolIEField(&v,
			&s)
		var root aper.Snapshot
		s.End(f, &root, false)
		return v,
			root
	}, compare: func(v ErrorIndicationIEField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

	) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		BridgeErrorIndicationIEValueCompareS1APProtocolIEField(&v, &s)
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
func RetrieveUEInformationIEValueIEFieldTableCodec(table s00.RetrieveUEInformationIEValueIETable) RetrieveUEInformationIEFieldValueCodec {
	if !*s00.BridgeRetrieveUEInformationIEValueIETableFieldBound(&table) {
		return RetrieveUEInformationIEFieldValueCodec{}
	}
	return RetrieveUEInformationIEFieldValueCodec{decode: func(data []byte, options aper.DecodeState) (RetrieveUEInformationIEField, error) {
		var field RetrieveUEInformationIEField
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
	}, encode: func(field RetrieveUEInformationIEField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		bb := aper.NewBudgetBuffer(budget)
		if err := field.marshalAPERTo(bb, fresh); err != nil {
			return nil, err
		}
		return bb.CompleteBytes(), nil
	}, capture: func(v RetrieveUEInformationIEField, options aper.DecodeState) (RetrieveUEInformationIEField, aper.Snapshot,
	) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeRetrieveUEInformationIEValueCaptureS1APProtocolIEField(&v,
			&s)
		var root aper.Snapshot
		s.End(f, &root, false)
		return v,
			root
	}, compare: func(v RetrieveUEInformationIEField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

	) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		BridgeRetrieveUEInformationIEValueCompareS1APProtocolIEField(&v, &s)
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
func SecondaryRATDataUsageReportItemIEValueIEFieldTableCodec(table s00.SecondaryRATDataUsageReportItemIEValueIETable) SecondaryRATDataUsageReportItemIEFieldValueCodec {
	if !*s00.BridgeSecondaryRATDataUsageReportItemIEValueIETableFieldBound(&table) {
		return SecondaryRATDataUsageReportItemIEFieldValueCodec{}
	}
	return SecondaryRATDataUsageReportItemIEFieldValueCodec{decode: func(data []byte, options aper.DecodeState) (SecondaryRATDataUsageReportItemIEField, error) {
		var field SecondaryRATDataUsageReportItemIEField
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
	}, encode: func(field SecondaryRATDataUsageReportItemIEField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		bb := aper.NewBudgetBuffer(budget)
		if err := field.marshalAPERTo(bb, fresh); err != nil {
			return nil, err
		}
		return bb.CompleteBytes(), nil
	}, capture: func(v SecondaryRATDataUsageReportItemIEField, options aper.DecodeState) (SecondaryRATDataUsageReportItemIEField, aper.Snapshot,
	) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeSecondaryRATDataUsageReportItemIEValueCaptureS1APProtocolIEField(&v,
			&s)
		var root aper.Snapshot
		s.End(f, &root, false)
		return v,
			root
	}, compare: func(v SecondaryRATDataUsageReportItemIEField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

	) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		BridgeSecondaryRATDataUsageReportItemIEValueCompareS1APProtocolIEField(&v, &s)
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
func ErrorIndicationIEValueIETableCodec(table s00.ErrorIndicationIEValueIETable, bounds aper.ListBounds) ErrorIndicationIEContainerValueCodec {
	if !*s00.BridgeErrorIndicationIEValueIETableFieldBound(&table) {
		return ErrorIndicationIEContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return ErrorIndicationIEContainerValueCodec{decode: func(data []byte, options aper.DecodeState) (ErrorIndicationIEContainer, error) {
		bb := aper.NewCompleteDecodeBuffer(data, options)
		if err := bb.SetDecodeOptionsAligned(options); err != nil {
			return nil, err
		}
		var fields ErrorIndicationIEContainer
		_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
			for i := int64(0); i < length; i++ {
				var field ErrorIndicationIEField
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
		encode: func(fields ErrorIndicationIEContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
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
		}, capture: func(v ErrorIndicationIEContainer, options aper.DecodeState) (ErrorIndicationIEContainer, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeErrorIndicationIEValueCaptureS1APProtocolIEContainer(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}, compare: func(v ErrorIndicationIEContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeErrorIndicationIEValueCompareS1APProtocolIEContainer(&v, &s)
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
func RetrieveUEInformationIEValueIETableCodec(table s00.RetrieveUEInformationIEValueIETable, bounds aper.ListBounds) RetrieveUEInformationIEContainerValueCodec {
	if !*s00.BridgeRetrieveUEInformationIEValueIETableFieldBound(&table) {
		return RetrieveUEInformationIEContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return RetrieveUEInformationIEContainerValueCodec{decode: func(data []byte, options aper.DecodeState) (RetrieveUEInformationIEContainer, error) {
		bb := aper.NewCompleteDecodeBuffer(data, options)
		if err := bb.SetDecodeOptionsAligned(options); err != nil {
			return nil, err
		}
		var fields RetrieveUEInformationIEContainer
		_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
			for i := int64(0); i < length; i++ {
				var field RetrieveUEInformationIEField
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
		encode: func(fields RetrieveUEInformationIEContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
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
		}, capture: func(v RetrieveUEInformationIEContainer, options aper.DecodeState) (RetrieveUEInformationIEContainer, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeRetrieveUEInformationIEValueCaptureS1APProtocolIEContainer(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}, compare: func(v RetrieveUEInformationIEContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeRetrieveUEInformationIEValueCompareS1APProtocolIEContainer(&v, &s)
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
func SecondaryRATDataUsageReportItemIEValueIETableCodec(table s00.SecondaryRATDataUsageReportItemIEValueIETable, bounds aper.ListBounds) SecondaryRATDataUsageReportItemIEContainerValueCodec {
	if !*s00.BridgeSecondaryRATDataUsageReportItemIEValueIETableFieldBound(&table) {
		return SecondaryRATDataUsageReportItemIEContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return SecondaryRATDataUsageReportItemIEContainerValueCodec{decode: func(data []byte, options aper.DecodeState) (SecondaryRATDataUsageReportItemIEContainer, error) {
		bb := aper.NewCompleteDecodeBuffer(data, options)
		if err := bb.SetDecodeOptionsAligned(options); err != nil {
			return nil, err
		}
		var fields SecondaryRATDataUsageReportItemIEContainer
		_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
			for i := int64(0); i < length; i++ {
				var field SecondaryRATDataUsageReportItemIEField
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
		encode: func(fields SecondaryRATDataUsageReportItemIEContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
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
		}, capture: func(v SecondaryRATDataUsageReportItemIEContainer, options aper.DecodeState) (SecondaryRATDataUsageReportItemIEContainer, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeSecondaryRATDataUsageReportItemIEValueCaptureS1APProtocolIEContainer(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}, compare: func(v SecondaryRATDataUsageReportItemIEContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeSecondaryRATDataUsageReportItemIEValueCompareS1APProtocolIEContainer(&v, &s)
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
func ErrorIndicationIEValueProtocolErrorIEContainerListCodec(table s00.ErrorIndicationIEValueIETable) ErrorIndicationIEValueProtocolErrorIEContainerListValueCodec {
	codec := ErrorIndicationIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if codec.decode == nil {
		return ErrorIndicationIEValueProtocolErrorIEContainerListValueCodec{}
	}
	return ErrorIndicationIEValueProtocolErrorIEContainerListValueCodec{decode: func(data []byte, options aper.DecodeState) (ErrorIndicationIEValueProtocolErrorIEContainerList, error) {
		value, err := codec.decode(data, options)
		return ErrorIndicationIEValueProtocolErrorIEContainerList(value), err
	}, encode: func(value ErrorIndicationIEValueProtocolErrorIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return codec.encode(ErrorIndicationIEContainer(value), fresh, budget)
	}, capture: func(v ErrorIndicationIEValueProtocolErrorIEContainerList, options aper.DecodeState) (ErrorIndicationIEValueProtocolErrorIEContainerList, aper.Snapshot,
	) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeErrorIndicationIEValueCaptureS1APProtocolErrorIEContainerList(&v, &s)
		var root aper.Snapshot

		s.End(f, &root, false)
		return v, root
	}, compare: func(v ErrorIndicationIEValueProtocolErrorIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

	) {
		s := aper.NewSemanticComparison(root, budget)
		f :=
			s.
				Begin()
		BridgeErrorIndicationIEValueCompareS1APProtocolErrorIEContainerList(&v, &s)
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
func RetrieveUEInformationIEValueProtocolErrorIEContainerListCodec(table s00.RetrieveUEInformationIEValueIETable) RetrieveUEInformationIEValueProtocolErrorIEContainerListValueCodec {
	codec := RetrieveUEInformationIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if codec.decode == nil {
		return RetrieveUEInformationIEValueProtocolErrorIEContainerListValueCodec{}
	}
	return RetrieveUEInformationIEValueProtocolErrorIEContainerListValueCodec{decode: func(data []byte, options aper.DecodeState) (RetrieveUEInformationIEValueProtocolErrorIEContainerList, error) {
		value, err := codec.decode(data, options)
		return RetrieveUEInformationIEValueProtocolErrorIEContainerList(value), err
	}, encode: func(value RetrieveUEInformationIEValueProtocolErrorIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return codec.encode(RetrieveUEInformationIEContainer(value), fresh, budget)
	}, capture: func(v RetrieveUEInformationIEValueProtocolErrorIEContainerList, options aper.DecodeState) (RetrieveUEInformationIEValueProtocolErrorIEContainerList, aper.Snapshot,
	) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeRetrieveUEInformationIEValueCaptureS1APProtocolErrorIEContainerList(&v, &s)
		var root aper.Snapshot

		s.End(f, &root, false)
		return v, root
	}, compare: func(v RetrieveUEInformationIEValueProtocolErrorIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

	) {
		s := aper.NewSemanticComparison(root, budget)
		f :=
			s.
				Begin()
		BridgeRetrieveUEInformationIEValueCompareS1APProtocolErrorIEContainerList(&v, &s)
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
func SecondaryRATDataUsageReportItemIEValueProtocolErrorIEContainerListCodec(table s00.SecondaryRATDataUsageReportItemIEValueIETable) SecondaryRATDataUsageReportItemIEValueProtocolErrorIEContainerListValueCodec {
	codec := SecondaryRATDataUsageReportItemIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if codec.decode == nil {
		return SecondaryRATDataUsageReportItemIEValueProtocolErrorIEContainerListValueCodec{}
	}
	return SecondaryRATDataUsageReportItemIEValueProtocolErrorIEContainerListValueCodec{decode: func(data []byte, options aper.DecodeState) (SecondaryRATDataUsageReportItemIEValueProtocolErrorIEContainerList, error) {
		value, err := codec.decode(data, options)
		return SecondaryRATDataUsageReportItemIEValueProtocolErrorIEContainerList(value), err
	}, encode: func(value SecondaryRATDataUsageReportItemIEValueProtocolErrorIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return codec.encode(SecondaryRATDataUsageReportItemIEContainer(value), fresh, budget)
	}, capture: func(v SecondaryRATDataUsageReportItemIEValueProtocolErrorIEContainerList, options aper.DecodeState) (SecondaryRATDataUsageReportItemIEValueProtocolErrorIEContainerList, aper.Snapshot,
	) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeSecondaryRATDataUsageReportItemIEValueCaptureS1APProtocolErrorIEContainerList(&v, &s)
		var root aper.Snapshot

		s.End(f, &root, false)
		return v, root
	}, compare: func(v SecondaryRATDataUsageReportItemIEValueProtocolErrorIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

	) {
		s := aper.NewSemanticComparison(root, budget)
		f :=
			s.
				Begin()
		BridgeSecondaryRATDataUsageReportItemIEValueCompareS1APProtocolErrorIEContainerList(&v, &s)
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
func ErrorIndicationIEValueProtocolIEContainerListCodec(table s00.ErrorIndicationIEValueIETable, bounds aper.ListBounds) ErrorIndicationIEValueProtocolIEContainerListValueCodec {
	codec := ErrorIndicationIEValueIETableCodec(table, bounds)
	if codec.decode == nil {
		return ErrorIndicationIEValueProtocolIEContainerListValueCodec{}
	}
	return ErrorIndicationIEValueProtocolIEContainerListValueCodec{decode: func(data []byte, options aper.DecodeState) (ErrorIndicationIEValueProtocolIEContainerList, error) {
		value, err := codec.decode(data, options)
		return ErrorIndicationIEValueProtocolIEContainerList(value), err
	}, encode: func(value ErrorIndicationIEValueProtocolIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return codec.encode(ErrorIndicationIEContainer(value), fresh, budget)
	}, capture: func(v ErrorIndicationIEValueProtocolIEContainerList, options aper.DecodeState) (ErrorIndicationIEValueProtocolIEContainerList, aper.Snapshot,
	) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeErrorIndicationIEValueCaptureS1APProtocolIEContainerList(&v, &s)
		var root aper.Snapshot
		s.End(
			f,
			&root, false)
		return v, root
	}, compare: func(v ErrorIndicationIEValueProtocolIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
	) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		BridgeErrorIndicationIEValueCompareS1APProtocolIEContainerList(&v, &s)
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
func RetrieveUEInformationIEValueProtocolIEContainerListCodec(table s00.RetrieveUEInformationIEValueIETable, bounds aper.ListBounds) RetrieveUEInformationIEValueProtocolIEContainerListValueCodec {
	codec := RetrieveUEInformationIEValueIETableCodec(table, bounds)
	if codec.decode == nil {
		return RetrieveUEInformationIEValueProtocolIEContainerListValueCodec{}
	}
	return RetrieveUEInformationIEValueProtocolIEContainerListValueCodec{decode: func(data []byte, options aper.DecodeState) (RetrieveUEInformationIEValueProtocolIEContainerList, error) {
		value, err := codec.decode(data, options)
		return RetrieveUEInformationIEValueProtocolIEContainerList(value), err
	}, encode: func(value RetrieveUEInformationIEValueProtocolIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return codec.encode(RetrieveUEInformationIEContainer(value), fresh, budget)
	}, capture: func(v RetrieveUEInformationIEValueProtocolIEContainerList, options aper.DecodeState) (RetrieveUEInformationIEValueProtocolIEContainerList, aper.Snapshot,
	) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeRetrieveUEInformationIEValueCaptureS1APProtocolIEContainerList(&v, &s)
		var root aper.Snapshot
		s.End(
			f,
			&root, false)
		return v, root
	}, compare: func(v RetrieveUEInformationIEValueProtocolIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
	) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		BridgeRetrieveUEInformationIEValueCompareS1APProtocolIEContainerList(&v, &s)
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
func SecondaryRATDataUsageReportItemIEValueProtocolIEContainerListCodec(table s00.SecondaryRATDataUsageReportItemIEValueIETable, bounds aper.ListBounds) SecondaryRATDataUsageReportItemIEValueProtocolIEContainerListValueCodec {
	codec := SecondaryRATDataUsageReportItemIEValueIETableCodec(table, bounds)
	if codec.decode == nil {
		return SecondaryRATDataUsageReportItemIEValueProtocolIEContainerListValueCodec{}
	}
	return SecondaryRATDataUsageReportItemIEValueProtocolIEContainerListValueCodec{decode: func(data []byte, options aper.DecodeState) (SecondaryRATDataUsageReportItemIEValueProtocolIEContainerList, error) {
		value, err := codec.decode(data, options)
		return SecondaryRATDataUsageReportItemIEValueProtocolIEContainerList(value), err
	}, encode: func(value SecondaryRATDataUsageReportItemIEValueProtocolIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return codec.encode(SecondaryRATDataUsageReportItemIEContainer(value), fresh, budget)
	}, capture: func(v SecondaryRATDataUsageReportItemIEValueProtocolIEContainerList, options aper.DecodeState) (SecondaryRATDataUsageReportItemIEValueProtocolIEContainerList, aper.Snapshot,
	) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeSecondaryRATDataUsageReportItemIEValueCaptureS1APProtocolIEContainerList(&v, &s)
		var root aper.Snapshot
		s.End(
			f,
			&root, false)
		return v, root
	}, compare: func(v SecondaryRATDataUsageReportItemIEValueProtocolIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
	) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		BridgeSecondaryRATDataUsageReportItemIEValueCompareS1APProtocolIEContainerList(&v, &s)
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

// errorIndicationIEValueProtocolOpenValue is the concrete protocolOpenValue[ErrorIndicationIEValue].
type ErrorIndicationIEValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) ErrorIndicationIEValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (ErrorIndicationIEValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

func BridgeErrorIndicationIEValueCaptureS1APProtocolIEField(v *ErrorIndicationIEField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolIEID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.Value = v.Value.captureSemantics(*s)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeErrorIndicationIEValueCompareS1APProtocolIEField(v *ErrorIndicationIEField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s02.BridgeCompareS1APProtocolIEID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = v.Value.compareSemantics(*s)
	s.End(f, v.replay, v.withoutReplay)
}

// retrieveUEInformationIEValueProtocolOpenValue is the concrete protocolOpenValue[RetrieveUEInformationIEValue].
type RetrieveUEInformationIEValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) RetrieveUEInformationIEValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (RetrieveUEInformationIEValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

func BridgeRetrieveUEInformationIEValueCaptureS1APProtocolIEField(v *RetrieveUEInformationIEField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolIEID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.Value = v.Value.captureSemantics(*s)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeRetrieveUEInformationIEValueCompareS1APProtocolIEField(v *RetrieveUEInformationIEField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s02.BridgeCompareS1APProtocolIEID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = v.Value.compareSemantics(*s)
	s.End(f, v.replay, v.withoutReplay)
}

// sTMSIExtIEsValueProtocolOpenValue is the concrete protocolOpenValue[STMSIExtIEsValue].
type STMSIExtIEsValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) s05.STMSIExtIEsValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (s05.STMSIExtIEsValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

// scheduledCommunicationTimeExtIEsValueProtocolOpenValue is the concrete protocolOpenValue[ScheduledCommunicationTimeExtIEsValue].
type ScheduledCommunicationTimeExtIEsValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) s05.ScheduledCommunicationTimeExtIEsValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (s05.ScheduledCommunicationTimeExtIEsValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

func BridgeScheduledCommunicationTimeExtIEsValueCaptureS1APProtocolExtensionField(v *s11.ScheduledCommunicationTimeExtIEsExtField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolExtensionID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.ExtensionValue = s05.BridgeScheduledCommunicationTimeExtIEsValueMethodCaptureSemantics(v.ExtensionValue, *s)
	s.End(f, s11.BridgeScheduledCommunicationTimeExtIEsExtFieldFieldReplay(v), *s11.BridgeScheduledCommunicationTimeExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeScheduledCommunicationTimeExtIEsValueCompareS1APProtocolExtensionField(v *s11.ScheduledCommunicationTimeExtIEsExtField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s02.BridgeCompareS1APProtocolExtensionID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s05.BridgeScheduledCommunicationTimeExtIEsValueMethodCompareSemantics(v.ExtensionValue, *s)
	s.End(f, *s11.BridgeScheduledCommunicationTimeExtIEsExtFieldFieldReplay(v), *s11.BridgeScheduledCommunicationTimeExtIEsExtFieldFieldWithoutReplay(v))
}

// secondaryRATDataUsageReportItemExtIEsValueProtocolOpenValue is the concrete protocolOpenValue[SecondaryRATDataUsageReportItemExtIEsValue].
type SecondaryRATDataUsageReportItemExtIEsValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) s05.SecondaryRATDataUsageReportItemExtIEsValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (s05.SecondaryRATDataUsageReportItemExtIEsValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

func BridgeSecondaryRATDataUsageReportItemExtIEsValueCaptureS1APProtocolExtensionField(v *s11.SecondaryRATDataUsageReportItemExtIEsExtField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolExtensionID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.ExtensionValue = s05.BridgeSecondaryRATDataUsageReportItemExtIEsValueMethodCaptureSemantics(v.ExtensionValue, *s)
	s.End(f, s11.BridgeSecondaryRATDataUsageReportItemExtIEsExtFieldFieldReplay(v), *s11.BridgeSecondaryRATDataUsageReportItemExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeSecondaryRATDataUsageReportItemExtIEsValueCompareS1APProtocolExtensionField(v *s11.SecondaryRATDataUsageReportItemExtIEsExtField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s02.BridgeCompareS1APProtocolExtensionID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s05.BridgeSecondaryRATDataUsageReportItemExtIEsValueMethodCompareSemantics(v.ExtensionValue, *s)
	s.End(f, *s11.BridgeSecondaryRATDataUsageReportItemExtIEsExtFieldFieldReplay(v), *s11.BridgeSecondaryRATDataUsageReportItemExtIEsExtFieldFieldWithoutReplay(v))
}

// secondaryRATDataUsageReportItemIEValueProtocolOpenValue is the concrete protocolOpenValue[SecondaryRATDataUsageReportItemIEValue].
type SecondaryRATDataUsageReportItemIEValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) SecondaryRATDataUsageReportItemIEValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (SecondaryRATDataUsageReportItemIEValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

func BridgeSecondaryRATDataUsageReportItemIEValueCaptureS1APProtocolIEField(v *SecondaryRATDataUsageReportItemIEField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolIEID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.Value = v.Value.captureSemantics(*s)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeSecondaryRATDataUsageReportItemIEValueCompareS1APProtocolIEField(v *SecondaryRATDataUsageReportItemIEField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s02.BridgeCompareS1APProtocolIEID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = v.Value.compareSemantics(*s)
	s.End(f, v.replay, v.withoutReplay)
}

// securityContextExtIEsValueProtocolOpenValue is the concrete protocolOpenValue[SecurityContextExtIEsValue].
type SecurityContextExtIEsValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) s05.SecurityContextExtIEsValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (s05.SecurityContextExtIEsValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

func BridgeSecurityContextExtIEsValueCaptureS1APProtocolExtensionField(v *s11.SecurityContextExtIEsExtField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolExtensionID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.ExtensionValue = s05.BridgeSecurityContextExtIEsValueMethodCaptureSemantics(v.ExtensionValue, *s)
	s.End(f, s11.BridgeSecurityContextExtIEsExtFieldFieldReplay(v), *s11.BridgeSecurityContextExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeSecurityContextExtIEsValueCompareS1APProtocolExtensionField(v *s11.SecurityContextExtIEsExtField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s02.BridgeCompareS1APProtocolExtensionID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s05.BridgeSecurityContextExtIEsValueMethodCompareSemantics(v.ExtensionValue, *s)
	s.End(f, *s11.BridgeSecurityContextExtIEsExtFieldFieldReplay(v), *s11.BridgeSecurityContextExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeSecurityIndicationExtIEsValueCaptureS1APProtocolExtensionField(v *s11.SecurityIndicationExtIEsExtField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolExtensionID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.ExtensionValue = s05.BridgeSecurityIndicationExtIEsValueMethodCaptureSemantics(v.ExtensionValue, *s)
	s.End(f, s11.BridgeSecurityIndicationExtIEsExtFieldFieldReplay(v), *s11.BridgeSecurityIndicationExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeSecurityIndicationExtIEsValueCompareS1APProtocolExtensionField(v *s11.SecurityIndicationExtIEsExtField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s02.BridgeCompareS1APProtocolExtensionID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s05.BridgeSecurityIndicationExtIEsValueMethodCompareSemantics(v.ExtensionValue, *s)
	s.End(f, *s11.BridgeSecurityIndicationExtIEsExtFieldFieldReplay(v), *s11.BridgeSecurityIndicationExtIEsExtFieldFieldWithoutReplay(v))
}

// SecondaryRATDataUsageReportItemAPERValue is the concrete APERValue[SecondaryRATDataUsageReportItem].
type SecondaryRATDataUsageReportItemAPERValue struct {
	context s00.BridgeCodecContext
	Value   SecondaryRATDataUsageReportItem

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v SecondaryRATDataUsageReportItemAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v SecondaryRATDataUsageReportItemAPERValue) WithoutReplay() SecondaryRATDataUsageReportItemAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// SecondaryRATDataUsageReportListAPERValue is the concrete APERValue[SecondaryRATDataUsageReportList].
type SecondaryRATDataUsageReportListAPERValue struct {
	context s00.BridgeCodecContext
	Value   SecondaryRATDataUsageReportList

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v SecondaryRATDataUsageReportListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v SecondaryRATDataUsageReportListAPERValue) WithoutReplay() SecondaryRATDataUsageReportListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// STMSIAPERValue is the concrete APERValue[STMSI].
type STMSIAPERValue struct {
	context s00.BridgeCodecContext
	Value   s27.STMSI

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v STMSIAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v STMSIAPERValue) WithoutReplay() STMSIAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// SecurityContextAPERValue is the concrete APERValue[SecurityContext].
type SecurityContextAPERValue struct {
	context s00.BridgeCodecContext
	Value   SecurityContext

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v SecurityContextAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v SecurityContextAPERValue) WithoutReplay() SecurityContextAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// UEPagingIDAPERValue is the concrete APERValue[UEPagingID].
type UEPagingIDAPERValue struct {
	context s00.BridgeCodecContext
	Value   UEPagingID

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v UEPagingIDAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v UEPagingIDAPERValue) WithoutReplay() UEPagingIDAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ErrorIndicationAPERValue is the concrete APERValue[ErrorIndication].
type ErrorIndicationAPERValue struct {
	context s00.BridgeCodecContext
	Value   ErrorIndication

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ErrorIndicationAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ErrorIndicationAPERValue) WithoutReplay() ErrorIndicationAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// RetrieveUEInformationAPERValue is the concrete APERValue[RetrieveUEInformation].
type RetrieveUEInformationAPERValue struct {
	context s00.BridgeCodecContext
	Value   RetrieveUEInformation

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v RetrieveUEInformationAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v RetrieveUEInformationAPERValue) WithoutReplay() RetrieveUEInformationAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ScheduledCommunicationTimeAPERValue is the concrete APERValue[ScheduledCommunicationTime].
type ScheduledCommunicationTimeAPERValue struct {
	context s00.BridgeCodecContext
	Value   ScheduledCommunicationTime

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ScheduledCommunicationTimeAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ScheduledCommunicationTimeAPERValue) WithoutReplay() ScheduledCommunicationTimeAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ERABInformationListItemExtIEsIEField is the concrete ProtocolIEField[ERABInformationListItemExtIEsValue].
type ERABInformationListItemExtIEsIEField struct {
	withoutReplay bool
	replay        aper.Snapshot
	stream        aper.WireSpan
	Id            s00.ProtocolIEID
	Criticality   s00.Criticality
	Value         ERABInformationListItemExtIEsValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ERABInformationListItemExtIEsIEField) WithoutReplay() ERABInformationListItemExtIEsIEField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *ERABInformationListItemExtIEsIEField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *ERABInformationListItemExtIEsIEField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
func (v *ERABInformationListItemExtIEsIEField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolIEField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = ERABInformationListItemExtIEsIEField{}
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
	var zero ERABInformationListItemExtIEsValue

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

// ERABInformationListItemExtIEsIEContainer is the concrete ProtocolIEContainer[ERABInformationListItemExtIEsValue].
type ERABInformationListItemExtIEsIEContainer []ERABInformationListItemExtIEsIEField

// ERABToBeSetupItemBearerSUReqExtIEsIEField is the concrete ProtocolIEField[ERABToBeSetupItemBearerSUReqExtIEsValue].
type ERABToBeSetupItemBearerSUReqExtIEsIEField struct {
	withoutReplay bool
	replay        aper.Snapshot
	stream        aper.WireSpan
	Id            s00.ProtocolIEID
	Criticality   s00.Criticality
	Value         ERABToBeSetupItemBearerSUReqExtIEsValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ERABToBeSetupItemBearerSUReqExtIEsIEField) WithoutReplay() ERABToBeSetupItemBearerSUReqExtIEsIEField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *ERABToBeSetupItemBearerSUReqExtIEsIEField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *ERABToBeSetupItemBearerSUReqExtIEsIEField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
func (v *ERABToBeSetupItemBearerSUReqExtIEsIEField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolIEField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = ERABToBeSetupItemBearerSUReqExtIEsIEField{}
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
	var zero ERABToBeSetupItemBearerSUReqExtIEsValue

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

// ERABToBeSetupItemBearerSUReqExtIEsIEContainer is the concrete ProtocolIEContainer[ERABToBeSetupItemBearerSUReqExtIEsValue].
type ERABToBeSetupItemBearerSUReqExtIEsIEContainer []ERABToBeSetupItemBearerSUReqExtIEsIEField

// ERABToBeSetupItemCtxtSUReqExtIEsIEField is the concrete ProtocolIEField[ERABToBeSetupItemCtxtSUReqExtIEsValue].
type ERABToBeSetupItemCtxtSUReqExtIEsIEField struct {
	withoutReplay bool
	replay        aper.Snapshot
	stream        aper.WireSpan
	Id            s00.ProtocolIEID
	Criticality   s00.Criticality
	Value         ERABToBeSetupItemCtxtSUReqExtIEsValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ERABToBeSetupItemCtxtSUReqExtIEsIEField) WithoutReplay() ERABToBeSetupItemCtxtSUReqExtIEsIEField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *ERABToBeSetupItemCtxtSUReqExtIEsIEField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *ERABToBeSetupItemCtxtSUReqExtIEsIEField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
func (v *ERABToBeSetupItemCtxtSUReqExtIEsIEField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolIEField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = ERABToBeSetupItemCtxtSUReqExtIEsIEField{}
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
	var zero ERABToBeSetupItemCtxtSUReqExtIEsValue

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

// ERABToBeSetupItemCtxtSUReqExtIEsIEContainer is the concrete ProtocolIEContainer[ERABToBeSetupItemCtxtSUReqExtIEsValue].
type ERABToBeSetupItemCtxtSUReqExtIEsIEContainer []ERABToBeSetupItemCtxtSUReqExtIEsIEField

// TS 36.413 V19.2.0 §§9.3.3–9.3.4 supply the selected object-set order and
// presence. §§10.3.1–10.3.6 define abstract-syntax diagnostics. Unknown IEs do
// not determine the order of known rows.
func BridgeSTMSIExtIEsValueValidateS1APIEContainer(fields s11.STMSIExtIEsIEContainer, rows []s00.FieldInfo, path string, budget *aper.DecodeBudget,

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
		if !s05.BridgeSTMSIExtIEsValueMethodMatchesID(field.Value, field.Id, budget) {
			rule := s05.BridgeSTMSIExtIEsValueMethodRule(field.Value)
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.ValueIDMismatch, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: aper.Path(fmt.Sprintf("%s.id", location.Path))}, Table: func() s00.TableID {
				sealed := s00.TableID{}
				*s00.BridgeTableIDFieldSource(&sealed) = rule.Assignment
				return sealed
			}(), IEID: field.Id, HasIEID: true, Rule: s26.BridgeS1apValidationRule(s00.ValueIDMismatch), RelatedRules: []aper.SourceRule{rule}})
		}
		rank, allowed := byID[field.Id]
		table := func() s00.TableID {
			sealed := s00.TableID{}
			*s00.BridgeTableIDFieldSource(&sealed) = s05.BridgeSTMSIExtIEsValueMethodRule(field.Value).Assignment
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
func BridgeScheduledCommunicationTimeExtIEsValueValidateS1APIEContainer(fields s11.ScheduledCommunicationTimeExtIEsIEContainer, rows []s00.FieldInfo, path string, budget *aper.DecodeBudget,

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
		if !s05.BridgeScheduledCommunicationTimeExtIEsValueMethodMatchesID(field.Value, field.Id, budget) {
			rule := s05.BridgeScheduledCommunicationTimeExtIEsValueMethodRule(field.Value)
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.ValueIDMismatch, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: aper.Path(fmt.Sprintf("%s.id", location.Path))}, Table: func() s00.TableID {
				sealed := s00.TableID{}
				*s00.BridgeTableIDFieldSource(&sealed) = rule.Assignment
				return sealed
			}(), IEID: field.Id, HasIEID: true, Rule: s26.BridgeS1apValidationRule(s00.ValueIDMismatch), RelatedRules: []aper.SourceRule{rule}})
		}
		rank, allowed := byID[field.Id]
		table := func() s00.TableID {
			sealed := s00.TableID{}
			*s00.BridgeTableIDFieldSource(&sealed) = s05.BridgeScheduledCommunicationTimeExtIEsValueMethodRule(field.Value).Assignment
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
func BridgeSecondaryRATDataUsageReportItemExtIEsValueValidateS1APIEContainer(fields s11.SecondaryRATDataUsageReportItemExtIEsIEContainer, rows []s00.FieldInfo, path string, budget *aper.DecodeBudget,

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
		if !s05.BridgeSecondaryRATDataUsageReportItemExtIEsValueMethodMatchesID(field.Value, field.Id, budget) {
			rule := s05.BridgeSecondaryRATDataUsageReportItemExtIEsValueMethodRule(field.Value)
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.ValueIDMismatch, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: aper.Path(fmt.Sprintf("%s.id", location.Path))}, Table: func() s00.TableID {
				sealed := s00.TableID{}
				*s00.BridgeTableIDFieldSource(&sealed) = rule.Assignment
				return sealed
			}(), IEID: field.Id, HasIEID: true, Rule: s26.BridgeS1apValidationRule(s00.ValueIDMismatch), RelatedRules: []aper.SourceRule{rule}})
		}
		rank, allowed := byID[field.Id]
		table := func() s00.TableID {
			sealed := s00.TableID{}
			*s00.BridgeTableIDFieldSource(&sealed) = s05.BridgeSecondaryRATDataUsageReportItemExtIEsValueMethodRule(field.Value).Assignment
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
func BridgeSecurityContextExtIEsValueValidateS1APIEContainer(fields s11.SecurityContextExtIEsIEContainer, rows []s00.FieldInfo, path string, budget *aper.DecodeBudget,

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
		if !s05.BridgeSecurityContextExtIEsValueMethodMatchesID(field.Value, field.Id, budget) {
			rule := s05.BridgeSecurityContextExtIEsValueMethodRule(field.Value)
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.ValueIDMismatch, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: aper.Path(fmt.Sprintf("%s.id", location.Path))}, Table: func() s00.TableID {
				sealed := s00.TableID{}
				*s00.BridgeTableIDFieldSource(&sealed) = rule.Assignment
				return sealed
			}(), IEID: field.Id, HasIEID: true, Rule: s26.BridgeS1apValidationRule(s00.ValueIDMismatch), RelatedRules: []aper.SourceRule{rule}})
		}
		rank, allowed := byID[field.Id]
		table := func() s00.TableID {
			sealed := s00.TableID{}
			*s00.BridgeTableIDFieldSource(&sealed) = s05.BridgeSecurityContextExtIEsValueMethodRule(field.Value).Assignment
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

// ErrorIndicationIEValueERABIEContainerListValueCodec is the concrete ValueCodec[ERABIEContainerList[ErrorIndicationIEValue]].
type ErrorIndicationIEValueERABIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ErrorIndicationIEValueERABIEContainerList, error)
	encode  func(ErrorIndicationIEValueERABIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ErrorIndicationIEValueERABIEContainerList, aper.DecodeState) (ErrorIndicationIEValueERABIEContainerList, aper.Snapshot)
	compare func(ErrorIndicationIEValueERABIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ErrorIndicationIEValueERABIEContainerListValueCodec) New(value ErrorIndicationIEValueERABIEContainerList) (ErrorIndicationIEValueERABIEContainerListAPERValue, error) {
	if c.encode == nil {
		return ErrorIndicationIEValueERABIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ErrorIndicationIEValueERABIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ErrorIndicationIEValueERABIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ErrorIndicationIEValueERABIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ErrorIndicationIEValueERABIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ErrorIndicationIEValueERABIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ErrorIndicationIEValueERABIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ErrorIndicationIEValueERABIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ErrorIndicationIEValueERABIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ErrorIndicationIEValueERABIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ErrorIndicationIEValueERABIEContainerListValueCodec) EncodeAPER(value ErrorIndicationIEValueERABIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c ErrorIndicationIEValueERABIEContainerListValueCodec) encodeBudgetValue(value ErrorIndicationIEValueERABIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ErrorIndicationIEValueERABIEContainerListValueCodec) encodeChanged(value ErrorIndicationIEValueERABIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ErrorIndicationIEValueERABIEContainerList is the concrete ERABIEContainerList[ErrorIndicationIEValue].
type ErrorIndicationIEValueERABIEContainerList []ErrorIndicationIEValueProtocolIESingleContainer

func BridgeErrorIndicationIEValueCaptureS1APERABIEContainerList(v *ErrorIndicationIEValueERABIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeErrorIndicationIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeErrorIndicationIEValueCompareS1APERABIEContainerList(v *ErrorIndicationIEValueERABIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeErrorIndicationIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}

// RetrieveUEInformationIEValueERABIEContainerListValueCodec is the concrete ValueCodec[ERABIEContainerList[RetrieveUEInformationIEValue]].
type RetrieveUEInformationIEValueERABIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (RetrieveUEInformationIEValueERABIEContainerList, error)
	encode  func(RetrieveUEInformationIEValueERABIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(RetrieveUEInformationIEValueERABIEContainerList, aper.DecodeState) (RetrieveUEInformationIEValueERABIEContainerList, aper.Snapshot)
	compare func(RetrieveUEInformationIEValueERABIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c RetrieveUEInformationIEValueERABIEContainerListValueCodec) New(value RetrieveUEInformationIEValueERABIEContainerList) (RetrieveUEInformationIEValueERABIEContainerListAPERValue, error) {
	if c.encode == nil {
		return RetrieveUEInformationIEValueERABIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return RetrieveUEInformationIEValueERABIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return RetrieveUEInformationIEValueERABIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return RetrieveUEInformationIEValueERABIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c RetrieveUEInformationIEValueERABIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (RetrieveUEInformationIEValueERABIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return RetrieveUEInformationIEValueERABIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return RetrieveUEInformationIEValueERABIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return RetrieveUEInformationIEValueERABIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return RetrieveUEInformationIEValueERABIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c RetrieveUEInformationIEValueERABIEContainerListValueCodec) EncodeAPER(value RetrieveUEInformationIEValueERABIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c RetrieveUEInformationIEValueERABIEContainerListValueCodec) encodeBudgetValue(value RetrieveUEInformationIEValueERABIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c RetrieveUEInformationIEValueERABIEContainerListValueCodec) encodeChanged(value RetrieveUEInformationIEValueERABIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// RetrieveUEInformationIEValueERABIEContainerList is the concrete ERABIEContainerList[RetrieveUEInformationIEValue].
type RetrieveUEInformationIEValueERABIEContainerList []RetrieveUEInformationIEValueProtocolIESingleContainer

func BridgeRetrieveUEInformationIEValueCaptureS1APERABIEContainerList(v *RetrieveUEInformationIEValueERABIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeRetrieveUEInformationIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeRetrieveUEInformationIEValueCompareS1APERABIEContainerList(v *RetrieveUEInformationIEValueERABIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeRetrieveUEInformationIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}

// SecondaryRATDataUsageReportItemIEValueERABIEContainerListValueCodec is the concrete ValueCodec[ERABIEContainerList[SecondaryRATDataUsageReportItemIEValue]].
type SecondaryRATDataUsageReportItemIEValueERABIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (SecondaryRATDataUsageReportItemIEValueERABIEContainerList, error)
	encode  func(SecondaryRATDataUsageReportItemIEValueERABIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(SecondaryRATDataUsageReportItemIEValueERABIEContainerList, aper.DecodeState) (SecondaryRATDataUsageReportItemIEValueERABIEContainerList, aper.Snapshot)
	compare func(SecondaryRATDataUsageReportItemIEValueERABIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c SecondaryRATDataUsageReportItemIEValueERABIEContainerListValueCodec) New(value SecondaryRATDataUsageReportItemIEValueERABIEContainerList) (SecondaryRATDataUsageReportItemIEValueERABIEContainerListAPERValue, error) {
	if c.encode == nil {
		return SecondaryRATDataUsageReportItemIEValueERABIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return SecondaryRATDataUsageReportItemIEValueERABIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return SecondaryRATDataUsageReportItemIEValueERABIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return SecondaryRATDataUsageReportItemIEValueERABIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c SecondaryRATDataUsageReportItemIEValueERABIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (SecondaryRATDataUsageReportItemIEValueERABIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return SecondaryRATDataUsageReportItemIEValueERABIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return SecondaryRATDataUsageReportItemIEValueERABIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return SecondaryRATDataUsageReportItemIEValueERABIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return SecondaryRATDataUsageReportItemIEValueERABIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c SecondaryRATDataUsageReportItemIEValueERABIEContainerListValueCodec) EncodeAPER(value SecondaryRATDataUsageReportItemIEValueERABIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c SecondaryRATDataUsageReportItemIEValueERABIEContainerListValueCodec) encodeBudgetValue(value SecondaryRATDataUsageReportItemIEValueERABIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c SecondaryRATDataUsageReportItemIEValueERABIEContainerListValueCodec) encodeChanged(value SecondaryRATDataUsageReportItemIEValueERABIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// SecondaryRATDataUsageReportItemIEValueERABIEContainerList is the concrete ERABIEContainerList[SecondaryRATDataUsageReportItemIEValue].
type SecondaryRATDataUsageReportItemIEValueERABIEContainerList []SecondaryRATDataUsageReportItemIEValueProtocolIESingleContainer

func BridgeSecondaryRATDataUsageReportItemIEValueCaptureS1APERABIEContainerList(v *SecondaryRATDataUsageReportItemIEValueERABIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeSecondaryRATDataUsageReportItemIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeSecondaryRATDataUsageReportItemIEValueCompareS1APERABIEContainerList(v *SecondaryRATDataUsageReportItemIEValueERABIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeSecondaryRATDataUsageReportItemIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}

// UEContextSuspendResponseIEValueERABIEContainerListValueCodec is the concrete ValueCodec[ERABIEContainerList[UEContextSuspendResponseIEValue]].
type UEContextSuspendResponseIEValueERABIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (UEContextSuspendResponseIEValueERABIEContainerList, error)
	encode  func(UEContextSuspendResponseIEValueERABIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(UEContextSuspendResponseIEValueERABIEContainerList, aper.DecodeState) (UEContextSuspendResponseIEValueERABIEContainerList, aper.Snapshot)
	compare func(UEContextSuspendResponseIEValueERABIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c UEContextSuspendResponseIEValueERABIEContainerListValueCodec) New(value UEContextSuspendResponseIEValueERABIEContainerList) (UEContextSuspendResponseIEValueERABIEContainerListAPERValue, error) {
	if c.encode == nil {
		return UEContextSuspendResponseIEValueERABIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return UEContextSuspendResponseIEValueERABIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return UEContextSuspendResponseIEValueERABIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return UEContextSuspendResponseIEValueERABIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c UEContextSuspendResponseIEValueERABIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (UEContextSuspendResponseIEValueERABIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return UEContextSuspendResponseIEValueERABIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return UEContextSuspendResponseIEValueERABIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return UEContextSuspendResponseIEValueERABIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return UEContextSuspendResponseIEValueERABIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c UEContextSuspendResponseIEValueERABIEContainerListValueCodec) EncodeAPER(value UEContextSuspendResponseIEValueERABIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c UEContextSuspendResponseIEValueERABIEContainerListValueCodec) encodeBudgetValue(value UEContextSuspendResponseIEValueERABIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c UEContextSuspendResponseIEValueERABIEContainerListValueCodec) encodeChanged(value UEContextSuspendResponseIEValueERABIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// UEContextSuspendResponseIEValueERABIEContainerList is the concrete ERABIEContainerList[UEContextSuspendResponseIEValue].
type UEContextSuspendResponseIEValueERABIEContainerList []UEContextSuspendResponseIEValueProtocolIESingleContainer

// ERABInformationListItemExtIEsExtFieldValueCodec is the concrete ValueCodec[ProtocolExtensionField[ERABInformationListItemExtIEsValue]].
type ERABInformationListItemExtIEsExtFieldValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ERABInformationListItemExtIEsExtField, error)
	encode  func(ERABInformationListItemExtIEsExtField, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ERABInformationListItemExtIEsExtField, aper.DecodeState) (ERABInformationListItemExtIEsExtField, aper.Snapshot)
	compare func(ERABInformationListItemExtIEsExtField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ERABInformationListItemExtIEsExtFieldValueCodec) New(value ERABInformationListItemExtIEsExtField) (ERABInformationListItemExtIEsExtFieldAPERValue, error) {
	if c.encode == nil {
		return ERABInformationListItemExtIEsExtFieldAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ERABInformationListItemExtIEsExtFieldAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ERABInformationListItemExtIEsExtFieldAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ERABInformationListItemExtIEsExtFieldAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ERABInformationListItemExtIEsExtFieldValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ERABInformationListItemExtIEsExtFieldAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ERABInformationListItemExtIEsExtFieldAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ERABInformationListItemExtIEsExtFieldAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ERABInformationListItemExtIEsExtFieldAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ERABInformationListItemExtIEsExtFieldAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ERABInformationListItemExtIEsExtFieldValueCodec) EncodeAPER(value ERABInformationListItemExtIEsExtFieldAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c ERABInformationListItemExtIEsExtFieldValueCodec) encodeBudgetValue(value ERABInformationListItemExtIEsExtField, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ERABInformationListItemExtIEsExtFieldValueCodec) encodeChanged(value ERABInformationListItemExtIEsExtField, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ERABToBeSetupItemBearerSUReqExtIEsExtFieldValueCodec is the concrete ValueCodec[ProtocolExtensionField[ERABToBeSetupItemBearerSUReqExtIEsValue]].
type ERABToBeSetupItemBearerSUReqExtIEsExtFieldValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ERABToBeSetupItemBearerSUReqExtIEsExtField, error)
	encode  func(ERABToBeSetupItemBearerSUReqExtIEsExtField, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ERABToBeSetupItemBearerSUReqExtIEsExtField, aper.DecodeState) (ERABToBeSetupItemBearerSUReqExtIEsExtField, aper.Snapshot)
	compare func(ERABToBeSetupItemBearerSUReqExtIEsExtField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ERABToBeSetupItemBearerSUReqExtIEsExtFieldValueCodec) New(value ERABToBeSetupItemBearerSUReqExtIEsExtField) (ERABToBeSetupItemBearerSUReqExtIEsExtFieldAPERValue, error) {
	if c.encode == nil {
		return ERABToBeSetupItemBearerSUReqExtIEsExtFieldAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ERABToBeSetupItemBearerSUReqExtIEsExtFieldAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ERABToBeSetupItemBearerSUReqExtIEsExtFieldAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ERABToBeSetupItemBearerSUReqExtIEsExtFieldAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ERABToBeSetupItemBearerSUReqExtIEsExtFieldValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ERABToBeSetupItemBearerSUReqExtIEsExtFieldAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ERABToBeSetupItemBearerSUReqExtIEsExtFieldAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ERABToBeSetupItemBearerSUReqExtIEsExtFieldAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ERABToBeSetupItemBearerSUReqExtIEsExtFieldAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ERABToBeSetupItemBearerSUReqExtIEsExtFieldAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ERABToBeSetupItemBearerSUReqExtIEsExtFieldValueCodec) EncodeAPER(value ERABToBeSetupItemBearerSUReqExtIEsExtFieldAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c ERABToBeSetupItemBearerSUReqExtIEsExtFieldValueCodec) encodeBudgetValue(value ERABToBeSetupItemBearerSUReqExtIEsExtField, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ERABToBeSetupItemBearerSUReqExtIEsExtFieldValueCodec) encodeChanged(value ERABToBeSetupItemBearerSUReqExtIEsExtField, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ERABToBeSetupItemCtxtSUReqExtIEsExtFieldValueCodec is the concrete ValueCodec[ProtocolExtensionField[ERABToBeSetupItemCtxtSUReqExtIEsValue]].
type ERABToBeSetupItemCtxtSUReqExtIEsExtFieldValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ERABToBeSetupItemCtxtSUReqExtIEsExtField, error)
	encode  func(ERABToBeSetupItemCtxtSUReqExtIEsExtField, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ERABToBeSetupItemCtxtSUReqExtIEsExtField, aper.DecodeState) (ERABToBeSetupItemCtxtSUReqExtIEsExtField, aper.Snapshot)
	compare func(ERABToBeSetupItemCtxtSUReqExtIEsExtField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ERABToBeSetupItemCtxtSUReqExtIEsExtFieldValueCodec) New(value ERABToBeSetupItemCtxtSUReqExtIEsExtField) (ERABToBeSetupItemCtxtSUReqExtIEsExtFieldAPERValue, error) {
	if c.encode == nil {
		return ERABToBeSetupItemCtxtSUReqExtIEsExtFieldAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ERABToBeSetupItemCtxtSUReqExtIEsExtFieldAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ERABToBeSetupItemCtxtSUReqExtIEsExtFieldAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ERABToBeSetupItemCtxtSUReqExtIEsExtFieldAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ERABToBeSetupItemCtxtSUReqExtIEsExtFieldValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ERABToBeSetupItemCtxtSUReqExtIEsExtFieldAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ERABToBeSetupItemCtxtSUReqExtIEsExtFieldAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ERABToBeSetupItemCtxtSUReqExtIEsExtFieldAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ERABToBeSetupItemCtxtSUReqExtIEsExtFieldAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ERABToBeSetupItemCtxtSUReqExtIEsExtFieldAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ERABToBeSetupItemCtxtSUReqExtIEsExtFieldValueCodec) EncodeAPER(value ERABToBeSetupItemCtxtSUReqExtIEsExtFieldAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c ERABToBeSetupItemCtxtSUReqExtIEsExtFieldValueCodec) encodeBudgetValue(value ERABToBeSetupItemCtxtSUReqExtIEsExtField, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ERABToBeSetupItemCtxtSUReqExtIEsExtFieldValueCodec) encodeChanged(value ERABToBeSetupItemCtxtSUReqExtIEsExtField, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ERABInformationListItemExtIEsExtContainerValueCodec is the concrete ValueCodec[ProtocolExtensionContainer[ERABInformationListItemExtIEsValue]].
type ERABInformationListItemExtIEsExtContainerValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ERABInformationListItemExtIEsExtContainer, error)
	encode  func(ERABInformationListItemExtIEsExtContainer, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ERABInformationListItemExtIEsExtContainer, aper.DecodeState) (ERABInformationListItemExtIEsExtContainer, aper.Snapshot)
	compare func(ERABInformationListItemExtIEsExtContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ERABInformationListItemExtIEsExtContainerValueCodec) New(value ERABInformationListItemExtIEsExtContainer) (ERABInformationListItemExtIEsExtContainerAPERValue, error) {
	if c.encode == nil {
		return ERABInformationListItemExtIEsExtContainerAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ERABInformationListItemExtIEsExtContainerAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ERABInformationListItemExtIEsExtContainerAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ERABInformationListItemExtIEsExtContainerAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ERABInformationListItemExtIEsExtContainerValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ERABInformationListItemExtIEsExtContainerAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ERABInformationListItemExtIEsExtContainerAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ERABInformationListItemExtIEsExtContainerAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ERABInformationListItemExtIEsExtContainerAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ERABInformationListItemExtIEsExtContainerAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ERABInformationListItemExtIEsExtContainerValueCodec) EncodeAPER(value ERABInformationListItemExtIEsExtContainerAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c ERABInformationListItemExtIEsExtContainerValueCodec) encodeBudgetValue(value ERABInformationListItemExtIEsExtContainer, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ERABInformationListItemExtIEsExtContainerValueCodec) encodeChanged(value ERABInformationListItemExtIEsExtContainer, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ERABToBeSetupItemBearerSUReqExtIEsExtContainerValueCodec is the concrete ValueCodec[ProtocolExtensionContainer[ERABToBeSetupItemBearerSUReqExtIEsValue]].
type ERABToBeSetupItemBearerSUReqExtIEsExtContainerValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ERABToBeSetupItemBearerSUReqExtIEsExtContainer, error)
	encode  func(ERABToBeSetupItemBearerSUReqExtIEsExtContainer, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ERABToBeSetupItemBearerSUReqExtIEsExtContainer, aper.DecodeState) (ERABToBeSetupItemBearerSUReqExtIEsExtContainer, aper.Snapshot)
	compare func(ERABToBeSetupItemBearerSUReqExtIEsExtContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ERABToBeSetupItemBearerSUReqExtIEsExtContainerValueCodec) New(value ERABToBeSetupItemBearerSUReqExtIEsExtContainer) (ERABToBeSetupItemBearerSUReqExtIEsExtContainerAPERValue, error) {
	if c.encode == nil {
		return ERABToBeSetupItemBearerSUReqExtIEsExtContainerAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ERABToBeSetupItemBearerSUReqExtIEsExtContainerAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ERABToBeSetupItemBearerSUReqExtIEsExtContainerAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ERABToBeSetupItemBearerSUReqExtIEsExtContainerAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ERABToBeSetupItemBearerSUReqExtIEsExtContainerValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ERABToBeSetupItemBearerSUReqExtIEsExtContainerAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ERABToBeSetupItemBearerSUReqExtIEsExtContainerAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ERABToBeSetupItemBearerSUReqExtIEsExtContainerAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ERABToBeSetupItemBearerSUReqExtIEsExtContainerAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ERABToBeSetupItemBearerSUReqExtIEsExtContainerAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ERABToBeSetupItemBearerSUReqExtIEsExtContainerValueCodec) EncodeAPER(value ERABToBeSetupItemBearerSUReqExtIEsExtContainerAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c ERABToBeSetupItemBearerSUReqExtIEsExtContainerValueCodec) encodeBudgetValue(value ERABToBeSetupItemBearerSUReqExtIEsExtContainer, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ERABToBeSetupItemBearerSUReqExtIEsExtContainerValueCodec) encodeChanged(value ERABToBeSetupItemBearerSUReqExtIEsExtContainer, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ERABToBeSetupItemCtxtSUReqExtIEsExtContainerValueCodec is the concrete ValueCodec[ProtocolExtensionContainer[ERABToBeSetupItemCtxtSUReqExtIEsValue]].
type ERABToBeSetupItemCtxtSUReqExtIEsExtContainerValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ERABToBeSetupItemCtxtSUReqExtIEsExtContainer, error)
	encode  func(ERABToBeSetupItemCtxtSUReqExtIEsExtContainer, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ERABToBeSetupItemCtxtSUReqExtIEsExtContainer, aper.DecodeState) (ERABToBeSetupItemCtxtSUReqExtIEsExtContainer, aper.Snapshot)
	compare func(ERABToBeSetupItemCtxtSUReqExtIEsExtContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ERABToBeSetupItemCtxtSUReqExtIEsExtContainerValueCodec) New(value ERABToBeSetupItemCtxtSUReqExtIEsExtContainer) (ERABToBeSetupItemCtxtSUReqExtIEsExtContainerAPERValue, error) {
	if c.encode == nil {
		return ERABToBeSetupItemCtxtSUReqExtIEsExtContainerAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ERABToBeSetupItemCtxtSUReqExtIEsExtContainerAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ERABToBeSetupItemCtxtSUReqExtIEsExtContainerAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ERABToBeSetupItemCtxtSUReqExtIEsExtContainerAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ERABToBeSetupItemCtxtSUReqExtIEsExtContainerValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ERABToBeSetupItemCtxtSUReqExtIEsExtContainerAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ERABToBeSetupItemCtxtSUReqExtIEsExtContainerAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ERABToBeSetupItemCtxtSUReqExtIEsExtContainerAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ERABToBeSetupItemCtxtSUReqExtIEsExtContainerAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ERABToBeSetupItemCtxtSUReqExtIEsExtContainerAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ERABToBeSetupItemCtxtSUReqExtIEsExtContainerValueCodec) EncodeAPER(value ERABToBeSetupItemCtxtSUReqExtIEsExtContainerAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c ERABToBeSetupItemCtxtSUReqExtIEsExtContainerValueCodec) encodeBudgetValue(value ERABToBeSetupItemCtxtSUReqExtIEsExtContainer, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ERABToBeSetupItemCtxtSUReqExtIEsExtContainerValueCodec) encodeChanged(value ERABToBeSetupItemCtxtSUReqExtIEsExtContainer, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ErrorIndicationIEFieldValueCodec is the concrete ValueCodec[ProtocolIEField[ErrorIndicationIEValue]].
type ErrorIndicationIEFieldValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ErrorIndicationIEField, error)
	encode  func(ErrorIndicationIEField, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ErrorIndicationIEField, aper.DecodeState) (ErrorIndicationIEField, aper.Snapshot)
	compare func(ErrorIndicationIEField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ErrorIndicationIEFieldValueCodec) New(value ErrorIndicationIEField) (ErrorIndicationIEFieldAPERValue, error) {
	if c.encode == nil {
		return ErrorIndicationIEFieldAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ErrorIndicationIEFieldAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ErrorIndicationIEFieldAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ErrorIndicationIEFieldAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ErrorIndicationIEFieldValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ErrorIndicationIEFieldAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ErrorIndicationIEFieldAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ErrorIndicationIEFieldAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ErrorIndicationIEFieldAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ErrorIndicationIEFieldAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ErrorIndicationIEFieldValueCodec) EncodeAPER(value ErrorIndicationIEFieldAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c ErrorIndicationIEFieldValueCodec) encodeBudgetValue(value ErrorIndicationIEField, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ErrorIndicationIEFieldValueCodec) encodeChanged(value ErrorIndicationIEField, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// RetrieveUEInformationIEFieldValueCodec is the concrete ValueCodec[ProtocolIEField[RetrieveUEInformationIEValue]].
type RetrieveUEInformationIEFieldValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (RetrieveUEInformationIEField, error)
	encode  func(RetrieveUEInformationIEField, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(RetrieveUEInformationIEField, aper.DecodeState) (RetrieveUEInformationIEField, aper.Snapshot)
	compare func(RetrieveUEInformationIEField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c RetrieveUEInformationIEFieldValueCodec) New(value RetrieveUEInformationIEField) (RetrieveUEInformationIEFieldAPERValue, error) {
	if c.encode == nil {
		return RetrieveUEInformationIEFieldAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return RetrieveUEInformationIEFieldAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return RetrieveUEInformationIEFieldAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return RetrieveUEInformationIEFieldAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c RetrieveUEInformationIEFieldValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (RetrieveUEInformationIEFieldAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return RetrieveUEInformationIEFieldAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return RetrieveUEInformationIEFieldAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return RetrieveUEInformationIEFieldAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return RetrieveUEInformationIEFieldAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c RetrieveUEInformationIEFieldValueCodec) EncodeAPER(value RetrieveUEInformationIEFieldAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c RetrieveUEInformationIEFieldValueCodec) encodeBudgetValue(value RetrieveUEInformationIEField, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c RetrieveUEInformationIEFieldValueCodec) encodeChanged(value RetrieveUEInformationIEField, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// SecondaryRATDataUsageReportItemIEFieldValueCodec is the concrete ValueCodec[ProtocolIEField[SecondaryRATDataUsageReportItemIEValue]].
type SecondaryRATDataUsageReportItemIEFieldValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (SecondaryRATDataUsageReportItemIEField, error)
	encode  func(SecondaryRATDataUsageReportItemIEField, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(SecondaryRATDataUsageReportItemIEField, aper.DecodeState) (SecondaryRATDataUsageReportItemIEField, aper.Snapshot)
	compare func(SecondaryRATDataUsageReportItemIEField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c SecondaryRATDataUsageReportItemIEFieldValueCodec) New(value SecondaryRATDataUsageReportItemIEField) (SecondaryRATDataUsageReportItemIEFieldAPERValue, error) {
	if c.encode == nil {
		return SecondaryRATDataUsageReportItemIEFieldAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return SecondaryRATDataUsageReportItemIEFieldAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return SecondaryRATDataUsageReportItemIEFieldAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return SecondaryRATDataUsageReportItemIEFieldAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c SecondaryRATDataUsageReportItemIEFieldValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (SecondaryRATDataUsageReportItemIEFieldAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return SecondaryRATDataUsageReportItemIEFieldAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return SecondaryRATDataUsageReportItemIEFieldAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return SecondaryRATDataUsageReportItemIEFieldAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return SecondaryRATDataUsageReportItemIEFieldAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c SecondaryRATDataUsageReportItemIEFieldValueCodec) EncodeAPER(value SecondaryRATDataUsageReportItemIEFieldAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c SecondaryRATDataUsageReportItemIEFieldValueCodec) encodeBudgetValue(value SecondaryRATDataUsageReportItemIEField, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c SecondaryRATDataUsageReportItemIEFieldValueCodec) encodeChanged(value SecondaryRATDataUsageReportItemIEField, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// UEContextSuspendResponseIEFieldValueCodec is the concrete ValueCodec[ProtocolIEField[UEContextSuspendResponseIEValue]].
type UEContextSuspendResponseIEFieldValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (UEContextSuspendResponseIEField, error)
	encode  func(UEContextSuspendResponseIEField, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(UEContextSuspendResponseIEField, aper.DecodeState) (UEContextSuspendResponseIEField, aper.Snapshot)
	compare func(UEContextSuspendResponseIEField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c UEContextSuspendResponseIEFieldValueCodec) New(value UEContextSuspendResponseIEField) (UEContextSuspendResponseIEFieldAPERValue, error) {
	if c.encode == nil {
		return UEContextSuspendResponseIEFieldAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return UEContextSuspendResponseIEFieldAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return UEContextSuspendResponseIEFieldAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return UEContextSuspendResponseIEFieldAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c UEContextSuspendResponseIEFieldValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (UEContextSuspendResponseIEFieldAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return UEContextSuspendResponseIEFieldAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return UEContextSuspendResponseIEFieldAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return UEContextSuspendResponseIEFieldAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return UEContextSuspendResponseIEFieldAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c UEContextSuspendResponseIEFieldValueCodec) EncodeAPER(value UEContextSuspendResponseIEFieldAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c UEContextSuspendResponseIEFieldValueCodec) encodeBudgetValue(value UEContextSuspendResponseIEField, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c UEContextSuspendResponseIEFieldValueCodec) encodeChanged(value UEContextSuspendResponseIEField, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ErrorIndicationIEContainerValueCodec is the concrete ValueCodec[ProtocolIEContainer[ErrorIndicationIEValue]].
type ErrorIndicationIEContainerValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ErrorIndicationIEContainer, error)
	encode  func(ErrorIndicationIEContainer, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ErrorIndicationIEContainer, aper.DecodeState) (ErrorIndicationIEContainer, aper.Snapshot)
	compare func(ErrorIndicationIEContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ErrorIndicationIEContainerValueCodec) New(value ErrorIndicationIEContainer) (ErrorIndicationIEContainerAPERValue, error) {
	if c.encode == nil {
		return ErrorIndicationIEContainerAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ErrorIndicationIEContainerAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ErrorIndicationIEContainerAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ErrorIndicationIEContainerAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ErrorIndicationIEContainerValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ErrorIndicationIEContainerAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ErrorIndicationIEContainerAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ErrorIndicationIEContainerAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ErrorIndicationIEContainerAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ErrorIndicationIEContainerAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ErrorIndicationIEContainerValueCodec) EncodeAPER(value ErrorIndicationIEContainerAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c ErrorIndicationIEContainerValueCodec) encodeBudgetValue(value ErrorIndicationIEContainer, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ErrorIndicationIEContainerValueCodec) encodeChanged(value ErrorIndicationIEContainer, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// RetrieveUEInformationIEContainerValueCodec is the concrete ValueCodec[ProtocolIEContainer[RetrieveUEInformationIEValue]].
type RetrieveUEInformationIEContainerValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (RetrieveUEInformationIEContainer, error)
	encode  func(RetrieveUEInformationIEContainer, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(RetrieveUEInformationIEContainer, aper.DecodeState) (RetrieveUEInformationIEContainer, aper.Snapshot)
	compare func(RetrieveUEInformationIEContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c RetrieveUEInformationIEContainerValueCodec) New(value RetrieveUEInformationIEContainer) (RetrieveUEInformationIEContainerAPERValue, error) {
	if c.encode == nil {
		return RetrieveUEInformationIEContainerAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return RetrieveUEInformationIEContainerAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return RetrieveUEInformationIEContainerAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return RetrieveUEInformationIEContainerAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c RetrieveUEInformationIEContainerValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (RetrieveUEInformationIEContainerAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return RetrieveUEInformationIEContainerAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return RetrieveUEInformationIEContainerAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return RetrieveUEInformationIEContainerAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return RetrieveUEInformationIEContainerAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c RetrieveUEInformationIEContainerValueCodec) EncodeAPER(value RetrieveUEInformationIEContainerAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c RetrieveUEInformationIEContainerValueCodec) encodeBudgetValue(value RetrieveUEInformationIEContainer, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c RetrieveUEInformationIEContainerValueCodec) encodeChanged(value RetrieveUEInformationIEContainer, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// SecondaryRATDataUsageReportItemIEContainerValueCodec is the concrete ValueCodec[ProtocolIEContainer[SecondaryRATDataUsageReportItemIEValue]].
type SecondaryRATDataUsageReportItemIEContainerValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (SecondaryRATDataUsageReportItemIEContainer, error)
	encode  func(SecondaryRATDataUsageReportItemIEContainer, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(SecondaryRATDataUsageReportItemIEContainer, aper.DecodeState) (SecondaryRATDataUsageReportItemIEContainer, aper.Snapshot)
	compare func(SecondaryRATDataUsageReportItemIEContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c SecondaryRATDataUsageReportItemIEContainerValueCodec) New(value SecondaryRATDataUsageReportItemIEContainer) (SecondaryRATDataUsageReportItemIEContainerAPERValue, error) {
	if c.encode == nil {
		return SecondaryRATDataUsageReportItemIEContainerAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return SecondaryRATDataUsageReportItemIEContainerAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return SecondaryRATDataUsageReportItemIEContainerAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return SecondaryRATDataUsageReportItemIEContainerAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c SecondaryRATDataUsageReportItemIEContainerValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (SecondaryRATDataUsageReportItemIEContainerAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return SecondaryRATDataUsageReportItemIEContainerAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return SecondaryRATDataUsageReportItemIEContainerAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return SecondaryRATDataUsageReportItemIEContainerAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return SecondaryRATDataUsageReportItemIEContainerAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c SecondaryRATDataUsageReportItemIEContainerValueCodec) EncodeAPER(value SecondaryRATDataUsageReportItemIEContainerAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c SecondaryRATDataUsageReportItemIEContainerValueCodec) encodeBudgetValue(value SecondaryRATDataUsageReportItemIEContainer, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c SecondaryRATDataUsageReportItemIEContainerValueCodec) encodeChanged(value SecondaryRATDataUsageReportItemIEContainer, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func BridgeSecondaryRATDataUsageReportItemIEValueCaptureS1APProtocolIEContainer(v *SecondaryRATDataUsageReportItemIEContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeSecondaryRATDataUsageReportItemIEValueCaptureS1APProtocolIEField(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeSecondaryRATDataUsageReportItemIEValueCompareS1APProtocolIEContainer(v *SecondaryRATDataUsageReportItemIEContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeSecondaryRATDataUsageReportItemIEValueCompareS1APProtocolIEField(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}

// UEContextSuspendResponseIEContainerValueCodec is the concrete ValueCodec[ProtocolIEContainer[UEContextSuspendResponseIEValue]].
type UEContextSuspendResponseIEContainerValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (UEContextSuspendResponseIEContainer, error)
	encode  func(UEContextSuspendResponseIEContainer, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(UEContextSuspendResponseIEContainer, aper.DecodeState) (UEContextSuspendResponseIEContainer, aper.Snapshot)
	compare func(UEContextSuspendResponseIEContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c UEContextSuspendResponseIEContainerValueCodec) New(value UEContextSuspendResponseIEContainer) (UEContextSuspendResponseIEContainerAPERValue, error) {
	if c.encode == nil {
		return UEContextSuspendResponseIEContainerAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return UEContextSuspendResponseIEContainerAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return UEContextSuspendResponseIEContainerAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return UEContextSuspendResponseIEContainerAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c UEContextSuspendResponseIEContainerValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (UEContextSuspendResponseIEContainerAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return UEContextSuspendResponseIEContainerAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return UEContextSuspendResponseIEContainerAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return UEContextSuspendResponseIEContainerAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return UEContextSuspendResponseIEContainerAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c UEContextSuspendResponseIEContainerValueCodec) EncodeAPER(value UEContextSuspendResponseIEContainerAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c UEContextSuspendResponseIEContainerValueCodec) encodeBudgetValue(value UEContextSuspendResponseIEContainer, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c UEContextSuspendResponseIEContainerValueCodec) encodeChanged(value UEContextSuspendResponseIEContainer, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ErrorIndicationIEValueProtocolErrorIEContainerListValueCodec is the concrete ValueCodec[ProtocolErrorIEContainerList[ErrorIndicationIEValue]].
type ErrorIndicationIEValueProtocolErrorIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ErrorIndicationIEValueProtocolErrorIEContainerList, error)
	encode  func(ErrorIndicationIEValueProtocolErrorIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ErrorIndicationIEValueProtocolErrorIEContainerList, aper.DecodeState) (ErrorIndicationIEValueProtocolErrorIEContainerList, aper.Snapshot)
	compare func(ErrorIndicationIEValueProtocolErrorIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ErrorIndicationIEValueProtocolErrorIEContainerListValueCodec) New(value ErrorIndicationIEValueProtocolErrorIEContainerList) (ErrorIndicationIEValueProtocolErrorIEContainerListAPERValue, error) {
	if c.encode == nil {
		return ErrorIndicationIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ErrorIndicationIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ErrorIndicationIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ErrorIndicationIEValueProtocolErrorIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ErrorIndicationIEValueProtocolErrorIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ErrorIndicationIEValueProtocolErrorIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ErrorIndicationIEValueProtocolErrorIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ErrorIndicationIEValueProtocolErrorIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ErrorIndicationIEValueProtocolErrorIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ErrorIndicationIEValueProtocolErrorIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ErrorIndicationIEValueProtocolErrorIEContainerListValueCodec) EncodeAPER(value ErrorIndicationIEValueProtocolErrorIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c ErrorIndicationIEValueProtocolErrorIEContainerListValueCodec) encodeBudgetValue(value ErrorIndicationIEValueProtocolErrorIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ErrorIndicationIEValueProtocolErrorIEContainerListValueCodec) encodeChanged(value ErrorIndicationIEValueProtocolErrorIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ErrorIndicationIEValueProtocolErrorIEContainerList is the concrete ProtocolErrorIEContainerList[ErrorIndicationIEValue].
type ErrorIndicationIEValueProtocolErrorIEContainerList []ErrorIndicationIEValueProtocolIESingleContainer

func BridgeErrorIndicationIEValueCaptureS1APProtocolErrorIEContainerList(v *ErrorIndicationIEValueProtocolErrorIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeErrorIndicationIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeErrorIndicationIEValueCompareS1APProtocolErrorIEContainerList(v *ErrorIndicationIEValueProtocolErrorIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeErrorIndicationIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}

// RetrieveUEInformationIEValueProtocolErrorIEContainerListValueCodec is the concrete ValueCodec[ProtocolErrorIEContainerList[RetrieveUEInformationIEValue]].
type RetrieveUEInformationIEValueProtocolErrorIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (RetrieveUEInformationIEValueProtocolErrorIEContainerList, error)
	encode  func(RetrieveUEInformationIEValueProtocolErrorIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(RetrieveUEInformationIEValueProtocolErrorIEContainerList, aper.DecodeState) (RetrieveUEInformationIEValueProtocolErrorIEContainerList, aper.Snapshot)
	compare func(RetrieveUEInformationIEValueProtocolErrorIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c RetrieveUEInformationIEValueProtocolErrorIEContainerListValueCodec) New(value RetrieveUEInformationIEValueProtocolErrorIEContainerList) (RetrieveUEInformationIEValueProtocolErrorIEContainerListAPERValue, error) {
	if c.encode == nil {
		return RetrieveUEInformationIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return RetrieveUEInformationIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return RetrieveUEInformationIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return RetrieveUEInformationIEValueProtocolErrorIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c RetrieveUEInformationIEValueProtocolErrorIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (RetrieveUEInformationIEValueProtocolErrorIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return RetrieveUEInformationIEValueProtocolErrorIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return RetrieveUEInformationIEValueProtocolErrorIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return RetrieveUEInformationIEValueProtocolErrorIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return RetrieveUEInformationIEValueProtocolErrorIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c RetrieveUEInformationIEValueProtocolErrorIEContainerListValueCodec) EncodeAPER(value RetrieveUEInformationIEValueProtocolErrorIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c RetrieveUEInformationIEValueProtocolErrorIEContainerListValueCodec) encodeBudgetValue(value RetrieveUEInformationIEValueProtocolErrorIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c RetrieveUEInformationIEValueProtocolErrorIEContainerListValueCodec) encodeChanged(value RetrieveUEInformationIEValueProtocolErrorIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// RetrieveUEInformationIEValueProtocolErrorIEContainerList is the concrete ProtocolErrorIEContainerList[RetrieveUEInformationIEValue].
type RetrieveUEInformationIEValueProtocolErrorIEContainerList []RetrieveUEInformationIEValueProtocolIESingleContainer

func BridgeRetrieveUEInformationIEValueCaptureS1APProtocolErrorIEContainerList(v *RetrieveUEInformationIEValueProtocolErrorIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeRetrieveUEInformationIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeRetrieveUEInformationIEValueCompareS1APProtocolErrorIEContainerList(v *RetrieveUEInformationIEValueProtocolErrorIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeRetrieveUEInformationIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}

// SecondaryRATDataUsageReportItemIEValueProtocolErrorIEContainerListValueCodec is the concrete ValueCodec[ProtocolErrorIEContainerList[SecondaryRATDataUsageReportItemIEValue]].
type SecondaryRATDataUsageReportItemIEValueProtocolErrorIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (SecondaryRATDataUsageReportItemIEValueProtocolErrorIEContainerList, error)
	encode  func(SecondaryRATDataUsageReportItemIEValueProtocolErrorIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(SecondaryRATDataUsageReportItemIEValueProtocolErrorIEContainerList, aper.DecodeState) (SecondaryRATDataUsageReportItemIEValueProtocolErrorIEContainerList, aper.Snapshot)
	compare func(SecondaryRATDataUsageReportItemIEValueProtocolErrorIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c SecondaryRATDataUsageReportItemIEValueProtocolErrorIEContainerListValueCodec) New(value SecondaryRATDataUsageReportItemIEValueProtocolErrorIEContainerList) (SecondaryRATDataUsageReportItemIEValueProtocolErrorIEContainerListAPERValue, error) {
	if c.encode == nil {
		return SecondaryRATDataUsageReportItemIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return SecondaryRATDataUsageReportItemIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return SecondaryRATDataUsageReportItemIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return SecondaryRATDataUsageReportItemIEValueProtocolErrorIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c SecondaryRATDataUsageReportItemIEValueProtocolErrorIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (SecondaryRATDataUsageReportItemIEValueProtocolErrorIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return SecondaryRATDataUsageReportItemIEValueProtocolErrorIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return SecondaryRATDataUsageReportItemIEValueProtocolErrorIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return SecondaryRATDataUsageReportItemIEValueProtocolErrorIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return SecondaryRATDataUsageReportItemIEValueProtocolErrorIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c SecondaryRATDataUsageReportItemIEValueProtocolErrorIEContainerListValueCodec) EncodeAPER(value SecondaryRATDataUsageReportItemIEValueProtocolErrorIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c SecondaryRATDataUsageReportItemIEValueProtocolErrorIEContainerListValueCodec) encodeBudgetValue(value SecondaryRATDataUsageReportItemIEValueProtocolErrorIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c SecondaryRATDataUsageReportItemIEValueProtocolErrorIEContainerListValueCodec) encodeChanged(value SecondaryRATDataUsageReportItemIEValueProtocolErrorIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// SecondaryRATDataUsageReportItemIEValueProtocolErrorIEContainerList is the concrete ProtocolErrorIEContainerList[SecondaryRATDataUsageReportItemIEValue].
type SecondaryRATDataUsageReportItemIEValueProtocolErrorIEContainerList []SecondaryRATDataUsageReportItemIEValueProtocolIESingleContainer

func BridgeSecondaryRATDataUsageReportItemIEValueCaptureS1APProtocolErrorIEContainerList(v *SecondaryRATDataUsageReportItemIEValueProtocolErrorIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeSecondaryRATDataUsageReportItemIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeSecondaryRATDataUsageReportItemIEValueCompareS1APProtocolErrorIEContainerList(v *SecondaryRATDataUsageReportItemIEValueProtocolErrorIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeSecondaryRATDataUsageReportItemIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}

// UEContextSuspendResponseIEValueProtocolErrorIEContainerListValueCodec is the concrete ValueCodec[ProtocolErrorIEContainerList[UEContextSuspendResponseIEValue]].
type UEContextSuspendResponseIEValueProtocolErrorIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (UEContextSuspendResponseIEValueProtocolErrorIEContainerList, error)
	encode  func(UEContextSuspendResponseIEValueProtocolErrorIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(UEContextSuspendResponseIEValueProtocolErrorIEContainerList, aper.DecodeState) (UEContextSuspendResponseIEValueProtocolErrorIEContainerList, aper.Snapshot)
	compare func(UEContextSuspendResponseIEValueProtocolErrorIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c UEContextSuspendResponseIEValueProtocolErrorIEContainerListValueCodec) New(value UEContextSuspendResponseIEValueProtocolErrorIEContainerList) (UEContextSuspendResponseIEValueProtocolErrorIEContainerListAPERValue, error) {
	if c.encode == nil {
		return UEContextSuspendResponseIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return UEContextSuspendResponseIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return UEContextSuspendResponseIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return UEContextSuspendResponseIEValueProtocolErrorIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c UEContextSuspendResponseIEValueProtocolErrorIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (UEContextSuspendResponseIEValueProtocolErrorIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return UEContextSuspendResponseIEValueProtocolErrorIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return UEContextSuspendResponseIEValueProtocolErrorIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return UEContextSuspendResponseIEValueProtocolErrorIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return UEContextSuspendResponseIEValueProtocolErrorIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c UEContextSuspendResponseIEValueProtocolErrorIEContainerListValueCodec) EncodeAPER(value UEContextSuspendResponseIEValueProtocolErrorIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c UEContextSuspendResponseIEValueProtocolErrorIEContainerListValueCodec) encodeBudgetValue(value UEContextSuspendResponseIEValueProtocolErrorIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c UEContextSuspendResponseIEValueProtocolErrorIEContainerListValueCodec) encodeChanged(value UEContextSuspendResponseIEValueProtocolErrorIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// UEContextSuspendResponseIEValueProtocolErrorIEContainerList is the concrete ProtocolErrorIEContainerList[UEContextSuspendResponseIEValue].
type UEContextSuspendResponseIEValueProtocolErrorIEContainerList []UEContextSuspendResponseIEValueProtocolIESingleContainer

// ErrorIndicationIEValueProtocolIEContainerListValueCodec is the concrete ValueCodec[ProtocolIEContainerList[ErrorIndicationIEValue]].
type ErrorIndicationIEValueProtocolIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ErrorIndicationIEValueProtocolIEContainerList, error)
	encode  func(ErrorIndicationIEValueProtocolIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ErrorIndicationIEValueProtocolIEContainerList, aper.DecodeState) (ErrorIndicationIEValueProtocolIEContainerList, aper.Snapshot)
	compare func(ErrorIndicationIEValueProtocolIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ErrorIndicationIEValueProtocolIEContainerListValueCodec) New(value ErrorIndicationIEValueProtocolIEContainerList) (ErrorIndicationIEValueProtocolIEContainerListAPERValue, error) {
	if c.encode == nil {
		return ErrorIndicationIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ErrorIndicationIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ErrorIndicationIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ErrorIndicationIEValueProtocolIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ErrorIndicationIEValueProtocolIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ErrorIndicationIEValueProtocolIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ErrorIndicationIEValueProtocolIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ErrorIndicationIEValueProtocolIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ErrorIndicationIEValueProtocolIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ErrorIndicationIEValueProtocolIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ErrorIndicationIEValueProtocolIEContainerListValueCodec) EncodeAPER(value ErrorIndicationIEValueProtocolIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c ErrorIndicationIEValueProtocolIEContainerListValueCodec) encodeBudgetValue(value ErrorIndicationIEValueProtocolIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ErrorIndicationIEValueProtocolIEContainerListValueCodec) encodeChanged(value ErrorIndicationIEValueProtocolIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ErrorIndicationIEValueProtocolIEContainerList is the concrete ProtocolIEContainerList[ErrorIndicationIEValue].
type ErrorIndicationIEValueProtocolIEContainerList []ErrorIndicationIEValueProtocolIESingleContainer

func BridgeErrorIndicationIEValueCaptureS1APProtocolIEContainerList(v *ErrorIndicationIEValueProtocolIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeErrorIndicationIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeErrorIndicationIEValueCompareS1APProtocolIEContainerList(v *ErrorIndicationIEValueProtocolIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeErrorIndicationIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}

// RetrieveUEInformationIEValueProtocolIEContainerListValueCodec is the concrete ValueCodec[ProtocolIEContainerList[RetrieveUEInformationIEValue]].
type RetrieveUEInformationIEValueProtocolIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (RetrieveUEInformationIEValueProtocolIEContainerList, error)
	encode  func(RetrieveUEInformationIEValueProtocolIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(RetrieveUEInformationIEValueProtocolIEContainerList, aper.DecodeState) (RetrieveUEInformationIEValueProtocolIEContainerList, aper.Snapshot)
	compare func(RetrieveUEInformationIEValueProtocolIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c RetrieveUEInformationIEValueProtocolIEContainerListValueCodec) New(value RetrieveUEInformationIEValueProtocolIEContainerList) (RetrieveUEInformationIEValueProtocolIEContainerListAPERValue, error) {
	if c.encode == nil {
		return RetrieveUEInformationIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return RetrieveUEInformationIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return RetrieveUEInformationIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return RetrieveUEInformationIEValueProtocolIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c RetrieveUEInformationIEValueProtocolIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (RetrieveUEInformationIEValueProtocolIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return RetrieveUEInformationIEValueProtocolIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return RetrieveUEInformationIEValueProtocolIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return RetrieveUEInformationIEValueProtocolIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return RetrieveUEInformationIEValueProtocolIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c RetrieveUEInformationIEValueProtocolIEContainerListValueCodec) EncodeAPER(value RetrieveUEInformationIEValueProtocolIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c RetrieveUEInformationIEValueProtocolIEContainerListValueCodec) encodeBudgetValue(value RetrieveUEInformationIEValueProtocolIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c RetrieveUEInformationIEValueProtocolIEContainerListValueCodec) encodeChanged(value RetrieveUEInformationIEValueProtocolIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// RetrieveUEInformationIEValueProtocolIEContainerList is the concrete ProtocolIEContainerList[RetrieveUEInformationIEValue].
type RetrieveUEInformationIEValueProtocolIEContainerList []RetrieveUEInformationIEValueProtocolIESingleContainer

func BridgeRetrieveUEInformationIEValueCaptureS1APProtocolIEContainerList(v *RetrieveUEInformationIEValueProtocolIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeRetrieveUEInformationIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeRetrieveUEInformationIEValueCompareS1APProtocolIEContainerList(v *RetrieveUEInformationIEValueProtocolIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeRetrieveUEInformationIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}

// SecondaryRATDataUsageReportItemIEValueProtocolIEContainerListValueCodec is the concrete ValueCodec[ProtocolIEContainerList[SecondaryRATDataUsageReportItemIEValue]].
type SecondaryRATDataUsageReportItemIEValueProtocolIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (SecondaryRATDataUsageReportItemIEValueProtocolIEContainerList, error)
	encode  func(SecondaryRATDataUsageReportItemIEValueProtocolIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(SecondaryRATDataUsageReportItemIEValueProtocolIEContainerList, aper.DecodeState) (SecondaryRATDataUsageReportItemIEValueProtocolIEContainerList, aper.Snapshot)
	compare func(SecondaryRATDataUsageReportItemIEValueProtocolIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c SecondaryRATDataUsageReportItemIEValueProtocolIEContainerListValueCodec) New(value SecondaryRATDataUsageReportItemIEValueProtocolIEContainerList) (SecondaryRATDataUsageReportItemIEValueProtocolIEContainerListAPERValue, error) {
	if c.encode == nil {
		return SecondaryRATDataUsageReportItemIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return SecondaryRATDataUsageReportItemIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return SecondaryRATDataUsageReportItemIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return SecondaryRATDataUsageReportItemIEValueProtocolIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c SecondaryRATDataUsageReportItemIEValueProtocolIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (SecondaryRATDataUsageReportItemIEValueProtocolIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return SecondaryRATDataUsageReportItemIEValueProtocolIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return SecondaryRATDataUsageReportItemIEValueProtocolIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return SecondaryRATDataUsageReportItemIEValueProtocolIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return SecondaryRATDataUsageReportItemIEValueProtocolIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c SecondaryRATDataUsageReportItemIEValueProtocolIEContainerListValueCodec) EncodeAPER(value SecondaryRATDataUsageReportItemIEValueProtocolIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c SecondaryRATDataUsageReportItemIEValueProtocolIEContainerListValueCodec) encodeBudgetValue(value SecondaryRATDataUsageReportItemIEValueProtocolIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c SecondaryRATDataUsageReportItemIEValueProtocolIEContainerListValueCodec) encodeChanged(value SecondaryRATDataUsageReportItemIEValueProtocolIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// SecondaryRATDataUsageReportItemIEValueProtocolIEContainerList is the concrete ProtocolIEContainerList[SecondaryRATDataUsageReportItemIEValue].
type SecondaryRATDataUsageReportItemIEValueProtocolIEContainerList []SecondaryRATDataUsageReportItemIEValueProtocolIESingleContainer

func BridgeSecondaryRATDataUsageReportItemIEValueCaptureS1APProtocolIEContainerList(v *SecondaryRATDataUsageReportItemIEValueProtocolIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeSecondaryRATDataUsageReportItemIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeSecondaryRATDataUsageReportItemIEValueCompareS1APProtocolIEContainerList(v *SecondaryRATDataUsageReportItemIEValueProtocolIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeSecondaryRATDataUsageReportItemIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}

// UEContextSuspendResponseIEValueProtocolIEContainerListValueCodec is the concrete ValueCodec[ProtocolIEContainerList[UEContextSuspendResponseIEValue]].
type UEContextSuspendResponseIEValueProtocolIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (UEContextSuspendResponseIEValueProtocolIEContainerList, error)
	encode  func(UEContextSuspendResponseIEValueProtocolIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(UEContextSuspendResponseIEValueProtocolIEContainerList, aper.DecodeState) (UEContextSuspendResponseIEValueProtocolIEContainerList, aper.Snapshot)
	compare func(UEContextSuspendResponseIEValueProtocolIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c UEContextSuspendResponseIEValueProtocolIEContainerListValueCodec) New(value UEContextSuspendResponseIEValueProtocolIEContainerList) (UEContextSuspendResponseIEValueProtocolIEContainerListAPERValue, error) {
	if c.encode == nil {
		return UEContextSuspendResponseIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return UEContextSuspendResponseIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return UEContextSuspendResponseIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return UEContextSuspendResponseIEValueProtocolIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c UEContextSuspendResponseIEValueProtocolIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (UEContextSuspendResponseIEValueProtocolIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return UEContextSuspendResponseIEValueProtocolIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return UEContextSuspendResponseIEValueProtocolIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return UEContextSuspendResponseIEValueProtocolIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return UEContextSuspendResponseIEValueProtocolIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c UEContextSuspendResponseIEValueProtocolIEContainerListValueCodec) EncodeAPER(value UEContextSuspendResponseIEValueProtocolIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c UEContextSuspendResponseIEValueProtocolIEContainerListValueCodec) encodeBudgetValue(value UEContextSuspendResponseIEValueProtocolIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c UEContextSuspendResponseIEValueProtocolIEContainerListValueCodec) encodeChanged(value UEContextSuspendResponseIEValueProtocolIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// UEContextSuspendResponseIEValueProtocolIEContainerList is the concrete ProtocolIEContainerList[UEContextSuspendResponseIEValue].
type UEContextSuspendResponseIEValueProtocolIEContainerList []UEContextSuspendResponseIEValueProtocolIESingleContainer

// ErrorIndicationIEValueERABIEContainerListAPERValue is the concrete APERValue[ERABIEContainerList[ErrorIndicationIEValue]].
type ErrorIndicationIEValueERABIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         ErrorIndicationIEValueERABIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ErrorIndicationIEValueERABIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ErrorIndicationIEValueERABIEContainerListAPERValue) WithoutReplay() ErrorIndicationIEValueERABIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ErrorIndicationIEValueProtocolIESingleContainer is the concrete ProtocolIESingleContainer[ErrorIndicationIEValue].
type ErrorIndicationIEValueProtocolIESingleContainer = ErrorIndicationIEField

func BridgeErrorIndicationIEValueCaptureS1APProtocolIESingleContainer(v *ErrorIndicationIEValueProtocolIESingleContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeErrorIndicationIEValueCaptureS1APProtocolIEField(v, s)
	s.End(f, nil, false)
}
func BridgeErrorIndicationIEValueCompareS1APProtocolIESingleContainer(v *ErrorIndicationIEValueProtocolIESingleContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeErrorIndicationIEValueCompareS1APProtocolIEField(v, s)
	s.End(f, aper.Snapshot{}, false)
}

// RetrieveUEInformationIEValueERABIEContainerListAPERValue is the concrete APERValue[ERABIEContainerList[RetrieveUEInformationIEValue]].
type RetrieveUEInformationIEValueERABIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         RetrieveUEInformationIEValueERABIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v RetrieveUEInformationIEValueERABIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v RetrieveUEInformationIEValueERABIEContainerListAPERValue) WithoutReplay() RetrieveUEInformationIEValueERABIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// RetrieveUEInformationIEValueProtocolIESingleContainer is the concrete ProtocolIESingleContainer[RetrieveUEInformationIEValue].
type RetrieveUEInformationIEValueProtocolIESingleContainer = RetrieveUEInformationIEField

func BridgeRetrieveUEInformationIEValueCaptureS1APProtocolIESingleContainer(v *RetrieveUEInformationIEValueProtocolIESingleContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeRetrieveUEInformationIEValueCaptureS1APProtocolIEField(v, s)
	s.End(f, nil, false)
}
func BridgeRetrieveUEInformationIEValueCompareS1APProtocolIESingleContainer(v *RetrieveUEInformationIEValueProtocolIESingleContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeRetrieveUEInformationIEValueCompareS1APProtocolIEField(v, s)
	s.End(f, aper.Snapshot{}, false)
}

// SecondaryRATDataUsageReportItemIEValueERABIEContainerListAPERValue is the concrete APERValue[ERABIEContainerList[SecondaryRATDataUsageReportItemIEValue]].
type SecondaryRATDataUsageReportItemIEValueERABIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         SecondaryRATDataUsageReportItemIEValueERABIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v SecondaryRATDataUsageReportItemIEValueERABIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v SecondaryRATDataUsageReportItemIEValueERABIEContainerListAPERValue) WithoutReplay() SecondaryRATDataUsageReportItemIEValueERABIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// UEContextSuspendResponseIEValueERABIEContainerListAPERValue is the concrete APERValue[ERABIEContainerList[UEContextSuspendResponseIEValue]].
type UEContextSuspendResponseIEValueERABIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         UEContextSuspendResponseIEValueERABIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v UEContextSuspendResponseIEValueERABIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v UEContextSuspendResponseIEValueERABIEContainerListAPERValue) WithoutReplay() UEContextSuspendResponseIEValueERABIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// UEContextSuspendResponseIEValueProtocolIESingleContainer is the concrete ProtocolIESingleContainer[UEContextSuspendResponseIEValue].
type UEContextSuspendResponseIEValueProtocolIESingleContainer = UEContextSuspendResponseIEField

// ERABInformationListItemExtIEsExtFieldAPERValue is the concrete APERValue[ProtocolExtensionField[ERABInformationListItemExtIEsValue]].
type ERABInformationListItemExtIEsExtFieldAPERValue struct {
	context       s00.BridgeCodecContext
	Value         ERABInformationListItemExtIEsExtField
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ERABInformationListItemExtIEsExtFieldAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ERABInformationListItemExtIEsExtFieldAPERValue) WithoutReplay() ERABInformationListItemExtIEsExtFieldAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ERABToBeSetupItemBearerSUReqExtIEsExtFieldAPERValue is the concrete APERValue[ProtocolExtensionField[ERABToBeSetupItemBearerSUReqExtIEsValue]].
type ERABToBeSetupItemBearerSUReqExtIEsExtFieldAPERValue struct {
	context       s00.BridgeCodecContext
	Value         ERABToBeSetupItemBearerSUReqExtIEsExtField
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ERABToBeSetupItemBearerSUReqExtIEsExtFieldAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ERABToBeSetupItemBearerSUReqExtIEsExtFieldAPERValue) WithoutReplay() ERABToBeSetupItemBearerSUReqExtIEsExtFieldAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ERABToBeSetupItemCtxtSUReqExtIEsExtFieldAPERValue is the concrete APERValue[ProtocolExtensionField[ERABToBeSetupItemCtxtSUReqExtIEsValue]].
type ERABToBeSetupItemCtxtSUReqExtIEsExtFieldAPERValue struct {
	context       s00.BridgeCodecContext
	Value         ERABToBeSetupItemCtxtSUReqExtIEsExtField
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ERABToBeSetupItemCtxtSUReqExtIEsExtFieldAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ERABToBeSetupItemCtxtSUReqExtIEsExtFieldAPERValue) WithoutReplay() ERABToBeSetupItemCtxtSUReqExtIEsExtFieldAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ERABInformationListItemExtIEsExtContainerAPERValue is the concrete APERValue[ProtocolExtensionContainer[ERABInformationListItemExtIEsValue]].
type ERABInformationListItemExtIEsExtContainerAPERValue struct {
	context       s00.BridgeCodecContext
	Value         ERABInformationListItemExtIEsExtContainer
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ERABInformationListItemExtIEsExtContainerAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ERABInformationListItemExtIEsExtContainerAPERValue) WithoutReplay() ERABInformationListItemExtIEsExtContainerAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ERABToBeSetupItemBearerSUReqExtIEsExtContainerAPERValue is the concrete APERValue[ProtocolExtensionContainer[ERABToBeSetupItemBearerSUReqExtIEsValue]].
type ERABToBeSetupItemBearerSUReqExtIEsExtContainerAPERValue struct {
	context       s00.BridgeCodecContext
	Value         ERABToBeSetupItemBearerSUReqExtIEsExtContainer
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ERABToBeSetupItemBearerSUReqExtIEsExtContainerAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ERABToBeSetupItemBearerSUReqExtIEsExtContainerAPERValue) WithoutReplay() ERABToBeSetupItemBearerSUReqExtIEsExtContainerAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ERABToBeSetupItemCtxtSUReqExtIEsExtContainerAPERValue is the concrete APERValue[ProtocolExtensionContainer[ERABToBeSetupItemCtxtSUReqExtIEsValue]].
type ERABToBeSetupItemCtxtSUReqExtIEsExtContainerAPERValue struct {
	context       s00.BridgeCodecContext
	Value         ERABToBeSetupItemCtxtSUReqExtIEsExtContainer
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ERABToBeSetupItemCtxtSUReqExtIEsExtContainerAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ERABToBeSetupItemCtxtSUReqExtIEsExtContainerAPERValue) WithoutReplay() ERABToBeSetupItemCtxtSUReqExtIEsExtContainerAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ErrorIndicationIEFieldAPERValue is the concrete APERValue[ProtocolIEField[ErrorIndicationIEValue]].
type ErrorIndicationIEFieldAPERValue struct {
	context       s00.BridgeCodecContext
	Value         ErrorIndicationIEField
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ErrorIndicationIEFieldAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ErrorIndicationIEFieldAPERValue) WithoutReplay() ErrorIndicationIEFieldAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// RetrieveUEInformationIEFieldAPERValue is the concrete APERValue[ProtocolIEField[RetrieveUEInformationIEValue]].
type RetrieveUEInformationIEFieldAPERValue struct {
	context       s00.BridgeCodecContext
	Value         RetrieveUEInformationIEField
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v RetrieveUEInformationIEFieldAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v RetrieveUEInformationIEFieldAPERValue) WithoutReplay() RetrieveUEInformationIEFieldAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// SecondaryRATDataUsageReportItemIEFieldAPERValue is the concrete APERValue[ProtocolIEField[SecondaryRATDataUsageReportItemIEValue]].
type SecondaryRATDataUsageReportItemIEFieldAPERValue struct {
	context       s00.BridgeCodecContext
	Value         SecondaryRATDataUsageReportItemIEField
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v SecondaryRATDataUsageReportItemIEFieldAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v SecondaryRATDataUsageReportItemIEFieldAPERValue) WithoutReplay() SecondaryRATDataUsageReportItemIEFieldAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// UEContextSuspendResponseIEFieldAPERValue is the concrete APERValue[ProtocolIEField[UEContextSuspendResponseIEValue]].
type UEContextSuspendResponseIEFieldAPERValue struct {
	context       s00.BridgeCodecContext
	Value         UEContextSuspendResponseIEField
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v UEContextSuspendResponseIEFieldAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v UEContextSuspendResponseIEFieldAPERValue) WithoutReplay() UEContextSuspendResponseIEFieldAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ErrorIndicationIEContainerAPERValue is the concrete APERValue[ProtocolIEContainer[ErrorIndicationIEValue]].
type ErrorIndicationIEContainerAPERValue struct {
	context       s00.BridgeCodecContext
	Value         ErrorIndicationIEContainer
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ErrorIndicationIEContainerAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ErrorIndicationIEContainerAPERValue) WithoutReplay() ErrorIndicationIEContainerAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// RetrieveUEInformationIEContainerAPERValue is the concrete APERValue[ProtocolIEContainer[RetrieveUEInformationIEValue]].
type RetrieveUEInformationIEContainerAPERValue struct {
	context       s00.BridgeCodecContext
	Value         RetrieveUEInformationIEContainer
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v RetrieveUEInformationIEContainerAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v RetrieveUEInformationIEContainerAPERValue) WithoutReplay() RetrieveUEInformationIEContainerAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// SecondaryRATDataUsageReportItemIEContainerAPERValue is the concrete APERValue[ProtocolIEContainer[SecondaryRATDataUsageReportItemIEValue]].
type SecondaryRATDataUsageReportItemIEContainerAPERValue struct {
	context       s00.BridgeCodecContext
	Value         SecondaryRATDataUsageReportItemIEContainer
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v SecondaryRATDataUsageReportItemIEContainerAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v SecondaryRATDataUsageReportItemIEContainerAPERValue) WithoutReplay() SecondaryRATDataUsageReportItemIEContainerAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// UEContextSuspendResponseIEContainerAPERValue is the concrete APERValue[ProtocolIEContainer[UEContextSuspendResponseIEValue]].
type UEContextSuspendResponseIEContainerAPERValue struct {
	context       s00.BridgeCodecContext
	Value         UEContextSuspendResponseIEContainer
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v UEContextSuspendResponseIEContainerAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v UEContextSuspendResponseIEContainerAPERValue) WithoutReplay() UEContextSuspendResponseIEContainerAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ErrorIndicationIEValueProtocolErrorIEContainerListAPERValue is the concrete APERValue[ProtocolErrorIEContainerList[ErrorIndicationIEValue]].
type ErrorIndicationIEValueProtocolErrorIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         ErrorIndicationIEValueProtocolErrorIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ErrorIndicationIEValueProtocolErrorIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ErrorIndicationIEValueProtocolErrorIEContainerListAPERValue) WithoutReplay() ErrorIndicationIEValueProtocolErrorIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// RetrieveUEInformationIEValueProtocolErrorIEContainerListAPERValue is the concrete APERValue[ProtocolErrorIEContainerList[RetrieveUEInformationIEValue]].
type RetrieveUEInformationIEValueProtocolErrorIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         RetrieveUEInformationIEValueProtocolErrorIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v RetrieveUEInformationIEValueProtocolErrorIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v RetrieveUEInformationIEValueProtocolErrorIEContainerListAPERValue) WithoutReplay() RetrieveUEInformationIEValueProtocolErrorIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// SecondaryRATDataUsageReportItemIEValueProtocolErrorIEContainerListAPERValue is the concrete APERValue[ProtocolErrorIEContainerList[SecondaryRATDataUsageReportItemIEValue]].
type SecondaryRATDataUsageReportItemIEValueProtocolErrorIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         SecondaryRATDataUsageReportItemIEValueProtocolErrorIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v SecondaryRATDataUsageReportItemIEValueProtocolErrorIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v SecondaryRATDataUsageReportItemIEValueProtocolErrorIEContainerListAPERValue) WithoutReplay() SecondaryRATDataUsageReportItemIEValueProtocolErrorIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// UEContextSuspendResponseIEValueProtocolErrorIEContainerListAPERValue is the concrete APERValue[ProtocolErrorIEContainerList[UEContextSuspendResponseIEValue]].
type UEContextSuspendResponseIEValueProtocolErrorIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         UEContextSuspendResponseIEValueProtocolErrorIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v UEContextSuspendResponseIEValueProtocolErrorIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v UEContextSuspendResponseIEValueProtocolErrorIEContainerListAPERValue) WithoutReplay() UEContextSuspendResponseIEValueProtocolErrorIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ErrorIndicationIEValueProtocolIEContainerListAPERValue is the concrete APERValue[ProtocolIEContainerList[ErrorIndicationIEValue]].
type ErrorIndicationIEValueProtocolIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         ErrorIndicationIEValueProtocolIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ErrorIndicationIEValueProtocolIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ErrorIndicationIEValueProtocolIEContainerListAPERValue) WithoutReplay() ErrorIndicationIEValueProtocolIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// RetrieveUEInformationIEValueProtocolIEContainerListAPERValue is the concrete APERValue[ProtocolIEContainerList[RetrieveUEInformationIEValue]].
type RetrieveUEInformationIEValueProtocolIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         RetrieveUEInformationIEValueProtocolIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v RetrieveUEInformationIEValueProtocolIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v RetrieveUEInformationIEValueProtocolIEContainerListAPERValue) WithoutReplay() RetrieveUEInformationIEValueProtocolIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// SecondaryRATDataUsageReportItemIEValueProtocolIEContainerListAPERValue is the concrete APERValue[ProtocolIEContainerList[SecondaryRATDataUsageReportItemIEValue]].
type SecondaryRATDataUsageReportItemIEValueProtocolIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         SecondaryRATDataUsageReportItemIEValueProtocolIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v SecondaryRATDataUsageReportItemIEValueProtocolIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v SecondaryRATDataUsageReportItemIEValueProtocolIEContainerListAPERValue) WithoutReplay() SecondaryRATDataUsageReportItemIEValueProtocolIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// UEContextSuspendResponseIEValueProtocolIEContainerListAPERValue is the concrete APERValue[ProtocolIEContainerList[UEContextSuspendResponseIEValue]].
type UEContextSuspendResponseIEValueProtocolIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         UEContextSuspendResponseIEValueProtocolIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v UEContextSuspendResponseIEValueProtocolIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v UEContextSuspendResponseIEValueProtocolIEContainerListAPERValue) WithoutReplay() UEContextSuspendResponseIEValueProtocolIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}
func BridgeCaptureS1APERABInformationListItemExtIEsValue(v *ERABInformationListItemExtIEsValue, s *aper.SemanticCapture) {
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
		case s00.ProtocolIEID(317):
			{
				f := s.Begin()
				s.Bool(v.rowDAPSRequestInfo == nil)
				if v.rowDAPSRequestInfo != nil {
					s14.BridgeCaptureS1APDAPSRequestInfo(v.rowDAPSRequestInfo, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(328):
			{
				f := s.Begin()
				s.Bool(v.rowSourceTransportLayerAddress == nil)
				if v.rowSourceTransportLayerAddress != nil {
					s00.BridgeCaptureS1APTransportLayerAddress(v.rowSourceTransportLayerAddress, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(332):
			{
				f := s.Begin()
				s.Bool(v.rowSecurityIndication == nil)
				if v.rowSecurityIndication != nil {
					BridgeCaptureS1APSecurityIndication(v.rowSecurityIndication, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(340):
			{
				f := s.Begin()
				s.Bool(v.rowSourceNodeTransportLayerAddress == nil)
				if v.rowSourceNodeTransportLayerAddress != nil {
					s00.BridgeCaptureS1APTransportLayerAddress(v.rowSourceNodeTransportLayerAddress, s)
				}
				s.End(f, nil, false)
			}
		}
	}
	s.End(f, &v.replay, false)
	s.CheckReceived(v.replay, v.received)
}
func (v ERABInformationListItemExtIEsValue) captureSemantics(s aper.SemanticCapture) ERABInformationListItemExtIEsValue {
	BridgeCaptureS1APERABInformationListItemExtIEsValue(&v, &s)
	return v
}
func BridgeCompareS1APERABInformationListItemExtIEsValue(v *ERABInformationListItemExtIEsValue, s *aper.SemanticComparison) {
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
		case s00.ProtocolIEID(317):
			{
				f := s.Begin()
				s.Bool(v.rowDAPSRequestInfo == nil)
				if v.rowDAPSRequestInfo != nil {
					s14.BridgeCompareS1APDAPSRequestInfo(v.rowDAPSRequestInfo, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(328):
			{
				f := s.Begin()
				s.Bool(v.rowSourceTransportLayerAddress == nil)
				if v.rowSourceTransportLayerAddress != nil {
					s07.BridgeCompareS1APTransportLayerAddress(v.rowSourceTransportLayerAddress, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(332):
			{
				f := s.Begin()
				s.Bool(v.rowSecurityIndication == nil)
				if v.rowSecurityIndication != nil {
					BridgeCompareS1APSecurityIndication(v.rowSecurityIndication, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(340):
			{
				f := s.Begin()
				s.Bool(v.rowSourceNodeTransportLayerAddress == nil)
				if v.rowSourceNodeTransportLayerAddress != nil {
					s07.BridgeCompareS1APTransportLayerAddress(v.rowSourceNodeTransportLayerAddress, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		}
	}
	s.End(f, v.replay, false)
	s.CheckReceived(v.replay, v.received)
}
func (v ERABInformationListItemExtIEsValue) compareSemantics(s aper.SemanticComparison) aper.SemanticComparison {
	BridgeCompareS1APERABInformationListItemExtIEsValue(&v, &s)
	return s
}
func BridgeCaptureS1APERABToBeSetupItemBearerSUReqExtIEsValue(v *ERABToBeSetupItemBearerSUReqExtIEsValue, s *aper.SemanticCapture) {
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
		case s00.ProtocolIEID(156):
			{
				f := s.Begin()
				s.Bool(v.rowCorrelationID == nil)
				if v.rowCorrelationID != nil {
					s00.BridgeCaptureS1APCorrelationID(v.rowCorrelationID, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(183):
			{
				f := s.Begin()
				s.Bool(v.rowSIPTOCorrelationID == nil)
				if v.rowSIPTOCorrelationID != nil {
					s00.BridgeCaptureS1APCorrelationID(v.rowSIPTOCorrelationID, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(233):
			{
				f := s.Begin()
				s.Bool(v.rowBearerType == nil)
				if v.rowBearerType != nil {
					s00.BridgeCaptureS1APBearerType(v.rowBearerType, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(305):
			{
				f := s.Begin()
				s.Bool(v.rowEthernetType == nil)
				if v.rowEthernetType != nil {
					s00.BridgeCaptureS1APEthernetType(v.rowEthernetType, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(332):
			{
				f := s.Begin()
				s.Bool(v.rowSecurityIndication == nil)
				if v.rowSecurityIndication != nil {
					BridgeCaptureS1APSecurityIndication(v.rowSecurityIndication, s)
				}
				s.End(f, nil, false)
			}
		}
	}
	s.End(f, &v.replay, false)
	s.CheckReceived(v.replay, v.received)
}
func (v ERABToBeSetupItemBearerSUReqExtIEsValue) captureSemantics(s aper.SemanticCapture) ERABToBeSetupItemBearerSUReqExtIEsValue {
	BridgeCaptureS1APERABToBeSetupItemBearerSUReqExtIEsValue(&v, &s)
	return v
}
func BridgeCompareS1APERABToBeSetupItemBearerSUReqExtIEsValue(v *ERABToBeSetupItemBearerSUReqExtIEsValue, s *aper.SemanticComparison) {
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
		case s00.ProtocolIEID(156):
			{
				f := s.Begin()
				s.Bool(v.rowCorrelationID == nil)
				if v.rowCorrelationID != nil {
					s02.BridgeCompareS1APCorrelationID(v.rowCorrelationID, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(183):
			{
				f := s.Begin()
				s.Bool(v.rowSIPTOCorrelationID == nil)
				if v.rowSIPTOCorrelationID != nil {
					s02.BridgeCompareS1APCorrelationID(v.rowSIPTOCorrelationID, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(233):
			{
				f := s.Begin()
				s.Bool(v.rowBearerType == nil)
				if v.rowBearerType != nil {
					s02.BridgeCompareS1APBearerType(v.rowBearerType, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(305):
			{
				f := s.Begin()
				s.Bool(v.rowEthernetType == nil)
				if v.rowEthernetType != nil {
					s02.BridgeCompareS1APEthernetType(v.rowEthernetType, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(332):
			{
				f := s.Begin()
				s.Bool(v.rowSecurityIndication == nil)
				if v.rowSecurityIndication != nil {
					BridgeCompareS1APSecurityIndication(v.rowSecurityIndication, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		}
	}
	s.End(f, v.replay, false)
	s.CheckReceived(v.replay, v.received)
}
func (v ERABToBeSetupItemBearerSUReqExtIEsValue) compareSemantics(s aper.SemanticComparison) aper.SemanticComparison {
	BridgeCompareS1APERABToBeSetupItemBearerSUReqExtIEsValue(&v, &s)
	return s
}
func BridgeCaptureS1APERABToBeSetupItemCtxtSUReqExtIEsValue(v *ERABToBeSetupItemCtxtSUReqExtIEsValue, s *aper.SemanticCapture) {
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
		case s00.ProtocolIEID(156):
			{
				f := s.Begin()
				s.Bool(v.rowCorrelationID == nil)
				if v.rowCorrelationID != nil {
					s00.BridgeCaptureS1APCorrelationID(v.rowCorrelationID, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(183):
			{
				f := s.Begin()
				s.Bool(v.rowSIPTOCorrelationID == nil)
				if v.rowSIPTOCorrelationID != nil {
					s00.BridgeCaptureS1APCorrelationID(v.rowSIPTOCorrelationID, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(233):
			{
				f := s.Begin()
				s.Bool(v.rowBearerType == nil)
				if v.rowBearerType != nil {
					s00.BridgeCaptureS1APBearerType(v.rowBearerType, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(305):
			{
				f := s.Begin()
				s.Bool(v.rowEthernetType == nil)
				if v.rowEthernetType != nil {
					s00.BridgeCaptureS1APEthernetType(v.rowEthernetType, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(332):
			{
				f := s.Begin()
				s.Bool(v.rowSecurityIndication == nil)
				if v.rowSecurityIndication != nil {
					BridgeCaptureS1APSecurityIndication(v.rowSecurityIndication, s)
				}
				s.End(f, nil, false)
			}
		}
	}
	s.End(f, &v.replay, false)
	s.CheckReceived(v.replay, v.received)
}
func (v ERABToBeSetupItemCtxtSUReqExtIEsValue) captureSemantics(s aper.SemanticCapture) ERABToBeSetupItemCtxtSUReqExtIEsValue {
	BridgeCaptureS1APERABToBeSetupItemCtxtSUReqExtIEsValue(&v, &s)
	return v
}
func BridgeCompareS1APERABToBeSetupItemCtxtSUReqExtIEsValue(v *ERABToBeSetupItemCtxtSUReqExtIEsValue, s *aper.SemanticComparison) {
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
		case s00.ProtocolIEID(156):
			{
				f := s.Begin()
				s.Bool(v.rowCorrelationID == nil)
				if v.rowCorrelationID != nil {
					s02.BridgeCompareS1APCorrelationID(v.rowCorrelationID, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(183):
			{
				f := s.Begin()
				s.Bool(v.rowSIPTOCorrelationID == nil)
				if v.rowSIPTOCorrelationID != nil {
					s02.BridgeCompareS1APCorrelationID(v.rowSIPTOCorrelationID, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(233):
			{
				f := s.Begin()
				s.Bool(v.rowBearerType == nil)
				if v.rowBearerType != nil {
					s02.BridgeCompareS1APBearerType(v.rowBearerType, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(305):
			{
				f := s.Begin()
				s.Bool(v.rowEthernetType == nil)
				if v.rowEthernetType != nil {
					s02.BridgeCompareS1APEthernetType(v.rowEthernetType, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(332):
			{
				f := s.Begin()
				s.Bool(v.rowSecurityIndication == nil)
				if v.rowSecurityIndication != nil {
					BridgeCompareS1APSecurityIndication(v.rowSecurityIndication, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		}
	}
	s.End(f, v.replay, false)
	s.CheckReceived(v.replay, v.received)
}
func (v ERABToBeSetupItemCtxtSUReqExtIEsValue) compareSemantics(s aper.SemanticComparison) aper.SemanticComparison {
	BridgeCompareS1APERABToBeSetupItemCtxtSUReqExtIEsValue(&v, &s)
	return s
}
func BridgeCaptureS1APErrorIndication(v *ErrorIndication, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeErrorIndicationIEValueCaptureS1APProtocolIEContainer(&v.ProtocolIEs, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APErrorIndication(v *ErrorIndication, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeErrorIndicationIEValueCompareS1APProtocolIEContainer(&v.ProtocolIEs, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APErrorIndicationIEValue(v *ErrorIndicationIEValue, s *aper.SemanticCapture) {
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
		case s00.ProtocolIEID(58):
			{
				f := s.Begin()
				s.Bool(v.rowCriticalityDiagnostics == nil)
				if v.rowCriticalityDiagnostics != nil {
					s22.BridgeCaptureS1APCriticalityDiagnostics(v.rowCriticalityDiagnostics, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(96):
			{
				f := s.Begin()
				s.Bool(v.rowSTMSI == nil)
				if v.rowSTMSI != nil {
					s27.BridgeCaptureS1APSTMSI(v.rowSTMSI, s)
				}
				s.End(f, nil, false)
			}
		}
	}
	s.End(f, &v.replay, false)
	s.CheckReceived(v.replay, v.received)
}
func (v ErrorIndicationIEValue) captureSemantics(s aper.SemanticCapture) ErrorIndicationIEValue {
	BridgeCaptureS1APErrorIndicationIEValue(&v, &s)
	return v
}
func BridgeCompareS1APErrorIndicationIEValue(v *ErrorIndicationIEValue, s *aper.SemanticComparison) {
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
		case s00.ProtocolIEID(58):
			{
				f := s.Begin()
				s.Bool(v.rowCriticalityDiagnostics == nil)
				if v.rowCriticalityDiagnostics != nil {
					s22.BridgeCompareS1APCriticalityDiagnostics(v.rowCriticalityDiagnostics, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(96):
			{
				f := s.Begin()
				s.Bool(v.rowSTMSI == nil)
				if v.rowSTMSI != nil {
					s27.BridgeCompareS1APSTMSI(v.rowSTMSI, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		}
	}
	s.End(f, v.replay, false)
	s.CheckReceived(v.replay, v.received)
}
func (v ErrorIndicationIEValue) compareSemantics(s aper.SemanticComparison) aper.SemanticComparison {
	BridgeCompareS1APErrorIndicationIEValue(&v, &s)
	return s
}
func BridgeCaptureS1APRetrieveUEInformation(v *RetrieveUEInformation, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeRetrieveUEInformationIEValueCaptureS1APProtocolIEContainer(&v.ProtocolIEs, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APRetrieveUEInformation(v *RetrieveUEInformation, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeRetrieveUEInformationIEValueCompareS1APProtocolIEContainer(&v.ProtocolIEs, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APRetrieveUEInformationIEValue(v *RetrieveUEInformationIEValue, s *aper.SemanticCapture) {
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
		}
	}
	s.End(f, &v.replay, false)
	s.CheckReceived(v.replay, v.received)
}
func (v RetrieveUEInformationIEValue) captureSemantics(s aper.SemanticCapture) RetrieveUEInformationIEValue {
	BridgeCaptureS1APRetrieveUEInformationIEValue(&v, &s)
	return v
}
func BridgeCompareS1APRetrieveUEInformationIEValue(v *RetrieveUEInformationIEValue, s *aper.SemanticComparison) {
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
		}
	}
	s.End(f, v.replay, false)
	s.CheckReceived(v.replay, v.received)
}
func (v RetrieveUEInformationIEValue) compareSemantics(s aper.SemanticComparison) aper.SemanticComparison {
	BridgeCompareS1APRetrieveUEInformationIEValue(&v, &s)
	return s
}
func BridgeCaptureS1APScheduledCommunicationTime(v *ScheduledCommunicationTime, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Bool(v.DayofWeek == nil)
		if v.DayofWeek != nil {
			s.BitString((*v.DayofWeek).Bytes, (*v.DayofWeek).BitLength)
		}
		s.End(f, nil, false)
	}
	{
		f := s.Begin()
		s.BigInt(v.TimeofDayStart)
		s.End(f, nil, false)
	}
	{
		f := s.Begin()
		s.BigInt(v.TimeofDayEnd)
		s.End(f, nil, false)
	}
	s.Bool(v.IEExtensions == nil)
	BridgeScheduledCommunicationTimeExtIEsValueCaptureS1APProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APScheduledCommunicationTime(v *ScheduledCommunicationTime, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Bool(v.DayofWeek == nil)
		if v.DayofWeek != nil {
			s.BitString((*v.DayofWeek).Bytes, (*v.DayofWeek).BitLength)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	{
		f := s.Begin()
		s.BigInt(v.TimeofDayStart)
		s.End(f, aper.Snapshot{}, false)
	}
	{
		f := s.Begin()
		s.BigInt(v.TimeofDayEnd)
		s.End(f, aper.Snapshot{}, false)
	}
	s.Bool(v.IEExtensions == nil)
	BridgeScheduledCommunicationTimeExtIEsValueCompareS1APProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APSecondaryRATDataUsageReportItem(v *SecondaryRATDataUsageReportItem, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APERABID(&v.ERABID, s)
	s00.BridgeCaptureS1APSecondaryRATType(&v.SecondaryRATType, s)
	s25.BridgeCaptureS1APERABUsageReportList(&v.ERABUsageReportList, s)
	s.Bool(v.IEExtensions == nil)
	BridgeSecondaryRATDataUsageReportItemExtIEsValueCaptureS1APProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APSecondaryRATDataUsageReportItem(v *SecondaryRATDataUsageReportItem, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s02.BridgeCompareS1APERABID(&v.ERABID, s)
	s06.BridgeCompareS1APSecondaryRATType(&v.SecondaryRATType, s)
	s25.BridgeCompareS1APERABUsageReportList(&v.ERABUsageReportList, s)
	s.Bool(v.IEExtensions == nil)
	BridgeSecondaryRATDataUsageReportItemExtIEsValueCompareS1APProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APSecondaryRATDataUsageReportItemIEValue(v *SecondaryRATDataUsageReportItemIEValue, s *aper.SemanticCapture) {
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
		case s00.ProtocolIEID(265):
			{
				f := s.Begin()
				s.Bool(v.rowSecondaryRATDataUsageReportItem == nil)
				if v.rowSecondaryRATDataUsageReportItem != nil {
					BridgeCaptureS1APSecondaryRATDataUsageReportItem(v.rowSecondaryRATDataUsageReportItem, s)
				}
				s.End(f, nil, false)
			}
		}
	}
	s.End(f, &v.replay, false)
	s.CheckReceived(v.replay, v.received)
}
func (v SecondaryRATDataUsageReportItemIEValue) captureSemantics(s aper.SemanticCapture) SecondaryRATDataUsageReportItemIEValue {
	BridgeCaptureS1APSecondaryRATDataUsageReportItemIEValue(&v, &s)
	return v
}
func BridgeCompareS1APSecondaryRATDataUsageReportItemIEValue(v *SecondaryRATDataUsageReportItemIEValue, s *aper.SemanticComparison) {
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
		case s00.ProtocolIEID(265):
			{
				f := s.Begin()
				s.Bool(v.rowSecondaryRATDataUsageReportItem == nil)
				if v.rowSecondaryRATDataUsageReportItem != nil {
					BridgeCompareS1APSecondaryRATDataUsageReportItem(v.rowSecondaryRATDataUsageReportItem, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		}
	}
	s.End(f, v.replay, false)
	s.CheckReceived(v.replay, v.received)
}
func (v SecondaryRATDataUsageReportItemIEValue) compareSemantics(s aper.SemanticComparison) aper.SemanticComparison {
	BridgeCompareS1APSecondaryRATDataUsageReportItemIEValue(&v, &s)
	return s
}
func BridgeCaptureS1APSecondaryRATDataUsageReportList(v *SecondaryRATDataUsageReportList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeSecondaryRATDataUsageReportItemIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeCompareS1APSecondaryRATDataUsageReportList(v *SecondaryRATDataUsageReportList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeSecondaryRATDataUsageReportItemIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCaptureS1APSecurityContext(v *SecurityContext, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s.Int(int64(v.NextHopChainingCount))
	s00.BridgeCaptureS1APSecurityKey(&v.NextHopParameter, s)
	s.Bool(v.IEExtensions == nil)
	BridgeSecurityContextExtIEsValueCaptureS1APProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APSecurityContext(v *SecurityContext, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s.Int(int64(v.NextHopChainingCount))
	s07.BridgeCompareS1APSecurityKey(&v.NextHopParameter, s)
	s.Bool(v.IEExtensions == nil)
	BridgeSecurityContextExtIEsValueCompareS1APProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APSecurityIndication(v *SecurityIndication, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APIntegrityProtectionIndication(&v.IntegrityProtectionIndication, s)
	s.Bool(v.IEExtensions == nil)
	BridgeSecurityIndicationExtIEsValueCaptureS1APProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APSecurityIndication(v *SecurityIndication, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s02.BridgeCompareS1APIntegrityProtectionIndication(&v.IntegrityProtectionIndication, s)
	s.Bool(v.IEExtensions == nil)
	BridgeSecurityIndicationExtIEsValueCompareS1APProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APUEContextSuspendResponseIEValue(v *UEContextSuspendResponseIEValue, s *aper.SemanticCapture) {
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
		case s00.ProtocolIEID(58):
			{
				f := s.Begin()
				s.Bool(v.rowCriticalityDiagnostics == nil)
				if v.rowCriticalityDiagnostics != nil {
					s22.BridgeCaptureS1APCriticalityDiagnostics(v.rowCriticalityDiagnostics, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(40):
			{
				f := s.Begin()
				s.Bool(v.rowSecurityContext == nil)
				if v.rowSecurityContext != nil {
					BridgeCaptureS1APSecurityContext(v.rowSecurityContext, s)
				}
				s.End(f, nil, false)
			}
		}
	}
	s.End(f, &v.replay, false)
	s.CheckReceived(v.replay, v.received)
}
func (v UEContextSuspendResponseIEValue) captureSemantics(s aper.SemanticCapture) UEContextSuspendResponseIEValue {
	BridgeCaptureS1APUEContextSuspendResponseIEValue(&v, &s)
	return v
}
func BridgeCompareS1APUEContextSuspendResponseIEValue(v *UEContextSuspendResponseIEValue, s *aper.SemanticComparison) {
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
		case s00.ProtocolIEID(58):
			{
				f := s.Begin()
				s.Bool(v.rowCriticalityDiagnostics == nil)
				if v.rowCriticalityDiagnostics != nil {
					s22.BridgeCompareS1APCriticalityDiagnostics(v.rowCriticalityDiagnostics, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(40):
			{
				f := s.Begin()
				s.Bool(v.rowSecurityContext == nil)
				if v.rowSecurityContext != nil {
					BridgeCompareS1APSecurityContext(v.rowSecurityContext, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		}
	}
	s.End(f, v.replay, false)
	s.CheckReceived(v.replay, v.received)
}
func (v UEContextSuspendResponseIEValue) compareSemantics(s aper.SemanticComparison) aper.SemanticComparison {
	BridgeCompareS1APUEContextSuspendResponseIEValue(&v, &s)
	return s
}
func BridgeCaptureS1APUEPagingID(v *UEPagingID, s *aper.SemanticCapture) {
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
	case s00.UEPagingIDChoiceSTMSI:
		{
			f := s.Begin()
			s.Bool(v.STMSI == nil)
			if v.STMSI != nil {
				s27.BridgeCaptureS1APSTMSI(v.STMSI, s)
			}
			s.End(f, nil, false)
		}
	case s00.UEPagingIDChoiceIMSI:
		{
			f := s.Begin()
			s.Bool(v.IMSI == nil)
			if v.IMSI != nil {
				s00.BridgeCaptureS1APIMSI(v.IMSI, s)
			}
			s.End(f, nil, false)
		}
	}
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APUEPagingID(v *UEPagingID, s *aper.SemanticComparison) {
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
	case s00.UEPagingIDChoiceSTMSI:
		{
			f := s.Begin()
			s.Bool(v.STMSI == nil)
			if v.STMSI != nil {
				s27.BridgeCompareS1APSTMSI(v.STMSI, s)
			}
			s.End(f, aper.Snapshot{}, false)
		}
	case s00.UEPagingIDChoiceIMSI:
		{
			f := s.Begin()
			s.Bool(v.IMSI == nil)
			if v.IMSI != nil {
				s02.BridgeCompareS1APIMSI(v.IMSI, s)
			}
			s.End(f, aper.Snapshot{}, false)
		}
	}
	s.End(f, v.replay, v.withoutReplay)
}

// SecurityContext represents the ASN.1 type SecurityContext (SEQUENCE).
type SecurityContext struct {
	replay               aper.Snapshot
	stream               aper.WireSpan
	received             bool
	withoutReplay        bool
	receivedAbsolute     bool
	receivedBytes        aper.WireSpan
	receivedLocation     aper.Location
	NextHopChainingCount int64                                 `asn1:"tag:0,context,implicit"`
	NextHopParameter     s00.SecurityKey                       `asn1:"tag:1,context,implicit"`
	IEExtensions         s11.SecurityContextExtIEsExtContainer `asn1:"tag:2,context,implicit,optional" json:"IEExtensions,omitzero"`
	iEExtensionsIndef    bool                                  `asn1:"-" json:"-"`
	extCount             int64                                 `asn1:"-" json:"-"`
	extPresent           []bool                                `asn1:"-" json:"-"`
	extData              [][]byte                              `asn1:"-" json:"-"`
	perPadding           aper.FinalPadding                     `asn1:"-" json:"-"`
	perExtPadding        []aper.CompletePadding                `asn1:"-" json:"-"`
	extOrigin            []aper.OpaqueOrigin
	extWire              []aper.WireSpan
}
type SecondaryRATDataUsageReportList = []SecondaryRATDataUsageReportItemIEValueProtocolIESingleContainer

// SecondaryRATDataUsageReportItem represents the ASN.1 type SecondaryRATDataUsageReportItem (SEQUENCE).
type SecondaryRATDataUsageReportItem struct {
	replay                   aper.Snapshot
	stream                   aper.WireSpan
	received                 bool
	withoutReplay            bool
	receivedAbsolute         bool
	receivedBytes            aper.WireSpan
	receivedLocation         aper.Location
	ERABID                   s00.ERABID                                            `asn1:"tag:0,context,implicit"`
	SecondaryRATType         s00.SecondaryRATType                                  `asn1:"tag:1,context,implicit"`
	ERABUsageReportList      s17.ERABUsageReportList                               `asn1:"tag:2,context,implicit"`
	eRABUsageReportListIndef bool                                                  `asn1:"-" json:"-"`
	IEExtensions             s11.SecondaryRATDataUsageReportItemExtIEsExtContainer `asn1:"tag:3,context,implicit,optional" json:"IEExtensions,omitzero"`
	iEExtensionsIndef        bool                                                  `asn1:"-" json:"-"`
	extCount                 int64                                                 `asn1:"-" json:"-"`
	extPresent               []bool                                                `asn1:"-" json:"-"`
	extData                  [][]byte                                              `asn1:"-" json:"-"`
	perPadding               aper.FinalPadding                                     `asn1:"-" json:"-"`
	perExtPadding            []aper.CompletePadding                                `asn1:"-" json:"-"`
	extOrigin                []aper.OpaqueOrigin
	extWire                  []aper.WireSpan
}

// SecurityIndication represents the ASN.1 type SecurityIndication (SEQUENCE).
type SecurityIndication struct {
	replay                        aper.Snapshot
	stream                        aper.WireSpan
	received                      bool
	withoutReplay                 bool
	receivedAbsolute              bool
	receivedBytes                 aper.WireSpan
	receivedLocation              aper.Location
	IntegrityProtectionIndication s00.IntegrityProtectionIndication        `asn1:"tag:0,context,implicit"`
	IEExtensions                  s11.SecurityIndicationExtIEsExtContainer `asn1:"tag:1,context,implicit,optional" json:"IEExtensions,omitzero"`
	iEExtensionsIndef             bool                                     `asn1:"-" json:"-"`
	extCount                      int64                                    `asn1:"-" json:"-"`
	extPresent                    []bool                                   `asn1:"-" json:"-"`
	extData                       [][]byte                                 `asn1:"-" json:"-"`
	perPadding                    aper.FinalPadding                        `asn1:"-" json:"-"`
	perExtPadding                 []aper.CompletePadding                   `asn1:"-" json:"-"`
	extOrigin                     []aper.OpaqueOrigin
	extWire                       []aper.WireSpan
}

// ScheduledCommunicationTime represents the ASN.1 type ScheduledCommunicationTime (SEQUENCE).
type ScheduledCommunicationTime struct {
	replay            aper.Snapshot
	stream            aper.WireSpan
	received          bool
	withoutReplay     bool
	receivedAbsolute  bool
	receivedBytes     aper.WireSpan
	receivedLocation  aper.Location
	DayofWeek         *runtime.BitString                               `asn1:"tag:0,context,implicit,optional" json:"DayofWeek,omitempty"`
	TimeofDayStart    *big.Int                                         `asn1:"tag:1,context,implicit,optional" json:"TimeofDayStart,omitempty"`
	TimeofDayEnd      *big.Int                                         `asn1:"tag:2,context,implicit,optional" json:"TimeofDayEnd,omitempty"`
	IEExtensions      s11.ScheduledCommunicationTimeExtIEsExtContainer `asn1:"tag:3,context,implicit,optional" json:"IEExtensions,omitzero"`
	iEExtensionsIndef bool                                             `asn1:"-" json:"-"`
	extCount          int64                                            `asn1:"-" json:"-"`
	extPresent        []bool                                           `asn1:"-" json:"-"`
	extData           [][]byte                                         `asn1:"-" json:"-"`
	perPadding        aper.FinalPadding                                `asn1:"-" json:"-"`
	perExtPadding     []aper.CompletePadding                           `asn1:"-" json:"-"`
	extOrigin         []aper.OpaqueOrigin
	extWire           []aper.WireSpan
}

// UEPagingID represents the ASN.1 CHOICE type UEPagingID.
type UEPagingID struct {
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
	STMSI              *s27.STMSI            `json:"STMSI,omitempty"`
	IMSI               *s00.IMSI             `json:"IMSI,omitempty"`
}

// NewUEPagingIDSTMSI creates a UEPagingID with the s-TMSI alternative.
func BridgeNewUEPagingIDSTMSILegacy(v s27.STMSI) UEPagingID {
	return UEPagingID{
		Choice: s00.UEPagingIDChoiceSTMSI,
		STMSI:  &v,
	}
}

// NewUEPagingIDIMSI creates a UEPagingID with the iMSI alternative.
func BridgeNewUEPagingIDIMSILegacy(v s00.IMSI) UEPagingID {
	return UEPagingID{
		Choice: s00.UEPagingIDChoiceIMSI,
		IMSI:   &v,
	}
}

// MarshalAPER encodes SecurityContext to APER format.
func (v *SecurityContext) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *SecurityContext) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
	if err := aper.EncodeIntegerAligned(bb, int64(v.NextHopChainingCount), s07.BridgeInt64Ptr(0), s07.BridgeInt64Ptr(7), false); err != nil {
		return fmt.Errorf("encoding nextHopChainingCount: %w", err)
	}
	if err := aper.EncodeBitStringAligned(bb, v.NextHopParameter.Bytes, v.NextHopParameter.BitLength, 256, 256, true); err != nil {
		return fmt.Errorf("encoding nextHopParameter: %w", err)
	}
	if v.IEExtensions != nil {
		if err := aper.EncodeCollection(bb, int64(len(v.IEExtensions)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
			if fragmentOffset_ieextensions < 0 || fragmentOffset_ieextensions > int64(len(v.IEExtensions)) || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(len(v.IEExtensions[fragmentOffset_ieextensions:])) {
				return fmt.Errorf("collection fragment outside value")
			}
			for _, elem := range v.IEExtensions[fragmentOffset_ieextensions : fragmentOffset_ieextensions+fragmentLength_ieextensions] {
				if err := s11.BridgeSecurityContextExtIEsExtFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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

// UnmarshalAPER decodes SecurityContext from APER format.
func (v *SecurityContext) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes SecurityContext with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *SecurityContext) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "SecurityContext")
	}
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "SecurityContext")
	}
	padding, err := aper.CaptureFinalBits(bb, "SecurityContext")
	if err != nil {
		return runtime.WrapDecodePath(err, "SecurityContext")
	}
	v.perPadding = padding.WithRecords(v.perPadding)
	return nil
}
func (v *SecurityContext) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = SecurityContext{}
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
	val_nexthopchainingcount, err := aper.DecodeIntegerAligned(bb, s07.BridgeInt64Ptr(0), s07.BridgeInt64Ptr(7), false)
	if err != nil {
		return runtime.WrapDecodePath(err, "NextHopChainingCount")
	}
	v.NextHopChainingCount = val_nexthopchainingcount
	bsBytes_nexthopparameter, bsBitLen_nexthopparameter, err := aper.DecodeBitStringAligned(bb, 256, 256, true)
	if err != nil {
		return runtime.WrapDecodePath(err, "NextHopParameter")
	}
	v.NextHopParameter = runtime.BitString{Bytes: bsBytes_nexthopparameter, BitLength: bsBitLen_nexthopparameter}
	if opt_ieextensions {
		tmp_ieextensions := make(s11.SecurityContextExtIEsExtContainer, 0)
		_, errCollection_ieextensions := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1128
			if fragmentOffset_ieextensions < 0 || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(^uint(0)>>1) || fragmentOffset_ieextensions > int64(^uint(0)>>1)-fragmentLength_ieextensions {
				return fmt.Errorf("collection fragment count out of range")
			}
			for i := int64(0); i < fragmentLength_ieextensions; i++ {
				var elem s11.SecurityContextExtIEsExtField
				if err := s11.BridgeSecurityContextExtIEsExtFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
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

type BridgeAsn1cAPERSecondaryRATDataUsageReportListListValue struct {
	Value SecondaryRATDataUsageReportList
}

// MarshalAPERSecondaryRATDataUsageReportListTo appends a SecondaryRATDataUsageReportList list to bb.
func BridgeMarshalAPERSecondaryRATDataUsageReportListTo(list SecondaryRATDataUsageReportList, bb *aper.BitBuffer, fresh ...bool) error {
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()

	v := BridgeAsn1cAPERSecondaryRATDataUsageReportListListValue{Value: list}
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

// MarshalAPER encodes SecondaryRATDataUsageReportItem to APER format.
func (v *SecondaryRATDataUsageReportItem) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *SecondaryRATDataUsageReportItem) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
	if err := aper.EncodeIntegerBigBoundsAligned(bb, v.ERABID, s00.BridgeAsn1IntegerBound0, s00.BridgeAsn1IntegerBound5, true); err != nil {
		return fmt.Errorf("encoding e-RAB-ID: %w", err)
	}
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.SecondaryRATType), 1, true); err != nil {
		return fmt.Errorf("encoding secondaryRATType: %w", err)
	}
	if err := aper.EncodeCollection(bb, int64(len(v.ERABUsageReportList)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 2, HasUpper: true}, true, func(fragmentOffset_erabusagereportlist, fragmentLength_erabusagereportlist int64) error {
		// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
		if fragmentOffset_erabusagereportlist < 0 || fragmentOffset_erabusagereportlist > int64(len(v.ERABUsageReportList)) || fragmentLength_erabusagereportlist < 0 || fragmentLength_erabusagereportlist > int64(len(v.ERABUsageReportList[fragmentOffset_erabusagereportlist:])) {
			return fmt.Errorf("collection fragment outside value")
		}
		for _, elem := range v.ERABUsageReportList[fragmentOffset_erabusagereportlist : fragmentOffset_erabusagereportlist+fragmentLength_erabusagereportlist] {
			if err := s17.BridgeERABUsageReportItemIEFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
				return fmt.Errorf("encoding e-RABUsageReportList element: %w", err)
			}
		}
		return nil
	}); err != nil {
		return fmt.Errorf("encoding e-RABUsageReportList: %w", err)
	}
	if v.IEExtensions != nil {
		if err := aper.EncodeCollection(bb, int64(len(v.IEExtensions)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
			if fragmentOffset_ieextensions < 0 || fragmentOffset_ieextensions > int64(len(v.IEExtensions)) || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(len(v.IEExtensions[fragmentOffset_ieextensions:])) {
				return fmt.Errorf("collection fragment outside value")
			}
			for _, elem := range v.IEExtensions[fragmentOffset_ieextensions : fragmentOffset_ieextensions+fragmentLength_ieextensions] {
				if err := s11.BridgeSecondaryRATDataUsageReportItemExtIEsExtFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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

// UnmarshalAPER decodes SecondaryRATDataUsageReportItem from APER format.
func (v *SecondaryRATDataUsageReportItem) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes SecondaryRATDataUsageReportItem with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *SecondaryRATDataUsageReportItem) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "SecondaryRATDataUsageReportItem")
	}
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "SecondaryRATDataUsageReportItem")
	}
	padding, err := aper.CaptureFinalBits(bb, "SecondaryRATDataUsageReportItem")
	if err != nil {
		return runtime.WrapDecodePath(err, "SecondaryRATDataUsageReportItem")
	}
	v.perPadding = padding.WithRecords(v.perPadding)
	return nil
}
func (v *SecondaryRATDataUsageReportItem) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = SecondaryRATDataUsageReportItem{}
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
	val_erabid, err := aper.DecodeIntegerBigBoundsAligned(bb, s00.BridgeAsn1IntegerBound0, s00.BridgeAsn1IntegerBound5, true)
	if err != nil {
		return runtime.WrapDecodePath(err, "ERABID")
	}
	v.ERABID = val_erabid
	val_secondaryrattype, err := aper.DecodeEnumeratedAligned(bb, 1, true, aper.EnumerationSource{KnownExtensions: 1, Path: "SecondaryRATType"})
	if err != nil {
		return runtime.WrapDecodePath(err, "SecondaryRATType")
	}
	v.SecondaryRATType = s00.SecondaryRATType(val_secondaryrattype)
	v.ERABUsageReportList = make(s17.ERABUsageReportList, 0)
	_, errCollection_erabusagereportlist := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 2, HasUpper: true}, true, func(fragmentOffset_erabusagereportlist, fragmentLength_erabusagereportlist int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1128
		if fragmentOffset_erabusagereportlist < 0 || fragmentLength_erabusagereportlist < 0 || fragmentLength_erabusagereportlist > int64(^uint(0)>>1) || fragmentOffset_erabusagereportlist > int64(^uint(0)>>1)-fragmentLength_erabusagereportlist {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_erabusagereportlist; i++ {
			var elem s17.ERABUsageReportItemIEValueProtocolIESingleContainer
			if err := s17.BridgeERABUsageReportItemIEFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
				return runtime.WrapDecodePath(err, fmt.Sprintf("ERABUsageReportList[%d]", fragmentOffset_erabusagereportlist+i))
			}
			if next, err := aper.AppendValues(bb, v.ERABUsageReportList, elem); err != nil {
				return err
			} else {
				v.ERABUsageReportList = next
			}
		}
		return nil
	})
	if errCollection_erabusagereportlist != nil {
		return runtime.WrapDecodePath(errCollection_erabusagereportlist, "ERABUsageReportList")
	}
	if opt_ieextensions {
		tmp_ieextensions := make(s11.SecondaryRATDataUsageReportItemExtIEsExtContainer, 0)
		_, errCollection_ieextensions := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1128
			if fragmentOffset_ieextensions < 0 || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(^uint(0)>>1) || fragmentOffset_ieextensions > int64(^uint(0)>>1)-fragmentLength_ieextensions {
				return fmt.Errorf("collection fragment count out of range")
			}
			for i := int64(0); i < fragmentLength_ieextensions; i++ {
				var elem s11.SecondaryRATDataUsageReportItemExtIEsExtField
				if err := s11.BridgeSecondaryRATDataUsageReportItemExtIEsExtFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
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

// MarshalAPER encodes SecurityIndication to APER format.
func (v *SecurityIndication) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *SecurityIndication) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.IntegrityProtectionIndication), 3, true); err != nil {
		return fmt.Errorf("encoding integrityProtectionIndication: %w", err)
	}
	if v.IEExtensions != nil {
		if err := aper.EncodeCollection(bb, int64(len(v.IEExtensions)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
			if fragmentOffset_ieextensions < 0 || fragmentOffset_ieextensions > int64(len(v.IEExtensions)) || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(len(v.IEExtensions[fragmentOffset_ieextensions:])) {
				return fmt.Errorf("collection fragment outside value")
			}
			for _, elem := range v.IEExtensions[fragmentOffset_ieextensions : fragmentOffset_ieextensions+fragmentLength_ieextensions] {
				if err := s11.BridgeSecurityIndicationExtIEsExtFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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

// UnmarshalAPER decodes SecurityIndication from APER format.
func (v *SecurityIndication) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes SecurityIndication with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *SecurityIndication) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "SecurityIndication")
	}
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "SecurityIndication")
	}
	padding, err := aper.CaptureFinalBits(bb, "SecurityIndication")
	if err != nil {
		return runtime.WrapDecodePath(err, "SecurityIndication")
	}
	v.perPadding = padding.WithRecords(v.perPadding)
	return nil
}
func (v *SecurityIndication) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = SecurityIndication{}
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
	val_integrityprotectionindication, err := aper.DecodeEnumeratedAligned(bb, 3, true, aper.EnumerationSource{KnownExtensions: 0, Path: "IntegrityProtectionIndication"})
	if err != nil {
		return runtime.WrapDecodePath(err, "IntegrityProtectionIndication")
	}
	v.IntegrityProtectionIndication = s00.IntegrityProtectionIndication(val_integrityprotectionindication)
	if opt_ieextensions {
		tmp_ieextensions := make(s11.SecurityIndicationExtIEsExtContainer, 0)
		_, errCollection_ieextensions := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1128
			if fragmentOffset_ieextensions < 0 || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(^uint(0)>>1) || fragmentOffset_ieextensions > int64(^uint(0)>>1)-fragmentLength_ieextensions {
				return fmt.Errorf("collection fragment count out of range")
			}
			for i := int64(0); i < fragmentLength_ieextensions; i++ {
				var elem s11.SecurityIndicationExtIEsExtField
				if err := s11.BridgeSecurityIndicationExtIEsExtFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
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

// MarshalAPER encodes ScheduledCommunicationTime to APER format.
func (v *ScheduledCommunicationTime) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *ScheduledCommunicationTime) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
	if err := aper.EncodeBoolean(bb, v.DayofWeek != nil); err != nil {
		return err
	}
	if err := aper.EncodeBoolean(bb, v.TimeofDayStart != nil); err != nil {
		return err
	}
	if err := aper.EncodeBoolean(bb, v.TimeofDayEnd != nil); err != nil {
		return err
	}
	if err := aper.EncodeBoolean(bb, v.IEExtensions != nil); err != nil {
		return err
	}
	if v.DayofWeek != nil {
		if err := aper.EncodeBitStringAligned(bb, v.DayofWeek.Bytes, v.DayofWeek.BitLength, 7, 7, true); err != nil {
			return fmt.Errorf("encoding dayofWeek: %w", err)
		}
	}
	if v.TimeofDayStart != nil {
		if err := aper.EncodeIntegerBigBoundsAligned(bb, v.TimeofDayStart, s00.BridgeAsn1IntegerBound0, s00.BridgeAsn1IntegerBound14, true); err != nil {
			return fmt.Errorf("encoding timeofDayStart: %w", err)
		}
	}
	if v.TimeofDayEnd != nil {
		if err := aper.EncodeIntegerBigBoundsAligned(bb, v.TimeofDayEnd, s00.BridgeAsn1IntegerBound0, s00.BridgeAsn1IntegerBound14, true); err != nil {
			return fmt.Errorf("encoding timeofDayEnd: %w", err)
		}
	}
	if v.IEExtensions != nil {
		if err := aper.EncodeCollection(bb, int64(len(v.IEExtensions)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
			if fragmentOffset_ieextensions < 0 || fragmentOffset_ieextensions > int64(len(v.IEExtensions)) || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(len(v.IEExtensions[fragmentOffset_ieextensions:])) {
				return fmt.Errorf("collection fragment outside value")
			}
			for _, elem := range v.IEExtensions[fragmentOffset_ieextensions : fragmentOffset_ieextensions+fragmentLength_ieextensions] {
				if err := s11.BridgeScheduledCommunicationTimeExtIEsExtFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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

// UnmarshalAPER decodes ScheduledCommunicationTime from APER format.
func (v *ScheduledCommunicationTime) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes ScheduledCommunicationTime with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *ScheduledCommunicationTime) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "ScheduledCommunicationTime")
	}
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "ScheduledCommunicationTime")
	}
	padding, err := aper.CaptureFinalBits(bb, "ScheduledCommunicationTime")
	if err != nil {
		return runtime.WrapDecodePath(err, "ScheduledCommunicationTime")
	}
	v.perPadding = padding.WithRecords(v.perPadding)
	return nil
}
func (v *ScheduledCommunicationTime) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = ScheduledCommunicationTime{}
	extAdditions := aper.BeginExtensionAdditions(bb)
	hasExtensions, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	// Read preamble bitmap for optional root fields
	opt_dayofweek, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	opt_timeofdaystart, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	opt_timeofdayend, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	opt_ieextensions, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	if opt_dayofweek {
		bsBytes_dayofweek, bsBitLen_dayofweek, err := aper.DecodeBitStringAligned(bb, 7, 7, true)
		if err != nil {
			return runtime.WrapDecodePath(err, "DayofWeek")
		}
		tmp_dayofweek := runtime.BitString{Bytes: bsBytes_dayofweek, BitLength: bsBitLen_dayofweek}
		if err := aper.ChargeValue(bb, tmp_dayofweek); err != nil {
			return err
		}
		v.DayofWeek = &tmp_dayofweek
	}
	if opt_timeofdaystart {
		val_timeofdaystart, err := aper.DecodeIntegerBigBoundsAligned(bb, s00.BridgeAsn1IntegerBound0, s00.BridgeAsn1IntegerBound14, true)
		if err != nil {
			return runtime.WrapDecodePath(err, "TimeofDayStart")
		}
		v.TimeofDayStart = val_timeofdaystart
	}
	if opt_timeofdayend {
		val_timeofdayend, err := aper.DecodeIntegerBigBoundsAligned(bb, s00.BridgeAsn1IntegerBound0, s00.BridgeAsn1IntegerBound14, true)
		if err != nil {
			return runtime.WrapDecodePath(err, "TimeofDayEnd")
		}
		v.TimeofDayEnd = val_timeofdayend
	}
	if opt_ieextensions {
		tmp_ieextensions := make(s11.ScheduledCommunicationTimeExtIEsExtContainer, 0)
		_, errCollection_ieextensions := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1128
			if fragmentOffset_ieextensions < 0 || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(^uint(0)>>1) || fragmentOffset_ieextensions > int64(^uint(0)>>1)-fragmentLength_ieextensions {
				return fmt.Errorf("collection fragment count out of range")
			}
			for i := int64(0); i < fragmentLength_ieextensions; i++ {
				var elem s11.ScheduledCommunicationTimeExtIEsExtField
				if err := s11.BridgeScheduledCommunicationTimeExtIEsExtFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
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

// MarshalAPER encodes UEPagingID to APER format.
func (v *UEPagingID) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.perPadding)
}
func (v *UEPagingID) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
			return fmt.Errorf("%s known choice %d and unknown extension are both selected", "UEPagingID:", v.Choice)
		}
		if v.UnknownExtension.Index() < 0 {
			return fmt.Errorf("%s extension index %d must be non-negative", "UEPagingID:", v.UnknownExtension.Index())
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
		return fmt.Errorf("%s choice %d must be positive", "UEPagingID:", v.Choice)
	}
	isExtension := v.Choice > 2
	if err := aper.EncodeBoolean(bb, isExtension); err != nil {
		return err
	}
	if isExtension {
		return fmt.Errorf("%s extension choice %d not supported", "UEPagingID:", v.Choice)
	}
	// arithmetic pattern APER_CHOICE_ROOT_ENCODE: choice index fits the emitted representation; gen/codegen_aper.go:149
	if v.Choice < 1 {
		return fmt.Errorf("choice index outside root")
	}
	if err := aper.EncodeConstrainedWholeNumberAligned(bb, int64(v.Choice-1), 0, 1); err != nil {
		return err
	}
	switch v.Choice {
	case s00.UEPagingIDChoiceSTMSI:
		if v.STMSI == nil {
			return fmt.Errorf("choice alternative s-TMSI is nil")
		}
		if err := s27.BridgeSTMSIMethodMarshalAPERTo(v.STMSI, bb, len(fresh) != 0 && fresh[0]); err != nil {
			return fmt.Errorf("encoding s-TMSI: %w", err)
		}
	case s00.UEPagingIDChoiceIMSI:
		if v.IMSI == nil {
			return fmt.Errorf("choice alternative iMSI is nil")
		}
		if err := aper.EncodeOctetStringAligned(bb, []byte(*v.IMSI), 3, 8, true); err != nil {
			return fmt.Errorf("encoding iMSI: %w", err)
		}
	default:
		return fmt.Errorf("unknown UEPagingID choice %d", v.Choice)
	}
	return nil
}

// UnmarshalAPER decodes UEPagingID from APER format.
func (v *UEPagingID) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes UEPagingID with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *UEPagingID) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "UEPagingID")
	}
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "UEPagingID")
	}
	padding, err := aper.CaptureFinalBits(bb, "UEPagingID")
	if err != nil {
		return runtime.WrapDecodePath(err, "UEPagingID")
	}
	v.perPadding = padding.Padding()
	return nil
}
func (v *UEPagingID) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = UEPagingID{}
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
	case s00.UEPagingIDChoiceSTMSI:
		toleranceMark_stmsi := bb.EnterComponent("STMSI")
		var dec_stmsi s27.STMSI
		if err := s27.BridgeSTMSIMethodUnmarshalAPERFrom(&dec_stmsi, bb); err != nil {
			return runtime.WrapDecodePath(err, "STMSI")
		}
		if err := aper.ChargeValue(bb, dec_stmsi); err != nil {
			return err
		}
		v.STMSI = &dec_stmsi
		bb.LeaveComponent(toleranceMark_stmsi)
	case s00.UEPagingIDChoiceIMSI:
		val_imsi, err := aper.DecodeOctetStringAligned(bb, 3, 8, true)
		if err != nil {
			return runtime.WrapDecodePath(err, "IMSI")
		}
		tmp_imsi := s00.IMSI(val_imsi)
		if err := aper.ChargeValue(bb, tmp_imsi); err != nil {
			return err
		}
		v.IMSI = &tmp_imsi
	}
	v.stream = bb.CaptureWireSpan(replayStart)

	return nil
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *ScheduledCommunicationTime) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s14.BridgeReceivedFormAt(v.received, v.receivedBytes, "ScheduledCommunicationTime", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "ScheduledCommunicationTime", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v ScheduledCommunicationTime) WithoutReplay() ScheduledCommunicationTime {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero ScheduledCommunicationTime
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *SecondaryRATDataUsageReportItem) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s14.BridgeReceivedFormAt(v.received, v.receivedBytes, "SecondaryRATDataUsageReportItem", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "SecondaryRATDataUsageReportItem", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v SecondaryRATDataUsageReportItem) WithoutReplay() SecondaryRATDataUsageReportItem {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero SecondaryRATDataUsageReportItem
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *SecurityContext) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s14.BridgeReceivedFormAt(v.received, v.receivedBytes, "SecurityContext", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "SecurityContext", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v SecurityContext) WithoutReplay() SecurityContext {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero SecurityContext
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *SecurityIndication) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s14.BridgeReceivedFormAt(v.received, v.receivedBytes, "SecurityIndication", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "SecurityIndication", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v SecurityIndication) WithoutReplay() SecurityIndication {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero SecurityIndication
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *UEPagingID) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s14.BridgeReceivedFormAt(v.received, v.receivedBytes, "UEPagingID", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "UEPagingID", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v UEPagingID) WithoutReplay() UEPagingID {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero UEPagingID
	v.perPadding = zero.perPadding
	return v
}

// Extensions returns owned unknown sequence additions.
func (v *ScheduledCommunicationTime) Extensions() []aper.SequenceExtension {
	if v == nil {
		return nil
	}
	views := aper.SequenceExtensionViews(v.extPresent, aper.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *ScheduledCommunicationTime) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("ScheduledCommunicationTime.Extensions[%d]", index))
	}
	if err := aper.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("ScheduledCommunicationTime.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *ScheduledCommunicationTime) RemoveExtension(index uint64) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("ScheduledCommunicationTime.Extensions[%d]", index))
	}
	if err := aper.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("ScheduledCommunicationTime.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// Extensions returns owned unknown sequence additions.
func (v *SecondaryRATDataUsageReportItem) Extensions() []aper.SequenceExtension {
	if v == nil {
		return nil
	}
	views := aper.SequenceExtensionViews(v.extPresent, aper.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *SecondaryRATDataUsageReportItem) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("SecondaryRATDataUsageReportItem.Extensions[%d]", index))
	}
	if err := aper.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("SecondaryRATDataUsageReportItem.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *SecondaryRATDataUsageReportItem) RemoveExtension(index uint64) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("SecondaryRATDataUsageReportItem.Extensions[%d]", index))
	}
	if err := aper.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("SecondaryRATDataUsageReportItem.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// Extensions returns owned unknown sequence additions.
func (v *SecurityContext) Extensions() []aper.SequenceExtension {
	if v == nil {
		return nil
	}
	views := aper.SequenceExtensionViews(v.extPresent, aper.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *SecurityContext) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("SecurityContext.Extensions[%d]", index))
	}
	if err := aper.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("SecurityContext.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *SecurityContext) RemoveExtension(index uint64) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("SecurityContext.Extensions[%d]", index))
	}
	if err := aper.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("SecurityContext.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// Extensions returns owned unknown sequence additions.
func (v *SecurityIndication) Extensions() []aper.SequenceExtension {
	if v == nil {
		return nil
	}
	views := aper.SequenceExtensionViews(v.extPresent, aper.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *SecurityIndication) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("SecurityIndication.Extensions[%d]", index))
	}
	if err := aper.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("SecurityIndication.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *SecurityIndication) RemoveExtension(index uint64) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("SecurityIndication.Extensions[%d]", index))
	}
	if err := aper.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("SecurityIndication.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// MarshalAPER encodes a complete value using one per-call change plan.
func (v *ScheduledCommunicationTime) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "ScheduledCommunicationTime")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *ScheduledCommunicationTime) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "ScheduledCommunicationTime")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APScheduledCommunicationTime(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "ScheduledCommunicationTime")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "ScheduledCommunicationTime")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *ScheduledCommunicationTime) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "ScheduledCommunicationTime")
}
func (v *ScheduledCommunicationTime) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "ScheduledCommunicationTime")
}
func (v *ScheduledCommunicationTime) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APScheduledCommunicationTime(v, &s)
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
func (v *ScheduledCommunicationTime) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *ScheduledCommunicationTime) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
func (v *SecondaryRATDataUsageReportItem) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "SecondaryRATDataUsageReportItem")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *SecondaryRATDataUsageReportItem) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "SecondaryRATDataUsageReportItem")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APSecondaryRATDataUsageReportItem(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "SecondaryRATDataUsageReportItem")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "SecondaryRATDataUsageReportItem")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *SecondaryRATDataUsageReportItem) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "SecondaryRATDataUsageReportItem")
}
func (v *SecondaryRATDataUsageReportItem) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "SecondaryRATDataUsageReportItem")
}
func (v *SecondaryRATDataUsageReportItem) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APSecondaryRATDataUsageReportItem(v, &s)
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
func (v *SecondaryRATDataUsageReportItem) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *SecondaryRATDataUsageReportItem) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
func (v *SecurityContext) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "SecurityContext")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *SecurityContext) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "SecurityContext")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APSecurityContext(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "SecurityContext")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "SecurityContext")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *SecurityContext) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "SecurityContext")
}
func (v *SecurityContext) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "SecurityContext")
}
func (v *SecurityContext) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APSecurityContext(v, &s)
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
func (v *SecurityContext) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *SecurityContext) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
func (v *SecurityIndication) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "SecurityIndication")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *SecurityIndication) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "SecurityIndication")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APSecurityIndication(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "SecurityIndication")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "SecurityIndication")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *SecurityIndication) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "SecurityIndication")
}
func (v *SecurityIndication) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "SecurityIndication")
}
func (v *SecurityIndication) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APSecurityIndication(v, &s)
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
func (v *SecurityIndication) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *SecurityIndication) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
func (v *UEPagingID) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "UEPagingID")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *UEPagingID) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "UEPagingID")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APUEPagingID(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "UEPagingID")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "UEPagingID")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *UEPagingID) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "UEPagingID")
}
func (v *UEPagingID) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "UEPagingID")
}
func (v *UEPagingID) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APUEPagingID(v, &s)
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
func (v *UEPagingID) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *UEPagingID) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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

// UnmarshalAPER decodes one complete value and returns its report.
func (v *ScheduledCommunicationTime) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "ScheduledCommunicationTime")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded ScheduledCommunicationTime
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APScheduledCommunicationTime(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = ScheduledCommunicationTime{}
		return report, aper.OperationError(err, "ScheduledCommunicationTime")
	}
	*v = decoded
	return report, aper.OperationError(nil, "ScheduledCommunicationTime")
}

// UnmarshalAPER decodes one complete value and returns its report.
func (v *SecondaryRATDataUsageReportItem) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "SecondaryRATDataUsageReportItem")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded SecondaryRATDataUsageReportItem
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APSecondaryRATDataUsageReportItem(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = SecondaryRATDataUsageReportItem{}
		return report, aper.OperationError(err, "SecondaryRATDataUsageReportItem")
	}
	*v = decoded
	return report, aper.OperationError(nil, "SecondaryRATDataUsageReportItem")
}

// UnmarshalAPER decodes one complete value and returns its report.
func (v *SecurityContext) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "SecurityContext")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded SecurityContext
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APSecurityContext(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = SecurityContext{}
		return report, aper.OperationError(err, "SecurityContext")
	}
	*v = decoded
	return report, aper.OperationError(nil, "SecurityContext")
}

// UnmarshalAPER decodes one complete value and returns its report.
func (v *SecurityIndication) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "SecurityIndication")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded SecurityIndication
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APSecurityIndication(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = SecurityIndication{}
		return report, aper.OperationError(err, "SecurityIndication")
	}
	*v = decoded
	return report, aper.OperationError(nil, "SecurityIndication")
}

// UnmarshalAPER decodes one complete value and returns its report.
func (v *UEPagingID) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "UEPagingID")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded UEPagingID
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APUEPagingID(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = UEPagingID{}
		return report, aper.OperationError(err, "UEPagingID")
	}
	*v = decoded
	return report, aper.OperationError(nil, "UEPagingID")
}

// NewUEPagingIDSTMSI constructs a checked complete value.
func NewUEPagingIDSTMSI(v s27.STMSI, options ...aper.BuildOption) (UEPagingID, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return UEPagingID{}, aper.OperationError(err, "UEPagingIDSTMSI")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), v); err != nil {
		return UEPagingID{}, aper.OperationError(err, "UEPagingIDSTMSI")
	}
	value := BridgeNewUEPagingIDSTMSILegacy(v)
	if _, err := (&value).marshalAPERBudget(budget, false); err != nil {
		return UEPagingID{}, aper.OperationError(err, "UEPagingIDSTMSI")
	}
	return value, aper.OperationError(nil, "UEPagingIDSTMSI")
}

// NewUEPagingIDIMSI constructs a checked complete value.
func NewUEPagingIDIMSI(v s00.IMSI, options ...aper.BuildOption) (UEPagingID, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return UEPagingID{}, aper.OperationError(err, "UEPagingIDIMSI")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), v); err != nil {
		return UEPagingID{}, aper.OperationError(err, "UEPagingIDIMSI")
	}
	value := BridgeNewUEPagingIDIMSILegacy(v)
	if _, err := (&value).marshalAPERBudget(budget, false); err != nil {
		return UEPagingID{}, aper.OperationError(err, "UEPagingIDIMSI")
	}
	return value, aper.OperationError(nil, "UEPagingIDIMSI")
}

// NewUEPagingIDUnknownExtension builds a checked, owned unknown CHOICE alternative.
func NewUEPagingIDUnknownExtension(index uint64, contents []byte, options ...aper.BuildOption) (UEPagingID, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return UEPagingID{}, aper.OperationError(err, "UEPagingIDUnknownExtension")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), aper.ChoiceExtension{}); err != nil {
		return UEPagingID{}, aper.OperationError(err, "UEPagingIDUnknownExtension")
	}
	extension, err := aper.BuildChoiceExtension(index, contents, budget)
	if err != nil {
		return UEPagingID{}, aper.OperationError(err, "UEPagingIDUnknownExtension")
	}
	value := UEPagingID{UnknownExtension: &extension}
	if _, err := value.marshalAPERBudget(budget, false); err != nil {
		return UEPagingID{}, aper.OperationError(err, "UEPagingIDUnknownExtension")
	}
	return value, aper.OperationError(nil, "UEPagingIDUnknownExtension")
}

// ErrorIndication represents the ASN.1 type ErrorIndication (SEQUENCE).
type ErrorIndication struct {
	replay           aper.Snapshot
	stream           aper.WireSpan
	received         bool
	withoutReplay    bool
	receivedAbsolute bool
	receivedBytes    aper.WireSpan
	receivedLocation aper.Location
	ProtocolIEs      ErrorIndicationIEContainer `asn1:"tag:0,context,implicit"`
	protocolIEsIndef bool                       `asn1:"-" json:"-"`
	extCount         int64                      `asn1:"-" json:"-"`
	extPresent       []bool                     `asn1:"-" json:"-"`
	extData          [][]byte                   `asn1:"-" json:"-"`
	perPadding       aper.FinalPadding          `asn1:"-" json:"-"`
	perExtPadding    []aper.CompletePadding     `asn1:"-" json:"-"`
	extOrigin        []aper.OpaqueOrigin
	extWire          []aper.WireSpan
}

// RetrieveUEInformation represents the ASN.1 type RetrieveUEInformation (SEQUENCE).
type RetrieveUEInformation struct {
	replay           aper.Snapshot
	stream           aper.WireSpan
	received         bool
	withoutReplay    bool
	receivedAbsolute bool
	receivedBytes    aper.WireSpan
	receivedLocation aper.Location
	ProtocolIEs      RetrieveUEInformationIEContainer `asn1:"tag:0,context,implicit"`
	protocolIEsIndef bool                             `asn1:"-" json:"-"`
	extCount         int64                            `asn1:"-" json:"-"`
	extPresent       []bool                           `asn1:"-" json:"-"`
	extData          [][]byte                         `asn1:"-" json:"-"`
	perPadding       aper.FinalPadding                `asn1:"-" json:"-"`
	perExtPadding    []aper.CompletePadding           `asn1:"-" json:"-"`
	extOrigin        []aper.OpaqueOrigin
	extWire          []aper.WireSpan
}

// MarshalAPER encodes ErrorIndication to APER format.
func (v *ErrorIndication) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *ErrorIndication) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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

// UnmarshalAPER decodes ErrorIndication from APER format.
func (v *ErrorIndication) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes ErrorIndication with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *ErrorIndication) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "ErrorIndication")
	}
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "ErrorIndication")
	}
	padding, err := aper.CaptureFinalBits(bb, "ErrorIndication")
	if err != nil {
		return runtime.WrapDecodePath(err, "ErrorIndication")
	}
	v.perPadding = padding.WithRecords(v.perPadding)
	return nil
}
func (v *ErrorIndication) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = ErrorIndication{}
	extAdditions := aper.BeginExtensionAdditions(bb)
	hasExtensions, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	v.ProtocolIEs = make(ErrorIndicationIEContainer, 0)
	_, errCollection_protocolies := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1128
		if fragmentOffset_protocolies < 0 || fragmentLength_protocolies < 0 || fragmentLength_protocolies > int64(^uint(0)>>1) || fragmentOffset_protocolies > int64(^uint(0)>>1)-fragmentLength_protocolies {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_protocolies; i++ {
			var elem ErrorIndicationIEField
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

// MarshalAPER encodes RetrieveUEInformation to APER format.
func (v *RetrieveUEInformation) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *RetrieveUEInformation) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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

// UnmarshalAPER decodes RetrieveUEInformation from APER format.
func (v *RetrieveUEInformation) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes RetrieveUEInformation with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *RetrieveUEInformation) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "RetrieveUEInformation")
	}
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "RetrieveUEInformation")
	}
	padding, err := aper.CaptureFinalBits(bb, "RetrieveUEInformation")
	if err != nil {
		return runtime.WrapDecodePath(err, "RetrieveUEInformation")
	}
	v.perPadding = padding.WithRecords(v.perPadding)
	return nil
}
func (v *RetrieveUEInformation) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = RetrieveUEInformation{}
	extAdditions := aper.BeginExtensionAdditions(bb)
	hasExtensions, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	v.ProtocolIEs = make(RetrieveUEInformationIEContainer, 0)
	_, errCollection_protocolies := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1128
		if fragmentOffset_protocolies < 0 || fragmentLength_protocolies < 0 || fragmentLength_protocolies > int64(^uint(0)>>1) || fragmentOffset_protocolies > int64(^uint(0)>>1)-fragmentLength_protocolies {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_protocolies; i++ {
			var elem RetrieveUEInformationIEField
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
func (v *ErrorIndication) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s14.BridgeReceivedFormAt(v.received, v.receivedBytes, "ErrorIndication", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "ErrorIndication", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v ErrorIndication) WithoutReplay() ErrorIndication {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero ErrorIndication
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *RetrieveUEInformation) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s14.BridgeReceivedFormAt(v.received, v.receivedBytes, "RetrieveUEInformation", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "RetrieveUEInformation", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v RetrieveUEInformation) WithoutReplay() RetrieveUEInformation {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero RetrieveUEInformation
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// Extensions returns owned unknown sequence additions.
func (v *ErrorIndication) Extensions() []aper.SequenceExtension {
	if v == nil {
		return nil
	}
	views := aper.SequenceExtensionViews(v.extPresent, aper.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *ErrorIndication) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("ErrorIndication.Extensions[%d]", index))
	}
	if err := aper.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("ErrorIndication.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *ErrorIndication) RemoveExtension(index uint64) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("ErrorIndication.Extensions[%d]", index))
	}
	if err := aper.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("ErrorIndication.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// Extensions returns owned unknown sequence additions.
func (v *RetrieveUEInformation) Extensions() []aper.SequenceExtension {
	if v == nil {
		return nil
	}
	views := aper.SequenceExtensionViews(v.extPresent, aper.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *RetrieveUEInformation) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("RetrieveUEInformation.Extensions[%d]", index))
	}
	if err := aper.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("RetrieveUEInformation.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *RetrieveUEInformation) RemoveExtension(index uint64) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("RetrieveUEInformation.Extensions[%d]", index))
	}
	if err := aper.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("RetrieveUEInformation.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// MarshalAPER encodes a complete value using one per-call change plan.
func (v *ErrorIndication) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "ErrorIndication")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *ErrorIndication) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "ErrorIndication")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APErrorIndication(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "ErrorIndication")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "ErrorIndication")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *ErrorIndication) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "ErrorIndication")
}
func (v *ErrorIndication) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "ErrorIndication")
}
func (v *ErrorIndication) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APErrorIndication(v, &s)
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
func (v *ErrorIndication) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *ErrorIndication) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
func (v *RetrieveUEInformation) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "RetrieveUEInformation")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *RetrieveUEInformation) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "RetrieveUEInformation")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APRetrieveUEInformation(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "RetrieveUEInformation")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "RetrieveUEInformation")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *RetrieveUEInformation) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "RetrieveUEInformation")
}
func (v *RetrieveUEInformation) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "RetrieveUEInformation")
}
func (v *RetrieveUEInformation) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APRetrieveUEInformation(v, &s)
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
func (v *RetrieveUEInformation) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *RetrieveUEInformation) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
func (v *ErrorIndication) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "ErrorIndication")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded ErrorIndication
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APErrorIndication(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = ErrorIndication{}
		return report, aper.OperationError(err, "ErrorIndication")
	}
	*v = decoded
	return report, aper.OperationError(nil, "ErrorIndication")
}

// UnmarshalAPER decodes one complete value and returns its report.
func (v *RetrieveUEInformation) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "RetrieveUEInformation")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded RetrieveUEInformation
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APRetrieveUEInformation(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = RetrieveUEInformation{}
		return report, aper.OperationError(err, "RetrieveUEInformation")
	}
	*v = decoded
	return report, aper.OperationError(nil, "RetrieveUEInformation")
}

type ERABInformationListItemExtIEsValue struct {
	id                                 s00.ProtocolIEID
	received                           aper.WireSpan
	replay                             aper.Snapshot
	opaque                             aper.OpaqueOpenType
	isOpaque                           bool
	rowDAPSRequestInfo                 *s14.DAPSRequestInfo
	rowSourceTransportLayerAddress     *s00.TransportLayerAddress
	rowSecurityIndication              *SecurityIndication
	rowSourceNodeTransportLayerAddress *s00.TransportLayerAddress
}

func (v ERABInformationListItemExtIEsValue) matchesID(id s00.ProtocolIEID, _ ...*aper.DecodeBudget) bool {
	if v.id != id {
		return false
	}
	if v.isOpaque {
		return true
	}
	switch id {
	case s00.ProtocolIEID(317):
		return v.rowDAPSRequestInfo != nil
	case s00.ProtocolIEID(328):
		return v.rowSourceTransportLayerAddress != nil
	case s00.ProtocolIEID(332):
		return v.rowSecurityIndication != nil
	case s00.ProtocolIEID(340):
		return v.rowSourceNodeTransportLayerAddress != nil
	}
	return false
}
func (v *ERABInformationListItemExtIEsValue) Opaque() (aper.OpaqueOpenType, bool) {
	if v == nil || !v.isOpaque {
		return aper.OpaqueOpenType{}, false
	}
	return v.opaque, true
}
func (ERABInformationListItemExtIEsValue) rule() aper.SourceRule {
	return aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.4", Assignment: aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "E-RABInformationListItem-ExtIEs"}}
}
func (ERABInformationListItemExtIEsValue) reason(id s00.ProtocolIEID) aper.OpaqueReason {
	switch id {
	case s00.ProtocolIEID(317):
		return aper.UnknownSelector
	case s00.ProtocolIEID(328):
		return aper.UnknownSelector
	case s00.ProtocolIEID(332):
		return aper.UnknownSelector
	case s00.ProtocolIEID(340):
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
	case s00.ProtocolIEID(329):
		return aper.NotInTable
	case s00.ProtocolIEID(330):
		return aper.NotInTable
	case s00.ProtocolIEID(331):
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
func (v *ERABInformationListItemExtIEsValue) AsDAPSRequestInfo() (*s14.DAPSRequestInfo, bool) {
	if v == nil || v.id != s00.ProtocolIEID(317) || v.rowDAPSRequestInfo == nil {
		return nil, false
	}
	return v.rowDAPSRequestInfo, true
}
func (v *ERABInformationListItemExtIEsValue) AsSourceTransportLayerAddress() (*s00.TransportLayerAddress, bool) {
	if v == nil || v.id != s00.ProtocolIEID(328) || v.rowSourceTransportLayerAddress == nil {
		return nil, false
	}
	return v.rowSourceTransportLayerAddress, true
}
func (v *ERABInformationListItemExtIEsValue) AsSecurityIndication() (*SecurityIndication, bool) {
	if v == nil || v.id != s00.ProtocolIEID(332) || v.rowSecurityIndication == nil {
		return nil, false
	}
	return v.rowSecurityIndication, true
}
func (v *ERABInformationListItemExtIEsValue) AsSourceNodeTransportLayerAddress() (*s00.TransportLayerAddress, bool) {
	if v == nil || v.id != s00.ProtocolIEID(340) || v.rowSourceNodeTransportLayerAddress == nil {
		return nil, false
	}
	return v.rowSourceNodeTransportLayerAddress, true
}
func (v ERABInformationListItemExtIEsValue) decode(id s00.ProtocolIEID, raw aper.OpaqueOpenType) (ERABInformationListItemExtIEsValue, error) {
	out := ERABInformationListItemExtIEsValue{id: id}
	switch id {
	case s00.ProtocolIEID(317):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		var value s14.DAPSRequestInfo
		child := scope
		if err := s14.BridgeDAPSRequestInfoMethodUnmarshalAPERFrom(&value, child); err != nil {
			return out, fmt.Errorf("%s %w", "DAPSRequestInfo:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "DAPSRequestInfo")
		if err != nil {
			return out, err
		}
		*s14.BridgeDAPSRequestInfoFieldPerPadding(&value) = padding
		*s14.BridgeDAPSRequestInfoFieldReceived(&value) = true
		raw.RetainContents(s14.BridgeDAPSRequestInfoFieldReceivedBytes(&value))
		*s14.BridgeDAPSRequestInfoFieldReceivedLocation(&value) = raw.ContentLocation()
		out.rowDAPSRequestInfo = &value
		raw.RetainContents(&out.received)
	case s00.ProtocolIEID(328):
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
		out.rowSourceTransportLayerAddress = &value
		raw.RetainContents(&out.received)
	case s00.ProtocolIEID(332):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		var value SecurityIndication
		child := scope
		if err := value.unmarshalAPERFrom(child); err != nil {
			return out, fmt.Errorf("%s %w", "SecurityIndication:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "SecurityIndication")
		if err != nil {
			return out, err
		}
		value.perPadding = padding
		value.received = true
		raw.RetainContents(&value.receivedBytes)
		value.receivedLocation = raw.ContentLocation()
		out.rowSecurityIndication = &value
		raw.RetainContents(&out.received)
	case s00.ProtocolIEID(340):
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
		out.rowSourceNodeTransportLayerAddress = &value
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
func (v ERABInformationListItemExtIEsValue) encode() ([]byte, error) {
	return v.encodeFresh(false, nil)
}
func (v ERABInformationListItemExtIEsValue) encodeFresh(fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
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
	case s00.ProtocolIEID(317):
		if v.rowDAPSRequestInfo == nil {
			return nil, fmt.Errorf("%s missing value", "E-RABInformationListItem-ExtIEs.id-DAPSRequestInfo:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		candidate, err := s14.BridgeDAPSRequestInfoMethodMarshalAPERBudget(v.rowDAPSRequestInfo, budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	case s00.ProtocolIEID(328):
		if v.rowSourceTransportLayerAddress == nil {
			return nil, fmt.Errorf("%s missing value", "E-RABInformationListItem-ExtIEs.id-SourceTransportLayerAddress:")
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
		})(*v.rowSourceTransportLayerAddress, budget)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	case s00.ProtocolIEID(332):
		if v.rowSecurityIndication == nil {
			return nil, fmt.Errorf("%s missing value", "E-RABInformationListItem-ExtIEs.id-SecurityIndication:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		candidate, err := v.rowSecurityIndication.marshalAPERBudget(budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	case s00.ProtocolIEID(340):
		if v.rowSourceNodeTransportLayerAddress == nil {
			return nil, fmt.Errorf("%s missing value", "E-RABInformationListItem-ExtIEs.id-SourceNodeTransportLayerAddress:")
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
		})(*v.rowSourceNodeTransportLayerAddress, budget)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	default:
		return nil, fmt.Errorf("%s id %d has no value", "ERABInformationListItemExtIEsValue:", v.id)
	}
}

type SecondaryRATDataUsageReportItemIEValue struct {
	id                                 s00.ProtocolIEID
	received                           aper.WireSpan
	replay                             aper.Snapshot
	opaque                             aper.OpaqueOpenType
	isOpaque                           bool
	rowSecondaryRATDataUsageReportItem *SecondaryRATDataUsageReportItem
}

func (v SecondaryRATDataUsageReportItemIEValue) matchesID(id s00.ProtocolIEID, _ ...*aper.DecodeBudget) bool {
	if v.id != id {
		return false
	}
	if v.isOpaque {
		return true
	}
	switch id {
	case s00.ProtocolIEID(265):
		return v.rowSecondaryRATDataUsageReportItem != nil
	}
	return false
}
func (v *SecondaryRATDataUsageReportItemIEValue) Opaque() (aper.OpaqueOpenType, bool) {
	if v == nil || !v.isOpaque {
		return aper.OpaqueOpenType{}, false
	}
	return v.opaque, true
}
func (SecondaryRATDataUsageReportItemIEValue) rule() aper.SourceRule {
	return aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.4", Assignment: aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "SecondaryRATDataUsageReportItemIEs"}}
}
func (SecondaryRATDataUsageReportItemIEValue) reason(id s00.ProtocolIEID) aper.OpaqueReason {
	switch id {
	case s00.ProtocolIEID(265):
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
func (v *SecondaryRATDataUsageReportItemIEValue) AsSecondaryRATDataUsageReportItem() (*SecondaryRATDataUsageReportItem, bool) {
	if v == nil || v.id != s00.ProtocolIEID(265) || v.rowSecondaryRATDataUsageReportItem == nil {
		return nil, false
	}
	return v.rowSecondaryRATDataUsageReportItem, true
}
func (v SecondaryRATDataUsageReportItemIEValue) decode(id s00.ProtocolIEID, raw aper.OpaqueOpenType) (SecondaryRATDataUsageReportItemIEValue, error) {
	out := SecondaryRATDataUsageReportItemIEValue{id: id}
	switch id {
	case s00.ProtocolIEID(265):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		var value SecondaryRATDataUsageReportItem
		child := scope
		if err := value.unmarshalAPERFrom(child); err != nil {
			return out, fmt.Errorf("%s %w", "SecondaryRATDataUsageReportItem:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "SecondaryRATDataUsageReportItem")
		if err != nil {
			return out, err
		}
		value.perPadding = padding
		value.received = true
		raw.RetainContents(&value.receivedBytes)
		value.receivedLocation = raw.ContentLocation()
		out.rowSecondaryRATDataUsageReportItem = &value
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
func (v SecondaryRATDataUsageReportItemIEValue) encode() ([]byte, error) {
	return v.encodeFresh(false, nil)
}
func (v SecondaryRATDataUsageReportItemIEValue) encodeFresh(fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
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
	case s00.ProtocolIEID(265):
		if v.rowSecondaryRATDataUsageReportItem == nil {
			return nil, fmt.Errorf("%s missing value", "SecondaryRATDataUsageReportItemIEs.id-SecondaryRATDataUsageReportItem:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		candidate, err := v.rowSecondaryRATDataUsageReportItem.marshalAPERBudget(budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	default:
		return nil, fmt.Errorf("%s id %d has no value", "SecondaryRATDataUsageReportItemIEValue:", v.id)
	}
}

type ERABToBeSetupItemBearerSUReqExtIEsValue struct {
	id                    s00.ProtocolIEID
	received              aper.WireSpan
	replay                aper.Snapshot
	opaque                aper.OpaqueOpenType
	isOpaque              bool
	rowCorrelationID      *s00.CorrelationID
	rowSIPTOCorrelationID *s00.CorrelationID
	rowBearerType         *s00.BearerType
	rowEthernetType       *s00.EthernetType
	rowSecurityIndication *SecurityIndication
}

func (v ERABToBeSetupItemBearerSUReqExtIEsValue) matchesID(id s00.ProtocolIEID, _ ...*aper.DecodeBudget) bool {
	if v.id != id {
		return false
	}
	if v.isOpaque {
		return true
	}
	switch id {
	case s00.ProtocolIEID(156):
		return v.rowCorrelationID != nil
	case s00.ProtocolIEID(183):
		return v.rowSIPTOCorrelationID != nil
	case s00.ProtocolIEID(233):
		return v.rowBearerType != nil
	case s00.ProtocolIEID(305):
		return v.rowEthernetType != nil
	case s00.ProtocolIEID(332):
		return v.rowSecurityIndication != nil
	}
	return false
}
func (v *ERABToBeSetupItemBearerSUReqExtIEsValue) Opaque() (aper.OpaqueOpenType, bool) {
	if v == nil || !v.isOpaque {
		return aper.OpaqueOpenType{}, false
	}
	return v.opaque, true
}
func (ERABToBeSetupItemBearerSUReqExtIEsValue) rule() aper.SourceRule {
	return aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "E-RABToBeSetupItemBearerSUReqExtIEs"}}
}
func (ERABToBeSetupItemBearerSUReqExtIEsValue) reason(id s00.ProtocolIEID) aper.OpaqueReason {
	switch id {
	case s00.ProtocolIEID(156):
		return aper.UnknownSelector
	case s00.ProtocolIEID(183):
		return aper.UnknownSelector
	case s00.ProtocolIEID(233):
		return aper.UnknownSelector
	case s00.ProtocolIEID(305):
		return aper.UnknownSelector
	case s00.ProtocolIEID(332):
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
func (v *ERABToBeSetupItemBearerSUReqExtIEsValue) AsCorrelationID() (*s00.CorrelationID, bool) {
	if v == nil || v.id != s00.ProtocolIEID(156) || v.rowCorrelationID == nil {
		return nil, false
	}
	return v.rowCorrelationID, true
}
func (v *ERABToBeSetupItemBearerSUReqExtIEsValue) AsSIPTOCorrelationID() (*s00.CorrelationID, bool) {
	if v == nil || v.id != s00.ProtocolIEID(183) || v.rowSIPTOCorrelationID == nil {
		return nil, false
	}
	return v.rowSIPTOCorrelationID, true
}
func (v *ERABToBeSetupItemBearerSUReqExtIEsValue) AsBearerType() (*s00.BearerType, bool) {
	if v == nil || v.id != s00.ProtocolIEID(233) || v.rowBearerType == nil {
		return nil, false
	}
	return v.rowBearerType, true
}
func (v *ERABToBeSetupItemBearerSUReqExtIEsValue) AsEthernetType() (*s00.EthernetType, bool) {
	if v == nil || v.id != s00.ProtocolIEID(305) || v.rowEthernetType == nil {
		return nil, false
	}
	return v.rowEthernetType, true
}
func (v *ERABToBeSetupItemBearerSUReqExtIEsValue) AsSecurityIndication() (*SecurityIndication, bool) {
	if v == nil || v.id != s00.ProtocolIEID(332) || v.rowSecurityIndication == nil {
		return nil, false
	}
	return v.rowSecurityIndication, true
}
func (v ERABToBeSetupItemBearerSUReqExtIEsValue) decode(id s00.ProtocolIEID, raw aper.OpaqueOpenType) (ERABToBeSetupItemBearerSUReqExtIEsValue, error) {
	out := ERABToBeSetupItemBearerSUReqExtIEsValue{id: id}
	switch id {
	case s00.ProtocolIEID(156):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		child := scope
		value, err := (func(bb *aper.BitBuffer) (s00.CorrelationID, error) {
			var v struct{ Value s00.CorrelationID }
			err := func() error {
				val_value, err := aper.DecodeOctetStringAligned(bb, 4, 4, true)
				if err != nil {
					return runtime.WrapDecodePath(err, "Value")
				}
				v.Value = s00.CorrelationID(val_value)
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
		out.rowCorrelationID = &value
		raw.RetainContents(&out.received)
	case s00.ProtocolIEID(183):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		child := scope
		value, err := (func(bb *aper.BitBuffer) (s00.CorrelationID, error) {
			var v struct{ Value s00.CorrelationID }
			err := func() error {
				val_value, err := aper.DecodeOctetStringAligned(bb, 4, 4, true)
				if err != nil {
					return runtime.WrapDecodePath(err, "Value")
				}
				v.Value = s00.CorrelationID(val_value)
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
		out.rowSIPTOCorrelationID = &value
		raw.RetainContents(&out.received)
	case s00.ProtocolIEID(233):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		bb := scope
		decoded, err := aper.DecodeEnumeratedAligned(bb, 1, true, aper.EnumerationSource{KnownExtensions: 0, Path: "BearerType"})
		value := s00.BearerType(decoded)
		if err != nil {
			return out, fmt.Errorf("%s %w", "BearerType:", err)
		}
		if _, err := aper.CompleteOpenTypeValue(bb, value); err != nil {
			return out, err
		}
		out.rowBearerType = &value
		raw.RetainContents(&out.received)
	case s00.ProtocolIEID(305):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		bb := scope
		decoded, err := aper.DecodeEnumeratedAligned(bb, 1, true, aper.EnumerationSource{KnownExtensions: 0, Path: "EthernetType"})
		value := s00.EthernetType(decoded)
		if err != nil {
			return out, fmt.Errorf("%s %w", "EthernetType:", err)
		}
		if _, err := aper.CompleteOpenTypeValue(bb, value); err != nil {
			return out, err
		}
		out.rowEthernetType = &value
		raw.RetainContents(&out.received)
	case s00.ProtocolIEID(332):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		var value SecurityIndication
		child := scope
		if err := value.unmarshalAPERFrom(child); err != nil {
			return out, fmt.Errorf("%s %w", "SecurityIndication:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "SecurityIndication")
		if err != nil {
			return out, err
		}
		value.perPadding = padding
		value.received = true
		raw.RetainContents(&value.receivedBytes)
		value.receivedLocation = raw.ContentLocation()
		out.rowSecurityIndication = &value
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
func (v ERABToBeSetupItemBearerSUReqExtIEsValue) encode() ([]byte, error) {
	return v.encodeFresh(false, nil)
}
func (v ERABToBeSetupItemBearerSUReqExtIEsValue) encodeFresh(fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
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
	case s00.ProtocolIEID(156):
		if v.rowCorrelationID == nil {
			return nil, fmt.Errorf("%s missing value", "E-RABToBeSetupItemBearerSUReqExtIEs.id-Correlation-ID:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		candidate, err := (func(value s00.CorrelationID, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			v := struct{ Value s00.CorrelationID }{Value: value}
			_ = v
			err := func() error {
				if err := aper.EncodeOctetStringAligned(bb, []byte(v.Value), 4, 4, true); err != nil {
					return fmt.Errorf("encoding value: %w", err)
				}
				return nil
			}()
			if err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		})(*v.rowCorrelationID, budget)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	case s00.ProtocolIEID(183):
		if v.rowSIPTOCorrelationID == nil {
			return nil, fmt.Errorf("%s missing value", "E-RABToBeSetupItemBearerSUReqExtIEs.id-SIPTO-Correlation-ID:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		candidate, err := (func(value s00.CorrelationID, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			v := struct{ Value s00.CorrelationID }{Value: value}
			_ = v
			err := func() error {
				if err := aper.EncodeOctetStringAligned(bb, []byte(v.Value), 4, 4, true); err != nil {
					return fmt.Errorf("encoding value: %w", err)
				}
				return nil
			}()
			if err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		})(*v.rowSIPTOCorrelationID, budget)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	case s00.ProtocolIEID(233):
		if v.rowBearerType == nil {
			return nil, fmt.Errorf("%s missing value", "E-RABToBeSetupItemBearerSUReqExtIEs.id-BearerType:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		encodeBB := aper.NewBudgetBuffer(budget)
		if err := aper.EncodeEnumeratedAligned(encodeBB, int64(*v.rowBearerType), 1, true); err != nil {
			return nil, err
		}
		candidate := encodeBB.CompleteBytes()
		return candidate, nil
	case s00.ProtocolIEID(305):
		if v.rowEthernetType == nil {
			return nil, fmt.Errorf("%s missing value", "E-RABToBeSetupItemBearerSUReqExtIEs.id-Ethernet-Type:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		encodeBB := aper.NewBudgetBuffer(budget)
		if err := aper.EncodeEnumeratedAligned(encodeBB, int64(*v.rowEthernetType), 1, true); err != nil {
			return nil, err
		}
		candidate := encodeBB.CompleteBytes()
		return candidate, nil
	case s00.ProtocolIEID(332):
		if v.rowSecurityIndication == nil {
			return nil, fmt.Errorf("%s missing value", "E-RABToBeSetupItemBearerSUReqExtIEs.id-SecurityIndication:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		candidate, err := v.rowSecurityIndication.marshalAPERBudget(budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	default:
		return nil, fmt.Errorf("%s id %d has no value", "ERABToBeSetupItemBearerSUReqExtIEsValue:", v.id)
	}
}

type ERABToBeSetupItemCtxtSUReqExtIEsValue struct {
	id                    s00.ProtocolIEID
	received              aper.WireSpan
	replay                aper.Snapshot
	opaque                aper.OpaqueOpenType
	isOpaque              bool
	rowCorrelationID      *s00.CorrelationID
	rowSIPTOCorrelationID *s00.CorrelationID
	rowBearerType         *s00.BearerType
	rowEthernetType       *s00.EthernetType
	rowSecurityIndication *SecurityIndication
}

func (v ERABToBeSetupItemCtxtSUReqExtIEsValue) matchesID(id s00.ProtocolIEID, _ ...*aper.DecodeBudget) bool {
	if v.id != id {
		return false
	}
	if v.isOpaque {
		return true
	}
	switch id {
	case s00.ProtocolIEID(156):
		return v.rowCorrelationID != nil
	case s00.ProtocolIEID(183):
		return v.rowSIPTOCorrelationID != nil
	case s00.ProtocolIEID(233):
		return v.rowBearerType != nil
	case s00.ProtocolIEID(305):
		return v.rowEthernetType != nil
	case s00.ProtocolIEID(332):
		return v.rowSecurityIndication != nil
	}
	return false
}
func (v *ERABToBeSetupItemCtxtSUReqExtIEsValue) Opaque() (aper.OpaqueOpenType, bool) {
	if v == nil || !v.isOpaque {
		return aper.OpaqueOpenType{}, false
	}
	return v.opaque, true
}
func (ERABToBeSetupItemCtxtSUReqExtIEsValue) rule() aper.SourceRule {
	return aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "E-RABToBeSetupItemCtxtSUReqExtIEs"}}
}
func (ERABToBeSetupItemCtxtSUReqExtIEsValue) reason(id s00.ProtocolIEID) aper.OpaqueReason {
	switch id {
	case s00.ProtocolIEID(156):
		return aper.UnknownSelector
	case s00.ProtocolIEID(183):
		return aper.UnknownSelector
	case s00.ProtocolIEID(233):
		return aper.UnknownSelector
	case s00.ProtocolIEID(305):
		return aper.UnknownSelector
	case s00.ProtocolIEID(332):
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
func (v *ERABToBeSetupItemCtxtSUReqExtIEsValue) AsCorrelationID() (*s00.CorrelationID, bool) {
	if v == nil || v.id != s00.ProtocolIEID(156) || v.rowCorrelationID == nil {
		return nil, false
	}
	return v.rowCorrelationID, true
}
func (v *ERABToBeSetupItemCtxtSUReqExtIEsValue) AsSIPTOCorrelationID() (*s00.CorrelationID, bool) {
	if v == nil || v.id != s00.ProtocolIEID(183) || v.rowSIPTOCorrelationID == nil {
		return nil, false
	}
	return v.rowSIPTOCorrelationID, true
}
func (v *ERABToBeSetupItemCtxtSUReqExtIEsValue) AsBearerType() (*s00.BearerType, bool) {
	if v == nil || v.id != s00.ProtocolIEID(233) || v.rowBearerType == nil {
		return nil, false
	}
	return v.rowBearerType, true
}
func (v *ERABToBeSetupItemCtxtSUReqExtIEsValue) AsEthernetType() (*s00.EthernetType, bool) {
	if v == nil || v.id != s00.ProtocolIEID(305) || v.rowEthernetType == nil {
		return nil, false
	}
	return v.rowEthernetType, true
}
func (v *ERABToBeSetupItemCtxtSUReqExtIEsValue) AsSecurityIndication() (*SecurityIndication, bool) {
	if v == nil || v.id != s00.ProtocolIEID(332) || v.rowSecurityIndication == nil {
		return nil, false
	}
	return v.rowSecurityIndication, true
}
func (v ERABToBeSetupItemCtxtSUReqExtIEsValue) decode(id s00.ProtocolIEID, raw aper.OpaqueOpenType) (ERABToBeSetupItemCtxtSUReqExtIEsValue, error) {
	out := ERABToBeSetupItemCtxtSUReqExtIEsValue{id: id}
	switch id {
	case s00.ProtocolIEID(156):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		child := scope
		value, err := (func(bb *aper.BitBuffer) (s00.CorrelationID, error) {
			var v struct{ Value s00.CorrelationID }
			err := func() error {
				val_value, err := aper.DecodeOctetStringAligned(bb, 4, 4, true)
				if err != nil {
					return runtime.WrapDecodePath(err, "Value")
				}
				v.Value = s00.CorrelationID(val_value)
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
		out.rowCorrelationID = &value
		raw.RetainContents(&out.received)
	case s00.ProtocolIEID(183):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		child := scope
		value, err := (func(bb *aper.BitBuffer) (s00.CorrelationID, error) {
			var v struct{ Value s00.CorrelationID }
			err := func() error {
				val_value, err := aper.DecodeOctetStringAligned(bb, 4, 4, true)
				if err != nil {
					return runtime.WrapDecodePath(err, "Value")
				}
				v.Value = s00.CorrelationID(val_value)
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
		out.rowSIPTOCorrelationID = &value
		raw.RetainContents(&out.received)
	case s00.ProtocolIEID(233):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		bb := scope
		decoded, err := aper.DecodeEnumeratedAligned(bb, 1, true, aper.EnumerationSource{KnownExtensions: 0, Path: "BearerType"})
		value := s00.BearerType(decoded)
		if err != nil {
			return out, fmt.Errorf("%s %w", "BearerType:", err)
		}
		if _, err := aper.CompleteOpenTypeValue(bb, value); err != nil {
			return out, err
		}
		out.rowBearerType = &value
		raw.RetainContents(&out.received)
	case s00.ProtocolIEID(305):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		bb := scope
		decoded, err := aper.DecodeEnumeratedAligned(bb, 1, true, aper.EnumerationSource{KnownExtensions: 0, Path: "EthernetType"})
		value := s00.EthernetType(decoded)
		if err != nil {
			return out, fmt.Errorf("%s %w", "EthernetType:", err)
		}
		if _, err := aper.CompleteOpenTypeValue(bb, value); err != nil {
			return out, err
		}
		out.rowEthernetType = &value
		raw.RetainContents(&out.received)
	case s00.ProtocolIEID(332):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		var value SecurityIndication
		child := scope
		if err := value.unmarshalAPERFrom(child); err != nil {
			return out, fmt.Errorf("%s %w", "SecurityIndication:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "SecurityIndication")
		if err != nil {
			return out, err
		}
		value.perPadding = padding
		value.received = true
		raw.RetainContents(&value.receivedBytes)
		value.receivedLocation = raw.ContentLocation()
		out.rowSecurityIndication = &value
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
func (v ERABToBeSetupItemCtxtSUReqExtIEsValue) encode() ([]byte, error) {
	return v.encodeFresh(false, nil)
}
func (v ERABToBeSetupItemCtxtSUReqExtIEsValue) encodeFresh(fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
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
	case s00.ProtocolIEID(156):
		if v.rowCorrelationID == nil {
			return nil, fmt.Errorf("%s missing value", "E-RABToBeSetupItemCtxtSUReqExtIEs.id-Correlation-ID:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		candidate, err := (func(value s00.CorrelationID, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			v := struct{ Value s00.CorrelationID }{Value: value}
			_ = v
			err := func() error {
				if err := aper.EncodeOctetStringAligned(bb, []byte(v.Value), 4, 4, true); err != nil {
					return fmt.Errorf("encoding value: %w", err)
				}
				return nil
			}()
			if err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		})(*v.rowCorrelationID, budget)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	case s00.ProtocolIEID(183):
		if v.rowSIPTOCorrelationID == nil {
			return nil, fmt.Errorf("%s missing value", "E-RABToBeSetupItemCtxtSUReqExtIEs.id-SIPTO-Correlation-ID:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		candidate, err := (func(value s00.CorrelationID, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			v := struct{ Value s00.CorrelationID }{Value: value}
			_ = v
			err := func() error {
				if err := aper.EncodeOctetStringAligned(bb, []byte(v.Value), 4, 4, true); err != nil {
					return fmt.Errorf("encoding value: %w", err)
				}
				return nil
			}()
			if err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		})(*v.rowSIPTOCorrelationID, budget)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	case s00.ProtocolIEID(233):
		if v.rowBearerType == nil {
			return nil, fmt.Errorf("%s missing value", "E-RABToBeSetupItemCtxtSUReqExtIEs.id-BearerType:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		encodeBB := aper.NewBudgetBuffer(budget)
		if err := aper.EncodeEnumeratedAligned(encodeBB, int64(*v.rowBearerType), 1, true); err != nil {
			return nil, err
		}
		candidate := encodeBB.CompleteBytes()
		return candidate, nil
	case s00.ProtocolIEID(305):
		if v.rowEthernetType == nil {
			return nil, fmt.Errorf("%s missing value", "E-RABToBeSetupItemCtxtSUReqExtIEs.id-Ethernet-Type:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		encodeBB := aper.NewBudgetBuffer(budget)
		if err := aper.EncodeEnumeratedAligned(encodeBB, int64(*v.rowEthernetType), 1, true); err != nil {
			return nil, err
		}
		candidate := encodeBB.CompleteBytes()
		return candidate, nil
	case s00.ProtocolIEID(332):
		if v.rowSecurityIndication == nil {
			return nil, fmt.Errorf("%s missing value", "E-RABToBeSetupItemCtxtSUReqExtIEs.id-SecurityIndication:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		candidate, err := v.rowSecurityIndication.marshalAPERBudget(budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	default:
		return nil, fmt.Errorf("%s id %d has no value", "ERABToBeSetupItemCtxtSUReqExtIEsValue:", v.id)
	}
}

type ErrorIndicationIEValue struct {
	id                        s00.ProtocolIEID
	received                  aper.WireSpan
	replay                    aper.Snapshot
	opaque                    aper.OpaqueOpenType
	isOpaque                  bool
	rowMMEUES1APID            *s00.MMEUES1APID
	rowENBUES1APID            *s00.ENBUES1APID
	rowCause                  *s14.Cause
	rowCriticalityDiagnostics *s22.CriticalityDiagnostics
	rowSTMSI                  *s27.STMSI
}

func (v ErrorIndicationIEValue) matchesID(id s00.ProtocolIEID, _ ...*aper.DecodeBudget) bool {
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
	case s00.ProtocolIEID(58):
		return v.rowCriticalityDiagnostics != nil
	case s00.ProtocolIEID(96):
		return v.rowSTMSI != nil
	}
	return false
}
func (v *ErrorIndicationIEValue) Opaque() (aper.OpaqueOpenType, bool) {
	if v == nil || !v.isOpaque {
		return aper.OpaqueOpenType{}, false
	}
	return v.opaque, true
}
func (ErrorIndicationIEValue) rule() aper.SourceRule {
	return aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "ErrorIndicationIEs"}}
}
func (ErrorIndicationIEValue) reason(id s00.ProtocolIEID) aper.OpaqueReason {
	switch id {
	case s00.ProtocolIEID(0):
		return aper.UnknownSelector
	case s00.ProtocolIEID(8):
		return aper.UnknownSelector
	case s00.ProtocolIEID(2):
		return aper.UnknownSelector
	case s00.ProtocolIEID(58):
		return aper.UnknownSelector
	case s00.ProtocolIEID(96):
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
func (v *ErrorIndicationIEValue) AsMMEUES1APID() (*s00.MMEUES1APID, bool) {
	if v == nil || v.id != s00.ProtocolIEID(0) || v.rowMMEUES1APID == nil {
		return nil, false
	}
	return v.rowMMEUES1APID, true
}
func (v *ErrorIndicationIEValue) AsENBUES1APID() (*s00.ENBUES1APID, bool) {
	if v == nil || v.id != s00.ProtocolIEID(8) || v.rowENBUES1APID == nil {
		return nil, false
	}
	return v.rowENBUES1APID, true
}
func (v *ErrorIndicationIEValue) AsCause() (*s14.Cause, bool) {
	if v == nil || v.id != s00.ProtocolIEID(2) || v.rowCause == nil {
		return nil, false
	}
	return v.rowCause, true
}
func (v *ErrorIndicationIEValue) AsCriticalityDiagnostics() (*s22.CriticalityDiagnostics, bool) {
	if v == nil || v.id != s00.ProtocolIEID(58) || v.rowCriticalityDiagnostics == nil {
		return nil, false
	}
	return v.rowCriticalityDiagnostics, true
}
func (v *ErrorIndicationIEValue) AsSTMSI() (*s27.STMSI, bool) {
	if v == nil || v.id != s00.ProtocolIEID(96) || v.rowSTMSI == nil {
		return nil, false
	}
	return v.rowSTMSI, true
}
func (v ErrorIndicationIEValue) decode(id s00.ProtocolIEID, raw aper.OpaqueOpenType) (ErrorIndicationIEValue, error) {
	out := ErrorIndicationIEValue{id: id}
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
	default:
		if err := raw.Observe(aper.UnknownIE); err != nil {
			return out, err
		}
		out.opaque = raw.Detached()
		out.isOpaque = true
	}
	return out, nil
}
func (v ErrorIndicationIEValue) encode() ([]byte, error) { return v.encodeFresh(false, nil) }
func (v ErrorIndicationIEValue) encodeFresh(fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
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
			return nil, fmt.Errorf("%s missing value", "ErrorIndicationIEs.id-MME-UE-S1AP-ID:")
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
			return nil, fmt.Errorf("%s missing value", "ErrorIndicationIEs.id-eNB-UE-S1AP-ID:")
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
			return nil, fmt.Errorf("%s missing value", "ErrorIndicationIEs.id-Cause:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		candidate, err := s14.BridgeCauseMethodMarshalAPERBudget(v.rowCause, budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	case s00.ProtocolIEID(58):
		if v.rowCriticalityDiagnostics == nil {
			return nil, fmt.Errorf("%s missing value", "ErrorIndicationIEs.id-CriticalityDiagnostics:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		candidate, err := s22.BridgeCriticalityDiagnosticsMethodMarshalAPERBudget(v.rowCriticalityDiagnostics, budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	case s00.ProtocolIEID(96):
		if v.rowSTMSI == nil {
			return nil, fmt.Errorf("%s missing value", "ErrorIndicationIEs.id-S-TMSI:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		candidate, err := s27.BridgeSTMSIMethodMarshalAPERBudget(v.rowSTMSI, budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	default:
		return nil, fmt.Errorf("%s id %d has no value", "ErrorIndicationIEValue:", v.id)
	}
}

type RetrieveUEInformationIEValue struct {
	id       s00.ProtocolIEID
	received aper.WireSpan
	replay   aper.Snapshot
	opaque   aper.OpaqueOpenType
	isOpaque bool
	rowSTMSI *s27.STMSI
}

func (v RetrieveUEInformationIEValue) matchesID(id s00.ProtocolIEID, _ ...*aper.DecodeBudget) bool {
	if v.id != id {
		return false
	}
	if v.isOpaque {
		return true
	}
	switch id {
	case s00.ProtocolIEID(96):
		return v.rowSTMSI != nil
	}
	return false
}
func (v *RetrieveUEInformationIEValue) Opaque() (aper.OpaqueOpenType, bool) {
	if v == nil || !v.isOpaque {
		return aper.OpaqueOpenType{}, false
	}
	return v.opaque, true
}
func (RetrieveUEInformationIEValue) rule() aper.SourceRule {
	return aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "RetrieveUEInformationIEs"}}
}
func (RetrieveUEInformationIEValue) reason(id s00.ProtocolIEID) aper.OpaqueReason {
	switch id {
	case s00.ProtocolIEID(96):
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
func (v *RetrieveUEInformationIEValue) AsSTMSI() (*s27.STMSI, bool) {
	if v == nil || v.id != s00.ProtocolIEID(96) || v.rowSTMSI == nil {
		return nil, false
	}
	return v.rowSTMSI, true
}
func (v RetrieveUEInformationIEValue) decode(id s00.ProtocolIEID, raw aper.OpaqueOpenType) (RetrieveUEInformationIEValue, error) {
	out := RetrieveUEInformationIEValue{id: id}
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
	default:
		if err := raw.Observe(aper.UnknownIE); err != nil {
			return out, err
		}
		out.opaque = raw.Detached()
		out.isOpaque = true
	}
	return out, nil
}
func (v RetrieveUEInformationIEValue) encode() ([]byte, error) { return v.encodeFresh(false, nil) }
func (v RetrieveUEInformationIEValue) encodeFresh(fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
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
			return nil, fmt.Errorf("%s missing value", "RetrieveUEInformationIEs.id-S-TMSI:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		candidate, err := s27.BridgeSTMSIMethodMarshalAPERBudget(v.rowSTMSI, budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	default:
		return nil, fmt.Errorf("%s id %d has no value", "RetrieveUEInformationIEValue:", v.id)
	}
}

type UEContextSuspendResponseIEValue struct {
	id                        s00.ProtocolIEID
	received                  aper.WireSpan
	replay                    aper.Snapshot
	opaque                    aper.OpaqueOpenType
	isOpaque                  bool
	rowMMEUES1APID            *s00.MMEUES1APID
	rowENBUES1APID            *s00.ENBUES1APID
	rowCriticalityDiagnostics *s22.CriticalityDiagnostics
	rowSecurityContext        *SecurityContext
}

func (v UEContextSuspendResponseIEValue) matchesID(id s00.ProtocolIEID, _ ...*aper.DecodeBudget) bool {
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
	case s00.ProtocolIEID(58):
		return v.rowCriticalityDiagnostics != nil
	case s00.ProtocolIEID(40):
		return v.rowSecurityContext != nil
	}
	return false
}
func (v *UEContextSuspendResponseIEValue) Opaque() (aper.OpaqueOpenType, bool) {
	if v == nil || !v.isOpaque {
		return aper.OpaqueOpenType{}, false
	}
	return v.opaque, true
}
func (UEContextSuspendResponseIEValue) rule() aper.SourceRule {
	return aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "UEContextSuspendResponseIEs"}}
}
func (UEContextSuspendResponseIEValue) reason(id s00.ProtocolIEID) aper.OpaqueReason {
	switch id {
	case s00.ProtocolIEID(0):
		return aper.UnknownSelector
	case s00.ProtocolIEID(8):
		return aper.UnknownSelector
	case s00.ProtocolIEID(58):
		return aper.UnknownSelector
	case s00.ProtocolIEID(40):
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
func (v *UEContextSuspendResponseIEValue) AsMMEUES1APID() (*s00.MMEUES1APID, bool) {
	if v == nil || v.id != s00.ProtocolIEID(0) || v.rowMMEUES1APID == nil {
		return nil, false
	}
	return v.rowMMEUES1APID, true
}
func (v *UEContextSuspendResponseIEValue) AsENBUES1APID() (*s00.ENBUES1APID, bool) {
	if v == nil || v.id != s00.ProtocolIEID(8) || v.rowENBUES1APID == nil {
		return nil, false
	}
	return v.rowENBUES1APID, true
}
func (v *UEContextSuspendResponseIEValue) AsCriticalityDiagnostics() (*s22.CriticalityDiagnostics, bool) {
	if v == nil || v.id != s00.ProtocolIEID(58) || v.rowCriticalityDiagnostics == nil {
		return nil, false
	}
	return v.rowCriticalityDiagnostics, true
}
func (v *UEContextSuspendResponseIEValue) AsSecurityContext() (*SecurityContext, bool) {
	if v == nil || v.id != s00.ProtocolIEID(40) || v.rowSecurityContext == nil {
		return nil, false
	}
	return v.rowSecurityContext, true
}
func (v UEContextSuspendResponseIEValue) decode(id s00.ProtocolIEID, raw aper.OpaqueOpenType) (UEContextSuspendResponseIEValue, error) {
	out := UEContextSuspendResponseIEValue{id: id}
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
	case s00.ProtocolIEID(40):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		var value SecurityContext
		child := scope
		if err := value.unmarshalAPERFrom(child); err != nil {
			return out, fmt.Errorf("%s %w", "SecurityContext:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "SecurityContext")
		if err != nil {
			return out, err
		}
		value.perPadding = padding
		value.received = true
		raw.RetainContents(&value.receivedBytes)
		value.receivedLocation = raw.ContentLocation()
		out.rowSecurityContext = &value
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
func (v UEContextSuspendResponseIEValue) encode() ([]byte, error) { return v.encodeFresh(false, nil) }
func (v UEContextSuspendResponseIEValue) encodeFresh(fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
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
			return nil, fmt.Errorf("%s missing value", "UEContextSuspendResponseIEs.id-MME-UE-S1AP-ID:")
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
			return nil, fmt.Errorf("%s missing value", "UEContextSuspendResponseIEs.id-eNB-UE-S1AP-ID:")
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
	case s00.ProtocolIEID(58):
		if v.rowCriticalityDiagnostics == nil {
			return nil, fmt.Errorf("%s missing value", "UEContextSuspendResponseIEs.id-CriticalityDiagnostics:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		candidate, err := s22.BridgeCriticalityDiagnosticsMethodMarshalAPERBudget(v.rowCriticalityDiagnostics, budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	case s00.ProtocolIEID(40):
		if v.rowSecurityContext == nil {
			return nil, fmt.Errorf("%s missing value", "UEContextSuspendResponseIEs.id-SecurityContext:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		candidate, err := v.rowSecurityContext.marshalAPERBudget(budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	default:
		return nil, fmt.Errorf("%s id %d has no value", "UEContextSuspendResponseIEValue:", v.id)
	}
}

type SecondaryRATDataUsageReportItemIETable struct{}

func SecondaryRATDataUsageReportItemIEs() SecondaryRATDataUsageReportItemIETable {
	return SecondaryRATDataUsageReportItemIETable{}
}
func (SecondaryRATDataUsageReportItemIETable) ID() s00.TableID {
	return func() s00.TableID {
		sealed := s00.TableID{}
		*s00.BridgeTableIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "SecondaryRATDataUsageReportItemIEs"}
		return sealed
	}()
}
func (SecondaryRATDataUsageReportItemIETable) Table() s00.SecondaryRATDataUsageReportItemIEValueIETable {
	return func() s00.SecondaryRATDataUsageReportItemIEValueIETable {
		sealed := s00.SecondaryRATDataUsageReportItemIEValueIETable{}
		*s00.BridgeSecondaryRATDataUsageReportItemIEValueIETableFieldBound(&sealed) = true
		return sealed
	}()
}
func (SecondaryRATDataUsageReportItemIETable) infoSecondaryRATDataUsageReportItem() s00.FieldInfo {
	return s00.FieldInfo{Table: SecondaryRATDataUsageReportItemIEs().ID(), ID: s00.ProtocolIEID(265), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceMandatory, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "SecondaryRATDataUsageReportItem"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.4", Assignment: aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "SecondaryRATDataUsageReportItemIEs", Row: "id-SecondaryRATDataUsageReportItem"}}}
}
func (t SecondaryRATDataUsageReportItemIETable) SecondaryRATDataUsageReportItem() SecondaryRATDataUsageReportItemSecondaryRATDataUsageReportItemIEBinding {
	return SecondaryRATDataUsageReportItemSecondaryRATDataUsageReportItemIEBinding{info: t.infoSecondaryRATDataUsageReportItem(), codec: SecondaryRATDataUsageReportItemValueCodec{path: "SecondaryRATDataUsageReportItem",
		decode: func(data []byte, options aper.DecodeState) (SecondaryRATDataUsageReportItem, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty SecondaryRATDataUsageReportItem
				return empty, err
			}
			var zero SecondaryRATDataUsageReportItemIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(265), raw)
			if err != nil {
				var empty SecondaryRATDataUsageReportItem
				return empty, err
			}
			value, ok := decoded.AsSecondaryRATDataUsageReportItem()
			if !ok {
				var empty SecondaryRATDataUsageReportItem
				return empty, fmt.Errorf("binding SecondaryRATDataUsageReportItemIEs.id-SecondaryRATDataUsageReportItem: no selected value")
			}
			return *value, nil
		},
		encode: func(value SecondaryRATDataUsageReportItem, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (SecondaryRATDataUsageReportItemIEValue{id: s00.ProtocolIEID(265), rowSecondaryRATDataUsageReportItem: &value}).encodeFresh(fresh, budget)
		}, capture: func(v SecondaryRATDataUsageReportItem, options aper.DecodeState) (SecondaryRATDataUsageReportItem, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeCaptureS1APSecondaryRATDataUsageReportItem(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}, compare: func(v SecondaryRATDataUsageReportItem, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeCompareS1APSecondaryRATDataUsageReportItem(&v, &s)

			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}, context: func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:SecondaryRATDataUsageReportItem"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}(),
	}, inject: func(value SecondaryRATDataUsageReportItem) SecondaryRATDataUsageReportItemIEValue {
		return SecondaryRATDataUsageReportItemIEValue{id: s00.ProtocolIEID(265), rowSecondaryRATDataUsageReportItem: &value}
	}, get: func(value *SecondaryRATDataUsageReportItemIEValue) (*SecondaryRATDataUsageReportItem, bool) {
		return value.AsSecondaryRATDataUsageReportItem()
	}}
}
func (t SecondaryRATDataUsageReportItemIETable) NewOpaque(id s00.ProtocolIEID, criticality s00.Criticality, data []byte) (SecondaryRATDataUsageReportItemIEField, error) {
	if id < 0 || id > 65535 || criticality < 0 || criticality > 2 {
		return SecondaryRATDataUsageReportItemIEField{}, aper.OperationError(fmt.Errorf("invalid opaque IE selector or criticality"), "Opaque")
	}
	switch id {
	case s00.ProtocolIEID(265):
		return SecondaryRATDataUsageReportItemIEField{}, aper.OperationError(fmt.Errorf("known IE id-SecondaryRATDataUsageReportItem requires its typed binding"), "Opaque")
	default:
		budget, err := aper.BuildBudget()
		if err != nil {
			return SecondaryRATDataUsageReportItemIEField{}, aper.OperationError(err, "Opaque")
		}
		opaque, err := aper.BuildOpaqueOpenType(data, budget)
		if err != nil {
			return SecondaryRATDataUsageReportItemIEField{}, aper.OperationError(err, "Opaque")
		}
		return SecondaryRATDataUsageReportItemIEField{Id: id, Criticality: criticality, Value: SecondaryRATDataUsageReportItemIEValue{id: id, opaque: opaque, isOpaque: true}}, aper.OperationError(nil, "Opaque")
	}
}

type ErrorIndicationIETable struct{}

func ErrorIndicationIEs() ErrorIndicationIETable { return ErrorIndicationIETable{} }
func (ErrorIndicationIETable) ID() s00.TableID {
	return func() s00.TableID {
		sealed := s00.TableID{}
		*s00.BridgeTableIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "ErrorIndicationIEs"}
		return sealed
	}()
}
func (ErrorIndicationIETable) Table() s00.ErrorIndicationIEValueIETable {
	return func() s00.ErrorIndicationIEValueIETable {
		sealed := s00.ErrorIndicationIEValueIETable{}
		*s00.BridgeErrorIndicationIEValueIETableFieldBound(&sealed) = true
		return sealed
	}()
}
func (ErrorIndicationIETable) infoMMEUES1APID() s00.FieldInfo {
	return s00.FieldInfo{Table: ErrorIndicationIEs().ID(), ID: s00.ProtocolIEID(0), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "MME-UE-S1AP-ID"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "ErrorIndicationIEs", Row: "id-MME-UE-S1AP-ID"}}}
}
func (t ErrorIndicationIETable) MMEUES1APID() ErrorIndicationMMEUES1APIDIEBinding {
	return ErrorIndicationMMEUES1APIDIEBinding{info: t.infoMMEUES1APID(), codec: func() s01.MMEUES1APIDValueCodec {
		sealed := s01.MMEUES1APIDValueCodec{}
		*s01.BridgeMMEUES1APIDValueCodecFieldPath(&sealed) = "MMEUES1APID"
		*s01.BridgeMMEUES1APIDValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.MMEUES1APID, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s00.MMEUES1APID
				return empty, err
			}
			var zero ErrorIndicationIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(0), raw)
			if err != nil {
				var empty s00.MMEUES1APID
				return empty, err
			}
			value, ok := decoded.AsMMEUES1APID()
			if !ok {
				var empty s00.MMEUES1APID
				return empty, fmt.Errorf("binding ErrorIndicationIEs.id-MME-UE-S1AP-ID: no selected value")
			}
			return *value, nil
		}
		*s01.BridgeMMEUES1APIDValueCodecFieldEncode(&sealed) = func(value s00.MMEUES1APID, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (ErrorIndicationIEValue{id: s00.ProtocolIEID(0), rowMMEUES1APID: &value}).encodeFresh(fresh, budget)
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
		inject: func(value s00.MMEUES1APID) ErrorIndicationIEValue {
			return ErrorIndicationIEValue{id: s00.ProtocolIEID(0), rowMMEUES1APID: &value}
		}, get: func(value *ErrorIndicationIEValue) (*s00.MMEUES1APID, bool) { return value.AsMMEUES1APID() }}
}
func (ErrorIndicationIETable) infoENBUES1APID() s00.FieldInfo {
	return s00.FieldInfo{Table: ErrorIndicationIEs().ID(), ID: s00.ProtocolIEID(8), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "ENB-UE-S1AP-ID"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "ErrorIndicationIEs", Row: "id-eNB-UE-S1AP-ID"}}}
}
func (t ErrorIndicationIETable) ENBUES1APID() ErrorIndicationENBUES1APIDIEBinding {
	return ErrorIndicationENBUES1APIDIEBinding{info: t.infoENBUES1APID(), codec: func() s00.ENBUES1APIDValueCodec {
		sealed := s00.ENBUES1APIDValueCodec{}
		*s00.BridgeENBUES1APIDValueCodecFieldPath(&sealed) = "ENBUES1APID"
		*s00.BridgeENBUES1APIDValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.ENBUES1APID, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s00.ENBUES1APID
				return empty, err
			}
			var zero ErrorIndicationIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(8), raw)
			if err != nil {
				var empty s00.ENBUES1APID
				return empty, err
			}
			value, ok := decoded.AsENBUES1APID()
			if !ok {
				var empty s00.ENBUES1APID
				return empty, fmt.Errorf("binding ErrorIndicationIEs.id-eNB-UE-S1AP-ID: no selected value")
			}
			return *value, nil
		}
		*s00.BridgeENBUES1APIDValueCodecFieldEncode(&sealed) = func(value s00.ENBUES1APID, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (ErrorIndicationIEValue{id: s00.ProtocolIEID(8), rowENBUES1APID: &value}).encodeFresh(fresh, budget)
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
		inject: func(value s00.ENBUES1APID) ErrorIndicationIEValue {
			return ErrorIndicationIEValue{id: s00.ProtocolIEID(8), rowENBUES1APID: &value}
		}, get: func(value *ErrorIndicationIEValue) (*s00.ENBUES1APID, bool) { return value.AsENBUES1APID() }}
}
func (ErrorIndicationIETable) infoCause() s00.FieldInfo {
	return s00.FieldInfo{Table: ErrorIndicationIEs().ID(), ID: s00.ProtocolIEID(2), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "Cause"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "ErrorIndicationIEs", Row: "id-Cause"}}}
}
func (t ErrorIndicationIETable) Cause() ErrorIndicationCauseIEBinding {
	return ErrorIndicationCauseIEBinding{info: t.infoCause(), codec: func() s14.CauseValueCodec {
		sealed := s14.CauseValueCodec{}
		*s14.BridgeCauseValueCodecFieldPath(&sealed) = "Cause"
		*s14.BridgeCauseValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s14.Cause, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s14.Cause
				return empty, err
			}
			var zero ErrorIndicationIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(2), raw)
			if err != nil {
				var empty s14.Cause
				return empty, err
			}
			value, ok := decoded.AsCause()
			if !ok {
				var empty s14.Cause
				return empty, fmt.Errorf("binding ErrorIndicationIEs.id-Cause: no selected value")
			}
			return *value, nil
		}
		*s14.BridgeCauseValueCodecFieldEncode(&sealed) = func(value s14.Cause, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (ErrorIndicationIEValue{id: s00.ProtocolIEID(2), rowCause: &value}).encodeFresh(fresh, budget)
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
		inject: func(value s14.Cause) ErrorIndicationIEValue {
			return ErrorIndicationIEValue{id: s00.ProtocolIEID(2), rowCause: &value}
		}, get: func(value *ErrorIndicationIEValue) (*s14.Cause, bool) { return value.AsCause() }}
}
func (ErrorIndicationIETable) infoCriticalityDiagnostics() s00.FieldInfo {
	return s00.FieldInfo{Table: ErrorIndicationIEs().ID(), ID: s00.ProtocolIEID(58), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "CriticalityDiagnostics"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "ErrorIndicationIEs", Row: "id-CriticalityDiagnostics"}}}
}
func (t ErrorIndicationIETable) CriticalityDiagnostics() ErrorIndicationCriticalityDiagnosticsIEBinding {
	return ErrorIndicationCriticalityDiagnosticsIEBinding{info: t.infoCriticalityDiagnostics(), codec: func() s22.CriticalityDiagnosticsValueCodec {
		sealed := s22.CriticalityDiagnosticsValueCodec{}
		*s22.BridgeCriticalityDiagnosticsValueCodecFieldPath(&sealed) = "CriticalityDiagnostics"
		*s22.BridgeCriticalityDiagnosticsValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s22.CriticalityDiagnostics, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s22.CriticalityDiagnostics
				return empty, err
			}
			var zero ErrorIndicationIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(58), raw)
			if err != nil {
				var empty s22.CriticalityDiagnostics
				return empty, err
			}
			value, ok := decoded.AsCriticalityDiagnostics()
			if !ok {
				var empty s22.CriticalityDiagnostics
				return empty, fmt.Errorf("binding ErrorIndicationIEs.id-CriticalityDiagnostics: no selected value")
			}
			return *value, nil
		}
		*s22.BridgeCriticalityDiagnosticsValueCodecFieldEncode(&sealed) = func(value s22.CriticalityDiagnostics, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (ErrorIndicationIEValue{id: s00.ProtocolIEID(58), rowCriticalityDiagnostics: &value}).encodeFresh(fresh, budget)
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
		inject: func(value s22.CriticalityDiagnostics) ErrorIndicationIEValue {
			return ErrorIndicationIEValue{id: s00.ProtocolIEID(58), rowCriticalityDiagnostics: &value}
		}, get: func(value *ErrorIndicationIEValue) (*s22.CriticalityDiagnostics, bool) {
			return value.AsCriticalityDiagnostics()
		}}
}
func (ErrorIndicationIETable) infoSTMSI() s00.FieldInfo {
	return s00.FieldInfo{Table: ErrorIndicationIEs().ID(), ID: s00.ProtocolIEID(96), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "S-TMSI"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "ErrorIndicationIEs", Row: "id-S-TMSI"}}}
}
func (t ErrorIndicationIETable) STMSI() ErrorIndicationSTMSIIEBinding {
	return ErrorIndicationSTMSIIEBinding{info: t.infoSTMSI(), codec: STMSIValueCodec{path: "STMSI",
		decode: func(data []byte, options aper.DecodeState) (s27.STMSI, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s27.STMSI
				return empty, err
			}
			var zero ErrorIndicationIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(96), raw)
			if err != nil {
				var empty s27.STMSI
				return empty, err
			}
			value, ok := decoded.AsSTMSI()
			if !ok {
				var empty s27.STMSI
				return empty, fmt.Errorf("binding ErrorIndicationIEs.id-S-TMSI: no selected value")
			}
			return *value, nil
		},
		encode: func(value s27.STMSI, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (ErrorIndicationIEValue{id: s00.ProtocolIEID(96), rowSTMSI: &value}).encodeFresh(fresh, budget)
		}, capture: func(v s27.STMSI, options aper.DecodeState) (s27.STMSI, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s27.BridgeCaptureS1APSTMSI(&v, &s)
			var root aper.Snapshot
			s.End(f,
				&root, false)
			return v, root
		}, compare: func(v s27.STMSI, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s27.BridgeCompareS1APSTMSI(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}, context: func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:STMSI"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}(),
	}, inject: func(value s27.STMSI) ErrorIndicationIEValue {
		return ErrorIndicationIEValue{id: s00.ProtocolIEID(96), rowSTMSI: &value}
	}, get: func(value *ErrorIndicationIEValue) (*s27.STMSI, bool) { return value.AsSTMSI() }}
}
func (t ErrorIndicationIETable) NewOpaque(id s00.ProtocolIEID, criticality s00.Criticality, data []byte) (ErrorIndicationIEField, error) {
	if id < 0 || id > 65535 || criticality < 0 || criticality > 2 {
		return ErrorIndicationIEField{}, aper.OperationError(fmt.Errorf("invalid opaque IE selector or criticality"), "Opaque")
	}
	switch id {
	case s00.ProtocolIEID(0):
		return ErrorIndicationIEField{}, aper.OperationError(fmt.Errorf("known IE id-MME-UE-S1AP-ID requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(8):
		return ErrorIndicationIEField{}, aper.OperationError(fmt.Errorf("known IE id-eNB-UE-S1AP-ID requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(2):
		return ErrorIndicationIEField{}, aper.OperationError(fmt.Errorf("known IE id-Cause requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(58):
		return ErrorIndicationIEField{}, aper.OperationError(fmt.Errorf("known IE id-CriticalityDiagnostics requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(96):
		return ErrorIndicationIEField{}, aper.OperationError(fmt.Errorf("known IE id-S-TMSI requires its typed binding"), "Opaque")
	default:
		budget, err := aper.BuildBudget()
		if err != nil {
			return ErrorIndicationIEField{}, aper.OperationError(err, "Opaque")
		}
		opaque, err := aper.BuildOpaqueOpenType(data, budget)
		if err != nil {
			return ErrorIndicationIEField{}, aper.OperationError(err, "Opaque")
		}
		return ErrorIndicationIEField{Id: id, Criticality: criticality, Value: ErrorIndicationIEValue{id: id, opaque: opaque, isOpaque: true}}, aper.OperationError(nil, "Opaque")
	}
}

type RetrieveUEInformationIETable struct{}

func RetrieveUEInformationIEs() RetrieveUEInformationIETable { return RetrieveUEInformationIETable{} }
func (RetrieveUEInformationIETable) ID() s00.TableID {
	return func() s00.TableID {
		sealed := s00.TableID{}
		*s00.BridgeTableIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "RetrieveUEInformationIEs"}
		return sealed
	}()
}
func (RetrieveUEInformationIETable) Table() s00.RetrieveUEInformationIEValueIETable {
	return func() s00.RetrieveUEInformationIEValueIETable {
		sealed := s00.RetrieveUEInformationIEValueIETable{}
		*s00.BridgeRetrieveUEInformationIEValueIETableFieldBound(&sealed) = true
		return sealed
	}()
}
func (RetrieveUEInformationIETable) infoSTMSI() s00.FieldInfo {
	return s00.FieldInfo{Table: RetrieveUEInformationIEs().ID(), ID: s00.ProtocolIEID(96), Criticality: s00.CriticalityReject, Presence: s00.PresenceMandatory, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "S-TMSI"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "RetrieveUEInformationIEs", Row: "id-S-TMSI"}}}
}
func (t RetrieveUEInformationIETable) STMSI() RetrieveUEInformationSTMSIIEBinding {
	return RetrieveUEInformationSTMSIIEBinding{info: t.infoSTMSI(), codec: STMSIValueCodec{path: "STMSI",
		decode: func(data []byte, options aper.DecodeState) (s27.STMSI, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s27.STMSI
				return empty, err
			}
			var zero RetrieveUEInformationIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(96), raw)
			if err != nil {
				var empty s27.STMSI
				return empty, err
			}
			value, ok := decoded.AsSTMSI()
			if !ok {
				var empty s27.STMSI
				return empty, fmt.Errorf("binding RetrieveUEInformationIEs.id-S-TMSI: no selected value")
			}
			return *value, nil
		},
		encode: func(value s27.STMSI, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (RetrieveUEInformationIEValue{id: s00.ProtocolIEID(96), rowSTMSI: &value}).encodeFresh(fresh, budget)
		}, capture: func(v s27.STMSI, options aper.DecodeState) (s27.STMSI, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s27.BridgeCaptureS1APSTMSI(&v, &s)
			var root aper.Snapshot
			s.End(f,
				&root, false)
			return v, root
		}, compare: func(v s27.STMSI, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s27.BridgeCompareS1APSTMSI(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}, context: func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:STMSI"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}(),
	}, inject: func(value s27.STMSI) RetrieveUEInformationIEValue {
		return RetrieveUEInformationIEValue{id: s00.ProtocolIEID(96), rowSTMSI: &value}
	}, get: func(value *RetrieveUEInformationIEValue) (*s27.STMSI, bool) { return value.AsSTMSI() }}
}
func (t RetrieveUEInformationIETable) NewOpaque(id s00.ProtocolIEID, criticality s00.Criticality, data []byte) (RetrieveUEInformationIEField, error) {
	if id < 0 || id > 65535 || criticality < 0 || criticality > 2 {
		return RetrieveUEInformationIEField{}, aper.OperationError(fmt.Errorf("invalid opaque IE selector or criticality"), "Opaque")
	}
	switch id {
	case s00.ProtocolIEID(96):
		return RetrieveUEInformationIEField{}, aper.OperationError(fmt.Errorf("known IE id-S-TMSI requires its typed binding"), "Opaque")
	default:
		budget, err := aper.BuildBudget()
		if err != nil {
			return RetrieveUEInformationIEField{}, aper.OperationError(err, "Opaque")
		}
		opaque, err := aper.BuildOpaqueOpenType(data, budget)
		if err != nil {
			return RetrieveUEInformationIEField{}, aper.OperationError(err, "Opaque")
		}
		return RetrieveUEInformationIEField{Id: id, Criticality: criticality, Value: RetrieveUEInformationIEValue{id: id, opaque: opaque, isOpaque: true}}, aper.OperationError(nil, "Opaque")
	}
}

type UEContextSuspendResponseIETable struct{}

func UEContextSuspendResponseIEs() UEContextSuspendResponseIETable {
	return UEContextSuspendResponseIETable{}
}
func (UEContextSuspendResponseIETable) ID() s00.TableID {
	return func() s00.TableID {
		sealed := s00.TableID{}
		*s00.BridgeTableIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "UEContextSuspendResponseIEs"}
		return sealed
	}()
}
func (UEContextSuspendResponseIETable) Table() s00.UEContextSuspendResponseIEValueIETable {
	return func() s00.UEContextSuspendResponseIEValueIETable {
		sealed := s00.UEContextSuspendResponseIEValueIETable{}
		*s00.BridgeUEContextSuspendResponseIEValueIETableFieldBound(&sealed) = true
		return sealed
	}()
}
func (UEContextSuspendResponseIETable) infoMMEUES1APID() s00.FieldInfo {
	return s00.FieldInfo{Table: UEContextSuspendResponseIEs().ID(), ID: s00.ProtocolIEID(0), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceMandatory, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "MME-UE-S1AP-ID"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "UEContextSuspendResponseIEs", Row: "id-MME-UE-S1AP-ID"}}}
}
func (t UEContextSuspendResponseIETable) MMEUES1APID() UEContextSuspendResponseMMEUES1APIDIEBinding {
	return UEContextSuspendResponseMMEUES1APIDIEBinding{info: t.infoMMEUES1APID(), codec: func() s01.MMEUES1APIDValueCodec {
		sealed := s01.MMEUES1APIDValueCodec{}
		*s01.BridgeMMEUES1APIDValueCodecFieldPath(&sealed) = "MMEUES1APID"
		*s01.BridgeMMEUES1APIDValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.MMEUES1APID, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s00.MMEUES1APID
				return empty, err
			}
			var zero UEContextSuspendResponseIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(0), raw)
			if err != nil {
				var empty s00.MMEUES1APID
				return empty, err
			}
			value, ok := decoded.AsMMEUES1APID()
			if !ok {
				var empty s00.MMEUES1APID
				return empty, fmt.Errorf("binding UEContextSuspendResponseIEs.id-MME-UE-S1AP-ID: no selected value")
			}
			return *value, nil
		}
		*s01.BridgeMMEUES1APIDValueCodecFieldEncode(&sealed) = func(value s00.MMEUES1APID, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (UEContextSuspendResponseIEValue{id: s00.ProtocolIEID(0), rowMMEUES1APID: &value}).encodeFresh(fresh, budget)
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
		inject: func(value s00.MMEUES1APID) UEContextSuspendResponseIEValue {
			return UEContextSuspendResponseIEValue{id: s00.ProtocolIEID(0), rowMMEUES1APID: &value}
		}, get: func(value *UEContextSuspendResponseIEValue) (*s00.MMEUES1APID, bool) { return value.AsMMEUES1APID() }}
}
func (UEContextSuspendResponseIETable) infoENBUES1APID() s00.FieldInfo {
	return s00.FieldInfo{Table: UEContextSuspendResponseIEs().ID(), ID: s00.ProtocolIEID(8), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceMandatory, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "ENB-UE-S1AP-ID"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "UEContextSuspendResponseIEs", Row: "id-eNB-UE-S1AP-ID"}}}
}
func (t UEContextSuspendResponseIETable) ENBUES1APID() UEContextSuspendResponseENBUES1APIDIEBinding {
	return UEContextSuspendResponseENBUES1APIDIEBinding{info: t.infoENBUES1APID(), codec: func() s00.ENBUES1APIDValueCodec {
		sealed := s00.ENBUES1APIDValueCodec{}
		*s00.BridgeENBUES1APIDValueCodecFieldPath(&sealed) = "ENBUES1APID"
		*s00.BridgeENBUES1APIDValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.ENBUES1APID, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s00.ENBUES1APID
				return empty, err
			}
			var zero UEContextSuspendResponseIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(8), raw)
			if err != nil {
				var empty s00.ENBUES1APID
				return empty, err
			}
			value, ok := decoded.AsENBUES1APID()
			if !ok {
				var empty s00.ENBUES1APID
				return empty, fmt.Errorf("binding UEContextSuspendResponseIEs.id-eNB-UE-S1AP-ID: no selected value")
			}
			return *value, nil
		}
		*s00.BridgeENBUES1APIDValueCodecFieldEncode(&sealed) = func(value s00.ENBUES1APID, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (UEContextSuspendResponseIEValue{id: s00.ProtocolIEID(8), rowENBUES1APID: &value}).encodeFresh(fresh, budget)
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
		inject: func(value s00.ENBUES1APID) UEContextSuspendResponseIEValue {
			return UEContextSuspendResponseIEValue{id: s00.ProtocolIEID(8), rowENBUES1APID: &value}
		}, get: func(value *UEContextSuspendResponseIEValue) (*s00.ENBUES1APID, bool) { return value.AsENBUES1APID() }}
}
func (UEContextSuspendResponseIETable) infoCriticalityDiagnostics() s00.FieldInfo {
	return s00.FieldInfo{Table: UEContextSuspendResponseIEs().ID(), ID: s00.ProtocolIEID(58), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "CriticalityDiagnostics"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "UEContextSuspendResponseIEs", Row: "id-CriticalityDiagnostics"}}}
}
func (t UEContextSuspendResponseIETable) CriticalityDiagnostics() UEContextSuspendResponseCriticalityDiagnosticsIEBinding {
	return UEContextSuspendResponseCriticalityDiagnosticsIEBinding{info: t.infoCriticalityDiagnostics(), codec: func() s22.CriticalityDiagnosticsValueCodec {
		sealed := s22.CriticalityDiagnosticsValueCodec{}
		*s22.BridgeCriticalityDiagnosticsValueCodecFieldPath(&sealed) = "CriticalityDiagnostics"
		*s22.BridgeCriticalityDiagnosticsValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s22.CriticalityDiagnostics, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s22.CriticalityDiagnostics
				return empty, err
			}
			var zero UEContextSuspendResponseIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(58), raw)
			if err != nil {
				var empty s22.CriticalityDiagnostics
				return empty, err
			}
			value, ok := decoded.AsCriticalityDiagnostics()
			if !ok {
				var empty s22.CriticalityDiagnostics
				return empty, fmt.Errorf("binding UEContextSuspendResponseIEs.id-CriticalityDiagnostics: no selected value")
			}
			return *value, nil
		}
		*s22.BridgeCriticalityDiagnosticsValueCodecFieldEncode(&sealed) = func(value s22.CriticalityDiagnostics, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (UEContextSuspendResponseIEValue{id: s00.ProtocolIEID(58), rowCriticalityDiagnostics: &value}).encodeFresh(fresh, budget)
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
		inject: func(value s22.CriticalityDiagnostics) UEContextSuspendResponseIEValue {
			return UEContextSuspendResponseIEValue{id: s00.ProtocolIEID(58), rowCriticalityDiagnostics: &value}
		}, get: func(value *UEContextSuspendResponseIEValue) (*s22.CriticalityDiagnostics, bool) {
			return value.AsCriticalityDiagnostics()
		}}
}
func (UEContextSuspendResponseIETable) infoSecurityContext() s00.FieldInfo {
	return s00.FieldInfo{Table: UEContextSuspendResponseIEs().ID(), ID: s00.ProtocolIEID(40), Criticality: s00.CriticalityReject, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "SecurityContext"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "UEContextSuspendResponseIEs", Row: "id-SecurityContext"}}}
}
func (t UEContextSuspendResponseIETable) SecurityContext() UEContextSuspendResponseSecurityContextIEBinding {
	return UEContextSuspendResponseSecurityContextIEBinding{info: t.infoSecurityContext(), codec: SecurityContextValueCodec{path: "SecurityContext",
		decode: func(data []byte, options aper.DecodeState) (SecurityContext, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty SecurityContext
				return empty, err
			}
			var zero UEContextSuspendResponseIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(40), raw)
			if err != nil {
				var empty SecurityContext
				return empty, err
			}
			value, ok := decoded.AsSecurityContext()
			if !ok {
				var empty SecurityContext
				return empty, fmt.Errorf("binding UEContextSuspendResponseIEs.id-SecurityContext: no selected value")
			}
			return *value, nil
		},
		encode: func(value SecurityContext, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (UEContextSuspendResponseIEValue{id: s00.ProtocolIEID(40), rowSecurityContext: &value}).encodeFresh(fresh, budget)
		}, capture: func(v SecurityContext, options aper.DecodeState) (SecurityContext, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeCaptureS1APSecurityContext(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}, compare: func(v SecurityContext, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeCompareS1APSecurityContext(&v, &s)
			s.End(f, root, false)
			return s.
				Plan(), s.BudgetValue()
		}, context: func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:SecurityContext"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}(),
	}, inject: func(value SecurityContext) UEContextSuspendResponseIEValue {
		return UEContextSuspendResponseIEValue{id: s00.ProtocolIEID(40), rowSecurityContext: &value}
	}, get: func(value *UEContextSuspendResponseIEValue) (*SecurityContext, bool) {
		return value.AsSecurityContext()
	}}
}
func (t UEContextSuspendResponseIETable) NewOpaque(id s00.ProtocolIEID, criticality s00.Criticality, data []byte) (UEContextSuspendResponseIEField, error) {
	if id < 0 || id > 65535 || criticality < 0 || criticality > 2 {
		return UEContextSuspendResponseIEField{}, aper.OperationError(fmt.Errorf("invalid opaque IE selector or criticality"), "Opaque")
	}
	switch id {
	case s00.ProtocolIEID(0):
		return UEContextSuspendResponseIEField{}, aper.OperationError(fmt.Errorf("known IE id-MME-UE-S1AP-ID requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(8):
		return UEContextSuspendResponseIEField{}, aper.OperationError(fmt.Errorf("known IE id-eNB-UE-S1AP-ID requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(58):
		return UEContextSuspendResponseIEField{}, aper.OperationError(fmt.Errorf("known IE id-CriticalityDiagnostics requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(40):
		return UEContextSuspendResponseIEField{}, aper.OperationError(fmt.Errorf("known IE id-SecurityContext requires its typed binding"), "Opaque")
	default:
		budget, err := aper.BuildBudget()
		if err != nil {
			return UEContextSuspendResponseIEField{}, aper.OperationError(err, "Opaque")
		}
		opaque, err := aper.BuildOpaqueOpenType(data, budget)
		if err != nil {
			return UEContextSuspendResponseIEField{}, aper.OperationError(err, "Opaque")
		}
		return UEContextSuspendResponseIEField{Id: id, Criticality: criticality, Value: UEContextSuspendResponseIEValue{id: id, opaque: opaque, isOpaque: true}}, aper.OperationError(nil, "Opaque")
	}
}

// ScheduledCommunicationTimeCodec binds the complete source value type.
func ScheduledCommunicationTimeCodec() ScheduledCommunicationTimeValueCodec {
	return ScheduledCommunicationTimeValueCodec{path: "ScheduledCommunicationTime", decode: func(data []byte, options aper.DecodeState) (ScheduledCommunicationTime, error) {
		var value ScheduledCommunicationTime
		if err := value.unmarshalAPERWithOptions(data, options); err != nil {
			return ScheduledCommunicationTime{}, err
		}
		value.received = true
		value.receivedAbsolute = true
		value.receivedBytes = aper.OriginalWire(data)
		return value, nil
	}, encode: func(value ScheduledCommunicationTime, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return (&value).marshalAPERBudget(budget, fresh)
	}, capture: func(v ScheduledCommunicationTime, options aper.DecodeState) (ScheduledCommunicationTime, aper.Snapshot,
	) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeCaptureS1APScheduledCommunicationTime(&v, &s)
		var root aper.Snapshot
		s.End(
			f, &root, false)
		return v, root
	}, compare: func(v ScheduledCommunicationTime, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
	) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		BridgeCompareS1APScheduledCommunicationTime(&v, &s)
		s.End(f,
			root,

			false)
		return s.Plan(), s.BudgetValue()
	}, context: func() s00.BridgeCodecContext {
		sealed := s00.BridgeCodecContext{}
		*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ScheduledCommunicationTime"
		*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
		return sealed
	}(),
	}
}

// SecondaryRATDataUsageReportItemCodec binds the complete APER value type.
func SecondaryRATDataUsageReportItemCodec() SecondaryRATDataUsageReportItemValueCodec {
	return SecondaryRATDataUsageReportItemIEs().SecondaryRATDataUsageReportItem().Codec()
}
func BridgeERABInformationListItemExtIEsDAPSRequestInfoExtBindingFieldCodec(v *ERABInformationListItemExtIEsDAPSRequestInfoExtBinding) *s14.DAPSRequestInfoValueCodec {
	return &v.codec
}
func BridgeERABInformationListItemExtIEsDAPSRequestInfoExtBindingFieldGet(v *ERABInformationListItemExtIEsDAPSRequestInfoExtBinding) *func(*ERABInformationListItemExtIEsValue) (*s14.DAPSRequestInfo, bool) {
	return &v.get
}
func BridgeERABInformationListItemExtIEsDAPSRequestInfoExtBindingFieldInfo(v *ERABInformationListItemExtIEsDAPSRequestInfoExtBinding) *s00.ExtensionInfo {
	return &v.info
}
func BridgeERABInformationListItemExtIEsDAPSRequestInfoExtBindingFieldInject(v *ERABInformationListItemExtIEsDAPSRequestInfoExtBinding) *func(s14.DAPSRequestInfo) ERABInformationListItemExtIEsValue {
	return &v.inject
}
func BridgeERABInformationListItemExtIEsExtContainerAPERValueFieldContext(v *ERABInformationListItemExtIEsExtContainerAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABInformationListItemExtIEsExtContainerAPERValueFieldReceived(v *ERABInformationListItemExtIEsExtContainerAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeERABInformationListItemExtIEsExtContainerAPERValueFieldReplay(v *ERABInformationListItemExtIEsExtContainerAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeERABInformationListItemExtIEsExtContainerAPERValueFieldWithoutReplay(v *ERABInformationListItemExtIEsExtContainerAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeERABInformationListItemExtIEsExtContainerValueCodecFieldCapture(v *ERABInformationListItemExtIEsExtContainerValueCodec) *func(ERABInformationListItemExtIEsExtContainer, aper.DecodeState) (ERABInformationListItemExtIEsExtContainer, aper.Snapshot) {
	return &v.capture
}
func BridgeERABInformationListItemExtIEsExtContainerValueCodecFieldCompare(v *ERABInformationListItemExtIEsExtContainerValueCodec) *func(ERABInformationListItemExtIEsExtContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeERABInformationListItemExtIEsExtContainerValueCodecFieldContext(v *ERABInformationListItemExtIEsExtContainerValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABInformationListItemExtIEsExtContainerValueCodecFieldDecode(v *ERABInformationListItemExtIEsExtContainerValueCodec) *func([]byte, aper.DecodeState) (ERABInformationListItemExtIEsExtContainer, error) {
	return &v.decode
}
func BridgeERABInformationListItemExtIEsExtContainerValueCodecFieldEncode(v *ERABInformationListItemExtIEsExtContainerValueCodec) *func(ERABInformationListItemExtIEsExtContainer, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeERABInformationListItemExtIEsExtContainerValueCodecFieldPath(v *ERABInformationListItemExtIEsExtContainerValueCodec) *aper.Path {
	return &v.path
}
func BridgeERABInformationListItemExtIEsExtContainerValueCodecMethodEncodeBudgetValue(v ERABInformationListItemExtIEsExtContainerValueCodec, a0 ERABInformationListItemExtIEsExtContainer, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeERABInformationListItemExtIEsExtContainerValueCodecMethodEncodeChanged(v ERABInformationListItemExtIEsExtContainerValueCodec, a0 ERABInformationListItemExtIEsExtContainer, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeERABInformationListItemExtIEsExtFieldAPERValueFieldContext(v *ERABInformationListItemExtIEsExtFieldAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABInformationListItemExtIEsExtFieldAPERValueFieldReceived(v *ERABInformationListItemExtIEsExtFieldAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeERABInformationListItemExtIEsExtFieldAPERValueFieldReplay(v *ERABInformationListItemExtIEsExtFieldAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeERABInformationListItemExtIEsExtFieldAPERValueFieldWithoutReplay(v *ERABInformationListItemExtIEsExtFieldAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeERABInformationListItemExtIEsExtFieldFieldReceived(v *ERABInformationListItemExtIEsExtField) *aper.CompletePadding {
	return &v.received
}
func BridgeERABInformationListItemExtIEsExtFieldFieldReplay(v *ERABInformationListItemExtIEsExtField) *aper.Snapshot {
	return &v.replay
}
func BridgeERABInformationListItemExtIEsExtFieldFieldStream(v *ERABInformationListItemExtIEsExtField) *aper.WireSpan {
	return &v.stream
}
func BridgeERABInformationListItemExtIEsExtFieldFieldWithoutReplay(v *ERABInformationListItemExtIEsExtField) *bool {
	return &v.withoutReplay
}
func BridgeERABInformationListItemExtIEsExtFieldMethodMarshalAPERTo(v *ERABInformationListItemExtIEsExtField, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeERABInformationListItemExtIEsExtFieldMethodUnmarshalAPERFrom(v *ERABInformationListItemExtIEsExtField, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeERABInformationListItemExtIEsExtFieldValueCodecFieldCapture(v *ERABInformationListItemExtIEsExtFieldValueCodec) *func(ERABInformationListItemExtIEsExtField, aper.DecodeState) (ERABInformationListItemExtIEsExtField, aper.Snapshot) {
	return &v.capture
}
func BridgeERABInformationListItemExtIEsExtFieldValueCodecFieldCompare(v *ERABInformationListItemExtIEsExtFieldValueCodec) *func(ERABInformationListItemExtIEsExtField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeERABInformationListItemExtIEsExtFieldValueCodecFieldContext(v *ERABInformationListItemExtIEsExtFieldValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABInformationListItemExtIEsExtFieldValueCodecFieldDecode(v *ERABInformationListItemExtIEsExtFieldValueCodec) *func([]byte, aper.DecodeState) (ERABInformationListItemExtIEsExtField, error) {
	return &v.decode
}
func BridgeERABInformationListItemExtIEsExtFieldValueCodecFieldEncode(v *ERABInformationListItemExtIEsExtFieldValueCodec) *func(ERABInformationListItemExtIEsExtField, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeERABInformationListItemExtIEsExtFieldValueCodecFieldPath(v *ERABInformationListItemExtIEsExtFieldValueCodec) *aper.Path {
	return &v.path
}
func BridgeERABInformationListItemExtIEsExtFieldValueCodecMethodEncodeBudgetValue(v ERABInformationListItemExtIEsExtFieldValueCodec, a0 ERABInformationListItemExtIEsExtField, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeERABInformationListItemExtIEsExtFieldValueCodecMethodEncodeChanged(v ERABInformationListItemExtIEsExtFieldValueCodec, a0 ERABInformationListItemExtIEsExtField, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeERABInformationListItemExtIEsIEFieldFieldReceived(v *ERABInformationListItemExtIEsIEField) *aper.CompletePadding {
	return &v.received
}
func BridgeERABInformationListItemExtIEsIEFieldFieldReplay(v *ERABInformationListItemExtIEsIEField) *aper.Snapshot {
	return &v.replay
}
func BridgeERABInformationListItemExtIEsIEFieldFieldStream(v *ERABInformationListItemExtIEsIEField) *aper.WireSpan {
	return &v.stream
}
func BridgeERABInformationListItemExtIEsIEFieldFieldWithoutReplay(v *ERABInformationListItemExtIEsIEField) *bool {
	return &v.withoutReplay
}
func BridgeERABInformationListItemExtIEsIEFieldMethodMarshalAPERTo(v *ERABInformationListItemExtIEsIEField, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeERABInformationListItemExtIEsIEFieldMethodUnmarshalAPERFrom(v *ERABInformationListItemExtIEsIEField, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeERABInformationListItemExtIEsTransportLayerAddressExtBindingFieldCodec(v *ERABInformationListItemExtIEsTransportLayerAddressExtBinding) *s02.TransportLayerAddressValueCodec {
	return &v.codec
}
func BridgeERABInformationListItemExtIEsTransportLayerAddressExtBindingFieldGet(v *ERABInformationListItemExtIEsTransportLayerAddressExtBinding) *func(*ERABInformationListItemExtIEsValue) (*s00.TransportLayerAddress, bool) {
	return &v.get
}
func BridgeERABInformationListItemExtIEsTransportLayerAddressExtBindingFieldInfo(v *ERABInformationListItemExtIEsTransportLayerAddressExtBinding) *s00.ExtensionInfo {
	return &v.info
}
func BridgeERABInformationListItemExtIEsTransportLayerAddressExtBindingFieldInject(v *ERABInformationListItemExtIEsTransportLayerAddressExtBinding) *func(s00.TransportLayerAddress) ERABInformationListItemExtIEsValue {
	return &v.inject
}
func BridgeERABInformationListItemExtIEsValueFieldId(v *ERABInformationListItemExtIEsValue) *s00.ProtocolIEID {
	return &v.id
}
func BridgeERABInformationListItemExtIEsValueFieldIsOpaque(v *ERABInformationListItemExtIEsValue) *bool {
	return &v.isOpaque
}
func BridgeERABInformationListItemExtIEsValueFieldOpaque(v *ERABInformationListItemExtIEsValue) *aper.OpaqueOpenType {
	return &v.opaque
}
func BridgeERABInformationListItemExtIEsValueFieldReceived(v *ERABInformationListItemExtIEsValue) *aper.WireSpan {
	return &v.received
}
func BridgeERABInformationListItemExtIEsValueFieldReplay(v *ERABInformationListItemExtIEsValue) *aper.Snapshot {
	return &v.replay
}
func BridgeERABInformationListItemExtIEsValueFieldRowDAPSRequestInfo(v *ERABInformationListItemExtIEsValue) **s14.DAPSRequestInfo {
	return &v.rowDAPSRequestInfo
}
func BridgeERABInformationListItemExtIEsValueFieldRowSecurityIndication(v *ERABInformationListItemExtIEsValue) **SecurityIndication {
	return &v.rowSecurityIndication
}
func BridgeERABInformationListItemExtIEsValueFieldRowSourceNodeTransportLayerAddress(v *ERABInformationListItemExtIEsValue) **s00.TransportLayerAddress {
	return &v.rowSourceNodeTransportLayerAddress
}
func BridgeERABInformationListItemExtIEsValueFieldRowSourceTransportLayerAddress(v *ERABInformationListItemExtIEsValue) **s00.TransportLayerAddress {
	return &v.rowSourceTransportLayerAddress
}
func BridgeERABInformationListItemExtIEsValueMethodCaptureSemantics(v ERABInformationListItemExtIEsValue, a0 aper.SemanticCapture) ERABInformationListItemExtIEsValue {
	return v.captureSemantics(a0)
}
func BridgeERABInformationListItemExtIEsValueMethodCompareSemantics(v ERABInformationListItemExtIEsValue, a0 aper.SemanticComparison) aper.SemanticComparison {
	return v.compareSemantics(a0)
}
func BridgeERABInformationListItemExtIEsValueMethodDecode(v ERABInformationListItemExtIEsValue, a0 s00.ProtocolIEID, a1 aper.OpaqueOpenType) (ERABInformationListItemExtIEsValue, error) {
	return v.decode(a0, a1)
}
func BridgeERABInformationListItemExtIEsValueMethodEncode(v ERABInformationListItemExtIEsValue) ([]byte, error) {
	return v.encode()
}
func BridgeERABInformationListItemExtIEsValueMethodEncodeFresh(v ERABInformationListItemExtIEsValue, a0 bool, a1 *aper.DecodeBudget) ([]byte, error) {
	return v.encodeFresh(a0, a1)
}
func BridgeERABInformationListItemExtIEsValueMethodMatchesID(v ERABInformationListItemExtIEsValue, a0 s00.ProtocolIEID, a1 ...*aper.DecodeBudget) bool {
	return v.matchesID(a0, a1...)
}
func BridgeERABInformationListItemExtIEsValueMethodReason(v ERABInformationListItemExtIEsValue, a0 s00.ProtocolIEID) aper.OpaqueReason {
	return v.reason(a0)
}
func BridgeERABInformationListItemExtIEsValueMethodRule(v ERABInformationListItemExtIEsValue) aper.SourceRule {
	return v.rule()
}
func BridgeERABToBeSetupItemBearerSUReqExtIEsBearerTypeExtBindingFieldCodec(v *ERABToBeSetupItemBearerSUReqExtIEsBearerTypeExtBinding) *s00.BearerTypeValueCodec {
	return &v.codec
}
func BridgeERABToBeSetupItemBearerSUReqExtIEsBearerTypeExtBindingFieldGet(v *ERABToBeSetupItemBearerSUReqExtIEsBearerTypeExtBinding) *func(*ERABToBeSetupItemBearerSUReqExtIEsValue) (*s00.BearerType, bool) {
	return &v.get
}
func BridgeERABToBeSetupItemBearerSUReqExtIEsBearerTypeExtBindingFieldInfo(v *ERABToBeSetupItemBearerSUReqExtIEsBearerTypeExtBinding) *s00.ExtensionInfo {
	return &v.info
}
func BridgeERABToBeSetupItemBearerSUReqExtIEsBearerTypeExtBindingFieldInject(v *ERABToBeSetupItemBearerSUReqExtIEsBearerTypeExtBinding) *func(s00.BearerType) ERABToBeSetupItemBearerSUReqExtIEsValue {
	return &v.inject
}
func BridgeERABToBeSetupItemBearerSUReqExtIEsCorrelationIDExtBindingFieldCodec(v *ERABToBeSetupItemBearerSUReqExtIEsCorrelationIDExtBinding) *s00.CorrelationIDValueCodec {
	return &v.codec
}
func BridgeERABToBeSetupItemBearerSUReqExtIEsCorrelationIDExtBindingFieldGet(v *ERABToBeSetupItemBearerSUReqExtIEsCorrelationIDExtBinding) *func(*ERABToBeSetupItemBearerSUReqExtIEsValue) (*s00.CorrelationID, bool) {
	return &v.get
}
func BridgeERABToBeSetupItemBearerSUReqExtIEsCorrelationIDExtBindingFieldInfo(v *ERABToBeSetupItemBearerSUReqExtIEsCorrelationIDExtBinding) *s00.ExtensionInfo {
	return &v.info
}
func BridgeERABToBeSetupItemBearerSUReqExtIEsCorrelationIDExtBindingFieldInject(v *ERABToBeSetupItemBearerSUReqExtIEsCorrelationIDExtBinding) *func(s00.CorrelationID) ERABToBeSetupItemBearerSUReqExtIEsValue {
	return &v.inject
}
func BridgeERABToBeSetupItemBearerSUReqExtIEsEthernetTypeExtBindingFieldCodec(v *ERABToBeSetupItemBearerSUReqExtIEsEthernetTypeExtBinding) *s00.EthernetTypeValueCodec {
	return &v.codec
}
func BridgeERABToBeSetupItemBearerSUReqExtIEsEthernetTypeExtBindingFieldGet(v *ERABToBeSetupItemBearerSUReqExtIEsEthernetTypeExtBinding) *func(*ERABToBeSetupItemBearerSUReqExtIEsValue) (*s00.EthernetType, bool) {
	return &v.get
}
func BridgeERABToBeSetupItemBearerSUReqExtIEsEthernetTypeExtBindingFieldInfo(v *ERABToBeSetupItemBearerSUReqExtIEsEthernetTypeExtBinding) *s00.ExtensionInfo {
	return &v.info
}
func BridgeERABToBeSetupItemBearerSUReqExtIEsEthernetTypeExtBindingFieldInject(v *ERABToBeSetupItemBearerSUReqExtIEsEthernetTypeExtBinding) *func(s00.EthernetType) ERABToBeSetupItemBearerSUReqExtIEsValue {
	return &v.inject
}
func BridgeERABToBeSetupItemBearerSUReqExtIEsExtContainerAPERValueFieldContext(v *ERABToBeSetupItemBearerSUReqExtIEsExtContainerAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABToBeSetupItemBearerSUReqExtIEsExtContainerAPERValueFieldReceived(v *ERABToBeSetupItemBearerSUReqExtIEsExtContainerAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeERABToBeSetupItemBearerSUReqExtIEsExtContainerAPERValueFieldReplay(v *ERABToBeSetupItemBearerSUReqExtIEsExtContainerAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeERABToBeSetupItemBearerSUReqExtIEsExtContainerAPERValueFieldWithoutReplay(v *ERABToBeSetupItemBearerSUReqExtIEsExtContainerAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeERABToBeSetupItemBearerSUReqExtIEsExtContainerValueCodecFieldCapture(v *ERABToBeSetupItemBearerSUReqExtIEsExtContainerValueCodec) *func(ERABToBeSetupItemBearerSUReqExtIEsExtContainer, aper.DecodeState) (ERABToBeSetupItemBearerSUReqExtIEsExtContainer, aper.Snapshot) {
	return &v.capture
}
func BridgeERABToBeSetupItemBearerSUReqExtIEsExtContainerValueCodecFieldCompare(v *ERABToBeSetupItemBearerSUReqExtIEsExtContainerValueCodec) *func(ERABToBeSetupItemBearerSUReqExtIEsExtContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeERABToBeSetupItemBearerSUReqExtIEsExtContainerValueCodecFieldContext(v *ERABToBeSetupItemBearerSUReqExtIEsExtContainerValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABToBeSetupItemBearerSUReqExtIEsExtContainerValueCodecFieldDecode(v *ERABToBeSetupItemBearerSUReqExtIEsExtContainerValueCodec) *func([]byte, aper.DecodeState) (ERABToBeSetupItemBearerSUReqExtIEsExtContainer, error) {
	return &v.decode
}
func BridgeERABToBeSetupItemBearerSUReqExtIEsExtContainerValueCodecFieldEncode(v *ERABToBeSetupItemBearerSUReqExtIEsExtContainerValueCodec) *func(ERABToBeSetupItemBearerSUReqExtIEsExtContainer, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeERABToBeSetupItemBearerSUReqExtIEsExtContainerValueCodecFieldPath(v *ERABToBeSetupItemBearerSUReqExtIEsExtContainerValueCodec) *aper.Path {
	return &v.path
}
func BridgeERABToBeSetupItemBearerSUReqExtIEsExtContainerValueCodecMethodEncodeBudgetValue(v ERABToBeSetupItemBearerSUReqExtIEsExtContainerValueCodec, a0 ERABToBeSetupItemBearerSUReqExtIEsExtContainer, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeERABToBeSetupItemBearerSUReqExtIEsExtContainerValueCodecMethodEncodeChanged(v ERABToBeSetupItemBearerSUReqExtIEsExtContainerValueCodec, a0 ERABToBeSetupItemBearerSUReqExtIEsExtContainer, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeERABToBeSetupItemBearerSUReqExtIEsExtFieldAPERValueFieldContext(v *ERABToBeSetupItemBearerSUReqExtIEsExtFieldAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABToBeSetupItemBearerSUReqExtIEsExtFieldAPERValueFieldReceived(v *ERABToBeSetupItemBearerSUReqExtIEsExtFieldAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeERABToBeSetupItemBearerSUReqExtIEsExtFieldAPERValueFieldReplay(v *ERABToBeSetupItemBearerSUReqExtIEsExtFieldAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeERABToBeSetupItemBearerSUReqExtIEsExtFieldAPERValueFieldWithoutReplay(v *ERABToBeSetupItemBearerSUReqExtIEsExtFieldAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeERABToBeSetupItemBearerSUReqExtIEsExtFieldFieldReceived(v *ERABToBeSetupItemBearerSUReqExtIEsExtField) *aper.CompletePadding {
	return &v.received
}
func BridgeERABToBeSetupItemBearerSUReqExtIEsExtFieldFieldReplay(v *ERABToBeSetupItemBearerSUReqExtIEsExtField) *aper.Snapshot {
	return &v.replay
}
func BridgeERABToBeSetupItemBearerSUReqExtIEsExtFieldFieldStream(v *ERABToBeSetupItemBearerSUReqExtIEsExtField) *aper.WireSpan {
	return &v.stream
}
func BridgeERABToBeSetupItemBearerSUReqExtIEsExtFieldFieldWithoutReplay(v *ERABToBeSetupItemBearerSUReqExtIEsExtField) *bool {
	return &v.withoutReplay
}
func BridgeERABToBeSetupItemBearerSUReqExtIEsExtFieldMethodMarshalAPERTo(v *ERABToBeSetupItemBearerSUReqExtIEsExtField, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeERABToBeSetupItemBearerSUReqExtIEsExtFieldMethodUnmarshalAPERFrom(v *ERABToBeSetupItemBearerSUReqExtIEsExtField, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeERABToBeSetupItemBearerSUReqExtIEsExtFieldValueCodecFieldCapture(v *ERABToBeSetupItemBearerSUReqExtIEsExtFieldValueCodec) *func(ERABToBeSetupItemBearerSUReqExtIEsExtField, aper.DecodeState) (ERABToBeSetupItemBearerSUReqExtIEsExtField, aper.Snapshot) {
	return &v.capture
}
func BridgeERABToBeSetupItemBearerSUReqExtIEsExtFieldValueCodecFieldCompare(v *ERABToBeSetupItemBearerSUReqExtIEsExtFieldValueCodec) *func(ERABToBeSetupItemBearerSUReqExtIEsExtField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeERABToBeSetupItemBearerSUReqExtIEsExtFieldValueCodecFieldContext(v *ERABToBeSetupItemBearerSUReqExtIEsExtFieldValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABToBeSetupItemBearerSUReqExtIEsExtFieldValueCodecFieldDecode(v *ERABToBeSetupItemBearerSUReqExtIEsExtFieldValueCodec) *func([]byte, aper.DecodeState) (ERABToBeSetupItemBearerSUReqExtIEsExtField, error) {
	return &v.decode
}
func BridgeERABToBeSetupItemBearerSUReqExtIEsExtFieldValueCodecFieldEncode(v *ERABToBeSetupItemBearerSUReqExtIEsExtFieldValueCodec) *func(ERABToBeSetupItemBearerSUReqExtIEsExtField, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeERABToBeSetupItemBearerSUReqExtIEsExtFieldValueCodecFieldPath(v *ERABToBeSetupItemBearerSUReqExtIEsExtFieldValueCodec) *aper.Path {
	return &v.path
}
func BridgeERABToBeSetupItemBearerSUReqExtIEsExtFieldValueCodecMethodEncodeBudgetValue(v ERABToBeSetupItemBearerSUReqExtIEsExtFieldValueCodec, a0 ERABToBeSetupItemBearerSUReqExtIEsExtField, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeERABToBeSetupItemBearerSUReqExtIEsExtFieldValueCodecMethodEncodeChanged(v ERABToBeSetupItemBearerSUReqExtIEsExtFieldValueCodec, a0 ERABToBeSetupItemBearerSUReqExtIEsExtField, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeERABToBeSetupItemBearerSUReqExtIEsIEFieldFieldReceived(v *ERABToBeSetupItemBearerSUReqExtIEsIEField) *aper.CompletePadding {
	return &v.received
}
func BridgeERABToBeSetupItemBearerSUReqExtIEsIEFieldFieldReplay(v *ERABToBeSetupItemBearerSUReqExtIEsIEField) *aper.Snapshot {
	return &v.replay
}
func BridgeERABToBeSetupItemBearerSUReqExtIEsIEFieldFieldStream(v *ERABToBeSetupItemBearerSUReqExtIEsIEField) *aper.WireSpan {
	return &v.stream
}
func BridgeERABToBeSetupItemBearerSUReqExtIEsIEFieldFieldWithoutReplay(v *ERABToBeSetupItemBearerSUReqExtIEsIEField) *bool {
	return &v.withoutReplay
}
func BridgeERABToBeSetupItemBearerSUReqExtIEsIEFieldMethodMarshalAPERTo(v *ERABToBeSetupItemBearerSUReqExtIEsIEField, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeERABToBeSetupItemBearerSUReqExtIEsIEFieldMethodUnmarshalAPERFrom(v *ERABToBeSetupItemBearerSUReqExtIEsIEField, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeERABToBeSetupItemBearerSUReqExtIEsValueFieldId(v *ERABToBeSetupItemBearerSUReqExtIEsValue) *s00.ProtocolIEID {
	return &v.id
}
func BridgeERABToBeSetupItemBearerSUReqExtIEsValueFieldIsOpaque(v *ERABToBeSetupItemBearerSUReqExtIEsValue) *bool {
	return &v.isOpaque
}
func BridgeERABToBeSetupItemBearerSUReqExtIEsValueFieldOpaque(v *ERABToBeSetupItemBearerSUReqExtIEsValue) *aper.OpaqueOpenType {
	return &v.opaque
}
func BridgeERABToBeSetupItemBearerSUReqExtIEsValueFieldReceived(v *ERABToBeSetupItemBearerSUReqExtIEsValue) *aper.WireSpan {
	return &v.received
}
func BridgeERABToBeSetupItemBearerSUReqExtIEsValueFieldReplay(v *ERABToBeSetupItemBearerSUReqExtIEsValue) *aper.Snapshot {
	return &v.replay
}
func BridgeERABToBeSetupItemBearerSUReqExtIEsValueFieldRowBearerType(v *ERABToBeSetupItemBearerSUReqExtIEsValue) **s00.BearerType {
	return &v.rowBearerType
}
func BridgeERABToBeSetupItemBearerSUReqExtIEsValueFieldRowCorrelationID(v *ERABToBeSetupItemBearerSUReqExtIEsValue) **s00.CorrelationID {
	return &v.rowCorrelationID
}
func BridgeERABToBeSetupItemBearerSUReqExtIEsValueFieldRowEthernetType(v *ERABToBeSetupItemBearerSUReqExtIEsValue) **s00.EthernetType {
	return &v.rowEthernetType
}
func BridgeERABToBeSetupItemBearerSUReqExtIEsValueFieldRowSIPTOCorrelationID(v *ERABToBeSetupItemBearerSUReqExtIEsValue) **s00.CorrelationID {
	return &v.rowSIPTOCorrelationID
}
func BridgeERABToBeSetupItemBearerSUReqExtIEsValueFieldRowSecurityIndication(v *ERABToBeSetupItemBearerSUReqExtIEsValue) **SecurityIndication {
	return &v.rowSecurityIndication
}
func BridgeERABToBeSetupItemBearerSUReqExtIEsValueMethodCaptureSemantics(v ERABToBeSetupItemBearerSUReqExtIEsValue, a0 aper.SemanticCapture) ERABToBeSetupItemBearerSUReqExtIEsValue {
	return v.captureSemantics(a0)
}
func BridgeERABToBeSetupItemBearerSUReqExtIEsValueMethodCompareSemantics(v ERABToBeSetupItemBearerSUReqExtIEsValue, a0 aper.SemanticComparison) aper.SemanticComparison {
	return v.compareSemantics(a0)
}
func BridgeERABToBeSetupItemBearerSUReqExtIEsValueMethodDecode(v ERABToBeSetupItemBearerSUReqExtIEsValue, a0 s00.ProtocolIEID, a1 aper.OpaqueOpenType) (ERABToBeSetupItemBearerSUReqExtIEsValue, error) {
	return v.decode(a0, a1)
}
func BridgeERABToBeSetupItemBearerSUReqExtIEsValueMethodEncode(v ERABToBeSetupItemBearerSUReqExtIEsValue) ([]byte, error) {
	return v.encode()
}
func BridgeERABToBeSetupItemBearerSUReqExtIEsValueMethodEncodeFresh(v ERABToBeSetupItemBearerSUReqExtIEsValue, a0 bool, a1 *aper.DecodeBudget) ([]byte, error) {
	return v.encodeFresh(a0, a1)
}
func BridgeERABToBeSetupItemBearerSUReqExtIEsValueMethodMatchesID(v ERABToBeSetupItemBearerSUReqExtIEsValue, a0 s00.ProtocolIEID, a1 ...*aper.DecodeBudget) bool {
	return v.matchesID(a0, a1...)
}
func BridgeERABToBeSetupItemBearerSUReqExtIEsValueMethodReason(v ERABToBeSetupItemBearerSUReqExtIEsValue, a0 s00.ProtocolIEID) aper.OpaqueReason {
	return v.reason(a0)
}
func BridgeERABToBeSetupItemBearerSUReqExtIEsValueMethodRule(v ERABToBeSetupItemBearerSUReqExtIEsValue) aper.SourceRule {
	return v.rule()
}
func BridgeERABToBeSetupItemCtxtSUReqExtIEsBearerTypeExtBindingFieldCodec(v *ERABToBeSetupItemCtxtSUReqExtIEsBearerTypeExtBinding) *s00.BearerTypeValueCodec {
	return &v.codec
}
func BridgeERABToBeSetupItemCtxtSUReqExtIEsBearerTypeExtBindingFieldGet(v *ERABToBeSetupItemCtxtSUReqExtIEsBearerTypeExtBinding) *func(*ERABToBeSetupItemCtxtSUReqExtIEsValue) (*s00.BearerType, bool) {
	return &v.get
}
func BridgeERABToBeSetupItemCtxtSUReqExtIEsBearerTypeExtBindingFieldInfo(v *ERABToBeSetupItemCtxtSUReqExtIEsBearerTypeExtBinding) *s00.ExtensionInfo {
	return &v.info
}
func BridgeERABToBeSetupItemCtxtSUReqExtIEsBearerTypeExtBindingFieldInject(v *ERABToBeSetupItemCtxtSUReqExtIEsBearerTypeExtBinding) *func(s00.BearerType) ERABToBeSetupItemCtxtSUReqExtIEsValue {
	return &v.inject
}
func BridgeERABToBeSetupItemCtxtSUReqExtIEsCorrelationIDExtBindingFieldCodec(v *ERABToBeSetupItemCtxtSUReqExtIEsCorrelationIDExtBinding) *s00.CorrelationIDValueCodec {
	return &v.codec
}
func BridgeERABToBeSetupItemCtxtSUReqExtIEsCorrelationIDExtBindingFieldGet(v *ERABToBeSetupItemCtxtSUReqExtIEsCorrelationIDExtBinding) *func(*ERABToBeSetupItemCtxtSUReqExtIEsValue) (*s00.CorrelationID, bool) {
	return &v.get
}
func BridgeERABToBeSetupItemCtxtSUReqExtIEsCorrelationIDExtBindingFieldInfo(v *ERABToBeSetupItemCtxtSUReqExtIEsCorrelationIDExtBinding) *s00.ExtensionInfo {
	return &v.info
}
func BridgeERABToBeSetupItemCtxtSUReqExtIEsCorrelationIDExtBindingFieldInject(v *ERABToBeSetupItemCtxtSUReqExtIEsCorrelationIDExtBinding) *func(s00.CorrelationID) ERABToBeSetupItemCtxtSUReqExtIEsValue {
	return &v.inject
}
func BridgeERABToBeSetupItemCtxtSUReqExtIEsEthernetTypeExtBindingFieldCodec(v *ERABToBeSetupItemCtxtSUReqExtIEsEthernetTypeExtBinding) *s00.EthernetTypeValueCodec {
	return &v.codec
}
func BridgeERABToBeSetupItemCtxtSUReqExtIEsEthernetTypeExtBindingFieldGet(v *ERABToBeSetupItemCtxtSUReqExtIEsEthernetTypeExtBinding) *func(*ERABToBeSetupItemCtxtSUReqExtIEsValue) (*s00.EthernetType, bool) {
	return &v.get
}
func BridgeERABToBeSetupItemCtxtSUReqExtIEsEthernetTypeExtBindingFieldInfo(v *ERABToBeSetupItemCtxtSUReqExtIEsEthernetTypeExtBinding) *s00.ExtensionInfo {
	return &v.info
}
func BridgeERABToBeSetupItemCtxtSUReqExtIEsEthernetTypeExtBindingFieldInject(v *ERABToBeSetupItemCtxtSUReqExtIEsEthernetTypeExtBinding) *func(s00.EthernetType) ERABToBeSetupItemCtxtSUReqExtIEsValue {
	return &v.inject
}
func BridgeERABToBeSetupItemCtxtSUReqExtIEsExtContainerAPERValueFieldContext(v *ERABToBeSetupItemCtxtSUReqExtIEsExtContainerAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABToBeSetupItemCtxtSUReqExtIEsExtContainerAPERValueFieldReceived(v *ERABToBeSetupItemCtxtSUReqExtIEsExtContainerAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeERABToBeSetupItemCtxtSUReqExtIEsExtContainerAPERValueFieldReplay(v *ERABToBeSetupItemCtxtSUReqExtIEsExtContainerAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeERABToBeSetupItemCtxtSUReqExtIEsExtContainerAPERValueFieldWithoutReplay(v *ERABToBeSetupItemCtxtSUReqExtIEsExtContainerAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeERABToBeSetupItemCtxtSUReqExtIEsExtContainerValueCodecFieldCapture(v *ERABToBeSetupItemCtxtSUReqExtIEsExtContainerValueCodec) *func(ERABToBeSetupItemCtxtSUReqExtIEsExtContainer, aper.DecodeState) (ERABToBeSetupItemCtxtSUReqExtIEsExtContainer, aper.Snapshot) {
	return &v.capture
}
func BridgeERABToBeSetupItemCtxtSUReqExtIEsExtContainerValueCodecFieldCompare(v *ERABToBeSetupItemCtxtSUReqExtIEsExtContainerValueCodec) *func(ERABToBeSetupItemCtxtSUReqExtIEsExtContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeERABToBeSetupItemCtxtSUReqExtIEsExtContainerValueCodecFieldContext(v *ERABToBeSetupItemCtxtSUReqExtIEsExtContainerValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABToBeSetupItemCtxtSUReqExtIEsExtContainerValueCodecFieldDecode(v *ERABToBeSetupItemCtxtSUReqExtIEsExtContainerValueCodec) *func([]byte, aper.DecodeState) (ERABToBeSetupItemCtxtSUReqExtIEsExtContainer, error) {
	return &v.decode
}
func BridgeERABToBeSetupItemCtxtSUReqExtIEsExtContainerValueCodecFieldEncode(v *ERABToBeSetupItemCtxtSUReqExtIEsExtContainerValueCodec) *func(ERABToBeSetupItemCtxtSUReqExtIEsExtContainer, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeERABToBeSetupItemCtxtSUReqExtIEsExtContainerValueCodecFieldPath(v *ERABToBeSetupItemCtxtSUReqExtIEsExtContainerValueCodec) *aper.Path {
	return &v.path
}
func BridgeERABToBeSetupItemCtxtSUReqExtIEsExtContainerValueCodecMethodEncodeBudgetValue(v ERABToBeSetupItemCtxtSUReqExtIEsExtContainerValueCodec, a0 ERABToBeSetupItemCtxtSUReqExtIEsExtContainer, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeERABToBeSetupItemCtxtSUReqExtIEsExtContainerValueCodecMethodEncodeChanged(v ERABToBeSetupItemCtxtSUReqExtIEsExtContainerValueCodec, a0 ERABToBeSetupItemCtxtSUReqExtIEsExtContainer, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeERABToBeSetupItemCtxtSUReqExtIEsExtFieldAPERValueFieldContext(v *ERABToBeSetupItemCtxtSUReqExtIEsExtFieldAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABToBeSetupItemCtxtSUReqExtIEsExtFieldAPERValueFieldReceived(v *ERABToBeSetupItemCtxtSUReqExtIEsExtFieldAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeERABToBeSetupItemCtxtSUReqExtIEsExtFieldAPERValueFieldReplay(v *ERABToBeSetupItemCtxtSUReqExtIEsExtFieldAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeERABToBeSetupItemCtxtSUReqExtIEsExtFieldAPERValueFieldWithoutReplay(v *ERABToBeSetupItemCtxtSUReqExtIEsExtFieldAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeERABToBeSetupItemCtxtSUReqExtIEsExtFieldFieldReceived(v *ERABToBeSetupItemCtxtSUReqExtIEsExtField) *aper.CompletePadding {
	return &v.received
}
func BridgeERABToBeSetupItemCtxtSUReqExtIEsExtFieldFieldReplay(v *ERABToBeSetupItemCtxtSUReqExtIEsExtField) *aper.Snapshot {
	return &v.replay
}
func BridgeERABToBeSetupItemCtxtSUReqExtIEsExtFieldFieldStream(v *ERABToBeSetupItemCtxtSUReqExtIEsExtField) *aper.WireSpan {
	return &v.stream
}
func BridgeERABToBeSetupItemCtxtSUReqExtIEsExtFieldFieldWithoutReplay(v *ERABToBeSetupItemCtxtSUReqExtIEsExtField) *bool {
	return &v.withoutReplay
}
func BridgeERABToBeSetupItemCtxtSUReqExtIEsExtFieldMethodMarshalAPERTo(v *ERABToBeSetupItemCtxtSUReqExtIEsExtField, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeERABToBeSetupItemCtxtSUReqExtIEsExtFieldMethodUnmarshalAPERFrom(v *ERABToBeSetupItemCtxtSUReqExtIEsExtField, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeERABToBeSetupItemCtxtSUReqExtIEsExtFieldValueCodecFieldCapture(v *ERABToBeSetupItemCtxtSUReqExtIEsExtFieldValueCodec) *func(ERABToBeSetupItemCtxtSUReqExtIEsExtField, aper.DecodeState) (ERABToBeSetupItemCtxtSUReqExtIEsExtField, aper.Snapshot) {
	return &v.capture
}
func BridgeERABToBeSetupItemCtxtSUReqExtIEsExtFieldValueCodecFieldCompare(v *ERABToBeSetupItemCtxtSUReqExtIEsExtFieldValueCodec) *func(ERABToBeSetupItemCtxtSUReqExtIEsExtField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeERABToBeSetupItemCtxtSUReqExtIEsExtFieldValueCodecFieldContext(v *ERABToBeSetupItemCtxtSUReqExtIEsExtFieldValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABToBeSetupItemCtxtSUReqExtIEsExtFieldValueCodecFieldDecode(v *ERABToBeSetupItemCtxtSUReqExtIEsExtFieldValueCodec) *func([]byte, aper.DecodeState) (ERABToBeSetupItemCtxtSUReqExtIEsExtField, error) {
	return &v.decode
}
func BridgeERABToBeSetupItemCtxtSUReqExtIEsExtFieldValueCodecFieldEncode(v *ERABToBeSetupItemCtxtSUReqExtIEsExtFieldValueCodec) *func(ERABToBeSetupItemCtxtSUReqExtIEsExtField, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeERABToBeSetupItemCtxtSUReqExtIEsExtFieldValueCodecFieldPath(v *ERABToBeSetupItemCtxtSUReqExtIEsExtFieldValueCodec) *aper.Path {
	return &v.path
}
func BridgeERABToBeSetupItemCtxtSUReqExtIEsExtFieldValueCodecMethodEncodeBudgetValue(v ERABToBeSetupItemCtxtSUReqExtIEsExtFieldValueCodec, a0 ERABToBeSetupItemCtxtSUReqExtIEsExtField, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeERABToBeSetupItemCtxtSUReqExtIEsExtFieldValueCodecMethodEncodeChanged(v ERABToBeSetupItemCtxtSUReqExtIEsExtFieldValueCodec, a0 ERABToBeSetupItemCtxtSUReqExtIEsExtField, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeERABToBeSetupItemCtxtSUReqExtIEsIEFieldFieldReceived(v *ERABToBeSetupItemCtxtSUReqExtIEsIEField) *aper.CompletePadding {
	return &v.received
}
func BridgeERABToBeSetupItemCtxtSUReqExtIEsIEFieldFieldReplay(v *ERABToBeSetupItemCtxtSUReqExtIEsIEField) *aper.Snapshot {
	return &v.replay
}
func BridgeERABToBeSetupItemCtxtSUReqExtIEsIEFieldFieldStream(v *ERABToBeSetupItemCtxtSUReqExtIEsIEField) *aper.WireSpan {
	return &v.stream
}
func BridgeERABToBeSetupItemCtxtSUReqExtIEsIEFieldFieldWithoutReplay(v *ERABToBeSetupItemCtxtSUReqExtIEsIEField) *bool {
	return &v.withoutReplay
}
func BridgeERABToBeSetupItemCtxtSUReqExtIEsIEFieldMethodMarshalAPERTo(v *ERABToBeSetupItemCtxtSUReqExtIEsIEField, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeERABToBeSetupItemCtxtSUReqExtIEsIEFieldMethodUnmarshalAPERFrom(v *ERABToBeSetupItemCtxtSUReqExtIEsIEField, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeERABToBeSetupItemCtxtSUReqExtIEsValueFieldId(v *ERABToBeSetupItemCtxtSUReqExtIEsValue) *s00.ProtocolIEID {
	return &v.id
}
func BridgeERABToBeSetupItemCtxtSUReqExtIEsValueFieldIsOpaque(v *ERABToBeSetupItemCtxtSUReqExtIEsValue) *bool {
	return &v.isOpaque
}
func BridgeERABToBeSetupItemCtxtSUReqExtIEsValueFieldOpaque(v *ERABToBeSetupItemCtxtSUReqExtIEsValue) *aper.OpaqueOpenType {
	return &v.opaque
}
func BridgeERABToBeSetupItemCtxtSUReqExtIEsValueFieldReceived(v *ERABToBeSetupItemCtxtSUReqExtIEsValue) *aper.WireSpan {
	return &v.received
}
func BridgeERABToBeSetupItemCtxtSUReqExtIEsValueFieldReplay(v *ERABToBeSetupItemCtxtSUReqExtIEsValue) *aper.Snapshot {
	return &v.replay
}
func BridgeERABToBeSetupItemCtxtSUReqExtIEsValueFieldRowBearerType(v *ERABToBeSetupItemCtxtSUReqExtIEsValue) **s00.BearerType {
	return &v.rowBearerType
}
func BridgeERABToBeSetupItemCtxtSUReqExtIEsValueFieldRowCorrelationID(v *ERABToBeSetupItemCtxtSUReqExtIEsValue) **s00.CorrelationID {
	return &v.rowCorrelationID
}
func BridgeERABToBeSetupItemCtxtSUReqExtIEsValueFieldRowEthernetType(v *ERABToBeSetupItemCtxtSUReqExtIEsValue) **s00.EthernetType {
	return &v.rowEthernetType
}
func BridgeERABToBeSetupItemCtxtSUReqExtIEsValueFieldRowSIPTOCorrelationID(v *ERABToBeSetupItemCtxtSUReqExtIEsValue) **s00.CorrelationID {
	return &v.rowSIPTOCorrelationID
}
func BridgeERABToBeSetupItemCtxtSUReqExtIEsValueFieldRowSecurityIndication(v *ERABToBeSetupItemCtxtSUReqExtIEsValue) **SecurityIndication {
	return &v.rowSecurityIndication
}
func BridgeERABToBeSetupItemCtxtSUReqExtIEsValueMethodCaptureSemantics(v ERABToBeSetupItemCtxtSUReqExtIEsValue, a0 aper.SemanticCapture) ERABToBeSetupItemCtxtSUReqExtIEsValue {
	return v.captureSemantics(a0)
}
func BridgeERABToBeSetupItemCtxtSUReqExtIEsValueMethodCompareSemantics(v ERABToBeSetupItemCtxtSUReqExtIEsValue, a0 aper.SemanticComparison) aper.SemanticComparison {
	return v.compareSemantics(a0)
}
func BridgeERABToBeSetupItemCtxtSUReqExtIEsValueMethodDecode(v ERABToBeSetupItemCtxtSUReqExtIEsValue, a0 s00.ProtocolIEID, a1 aper.OpaqueOpenType) (ERABToBeSetupItemCtxtSUReqExtIEsValue, error) {
	return v.decode(a0, a1)
}
func BridgeERABToBeSetupItemCtxtSUReqExtIEsValueMethodEncode(v ERABToBeSetupItemCtxtSUReqExtIEsValue) ([]byte, error) {
	return v.encode()
}
func BridgeERABToBeSetupItemCtxtSUReqExtIEsValueMethodEncodeFresh(v ERABToBeSetupItemCtxtSUReqExtIEsValue, a0 bool, a1 *aper.DecodeBudget) ([]byte, error) {
	return v.encodeFresh(a0, a1)
}
func BridgeERABToBeSetupItemCtxtSUReqExtIEsValueMethodMatchesID(v ERABToBeSetupItemCtxtSUReqExtIEsValue, a0 s00.ProtocolIEID, a1 ...*aper.DecodeBudget) bool {
	return v.matchesID(a0, a1...)
}
func BridgeERABToBeSetupItemCtxtSUReqExtIEsValueMethodReason(v ERABToBeSetupItemCtxtSUReqExtIEsValue, a0 s00.ProtocolIEID) aper.OpaqueReason {
	return v.reason(a0)
}
func BridgeERABToBeSetupItemCtxtSUReqExtIEsValueMethodRule(v ERABToBeSetupItemCtxtSUReqExtIEsValue) aper.SourceRule {
	return v.rule()
}
func BridgeErrorIndicationAPERValueFieldContext(v *ErrorIndicationAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeErrorIndicationAPERValueFieldReceived(v *ErrorIndicationAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeErrorIndicationAPERValueFieldReplay(v *ErrorIndicationAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeErrorIndicationAPERValueFieldWithoutReplay(v *ErrorIndicationAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeErrorIndicationCauseIEBindingFieldCodec(v *ErrorIndicationCauseIEBinding) *s14.CauseValueCodec {
	return &v.codec
}
func BridgeErrorIndicationCauseIEBindingFieldGet(v *ErrorIndicationCauseIEBinding) *func(*ErrorIndicationIEValue) (*s14.Cause, bool) {
	return &v.get
}
func BridgeErrorIndicationCauseIEBindingFieldInfo(v *ErrorIndicationCauseIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeErrorIndicationCauseIEBindingFieldInject(v *ErrorIndicationCauseIEBinding) *func(s14.Cause) ErrorIndicationIEValue {
	return &v.inject
}
func BridgeErrorIndicationCriticalityDiagnosticsIEBindingFieldCodec(v *ErrorIndicationCriticalityDiagnosticsIEBinding) *s22.CriticalityDiagnosticsValueCodec {
	return &v.codec
}
func BridgeErrorIndicationCriticalityDiagnosticsIEBindingFieldGet(v *ErrorIndicationCriticalityDiagnosticsIEBinding) *func(*ErrorIndicationIEValue) (*s22.CriticalityDiagnostics, bool) {
	return &v.get
}
func BridgeErrorIndicationCriticalityDiagnosticsIEBindingFieldInfo(v *ErrorIndicationCriticalityDiagnosticsIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeErrorIndicationCriticalityDiagnosticsIEBindingFieldInject(v *ErrorIndicationCriticalityDiagnosticsIEBinding) *func(s22.CriticalityDiagnostics) ErrorIndicationIEValue {
	return &v.inject
}
func BridgeErrorIndicationENBUES1APIDIEBindingFieldCodec(v *ErrorIndicationENBUES1APIDIEBinding) *s00.ENBUES1APIDValueCodec {
	return &v.codec
}
func BridgeErrorIndicationENBUES1APIDIEBindingFieldGet(v *ErrorIndicationENBUES1APIDIEBinding) *func(*ErrorIndicationIEValue) (*s00.ENBUES1APID, bool) {
	return &v.get
}
func BridgeErrorIndicationENBUES1APIDIEBindingFieldInfo(v *ErrorIndicationENBUES1APIDIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeErrorIndicationENBUES1APIDIEBindingFieldInject(v *ErrorIndicationENBUES1APIDIEBinding) *func(s00.ENBUES1APID) ErrorIndicationIEValue {
	return &v.inject
}
func BridgeErrorIndicationFieldExtCount(v *ErrorIndication) *int64   { return &v.extCount }
func BridgeErrorIndicationFieldExtData(v *ErrorIndication) *[][]byte { return &v.extData }
func BridgeErrorIndicationFieldExtOrigin(v *ErrorIndication) *[]aper.OpaqueOrigin {
	return &v.extOrigin
}
func BridgeErrorIndicationFieldExtPresent(v *ErrorIndication) *[]bool       { return &v.extPresent }
func BridgeErrorIndicationFieldExtWire(v *ErrorIndication) *[]aper.WireSpan { return &v.extWire }
func BridgeErrorIndicationFieldPerExtPadding(v *ErrorIndication) *[]aper.CompletePadding {
	return &v.perExtPadding
}
func BridgeErrorIndicationFieldPerPadding(v *ErrorIndication) *aper.FinalPadding {
	return &v.perPadding
}
func BridgeErrorIndicationFieldProtocolIEsIndef(v *ErrorIndication) *bool { return &v.protocolIEsIndef }
func BridgeErrorIndicationFieldReceived(v *ErrorIndication) *bool         { return &v.received }
func BridgeErrorIndicationFieldReceivedAbsolute(v *ErrorIndication) *bool { return &v.receivedAbsolute }
func BridgeErrorIndicationFieldReceivedBytes(v *ErrorIndication) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeErrorIndicationFieldReceivedLocation(v *ErrorIndication) *aper.Location {
	return &v.receivedLocation
}
func BridgeErrorIndicationFieldReplay(v *ErrorIndication) *aper.Snapshot { return &v.replay }
func BridgeErrorIndicationFieldStream(v *ErrorIndication) *aper.WireSpan { return &v.stream }
func BridgeErrorIndicationFieldWithoutReplay(v *ErrorIndication) *bool   { return &v.withoutReplay }
func BridgeErrorIndicationIEContainerAPERValueFieldContext(v *ErrorIndicationIEContainerAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeErrorIndicationIEContainerAPERValueFieldReceived(v *ErrorIndicationIEContainerAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeErrorIndicationIEContainerAPERValueFieldReplay(v *ErrorIndicationIEContainerAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeErrorIndicationIEContainerAPERValueFieldWithoutReplay(v *ErrorIndicationIEContainerAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeErrorIndicationIEContainerValueCodecFieldCapture(v *ErrorIndicationIEContainerValueCodec) *func(ErrorIndicationIEContainer, aper.DecodeState) (ErrorIndicationIEContainer, aper.Snapshot) {
	return &v.capture
}
func BridgeErrorIndicationIEContainerValueCodecFieldCompare(v *ErrorIndicationIEContainerValueCodec) *func(ErrorIndicationIEContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeErrorIndicationIEContainerValueCodecFieldContext(v *ErrorIndicationIEContainerValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeErrorIndicationIEContainerValueCodecFieldDecode(v *ErrorIndicationIEContainerValueCodec) *func([]byte, aper.DecodeState) (ErrorIndicationIEContainer, error) {
	return &v.decode
}
func BridgeErrorIndicationIEContainerValueCodecFieldEncode(v *ErrorIndicationIEContainerValueCodec) *func(ErrorIndicationIEContainer, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeErrorIndicationIEContainerValueCodecFieldPath(v *ErrorIndicationIEContainerValueCodec) *aper.Path {
	return &v.path
}
func BridgeErrorIndicationIEContainerValueCodecMethodEncodeBudgetValue(v ErrorIndicationIEContainerValueCodec, a0 ErrorIndicationIEContainer, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeErrorIndicationIEContainerValueCodecMethodEncodeChanged(v ErrorIndicationIEContainerValueCodec, a0 ErrorIndicationIEContainer, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeErrorIndicationIEFieldAPERValueFieldContext(v *ErrorIndicationIEFieldAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeErrorIndicationIEFieldAPERValueFieldReceived(v *ErrorIndicationIEFieldAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeErrorIndicationIEFieldAPERValueFieldReplay(v *ErrorIndicationIEFieldAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeErrorIndicationIEFieldAPERValueFieldWithoutReplay(v *ErrorIndicationIEFieldAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeErrorIndicationIEFieldFieldReceived(v *ErrorIndicationIEField) *aper.CompletePadding {
	return &v.received
}
func BridgeErrorIndicationIEFieldFieldReplay(v *ErrorIndicationIEField) *aper.Snapshot {
	return &v.replay
}
func BridgeErrorIndicationIEFieldFieldStream(v *ErrorIndicationIEField) *aper.WireSpan {
	return &v.stream
}
func BridgeErrorIndicationIEFieldFieldWithoutReplay(v *ErrorIndicationIEField) *bool {
	return &v.withoutReplay
}
func BridgeErrorIndicationIEFieldMethodMarshalAPERTo(v *ErrorIndicationIEField, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeErrorIndicationIEFieldMethodUnmarshalAPERFrom(v *ErrorIndicationIEField, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeErrorIndicationIEFieldValueCodecFieldCapture(v *ErrorIndicationIEFieldValueCodec) *func(ErrorIndicationIEField, aper.DecodeState) (ErrorIndicationIEField, aper.Snapshot) {
	return &v.capture
}
func BridgeErrorIndicationIEFieldValueCodecFieldCompare(v *ErrorIndicationIEFieldValueCodec) *func(ErrorIndicationIEField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeErrorIndicationIEFieldValueCodecFieldContext(v *ErrorIndicationIEFieldValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeErrorIndicationIEFieldValueCodecFieldDecode(v *ErrorIndicationIEFieldValueCodec) *func([]byte, aper.DecodeState) (ErrorIndicationIEField, error) {
	return &v.decode
}
func BridgeErrorIndicationIEFieldValueCodecFieldEncode(v *ErrorIndicationIEFieldValueCodec) *func(ErrorIndicationIEField, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeErrorIndicationIEFieldValueCodecFieldPath(v *ErrorIndicationIEFieldValueCodec) *aper.Path {
	return &v.path
}
func BridgeErrorIndicationIEFieldValueCodecMethodEncodeBudgetValue(v ErrorIndicationIEFieldValueCodec, a0 ErrorIndicationIEField, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeErrorIndicationIEFieldValueCodecMethodEncodeChanged(v ErrorIndicationIEFieldValueCodec, a0 ErrorIndicationIEField, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeErrorIndicationIETableMethodInfoCause(v ErrorIndicationIETable) s00.FieldInfo {
	return v.infoCause()
}
func BridgeErrorIndicationIETableMethodInfoCriticalityDiagnostics(v ErrorIndicationIETable) s00.FieldInfo {
	return v.infoCriticalityDiagnostics()
}
func BridgeErrorIndicationIETableMethodInfoENBUES1APID(v ErrorIndicationIETable) s00.FieldInfo {
	return v.infoENBUES1APID()
}
func BridgeErrorIndicationIETableMethodInfoMMEUES1APID(v ErrorIndicationIETable) s00.FieldInfo {
	return v.infoMMEUES1APID()
}
func BridgeErrorIndicationIETableMethodInfoSTMSI(v ErrorIndicationIETable) s00.FieldInfo {
	return v.infoSTMSI()
}
func BridgeErrorIndicationIEValueERABIEContainerListAPERValueFieldContext(v *ErrorIndicationIEValueERABIEContainerListAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeErrorIndicationIEValueERABIEContainerListAPERValueFieldReceived(v *ErrorIndicationIEValueERABIEContainerListAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeErrorIndicationIEValueERABIEContainerListAPERValueFieldReplay(v *ErrorIndicationIEValueERABIEContainerListAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeErrorIndicationIEValueERABIEContainerListAPERValueFieldWithoutReplay(v *ErrorIndicationIEValueERABIEContainerListAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeErrorIndicationIEValueERABIEContainerListValueCodecFieldCapture(v *ErrorIndicationIEValueERABIEContainerListValueCodec) *func(ErrorIndicationIEValueERABIEContainerList, aper.DecodeState) (ErrorIndicationIEValueERABIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgeErrorIndicationIEValueERABIEContainerListValueCodecFieldCompare(v *ErrorIndicationIEValueERABIEContainerListValueCodec) *func(ErrorIndicationIEValueERABIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeErrorIndicationIEValueERABIEContainerListValueCodecFieldContext(v *ErrorIndicationIEValueERABIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeErrorIndicationIEValueERABIEContainerListValueCodecFieldDecode(v *ErrorIndicationIEValueERABIEContainerListValueCodec) *func([]byte, aper.DecodeState) (ErrorIndicationIEValueERABIEContainerList, error) {
	return &v.decode
}
func BridgeErrorIndicationIEValueERABIEContainerListValueCodecFieldEncode(v *ErrorIndicationIEValueERABIEContainerListValueCodec) *func(ErrorIndicationIEValueERABIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeErrorIndicationIEValueERABIEContainerListValueCodecFieldPath(v *ErrorIndicationIEValueERABIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgeErrorIndicationIEValueERABIEContainerListValueCodecMethodEncodeBudgetValue(v ErrorIndicationIEValueERABIEContainerListValueCodec, a0 ErrorIndicationIEValueERABIEContainerList, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeErrorIndicationIEValueERABIEContainerListValueCodecMethodEncodeChanged(v ErrorIndicationIEValueERABIEContainerListValueCodec, a0 ErrorIndicationIEValueERABIEContainerList, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeErrorIndicationIEValueFieldId(v *ErrorIndicationIEValue) *s00.ProtocolIEID { return &v.id }
func BridgeErrorIndicationIEValueFieldIsOpaque(v *ErrorIndicationIEValue) *bool       { return &v.isOpaque }
func BridgeErrorIndicationIEValueFieldOpaque(v *ErrorIndicationIEValue) *aper.OpaqueOpenType {
	return &v.opaque
}
func BridgeErrorIndicationIEValueFieldReceived(v *ErrorIndicationIEValue) *aper.WireSpan {
	return &v.received
}
func BridgeErrorIndicationIEValueFieldReplay(v *ErrorIndicationIEValue) *aper.Snapshot {
	return &v.replay
}
func BridgeErrorIndicationIEValueFieldRowCause(v *ErrorIndicationIEValue) **s14.Cause {
	return &v.rowCause
}
func BridgeErrorIndicationIEValueFieldRowCriticalityDiagnostics(v *ErrorIndicationIEValue) **s22.CriticalityDiagnostics {
	return &v.rowCriticalityDiagnostics
}
func BridgeErrorIndicationIEValueFieldRowENBUES1APID(v *ErrorIndicationIEValue) **s00.ENBUES1APID {
	return &v.rowENBUES1APID
}
func BridgeErrorIndicationIEValueFieldRowMMEUES1APID(v *ErrorIndicationIEValue) **s00.MMEUES1APID {
	return &v.rowMMEUES1APID
}
func BridgeErrorIndicationIEValueFieldRowSTMSI(v *ErrorIndicationIEValue) **s27.STMSI {
	return &v.rowSTMSI
}
func BridgeErrorIndicationIEValueMethodCaptureSemantics(v ErrorIndicationIEValue, a0 aper.SemanticCapture) ErrorIndicationIEValue {
	return v.captureSemantics(a0)
}
func BridgeErrorIndicationIEValueMethodCompareSemantics(v ErrorIndicationIEValue, a0 aper.SemanticComparison) aper.SemanticComparison {
	return v.compareSemantics(a0)
}
func BridgeErrorIndicationIEValueMethodDecode(v ErrorIndicationIEValue, a0 s00.ProtocolIEID, a1 aper.OpaqueOpenType) (ErrorIndicationIEValue, error) {
	return v.decode(a0, a1)
}
func BridgeErrorIndicationIEValueMethodEncode(v ErrorIndicationIEValue) ([]byte, error) {
	return v.encode()
}
func BridgeErrorIndicationIEValueMethodEncodeFresh(v ErrorIndicationIEValue, a0 bool, a1 *aper.DecodeBudget) ([]byte, error) {
	return v.encodeFresh(a0, a1)
}
func BridgeErrorIndicationIEValueMethodMatchesID(v ErrorIndicationIEValue, a0 s00.ProtocolIEID, a1 ...*aper.DecodeBudget) bool {
	return v.matchesID(a0, a1...)
}
func BridgeErrorIndicationIEValueMethodReason(v ErrorIndicationIEValue, a0 s00.ProtocolIEID) aper.OpaqueReason {
	return v.reason(a0)
}
func BridgeErrorIndicationIEValueMethodRule(v ErrorIndicationIEValue) aper.SourceRule {
	return v.rule()
}
func BridgeErrorIndicationIEValueProtocolErrorIEContainerListAPERValueFieldContext(v *ErrorIndicationIEValueProtocolErrorIEContainerListAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeErrorIndicationIEValueProtocolErrorIEContainerListAPERValueFieldReceived(v *ErrorIndicationIEValueProtocolErrorIEContainerListAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeErrorIndicationIEValueProtocolErrorIEContainerListAPERValueFieldReplay(v *ErrorIndicationIEValueProtocolErrorIEContainerListAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeErrorIndicationIEValueProtocolErrorIEContainerListAPERValueFieldWithoutReplay(v *ErrorIndicationIEValueProtocolErrorIEContainerListAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeErrorIndicationIEValueProtocolErrorIEContainerListValueCodecFieldCapture(v *ErrorIndicationIEValueProtocolErrorIEContainerListValueCodec) *func(ErrorIndicationIEValueProtocolErrorIEContainerList, aper.DecodeState) (ErrorIndicationIEValueProtocolErrorIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgeErrorIndicationIEValueProtocolErrorIEContainerListValueCodecFieldCompare(v *ErrorIndicationIEValueProtocolErrorIEContainerListValueCodec) *func(ErrorIndicationIEValueProtocolErrorIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeErrorIndicationIEValueProtocolErrorIEContainerListValueCodecFieldContext(v *ErrorIndicationIEValueProtocolErrorIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeErrorIndicationIEValueProtocolErrorIEContainerListValueCodecFieldDecode(v *ErrorIndicationIEValueProtocolErrorIEContainerListValueCodec) *func([]byte, aper.DecodeState) (ErrorIndicationIEValueProtocolErrorIEContainerList, error) {
	return &v.decode
}
func BridgeErrorIndicationIEValueProtocolErrorIEContainerListValueCodecFieldEncode(v *ErrorIndicationIEValueProtocolErrorIEContainerListValueCodec) *func(ErrorIndicationIEValueProtocolErrorIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeErrorIndicationIEValueProtocolErrorIEContainerListValueCodecFieldPath(v *ErrorIndicationIEValueProtocolErrorIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgeErrorIndicationIEValueProtocolErrorIEContainerListValueCodecMethodEncodeBudgetValue(v ErrorIndicationIEValueProtocolErrorIEContainerListValueCodec, a0 ErrorIndicationIEValueProtocolErrorIEContainerList, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeErrorIndicationIEValueProtocolErrorIEContainerListValueCodecMethodEncodeChanged(v ErrorIndicationIEValueProtocolErrorIEContainerListValueCodec, a0 ErrorIndicationIEValueProtocolErrorIEContainerList, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeErrorIndicationIEValueProtocolIEContainerListAPERValueFieldContext(v *ErrorIndicationIEValueProtocolIEContainerListAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeErrorIndicationIEValueProtocolIEContainerListAPERValueFieldReceived(v *ErrorIndicationIEValueProtocolIEContainerListAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeErrorIndicationIEValueProtocolIEContainerListAPERValueFieldReplay(v *ErrorIndicationIEValueProtocolIEContainerListAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeErrorIndicationIEValueProtocolIEContainerListAPERValueFieldWithoutReplay(v *ErrorIndicationIEValueProtocolIEContainerListAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeErrorIndicationIEValueProtocolIEContainerListValueCodecFieldCapture(v *ErrorIndicationIEValueProtocolIEContainerListValueCodec) *func(ErrorIndicationIEValueProtocolIEContainerList, aper.DecodeState) (ErrorIndicationIEValueProtocolIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgeErrorIndicationIEValueProtocolIEContainerListValueCodecFieldCompare(v *ErrorIndicationIEValueProtocolIEContainerListValueCodec) *func(ErrorIndicationIEValueProtocolIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeErrorIndicationIEValueProtocolIEContainerListValueCodecFieldContext(v *ErrorIndicationIEValueProtocolIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeErrorIndicationIEValueProtocolIEContainerListValueCodecFieldDecode(v *ErrorIndicationIEValueProtocolIEContainerListValueCodec) *func([]byte, aper.DecodeState) (ErrorIndicationIEValueProtocolIEContainerList, error) {
	return &v.decode
}
func BridgeErrorIndicationIEValueProtocolIEContainerListValueCodecFieldEncode(v *ErrorIndicationIEValueProtocolIEContainerListValueCodec) *func(ErrorIndicationIEValueProtocolIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeErrorIndicationIEValueProtocolIEContainerListValueCodecFieldPath(v *ErrorIndicationIEValueProtocolIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgeErrorIndicationIEValueProtocolIEContainerListValueCodecMethodEncodeBudgetValue(v ErrorIndicationIEValueProtocolIEContainerListValueCodec, a0 ErrorIndicationIEValueProtocolIEContainerList, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeErrorIndicationIEValueProtocolIEContainerListValueCodecMethodEncodeChanged(v ErrorIndicationIEValueProtocolIEContainerListValueCodec, a0 ErrorIndicationIEValueProtocolIEContainerList, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeErrorIndicationMMEUES1APIDIEBindingFieldCodec(v *ErrorIndicationMMEUES1APIDIEBinding) *s01.MMEUES1APIDValueCodec {
	return &v.codec
}
func BridgeErrorIndicationMMEUES1APIDIEBindingFieldGet(v *ErrorIndicationMMEUES1APIDIEBinding) *func(*ErrorIndicationIEValue) (*s00.MMEUES1APID, bool) {
	return &v.get
}
func BridgeErrorIndicationMMEUES1APIDIEBindingFieldInfo(v *ErrorIndicationMMEUES1APIDIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeErrorIndicationMMEUES1APIDIEBindingFieldInject(v *ErrorIndicationMMEUES1APIDIEBinding) *func(s00.MMEUES1APID) ErrorIndicationIEValue {
	return &v.inject
}
func BridgeErrorIndicationMethodMarshalAPERBudget(v *ErrorIndication, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeErrorIndicationMethodMarshalAPERBudgetValue(v *ErrorIndication, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudgetValue(a0, a1)
}
func BridgeErrorIndicationMethodMarshalAPERChanged(v *ErrorIndication, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeErrorIndicationMethodMarshalAPERChangedValue(v *ErrorIndication, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeErrorIndicationMethodMarshalAPERLegacy(v *ErrorIndication) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeErrorIndicationMethodMarshalAPERNewValue(v *ErrorIndication, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERNewValue(a0, a1)
}
func BridgeErrorIndicationMethodMarshalAPERPlanned(v *ErrorIndication, a0 *aper.DecodeBudget, a1 bool, a2 *aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1, a2)
}
func BridgeErrorIndicationMethodMarshalAPERTo(v *ErrorIndication, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeErrorIndicationMethodUnmarshalAPERFrom(v *ErrorIndication, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeErrorIndicationMethodUnmarshalAPERLegacy(v *ErrorIndication, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeErrorIndicationMethodUnmarshalAPERWithOptions(v *ErrorIndication, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeErrorIndicationSTMSIIEBindingFieldCodec(v *ErrorIndicationSTMSIIEBinding) *STMSIValueCodec {
	return &v.codec
}
func BridgeErrorIndicationSTMSIIEBindingFieldGet(v *ErrorIndicationSTMSIIEBinding) *func(*ErrorIndicationIEValue) (*s27.STMSI, bool) {
	return &v.get
}
func BridgeErrorIndicationSTMSIIEBindingFieldInfo(v *ErrorIndicationSTMSIIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeErrorIndicationSTMSIIEBindingFieldInject(v *ErrorIndicationSTMSIIEBinding) *func(s27.STMSI) ErrorIndicationIEValue {
	return &v.inject
}
func BridgeErrorIndicationValueCodecFieldCapture(v *ErrorIndicationValueCodec) *func(ErrorIndication, aper.DecodeState) (ErrorIndication, aper.Snapshot) {
	return &v.capture
}
func BridgeErrorIndicationValueCodecFieldCompare(v *ErrorIndicationValueCodec) *func(ErrorIndication, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeErrorIndicationValueCodecFieldContext(v *ErrorIndicationValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeErrorIndicationValueCodecFieldDecode(v *ErrorIndicationValueCodec) *func([]byte, aper.DecodeState) (ErrorIndication, error) {
	return &v.decode
}
func BridgeErrorIndicationValueCodecFieldEncode(v *ErrorIndicationValueCodec) *func(ErrorIndication, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeErrorIndicationValueCodecFieldPath(v *ErrorIndicationValueCodec) *aper.Path {
	return &v.path
}
func BridgeErrorIndicationValueCodecMethodEncodeBudgetValue(v ErrorIndicationValueCodec, a0 ErrorIndication, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeErrorIndicationValueCodecMethodEncodeChanged(v ErrorIndicationValueCodec, a0 ErrorIndication, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeRetrieveUEInformationAPERValueFieldContext(v *RetrieveUEInformationAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeRetrieveUEInformationAPERValueFieldReceived(v *RetrieveUEInformationAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeRetrieveUEInformationAPERValueFieldReplay(v *RetrieveUEInformationAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeRetrieveUEInformationAPERValueFieldWithoutReplay(v *RetrieveUEInformationAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeRetrieveUEInformationFieldExtCount(v *RetrieveUEInformation) *int64   { return &v.extCount }
func BridgeRetrieveUEInformationFieldExtData(v *RetrieveUEInformation) *[][]byte { return &v.extData }
func BridgeRetrieveUEInformationFieldExtOrigin(v *RetrieveUEInformation) *[]aper.OpaqueOrigin {
	return &v.extOrigin
}
func BridgeRetrieveUEInformationFieldExtPresent(v *RetrieveUEInformation) *[]bool {
	return &v.extPresent
}
func BridgeRetrieveUEInformationFieldExtWire(v *RetrieveUEInformation) *[]aper.WireSpan {
	return &v.extWire
}
func BridgeRetrieveUEInformationFieldPerExtPadding(v *RetrieveUEInformation) *[]aper.CompletePadding {
	return &v.perExtPadding
}
func BridgeRetrieveUEInformationFieldPerPadding(v *RetrieveUEInformation) *aper.FinalPadding {
	return &v.perPadding
}
func BridgeRetrieveUEInformationFieldProtocolIEsIndef(v *RetrieveUEInformation) *bool {
	return &v.protocolIEsIndef
}
func BridgeRetrieveUEInformationFieldReceived(v *RetrieveUEInformation) *bool { return &v.received }
func BridgeRetrieveUEInformationFieldReceivedAbsolute(v *RetrieveUEInformation) *bool {
	return &v.receivedAbsolute
}
func BridgeRetrieveUEInformationFieldReceivedBytes(v *RetrieveUEInformation) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeRetrieveUEInformationFieldReceivedLocation(v *RetrieveUEInformation) *aper.Location {
	return &v.receivedLocation
}
func BridgeRetrieveUEInformationFieldReplay(v *RetrieveUEInformation) *aper.Snapshot {
	return &v.replay
}
func BridgeRetrieveUEInformationFieldStream(v *RetrieveUEInformation) *aper.WireSpan {
	return &v.stream
}
func BridgeRetrieveUEInformationFieldWithoutReplay(v *RetrieveUEInformation) *bool {
	return &v.withoutReplay
}
func BridgeRetrieveUEInformationIEContainerAPERValueFieldContext(v *RetrieveUEInformationIEContainerAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeRetrieveUEInformationIEContainerAPERValueFieldReceived(v *RetrieveUEInformationIEContainerAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeRetrieveUEInformationIEContainerAPERValueFieldReplay(v *RetrieveUEInformationIEContainerAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeRetrieveUEInformationIEContainerAPERValueFieldWithoutReplay(v *RetrieveUEInformationIEContainerAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeRetrieveUEInformationIEContainerValueCodecFieldCapture(v *RetrieveUEInformationIEContainerValueCodec) *func(RetrieveUEInformationIEContainer, aper.DecodeState) (RetrieveUEInformationIEContainer, aper.Snapshot) {
	return &v.capture
}
func BridgeRetrieveUEInformationIEContainerValueCodecFieldCompare(v *RetrieveUEInformationIEContainerValueCodec) *func(RetrieveUEInformationIEContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeRetrieveUEInformationIEContainerValueCodecFieldContext(v *RetrieveUEInformationIEContainerValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeRetrieveUEInformationIEContainerValueCodecFieldDecode(v *RetrieveUEInformationIEContainerValueCodec) *func([]byte, aper.DecodeState) (RetrieveUEInformationIEContainer, error) {
	return &v.decode
}
func BridgeRetrieveUEInformationIEContainerValueCodecFieldEncode(v *RetrieveUEInformationIEContainerValueCodec) *func(RetrieveUEInformationIEContainer, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeRetrieveUEInformationIEContainerValueCodecFieldPath(v *RetrieveUEInformationIEContainerValueCodec) *aper.Path {
	return &v.path
}
func BridgeRetrieveUEInformationIEContainerValueCodecMethodEncodeBudgetValue(v RetrieveUEInformationIEContainerValueCodec, a0 RetrieveUEInformationIEContainer, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeRetrieveUEInformationIEContainerValueCodecMethodEncodeChanged(v RetrieveUEInformationIEContainerValueCodec, a0 RetrieveUEInformationIEContainer, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeRetrieveUEInformationIEFieldAPERValueFieldContext(v *RetrieveUEInformationIEFieldAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeRetrieveUEInformationIEFieldAPERValueFieldReceived(v *RetrieveUEInformationIEFieldAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeRetrieveUEInformationIEFieldAPERValueFieldReplay(v *RetrieveUEInformationIEFieldAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeRetrieveUEInformationIEFieldAPERValueFieldWithoutReplay(v *RetrieveUEInformationIEFieldAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeRetrieveUEInformationIEFieldFieldReceived(v *RetrieveUEInformationIEField) *aper.CompletePadding {
	return &v.received
}
func BridgeRetrieveUEInformationIEFieldFieldReplay(v *RetrieveUEInformationIEField) *aper.Snapshot {
	return &v.replay
}
func BridgeRetrieveUEInformationIEFieldFieldStream(v *RetrieveUEInformationIEField) *aper.WireSpan {
	return &v.stream
}
func BridgeRetrieveUEInformationIEFieldFieldWithoutReplay(v *RetrieveUEInformationIEField) *bool {
	return &v.withoutReplay
}
func BridgeRetrieveUEInformationIEFieldMethodMarshalAPERTo(v *RetrieveUEInformationIEField, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeRetrieveUEInformationIEFieldMethodUnmarshalAPERFrom(v *RetrieveUEInformationIEField, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeRetrieveUEInformationIEFieldValueCodecFieldCapture(v *RetrieveUEInformationIEFieldValueCodec) *func(RetrieveUEInformationIEField, aper.DecodeState) (RetrieveUEInformationIEField, aper.Snapshot) {
	return &v.capture
}
func BridgeRetrieveUEInformationIEFieldValueCodecFieldCompare(v *RetrieveUEInformationIEFieldValueCodec) *func(RetrieveUEInformationIEField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeRetrieveUEInformationIEFieldValueCodecFieldContext(v *RetrieveUEInformationIEFieldValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeRetrieveUEInformationIEFieldValueCodecFieldDecode(v *RetrieveUEInformationIEFieldValueCodec) *func([]byte, aper.DecodeState) (RetrieveUEInformationIEField, error) {
	return &v.decode
}
func BridgeRetrieveUEInformationIEFieldValueCodecFieldEncode(v *RetrieveUEInformationIEFieldValueCodec) *func(RetrieveUEInformationIEField, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeRetrieveUEInformationIEFieldValueCodecFieldPath(v *RetrieveUEInformationIEFieldValueCodec) *aper.Path {
	return &v.path
}
func BridgeRetrieveUEInformationIEFieldValueCodecMethodEncodeBudgetValue(v RetrieveUEInformationIEFieldValueCodec, a0 RetrieveUEInformationIEField, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeRetrieveUEInformationIEFieldValueCodecMethodEncodeChanged(v RetrieveUEInformationIEFieldValueCodec, a0 RetrieveUEInformationIEField, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeRetrieveUEInformationIETableMethodInfoSTMSI(v RetrieveUEInformationIETable) s00.FieldInfo {
	return v.infoSTMSI()
}
func BridgeRetrieveUEInformationIEValueERABIEContainerListAPERValueFieldContext(v *RetrieveUEInformationIEValueERABIEContainerListAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeRetrieveUEInformationIEValueERABIEContainerListAPERValueFieldReceived(v *RetrieveUEInformationIEValueERABIEContainerListAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeRetrieveUEInformationIEValueERABIEContainerListAPERValueFieldReplay(v *RetrieveUEInformationIEValueERABIEContainerListAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeRetrieveUEInformationIEValueERABIEContainerListAPERValueFieldWithoutReplay(v *RetrieveUEInformationIEValueERABIEContainerListAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeRetrieveUEInformationIEValueERABIEContainerListValueCodecFieldCapture(v *RetrieveUEInformationIEValueERABIEContainerListValueCodec) *func(RetrieveUEInformationIEValueERABIEContainerList, aper.DecodeState) (RetrieveUEInformationIEValueERABIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgeRetrieveUEInformationIEValueERABIEContainerListValueCodecFieldCompare(v *RetrieveUEInformationIEValueERABIEContainerListValueCodec) *func(RetrieveUEInformationIEValueERABIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeRetrieveUEInformationIEValueERABIEContainerListValueCodecFieldContext(v *RetrieveUEInformationIEValueERABIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeRetrieveUEInformationIEValueERABIEContainerListValueCodecFieldDecode(v *RetrieveUEInformationIEValueERABIEContainerListValueCodec) *func([]byte, aper.DecodeState) (RetrieveUEInformationIEValueERABIEContainerList, error) {
	return &v.decode
}
func BridgeRetrieveUEInformationIEValueERABIEContainerListValueCodecFieldEncode(v *RetrieveUEInformationIEValueERABIEContainerListValueCodec) *func(RetrieveUEInformationIEValueERABIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeRetrieveUEInformationIEValueERABIEContainerListValueCodecFieldPath(v *RetrieveUEInformationIEValueERABIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgeRetrieveUEInformationIEValueERABIEContainerListValueCodecMethodEncodeBudgetValue(v RetrieveUEInformationIEValueERABIEContainerListValueCodec, a0 RetrieveUEInformationIEValueERABIEContainerList, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeRetrieveUEInformationIEValueERABIEContainerListValueCodecMethodEncodeChanged(v RetrieveUEInformationIEValueERABIEContainerListValueCodec, a0 RetrieveUEInformationIEValueERABIEContainerList, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeRetrieveUEInformationIEValueFieldId(v *RetrieveUEInformationIEValue) *s00.ProtocolIEID {
	return &v.id
}
func BridgeRetrieveUEInformationIEValueFieldIsOpaque(v *RetrieveUEInformationIEValue) *bool {
	return &v.isOpaque
}
func BridgeRetrieveUEInformationIEValueFieldOpaque(v *RetrieveUEInformationIEValue) *aper.OpaqueOpenType {
	return &v.opaque
}
func BridgeRetrieveUEInformationIEValueFieldReceived(v *RetrieveUEInformationIEValue) *aper.WireSpan {
	return &v.received
}
func BridgeRetrieveUEInformationIEValueFieldReplay(v *RetrieveUEInformationIEValue) *aper.Snapshot {
	return &v.replay
}
func BridgeRetrieveUEInformationIEValueFieldRowSTMSI(v *RetrieveUEInformationIEValue) **s27.STMSI {
	return &v.rowSTMSI
}
func BridgeRetrieveUEInformationIEValueMethodCaptureSemantics(v RetrieveUEInformationIEValue, a0 aper.SemanticCapture) RetrieveUEInformationIEValue {
	return v.captureSemantics(a0)
}
func BridgeRetrieveUEInformationIEValueMethodCompareSemantics(v RetrieveUEInformationIEValue, a0 aper.SemanticComparison) aper.SemanticComparison {
	return v.compareSemantics(a0)
}
func BridgeRetrieveUEInformationIEValueMethodDecode(v RetrieveUEInformationIEValue, a0 s00.ProtocolIEID, a1 aper.OpaqueOpenType) (RetrieveUEInformationIEValue, error) {
	return v.decode(a0, a1)
}
func BridgeRetrieveUEInformationIEValueMethodEncode(v RetrieveUEInformationIEValue) ([]byte, error) {
	return v.encode()
}
func BridgeRetrieveUEInformationIEValueMethodEncodeFresh(v RetrieveUEInformationIEValue, a0 bool, a1 *aper.DecodeBudget) ([]byte, error) {
	return v.encodeFresh(a0, a1)
}
func BridgeRetrieveUEInformationIEValueMethodMatchesID(v RetrieveUEInformationIEValue, a0 s00.ProtocolIEID, a1 ...*aper.DecodeBudget) bool {
	return v.matchesID(a0, a1...)
}
func BridgeRetrieveUEInformationIEValueMethodReason(v RetrieveUEInformationIEValue, a0 s00.ProtocolIEID) aper.OpaqueReason {
	return v.reason(a0)
}
func BridgeRetrieveUEInformationIEValueMethodRule(v RetrieveUEInformationIEValue) aper.SourceRule {
	return v.rule()
}
func BridgeRetrieveUEInformationIEValueProtocolErrorIEContainerListAPERValueFieldContext(v *RetrieveUEInformationIEValueProtocolErrorIEContainerListAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeRetrieveUEInformationIEValueProtocolErrorIEContainerListAPERValueFieldReceived(v *RetrieveUEInformationIEValueProtocolErrorIEContainerListAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeRetrieveUEInformationIEValueProtocolErrorIEContainerListAPERValueFieldReplay(v *RetrieveUEInformationIEValueProtocolErrorIEContainerListAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeRetrieveUEInformationIEValueProtocolErrorIEContainerListAPERValueFieldWithoutReplay(v *RetrieveUEInformationIEValueProtocolErrorIEContainerListAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeRetrieveUEInformationIEValueProtocolErrorIEContainerListValueCodecFieldCapture(v *RetrieveUEInformationIEValueProtocolErrorIEContainerListValueCodec) *func(RetrieveUEInformationIEValueProtocolErrorIEContainerList, aper.DecodeState) (RetrieveUEInformationIEValueProtocolErrorIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgeRetrieveUEInformationIEValueProtocolErrorIEContainerListValueCodecFieldCompare(v *RetrieveUEInformationIEValueProtocolErrorIEContainerListValueCodec) *func(RetrieveUEInformationIEValueProtocolErrorIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeRetrieveUEInformationIEValueProtocolErrorIEContainerListValueCodecFieldContext(v *RetrieveUEInformationIEValueProtocolErrorIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeRetrieveUEInformationIEValueProtocolErrorIEContainerListValueCodecFieldDecode(v *RetrieveUEInformationIEValueProtocolErrorIEContainerListValueCodec) *func([]byte, aper.DecodeState) (RetrieveUEInformationIEValueProtocolErrorIEContainerList, error) {
	return &v.decode
}
func BridgeRetrieveUEInformationIEValueProtocolErrorIEContainerListValueCodecFieldEncode(v *RetrieveUEInformationIEValueProtocolErrorIEContainerListValueCodec) *func(RetrieveUEInformationIEValueProtocolErrorIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeRetrieveUEInformationIEValueProtocolErrorIEContainerListValueCodecFieldPath(v *RetrieveUEInformationIEValueProtocolErrorIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgeRetrieveUEInformationIEValueProtocolErrorIEContainerListValueCodecMethodEncodeBudgetValue(v RetrieveUEInformationIEValueProtocolErrorIEContainerListValueCodec, a0 RetrieveUEInformationIEValueProtocolErrorIEContainerList, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeRetrieveUEInformationIEValueProtocolErrorIEContainerListValueCodecMethodEncodeChanged(v RetrieveUEInformationIEValueProtocolErrorIEContainerListValueCodec, a0 RetrieveUEInformationIEValueProtocolErrorIEContainerList, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeRetrieveUEInformationIEValueProtocolIEContainerListAPERValueFieldContext(v *RetrieveUEInformationIEValueProtocolIEContainerListAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeRetrieveUEInformationIEValueProtocolIEContainerListAPERValueFieldReceived(v *RetrieveUEInformationIEValueProtocolIEContainerListAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeRetrieveUEInformationIEValueProtocolIEContainerListAPERValueFieldReplay(v *RetrieveUEInformationIEValueProtocolIEContainerListAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeRetrieveUEInformationIEValueProtocolIEContainerListAPERValueFieldWithoutReplay(v *RetrieveUEInformationIEValueProtocolIEContainerListAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeRetrieveUEInformationIEValueProtocolIEContainerListValueCodecFieldCapture(v *RetrieveUEInformationIEValueProtocolIEContainerListValueCodec) *func(RetrieveUEInformationIEValueProtocolIEContainerList, aper.DecodeState) (RetrieveUEInformationIEValueProtocolIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgeRetrieveUEInformationIEValueProtocolIEContainerListValueCodecFieldCompare(v *RetrieveUEInformationIEValueProtocolIEContainerListValueCodec) *func(RetrieveUEInformationIEValueProtocolIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeRetrieveUEInformationIEValueProtocolIEContainerListValueCodecFieldContext(v *RetrieveUEInformationIEValueProtocolIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeRetrieveUEInformationIEValueProtocolIEContainerListValueCodecFieldDecode(v *RetrieveUEInformationIEValueProtocolIEContainerListValueCodec) *func([]byte, aper.DecodeState) (RetrieveUEInformationIEValueProtocolIEContainerList, error) {
	return &v.decode
}
func BridgeRetrieveUEInformationIEValueProtocolIEContainerListValueCodecFieldEncode(v *RetrieveUEInformationIEValueProtocolIEContainerListValueCodec) *func(RetrieveUEInformationIEValueProtocolIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeRetrieveUEInformationIEValueProtocolIEContainerListValueCodecFieldPath(v *RetrieveUEInformationIEValueProtocolIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgeRetrieveUEInformationIEValueProtocolIEContainerListValueCodecMethodEncodeBudgetValue(v RetrieveUEInformationIEValueProtocolIEContainerListValueCodec, a0 RetrieveUEInformationIEValueProtocolIEContainerList, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeRetrieveUEInformationIEValueProtocolIEContainerListValueCodecMethodEncodeChanged(v RetrieveUEInformationIEValueProtocolIEContainerListValueCodec, a0 RetrieveUEInformationIEValueProtocolIEContainerList, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeRetrieveUEInformationMethodMarshalAPERBudget(v *RetrieveUEInformation, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeRetrieveUEInformationMethodMarshalAPERBudgetValue(v *RetrieveUEInformation, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudgetValue(a0, a1)
}
func BridgeRetrieveUEInformationMethodMarshalAPERChanged(v *RetrieveUEInformation, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeRetrieveUEInformationMethodMarshalAPERChangedValue(v *RetrieveUEInformation, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeRetrieveUEInformationMethodMarshalAPERLegacy(v *RetrieveUEInformation) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeRetrieveUEInformationMethodMarshalAPERNewValue(v *RetrieveUEInformation, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERNewValue(a0, a1)
}
func BridgeRetrieveUEInformationMethodMarshalAPERPlanned(v *RetrieveUEInformation, a0 *aper.DecodeBudget, a1 bool, a2 *aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1, a2)
}
func BridgeRetrieveUEInformationMethodMarshalAPERTo(v *RetrieveUEInformation, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeRetrieveUEInformationMethodUnmarshalAPERFrom(v *RetrieveUEInformation, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeRetrieveUEInformationMethodUnmarshalAPERLegacy(v *RetrieveUEInformation, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeRetrieveUEInformationMethodUnmarshalAPERWithOptions(v *RetrieveUEInformation, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeRetrieveUEInformationSTMSIIEBindingFieldCodec(v *RetrieveUEInformationSTMSIIEBinding) *STMSIValueCodec {
	return &v.codec
}
func BridgeRetrieveUEInformationSTMSIIEBindingFieldGet(v *RetrieveUEInformationSTMSIIEBinding) *func(*RetrieveUEInformationIEValue) (*s27.STMSI, bool) {
	return &v.get
}
func BridgeRetrieveUEInformationSTMSIIEBindingFieldInfo(v *RetrieveUEInformationSTMSIIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeRetrieveUEInformationSTMSIIEBindingFieldInject(v *RetrieveUEInformationSTMSIIEBinding) *func(s27.STMSI) RetrieveUEInformationIEValue {
	return &v.inject
}
func BridgeRetrieveUEInformationValueCodecFieldCapture(v *RetrieveUEInformationValueCodec) *func(RetrieveUEInformation, aper.DecodeState) (RetrieveUEInformation, aper.Snapshot) {
	return &v.capture
}
func BridgeRetrieveUEInformationValueCodecFieldCompare(v *RetrieveUEInformationValueCodec) *func(RetrieveUEInformation, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeRetrieveUEInformationValueCodecFieldContext(v *RetrieveUEInformationValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeRetrieveUEInformationValueCodecFieldDecode(v *RetrieveUEInformationValueCodec) *func([]byte, aper.DecodeState) (RetrieveUEInformation, error) {
	return &v.decode
}
func BridgeRetrieveUEInformationValueCodecFieldEncode(v *RetrieveUEInformationValueCodec) *func(RetrieveUEInformation, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeRetrieveUEInformationValueCodecFieldPath(v *RetrieveUEInformationValueCodec) *aper.Path {
	return &v.path
}
func BridgeRetrieveUEInformationValueCodecMethodEncodeBudgetValue(v RetrieveUEInformationValueCodec, a0 RetrieveUEInformation, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeRetrieveUEInformationValueCodecMethodEncodeChanged(v RetrieveUEInformationValueCodec, a0 RetrieveUEInformation, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeSTMSIAPERValueFieldContext(v *STMSIAPERValue) *s00.BridgeCodecContext { return &v.context }
func BridgeSTMSIAPERValueFieldReceived(v *STMSIAPERValue) *aper.WireSpan         { return &v.received }
func BridgeSTMSIAPERValueFieldReplay(v *STMSIAPERValue) *aper.Snapshot           { return &v.replay }
func BridgeSTMSIAPERValueFieldWithoutReplay(v *STMSIAPERValue) *bool             { return &v.withoutReplay }
func BridgeSTMSIValueCodecFieldCapture(v *STMSIValueCodec) *func(s27.STMSI, aper.DecodeState) (s27.STMSI, aper.Snapshot) {
	return &v.capture
}
func BridgeSTMSIValueCodecFieldCompare(v *STMSIValueCodec) *func(s27.STMSI, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeSTMSIValueCodecFieldContext(v *STMSIValueCodec) *s00.BridgeCodecContext { return &v.context }
func BridgeSTMSIValueCodecFieldDecode(v *STMSIValueCodec) *func([]byte, aper.DecodeState) (s27.STMSI, error) {
	return &v.decode
}
func BridgeSTMSIValueCodecFieldEncode(v *STMSIValueCodec) *func(s27.STMSI, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeSTMSIValueCodecFieldPath(v *STMSIValueCodec) *aper.Path { return &v.path }
func BridgeSTMSIValueCodecMethodEncodeBudgetValue(v STMSIValueCodec, a0 s27.STMSI, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeSTMSIValueCodecMethodEncodeChanged(v STMSIValueCodec, a0 s27.STMSI, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeScheduledCommunicationTimeAPERValueFieldContext(v *ScheduledCommunicationTimeAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeScheduledCommunicationTimeAPERValueFieldReceived(v *ScheduledCommunicationTimeAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeScheduledCommunicationTimeAPERValueFieldReplay(v *ScheduledCommunicationTimeAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeScheduledCommunicationTimeAPERValueFieldWithoutReplay(v *ScheduledCommunicationTimeAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeScheduledCommunicationTimeFieldExtCount(v *ScheduledCommunicationTime) *int64 {
	return &v.extCount
}
func BridgeScheduledCommunicationTimeFieldExtData(v *ScheduledCommunicationTime) *[][]byte {
	return &v.extData
}
func BridgeScheduledCommunicationTimeFieldExtOrigin(v *ScheduledCommunicationTime) *[]aper.OpaqueOrigin {
	return &v.extOrigin
}
func BridgeScheduledCommunicationTimeFieldExtPresent(v *ScheduledCommunicationTime) *[]bool {
	return &v.extPresent
}
func BridgeScheduledCommunicationTimeFieldExtWire(v *ScheduledCommunicationTime) *[]aper.WireSpan {
	return &v.extWire
}
func BridgeScheduledCommunicationTimeFieldIEExtensionsIndef(v *ScheduledCommunicationTime) *bool {
	return &v.iEExtensionsIndef
}
func BridgeScheduledCommunicationTimeFieldPerExtPadding(v *ScheduledCommunicationTime) *[]aper.CompletePadding {
	return &v.perExtPadding
}
func BridgeScheduledCommunicationTimeFieldPerPadding(v *ScheduledCommunicationTime) *aper.FinalPadding {
	return &v.perPadding
}
func BridgeScheduledCommunicationTimeFieldReceived(v *ScheduledCommunicationTime) *bool {
	return &v.received
}
func BridgeScheduledCommunicationTimeFieldReceivedAbsolute(v *ScheduledCommunicationTime) *bool {
	return &v.receivedAbsolute
}
func BridgeScheduledCommunicationTimeFieldReceivedBytes(v *ScheduledCommunicationTime) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeScheduledCommunicationTimeFieldReceivedLocation(v *ScheduledCommunicationTime) *aper.Location {
	return &v.receivedLocation
}
func BridgeScheduledCommunicationTimeFieldReplay(v *ScheduledCommunicationTime) *aper.Snapshot {
	return &v.replay
}
func BridgeScheduledCommunicationTimeFieldStream(v *ScheduledCommunicationTime) *aper.WireSpan {
	return &v.stream
}
func BridgeScheduledCommunicationTimeFieldWithoutReplay(v *ScheduledCommunicationTime) *bool {
	return &v.withoutReplay
}
func BridgeScheduledCommunicationTimeMethodMarshalAPERBudget(v *ScheduledCommunicationTime, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeScheduledCommunicationTimeMethodMarshalAPERBudgetValue(v *ScheduledCommunicationTime, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudgetValue(a0, a1)
}
func BridgeScheduledCommunicationTimeMethodMarshalAPERChanged(v *ScheduledCommunicationTime, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeScheduledCommunicationTimeMethodMarshalAPERChangedValue(v *ScheduledCommunicationTime, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeScheduledCommunicationTimeMethodMarshalAPERLegacy(v *ScheduledCommunicationTime) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeScheduledCommunicationTimeMethodMarshalAPERNewValue(v *ScheduledCommunicationTime, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERNewValue(a0, a1)
}
func BridgeScheduledCommunicationTimeMethodMarshalAPERPlanned(v *ScheduledCommunicationTime, a0 *aper.DecodeBudget, a1 bool, a2 *aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1, a2)
}
func BridgeScheduledCommunicationTimeMethodMarshalAPERTo(v *ScheduledCommunicationTime, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeScheduledCommunicationTimeMethodUnmarshalAPERFrom(v *ScheduledCommunicationTime, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeScheduledCommunicationTimeMethodUnmarshalAPERLegacy(v *ScheduledCommunicationTime, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeScheduledCommunicationTimeMethodUnmarshalAPERWithOptions(v *ScheduledCommunicationTime, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeScheduledCommunicationTimeValueCodecFieldCapture(v *ScheduledCommunicationTimeValueCodec) *func(ScheduledCommunicationTime, aper.DecodeState) (ScheduledCommunicationTime, aper.Snapshot) {
	return &v.capture
}
func BridgeScheduledCommunicationTimeValueCodecFieldCompare(v *ScheduledCommunicationTimeValueCodec) *func(ScheduledCommunicationTime, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeScheduledCommunicationTimeValueCodecFieldContext(v *ScheduledCommunicationTimeValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeScheduledCommunicationTimeValueCodecFieldDecode(v *ScheduledCommunicationTimeValueCodec) *func([]byte, aper.DecodeState) (ScheduledCommunicationTime, error) {
	return &v.decode
}
func BridgeScheduledCommunicationTimeValueCodecFieldEncode(v *ScheduledCommunicationTimeValueCodec) *func(ScheduledCommunicationTime, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeScheduledCommunicationTimeValueCodecFieldPath(v *ScheduledCommunicationTimeValueCodec) *aper.Path {
	return &v.path
}
func BridgeScheduledCommunicationTimeValueCodecMethodEncodeBudgetValue(v ScheduledCommunicationTimeValueCodec, a0 ScheduledCommunicationTime, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeScheduledCommunicationTimeValueCodecMethodEncodeChanged(v ScheduledCommunicationTimeValueCodec, a0 ScheduledCommunicationTime, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeSecondaryRATDataUsageReportItemAPERValueFieldContext(v *SecondaryRATDataUsageReportItemAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeSecondaryRATDataUsageReportItemAPERValueFieldReceived(v *SecondaryRATDataUsageReportItemAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeSecondaryRATDataUsageReportItemAPERValueFieldReplay(v *SecondaryRATDataUsageReportItemAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeSecondaryRATDataUsageReportItemAPERValueFieldWithoutReplay(v *SecondaryRATDataUsageReportItemAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeSecondaryRATDataUsageReportItemFieldERABUsageReportListIndef(v *SecondaryRATDataUsageReportItem) *bool {
	return &v.eRABUsageReportListIndef
}
func BridgeSecondaryRATDataUsageReportItemFieldExtCount(v *SecondaryRATDataUsageReportItem) *int64 {
	return &v.extCount
}
func BridgeSecondaryRATDataUsageReportItemFieldExtData(v *SecondaryRATDataUsageReportItem) *[][]byte {
	return &v.extData
}
func BridgeSecondaryRATDataUsageReportItemFieldExtOrigin(v *SecondaryRATDataUsageReportItem) *[]aper.OpaqueOrigin {
	return &v.extOrigin
}
func BridgeSecondaryRATDataUsageReportItemFieldExtPresent(v *SecondaryRATDataUsageReportItem) *[]bool {
	return &v.extPresent
}
func BridgeSecondaryRATDataUsageReportItemFieldExtWire(v *SecondaryRATDataUsageReportItem) *[]aper.WireSpan {
	return &v.extWire
}
func BridgeSecondaryRATDataUsageReportItemFieldIEExtensionsIndef(v *SecondaryRATDataUsageReportItem) *bool {
	return &v.iEExtensionsIndef
}
func BridgeSecondaryRATDataUsageReportItemFieldPerExtPadding(v *SecondaryRATDataUsageReportItem) *[]aper.CompletePadding {
	return &v.perExtPadding
}
func BridgeSecondaryRATDataUsageReportItemFieldPerPadding(v *SecondaryRATDataUsageReportItem) *aper.FinalPadding {
	return &v.perPadding
}
func BridgeSecondaryRATDataUsageReportItemFieldReceived(v *SecondaryRATDataUsageReportItem) *bool {
	return &v.received
}
func BridgeSecondaryRATDataUsageReportItemFieldReceivedAbsolute(v *SecondaryRATDataUsageReportItem) *bool {
	return &v.receivedAbsolute
}
func BridgeSecondaryRATDataUsageReportItemFieldReceivedBytes(v *SecondaryRATDataUsageReportItem) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeSecondaryRATDataUsageReportItemFieldReceivedLocation(v *SecondaryRATDataUsageReportItem) *aper.Location {
	return &v.receivedLocation
}
func BridgeSecondaryRATDataUsageReportItemFieldReplay(v *SecondaryRATDataUsageReportItem) *aper.Snapshot {
	return &v.replay
}
func BridgeSecondaryRATDataUsageReportItemFieldStream(v *SecondaryRATDataUsageReportItem) *aper.WireSpan {
	return &v.stream
}
func BridgeSecondaryRATDataUsageReportItemFieldWithoutReplay(v *SecondaryRATDataUsageReportItem) *bool {
	return &v.withoutReplay
}
func BridgeSecondaryRATDataUsageReportItemIEContainerAPERValueFieldContext(v *SecondaryRATDataUsageReportItemIEContainerAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeSecondaryRATDataUsageReportItemIEContainerAPERValueFieldReceived(v *SecondaryRATDataUsageReportItemIEContainerAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeSecondaryRATDataUsageReportItemIEContainerAPERValueFieldReplay(v *SecondaryRATDataUsageReportItemIEContainerAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeSecondaryRATDataUsageReportItemIEContainerAPERValueFieldWithoutReplay(v *SecondaryRATDataUsageReportItemIEContainerAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeSecondaryRATDataUsageReportItemIEContainerValueCodecFieldCapture(v *SecondaryRATDataUsageReportItemIEContainerValueCodec) *func(SecondaryRATDataUsageReportItemIEContainer, aper.DecodeState) (SecondaryRATDataUsageReportItemIEContainer, aper.Snapshot) {
	return &v.capture
}
func BridgeSecondaryRATDataUsageReportItemIEContainerValueCodecFieldCompare(v *SecondaryRATDataUsageReportItemIEContainerValueCodec) *func(SecondaryRATDataUsageReportItemIEContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeSecondaryRATDataUsageReportItemIEContainerValueCodecFieldContext(v *SecondaryRATDataUsageReportItemIEContainerValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeSecondaryRATDataUsageReportItemIEContainerValueCodecFieldDecode(v *SecondaryRATDataUsageReportItemIEContainerValueCodec) *func([]byte, aper.DecodeState) (SecondaryRATDataUsageReportItemIEContainer, error) {
	return &v.decode
}
func BridgeSecondaryRATDataUsageReportItemIEContainerValueCodecFieldEncode(v *SecondaryRATDataUsageReportItemIEContainerValueCodec) *func(SecondaryRATDataUsageReportItemIEContainer, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeSecondaryRATDataUsageReportItemIEContainerValueCodecFieldPath(v *SecondaryRATDataUsageReportItemIEContainerValueCodec) *aper.Path {
	return &v.path
}
func BridgeSecondaryRATDataUsageReportItemIEContainerValueCodecMethodEncodeBudgetValue(v SecondaryRATDataUsageReportItemIEContainerValueCodec, a0 SecondaryRATDataUsageReportItemIEContainer, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeSecondaryRATDataUsageReportItemIEContainerValueCodecMethodEncodeChanged(v SecondaryRATDataUsageReportItemIEContainerValueCodec, a0 SecondaryRATDataUsageReportItemIEContainer, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeSecondaryRATDataUsageReportItemIEFieldAPERValueFieldContext(v *SecondaryRATDataUsageReportItemIEFieldAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeSecondaryRATDataUsageReportItemIEFieldAPERValueFieldReceived(v *SecondaryRATDataUsageReportItemIEFieldAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeSecondaryRATDataUsageReportItemIEFieldAPERValueFieldReplay(v *SecondaryRATDataUsageReportItemIEFieldAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeSecondaryRATDataUsageReportItemIEFieldAPERValueFieldWithoutReplay(v *SecondaryRATDataUsageReportItemIEFieldAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeSecondaryRATDataUsageReportItemIEFieldFieldReceived(v *SecondaryRATDataUsageReportItemIEField) *aper.CompletePadding {
	return &v.received
}
func BridgeSecondaryRATDataUsageReportItemIEFieldFieldReplay(v *SecondaryRATDataUsageReportItemIEField) *aper.Snapshot {
	return &v.replay
}
func BridgeSecondaryRATDataUsageReportItemIEFieldFieldStream(v *SecondaryRATDataUsageReportItemIEField) *aper.WireSpan {
	return &v.stream
}
func BridgeSecondaryRATDataUsageReportItemIEFieldFieldWithoutReplay(v *SecondaryRATDataUsageReportItemIEField) *bool {
	return &v.withoutReplay
}
func BridgeSecondaryRATDataUsageReportItemIEFieldMethodMarshalAPERTo(v *SecondaryRATDataUsageReportItemIEField, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeSecondaryRATDataUsageReportItemIEFieldMethodUnmarshalAPERFrom(v *SecondaryRATDataUsageReportItemIEField, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeSecondaryRATDataUsageReportItemIEFieldValueCodecFieldCapture(v *SecondaryRATDataUsageReportItemIEFieldValueCodec) *func(SecondaryRATDataUsageReportItemIEField, aper.DecodeState) (SecondaryRATDataUsageReportItemIEField, aper.Snapshot) {
	return &v.capture
}
func BridgeSecondaryRATDataUsageReportItemIEFieldValueCodecFieldCompare(v *SecondaryRATDataUsageReportItemIEFieldValueCodec) *func(SecondaryRATDataUsageReportItemIEField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeSecondaryRATDataUsageReportItemIEFieldValueCodecFieldContext(v *SecondaryRATDataUsageReportItemIEFieldValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeSecondaryRATDataUsageReportItemIEFieldValueCodecFieldDecode(v *SecondaryRATDataUsageReportItemIEFieldValueCodec) *func([]byte, aper.DecodeState) (SecondaryRATDataUsageReportItemIEField, error) {
	return &v.decode
}
func BridgeSecondaryRATDataUsageReportItemIEFieldValueCodecFieldEncode(v *SecondaryRATDataUsageReportItemIEFieldValueCodec) *func(SecondaryRATDataUsageReportItemIEField, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeSecondaryRATDataUsageReportItemIEFieldValueCodecFieldPath(v *SecondaryRATDataUsageReportItemIEFieldValueCodec) *aper.Path {
	return &v.path
}
func BridgeSecondaryRATDataUsageReportItemIEFieldValueCodecMethodEncodeBudgetValue(v SecondaryRATDataUsageReportItemIEFieldValueCodec, a0 SecondaryRATDataUsageReportItemIEField, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeSecondaryRATDataUsageReportItemIEFieldValueCodecMethodEncodeChanged(v SecondaryRATDataUsageReportItemIEFieldValueCodec, a0 SecondaryRATDataUsageReportItemIEField, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeSecondaryRATDataUsageReportItemIETableMethodInfoSecondaryRATDataUsageReportItem(v SecondaryRATDataUsageReportItemIETable) s00.FieldInfo {
	return v.infoSecondaryRATDataUsageReportItem()
}
func BridgeSecondaryRATDataUsageReportItemIEValueERABIEContainerListAPERValueFieldContext(v *SecondaryRATDataUsageReportItemIEValueERABIEContainerListAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeSecondaryRATDataUsageReportItemIEValueERABIEContainerListAPERValueFieldReceived(v *SecondaryRATDataUsageReportItemIEValueERABIEContainerListAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeSecondaryRATDataUsageReportItemIEValueERABIEContainerListAPERValueFieldReplay(v *SecondaryRATDataUsageReportItemIEValueERABIEContainerListAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeSecondaryRATDataUsageReportItemIEValueERABIEContainerListAPERValueFieldWithoutReplay(v *SecondaryRATDataUsageReportItemIEValueERABIEContainerListAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeSecondaryRATDataUsageReportItemIEValueERABIEContainerListValueCodecFieldCapture(v *SecondaryRATDataUsageReportItemIEValueERABIEContainerListValueCodec) *func(SecondaryRATDataUsageReportItemIEValueERABIEContainerList, aper.DecodeState) (SecondaryRATDataUsageReportItemIEValueERABIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgeSecondaryRATDataUsageReportItemIEValueERABIEContainerListValueCodecFieldCompare(v *SecondaryRATDataUsageReportItemIEValueERABIEContainerListValueCodec) *func(SecondaryRATDataUsageReportItemIEValueERABIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeSecondaryRATDataUsageReportItemIEValueERABIEContainerListValueCodecFieldContext(v *SecondaryRATDataUsageReportItemIEValueERABIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeSecondaryRATDataUsageReportItemIEValueERABIEContainerListValueCodecFieldDecode(v *SecondaryRATDataUsageReportItemIEValueERABIEContainerListValueCodec) *func([]byte, aper.DecodeState) (SecondaryRATDataUsageReportItemIEValueERABIEContainerList, error) {
	return &v.decode
}
func BridgeSecondaryRATDataUsageReportItemIEValueERABIEContainerListValueCodecFieldEncode(v *SecondaryRATDataUsageReportItemIEValueERABIEContainerListValueCodec) *func(SecondaryRATDataUsageReportItemIEValueERABIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeSecondaryRATDataUsageReportItemIEValueERABIEContainerListValueCodecFieldPath(v *SecondaryRATDataUsageReportItemIEValueERABIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgeSecondaryRATDataUsageReportItemIEValueERABIEContainerListValueCodecMethodEncodeBudgetValue(v SecondaryRATDataUsageReportItemIEValueERABIEContainerListValueCodec, a0 SecondaryRATDataUsageReportItemIEValueERABIEContainerList, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeSecondaryRATDataUsageReportItemIEValueERABIEContainerListValueCodecMethodEncodeChanged(v SecondaryRATDataUsageReportItemIEValueERABIEContainerListValueCodec, a0 SecondaryRATDataUsageReportItemIEValueERABIEContainerList, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeSecondaryRATDataUsageReportItemIEValueFieldId(v *SecondaryRATDataUsageReportItemIEValue) *s00.ProtocolIEID {
	return &v.id
}
func BridgeSecondaryRATDataUsageReportItemIEValueFieldIsOpaque(v *SecondaryRATDataUsageReportItemIEValue) *bool {
	return &v.isOpaque
}
func BridgeSecondaryRATDataUsageReportItemIEValueFieldOpaque(v *SecondaryRATDataUsageReportItemIEValue) *aper.OpaqueOpenType {
	return &v.opaque
}
func BridgeSecondaryRATDataUsageReportItemIEValueFieldReceived(v *SecondaryRATDataUsageReportItemIEValue) *aper.WireSpan {
	return &v.received
}
func BridgeSecondaryRATDataUsageReportItemIEValueFieldReplay(v *SecondaryRATDataUsageReportItemIEValue) *aper.Snapshot {
	return &v.replay
}
func BridgeSecondaryRATDataUsageReportItemIEValueFieldRowSecondaryRATDataUsageReportItem(v *SecondaryRATDataUsageReportItemIEValue) **SecondaryRATDataUsageReportItem {
	return &v.rowSecondaryRATDataUsageReportItem
}
func BridgeSecondaryRATDataUsageReportItemIEValueMethodCaptureSemantics(v SecondaryRATDataUsageReportItemIEValue, a0 aper.SemanticCapture) SecondaryRATDataUsageReportItemIEValue {
	return v.captureSemantics(a0)
}
func BridgeSecondaryRATDataUsageReportItemIEValueMethodCompareSemantics(v SecondaryRATDataUsageReportItemIEValue, a0 aper.SemanticComparison) aper.SemanticComparison {
	return v.compareSemantics(a0)
}
func BridgeSecondaryRATDataUsageReportItemIEValueMethodDecode(v SecondaryRATDataUsageReportItemIEValue, a0 s00.ProtocolIEID, a1 aper.OpaqueOpenType) (SecondaryRATDataUsageReportItemIEValue, error) {
	return v.decode(a0, a1)
}
func BridgeSecondaryRATDataUsageReportItemIEValueMethodEncode(v SecondaryRATDataUsageReportItemIEValue) ([]byte, error) {
	return v.encode()
}
func BridgeSecondaryRATDataUsageReportItemIEValueMethodEncodeFresh(v SecondaryRATDataUsageReportItemIEValue, a0 bool, a1 *aper.DecodeBudget) ([]byte, error) {
	return v.encodeFresh(a0, a1)
}
func BridgeSecondaryRATDataUsageReportItemIEValueMethodMatchesID(v SecondaryRATDataUsageReportItemIEValue, a0 s00.ProtocolIEID, a1 ...*aper.DecodeBudget) bool {
	return v.matchesID(a0, a1...)
}
func BridgeSecondaryRATDataUsageReportItemIEValueMethodReason(v SecondaryRATDataUsageReportItemIEValue, a0 s00.ProtocolIEID) aper.OpaqueReason {
	return v.reason(a0)
}
func BridgeSecondaryRATDataUsageReportItemIEValueMethodRule(v SecondaryRATDataUsageReportItemIEValue) aper.SourceRule {
	return v.rule()
}
func BridgeSecondaryRATDataUsageReportItemIEValueProtocolErrorIEContainerListAPERValueFieldContext(v *SecondaryRATDataUsageReportItemIEValueProtocolErrorIEContainerListAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeSecondaryRATDataUsageReportItemIEValueProtocolErrorIEContainerListAPERValueFieldReceived(v *SecondaryRATDataUsageReportItemIEValueProtocolErrorIEContainerListAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeSecondaryRATDataUsageReportItemIEValueProtocolErrorIEContainerListAPERValueFieldReplay(v *SecondaryRATDataUsageReportItemIEValueProtocolErrorIEContainerListAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeSecondaryRATDataUsageReportItemIEValueProtocolErrorIEContainerListAPERValueFieldWithoutReplay(v *SecondaryRATDataUsageReportItemIEValueProtocolErrorIEContainerListAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeSecondaryRATDataUsageReportItemIEValueProtocolErrorIEContainerListValueCodecFieldCapture(v *SecondaryRATDataUsageReportItemIEValueProtocolErrorIEContainerListValueCodec) *func(SecondaryRATDataUsageReportItemIEValueProtocolErrorIEContainerList, aper.DecodeState) (SecondaryRATDataUsageReportItemIEValueProtocolErrorIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgeSecondaryRATDataUsageReportItemIEValueProtocolErrorIEContainerListValueCodecFieldCompare(v *SecondaryRATDataUsageReportItemIEValueProtocolErrorIEContainerListValueCodec) *func(SecondaryRATDataUsageReportItemIEValueProtocolErrorIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeSecondaryRATDataUsageReportItemIEValueProtocolErrorIEContainerListValueCodecFieldContext(v *SecondaryRATDataUsageReportItemIEValueProtocolErrorIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeSecondaryRATDataUsageReportItemIEValueProtocolErrorIEContainerListValueCodecFieldDecode(v *SecondaryRATDataUsageReportItemIEValueProtocolErrorIEContainerListValueCodec) *func([]byte, aper.DecodeState) (SecondaryRATDataUsageReportItemIEValueProtocolErrorIEContainerList, error) {
	return &v.decode
}
func BridgeSecondaryRATDataUsageReportItemIEValueProtocolErrorIEContainerListValueCodecFieldEncode(v *SecondaryRATDataUsageReportItemIEValueProtocolErrorIEContainerListValueCodec) *func(SecondaryRATDataUsageReportItemIEValueProtocolErrorIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeSecondaryRATDataUsageReportItemIEValueProtocolErrorIEContainerListValueCodecFieldPath(v *SecondaryRATDataUsageReportItemIEValueProtocolErrorIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgeSecondaryRATDataUsageReportItemIEValueProtocolErrorIEContainerListValueCodecMethodEncodeBudgetValue(v SecondaryRATDataUsageReportItemIEValueProtocolErrorIEContainerListValueCodec, a0 SecondaryRATDataUsageReportItemIEValueProtocolErrorIEContainerList, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeSecondaryRATDataUsageReportItemIEValueProtocolErrorIEContainerListValueCodecMethodEncodeChanged(v SecondaryRATDataUsageReportItemIEValueProtocolErrorIEContainerListValueCodec, a0 SecondaryRATDataUsageReportItemIEValueProtocolErrorIEContainerList, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeSecondaryRATDataUsageReportItemIEValueProtocolIEContainerListAPERValueFieldContext(v *SecondaryRATDataUsageReportItemIEValueProtocolIEContainerListAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeSecondaryRATDataUsageReportItemIEValueProtocolIEContainerListAPERValueFieldReceived(v *SecondaryRATDataUsageReportItemIEValueProtocolIEContainerListAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeSecondaryRATDataUsageReportItemIEValueProtocolIEContainerListAPERValueFieldReplay(v *SecondaryRATDataUsageReportItemIEValueProtocolIEContainerListAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeSecondaryRATDataUsageReportItemIEValueProtocolIEContainerListAPERValueFieldWithoutReplay(v *SecondaryRATDataUsageReportItemIEValueProtocolIEContainerListAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeSecondaryRATDataUsageReportItemIEValueProtocolIEContainerListValueCodecFieldCapture(v *SecondaryRATDataUsageReportItemIEValueProtocolIEContainerListValueCodec) *func(SecondaryRATDataUsageReportItemIEValueProtocolIEContainerList, aper.DecodeState) (SecondaryRATDataUsageReportItemIEValueProtocolIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgeSecondaryRATDataUsageReportItemIEValueProtocolIEContainerListValueCodecFieldCompare(v *SecondaryRATDataUsageReportItemIEValueProtocolIEContainerListValueCodec) *func(SecondaryRATDataUsageReportItemIEValueProtocolIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeSecondaryRATDataUsageReportItemIEValueProtocolIEContainerListValueCodecFieldContext(v *SecondaryRATDataUsageReportItemIEValueProtocolIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeSecondaryRATDataUsageReportItemIEValueProtocolIEContainerListValueCodecFieldDecode(v *SecondaryRATDataUsageReportItemIEValueProtocolIEContainerListValueCodec) *func([]byte, aper.DecodeState) (SecondaryRATDataUsageReportItemIEValueProtocolIEContainerList, error) {
	return &v.decode
}
func BridgeSecondaryRATDataUsageReportItemIEValueProtocolIEContainerListValueCodecFieldEncode(v *SecondaryRATDataUsageReportItemIEValueProtocolIEContainerListValueCodec) *func(SecondaryRATDataUsageReportItemIEValueProtocolIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeSecondaryRATDataUsageReportItemIEValueProtocolIEContainerListValueCodecFieldPath(v *SecondaryRATDataUsageReportItemIEValueProtocolIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgeSecondaryRATDataUsageReportItemIEValueProtocolIEContainerListValueCodecMethodEncodeBudgetValue(v SecondaryRATDataUsageReportItemIEValueProtocolIEContainerListValueCodec, a0 SecondaryRATDataUsageReportItemIEValueProtocolIEContainerList, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeSecondaryRATDataUsageReportItemIEValueProtocolIEContainerListValueCodecMethodEncodeChanged(v SecondaryRATDataUsageReportItemIEValueProtocolIEContainerListValueCodec, a0 SecondaryRATDataUsageReportItemIEValueProtocolIEContainerList, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeSecondaryRATDataUsageReportItemMethodMarshalAPERBudget(v *SecondaryRATDataUsageReportItem, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeSecondaryRATDataUsageReportItemMethodMarshalAPERBudgetValue(v *SecondaryRATDataUsageReportItem, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudgetValue(a0, a1)
}
func BridgeSecondaryRATDataUsageReportItemMethodMarshalAPERChanged(v *SecondaryRATDataUsageReportItem, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeSecondaryRATDataUsageReportItemMethodMarshalAPERChangedValue(v *SecondaryRATDataUsageReportItem, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeSecondaryRATDataUsageReportItemMethodMarshalAPERLegacy(v *SecondaryRATDataUsageReportItem) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeSecondaryRATDataUsageReportItemMethodMarshalAPERNewValue(v *SecondaryRATDataUsageReportItem, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERNewValue(a0, a1)
}
func BridgeSecondaryRATDataUsageReportItemMethodMarshalAPERPlanned(v *SecondaryRATDataUsageReportItem, a0 *aper.DecodeBudget, a1 bool, a2 *aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1, a2)
}
func BridgeSecondaryRATDataUsageReportItemMethodMarshalAPERTo(v *SecondaryRATDataUsageReportItem, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeSecondaryRATDataUsageReportItemMethodUnmarshalAPERFrom(v *SecondaryRATDataUsageReportItem, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeSecondaryRATDataUsageReportItemMethodUnmarshalAPERLegacy(v *SecondaryRATDataUsageReportItem, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeSecondaryRATDataUsageReportItemMethodUnmarshalAPERWithOptions(v *SecondaryRATDataUsageReportItem, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeSecondaryRATDataUsageReportItemSecondaryRATDataUsageReportItemIEBindingFieldCodec(v *SecondaryRATDataUsageReportItemSecondaryRATDataUsageReportItemIEBinding) *SecondaryRATDataUsageReportItemValueCodec {
	return &v.codec
}
func BridgeSecondaryRATDataUsageReportItemSecondaryRATDataUsageReportItemIEBindingFieldGet(v *SecondaryRATDataUsageReportItemSecondaryRATDataUsageReportItemIEBinding) *func(*SecondaryRATDataUsageReportItemIEValue) (*SecondaryRATDataUsageReportItem, bool) {
	return &v.get
}
func BridgeSecondaryRATDataUsageReportItemSecondaryRATDataUsageReportItemIEBindingFieldInfo(v *SecondaryRATDataUsageReportItemSecondaryRATDataUsageReportItemIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeSecondaryRATDataUsageReportItemSecondaryRATDataUsageReportItemIEBindingFieldInject(v *SecondaryRATDataUsageReportItemSecondaryRATDataUsageReportItemIEBinding) *func(SecondaryRATDataUsageReportItem) SecondaryRATDataUsageReportItemIEValue {
	return &v.inject
}
func BridgeSecondaryRATDataUsageReportItemValueCodecFieldCapture(v *SecondaryRATDataUsageReportItemValueCodec) *func(SecondaryRATDataUsageReportItem, aper.DecodeState) (SecondaryRATDataUsageReportItem, aper.Snapshot) {
	return &v.capture
}
func BridgeSecondaryRATDataUsageReportItemValueCodecFieldCompare(v *SecondaryRATDataUsageReportItemValueCodec) *func(SecondaryRATDataUsageReportItem, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeSecondaryRATDataUsageReportItemValueCodecFieldContext(v *SecondaryRATDataUsageReportItemValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeSecondaryRATDataUsageReportItemValueCodecFieldDecode(v *SecondaryRATDataUsageReportItemValueCodec) *func([]byte, aper.DecodeState) (SecondaryRATDataUsageReportItem, error) {
	return &v.decode
}
func BridgeSecondaryRATDataUsageReportItemValueCodecFieldEncode(v *SecondaryRATDataUsageReportItemValueCodec) *func(SecondaryRATDataUsageReportItem, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeSecondaryRATDataUsageReportItemValueCodecFieldPath(v *SecondaryRATDataUsageReportItemValueCodec) *aper.Path {
	return &v.path
}
func BridgeSecondaryRATDataUsageReportItemValueCodecMethodEncodeBudgetValue(v SecondaryRATDataUsageReportItemValueCodec, a0 SecondaryRATDataUsageReportItem, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeSecondaryRATDataUsageReportItemValueCodecMethodEncodeChanged(v SecondaryRATDataUsageReportItemValueCodec, a0 SecondaryRATDataUsageReportItem, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeSecondaryRATDataUsageReportListAPERValueFieldContext(v *SecondaryRATDataUsageReportListAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeSecondaryRATDataUsageReportListAPERValueFieldReceived(v *SecondaryRATDataUsageReportListAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeSecondaryRATDataUsageReportListAPERValueFieldReplay(v *SecondaryRATDataUsageReportListAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeSecondaryRATDataUsageReportListAPERValueFieldWithoutReplay(v *SecondaryRATDataUsageReportListAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeSecondaryRATDataUsageReportListValueCodecFieldCapture(v *SecondaryRATDataUsageReportListValueCodec) *func(SecondaryRATDataUsageReportList, aper.DecodeState) (SecondaryRATDataUsageReportList, aper.Snapshot) {
	return &v.capture
}
func BridgeSecondaryRATDataUsageReportListValueCodecFieldCompare(v *SecondaryRATDataUsageReportListValueCodec) *func(SecondaryRATDataUsageReportList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeSecondaryRATDataUsageReportListValueCodecFieldContext(v *SecondaryRATDataUsageReportListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeSecondaryRATDataUsageReportListValueCodecFieldDecode(v *SecondaryRATDataUsageReportListValueCodec) *func([]byte, aper.DecodeState) (SecondaryRATDataUsageReportList, error) {
	return &v.decode
}
func BridgeSecondaryRATDataUsageReportListValueCodecFieldEncode(v *SecondaryRATDataUsageReportListValueCodec) *func(SecondaryRATDataUsageReportList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeSecondaryRATDataUsageReportListValueCodecFieldPath(v *SecondaryRATDataUsageReportListValueCodec) *aper.Path {
	return &v.path
}
func BridgeSecondaryRATDataUsageReportListValueCodecMethodEncodeBudgetValue(v SecondaryRATDataUsageReportListValueCodec, a0 SecondaryRATDataUsageReportList, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeSecondaryRATDataUsageReportListValueCodecMethodEncodeChanged(v SecondaryRATDataUsageReportListValueCodec, a0 SecondaryRATDataUsageReportList, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeSecurityContextAPERValueFieldContext(v *SecurityContextAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeSecurityContextAPERValueFieldReceived(v *SecurityContextAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeSecurityContextAPERValueFieldReplay(v *SecurityContextAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeSecurityContextAPERValueFieldWithoutReplay(v *SecurityContextAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeSecurityContextFieldExtCount(v *SecurityContext) *int64   { return &v.extCount }
func BridgeSecurityContextFieldExtData(v *SecurityContext) *[][]byte { return &v.extData }
func BridgeSecurityContextFieldExtOrigin(v *SecurityContext) *[]aper.OpaqueOrigin {
	return &v.extOrigin
}
func BridgeSecurityContextFieldExtPresent(v *SecurityContext) *[]bool       { return &v.extPresent }
func BridgeSecurityContextFieldExtWire(v *SecurityContext) *[]aper.WireSpan { return &v.extWire }
func BridgeSecurityContextFieldIEExtensionsIndef(v *SecurityContext) *bool {
	return &v.iEExtensionsIndef
}
func BridgeSecurityContextFieldPerExtPadding(v *SecurityContext) *[]aper.CompletePadding {
	return &v.perExtPadding
}
func BridgeSecurityContextFieldPerPadding(v *SecurityContext) *aper.FinalPadding {
	return &v.perPadding
}
func BridgeSecurityContextFieldReceived(v *SecurityContext) *bool         { return &v.received }
func BridgeSecurityContextFieldReceivedAbsolute(v *SecurityContext) *bool { return &v.receivedAbsolute }
func BridgeSecurityContextFieldReceivedBytes(v *SecurityContext) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeSecurityContextFieldReceivedLocation(v *SecurityContext) *aper.Location {
	return &v.receivedLocation
}
func BridgeSecurityContextFieldReplay(v *SecurityContext) *aper.Snapshot { return &v.replay }
func BridgeSecurityContextFieldStream(v *SecurityContext) *aper.WireSpan { return &v.stream }
func BridgeSecurityContextFieldWithoutReplay(v *SecurityContext) *bool   { return &v.withoutReplay }
func BridgeSecurityContextMethodMarshalAPERBudget(v *SecurityContext, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeSecurityContextMethodMarshalAPERBudgetValue(v *SecurityContext, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudgetValue(a0, a1)
}
func BridgeSecurityContextMethodMarshalAPERChanged(v *SecurityContext, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeSecurityContextMethodMarshalAPERChangedValue(v *SecurityContext, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeSecurityContextMethodMarshalAPERLegacy(v *SecurityContext) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeSecurityContextMethodMarshalAPERNewValue(v *SecurityContext, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERNewValue(a0, a1)
}
func BridgeSecurityContextMethodMarshalAPERPlanned(v *SecurityContext, a0 *aper.DecodeBudget, a1 bool, a2 *aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1, a2)
}
func BridgeSecurityContextMethodMarshalAPERTo(v *SecurityContext, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeSecurityContextMethodUnmarshalAPERFrom(v *SecurityContext, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeSecurityContextMethodUnmarshalAPERLegacy(v *SecurityContext, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeSecurityContextMethodUnmarshalAPERWithOptions(v *SecurityContext, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeSecurityContextValueCodecFieldCapture(v *SecurityContextValueCodec) *func(SecurityContext, aper.DecodeState) (SecurityContext, aper.Snapshot) {
	return &v.capture
}
func BridgeSecurityContextValueCodecFieldCompare(v *SecurityContextValueCodec) *func(SecurityContext, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeSecurityContextValueCodecFieldContext(v *SecurityContextValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeSecurityContextValueCodecFieldDecode(v *SecurityContextValueCodec) *func([]byte, aper.DecodeState) (SecurityContext, error) {
	return &v.decode
}
func BridgeSecurityContextValueCodecFieldEncode(v *SecurityContextValueCodec) *func(SecurityContext, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeSecurityContextValueCodecFieldPath(v *SecurityContextValueCodec) *aper.Path {
	return &v.path
}
func BridgeSecurityContextValueCodecMethodEncodeBudgetValue(v SecurityContextValueCodec, a0 SecurityContext, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeSecurityContextValueCodecMethodEncodeChanged(v SecurityContextValueCodec, a0 SecurityContext, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeSecurityIndicationFieldExtCount(v *SecurityIndication) *int64   { return &v.extCount }
func BridgeSecurityIndicationFieldExtData(v *SecurityIndication) *[][]byte { return &v.extData }
func BridgeSecurityIndicationFieldExtOrigin(v *SecurityIndication) *[]aper.OpaqueOrigin {
	return &v.extOrigin
}
func BridgeSecurityIndicationFieldExtPresent(v *SecurityIndication) *[]bool       { return &v.extPresent }
func BridgeSecurityIndicationFieldExtWire(v *SecurityIndication) *[]aper.WireSpan { return &v.extWire }
func BridgeSecurityIndicationFieldIEExtensionsIndef(v *SecurityIndication) *bool {
	return &v.iEExtensionsIndef
}
func BridgeSecurityIndicationFieldPerExtPadding(v *SecurityIndication) *[]aper.CompletePadding {
	return &v.perExtPadding
}
func BridgeSecurityIndicationFieldPerPadding(v *SecurityIndication) *aper.FinalPadding {
	return &v.perPadding
}
func BridgeSecurityIndicationFieldReceived(v *SecurityIndication) *bool { return &v.received }
func BridgeSecurityIndicationFieldReceivedAbsolute(v *SecurityIndication) *bool {
	return &v.receivedAbsolute
}
func BridgeSecurityIndicationFieldReceivedBytes(v *SecurityIndication) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeSecurityIndicationFieldReceivedLocation(v *SecurityIndication) *aper.Location {
	return &v.receivedLocation
}
func BridgeSecurityIndicationFieldReplay(v *SecurityIndication) *aper.Snapshot { return &v.replay }
func BridgeSecurityIndicationFieldStream(v *SecurityIndication) *aper.WireSpan { return &v.stream }
func BridgeSecurityIndicationFieldWithoutReplay(v *SecurityIndication) *bool   { return &v.withoutReplay }
func BridgeSecurityIndicationMethodMarshalAPERBudget(v *SecurityIndication, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeSecurityIndicationMethodMarshalAPERBudgetValue(v *SecurityIndication, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudgetValue(a0, a1)
}
func BridgeSecurityIndicationMethodMarshalAPERChanged(v *SecurityIndication, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeSecurityIndicationMethodMarshalAPERChangedValue(v *SecurityIndication, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeSecurityIndicationMethodMarshalAPERLegacy(v *SecurityIndication) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeSecurityIndicationMethodMarshalAPERNewValue(v *SecurityIndication, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERNewValue(a0, a1)
}
func BridgeSecurityIndicationMethodMarshalAPERPlanned(v *SecurityIndication, a0 *aper.DecodeBudget, a1 bool, a2 *aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1, a2)
}
func BridgeSecurityIndicationMethodMarshalAPERTo(v *SecurityIndication, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeSecurityIndicationMethodUnmarshalAPERFrom(v *SecurityIndication, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeSecurityIndicationMethodUnmarshalAPERLegacy(v *SecurityIndication, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeSecurityIndicationMethodUnmarshalAPERWithOptions(v *SecurityIndication, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeUEContextSuspendResponseCriticalityDiagnosticsIEBindingFieldCodec(v *UEContextSuspendResponseCriticalityDiagnosticsIEBinding) *s22.CriticalityDiagnosticsValueCodec {
	return &v.codec
}
func BridgeUEContextSuspendResponseCriticalityDiagnosticsIEBindingFieldGet(v *UEContextSuspendResponseCriticalityDiagnosticsIEBinding) *func(*UEContextSuspendResponseIEValue) (*s22.CriticalityDiagnostics, bool) {
	return &v.get
}
func BridgeUEContextSuspendResponseCriticalityDiagnosticsIEBindingFieldInfo(v *UEContextSuspendResponseCriticalityDiagnosticsIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeUEContextSuspendResponseCriticalityDiagnosticsIEBindingFieldInject(v *UEContextSuspendResponseCriticalityDiagnosticsIEBinding) *func(s22.CriticalityDiagnostics) UEContextSuspendResponseIEValue {
	return &v.inject
}
func BridgeUEContextSuspendResponseENBUES1APIDIEBindingFieldCodec(v *UEContextSuspendResponseENBUES1APIDIEBinding) *s00.ENBUES1APIDValueCodec {
	return &v.codec
}
func BridgeUEContextSuspendResponseENBUES1APIDIEBindingFieldGet(v *UEContextSuspendResponseENBUES1APIDIEBinding) *func(*UEContextSuspendResponseIEValue) (*s00.ENBUES1APID, bool) {
	return &v.get
}
func BridgeUEContextSuspendResponseENBUES1APIDIEBindingFieldInfo(v *UEContextSuspendResponseENBUES1APIDIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeUEContextSuspendResponseENBUES1APIDIEBindingFieldInject(v *UEContextSuspendResponseENBUES1APIDIEBinding) *func(s00.ENBUES1APID) UEContextSuspendResponseIEValue {
	return &v.inject
}
func BridgeUEContextSuspendResponseIEContainerAPERValueFieldContext(v *UEContextSuspendResponseIEContainerAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeUEContextSuspendResponseIEContainerAPERValueFieldReceived(v *UEContextSuspendResponseIEContainerAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeUEContextSuspendResponseIEContainerAPERValueFieldReplay(v *UEContextSuspendResponseIEContainerAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeUEContextSuspendResponseIEContainerAPERValueFieldWithoutReplay(v *UEContextSuspendResponseIEContainerAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeUEContextSuspendResponseIEContainerValueCodecFieldCapture(v *UEContextSuspendResponseIEContainerValueCodec) *func(UEContextSuspendResponseIEContainer, aper.DecodeState) (UEContextSuspendResponseIEContainer, aper.Snapshot) {
	return &v.capture
}
func BridgeUEContextSuspendResponseIEContainerValueCodecFieldCompare(v *UEContextSuspendResponseIEContainerValueCodec) *func(UEContextSuspendResponseIEContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeUEContextSuspendResponseIEContainerValueCodecFieldContext(v *UEContextSuspendResponseIEContainerValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeUEContextSuspendResponseIEContainerValueCodecFieldDecode(v *UEContextSuspendResponseIEContainerValueCodec) *func([]byte, aper.DecodeState) (UEContextSuspendResponseIEContainer, error) {
	return &v.decode
}
func BridgeUEContextSuspendResponseIEContainerValueCodecFieldEncode(v *UEContextSuspendResponseIEContainerValueCodec) *func(UEContextSuspendResponseIEContainer, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeUEContextSuspendResponseIEContainerValueCodecFieldPath(v *UEContextSuspendResponseIEContainerValueCodec) *aper.Path {
	return &v.path
}
func BridgeUEContextSuspendResponseIEContainerValueCodecMethodEncodeBudgetValue(v UEContextSuspendResponseIEContainerValueCodec, a0 UEContextSuspendResponseIEContainer, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeUEContextSuspendResponseIEContainerValueCodecMethodEncodeChanged(v UEContextSuspendResponseIEContainerValueCodec, a0 UEContextSuspendResponseIEContainer, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeUEContextSuspendResponseIEFieldAPERValueFieldContext(v *UEContextSuspendResponseIEFieldAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeUEContextSuspendResponseIEFieldAPERValueFieldReceived(v *UEContextSuspendResponseIEFieldAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeUEContextSuspendResponseIEFieldAPERValueFieldReplay(v *UEContextSuspendResponseIEFieldAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeUEContextSuspendResponseIEFieldAPERValueFieldWithoutReplay(v *UEContextSuspendResponseIEFieldAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeUEContextSuspendResponseIEFieldFieldReceived(v *UEContextSuspendResponseIEField) *aper.CompletePadding {
	return &v.received
}
func BridgeUEContextSuspendResponseIEFieldFieldReplay(v *UEContextSuspendResponseIEField) *aper.Snapshot {
	return &v.replay
}
func BridgeUEContextSuspendResponseIEFieldFieldStream(v *UEContextSuspendResponseIEField) *aper.WireSpan {
	return &v.stream
}
func BridgeUEContextSuspendResponseIEFieldFieldWithoutReplay(v *UEContextSuspendResponseIEField) *bool {
	return &v.withoutReplay
}
func BridgeUEContextSuspendResponseIEFieldMethodMarshalAPERTo(v *UEContextSuspendResponseIEField, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeUEContextSuspendResponseIEFieldMethodUnmarshalAPERFrom(v *UEContextSuspendResponseIEField, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeUEContextSuspendResponseIEFieldValueCodecFieldCapture(v *UEContextSuspendResponseIEFieldValueCodec) *func(UEContextSuspendResponseIEField, aper.DecodeState) (UEContextSuspendResponseIEField, aper.Snapshot) {
	return &v.capture
}
func BridgeUEContextSuspendResponseIEFieldValueCodecFieldCompare(v *UEContextSuspendResponseIEFieldValueCodec) *func(UEContextSuspendResponseIEField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeUEContextSuspendResponseIEFieldValueCodecFieldContext(v *UEContextSuspendResponseIEFieldValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeUEContextSuspendResponseIEFieldValueCodecFieldDecode(v *UEContextSuspendResponseIEFieldValueCodec) *func([]byte, aper.DecodeState) (UEContextSuspendResponseIEField, error) {
	return &v.decode
}
func BridgeUEContextSuspendResponseIEFieldValueCodecFieldEncode(v *UEContextSuspendResponseIEFieldValueCodec) *func(UEContextSuspendResponseIEField, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeUEContextSuspendResponseIEFieldValueCodecFieldPath(v *UEContextSuspendResponseIEFieldValueCodec) *aper.Path {
	return &v.path
}
func BridgeUEContextSuspendResponseIEFieldValueCodecMethodEncodeBudgetValue(v UEContextSuspendResponseIEFieldValueCodec, a0 UEContextSuspendResponseIEField, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeUEContextSuspendResponseIEFieldValueCodecMethodEncodeChanged(v UEContextSuspendResponseIEFieldValueCodec, a0 UEContextSuspendResponseIEField, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeUEContextSuspendResponseIETableMethodInfoCriticalityDiagnostics(v UEContextSuspendResponseIETable) s00.FieldInfo {
	return v.infoCriticalityDiagnostics()
}
func BridgeUEContextSuspendResponseIETableMethodInfoENBUES1APID(v UEContextSuspendResponseIETable) s00.FieldInfo {
	return v.infoENBUES1APID()
}
func BridgeUEContextSuspendResponseIETableMethodInfoMMEUES1APID(v UEContextSuspendResponseIETable) s00.FieldInfo {
	return v.infoMMEUES1APID()
}
func BridgeUEContextSuspendResponseIETableMethodInfoSecurityContext(v UEContextSuspendResponseIETable) s00.FieldInfo {
	return v.infoSecurityContext()
}
func BridgeUEContextSuspendResponseIEValueERABIEContainerListAPERValueFieldContext(v *UEContextSuspendResponseIEValueERABIEContainerListAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeUEContextSuspendResponseIEValueERABIEContainerListAPERValueFieldReceived(v *UEContextSuspendResponseIEValueERABIEContainerListAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeUEContextSuspendResponseIEValueERABIEContainerListAPERValueFieldReplay(v *UEContextSuspendResponseIEValueERABIEContainerListAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeUEContextSuspendResponseIEValueERABIEContainerListAPERValueFieldWithoutReplay(v *UEContextSuspendResponseIEValueERABIEContainerListAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeUEContextSuspendResponseIEValueERABIEContainerListValueCodecFieldCapture(v *UEContextSuspendResponseIEValueERABIEContainerListValueCodec) *func(UEContextSuspendResponseIEValueERABIEContainerList, aper.DecodeState) (UEContextSuspendResponseIEValueERABIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgeUEContextSuspendResponseIEValueERABIEContainerListValueCodecFieldCompare(v *UEContextSuspendResponseIEValueERABIEContainerListValueCodec) *func(UEContextSuspendResponseIEValueERABIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeUEContextSuspendResponseIEValueERABIEContainerListValueCodecFieldContext(v *UEContextSuspendResponseIEValueERABIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeUEContextSuspendResponseIEValueERABIEContainerListValueCodecFieldDecode(v *UEContextSuspendResponseIEValueERABIEContainerListValueCodec) *func([]byte, aper.DecodeState) (UEContextSuspendResponseIEValueERABIEContainerList, error) {
	return &v.decode
}
func BridgeUEContextSuspendResponseIEValueERABIEContainerListValueCodecFieldEncode(v *UEContextSuspendResponseIEValueERABIEContainerListValueCodec) *func(UEContextSuspendResponseIEValueERABIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeUEContextSuspendResponseIEValueERABIEContainerListValueCodecFieldPath(v *UEContextSuspendResponseIEValueERABIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgeUEContextSuspendResponseIEValueERABIEContainerListValueCodecMethodEncodeBudgetValue(v UEContextSuspendResponseIEValueERABIEContainerListValueCodec, a0 UEContextSuspendResponseIEValueERABIEContainerList, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeUEContextSuspendResponseIEValueERABIEContainerListValueCodecMethodEncodeChanged(v UEContextSuspendResponseIEValueERABIEContainerListValueCodec, a0 UEContextSuspendResponseIEValueERABIEContainerList, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeUEContextSuspendResponseIEValueFieldId(v *UEContextSuspendResponseIEValue) *s00.ProtocolIEID {
	return &v.id
}
func BridgeUEContextSuspendResponseIEValueFieldIsOpaque(v *UEContextSuspendResponseIEValue) *bool {
	return &v.isOpaque
}
func BridgeUEContextSuspendResponseIEValueFieldOpaque(v *UEContextSuspendResponseIEValue) *aper.OpaqueOpenType {
	return &v.opaque
}
func BridgeUEContextSuspendResponseIEValueFieldReceived(v *UEContextSuspendResponseIEValue) *aper.WireSpan {
	return &v.received
}
func BridgeUEContextSuspendResponseIEValueFieldReplay(v *UEContextSuspendResponseIEValue) *aper.Snapshot {
	return &v.replay
}
func BridgeUEContextSuspendResponseIEValueFieldRowCriticalityDiagnostics(v *UEContextSuspendResponseIEValue) **s22.CriticalityDiagnostics {
	return &v.rowCriticalityDiagnostics
}
func BridgeUEContextSuspendResponseIEValueFieldRowENBUES1APID(v *UEContextSuspendResponseIEValue) **s00.ENBUES1APID {
	return &v.rowENBUES1APID
}
func BridgeUEContextSuspendResponseIEValueFieldRowMMEUES1APID(v *UEContextSuspendResponseIEValue) **s00.MMEUES1APID {
	return &v.rowMMEUES1APID
}
func BridgeUEContextSuspendResponseIEValueFieldRowSecurityContext(v *UEContextSuspendResponseIEValue) **SecurityContext {
	return &v.rowSecurityContext
}
func BridgeUEContextSuspendResponseIEValueMethodCaptureSemantics(v UEContextSuspendResponseIEValue, a0 aper.SemanticCapture) UEContextSuspendResponseIEValue {
	return v.captureSemantics(a0)
}
func BridgeUEContextSuspendResponseIEValueMethodCompareSemantics(v UEContextSuspendResponseIEValue, a0 aper.SemanticComparison) aper.SemanticComparison {
	return v.compareSemantics(a0)
}
func BridgeUEContextSuspendResponseIEValueMethodDecode(v UEContextSuspendResponseIEValue, a0 s00.ProtocolIEID, a1 aper.OpaqueOpenType) (UEContextSuspendResponseIEValue, error) {
	return v.decode(a0, a1)
}
func BridgeUEContextSuspendResponseIEValueMethodEncode(v UEContextSuspendResponseIEValue) ([]byte, error) {
	return v.encode()
}
func BridgeUEContextSuspendResponseIEValueMethodEncodeFresh(v UEContextSuspendResponseIEValue, a0 bool, a1 *aper.DecodeBudget) ([]byte, error) {
	return v.encodeFresh(a0, a1)
}
func BridgeUEContextSuspendResponseIEValueMethodMatchesID(v UEContextSuspendResponseIEValue, a0 s00.ProtocolIEID, a1 ...*aper.DecodeBudget) bool {
	return v.matchesID(a0, a1...)
}
func BridgeUEContextSuspendResponseIEValueMethodReason(v UEContextSuspendResponseIEValue, a0 s00.ProtocolIEID) aper.OpaqueReason {
	return v.reason(a0)
}
func BridgeUEContextSuspendResponseIEValueMethodRule(v UEContextSuspendResponseIEValue) aper.SourceRule {
	return v.rule()
}
func BridgeUEContextSuspendResponseIEValueProtocolErrorIEContainerListAPERValueFieldContext(v *UEContextSuspendResponseIEValueProtocolErrorIEContainerListAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeUEContextSuspendResponseIEValueProtocolErrorIEContainerListAPERValueFieldReceived(v *UEContextSuspendResponseIEValueProtocolErrorIEContainerListAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeUEContextSuspendResponseIEValueProtocolErrorIEContainerListAPERValueFieldReplay(v *UEContextSuspendResponseIEValueProtocolErrorIEContainerListAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeUEContextSuspendResponseIEValueProtocolErrorIEContainerListAPERValueFieldWithoutReplay(v *UEContextSuspendResponseIEValueProtocolErrorIEContainerListAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeUEContextSuspendResponseIEValueProtocolErrorIEContainerListValueCodecFieldCapture(v *UEContextSuspendResponseIEValueProtocolErrorIEContainerListValueCodec) *func(UEContextSuspendResponseIEValueProtocolErrorIEContainerList, aper.DecodeState) (UEContextSuspendResponseIEValueProtocolErrorIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgeUEContextSuspendResponseIEValueProtocolErrorIEContainerListValueCodecFieldCompare(v *UEContextSuspendResponseIEValueProtocolErrorIEContainerListValueCodec) *func(UEContextSuspendResponseIEValueProtocolErrorIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeUEContextSuspendResponseIEValueProtocolErrorIEContainerListValueCodecFieldContext(v *UEContextSuspendResponseIEValueProtocolErrorIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeUEContextSuspendResponseIEValueProtocolErrorIEContainerListValueCodecFieldDecode(v *UEContextSuspendResponseIEValueProtocolErrorIEContainerListValueCodec) *func([]byte, aper.DecodeState) (UEContextSuspendResponseIEValueProtocolErrorIEContainerList, error) {
	return &v.decode
}
func BridgeUEContextSuspendResponseIEValueProtocolErrorIEContainerListValueCodecFieldEncode(v *UEContextSuspendResponseIEValueProtocolErrorIEContainerListValueCodec) *func(UEContextSuspendResponseIEValueProtocolErrorIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeUEContextSuspendResponseIEValueProtocolErrorIEContainerListValueCodecFieldPath(v *UEContextSuspendResponseIEValueProtocolErrorIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgeUEContextSuspendResponseIEValueProtocolErrorIEContainerListValueCodecMethodEncodeBudgetValue(v UEContextSuspendResponseIEValueProtocolErrorIEContainerListValueCodec, a0 UEContextSuspendResponseIEValueProtocolErrorIEContainerList, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeUEContextSuspendResponseIEValueProtocolErrorIEContainerListValueCodecMethodEncodeChanged(v UEContextSuspendResponseIEValueProtocolErrorIEContainerListValueCodec, a0 UEContextSuspendResponseIEValueProtocolErrorIEContainerList, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeUEContextSuspendResponseIEValueProtocolIEContainerListAPERValueFieldContext(v *UEContextSuspendResponseIEValueProtocolIEContainerListAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeUEContextSuspendResponseIEValueProtocolIEContainerListAPERValueFieldReceived(v *UEContextSuspendResponseIEValueProtocolIEContainerListAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeUEContextSuspendResponseIEValueProtocolIEContainerListAPERValueFieldReplay(v *UEContextSuspendResponseIEValueProtocolIEContainerListAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeUEContextSuspendResponseIEValueProtocolIEContainerListAPERValueFieldWithoutReplay(v *UEContextSuspendResponseIEValueProtocolIEContainerListAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeUEContextSuspendResponseIEValueProtocolIEContainerListValueCodecFieldCapture(v *UEContextSuspendResponseIEValueProtocolIEContainerListValueCodec) *func(UEContextSuspendResponseIEValueProtocolIEContainerList, aper.DecodeState) (UEContextSuspendResponseIEValueProtocolIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgeUEContextSuspendResponseIEValueProtocolIEContainerListValueCodecFieldCompare(v *UEContextSuspendResponseIEValueProtocolIEContainerListValueCodec) *func(UEContextSuspendResponseIEValueProtocolIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeUEContextSuspendResponseIEValueProtocolIEContainerListValueCodecFieldContext(v *UEContextSuspendResponseIEValueProtocolIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeUEContextSuspendResponseIEValueProtocolIEContainerListValueCodecFieldDecode(v *UEContextSuspendResponseIEValueProtocolIEContainerListValueCodec) *func([]byte, aper.DecodeState) (UEContextSuspendResponseIEValueProtocolIEContainerList, error) {
	return &v.decode
}
func BridgeUEContextSuspendResponseIEValueProtocolIEContainerListValueCodecFieldEncode(v *UEContextSuspendResponseIEValueProtocolIEContainerListValueCodec) *func(UEContextSuspendResponseIEValueProtocolIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeUEContextSuspendResponseIEValueProtocolIEContainerListValueCodecFieldPath(v *UEContextSuspendResponseIEValueProtocolIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgeUEContextSuspendResponseIEValueProtocolIEContainerListValueCodecMethodEncodeBudgetValue(v UEContextSuspendResponseIEValueProtocolIEContainerListValueCodec, a0 UEContextSuspendResponseIEValueProtocolIEContainerList, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeUEContextSuspendResponseIEValueProtocolIEContainerListValueCodecMethodEncodeChanged(v UEContextSuspendResponseIEValueProtocolIEContainerListValueCodec, a0 UEContextSuspendResponseIEValueProtocolIEContainerList, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeUEContextSuspendResponseMMEUES1APIDIEBindingFieldCodec(v *UEContextSuspendResponseMMEUES1APIDIEBinding) *s01.MMEUES1APIDValueCodec {
	return &v.codec
}
func BridgeUEContextSuspendResponseMMEUES1APIDIEBindingFieldGet(v *UEContextSuspendResponseMMEUES1APIDIEBinding) *func(*UEContextSuspendResponseIEValue) (*s00.MMEUES1APID, bool) {
	return &v.get
}
func BridgeUEContextSuspendResponseMMEUES1APIDIEBindingFieldInfo(v *UEContextSuspendResponseMMEUES1APIDIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeUEContextSuspendResponseMMEUES1APIDIEBindingFieldInject(v *UEContextSuspendResponseMMEUES1APIDIEBinding) *func(s00.MMEUES1APID) UEContextSuspendResponseIEValue {
	return &v.inject
}
func BridgeUEContextSuspendResponseSecurityContextIEBindingFieldCodec(v *UEContextSuspendResponseSecurityContextIEBinding) *SecurityContextValueCodec {
	return &v.codec
}
func BridgeUEContextSuspendResponseSecurityContextIEBindingFieldGet(v *UEContextSuspendResponseSecurityContextIEBinding) *func(*UEContextSuspendResponseIEValue) (*SecurityContext, bool) {
	return &v.get
}
func BridgeUEContextSuspendResponseSecurityContextIEBindingFieldInfo(v *UEContextSuspendResponseSecurityContextIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeUEContextSuspendResponseSecurityContextIEBindingFieldInject(v *UEContextSuspendResponseSecurityContextIEBinding) *func(SecurityContext) UEContextSuspendResponseIEValue {
	return &v.inject
}
func BridgeUEPagingIDAPERValueFieldContext(v *UEPagingIDAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeUEPagingIDAPERValueFieldReceived(v *UEPagingIDAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeUEPagingIDAPERValueFieldReplay(v *UEPagingIDAPERValue) *aper.Snapshot { return &v.replay }
func BridgeUEPagingIDAPERValueFieldWithoutReplay(v *UEPagingIDAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeUEPagingIDFieldPerOpenTypePadding(v *UEPagingID) *aper.CompletePadding {
	return &v.perOpenTypePadding
}
func BridgeUEPagingIDFieldPerPadding(v *UEPagingID) *aper.CompletePadding { return &v.perPadding }
func BridgeUEPagingIDFieldReceived(v *UEPagingID) *bool                   { return &v.received }
func BridgeUEPagingIDFieldReceivedAbsolute(v *UEPagingID) *bool           { return &v.receivedAbsolute }
func BridgeUEPagingIDFieldReceivedBytes(v *UEPagingID) *aper.WireSpan     { return &v.receivedBytes }
func BridgeUEPagingIDFieldReceivedLocation(v *UEPagingID) *aper.Location  { return &v.receivedLocation }
func BridgeUEPagingIDFieldReplay(v *UEPagingID) *aper.Snapshot            { return &v.replay }
func BridgeUEPagingIDFieldStream(v *UEPagingID) *aper.WireSpan            { return &v.stream }
func BridgeUEPagingIDFieldWithoutReplay(v *UEPagingID) *bool              { return &v.withoutReplay }
func BridgeUEPagingIDMethodMarshalAPERBudget(v *UEPagingID, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeUEPagingIDMethodMarshalAPERBudgetValue(v *UEPagingID, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudgetValue(a0, a1)
}
func BridgeUEPagingIDMethodMarshalAPERChanged(v *UEPagingID, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeUEPagingIDMethodMarshalAPERChangedValue(v *UEPagingID, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeUEPagingIDMethodMarshalAPERLegacy(v *UEPagingID) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeUEPagingIDMethodMarshalAPERNewValue(v *UEPagingID, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERNewValue(a0, a1)
}
func BridgeUEPagingIDMethodMarshalAPERPlanned(v *UEPagingID, a0 *aper.DecodeBudget, a1 bool, a2 *aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1, a2)
}
func BridgeUEPagingIDMethodMarshalAPERTo(v *UEPagingID, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeUEPagingIDMethodUnmarshalAPERFrom(v *UEPagingID, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeUEPagingIDMethodUnmarshalAPERLegacy(v *UEPagingID, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeUEPagingIDMethodUnmarshalAPERWithOptions(v *UEPagingID, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeUEPagingIDValueCodecFieldCapture(v *UEPagingIDValueCodec) *func(UEPagingID, aper.DecodeState) (UEPagingID, aper.Snapshot) {
	return &v.capture
}
func BridgeUEPagingIDValueCodecFieldCompare(v *UEPagingIDValueCodec) *func(UEPagingID, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeUEPagingIDValueCodecFieldContext(v *UEPagingIDValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeUEPagingIDValueCodecFieldDecode(v *UEPagingIDValueCodec) *func([]byte, aper.DecodeState) (UEPagingID, error) {
	return &v.decode
}
func BridgeUEPagingIDValueCodecFieldEncode(v *UEPagingIDValueCodec) *func(UEPagingID, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeUEPagingIDValueCodecFieldPath(v *UEPagingIDValueCodec) *aper.Path { return &v.path }
func BridgeUEPagingIDValueCodecMethodEncodeBudgetValue(v UEPagingIDValueCodec, a0 UEPagingID, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeUEPagingIDValueCodecMethodEncodeChanged(v UEPagingIDValueCodec, a0 UEPagingID, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
