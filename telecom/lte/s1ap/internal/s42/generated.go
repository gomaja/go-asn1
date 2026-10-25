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
	s22 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s22"
	s24 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s24"
	s25 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s25"
	s26 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s26"
	s27 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s27"
	s29 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s29"
	s30 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s30"
	s35 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s35"
	s41 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s41"
	runtime "github.com/gomaja/go-asn1/telecom/lte/s1ap/runtime"
	aper "github.com/gomaja/go-asn1/telecom/lte/s1ap/runtime/aper"
)

// OverloadStartIEContainer is ProtocolIE-Container {{OverloadStartIEs}} of TS 36.413: a list of OverloadStartIEField values.
type OverloadStartIEContainer []OverloadStartIEField

// OverloadStartIEField is ProtocolIE-Field {{OverloadStartIEs}} of TS 36.413: an information element field.
type OverloadStartIEField struct {
	withoutReplay bool
	replay        aper.Snapshot
	stream        aper.WireSpan
	Id            s00.ProtocolIEID
	Criticality   s00.Criticality
	Value         OverloadStartIEValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v OverloadStartIEField) WithoutReplay() OverloadStartIEField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *OverloadStartIEField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *OverloadStartIEField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
func (v *OverloadStartIEField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolIEField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = OverloadStartIEField{}
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
	var zero OverloadStartIEValue

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

// OverloadStopIEContainer is ProtocolIE-Container {{OverloadStopIEs}} of TS 36.413: a list of OverloadStopIEField values.
type OverloadStopIEContainer []OverloadStopIEField

// OverloadStopIEField is ProtocolIE-Field {{OverloadStopIEs}} of TS 36.413: an information element field.
type OverloadStopIEField struct {
	withoutReplay bool
	replay        aper.Snapshot
	stream        aper.WireSpan
	Id            s00.ProtocolIEID
	Criticality   s00.Criticality
	Value         OverloadStopIEValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v OverloadStopIEField) WithoutReplay() OverloadStopIEField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *OverloadStopIEField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *OverloadStopIEField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
func (v *OverloadStopIEField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolIEField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = OverloadStopIEField{}
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
	var zero OverloadStopIEValue

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
func BridgeLastVisitedEUTRANCellInformationExtIEsValueCaptureS1APProtocolExtensionContainer(v *LastVisitedEUTRANCellInformationExtIEsExtContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeLastVisitedEUTRANCellInformationExtIEsValueCaptureS1APProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeLastVisitedEUTRANCellInformationExtIEsValueCompareS1APProtocolExtensionContainer(v *LastVisitedEUTRANCellInformationExtIEsExtContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeLastVisitedEUTRANCellInformationExtIEsValueCompareS1APProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeMDTConfigurationExtIEsValueCaptureS1APProtocolExtensionContainer(v *MDTConfigurationExtIEsExtContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeMDTConfigurationExtIEsValueCaptureS1APProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeMDTConfigurationExtIEsValueCompareS1APProtocolExtensionContainer(v *MDTConfigurationExtIEsExtContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeMDTConfigurationExtIEsValueCompareS1APProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeOverloadStartIEValueCaptureS1APProtocolIEContainer(v *OverloadStartIEContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeOverloadStartIEValueCaptureS1APProtocolIEField(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeOverloadStartIEValueCompareS1APProtocolIEContainer(v *OverloadStartIEContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeOverloadStartIEValueCompareS1APProtocolIEField(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeOverloadStopIEValueCaptureS1APProtocolIEContainer(v *OverloadStopIEContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeOverloadStopIEValueCaptureS1APProtocolIEField(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeOverloadStopIEValueCompareS1APProtocolIEContainer(v *OverloadStopIEContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeOverloadStopIEValueCompareS1APProtocolIEField(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}

// LastVisitedEUTRANCellInformationExtIEsExtContainer is ProtocolExtensionContainer {{LastVisitedEUTRANCellInformation-ExtIEs}} of TS 36.413: a list of LastVisitedEUTRANCellInformationExtIEsExtField values.
type LastVisitedEUTRANCellInformationExtIEsExtContainer []LastVisitedEUTRANCellInformationExtIEsExtField

// MDTConfigurationExtIEsExtContainer is ProtocolExtensionContainer {{MDT-Configuration-ExtIEs}} of TS 36.413: a list of MDTConfigurationExtIEsExtField values.
type MDTConfigurationExtIEsExtContainer []MDTConfigurationExtIEsExtField

// LastVisitedEUTRANCellInformationExtIEsExtField is ProtocolExtensionField {{LastVisitedEUTRANCellInformation-ExtIEs}} of TS 36.413: an extension field.
type LastVisitedEUTRANCellInformationExtIEsExtField struct {
	withoutReplay  bool
	replay         aper.Snapshot
	stream         aper.WireSpan
	Id             s00.ProtocolExtensionID
	Criticality    s00.Criticality
	ExtensionValue LastVisitedEUTRANCellInformationExtIEsValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v LastVisitedEUTRANCellInformationExtIEsExtField) WithoutReplay() LastVisitedEUTRANCellInformationExtIEsExtField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *LastVisitedEUTRANCellInformationExtIEsExtField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *LastVisitedEUTRANCellInformationExtIEsExtField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
func (v *LastVisitedEUTRANCellInformationExtIEsExtField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolExtensionField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = LastVisitedEUTRANCellInformationExtIEsExtField{}
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
	var zero LastVisitedEUTRANCellInformationExtIEsValue

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

// MDTConfigurationExtIEsExtField is ProtocolExtensionField {{MDT-Configuration-ExtIEs}} of TS 36.413: an extension field.
type MDTConfigurationExtIEsExtField struct {
	withoutReplay  bool
	replay         aper.Snapshot
	stream         aper.WireSpan
	Id             s00.ProtocolExtensionID
	Criticality    s00.Criticality
	ExtensionValue MDTConfigurationExtIEsValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v MDTConfigurationExtIEsExtField) WithoutReplay() MDTConfigurationExtIEsExtField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *MDTConfigurationExtIEsExtField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *MDTConfigurationExtIEsExtField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
func (v *MDTConfigurationExtIEsExtField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolExtensionField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = MDTConfigurationExtIEsExtField{}
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
	var zero MDTConfigurationExtIEsValue

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

// LastVisitedEUTRANCellInformationExtIEsTimeUEStayedInCellEnhancedGranularityExtBinding binds TimeUEStayedInCellEnhancedGranularity to the LastVisitedEUTRANCellInformation-ExtIEs object set of TS 36.413.
type LastVisitedEUTRANCellInformationExtIEsTimeUEStayedInCellEnhancedGranularityExtBinding struct {
	info   s00.ExtensionInfo
	codec  s02.TimeUEStayedInCellEnhancedGranularityValueCodec
	inject func(s00.TimeUEStayedInCellEnhancedGranularity,

	) LastVisitedEUTRANCellInformationExtIEsValue

	get func(*LastVisitedEUTRANCellInformationExtIEsValue,

	) (*s00.TimeUEStayedInCellEnhancedGranularity,

		bool)
}

// Info returns the source descriptor for this binding.
func (b LastVisitedEUTRANCellInformationExtIEsTimeUEStayedInCellEnhancedGranularityExtBinding) Info() s00.ExtensionInfo {
	return b.info
}

// Codec returns the complete value codec for this binding.
func (b LastVisitedEUTRANCellInformationExtIEsTimeUEStayedInCellEnhancedGranularityExtBinding) Codec() s02.TimeUEStayedInCellEnhancedGranularityValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b LastVisitedEUTRANCellInformationExtIEsTimeUEStayedInCellEnhancedGranularityExtBinding) New(value s00.TimeUEStayedInCellEnhancedGranularity,

) (LastVisitedEUTRANCellInformationExtIEsExtField, error) {
	if b.inject == nil {
		return LastVisitedEUTRANCellInformationExtIEsExtField{}, aper.OperationError(fmt.Errorf("unbound extension binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return LastVisitedEUTRANCellInformationExtIEsExtField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s02.BridgeTimeUEStayedInCellEnhancedGranularityValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return LastVisitedEUTRANCellInformationExtIEsExtField{}, aper.OperationError(fmt.Errorf("extension %d: %w", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return LastVisitedEUTRANCellInformationExtIEsExtField{}, aper.OperationError(err, "Value.New")
	}
	return LastVisitedEUTRANCellInformationExtIEsExtField{Id: b.info.ID, Criticality: b.info.Criticality, ExtensionValue: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b LastVisitedEUTRANCellInformationExtIEsTimeUEStayedInCellEnhancedGranularityExtBinding) Get(field *LastVisitedEUTRANCellInformationExtIEsExtField) (*s00.TimeUEStayedInCellEnhancedGranularity,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.ExtensionValue)
}

// LastVisitedEUTRANCellInformationExtIEsCauseExtBinding binds Cause to the LastVisitedEUTRANCellInformation-ExtIEs object set of TS 36.413.
type LastVisitedEUTRANCellInformationExtIEsCauseExtBinding struct {
	info   s00.ExtensionInfo
	codec  s14.CauseValueCodec
	inject func(s14.Cause,

	) LastVisitedEUTRANCellInformationExtIEsValue

	get func(*LastVisitedEUTRANCellInformationExtIEsValue,

	) (*s14.Cause,

		bool)
}

// Info returns the source descriptor for this binding.
func (b LastVisitedEUTRANCellInformationExtIEsCauseExtBinding) Info() s00.ExtensionInfo {
	return b.info
}

// Codec returns the complete value codec for this binding.
func (b LastVisitedEUTRANCellInformationExtIEsCauseExtBinding) Codec() s14.CauseValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b LastVisitedEUTRANCellInformationExtIEsCauseExtBinding) New(value s14.Cause,

) (LastVisitedEUTRANCellInformationExtIEsExtField, error) {
	if b.inject == nil {
		return LastVisitedEUTRANCellInformationExtIEsExtField{}, aper.OperationError(fmt.Errorf("unbound extension binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return LastVisitedEUTRANCellInformationExtIEsExtField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s14.BridgeCauseValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return LastVisitedEUTRANCellInformationExtIEsExtField{}, aper.OperationError(fmt.Errorf("extension %d: %w", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return LastVisitedEUTRANCellInformationExtIEsExtField{}, aper.OperationError(err, "Value.New")
	}
	return LastVisitedEUTRANCellInformationExtIEsExtField{Id: b.info.ID, Criticality: b.info.Criticality, ExtensionValue: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b LastVisitedEUTRANCellInformationExtIEsCauseExtBinding) Get(field *LastVisitedEUTRANCellInformationExtIEsExtField) (*s14.Cause,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.ExtensionValue)
}

// LastVisitedEUTRANCellInformationExtIEsLastVisitedPSCellListExtBinding binds LastVisitedPSCellList to the LastVisitedEUTRANCellInformation-ExtIEs object set of TS 36.413.
type LastVisitedEUTRANCellInformationExtIEsLastVisitedPSCellListExtBinding struct {
	info   s00.ExtensionInfo
	codec  s20.LastVisitedPSCellListValueCodec
	inject func(s20.LastVisitedPSCellList,

	) LastVisitedEUTRANCellInformationExtIEsValue

	get func(*LastVisitedEUTRANCellInformationExtIEsValue,

	) (*s20.LastVisitedPSCellList,

		bool)
}

// Info returns the source descriptor for this binding.
func (b LastVisitedEUTRANCellInformationExtIEsLastVisitedPSCellListExtBinding) Info() s00.ExtensionInfo {
	return b.info
}

// Codec returns the complete value codec for this binding.
func (b LastVisitedEUTRANCellInformationExtIEsLastVisitedPSCellListExtBinding) Codec() s20.LastVisitedPSCellListValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b LastVisitedEUTRANCellInformationExtIEsLastVisitedPSCellListExtBinding) New(value s20.LastVisitedPSCellList,

) (LastVisitedEUTRANCellInformationExtIEsExtField, error) {
	if b.inject == nil {
		return LastVisitedEUTRANCellInformationExtIEsExtField{}, aper.OperationError(fmt.Errorf("unbound extension binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return LastVisitedEUTRANCellInformationExtIEsExtField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s20.BridgeLastVisitedPSCellListValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return LastVisitedEUTRANCellInformationExtIEsExtField{}, aper.OperationError(fmt.Errorf("extension %d: %w", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return LastVisitedEUTRANCellInformationExtIEsExtField{}, aper.OperationError(err, "Value.New")
	}
	return LastVisitedEUTRANCellInformationExtIEsExtField{Id: b.info.ID, Criticality: b.info.Criticality, ExtensionValue: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b LastVisitedEUTRANCellInformationExtIEsLastVisitedPSCellListExtBinding) Get(field *LastVisitedEUTRANCellInformationExtIEsExtField) (*s20.LastVisitedPSCellList,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.ExtensionValue)
}

// MDTConfigurationExtIEsMDTPLMNListExtBinding binds MDTPLMNList to the MDT-Configuration-ExtIEs object set of TS 36.413.
type MDTConfigurationExtIEsMDTPLMNListExtBinding struct {
	info   s00.ExtensionInfo
	codec  s01.MDTPLMNListValueCodec
	inject func(s00.MDTPLMNList,

	) MDTConfigurationExtIEsValue

	get func(*MDTConfigurationExtIEsValue,

	) (*s00.MDTPLMNList,

		bool)
}

// Info returns the source descriptor for this binding.
func (b MDTConfigurationExtIEsMDTPLMNListExtBinding) Info() s00.ExtensionInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b MDTConfigurationExtIEsMDTPLMNListExtBinding) Codec() s01.MDTPLMNListValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b MDTConfigurationExtIEsMDTPLMNListExtBinding) New(value s00.MDTPLMNList,

) (MDTConfigurationExtIEsExtField, error) {
	if b.inject == nil {
		return MDTConfigurationExtIEsExtField{}, aper.OperationError(fmt.Errorf("unbound extension binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return MDTConfigurationExtIEsExtField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s01.BridgeMDTPLMNListValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return MDTConfigurationExtIEsExtField{}, aper.OperationError(fmt.Errorf("extension %d: %w", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return MDTConfigurationExtIEsExtField{}, aper.OperationError(err, "Value.New")
	}
	return MDTConfigurationExtIEsExtField{Id: b.info.ID, Criticality: b.info.Criticality, ExtensionValue: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b MDTConfigurationExtIEsMDTPLMNListExtBinding) Get(field *MDTConfigurationExtIEsExtField) (*s00.MDTPLMNList,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.ExtensionValue)
}

// OverloadStartOverloadResponseIEBinding binds OverloadResponse to the OverloadStartIEs object set of TS 36.413.
type OverloadStartOverloadResponseIEBinding struct {
	info   s00.FieldInfo
	codec  s20.OverloadResponseValueCodec
	inject func(s20.OverloadResponse,

	) OverloadStartIEValue

	get func(*OverloadStartIEValue,

	) (*s20.OverloadResponse,

		bool)
}

// Info returns the source descriptor for this binding.
func (b OverloadStartOverloadResponseIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b OverloadStartOverloadResponseIEBinding) Codec() s20.OverloadResponseValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b OverloadStartOverloadResponseIEBinding) New(value s20.OverloadResponse,

) (OverloadStartIEField, error) {
	if b.inject == nil {
		return OverloadStartIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return OverloadStartIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s20.BridgeOverloadResponseValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return OverloadStartIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return OverloadStartIEField{}, aper.OperationError(err, "Value.New")
	}
	return OverloadStartIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b OverloadStartOverloadResponseIEBinding) Get(field *OverloadStartIEField) (*s20.OverloadResponse,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// OverloadStartGUMMEIListIEBinding binds GUMMEIList to the OverloadStartIEs object set of TS 36.413.
type OverloadStartGUMMEIListIEBinding struct {
	info   s00.FieldInfo
	codec  s18.GUMMEIListValueCodec
	inject func(s18.GUMMEIList,

	) OverloadStartIEValue

	get func(*OverloadStartIEValue,

	) (*s18.GUMMEIList,

		bool)
}

// Info returns the source descriptor for this binding.
func (b OverloadStartGUMMEIListIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b OverloadStartGUMMEIListIEBinding) Codec() s18.GUMMEIListValueCodec { return b.codec }

// New validates a source value and constructs its bound field.
func (b OverloadStartGUMMEIListIEBinding) New(value s18.GUMMEIList,

) (OverloadStartIEField, error) {
	if b.inject == nil {
		return OverloadStartIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return OverloadStartIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s18.BridgeGUMMEIListValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return OverloadStartIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return OverloadStartIEField{}, aper.OperationError(err, "Value.New")
	}
	return OverloadStartIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b OverloadStartGUMMEIListIEBinding) Get(field *OverloadStartIEField) (*s18.GUMMEIList,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// OverloadStartTrafficLoadReductionIndicationIEBinding binds TrafficLoadReductionIndication to the OverloadStartIEs object set of TS 36.413.
type OverloadStartTrafficLoadReductionIndicationIEBinding struct {
	info   s00.FieldInfo
	codec  s02.TrafficLoadReductionIndicationValueCodec
	inject func(s00.TrafficLoadReductionIndication,

	) OverloadStartIEValue

	get func(*OverloadStartIEValue,

	) (*s00.TrafficLoadReductionIndication,

		bool)
}

// Info returns the source descriptor for this binding.
func (b OverloadStartTrafficLoadReductionIndicationIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b OverloadStartTrafficLoadReductionIndicationIEBinding) Codec() s02.TrafficLoadReductionIndicationValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b OverloadStartTrafficLoadReductionIndicationIEBinding) New(value s00.TrafficLoadReductionIndication,

) (OverloadStartIEField, error) {
	if b.inject == nil {
		return OverloadStartIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return OverloadStartIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s02.BridgeTrafficLoadReductionIndicationValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return OverloadStartIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return OverloadStartIEField{}, aper.OperationError(err, "Value.New")
	}
	return OverloadStartIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b OverloadStartTrafficLoadReductionIndicationIEBinding) Get(field *OverloadStartIEField) (*s00.TrafficLoadReductionIndication,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// OverloadStopGUMMEIListIEBinding binds GUMMEIList to the OverloadStopIEs object set of TS 36.413.
type OverloadStopGUMMEIListIEBinding struct {
	info   s00.FieldInfo
	codec  s18.GUMMEIListValueCodec
	inject func(s18.GUMMEIList,

	) OverloadStopIEValue

	get func(*OverloadStopIEValue,

	) (*s18.GUMMEIList,

		bool)
}

// Info returns the source descriptor for this binding.
func (b OverloadStopGUMMEIListIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b OverloadStopGUMMEIListIEBinding) Codec() s18.GUMMEIListValueCodec { return b.codec }

// New validates a source value and constructs its bound field.
func (b OverloadStopGUMMEIListIEBinding) New(value s18.GUMMEIList,

) (OverloadStopIEField, error) {
	if b.inject == nil {
		return OverloadStopIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return OverloadStopIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s18.BridgeGUMMEIListValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return OverloadStopIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return OverloadStopIEField{}, aper.OperationError(err, "Value.New")
	}
	return OverloadStopIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b OverloadStopGUMMEIListIEBinding) Get(field *OverloadStopIEField) (*s18.GUMMEIList,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// LastVisitedCellItemValueCodec is the concrete ValueCodec[LastVisitedCellItem].
type LastVisitedCellItemValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (LastVisitedCellItem,

		error)
	encode func(LastVisitedCellItem,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(LastVisitedCellItem, aper.DecodeState,

	) (LastVisitedCellItem, aper.Snapshot,

	)
	compare func(LastVisitedCellItem, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c LastVisitedCellItemValueCodec) New(value LastVisitedCellItem,

) (LastVisitedCellItemAPERValue, error) {
	if c.encode == nil {
		return LastVisitedCellItemAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return LastVisitedCellItemAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return LastVisitedCellItemAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return LastVisitedCellItemAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c LastVisitedCellItemValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (LastVisitedCellItemAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return LastVisitedCellItemAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return LastVisitedCellItemAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return LastVisitedCellItemAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return LastVisitedCellItemAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c LastVisitedCellItemValueCodec) EncodeAPER(value LastVisitedCellItemAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c LastVisitedCellItemValueCodec) encodeBudgetValue(value LastVisitedCellItem,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c LastVisitedCellItemValueCodec) encodeChanged(value LastVisitedCellItem,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// LastVisitedEUTRANCellInformationValueCodec is the concrete ValueCodec[LastVisitedEUTRANCellInformation].
type LastVisitedEUTRANCellInformationValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (LastVisitedEUTRANCellInformation,

		error)
	encode func(LastVisitedEUTRANCellInformation,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(LastVisitedEUTRANCellInformation, aper.DecodeState,

	) (LastVisitedEUTRANCellInformation, aper.Snapshot,

	)
	compare func(LastVisitedEUTRANCellInformation, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c LastVisitedEUTRANCellInformationValueCodec) New(value LastVisitedEUTRANCellInformation,

) (LastVisitedEUTRANCellInformationAPERValue, error) {
	if c.encode == nil {
		return LastVisitedEUTRANCellInformationAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return LastVisitedEUTRANCellInformationAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return LastVisitedEUTRANCellInformationAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return LastVisitedEUTRANCellInformationAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c LastVisitedEUTRANCellInformationValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (LastVisitedEUTRANCellInformationAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return LastVisitedEUTRANCellInformationAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return LastVisitedEUTRANCellInformationAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return LastVisitedEUTRANCellInformationAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return LastVisitedEUTRANCellInformationAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c LastVisitedEUTRANCellInformationValueCodec) EncodeAPER(value LastVisitedEUTRANCellInformationAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c LastVisitedEUTRANCellInformationValueCodec) encodeBudgetValue(value LastVisitedEUTRANCellInformation,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c LastVisitedEUTRANCellInformationValueCodec) encodeChanged(value LastVisitedEUTRANCellInformation,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// OverloadStartValueCodec is the concrete ValueCodec[OverloadStart].
type OverloadStartValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (OverloadStart,

		error)
	encode func(OverloadStart,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(OverloadStart, aper.DecodeState,

	) (OverloadStart, aper.Snapshot,

	)
	compare func(OverloadStart, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c OverloadStartValueCodec) New(value OverloadStart,

) (OverloadStartAPERValue, error) {
	if c.encode == nil {
		return OverloadStartAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return OverloadStartAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return OverloadStartAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return OverloadStartAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c OverloadStartValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (OverloadStartAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return OverloadStartAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return OverloadStartAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return OverloadStartAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return OverloadStartAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c OverloadStartValueCodec) EncodeAPER(value OverloadStartAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c OverloadStartValueCodec) encodeBudgetValue(value OverloadStart,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c OverloadStartValueCodec) encodeChanged(value OverloadStart,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// OverloadStopValueCodec is the concrete ValueCodec[OverloadStop].
type OverloadStopValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (OverloadStop,

		error)
	encode func(OverloadStop,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(OverloadStop, aper.DecodeState,

	) (OverloadStop, aper.Snapshot,

	)
	compare func(OverloadStop, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c OverloadStopValueCodec) New(value OverloadStop,

) (OverloadStopAPERValue, error) {
	if c.encode == nil {
		return OverloadStopAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return OverloadStopAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return OverloadStopAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return OverloadStopAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c OverloadStopValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (OverloadStopAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return OverloadStopAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return OverloadStopAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return OverloadStopAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return OverloadStopAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c OverloadStopValueCodec) EncodeAPER(value OverloadStopAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c OverloadStopValueCodec) encodeBudgetValue(value OverloadStop,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c OverloadStopValueCodec) encodeChanged(value OverloadStop,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// SourceeNBToTargeteNBTransparentContainerValueCodec is the concrete ValueCodec[SourceeNBToTargeteNBTransparentContainer].
type SourceeNBToTargeteNBTransparentContainerValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (SourceeNBToTargeteNBTransparentContainer,

		error)
	encode func(SourceeNBToTargeteNBTransparentContainer,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(SourceeNBToTargeteNBTransparentContainer, aper.DecodeState,

	) (SourceeNBToTargeteNBTransparentContainer, aper.Snapshot,

	)
	compare func(SourceeNBToTargeteNBTransparentContainer, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c SourceeNBToTargeteNBTransparentContainerValueCodec) New(value SourceeNBToTargeteNBTransparentContainer,

) (SourceeNBToTargeteNBTransparentContainerAPERValue, error) {
	if c.encode == nil {
		return SourceeNBToTargeteNBTransparentContainerAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return SourceeNBToTargeteNBTransparentContainerAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return SourceeNBToTargeteNBTransparentContainerAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return SourceeNBToTargeteNBTransparentContainerAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c SourceeNBToTargeteNBTransparentContainerValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (SourceeNBToTargeteNBTransparentContainerAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return SourceeNBToTargeteNBTransparentContainerAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return SourceeNBToTargeteNBTransparentContainerAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return SourceeNBToTargeteNBTransparentContainerAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return SourceeNBToTargeteNBTransparentContainerAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c SourceeNBToTargeteNBTransparentContainerValueCodec) EncodeAPER(value SourceeNBToTargeteNBTransparentContainerAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c SourceeNBToTargeteNBTransparentContainerValueCodec) encodeBudgetValue(value SourceeNBToTargeteNBTransparentContainer,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c SourceeNBToTargeteNBTransparentContainerValueCodec) encodeChanged(value SourceeNBToTargeteNBTransparentContainer,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// UEHistoryInformationValueCodec is the concrete ValueCodec[UEHistoryInformation].
type UEHistoryInformationValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (UEHistoryInformation,

		error)
	encode func(UEHistoryInformation,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(UEHistoryInformation, aper.DecodeState,

	) (UEHistoryInformation, aper.Snapshot,

	)
	compare func(UEHistoryInformation, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c UEHistoryInformationValueCodec) New(value UEHistoryInformation,

) (UEHistoryInformationAPERValue, error) {
	if c.encode == nil {
		return UEHistoryInformationAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return UEHistoryInformationAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return UEHistoryInformationAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return UEHistoryInformationAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c UEHistoryInformationValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (UEHistoryInformationAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return UEHistoryInformationAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return UEHistoryInformationAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return UEHistoryInformationAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return UEHistoryInformationAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c UEHistoryInformationValueCodec) EncodeAPER(value UEHistoryInformationAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c UEHistoryInformationValueCodec) encodeBudgetValue(value UEHistoryInformation,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c UEHistoryInformationValueCodec) encodeChanged(value UEHistoryInformation,

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
func BridgePathSwitchRequestIEValueValidateS1APIEContainer(fields s41.PathSwitchRequestIEContainer, rows []s00.FieldInfo, path string, budget *aper.DecodeBudget,

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
		if !s41.BridgePathSwitchRequestIEValueMethodMatchesID(field.Value, field.Id, budget) {
			rule := s41.BridgePathSwitchRequestIEValueMethodRule(field.Value)
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.ValueIDMismatch, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: aper.Path(fmt.Sprintf("%s.id", location.Path))}, Table: func() s00.TableID {
				sealed := s00.TableID{}
				*s00.BridgeTableIDFieldSource(&sealed) = rule.Assignment
				return sealed
			}(), IEID: field.Id, HasIEID: true, Rule: s27.BridgeS1apValidationRule(s00.ValueIDMismatch), RelatedRules: []aper.SourceRule{rule}})
		}
		rank, allowed := byID[field.Id]
		table := func() s00.TableID {
			sealed := s00.TableID{}
			*s00.BridgeTableIDFieldSource(&sealed) = s41.BridgePathSwitchRequestIEValueMethodRule(field.Value).Assignment
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
func BridgeOverloadStartIEValueValidateS1APIEContainer(fields OverloadStartIEContainer, rows []s00.FieldInfo, path string, budget *aper.DecodeBudget,

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
func BridgeOverloadStopIEValueValidateS1APIEContainer(fields OverloadStopIEContainer, rows []s00.FieldInfo, path string, budget *aper.DecodeBudget,

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
func BridgeLastVisitedEUTRANCellInformationExtIEsValueValidateS1APExtensionContainer(fields LastVisitedEUTRANCellInformationExtIEsExtContainer, rows []s00.FieldInfo, path string, budget *aper.DecodeBudget) s21.ValidationReport {
	bb := aper.NewBudgetBuffer(budget)
	if err := aper.ChargeSlice[LastVisitedEUTRANCellInformationExtIEsIEField](bb, uint64(len(fields))); err != nil {
		return func() s21.ValidationReport {
			sealed := s21.ValidationReport{}
			*s21.BridgeValidationReportFieldErr(&sealed) = err
			*s21.BridgeValidationReportFieldBudget(&sealed) = budget
			return sealed
		}()
	}
	asIE := make(LastVisitedEUTRANCellInformationExtIEsIEContainer, len(fields))
	for i := range fields {
		asIE[i].Id = fields[i].Id
		asIE[i].Criticality = fields[i].Criticality
		asIE[i].Value = fields[i].ExtensionValue
	}
	return BridgeLastVisitedEUTRANCellInformationExtIEsValueValidateS1APIEContainer(asIE, rows, path, budget)
}
func BridgeMDTConfigurationExtIEsValueValidateS1APExtensionContainer(fields MDTConfigurationExtIEsExtContainer, rows []s00.FieldInfo, path string, budget *aper.DecodeBudget) s21.ValidationReport {
	bb := aper.NewBudgetBuffer(budget)
	if err := aper.ChargeSlice[MDTConfigurationExtIEsIEField](bb, uint64(len(fields))); err != nil {
		return func() s21.ValidationReport {
			sealed := s21.ValidationReport{}
			*s21.BridgeValidationReportFieldErr(&sealed) = err
			*s21.BridgeValidationReportFieldBudget(&sealed) = budget
			return sealed
		}()
	}
	asIE := make(MDTConfigurationExtIEsIEContainer, len(fields))
	for i := range fields {
		asIE[i].Id = fields[i].Id
		asIE[i].Criticality = fields[i].Criticality
		asIE[i].Value = fields[i].ExtensionValue
	}
	return BridgeMDTConfigurationExtIEsValueValidateS1APIEContainer(asIE, rows, path, budget)
}

// OverloadStartIEValueERABIEContainerListCodec constructs the E-RAB-IE-ContainerList {{OverloadStartIEs}} codec of TS 36.413.
func OverloadStartIEValueERABIEContainerListCodec(table s00.OverloadStartIEValueIETable) OverloadStartIEValueERABIEContainerListValueCodec {
	codec := OverloadStartIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if codec.decode == nil {
		return OverloadStartIEValueERABIEContainerListValueCodec{}
	}
	size := aper.SizeConstraint{Lower: (aper.ListBounds{Lower: 1, Upper: 256}).Lower, Upper: (aper.ListBounds{Lower: 1, Upper: 256}).Upper, HasLower: true, HasUpper: true}
	return OverloadStartIEValueERABIEContainerListValueCodec{decode: func(data []byte, options aper.DecodeState) (OverloadStartIEValueERABIEContainerList, error) {
		bb := aper.NewCompleteDecodeBuffer(data, options)
		if err := bb.SetDecodeOptionsAligned(options); err != nil {
			return nil, err
		}
		var fields OverloadStartIEValueERABIEContainerList
		_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
			for i := int64(0); i < length; i++ {
				var field OverloadStartIEField
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
			return nil, runtime.WrapDecodePath(err, "OverloadStartIEValueERABIEContainerList")
		}
		if _, err := aper.CaptureFinalBits(bb, "OverloadStartIEValueERABIEContainerList"); err != nil {
			return nil, runtime.WrapDecodePath(err, "OverloadStartIEValueERABIEContainerList")
		}
		return fields, nil
	}, encode: func(value OverloadStartIEValueERABIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return codec.encode(OverloadStartIEContainer(value), fresh, budget)
	}, capture: func(v OverloadStartIEValueERABIEContainerList, options aper.DecodeState) (OverloadStartIEValueERABIEContainerList, aper.Snapshot) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeOverloadStartIEValueCaptureS1APERABIEContainerList(&v, &s)
		var root aper.Snapshot
		s.End(f, &root,

			false)
		return v, root
	}, compare: func(v OverloadStartIEValueERABIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
	) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		BridgeOverloadStartIEValueCompareS1APERABIEContainerList(&v, &s)
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

// OverloadStopIEValueERABIEContainerListCodec constructs the E-RAB-IE-ContainerList {{OverloadStopIEs}} codec of TS 36.413.
func OverloadStopIEValueERABIEContainerListCodec(table s00.OverloadStopIEValueIETable) OverloadStopIEValueERABIEContainerListValueCodec {
	codec := OverloadStopIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if codec.decode == nil {
		return OverloadStopIEValueERABIEContainerListValueCodec{}
	}
	size := aper.SizeConstraint{Lower: (aper.ListBounds{Lower: 1, Upper: 256}).Lower, Upper: (aper.ListBounds{Lower: 1, Upper: 256}).Upper, HasLower: true, HasUpper: true}
	return OverloadStopIEValueERABIEContainerListValueCodec{decode: func(data []byte, options aper.DecodeState) (OverloadStopIEValueERABIEContainerList, error) {
		bb := aper.NewCompleteDecodeBuffer(data, options)
		if err := bb.SetDecodeOptionsAligned(options); err != nil {
			return nil, err
		}
		var fields OverloadStopIEValueERABIEContainerList
		_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
			for i := int64(0); i < length; i++ {
				var field OverloadStopIEField
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
			return nil, runtime.WrapDecodePath(err, "OverloadStopIEValueERABIEContainerList")
		}
		if _, err := aper.CaptureFinalBits(bb, "OverloadStopIEValueERABIEContainerList"); err != nil {
			return nil, runtime.WrapDecodePath(err, "OverloadStopIEValueERABIEContainerList")
		}
		return fields, nil
	}, encode: func(value OverloadStopIEValueERABIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return codec.encode(OverloadStopIEContainer(value), fresh, budget)
	}, capture: func(v OverloadStopIEValueERABIEContainerList, options aper.DecodeState) (OverloadStopIEValueERABIEContainerList, aper.Snapshot) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeOverloadStopIEValueCaptureS1APERABIEContainerList(&v, &s)
		var root aper.Snapshot
		s.End(f, &root,

			false)
		return v, root
	}, compare: func(v OverloadStopIEValueERABIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
	) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		BridgeOverloadStopIEValueCompareS1APERABIEContainerList(&v, &s)
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

// LastVisitedEUTRANCellInformationExtIEsValueExtensionFieldTableCodec constructs the ProtocolExtensionField {{LastVisitedEUTRANCellInformation-ExtIEs}} codec of TS 36.413.
func LastVisitedEUTRANCellInformationExtIEsValueExtensionFieldTableCodec(table s00.LastVisitedEUTRANCellInformationExtIEsValueExtensionTable) LastVisitedEUTRANCellInformationExtIEsExtFieldValueCodec {
	if !*s00.BridgeLastVisitedEUTRANCellInformationExtIEsValueExtensionTableFieldBound(&table) {
		return LastVisitedEUTRANCellInformationExtIEsExtFieldValueCodec{}
	}
	return LastVisitedEUTRANCellInformationExtIEsExtFieldValueCodec{decode: func(data []byte, options aper.DecodeState) (LastVisitedEUTRANCellInformationExtIEsExtField, error) {
		var field LastVisitedEUTRANCellInformationExtIEsExtField
		bb := aper.NewCompleteDecodeBuffer(data, options)
		if err := bb.SetDecodeOptionsAligned(options); err != nil {
			return field, err
		}
		if err := field.unmarshalAPERFrom(bb); err != nil {
			return field, runtime.WrapDecodePath(err, "LastVisitedEUTRANCellInformationExtIEsExtField")
		}
		if _, err := aper.CaptureFinalBits(bb, "LastVisitedEUTRANCellInformationExtIEsExtField"); err != nil {
			return field, runtime.WrapDecodePath(err, "LastVisitedEUTRANCellInformationExtIEsExtField")
		}
		return field, nil
	}, encode: func(field LastVisitedEUTRANCellInformationExtIEsExtField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		bb := aper.NewBudgetBuffer(budget)
		if err := field.marshalAPERTo(bb, fresh); err != nil {
			return nil, err
		}
		return bb.CompleteBytes(), nil
	}, capture: func(v LastVisitedEUTRANCellInformationExtIEsExtField, options aper.DecodeState) (LastVisitedEUTRANCellInformationExtIEsExtField, aper.Snapshot,
	) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeLastVisitedEUTRANCellInformationExtIEsValueCaptureS1APProtocolExtensionField(&v, &s)
		var root aper.Snapshot
		s.
			End(f, &root, false)
		return v, root
	}, compare: func(v LastVisitedEUTRANCellInformationExtIEsExtField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
	) {
		s := aper.NewSemanticComparison(root, budget)
		f :=
			s.Begin()
		BridgeLastVisitedEUTRANCellInformationExtIEsValueCompareS1APProtocolExtensionField(&v, &s)
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

// MDTConfigurationExtIEsValueExtensionFieldTableCodec constructs the ProtocolExtensionField {{MDT-Configuration-ExtIEs}} codec of TS 36.413.
func MDTConfigurationExtIEsValueExtensionFieldTableCodec(table s00.MDTConfigurationExtIEsValueExtensionTable) MDTConfigurationExtIEsExtFieldValueCodec {
	if !*s00.BridgeMDTConfigurationExtIEsValueExtensionTableFieldBound(&table) {
		return MDTConfigurationExtIEsExtFieldValueCodec{}
	}
	return MDTConfigurationExtIEsExtFieldValueCodec{decode: func(data []byte, options aper.DecodeState) (MDTConfigurationExtIEsExtField, error) {
		var field MDTConfigurationExtIEsExtField
		bb := aper.NewCompleteDecodeBuffer(data, options)
		if err := bb.SetDecodeOptionsAligned(options); err != nil {
			return field, err
		}
		if err := field.unmarshalAPERFrom(bb); err != nil {
			return field, runtime.WrapDecodePath(err, "MDTConfigurationExtIEsExtField")
		}
		if _, err := aper.CaptureFinalBits(bb, "MDTConfigurationExtIEsExtField"); err != nil {
			return field, runtime.WrapDecodePath(err, "MDTConfigurationExtIEsExtField")
		}
		return field, nil
	}, encode: func(field MDTConfigurationExtIEsExtField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		bb := aper.NewBudgetBuffer(budget)
		if err := field.marshalAPERTo(bb, fresh); err != nil {
			return nil, err
		}
		return bb.CompleteBytes(), nil
	}, capture: func(v MDTConfigurationExtIEsExtField, options aper.DecodeState) (MDTConfigurationExtIEsExtField, aper.Snapshot,
	) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeMDTConfigurationExtIEsValueCaptureS1APProtocolExtensionField(&v, &s)
		var root aper.Snapshot
		s.
			End(f, &root, false)
		return v, root
	}, compare: func(v MDTConfigurationExtIEsExtField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
	) {
		s := aper.NewSemanticComparison(root, budget)
		f :=
			s.Begin()
		BridgeMDTConfigurationExtIEsValueCompareS1APProtocolExtensionField(&v, &s)
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

// LastVisitedEUTRANCellInformationExtIEsValueExtensionTableCodec constructs the ProtocolExtensionContainer {{LastVisitedEUTRANCellInformation-ExtIEs}} codec of TS 36.413.
func LastVisitedEUTRANCellInformationExtIEsValueExtensionTableCodec(table s00.LastVisitedEUTRANCellInformationExtIEsValueExtensionTable, bounds aper.ListBounds) LastVisitedEUTRANCellInformationExtIEsExtContainerValueCodec {
	if !*s00.BridgeLastVisitedEUTRANCellInformationExtIEsValueExtensionTableFieldBound(&table) {
		return LastVisitedEUTRANCellInformationExtIEsExtContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return LastVisitedEUTRANCellInformationExtIEsExtContainerValueCodec{decode: func(data []byte, options aper.DecodeState) (LastVisitedEUTRANCellInformationExtIEsExtContainer, error) {
		bb := aper.NewCompleteDecodeBuffer(data, options)
		if err := bb.SetDecodeOptionsAligned(options); err != nil {
			return nil, err
		}
		var fields LastVisitedEUTRANCellInformationExtIEsExtContainer
		_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
			for i := int64(0); i < length; i++ {
				var field LastVisitedEUTRANCellInformationExtIEsExtField
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
			return nil, runtime.WrapDecodePath(err, "LastVisitedEUTRANCellInformationExtIEsExtContainer")
		}
		if _, err := aper.CaptureFinalBits(bb, "LastVisitedEUTRANCellInformationExtIEsExtContainer"); err != nil {
			return nil, runtime.WrapDecodePath(err, "LastVisitedEUTRANCellInformationExtIEsExtContainer")
		}
		return fields, nil
	},
		encode: func(fields LastVisitedEUTRANCellInformationExtIEsExtContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
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
		}, capture: func(v LastVisitedEUTRANCellInformationExtIEsExtContainer, options aper.DecodeState) (LastVisitedEUTRANCellInformationExtIEsExtContainer, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeLastVisitedEUTRANCellInformationExtIEsValueCaptureS1APProtocolExtensionContainer(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}, compare: func(v LastVisitedEUTRANCellInformationExtIEsExtContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeLastVisitedEUTRANCellInformationExtIEsValueCompareS1APProtocolExtensionContainer(&v, &s)

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

// MDTConfigurationExtIEsValueExtensionTableCodec constructs the ProtocolExtensionContainer {{MDT-Configuration-ExtIEs}} codec of TS 36.413.
func MDTConfigurationExtIEsValueExtensionTableCodec(table s00.MDTConfigurationExtIEsValueExtensionTable, bounds aper.ListBounds) MDTConfigurationExtIEsExtContainerValueCodec {
	if !*s00.BridgeMDTConfigurationExtIEsValueExtensionTableFieldBound(&table) {
		return MDTConfigurationExtIEsExtContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return MDTConfigurationExtIEsExtContainerValueCodec{decode: func(data []byte, options aper.DecodeState) (MDTConfigurationExtIEsExtContainer, error) {
		bb := aper.NewCompleteDecodeBuffer(data, options)
		if err := bb.SetDecodeOptionsAligned(options); err != nil {
			return nil, err
		}
		var fields MDTConfigurationExtIEsExtContainer
		_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
			for i := int64(0); i < length; i++ {
				var field MDTConfigurationExtIEsExtField
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
			return nil, runtime.WrapDecodePath(err, "MDTConfigurationExtIEsExtContainer")
		}
		if _, err := aper.CaptureFinalBits(bb, "MDTConfigurationExtIEsExtContainer"); err != nil {
			return nil, runtime.WrapDecodePath(err, "MDTConfigurationExtIEsExtContainer")
		}
		return fields, nil
	},
		encode: func(fields MDTConfigurationExtIEsExtContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
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
		}, capture: func(v MDTConfigurationExtIEsExtContainer, options aper.DecodeState) (MDTConfigurationExtIEsExtContainer, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeMDTConfigurationExtIEsValueCaptureS1APProtocolExtensionContainer(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}, compare: func(v MDTConfigurationExtIEsExtContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeMDTConfigurationExtIEsValueCompareS1APProtocolExtensionContainer(&v, &s)

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

// OverloadStartIEValueIEFieldTableCodec constructs the ProtocolIE-Field {{OverloadStartIEs}} codec of TS 36.413.
func OverloadStartIEValueIEFieldTableCodec(table s00.OverloadStartIEValueIETable) OverloadStartIEFieldValueCodec {
	if !*s00.BridgeOverloadStartIEValueIETableFieldBound(&table) {
		return OverloadStartIEFieldValueCodec{}
	}
	return OverloadStartIEFieldValueCodec{decode: func(data []byte, options aper.DecodeState) (OverloadStartIEField, error) {
		var field OverloadStartIEField
		bb := aper.NewCompleteDecodeBuffer(data, options)
		if err := bb.SetDecodeOptionsAligned(options); err != nil {
			return field, err
		}
		if err := field.unmarshalAPERFrom(bb); err != nil {
			return field, runtime.WrapDecodePath(err, "OverloadStartIEField")
		}
		if _, err := aper.CaptureFinalBits(bb, "OverloadStartIEField"); err != nil {
			return field, runtime.WrapDecodePath(err, "OverloadStartIEField")
		}
		return field, nil
	}, encode: func(field OverloadStartIEField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		bb := aper.NewBudgetBuffer(budget)
		if err := field.marshalAPERTo(bb, fresh); err != nil {
			return nil, err
		}
		return bb.CompleteBytes(), nil
	}, capture: func(v OverloadStartIEField, options aper.DecodeState) (OverloadStartIEField, aper.Snapshot,
	) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeOverloadStartIEValueCaptureS1APProtocolIEField(&v, &s)
		var root aper.Snapshot
		s.End(f, &root, false)
		return v, root
	}, compare: func(v OverloadStartIEField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

	) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		BridgeOverloadStartIEValueCompareS1APProtocolIEField(&v, &s)
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

// OverloadStopIEValueIEFieldTableCodec constructs the ProtocolIE-Field {{OverloadStopIEs}} codec of TS 36.413.
func OverloadStopIEValueIEFieldTableCodec(table s00.OverloadStopIEValueIETable) OverloadStopIEFieldValueCodec {
	if !*s00.BridgeOverloadStopIEValueIETableFieldBound(&table) {
		return OverloadStopIEFieldValueCodec{}
	}
	return OverloadStopIEFieldValueCodec{decode: func(data []byte, options aper.DecodeState) (OverloadStopIEField, error) {
		var field OverloadStopIEField
		bb := aper.NewCompleteDecodeBuffer(data, options)
		if err := bb.SetDecodeOptionsAligned(options); err != nil {
			return field, err
		}
		if err := field.unmarshalAPERFrom(bb); err != nil {
			return field, runtime.WrapDecodePath(err, "OverloadStopIEField")
		}
		if _, err := aper.CaptureFinalBits(bb, "OverloadStopIEField"); err != nil {
			return field, runtime.WrapDecodePath(err, "OverloadStopIEField")
		}
		return field, nil
	}, encode: func(field OverloadStopIEField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		bb := aper.NewBudgetBuffer(budget)
		if err := field.marshalAPERTo(bb, fresh); err != nil {
			return nil, err
		}
		return bb.CompleteBytes(), nil
	}, capture: func(v OverloadStopIEField, options aper.DecodeState) (OverloadStopIEField, aper.Snapshot,
	) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeOverloadStopIEValueCaptureS1APProtocolIEField(&v, &s)
		var root aper.Snapshot
		s.End(f, &root, false)
		return v, root
	}, compare: func(v OverloadStopIEField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

	) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		BridgeOverloadStopIEValueCompareS1APProtocolIEField(&v, &s)
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

// OverloadStartIEValueIETableCodec constructs the ProtocolIE-Container {{OverloadStartIEs}} codec of TS 36.413.
func OverloadStartIEValueIETableCodec(table s00.OverloadStartIEValueIETable, bounds aper.ListBounds) OverloadStartIEContainerValueCodec {
	if !*s00.BridgeOverloadStartIEValueIETableFieldBound(&table) {
		return OverloadStartIEContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return OverloadStartIEContainerValueCodec{decode: func(data []byte, options aper.DecodeState) (OverloadStartIEContainer, error) {
		bb := aper.NewCompleteDecodeBuffer(data, options)
		if err := bb.SetDecodeOptionsAligned(options); err != nil {
			return nil, err
		}
		var fields OverloadStartIEContainer
		_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
			for i := int64(0); i < length; i++ {
				var field OverloadStartIEField
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
			return nil, runtime.WrapDecodePath(err, "OverloadStartIEContainer")
		}
		if _, err := aper.CaptureFinalBits(bb, "OverloadStartIEContainer"); err != nil {
			return nil, runtime.WrapDecodePath(err, "OverloadStartIEContainer")
		}
		return fields, nil
	},
		encode: func(fields OverloadStartIEContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
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
		}, capture: func(v OverloadStartIEContainer, options aper.DecodeState) (OverloadStartIEContainer, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeOverloadStartIEValueCaptureS1APProtocolIEContainer(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,

				false)
			return v, root
		}, compare: func(v OverloadStartIEContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeOverloadStartIEValueCompareS1APProtocolIEContainer(&v, &s)
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

// OverloadStopIEValueIETableCodec constructs the ProtocolIE-Container {{OverloadStopIEs}} codec of TS 36.413.
func OverloadStopIEValueIETableCodec(table s00.OverloadStopIEValueIETable, bounds aper.ListBounds) OverloadStopIEContainerValueCodec {
	if !*s00.BridgeOverloadStopIEValueIETableFieldBound(&table) {
		return OverloadStopIEContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return OverloadStopIEContainerValueCodec{decode: func(data []byte, options aper.DecodeState) (OverloadStopIEContainer, error) {
		bb := aper.NewCompleteDecodeBuffer(data, options)
		if err := bb.SetDecodeOptionsAligned(options); err != nil {
			return nil, err
		}
		var fields OverloadStopIEContainer
		_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
			for i := int64(0); i < length; i++ {
				var field OverloadStopIEField
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
			return nil, runtime.WrapDecodePath(err, "OverloadStopIEContainer")
		}
		if _, err := aper.CaptureFinalBits(bb, "OverloadStopIEContainer"); err != nil {
			return nil, runtime.WrapDecodePath(err, "OverloadStopIEContainer")
		}
		return fields, nil
	},
		encode: func(fields OverloadStopIEContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
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
		}, capture: func(v OverloadStopIEContainer, options aper.DecodeState) (OverloadStopIEContainer, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeOverloadStopIEValueCaptureS1APProtocolIEContainer(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,

				false)
			return v, root
		}, compare: func(v OverloadStopIEContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeOverloadStopIEValueCompareS1APProtocolIEContainer(&v, &s)
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

// OverloadStartIEValueProtocolErrorIEContainerListCodec constructs the ProtocolError-IE-ContainerList {{OverloadStartIEs}} codec of TS 36.413.
func OverloadStartIEValueProtocolErrorIEContainerListCodec(table s00.OverloadStartIEValueIETable) OverloadStartIEValueProtocolErrorIEContainerListValueCodec {
	codec := OverloadStartIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if codec.decode == nil {
		return OverloadStartIEValueProtocolErrorIEContainerListValueCodec{}
	}
	size := aper.SizeConstraint{Lower: (aper.ListBounds{Lower: 1, Upper: 256}).Lower, Upper: (aper.ListBounds{Lower: 1, Upper: 256}).Upper, HasLower: true, HasUpper: true}
	return OverloadStartIEValueProtocolErrorIEContainerListValueCodec{decode: func(data []byte, options aper.DecodeState) (OverloadStartIEValueProtocolErrorIEContainerList, error) {
		bb := aper.NewCompleteDecodeBuffer(data, options)
		if err := bb.SetDecodeOptionsAligned(options); err != nil {
			return nil, err
		}
		var fields OverloadStartIEValueProtocolErrorIEContainerList
		_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
			for i := int64(0); i < length; i++ {
				var field OverloadStartIEField
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
			return nil, runtime.WrapDecodePath(err, "OverloadStartIEValueProtocolErrorIEContainerList")
		}
		if _, err := aper.CaptureFinalBits(bb, "OverloadStartIEValueProtocolErrorIEContainerList"); err != nil {
			return nil, runtime.WrapDecodePath(err, "OverloadStartIEValueProtocolErrorIEContainerList")
		}
		return fields, nil
	}, encode: func(value OverloadStartIEValueProtocolErrorIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return codec.encode(OverloadStartIEContainer(value), fresh, budget)
	}, capture: func(v OverloadStartIEValueProtocolErrorIEContainerList, options aper.DecodeState) (OverloadStartIEValueProtocolErrorIEContainerList, aper.Snapshot,
	) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeOverloadStartIEValueCaptureS1APProtocolErrorIEContainerList(&v, &s)
		var root aper.Snapshot

		s.End(f, &root, false)
		return v, root
	}, compare: func(v OverloadStartIEValueProtocolErrorIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

	) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		BridgeOverloadStartIEValueCompareS1APProtocolErrorIEContainerList(
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

// OverloadStopIEValueProtocolErrorIEContainerListCodec constructs the ProtocolError-IE-ContainerList {{OverloadStopIEs}} codec of TS 36.413.
func OverloadStopIEValueProtocolErrorIEContainerListCodec(table s00.OverloadStopIEValueIETable) OverloadStopIEValueProtocolErrorIEContainerListValueCodec {
	codec := OverloadStopIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if codec.decode == nil {
		return OverloadStopIEValueProtocolErrorIEContainerListValueCodec{}
	}
	size := aper.SizeConstraint{Lower: (aper.ListBounds{Lower: 1, Upper: 256}).Lower, Upper: (aper.ListBounds{Lower: 1, Upper: 256}).Upper, HasLower: true, HasUpper: true}
	return OverloadStopIEValueProtocolErrorIEContainerListValueCodec{decode: func(data []byte, options aper.DecodeState) (OverloadStopIEValueProtocolErrorIEContainerList, error) {
		bb := aper.NewCompleteDecodeBuffer(data, options)
		if err := bb.SetDecodeOptionsAligned(options); err != nil {
			return nil, err
		}
		var fields OverloadStopIEValueProtocolErrorIEContainerList
		_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
			for i := int64(0); i < length; i++ {
				var field OverloadStopIEField
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
			return nil, runtime.WrapDecodePath(err, "OverloadStopIEValueProtocolErrorIEContainerList")
		}
		if _, err := aper.CaptureFinalBits(bb, "OverloadStopIEValueProtocolErrorIEContainerList"); err != nil {
			return nil, runtime.WrapDecodePath(err, "OverloadStopIEValueProtocolErrorIEContainerList")
		}
		return fields, nil
	}, encode: func(value OverloadStopIEValueProtocolErrorIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return codec.encode(OverloadStopIEContainer(value), fresh, budget)
	}, capture: func(v OverloadStopIEValueProtocolErrorIEContainerList, options aper.DecodeState) (OverloadStopIEValueProtocolErrorIEContainerList, aper.Snapshot,
	) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeOverloadStopIEValueCaptureS1APProtocolErrorIEContainerList(&v, &s)
		var root aper.Snapshot

		s.End(f, &root, false)
		return v, root
	}, compare: func(v OverloadStopIEValueProtocolErrorIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

	) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		BridgeOverloadStopIEValueCompareS1APProtocolErrorIEContainerList(
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

// OverloadStartIEValueProtocolIEContainerListCodec constructs a codec for ProtocolIE-ContainerList with IEsSetParam = {OverloadStartIEs} of TS 36.413, with lowerBound and upperBound supplied by its arguments.
func OverloadStartIEValueProtocolIEContainerListCodec(table s00.OverloadStartIEValueIETable, bounds aper.ListBounds) OverloadStartIEValueProtocolIEContainerListValueCodec {
	codec := OverloadStartIEValueIETableCodec(table, bounds)
	if codec.decode == nil {
		return OverloadStartIEValueProtocolIEContainerListValueCodec{}
	}
	size := aper.SizeConstraint{Lower: (bounds).Lower, Upper: (bounds).Upper, HasLower: true, HasUpper: true}
	return OverloadStartIEValueProtocolIEContainerListValueCodec{decode: func(data []byte, options aper.DecodeState) (OverloadStartIEValueProtocolIEContainerList, error) {
		bb := aper.NewCompleteDecodeBuffer(data, options)
		if err := bb.SetDecodeOptionsAligned(options); err != nil {
			return nil, err
		}
		var fields OverloadStartIEValueProtocolIEContainerList
		_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
			for i := int64(0); i < length; i++ {
				var field OverloadStartIEField
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
			return nil, runtime.WrapDecodePath(err, "OverloadStartIEValueProtocolIEContainerList")
		}
		if _, err := aper.CaptureFinalBits(bb, "OverloadStartIEValueProtocolIEContainerList"); err != nil {
			return nil, runtime.WrapDecodePath(err, "OverloadStartIEValueProtocolIEContainerList")
		}
		return fields, nil
	}, encode: func(value OverloadStartIEValueProtocolIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return codec.encode(OverloadStartIEContainer(value), fresh, budget)
	}, capture: func(v OverloadStartIEValueProtocolIEContainerList, options aper.DecodeState) (OverloadStartIEValueProtocolIEContainerList, aper.Snapshot,
	) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeOverloadStartIEValueCaptureS1APProtocolIEContainerList(&v, &s)
		var root aper.Snapshot
		s.
			End(f, &root, false)
		return v, root
	}, compare: func(v OverloadStartIEValueProtocolIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
	) {
		s := aper.NewSemanticComparison(root, budget)
		f :=
			s.Begin()
		BridgeOverloadStartIEValueCompareS1APProtocolIEContainerList(&v, &s)
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

// OverloadStopIEValueProtocolIEContainerListCodec constructs a codec for ProtocolIE-ContainerList with IEsSetParam = {OverloadStopIEs} of TS 36.413, with lowerBound and upperBound supplied by its arguments.
func OverloadStopIEValueProtocolIEContainerListCodec(table s00.OverloadStopIEValueIETable, bounds aper.ListBounds) OverloadStopIEValueProtocolIEContainerListValueCodec {
	codec := OverloadStopIEValueIETableCodec(table, bounds)
	if codec.decode == nil {
		return OverloadStopIEValueProtocolIEContainerListValueCodec{}
	}
	size := aper.SizeConstraint{Lower: (bounds).Lower, Upper: (bounds).Upper, HasLower: true, HasUpper: true}
	return OverloadStopIEValueProtocolIEContainerListValueCodec{decode: func(data []byte, options aper.DecodeState) (OverloadStopIEValueProtocolIEContainerList, error) {
		bb := aper.NewCompleteDecodeBuffer(data, options)
		if err := bb.SetDecodeOptionsAligned(options); err != nil {
			return nil, err
		}
		var fields OverloadStopIEValueProtocolIEContainerList
		_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
			for i := int64(0); i < length; i++ {
				var field OverloadStopIEField
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
			return nil, runtime.WrapDecodePath(err, "OverloadStopIEValueProtocolIEContainerList")
		}
		if _, err := aper.CaptureFinalBits(bb, "OverloadStopIEValueProtocolIEContainerList"); err != nil {
			return nil, runtime.WrapDecodePath(err, "OverloadStopIEValueProtocolIEContainerList")
		}
		return fields, nil
	}, encode: func(value OverloadStopIEValueProtocolIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return codec.encode(OverloadStopIEContainer(value), fresh, budget)
	}, capture: func(v OverloadStopIEValueProtocolIEContainerList, options aper.DecodeState) (OverloadStopIEValueProtocolIEContainerList, aper.Snapshot,
	) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeOverloadStopIEValueCaptureS1APProtocolIEContainerList(&v, &s)
		var root aper.Snapshot
		s.
			End(f, &root, false)
		return v, root
	}, compare: func(v OverloadStopIEValueProtocolIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
	) {
		s := aper.NewSemanticComparison(root, budget)
		f :=
			s.Begin()
		BridgeOverloadStopIEValueCompareS1APProtocolIEContainerList(&v, &s)
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

// lastVisitedEUTRANCellInformationExtIEsValueProtocolOpenValue is the concrete protocolOpenValue[LastVisitedEUTRANCellInformationExtIEsValue].
type LastVisitedEUTRANCellInformationExtIEsValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) LastVisitedEUTRANCellInformationExtIEsValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (LastVisitedEUTRANCellInformationExtIEsValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

func BridgeLastVisitedEUTRANCellInformationExtIEsValueCaptureS1APProtocolExtensionField(v *LastVisitedEUTRANCellInformationExtIEsExtField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolExtensionID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.ExtensionValue = v.ExtensionValue.captureSemantics(*s)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeLastVisitedEUTRANCellInformationExtIEsValueCompareS1APProtocolExtensionField(v *LastVisitedEUTRANCellInformationExtIEsExtField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s02.BridgeCompareS1APProtocolExtensionID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = v.ExtensionValue.compareSemantics(*s)
	s.End(f, v.replay, v.withoutReplay)
}

// mDTConfigurationExtIEsValueProtocolOpenValue is the concrete protocolOpenValue[MDTConfigurationExtIEsValue].
type MDTConfigurationExtIEsValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) MDTConfigurationExtIEsValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (MDTConfigurationExtIEsValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

func BridgeMDTConfigurationExtIEsValueCaptureS1APProtocolExtensionField(v *MDTConfigurationExtIEsExtField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolExtensionID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.ExtensionValue = v.ExtensionValue.captureSemantics(*s)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeMDTConfigurationExtIEsValueCompareS1APProtocolExtensionField(v *MDTConfigurationExtIEsExtField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s02.BridgeCompareS1APProtocolExtensionID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = v.ExtensionValue.compareSemantics(*s)
	s.End(f, v.replay, v.withoutReplay)
}

// overloadStartIEValueProtocolOpenValue is the concrete protocolOpenValue[OverloadStartIEValue].
type OverloadStartIEValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) OverloadStartIEValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (OverloadStartIEValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

func BridgeOverloadStartIEValueCaptureS1APProtocolIEField(v *OverloadStartIEField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolIEID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.Value = v.Value.captureSemantics(*s)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeOverloadStartIEValueCompareS1APProtocolIEField(v *OverloadStartIEField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s02.BridgeCompareS1APProtocolIEID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = v.Value.compareSemantics(*s)
	s.End(f, v.replay, v.withoutReplay)
}

// overloadStopIEValueProtocolOpenValue is the concrete protocolOpenValue[OverloadStopIEValue].
type OverloadStopIEValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) OverloadStopIEValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (OverloadStopIEValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

func BridgeOverloadStopIEValueCaptureS1APProtocolIEField(v *OverloadStopIEField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolIEID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.Value = v.Value.captureSemantics(*s)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeOverloadStopIEValueCompareS1APProtocolIEField(v *OverloadStopIEField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s02.BridgeCompareS1APProtocolIEID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = v.Value.compareSemantics(*s)
	s.End(f, v.replay, v.withoutReplay)
}

// LastVisitedCellItemAPERValue is the concrete APERValue[LastVisitedCellItem].
type LastVisitedCellItemAPERValue struct {
	context s00.BridgeCodecContext
	Value   LastVisitedCellItem

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v LastVisitedCellItemAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v LastVisitedCellItemAPERValue) WithoutReplay() LastVisitedCellItemAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// LastVisitedEUTRANCellInformationAPERValue is the concrete APERValue[LastVisitedEUTRANCellInformation].
type LastVisitedEUTRANCellInformationAPERValue struct {
	context s00.BridgeCodecContext
	Value   LastVisitedEUTRANCellInformation

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v LastVisitedEUTRANCellInformationAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v LastVisitedEUTRANCellInformationAPERValue) WithoutReplay() LastVisitedEUTRANCellInformationAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// OverloadStartAPERValue is the concrete APERValue[OverloadStart].
type OverloadStartAPERValue struct {
	context s00.BridgeCodecContext
	Value   OverloadStart

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v OverloadStartAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v OverloadStartAPERValue) WithoutReplay() OverloadStartAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// OverloadStopAPERValue is the concrete APERValue[OverloadStop].
type OverloadStopAPERValue struct {
	context s00.BridgeCodecContext
	Value   OverloadStop

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v OverloadStopAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v OverloadStopAPERValue) WithoutReplay() OverloadStopAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// SourceeNBToTargeteNBTransparentContainerAPERValue is the concrete APERValue[SourceeNBToTargeteNBTransparentContainer].
type SourceeNBToTargeteNBTransparentContainerAPERValue struct {
	context s00.BridgeCodecContext
	Value   SourceeNBToTargeteNBTransparentContainer

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v SourceeNBToTargeteNBTransparentContainerAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v SourceeNBToTargeteNBTransparentContainerAPERValue) WithoutReplay() SourceeNBToTargeteNBTransparentContainerAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// UEHistoryInformationAPERValue is the concrete APERValue[UEHistoryInformation].
type UEHistoryInformationAPERValue struct {
	context s00.BridgeCodecContext
	Value   UEHistoryInformation

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v UEHistoryInformationAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v UEHistoryInformationAPERValue) WithoutReplay() UEHistoryInformationAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// LastVisitedEUTRANCellInformationExtIEsIEField uses the ProtocolIE-Field shape for object set LastVisitedEUTRANCellInformation-ExtIEs of TS 36.413.
type LastVisitedEUTRANCellInformationExtIEsIEField struct {
	withoutReplay bool
	replay        aper.Snapshot
	stream        aper.WireSpan
	Id            s00.ProtocolIEID
	Criticality   s00.Criticality
	Value         LastVisitedEUTRANCellInformationExtIEsValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v LastVisitedEUTRANCellInformationExtIEsIEField) WithoutReplay() LastVisitedEUTRANCellInformationExtIEsIEField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *LastVisitedEUTRANCellInformationExtIEsIEField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *LastVisitedEUTRANCellInformationExtIEsIEField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
func (v *LastVisitedEUTRANCellInformationExtIEsIEField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolIEField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = LastVisitedEUTRANCellInformationExtIEsIEField{}
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
	var zero LastVisitedEUTRANCellInformationExtIEsValue

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

// LastVisitedEUTRANCellInformationExtIEsIEContainer uses the ProtocolIE-Container shape for object set LastVisitedEUTRANCellInformation-ExtIEs of TS 36.413: a list of LastVisitedEUTRANCellInformationExtIEsIEField values.
type LastVisitedEUTRANCellInformationExtIEsIEContainer []LastVisitedEUTRANCellInformationExtIEsIEField

// TS 36.413 V19.2.0 §§9.3.3–9.3.4 supply the selected object-set order and
// presence. §§10.3.1–10.3.6 define abstract-syntax diagnostics. Unknown IEs do
// not determine the order of known rows.
func BridgeLastVisitedEUTRANCellInformationExtIEsValueValidateS1APIEContainer(fields LastVisitedEUTRANCellInformationExtIEsIEContainer, rows []s00.FieldInfo, path string, budget *aper.DecodeBudget,

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

// MDTConfigurationExtIEsIEField uses the ProtocolIE-Field shape for object set MDT-Configuration-ExtIEs of TS 36.413.
type MDTConfigurationExtIEsIEField struct {
	withoutReplay bool
	replay        aper.Snapshot
	stream        aper.WireSpan
	Id            s00.ProtocolIEID
	Criticality   s00.Criticality
	Value         MDTConfigurationExtIEsValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v MDTConfigurationExtIEsIEField) WithoutReplay() MDTConfigurationExtIEsIEField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *MDTConfigurationExtIEsIEField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *MDTConfigurationExtIEsIEField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
func (v *MDTConfigurationExtIEsIEField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolIEField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = MDTConfigurationExtIEsIEField{}
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
	var zero MDTConfigurationExtIEsValue

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

// MDTConfigurationExtIEsIEContainer uses the ProtocolIE-Container shape for object set MDT-Configuration-ExtIEs of TS 36.413: a list of MDTConfigurationExtIEsIEField values.
type MDTConfigurationExtIEsIEContainer []MDTConfigurationExtIEsIEField

// TS 36.413 V19.2.0 §§9.3.3–9.3.4 supply the selected object-set order and
// presence. §§10.3.1–10.3.6 define abstract-syntax diagnostics. Unknown IEs do
// not determine the order of known rows.
func BridgeMDTConfigurationExtIEsValueValidateS1APIEContainer(fields MDTConfigurationExtIEsIEContainer, rows []s00.FieldInfo, path string, budget *aper.DecodeBudget,

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

// OverloadStartIEValueERABIEContainerListValueCodec is the concrete ValueCodec[OverloadStartIEValueERABIEContainerList].
type OverloadStartIEValueERABIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (OverloadStartIEValueERABIEContainerList, error)
	encode  func(OverloadStartIEValueERABIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(OverloadStartIEValueERABIEContainerList, aper.DecodeState) (OverloadStartIEValueERABIEContainerList, aper.Snapshot)
	compare func(OverloadStartIEValueERABIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c OverloadStartIEValueERABIEContainerListValueCodec) New(value OverloadStartIEValueERABIEContainerList) (OverloadStartIEValueERABIEContainerListAPERValue, error) {
	if c.encode == nil {
		return OverloadStartIEValueERABIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return OverloadStartIEValueERABIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return OverloadStartIEValueERABIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return OverloadStartIEValueERABIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c OverloadStartIEValueERABIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (OverloadStartIEValueERABIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return OverloadStartIEValueERABIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return OverloadStartIEValueERABIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return OverloadStartIEValueERABIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return OverloadStartIEValueERABIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c OverloadStartIEValueERABIEContainerListValueCodec) EncodeAPER(value OverloadStartIEValueERABIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c OverloadStartIEValueERABIEContainerListValueCodec) encodeBudgetValue(value OverloadStartIEValueERABIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c OverloadStartIEValueERABIEContainerListValueCodec) encodeChanged(value OverloadStartIEValueERABIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// OverloadStartIEValueERABIEContainerList is E-RAB-IE-ContainerList {{OverloadStartIEs}} of TS 36.413: a list of information element fields.
type OverloadStartIEValueERABIEContainerList []OverloadStartIEValueProtocolIESingleContainer

func BridgeOverloadStartIEValueCaptureS1APERABIEContainerList(v *OverloadStartIEValueERABIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeOverloadStartIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeOverloadStartIEValueCompareS1APERABIEContainerList(v *OverloadStartIEValueERABIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeOverloadStartIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}

// OverloadStopIEValueERABIEContainerListValueCodec is the concrete ValueCodec[OverloadStopIEValueERABIEContainerList].
type OverloadStopIEValueERABIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (OverloadStopIEValueERABIEContainerList, error)
	encode  func(OverloadStopIEValueERABIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(OverloadStopIEValueERABIEContainerList, aper.DecodeState) (OverloadStopIEValueERABIEContainerList, aper.Snapshot)
	compare func(OverloadStopIEValueERABIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c OverloadStopIEValueERABIEContainerListValueCodec) New(value OverloadStopIEValueERABIEContainerList) (OverloadStopIEValueERABIEContainerListAPERValue, error) {
	if c.encode == nil {
		return OverloadStopIEValueERABIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return OverloadStopIEValueERABIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return OverloadStopIEValueERABIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return OverloadStopIEValueERABIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c OverloadStopIEValueERABIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (OverloadStopIEValueERABIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return OverloadStopIEValueERABIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return OverloadStopIEValueERABIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return OverloadStopIEValueERABIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return OverloadStopIEValueERABIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c OverloadStopIEValueERABIEContainerListValueCodec) EncodeAPER(value OverloadStopIEValueERABIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c OverloadStopIEValueERABIEContainerListValueCodec) encodeBudgetValue(value OverloadStopIEValueERABIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c OverloadStopIEValueERABIEContainerListValueCodec) encodeChanged(value OverloadStopIEValueERABIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// OverloadStopIEValueERABIEContainerList is E-RAB-IE-ContainerList {{OverloadStopIEs}} of TS 36.413: a list of information element fields.
type OverloadStopIEValueERABIEContainerList []OverloadStopIEValueProtocolIESingleContainer

func BridgeOverloadStopIEValueCaptureS1APERABIEContainerList(v *OverloadStopIEValueERABIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeOverloadStopIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeOverloadStopIEValueCompareS1APERABIEContainerList(v *OverloadStopIEValueERABIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeOverloadStopIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}

// LastVisitedEUTRANCellInformationExtIEsExtFieldValueCodec is the concrete ValueCodec[LastVisitedEUTRANCellInformationExtIEsExtField].
type LastVisitedEUTRANCellInformationExtIEsExtFieldValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (LastVisitedEUTRANCellInformationExtIEsExtField, error)
	encode  func(LastVisitedEUTRANCellInformationExtIEsExtField, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(LastVisitedEUTRANCellInformationExtIEsExtField, aper.DecodeState) (LastVisitedEUTRANCellInformationExtIEsExtField, aper.Snapshot)
	compare func(LastVisitedEUTRANCellInformationExtIEsExtField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c LastVisitedEUTRANCellInformationExtIEsExtFieldValueCodec) New(value LastVisitedEUTRANCellInformationExtIEsExtField) (LastVisitedEUTRANCellInformationExtIEsExtFieldAPERValue, error) {
	if c.encode == nil {
		return LastVisitedEUTRANCellInformationExtIEsExtFieldAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return LastVisitedEUTRANCellInformationExtIEsExtFieldAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return LastVisitedEUTRANCellInformationExtIEsExtFieldAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return LastVisitedEUTRANCellInformationExtIEsExtFieldAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c LastVisitedEUTRANCellInformationExtIEsExtFieldValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (LastVisitedEUTRANCellInformationExtIEsExtFieldAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return LastVisitedEUTRANCellInformationExtIEsExtFieldAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return LastVisitedEUTRANCellInformationExtIEsExtFieldAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return LastVisitedEUTRANCellInformationExtIEsExtFieldAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return LastVisitedEUTRANCellInformationExtIEsExtFieldAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c LastVisitedEUTRANCellInformationExtIEsExtFieldValueCodec) EncodeAPER(value LastVisitedEUTRANCellInformationExtIEsExtFieldAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c LastVisitedEUTRANCellInformationExtIEsExtFieldValueCodec) encodeBudgetValue(value LastVisitedEUTRANCellInformationExtIEsExtField, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c LastVisitedEUTRANCellInformationExtIEsExtFieldValueCodec) encodeChanged(value LastVisitedEUTRANCellInformationExtIEsExtField, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// MDTConfigurationExtIEsExtFieldValueCodec is the concrete ValueCodec[MDTConfigurationExtIEsExtField].
type MDTConfigurationExtIEsExtFieldValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (MDTConfigurationExtIEsExtField, error)
	encode  func(MDTConfigurationExtIEsExtField, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(MDTConfigurationExtIEsExtField, aper.DecodeState) (MDTConfigurationExtIEsExtField, aper.Snapshot)
	compare func(MDTConfigurationExtIEsExtField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c MDTConfigurationExtIEsExtFieldValueCodec) New(value MDTConfigurationExtIEsExtField) (MDTConfigurationExtIEsExtFieldAPERValue, error) {
	if c.encode == nil {
		return MDTConfigurationExtIEsExtFieldAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return MDTConfigurationExtIEsExtFieldAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return MDTConfigurationExtIEsExtFieldAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return MDTConfigurationExtIEsExtFieldAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c MDTConfigurationExtIEsExtFieldValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (MDTConfigurationExtIEsExtFieldAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return MDTConfigurationExtIEsExtFieldAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return MDTConfigurationExtIEsExtFieldAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return MDTConfigurationExtIEsExtFieldAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return MDTConfigurationExtIEsExtFieldAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c MDTConfigurationExtIEsExtFieldValueCodec) EncodeAPER(value MDTConfigurationExtIEsExtFieldAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c MDTConfigurationExtIEsExtFieldValueCodec) encodeBudgetValue(value MDTConfigurationExtIEsExtField, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c MDTConfigurationExtIEsExtFieldValueCodec) encodeChanged(value MDTConfigurationExtIEsExtField, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// LastVisitedEUTRANCellInformationExtIEsExtContainerValueCodec is the concrete ValueCodec[LastVisitedEUTRANCellInformationExtIEsExtContainer].
type LastVisitedEUTRANCellInformationExtIEsExtContainerValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (LastVisitedEUTRANCellInformationExtIEsExtContainer, error)
	encode  func(LastVisitedEUTRANCellInformationExtIEsExtContainer, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(LastVisitedEUTRANCellInformationExtIEsExtContainer, aper.DecodeState) (LastVisitedEUTRANCellInformationExtIEsExtContainer, aper.Snapshot)
	compare func(LastVisitedEUTRANCellInformationExtIEsExtContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c LastVisitedEUTRANCellInformationExtIEsExtContainerValueCodec) New(value LastVisitedEUTRANCellInformationExtIEsExtContainer) (LastVisitedEUTRANCellInformationExtIEsExtContainerAPERValue, error) {
	if c.encode == nil {
		return LastVisitedEUTRANCellInformationExtIEsExtContainerAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return LastVisitedEUTRANCellInformationExtIEsExtContainerAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return LastVisitedEUTRANCellInformationExtIEsExtContainerAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return LastVisitedEUTRANCellInformationExtIEsExtContainerAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c LastVisitedEUTRANCellInformationExtIEsExtContainerValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (LastVisitedEUTRANCellInformationExtIEsExtContainerAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return LastVisitedEUTRANCellInformationExtIEsExtContainerAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return LastVisitedEUTRANCellInformationExtIEsExtContainerAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return LastVisitedEUTRANCellInformationExtIEsExtContainerAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return LastVisitedEUTRANCellInformationExtIEsExtContainerAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c LastVisitedEUTRANCellInformationExtIEsExtContainerValueCodec) EncodeAPER(value LastVisitedEUTRANCellInformationExtIEsExtContainerAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c LastVisitedEUTRANCellInformationExtIEsExtContainerValueCodec) encodeBudgetValue(value LastVisitedEUTRANCellInformationExtIEsExtContainer, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c LastVisitedEUTRANCellInformationExtIEsExtContainerValueCodec) encodeChanged(value LastVisitedEUTRANCellInformationExtIEsExtContainer, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// MDTConfigurationExtIEsExtContainerValueCodec is the concrete ValueCodec[MDTConfigurationExtIEsExtContainer].
type MDTConfigurationExtIEsExtContainerValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (MDTConfigurationExtIEsExtContainer, error)
	encode  func(MDTConfigurationExtIEsExtContainer, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(MDTConfigurationExtIEsExtContainer, aper.DecodeState) (MDTConfigurationExtIEsExtContainer, aper.Snapshot)
	compare func(MDTConfigurationExtIEsExtContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c MDTConfigurationExtIEsExtContainerValueCodec) New(value MDTConfigurationExtIEsExtContainer) (MDTConfigurationExtIEsExtContainerAPERValue, error) {
	if c.encode == nil {
		return MDTConfigurationExtIEsExtContainerAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return MDTConfigurationExtIEsExtContainerAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return MDTConfigurationExtIEsExtContainerAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return MDTConfigurationExtIEsExtContainerAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c MDTConfigurationExtIEsExtContainerValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (MDTConfigurationExtIEsExtContainerAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return MDTConfigurationExtIEsExtContainerAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return MDTConfigurationExtIEsExtContainerAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return MDTConfigurationExtIEsExtContainerAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return MDTConfigurationExtIEsExtContainerAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c MDTConfigurationExtIEsExtContainerValueCodec) EncodeAPER(value MDTConfigurationExtIEsExtContainerAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c MDTConfigurationExtIEsExtContainerValueCodec) encodeBudgetValue(value MDTConfigurationExtIEsExtContainer, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c MDTConfigurationExtIEsExtContainerValueCodec) encodeChanged(value MDTConfigurationExtIEsExtContainer, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// OverloadStartIEFieldValueCodec is the concrete ValueCodec[OverloadStartIEField].
type OverloadStartIEFieldValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (OverloadStartIEField, error)
	encode  func(OverloadStartIEField, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(OverloadStartIEField, aper.DecodeState) (OverloadStartIEField, aper.Snapshot)
	compare func(OverloadStartIEField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c OverloadStartIEFieldValueCodec) New(value OverloadStartIEField) (OverloadStartIEFieldAPERValue, error) {
	if c.encode == nil {
		return OverloadStartIEFieldAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return OverloadStartIEFieldAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return OverloadStartIEFieldAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return OverloadStartIEFieldAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c OverloadStartIEFieldValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (OverloadStartIEFieldAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return OverloadStartIEFieldAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return OverloadStartIEFieldAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return OverloadStartIEFieldAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return OverloadStartIEFieldAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c OverloadStartIEFieldValueCodec) EncodeAPER(value OverloadStartIEFieldAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c OverloadStartIEFieldValueCodec) encodeBudgetValue(value OverloadStartIEField, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c OverloadStartIEFieldValueCodec) encodeChanged(value OverloadStartIEField, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// OverloadStopIEFieldValueCodec is the concrete ValueCodec[OverloadStopIEField].
type OverloadStopIEFieldValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (OverloadStopIEField, error)
	encode  func(OverloadStopIEField, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(OverloadStopIEField, aper.DecodeState) (OverloadStopIEField, aper.Snapshot)
	compare func(OverloadStopIEField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c OverloadStopIEFieldValueCodec) New(value OverloadStopIEField) (OverloadStopIEFieldAPERValue, error) {
	if c.encode == nil {
		return OverloadStopIEFieldAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return OverloadStopIEFieldAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return OverloadStopIEFieldAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return OverloadStopIEFieldAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c OverloadStopIEFieldValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (OverloadStopIEFieldAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return OverloadStopIEFieldAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return OverloadStopIEFieldAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return OverloadStopIEFieldAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return OverloadStopIEFieldAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c OverloadStopIEFieldValueCodec) EncodeAPER(value OverloadStopIEFieldAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c OverloadStopIEFieldValueCodec) encodeBudgetValue(value OverloadStopIEField, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c OverloadStopIEFieldValueCodec) encodeChanged(value OverloadStopIEField, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// OverloadStartIEContainerValueCodec is the concrete ValueCodec[OverloadStartIEContainer].
type OverloadStartIEContainerValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (OverloadStartIEContainer, error)
	encode  func(OverloadStartIEContainer, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(OverloadStartIEContainer, aper.DecodeState) (OverloadStartIEContainer, aper.Snapshot)
	compare func(OverloadStartIEContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c OverloadStartIEContainerValueCodec) New(value OverloadStartIEContainer) (OverloadStartIEContainerAPERValue, error) {
	if c.encode == nil {
		return OverloadStartIEContainerAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return OverloadStartIEContainerAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return OverloadStartIEContainerAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return OverloadStartIEContainerAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c OverloadStartIEContainerValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (OverloadStartIEContainerAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return OverloadStartIEContainerAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return OverloadStartIEContainerAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return OverloadStartIEContainerAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return OverloadStartIEContainerAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c OverloadStartIEContainerValueCodec) EncodeAPER(value OverloadStartIEContainerAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c OverloadStartIEContainerValueCodec) encodeBudgetValue(value OverloadStartIEContainer, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c OverloadStartIEContainerValueCodec) encodeChanged(value OverloadStartIEContainer, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// OverloadStopIEContainerValueCodec is the concrete ValueCodec[OverloadStopIEContainer].
type OverloadStopIEContainerValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (OverloadStopIEContainer, error)
	encode  func(OverloadStopIEContainer, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(OverloadStopIEContainer, aper.DecodeState) (OverloadStopIEContainer, aper.Snapshot)
	compare func(OverloadStopIEContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c OverloadStopIEContainerValueCodec) New(value OverloadStopIEContainer) (OverloadStopIEContainerAPERValue, error) {
	if c.encode == nil {
		return OverloadStopIEContainerAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return OverloadStopIEContainerAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return OverloadStopIEContainerAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return OverloadStopIEContainerAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c OverloadStopIEContainerValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (OverloadStopIEContainerAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return OverloadStopIEContainerAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return OverloadStopIEContainerAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return OverloadStopIEContainerAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return OverloadStopIEContainerAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c OverloadStopIEContainerValueCodec) EncodeAPER(value OverloadStopIEContainerAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c OverloadStopIEContainerValueCodec) encodeBudgetValue(value OverloadStopIEContainer, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c OverloadStopIEContainerValueCodec) encodeChanged(value OverloadStopIEContainer, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// OverloadStartIEValueProtocolErrorIEContainerListValueCodec is the concrete ValueCodec[OverloadStartIEValueProtocolErrorIEContainerList].
type OverloadStartIEValueProtocolErrorIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (OverloadStartIEValueProtocolErrorIEContainerList, error)
	encode  func(OverloadStartIEValueProtocolErrorIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(OverloadStartIEValueProtocolErrorIEContainerList, aper.DecodeState) (OverloadStartIEValueProtocolErrorIEContainerList, aper.Snapshot)
	compare func(OverloadStartIEValueProtocolErrorIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c OverloadStartIEValueProtocolErrorIEContainerListValueCodec) New(value OverloadStartIEValueProtocolErrorIEContainerList) (OverloadStartIEValueProtocolErrorIEContainerListAPERValue, error) {
	if c.encode == nil {
		return OverloadStartIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return OverloadStartIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return OverloadStartIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return OverloadStartIEValueProtocolErrorIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c OverloadStartIEValueProtocolErrorIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (OverloadStartIEValueProtocolErrorIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return OverloadStartIEValueProtocolErrorIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return OverloadStartIEValueProtocolErrorIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return OverloadStartIEValueProtocolErrorIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return OverloadStartIEValueProtocolErrorIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c OverloadStartIEValueProtocolErrorIEContainerListValueCodec) EncodeAPER(value OverloadStartIEValueProtocolErrorIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c OverloadStartIEValueProtocolErrorIEContainerListValueCodec) encodeBudgetValue(value OverloadStartIEValueProtocolErrorIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c OverloadStartIEValueProtocolErrorIEContainerListValueCodec) encodeChanged(value OverloadStartIEValueProtocolErrorIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// OverloadStartIEValueProtocolErrorIEContainerList is ProtocolError-IE-ContainerList {{OverloadStartIEs}} of TS 36.413: a list of information element fields.
type OverloadStartIEValueProtocolErrorIEContainerList []OverloadStartIEValueProtocolIESingleContainer

func BridgeOverloadStartIEValueCaptureS1APProtocolErrorIEContainerList(v *OverloadStartIEValueProtocolErrorIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeOverloadStartIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeOverloadStartIEValueCompareS1APProtocolErrorIEContainerList(v *OverloadStartIEValueProtocolErrorIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeOverloadStartIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}

// OverloadStopIEValueProtocolErrorIEContainerListValueCodec is the concrete ValueCodec[OverloadStopIEValueProtocolErrorIEContainerList].
type OverloadStopIEValueProtocolErrorIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (OverloadStopIEValueProtocolErrorIEContainerList, error)
	encode  func(OverloadStopIEValueProtocolErrorIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(OverloadStopIEValueProtocolErrorIEContainerList, aper.DecodeState) (OverloadStopIEValueProtocolErrorIEContainerList, aper.Snapshot)
	compare func(OverloadStopIEValueProtocolErrorIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c OverloadStopIEValueProtocolErrorIEContainerListValueCodec) New(value OverloadStopIEValueProtocolErrorIEContainerList) (OverloadStopIEValueProtocolErrorIEContainerListAPERValue, error) {
	if c.encode == nil {
		return OverloadStopIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return OverloadStopIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return OverloadStopIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return OverloadStopIEValueProtocolErrorIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c OverloadStopIEValueProtocolErrorIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (OverloadStopIEValueProtocolErrorIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return OverloadStopIEValueProtocolErrorIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return OverloadStopIEValueProtocolErrorIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return OverloadStopIEValueProtocolErrorIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return OverloadStopIEValueProtocolErrorIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c OverloadStopIEValueProtocolErrorIEContainerListValueCodec) EncodeAPER(value OverloadStopIEValueProtocolErrorIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c OverloadStopIEValueProtocolErrorIEContainerListValueCodec) encodeBudgetValue(value OverloadStopIEValueProtocolErrorIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c OverloadStopIEValueProtocolErrorIEContainerListValueCodec) encodeChanged(value OverloadStopIEValueProtocolErrorIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// OverloadStopIEValueProtocolErrorIEContainerList is ProtocolError-IE-ContainerList {{OverloadStopIEs}} of TS 36.413: a list of information element fields.
type OverloadStopIEValueProtocolErrorIEContainerList []OverloadStopIEValueProtocolIESingleContainer

func BridgeOverloadStopIEValueCaptureS1APProtocolErrorIEContainerList(v *OverloadStopIEValueProtocolErrorIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeOverloadStopIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeOverloadStopIEValueCompareS1APProtocolErrorIEContainerList(v *OverloadStopIEValueProtocolErrorIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeOverloadStopIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}

// OverloadStartIEValueProtocolIEContainerListValueCodec is the concrete ValueCodec[OverloadStartIEValueProtocolIEContainerList].
type OverloadStartIEValueProtocolIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (OverloadStartIEValueProtocolIEContainerList, error)
	encode  func(OverloadStartIEValueProtocolIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(OverloadStartIEValueProtocolIEContainerList, aper.DecodeState) (OverloadStartIEValueProtocolIEContainerList, aper.Snapshot)
	compare func(OverloadStartIEValueProtocolIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c OverloadStartIEValueProtocolIEContainerListValueCodec) New(value OverloadStartIEValueProtocolIEContainerList) (OverloadStartIEValueProtocolIEContainerListAPERValue, error) {
	if c.encode == nil {
		return OverloadStartIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return OverloadStartIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return OverloadStartIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return OverloadStartIEValueProtocolIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c OverloadStartIEValueProtocolIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (OverloadStartIEValueProtocolIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return OverloadStartIEValueProtocolIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return OverloadStartIEValueProtocolIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return OverloadStartIEValueProtocolIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return OverloadStartIEValueProtocolIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c OverloadStartIEValueProtocolIEContainerListValueCodec) EncodeAPER(value OverloadStartIEValueProtocolIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c OverloadStartIEValueProtocolIEContainerListValueCodec) encodeBudgetValue(value OverloadStartIEValueProtocolIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c OverloadStartIEValueProtocolIEContainerListValueCodec) encodeChanged(value OverloadStartIEValueProtocolIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// OverloadStartIEValueProtocolIEContainerList is ProtocolIE-ContainerList with IEsSetParam = {OverloadStartIEs} of TS 36.413: a list of information element fields with lowerBound and upperBound supplied by its concrete factory.
type OverloadStartIEValueProtocolIEContainerList []OverloadStartIEValueProtocolIESingleContainer

func BridgeOverloadStartIEValueCaptureS1APProtocolIEContainerList(v *OverloadStartIEValueProtocolIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeOverloadStartIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeOverloadStartIEValueCompareS1APProtocolIEContainerList(v *OverloadStartIEValueProtocolIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeOverloadStartIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}

// OverloadStopIEValueProtocolIEContainerListValueCodec is the concrete ValueCodec[OverloadStopIEValueProtocolIEContainerList].
type OverloadStopIEValueProtocolIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (OverloadStopIEValueProtocolIEContainerList, error)
	encode  func(OverloadStopIEValueProtocolIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(OverloadStopIEValueProtocolIEContainerList, aper.DecodeState) (OverloadStopIEValueProtocolIEContainerList, aper.Snapshot)
	compare func(OverloadStopIEValueProtocolIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c OverloadStopIEValueProtocolIEContainerListValueCodec) New(value OverloadStopIEValueProtocolIEContainerList) (OverloadStopIEValueProtocolIEContainerListAPERValue, error) {
	if c.encode == nil {
		return OverloadStopIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return OverloadStopIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return OverloadStopIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return OverloadStopIEValueProtocolIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c OverloadStopIEValueProtocolIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (OverloadStopIEValueProtocolIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return OverloadStopIEValueProtocolIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return OverloadStopIEValueProtocolIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return OverloadStopIEValueProtocolIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return OverloadStopIEValueProtocolIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c OverloadStopIEValueProtocolIEContainerListValueCodec) EncodeAPER(value OverloadStopIEValueProtocolIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c OverloadStopIEValueProtocolIEContainerListValueCodec) encodeBudgetValue(value OverloadStopIEValueProtocolIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c OverloadStopIEValueProtocolIEContainerListValueCodec) encodeChanged(value OverloadStopIEValueProtocolIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// OverloadStopIEValueProtocolIEContainerList is ProtocolIE-ContainerList with IEsSetParam = {OverloadStopIEs} of TS 36.413: a list of information element fields with lowerBound and upperBound supplied by its concrete factory.
type OverloadStopIEValueProtocolIEContainerList []OverloadStopIEValueProtocolIESingleContainer

func BridgeOverloadStopIEValueCaptureS1APProtocolIEContainerList(v *OverloadStopIEValueProtocolIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeOverloadStopIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeOverloadStopIEValueCompareS1APProtocolIEContainerList(v *OverloadStopIEValueProtocolIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeOverloadStopIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}

// OverloadStartIEValueERABIEContainerListAPERValue is the concrete APERValue[OverloadStartIEValueERABIEContainerList].
type OverloadStartIEValueERABIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         OverloadStartIEValueERABIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v OverloadStartIEValueERABIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v OverloadStartIEValueERABIEContainerListAPERValue) WithoutReplay() OverloadStartIEValueERABIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// OverloadStartIEValueProtocolIESingleContainer is ProtocolIE-SingleContainer {{OverloadStartIEs}} of TS 36.413: a single information element field.
type OverloadStartIEValueProtocolIESingleContainer = OverloadStartIEField

func BridgeOverloadStartIEValueCaptureS1APProtocolIESingleContainer(v *OverloadStartIEValueProtocolIESingleContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeOverloadStartIEValueCaptureS1APProtocolIEField(v, s)
	s.End(f, nil, false)
}
func BridgeOverloadStartIEValueCompareS1APProtocolIESingleContainer(v *OverloadStartIEValueProtocolIESingleContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeOverloadStartIEValueCompareS1APProtocolIEField(v, s)
	s.End(f, aper.Snapshot{}, false)
}

// OverloadStopIEValueERABIEContainerListAPERValue is the concrete APERValue[OverloadStopIEValueERABIEContainerList].
type OverloadStopIEValueERABIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         OverloadStopIEValueERABIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v OverloadStopIEValueERABIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v OverloadStopIEValueERABIEContainerListAPERValue) WithoutReplay() OverloadStopIEValueERABIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// OverloadStopIEValueProtocolIESingleContainer is ProtocolIE-SingleContainer {{OverloadStopIEs}} of TS 36.413: a single information element field.
type OverloadStopIEValueProtocolIESingleContainer = OverloadStopIEField

func BridgeOverloadStopIEValueCaptureS1APProtocolIESingleContainer(v *OverloadStopIEValueProtocolIESingleContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeOverloadStopIEValueCaptureS1APProtocolIEField(v, s)
	s.End(f, nil, false)
}
func BridgeOverloadStopIEValueCompareS1APProtocolIESingleContainer(v *OverloadStopIEValueProtocolIESingleContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeOverloadStopIEValueCompareS1APProtocolIEField(v, s)
	s.End(f, aper.Snapshot{}, false)
}

// LastVisitedEUTRANCellInformationExtIEsExtFieldAPERValue is the concrete APERValue[LastVisitedEUTRANCellInformationExtIEsExtField].
type LastVisitedEUTRANCellInformationExtIEsExtFieldAPERValue struct {
	context       s00.BridgeCodecContext
	Value         LastVisitedEUTRANCellInformationExtIEsExtField
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v LastVisitedEUTRANCellInformationExtIEsExtFieldAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v LastVisitedEUTRANCellInformationExtIEsExtFieldAPERValue) WithoutReplay() LastVisitedEUTRANCellInformationExtIEsExtFieldAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// MDTConfigurationExtIEsExtFieldAPERValue is the concrete APERValue[MDTConfigurationExtIEsExtField].
type MDTConfigurationExtIEsExtFieldAPERValue struct {
	context       s00.BridgeCodecContext
	Value         MDTConfigurationExtIEsExtField
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v MDTConfigurationExtIEsExtFieldAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v MDTConfigurationExtIEsExtFieldAPERValue) WithoutReplay() MDTConfigurationExtIEsExtFieldAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// LastVisitedEUTRANCellInformationExtIEsExtContainerAPERValue is the concrete APERValue[LastVisitedEUTRANCellInformationExtIEsExtContainer].
type LastVisitedEUTRANCellInformationExtIEsExtContainerAPERValue struct {
	context       s00.BridgeCodecContext
	Value         LastVisitedEUTRANCellInformationExtIEsExtContainer
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v LastVisitedEUTRANCellInformationExtIEsExtContainerAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v LastVisitedEUTRANCellInformationExtIEsExtContainerAPERValue) WithoutReplay() LastVisitedEUTRANCellInformationExtIEsExtContainerAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// MDTConfigurationExtIEsExtContainerAPERValue is the concrete APERValue[MDTConfigurationExtIEsExtContainer].
type MDTConfigurationExtIEsExtContainerAPERValue struct {
	context       s00.BridgeCodecContext
	Value         MDTConfigurationExtIEsExtContainer
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v MDTConfigurationExtIEsExtContainerAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v MDTConfigurationExtIEsExtContainerAPERValue) WithoutReplay() MDTConfigurationExtIEsExtContainerAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// OverloadStartIEFieldAPERValue is the concrete APERValue[OverloadStartIEField].
type OverloadStartIEFieldAPERValue struct {
	context       s00.BridgeCodecContext
	Value         OverloadStartIEField
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v OverloadStartIEFieldAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v OverloadStartIEFieldAPERValue) WithoutReplay() OverloadStartIEFieldAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// OverloadStopIEFieldAPERValue is the concrete APERValue[OverloadStopIEField].
type OverloadStopIEFieldAPERValue struct {
	context       s00.BridgeCodecContext
	Value         OverloadStopIEField
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v OverloadStopIEFieldAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v OverloadStopIEFieldAPERValue) WithoutReplay() OverloadStopIEFieldAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// OverloadStartIEContainerAPERValue is the concrete APERValue[OverloadStartIEContainer].
type OverloadStartIEContainerAPERValue struct {
	context       s00.BridgeCodecContext
	Value         OverloadStartIEContainer
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v OverloadStartIEContainerAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v OverloadStartIEContainerAPERValue) WithoutReplay() OverloadStartIEContainerAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// OverloadStopIEContainerAPERValue is the concrete APERValue[OverloadStopIEContainer].
type OverloadStopIEContainerAPERValue struct {
	context       s00.BridgeCodecContext
	Value         OverloadStopIEContainer
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v OverloadStopIEContainerAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v OverloadStopIEContainerAPERValue) WithoutReplay() OverloadStopIEContainerAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// OverloadStartIEValueProtocolErrorIEContainerListAPERValue is the concrete APERValue[OverloadStartIEValueProtocolErrorIEContainerList].
type OverloadStartIEValueProtocolErrorIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         OverloadStartIEValueProtocolErrorIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v OverloadStartIEValueProtocolErrorIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v OverloadStartIEValueProtocolErrorIEContainerListAPERValue) WithoutReplay() OverloadStartIEValueProtocolErrorIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// OverloadStopIEValueProtocolErrorIEContainerListAPERValue is the concrete APERValue[OverloadStopIEValueProtocolErrorIEContainerList].
type OverloadStopIEValueProtocolErrorIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         OverloadStopIEValueProtocolErrorIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v OverloadStopIEValueProtocolErrorIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v OverloadStopIEValueProtocolErrorIEContainerListAPERValue) WithoutReplay() OverloadStopIEValueProtocolErrorIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// OverloadStartIEValueProtocolIEContainerListAPERValue is the concrete APERValue[OverloadStartIEValueProtocolIEContainerList].
type OverloadStartIEValueProtocolIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         OverloadStartIEValueProtocolIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v OverloadStartIEValueProtocolIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v OverloadStartIEValueProtocolIEContainerListAPERValue) WithoutReplay() OverloadStartIEValueProtocolIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// OverloadStopIEValueProtocolIEContainerListAPERValue is the concrete APERValue[OverloadStopIEValueProtocolIEContainerList].
type OverloadStopIEValueProtocolIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         OverloadStopIEValueProtocolIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v OverloadStopIEValueProtocolIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v OverloadStopIEValueProtocolIEContainerListAPERValue) WithoutReplay() OverloadStopIEValueProtocolIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}
func BridgeCaptureS1APERABToBeSwitchedULListComplete(v *ERABToBeSwitchedULListComplete, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s25.BridgeCaptureS1APERABToBeSwitchedULList(&v.Value, s)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APERABToBeSwitchedULListComplete(v *ERABToBeSwitchedULListComplete, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s25.BridgeCompareS1APERABToBeSwitchedULList(&v.Value, s)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APERABToBeUpdatedListComplete(v *ERABToBeUpdatedListComplete, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s30.BridgeCaptureS1APERABToBeUpdatedList(&v.Value, s)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APERABToBeUpdatedListComplete(v *ERABToBeUpdatedListComplete, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s30.BridgeCompareS1APERABToBeUpdatedList(&v.Value, s)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APERABUsageReportListComplete(v *ERABUsageReportListComplete, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s25.BridgeCaptureS1APERABUsageReportList(&v.Value, s)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APERABUsageReportListComplete(v *ERABUsageReportListComplete, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s25.BridgeCompareS1APERABUsageReportList(&v.Value, s)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APEmergencyAreaIDBroadcastComplete(v *EmergencyAreaIDBroadcastComplete, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s22.BridgeCaptureS1APEmergencyAreaIDBroadcast(&v.Value, s)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APEmergencyAreaIDBroadcastComplete(v *EmergencyAreaIDBroadcastComplete, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s24.BridgeCompareS1APEmergencyAreaIDBroadcast(&v.Value, s)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APEmergencyAreaIDCancelledComplete(v *EmergencyAreaIDCancelledComplete, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s22.BridgeCaptureS1APEmergencyAreaIDCancelled(&v.Value, s)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APEmergencyAreaIDCancelledComplete(v *EmergencyAreaIDCancelledComplete, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s24.BridgeCompareS1APEmergencyAreaIDCancelled(&v.Value, s)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APEmergencyAreaIDListComplete(v *EmergencyAreaIDListComplete, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APEmergencyAreaIDList(&v.Value, s)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APEmergencyAreaIDListComplete(v *EmergencyAreaIDListComplete, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s02.BridgeCompareS1APEmergencyAreaIDList(&v.Value, s)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APEmergencyAreaIDListForRestartComplete(v *EmergencyAreaIDListForRestartComplete, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APEmergencyAreaIDListForRestart(&v.Value, s)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APEmergencyAreaIDListForRestartComplete(v *EmergencyAreaIDListForRestartComplete, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s02.BridgeCompareS1APEmergencyAreaIDListForRestart(&v.Value, s)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APForbiddenLACsComplete(v *ForbiddenLACsComplete, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APForbiddenLACs(&v.Value, s)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APForbiddenLACsComplete(v *ForbiddenLACsComplete, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s02.BridgeCompareS1APForbiddenLACs(&v.Value, s)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APForbiddenLAsComplete(v *ForbiddenLAsComplete, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s21.BridgeCaptureS1APForbiddenLAs(&v.Value, s)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APForbiddenLAsComplete(v *ForbiddenLAsComplete, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s24.BridgeCompareS1APForbiddenLAs(&v.Value, s)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APForbiddenTACsComplete(v *ForbiddenTACsComplete, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APForbiddenTACs(&v.Value, s)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APForbiddenTACsComplete(v *ForbiddenTACsComplete, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s07.BridgeCompareS1APForbiddenTACs(&v.Value, s)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APForbiddenTAsComplete(v *ForbiddenTAsComplete, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s21.BridgeCaptureS1APForbiddenTAs(&v.Value, s)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APForbiddenTAsComplete(v *ForbiddenTAsComplete, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s24.BridgeCompareS1APForbiddenTAs(&v.Value, s)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APGUMMEIListComplete(v *GUMMEIListComplete, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s21.BridgeCaptureS1APGUMMEIList(&v.Value, s)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APGUMMEIListComplete(v *GUMMEIListComplete, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s24.BridgeCompareS1APGUMMEIList(&v.Value, s)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APIEsECGIListComplete(v *IEsECGIListComplete, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s21.BridgeCaptureS1APIEsECGIList(&v.Value, s)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APIEsECGIListComplete(v *IEsECGIListComplete, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s24.BridgeCompareS1APIEsECGIList(&v.Value, s)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APInterSystemMeasurementListComplete(v *InterSystemMeasurementListComplete, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s21.BridgeCaptureS1APInterSystemMeasurementList(&v.Value, s)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APInterSystemMeasurementListComplete(v *InterSystemMeasurementListComplete, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s24.BridgeCompareS1APInterSystemMeasurementList(&v.Value, s)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APLastVisitedCellItem(v *LastVisitedCellItem, s *aper.SemanticCapture) {
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
	case s00.LastVisitedCellItemChoiceEUTRANCell:
		{
			f := s.Begin()
			s.Bool(v.EUTRANCell == nil)
			if v.EUTRANCell != nil {
				BridgeCaptureS1APLastVisitedEUTRANCellInformation(v.EUTRANCell, s)
			}
			s.End(f, nil, false)
		}
	case s00.LastVisitedCellItemChoiceUTRANCell:
		{
			f := s.Begin()
			s.Bool(v.UTRANCell == nil)
			if v.UTRANCell != nil {
				s00.BridgeCaptureS1APLastVisitedUTRANCellInformation(v.UTRANCell, s)
			}
			s.End(f, nil, false)
		}
	case s00.LastVisitedCellItemChoiceGERANCell:
		{
			f := s.Begin()
			s.Bool(v.GERANCell == nil)
			if v.GERANCell != nil {
				s18.BridgeCaptureS1APLastVisitedGERANCellInformation(v.GERANCell, s)
			}
			s.End(f, nil, false)
		}
	case s00.LastVisitedCellItemChoiceNGRANCell:
		{
			f := s.Begin()
			s.Bool(v.NGRANCell == nil)
			if v.NGRANCell != nil {
				s00.BridgeCaptureS1APLastVisitedNGRANCellInformation(v.NGRANCell, s)
			}
			s.End(f, nil, false)
		}
	}
	s.End(f, &v.replay, v.withoutReplay)
	if v.UnknownExtension == nil && v.Choice > 3 {
		s.CheckChoice(v.replay, v.stream)
	}
}
func BridgeCompareS1APLastVisitedCellItem(v *LastVisitedCellItem, s *aper.SemanticComparison) {
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
	case s00.LastVisitedCellItemChoiceEUTRANCell:
		{
			f := s.Begin()
			s.Bool(v.EUTRANCell == nil)
			if v.EUTRANCell != nil {
				BridgeCompareS1APLastVisitedEUTRANCellInformation(v.EUTRANCell, s)
			}
			s.End(f, aper.Snapshot{}, false)
		}
	case s00.LastVisitedCellItemChoiceUTRANCell:
		{
			f := s.Begin()
			s.Bool(v.UTRANCell == nil)
			if v.UTRANCell != nil {
				s02.BridgeCompareS1APLastVisitedUTRANCellInformation(v.UTRANCell, s)
			}
			s.End(f, aper.Snapshot{}, false)
		}
	case s00.LastVisitedCellItemChoiceGERANCell:
		{
			f := s.Begin()
			s.Bool(v.GERANCell == nil)
			if v.GERANCell != nil {
				s18.BridgeCompareS1APLastVisitedGERANCellInformation(v.GERANCell, s)
			}
			s.End(f, aper.Snapshot{}, false)
		}
	case s00.LastVisitedCellItemChoiceNGRANCell:
		{
			f := s.Begin()
			s.Bool(v.NGRANCell == nil)
			if v.NGRANCell != nil {
				s02.BridgeCompareS1APLastVisitedNGRANCellInformation(v.NGRANCell, s)
			}
			s.End(f, aper.Snapshot{}, false)
		}
	}
	s.End(f, v.replay, v.withoutReplay)
	if v.UnknownExtension == nil && v.Choice > 3 {
		s.CheckChoice(v.replay, v.stream)
	}
}
func BridgeCaptureS1APLastVisitedEUTRANCellInformation(v *LastVisitedEUTRANCellInformation, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s17.BridgeCaptureS1APEUTRANCGI(&v.GlobalCellID, s)
	s14.BridgeCaptureS1APCellType(&v.CellType, s)
	s00.BridgeCaptureS1APTimeUEStayedInCell(&v.TimeUEStayedInCell, s)
	s.Bool(v.IEExtensions == nil)
	BridgeLastVisitedEUTRANCellInformationExtIEsValueCaptureS1APProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APLastVisitedEUTRANCellInformation(v *LastVisitedEUTRANCellInformation, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s17.BridgeCompareS1APEUTRANCGI(&v.GlobalCellID, s)
	s14.BridgeCompareS1APCellType(&v.CellType, s)
	s07.BridgeCompareS1APTimeUEStayedInCell(&v.TimeUEStayedInCell, s)
	s.Bool(v.IEExtensions == nil)
	BridgeLastVisitedEUTRANCellInformationExtIEsValueCompareS1APProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APLastVisitedEUTRANCellInformationExtIEsValue(v *LastVisitedEUTRANCellInformationExtIEsValue, s *aper.SemanticCapture) {
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
		case s00.ProtocolIEID(167):
			{
				f := s.Begin()
				s.Bool(v.rowTimeUEStayedInCellEnhancedGranularity == nil)
				if v.rowTimeUEStayedInCellEnhancedGranularity != nil {
					s00.BridgeCaptureS1APTimeUEStayedInCellEnhancedGranularity(v.rowTimeUEStayedInCellEnhancedGranularity, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(168):
			{
				f := s.Begin()
				s.Bool(v.rowHOCause == nil)
				if v.rowHOCause != nil {
					s14.BridgeCaptureS1APCause(v.rowHOCause, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(329):
			{
				f := s.Begin()
				s.Bool(v.rowLastVisitedPSCellList == nil)
				if v.rowLastVisitedPSCellList != nil {
					s21.BridgeCaptureS1APLastVisitedPSCellList(v.rowLastVisitedPSCellList, s)
				}
				s.End(f, nil, false)
			}
		}
	}
	s.End(f, &v.replay, false)
	s.CheckReceived(v.replay, v.received)
}
func (v LastVisitedEUTRANCellInformationExtIEsValue) captureSemantics(s aper.SemanticCapture) LastVisitedEUTRANCellInformationExtIEsValue {
	BridgeCaptureS1APLastVisitedEUTRANCellInformationExtIEsValue(&v, &s)
	return v
}
func BridgeCompareS1APLastVisitedEUTRANCellInformationExtIEsValue(v *LastVisitedEUTRANCellInformationExtIEsValue, s *aper.SemanticComparison) {
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
		case s00.ProtocolIEID(167):
			{
				f := s.Begin()
				s.Bool(v.rowTimeUEStayedInCellEnhancedGranularity == nil)
				if v.rowTimeUEStayedInCellEnhancedGranularity != nil {
					s07.BridgeCompareS1APTimeUEStayedInCellEnhancedGranularity(v.rowTimeUEStayedInCellEnhancedGranularity, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(168):
			{
				f := s.Begin()
				s.Bool(v.rowHOCause == nil)
				if v.rowHOCause != nil {
					s14.BridgeCompareS1APCause(v.rowHOCause, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(329):
			{
				f := s.Begin()
				s.Bool(v.rowLastVisitedPSCellList == nil)
				if v.rowLastVisitedPSCellList != nil {
					s24.BridgeCompareS1APLastVisitedPSCellList(v.rowLastVisitedPSCellList, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		}
	}
	s.End(f, v.replay, false)
	s.CheckReceived(v.replay, v.received)
}
func (v LastVisitedEUTRANCellInformationExtIEsValue) compareSemantics(s aper.SemanticComparison) aper.SemanticComparison {
	BridgeCompareS1APLastVisitedEUTRANCellInformationExtIEsValue(&v, &s)
	return s
}
func BridgeCaptureS1APLastVisitedPSCellListComplete(v *LastVisitedPSCellListComplete, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s21.BridgeCaptureS1APLastVisitedPSCellList(&v.Value, s)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APLastVisitedPSCellListComplete(v *LastVisitedPSCellListComplete, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s24.BridgeCompareS1APLastVisitedPSCellList(&v.Value, s)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APMBSFNResultToLogComplete(v *MBSFNResultToLogComplete, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s21.BridgeCaptureS1APMBSFNResultToLog(&v.Value, s)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APMBSFNResultToLogComplete(v *MBSFNResultToLogComplete, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s24.BridgeCompareS1APMBSFNResultToLog(&v.Value, s)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APMDTConfigurationExtIEsValue(v *MDTConfigurationExtIEsValue, s *aper.SemanticCapture) {
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
		case s00.ProtocolIEID(178):
			{
				f := s.Begin()
				s.Bool(v.rowSignallingBasedMDTPLMNList == nil)
				if v.rowSignallingBasedMDTPLMNList != nil {
					s00.BridgeCaptureS1APMDTPLMNList(v.rowSignallingBasedMDTPLMNList, s)
				}
				s.End(f, nil, false)
			}
		}
	}
	s.End(f, &v.replay, false)
	s.CheckReceived(v.replay, v.received)
}
func (v MDTConfigurationExtIEsValue) captureSemantics(s aper.SemanticCapture) MDTConfigurationExtIEsValue {
	BridgeCaptureS1APMDTConfigurationExtIEsValue(&v, &s)
	return v
}
func BridgeCompareS1APMDTConfigurationExtIEsValue(v *MDTConfigurationExtIEsValue, s *aper.SemanticComparison) {
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
		case s00.ProtocolIEID(178):
			{
				f := s.Begin()
				s.Bool(v.rowSignallingBasedMDTPLMNList == nil)
				if v.rowSignallingBasedMDTPLMNList != nil {
					s07.BridgeCompareS1APMDTPLMNList(v.rowSignallingBasedMDTPLMNList, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		}
	}
	s.End(f, v.replay, false)
	s.CheckReceived(v.replay, v.received)
}
func (v MDTConfigurationExtIEsValue) compareSemantics(s aper.SemanticComparison) aper.SemanticComparison {
	BridgeCompareS1APMDTConfigurationExtIEsValue(&v, &s)
	return s
}
func BridgeCaptureS1APMDTPLMNListComplete(v *MDTPLMNListComplete, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APMDTPLMNList(&v.Value, s)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APMDTPLMNListComplete(v *MDTPLMNListComplete, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s07.BridgeCompareS1APMDTPLMNList(&v.Value, s)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APMultiCellLoadReportingResponseComplete(v *MultiCellLoadReportingResponseComplete, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s21.BridgeCaptureS1APMultiCellLoadReportingResponse(&v.Value, s)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APMultiCellLoadReportingResponseComplete(v *MultiCellLoadReportingResponseComplete, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s24.BridgeCompareS1APMultiCellLoadReportingResponse(&v.Value, s)
	s.End(f, v.replay, v.withoutReplay)
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
func BridgeCaptureS1APOverloadStart(v *OverloadStart, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeOverloadStartIEValueCaptureS1APProtocolIEContainer(&v.ProtocolIEs, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APOverloadStart(v *OverloadStart, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeOverloadStartIEValueCompareS1APProtocolIEContainer(&v.ProtocolIEs, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APOverloadStartIEValue(v *OverloadStartIEValue, s *aper.SemanticCapture) {
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
		case s00.ProtocolIEID(101):
			{
				f := s.Begin()
				s.Bool(v.rowOverloadResponse == nil)
				if v.rowOverloadResponse != nil {
					s20.BridgeCaptureS1APOverloadResponse(v.rowOverloadResponse, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(154):
			{
				f := s.Begin()
				s.Bool(v.rowGUMMEIList == nil)
				if v.rowGUMMEIList != nil {
					s21.BridgeCaptureS1APGUMMEIList(v.rowGUMMEIList, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(161):
			{
				f := s.Begin()
				s.Bool(v.rowTrafficLoadReductionIndication == nil)
				if v.rowTrafficLoadReductionIndication != nil {
					s00.BridgeCaptureS1APTrafficLoadReductionIndication(v.rowTrafficLoadReductionIndication, s)
				}
				s.End(f, nil, false)
			}
		}
	}
	s.End(f, &v.replay, false)
	s.CheckReceived(v.replay, v.received)
}
func (v OverloadStartIEValue) captureSemantics(s aper.SemanticCapture) OverloadStartIEValue {
	BridgeCaptureS1APOverloadStartIEValue(&v, &s)
	return v
}
func BridgeCompareS1APOverloadStartIEValue(v *OverloadStartIEValue, s *aper.SemanticComparison) {
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
		case s00.ProtocolIEID(101):
			{
				f := s.Begin()
				s.Bool(v.rowOverloadResponse == nil)
				if v.rowOverloadResponse != nil {
					s20.BridgeCompareS1APOverloadResponse(v.rowOverloadResponse, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(154):
			{
				f := s.Begin()
				s.Bool(v.rowGUMMEIList == nil)
				if v.rowGUMMEIList != nil {
					s24.BridgeCompareS1APGUMMEIList(v.rowGUMMEIList, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(161):
			{
				f := s.Begin()
				s.Bool(v.rowTrafficLoadReductionIndication == nil)
				if v.rowTrafficLoadReductionIndication != nil {
					s07.BridgeCompareS1APTrafficLoadReductionIndication(v.rowTrafficLoadReductionIndication, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		}
	}
	s.End(f, v.replay, false)
	s.CheckReceived(v.replay, v.received)
}
func (v OverloadStartIEValue) compareSemantics(s aper.SemanticComparison) aper.SemanticComparison {
	BridgeCompareS1APOverloadStartIEValue(&v, &s)
	return s
}
func BridgeCaptureS1APOverloadStop(v *OverloadStop, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeOverloadStopIEValueCaptureS1APProtocolIEContainer(&v.ProtocolIEs, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APOverloadStop(v *OverloadStop, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeOverloadStopIEValueCompareS1APProtocolIEContainer(&v.ProtocolIEs, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APOverloadStopIEValue(v *OverloadStopIEValue, s *aper.SemanticCapture) {
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
		case s00.ProtocolIEID(154):
			{
				f := s.Begin()
				s.Bool(v.rowGUMMEIList == nil)
				if v.rowGUMMEIList != nil {
					s21.BridgeCaptureS1APGUMMEIList(v.rowGUMMEIList, s)
				}
				s.End(f, nil, false)
			}
		}
	}
	s.End(f, &v.replay, false)
	s.CheckReceived(v.replay, v.received)
}
func (v OverloadStopIEValue) captureSemantics(s aper.SemanticCapture) OverloadStopIEValue {
	BridgeCaptureS1APOverloadStopIEValue(&v, &s)
	return v
}
func BridgeCompareS1APOverloadStopIEValue(v *OverloadStopIEValue, s *aper.SemanticComparison) {
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
		case s00.ProtocolIEID(154):
			{
				f := s.Begin()
				s.Bool(v.rowGUMMEIList == nil)
				if v.rowGUMMEIList != nil {
					s24.BridgeCompareS1APGUMMEIList(v.rowGUMMEIList, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		}
	}
	s.End(f, v.replay, false)
	s.CheckReceived(v.replay, v.received)
}
func (v OverloadStopIEValue) compareSemantics(s aper.SemanticComparison) aper.SemanticComparison {
	BridgeCompareS1APOverloadStopIEValue(&v, &s)
	return s
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
func BridgeCaptureS1APSourceeNBToTargeteNBTransparentContainer(v *SourceeNBToTargeteNBTransparentContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APRRCContainer(&v.RRCContainer, s)
	s.Bool(v.ERABInformationList == nil)
	s29.BridgeCaptureS1APERABInformationList(&v.ERABInformationList, s)
	s17.BridgeCaptureS1APEUTRANCGI(&v.TargetCellID, s)
	{
		f := s.Begin()
		s.Bool(v.SubscriberProfileIDforRFP == nil)
		if v.SubscriberProfileIDforRFP != nil {
			s00.BridgeCaptureS1APSubscriberProfileIDforRFP(v.SubscriberProfileIDforRFP, s)
		}
		s.End(f, nil, false)
	}
	BridgeCaptureS1APUEHistoryInformation(&v.UEHistoryInformation, s)
	s.Bool(v.IEExtensions == nil)
	s35.BridgeSourceeNBToTargeteNBTransparentContainerExtIEsValueCaptureS1APProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APSourceeNBToTargeteNBTransparentContainer(v *SourceeNBToTargeteNBTransparentContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s06.BridgeCompareS1APRRCContainer(&v.RRCContainer, s)
	s.Bool(v.ERABInformationList == nil)
	s29.BridgeCompareS1APERABInformationList(&v.ERABInformationList, s)
	s17.BridgeCompareS1APEUTRANCGI(&v.TargetCellID, s)
	{
		f := s.Begin()
		s.Bool(v.SubscriberProfileIDforRFP == nil)
		if v.SubscriberProfileIDforRFP != nil {
			s07.BridgeCompareS1APSubscriberProfileIDforRFP(v.SubscriberProfileIDforRFP, s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	BridgeCompareS1APUEHistoryInformation(&v.UEHistoryInformation, s)
	s.Bool(v.IEExtensions == nil)
	s35.BridgeSourceeNBToTargeteNBTransparentContainerExtIEsValueCompareS1APProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APUEHistoryInformation(v *UEHistoryInformation, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeCaptureS1APLastVisitedCellItem(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeCompareS1APUEHistoryInformation(v *UEHistoryInformation, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeCompareS1APLastVisitedCellItem(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}

// LastVisitedCellItem represents the ASN.1 CHOICE type LastVisitedCell-Item.
type LastVisitedCellItem struct {
	replay             aper.Snapshot
	stream             aper.WireSpan
	received           bool
	withoutReplay      bool
	receivedAbsolute   bool
	receivedBytes      aper.WireSpan
	receivedLocation   aper.Location
	Choice             int
	perPadding         aper.CompletePadding                 `json:"-"`
	perOpenTypePadding aper.CompletePadding                 `json:"-"`
	UnknownExtension   *aper.ChoiceExtension                `json:"UnknownExtension,omitempty"`
	EUTRANCell         *LastVisitedEUTRANCellInformation    `json:"EUTRANCell,omitempty"`
	UTRANCell          *s00.LastVisitedUTRANCellInformation `json:"UTRANCell,omitempty"`
	GERANCell          *s18.LastVisitedGERANCellInformation `json:"GERANCell,omitempty"`
	NGRANCell          *s00.LastVisitedNGRANCellInformation `json:"NGRANCell,omitempty"`
}

// NewLastVisitedCellItemEUTRANCell creates a LastVisitedCellItem with the e-UTRAN-Cell alternative.
func BridgeNewLastVisitedCellItemEUTRANCellLegacy(v LastVisitedEUTRANCellInformation) LastVisitedCellItem {
	return LastVisitedCellItem{
		Choice:     s00.LastVisitedCellItemChoiceEUTRANCell,
		EUTRANCell: &v,
	}
}

// NewLastVisitedCellItemUTRANCell creates a LastVisitedCellItem with the uTRAN-Cell alternative.
func BridgeNewLastVisitedCellItemUTRANCellLegacy(v s00.LastVisitedUTRANCellInformation) LastVisitedCellItem {
	return LastVisitedCellItem{
		Choice:    s00.LastVisitedCellItemChoiceUTRANCell,
		UTRANCell: &v,
	}
}

// NewLastVisitedCellItemGERANCell creates a LastVisitedCellItem with the gERAN-Cell alternative.
func BridgeNewLastVisitedCellItemGERANCellLegacy(v s18.LastVisitedGERANCellInformation) LastVisitedCellItem {
	return LastVisitedCellItem{
		Choice:    s00.LastVisitedCellItemChoiceGERANCell,
		GERANCell: &v,
	}
}

// NewLastVisitedCellItemNGRANCell creates a LastVisitedCellItem with the nG-RAN-Cell alternative.
func BridgeNewLastVisitedCellItemNGRANCellLegacy(v s00.LastVisitedNGRANCellInformation) LastVisitedCellItem {
	return LastVisitedCellItem{
		Choice:    s00.LastVisitedCellItemChoiceNGRANCell,
		NGRANCell: &v,
	}
}

// LastVisitedEUTRANCellInformation represents the ASN.1 type LastVisitedEUTRANCellInformation (SEQUENCE).
type LastVisitedEUTRANCellInformation struct {
	replay             aper.Snapshot
	stream             aper.WireSpan
	received           bool
	withoutReplay      bool
	receivedAbsolute   bool
	receivedBytes      aper.WireSpan
	receivedLocation   aper.Location
	GlobalCellID       s17.EUTRANCGI                                      `asn1:"tag:0,context,implicit"`
	CellType           s14.CellType                                       `asn1:"tag:1,context,implicit"`
	TimeUEStayedInCell s00.TimeUEStayedInCell                             `asn1:"tag:2,context,implicit"`
	IEExtensions       LastVisitedEUTRANCellInformationExtIEsExtContainer `asn1:"tag:3,context,implicit,optional" json:"IEExtensions,omitzero"`
	iEExtensionsIndef  bool                                               `asn1:"-" json:"-"`
	extCount           int64                                              `asn1:"-" json:"-"`
	extPresent         []bool                                             `asn1:"-" json:"-"`
	extData            [][]byte                                           `asn1:"-" json:"-"`
	perPadding         aper.FinalPadding                                  `asn1:"-" json:"-"`
	perExtPadding      []aper.CompletePadding                             `asn1:"-" json:"-"`
	extOrigin          []aper.OpaqueOrigin
	extWire            []aper.WireSpan
}

// SourceeNBToTargeteNBTransparentContainer represents the ASN.1 type SourceeNB-ToTargeteNB-TransparentContainer (SEQUENCE).
type SourceeNBToTargeteNBTransparentContainer struct {
	replay                    aper.Snapshot
	stream                    aper.WireSpan
	received                  bool
	withoutReplay             bool
	receivedAbsolute          bool
	receivedBytes             aper.WireSpan
	receivedLocation          aper.Location
	RRCContainer              s00.RRCContainer                                               `asn1:"tag:0,context,implicit"`
	ERABInformationList       s29.ERABInformationList                                        `asn1:"tag:1,context,implicit,optional" json:"ERABInformationList,omitzero"`
	eRABInformationListIndef  bool                                                           `asn1:"-" json:"-"`
	TargetCellID              s17.EUTRANCGI                                                  `asn1:"tag:2,context,implicit"`
	SubscriberProfileIDforRFP *s00.SubscriberProfileIDforRFP                                 `asn1:"tag:3,context,implicit,optional" json:"SubscriberProfileIDforRFP,omitempty"`
	UEHistoryInformation      UEHistoryInformation                                           `asn1:"tag:4,context,implicit"`
	uEHistoryInformationIndef bool                                                           `asn1:"-" json:"-"`
	IEExtensions              s35.SourceeNBToTargeteNBTransparentContainerExtIEsExtContainer `asn1:"tag:5,context,implicit,optional" json:"IEExtensions,omitzero"`
	iEExtensionsIndef         bool                                                           `asn1:"-" json:"-"`
	extCount                  int64                                                          `asn1:"-" json:"-"`
	extPresent                []bool                                                         `asn1:"-" json:"-"`
	extData                   [][]byte                                                       `asn1:"-" json:"-"`
	perPadding                aper.FinalPadding                                              `asn1:"-" json:"-"`
	perExtPadding             []aper.CompletePadding                                         `asn1:"-" json:"-"`
	extOrigin                 []aper.OpaqueOrigin
	extWire                   []aper.WireSpan
}
type UEHistoryInformation = []LastVisitedCellItem

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
	if err := s26.BridgeMarshalAPERPWSfailedECGIListTo(v.Value, bb); err != nil {
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
	bb.EnterComponent("PWSfailedECGIList")
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

// EmergencyAreaIDListComplete carries a complete EmergencyAreaIDList encoding, including observed terminal bits.
// ITU-T X.691 (02/2021) 11.1.3.1 and 11.1.4 require new encodings to pad with zero bits.
type EmergencyAreaIDListComplete struct {
	replay           aper.Snapshot
	stream           aper.WireSpan
	received         bool
	withoutReplay    bool
	receivedAbsolute bool
	receivedBytes    aper.WireSpan
	receivedLocation aper.Location
	Value            s00.EmergencyAreaIDList
	perPadding       aper.CompletePadding `json:"-"`
}

func (v *EmergencyAreaIDListComplete) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := s13.BridgeMarshalAPEREmergencyAreaIDListTo(v.Value, bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.perPadding)
}

// UnmarshalAPER decodes EmergencyAreaIDList from APER format.
func (v *EmergencyAreaIDListComplete) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes EmergencyAreaIDList with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *EmergencyAreaIDListComplete) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "EmergencyAreaIDList")
	}
	bb.EnterComponent("EmergencyAreaIDList")
	value, err := BridgeUnmarshalAPEREmergencyAreaIDListFrom(bb)
	if err != nil {
		return runtime.WrapDecodePath(err, "EmergencyAreaIDList")
	}
	padding, err := aper.CaptureFinalBits(bb, "EmergencyAreaIDList")
	if err != nil {
		return runtime.WrapDecodePath(err, "EmergencyAreaIDList")
	}
	v.Value, v.perPadding = value, padding.Padding()
	return nil
}

// MarshalAPEREmergencyAreaIDList encodes a EmergencyAreaIDList list to APER.
func BridgeMarshalAPEREmergencyAreaIDList(list EmergencyAreaIDListComplete) ([]byte, error) {
	return list.marshalAPERLegacy()
}

// UnmarshalAPEREmergencyAreaIDList decodes a EmergencyAreaIDList list from APER.
func BridgeUnmarshalAPEREmergencyAreaIDList(data []byte) (EmergencyAreaIDListComplete, error) {
	var value EmergencyAreaIDListComplete
	if err := value.unmarshalAPERLegacy(data); err != nil {
		return value, err
	}
	return value, nil
}

// UnmarshalAPEREmergencyAreaIDListFrom decodes a EmergencyAreaIDList list from bb.
func BridgeUnmarshalAPEREmergencyAreaIDListFrom(bb *aper.BitBuffer) (s00.EmergencyAreaIDList, error) {
	if err := bb.EnterDecodeValue(); err != nil {
		return nil, err
	}
	defer bb.LeaveDecodeValue()
	var v s00.BridgeAsn1cAPEREmergencyAreaIDListListValue
	if err := BridgeUnmarshalAPEREmergencyAreaIDListInto(&v, bb); err != nil {
		return nil, err
	}
	return v.Value, nil
}
func BridgeUnmarshalAPEREmergencyAreaIDListInto(v *s00.BridgeAsn1cAPEREmergencyAreaIDListListValue, bb *aper.BitBuffer) error {
	toleranceMark_value := bb.EnterComponent("Value")
	v.Value = make(s00.EmergencyAreaIDList, 0)
	_, errCollection_value := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
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

// EmergencyAreaIDBroadcastComplete carries a complete EmergencyAreaIDBroadcast encoding, including observed terminal bits.
// ITU-T X.691 (02/2021) 11.1.3.1 and 11.1.4 require new encodings to pad with zero bits.
type EmergencyAreaIDBroadcastComplete struct {
	replay           aper.Snapshot
	stream           aper.WireSpan
	received         bool
	withoutReplay    bool
	receivedAbsolute bool
	receivedBytes    aper.WireSpan
	receivedLocation aper.Location
	Value            s22.EmergencyAreaIDBroadcast
	perPadding       aper.CompletePadding `json:"-"`
}

func (v *EmergencyAreaIDBroadcastComplete) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := s26.BridgeMarshalAPEREmergencyAreaIDBroadcastTo(v.Value, bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.perPadding)
}

// UnmarshalAPER decodes EmergencyAreaIDBroadcast from APER format.
func (v *EmergencyAreaIDBroadcastComplete) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes EmergencyAreaIDBroadcast with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *EmergencyAreaIDBroadcastComplete) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "EmergencyAreaIDBroadcast")
	}
	bb.EnterComponent("EmergencyAreaIDBroadcast")
	value, err := BridgeUnmarshalAPEREmergencyAreaIDBroadcastFrom(bb)
	if err != nil {
		return runtime.WrapDecodePath(err, "EmergencyAreaIDBroadcast")
	}
	padding, err := aper.CaptureFinalBits(bb, "EmergencyAreaIDBroadcast")
	if err != nil {
		return runtime.WrapDecodePath(err, "EmergencyAreaIDBroadcast")
	}
	v.Value, v.perPadding = value, padding.Padding()
	return nil
}

// MarshalAPEREmergencyAreaIDBroadcast encodes a EmergencyAreaIDBroadcast list to APER.
func BridgeMarshalAPEREmergencyAreaIDBroadcast(list EmergencyAreaIDBroadcastComplete) ([]byte, error) {
	return list.marshalAPERLegacy()
}

// UnmarshalAPEREmergencyAreaIDBroadcast decodes a EmergencyAreaIDBroadcast list from APER.
func BridgeUnmarshalAPEREmergencyAreaIDBroadcast(data []byte) (EmergencyAreaIDBroadcastComplete, error) {
	var value EmergencyAreaIDBroadcastComplete
	if err := value.unmarshalAPERLegacy(data); err != nil {
		return value, err
	}
	return value, nil
}

// UnmarshalAPEREmergencyAreaIDBroadcastFrom decodes a EmergencyAreaIDBroadcast list from bb.
func BridgeUnmarshalAPEREmergencyAreaIDBroadcastFrom(bb *aper.BitBuffer) (s22.EmergencyAreaIDBroadcast, error) {
	if err := bb.EnterDecodeValue(); err != nil {
		return nil, err
	}
	defer bb.LeaveDecodeValue()
	var v s22.BridgeAsn1cAPEREmergencyAreaIDBroadcastListValue
	if err := BridgeUnmarshalAPEREmergencyAreaIDBroadcastInto(&v, bb); err != nil {
		return nil, err
	}
	return v.Value, nil
}
func BridgeUnmarshalAPEREmergencyAreaIDBroadcastInto(v *s22.BridgeAsn1cAPEREmergencyAreaIDBroadcastListValue, bb *aper.BitBuffer) error {
	toleranceMark_value := bb.EnterComponent("Value")
	v.Value = make(s22.EmergencyAreaIDBroadcast, 0)
	_, errCollection_value := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1128
		if fragmentOffset_value < 0 || fragmentLength_value < 0 || fragmentLength_value > int64(^uint(0)>>1) || fragmentOffset_value > int64(^uint(0)>>1)-fragmentLength_value {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_value; i++ {
			var elem s22.EmergencyAreaIDBroadcastItem
			elementMark := bb.EnterIndex(fragmentOffset_value + i)
			if err := s22.BridgeEmergencyAreaIDBroadcastItemMethodUnmarshalAPERFrom(&elem, bb); err != nil {
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

// EmergencyAreaIDCancelledComplete carries a complete EmergencyAreaIDCancelled encoding, including observed terminal bits.
// ITU-T X.691 (02/2021) 11.1.3.1 and 11.1.4 require new encodings to pad with zero bits.
type EmergencyAreaIDCancelledComplete struct {
	replay           aper.Snapshot
	stream           aper.WireSpan
	received         bool
	withoutReplay    bool
	receivedAbsolute bool
	receivedBytes    aper.WireSpan
	receivedLocation aper.Location
	Value            s22.EmergencyAreaIDCancelled
	perPadding       aper.CompletePadding `json:"-"`
}

func (v *EmergencyAreaIDCancelledComplete) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := s26.BridgeMarshalAPEREmergencyAreaIDCancelledTo(v.Value, bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.perPadding)
}

// UnmarshalAPER decodes EmergencyAreaIDCancelled from APER format.
func (v *EmergencyAreaIDCancelledComplete) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes EmergencyAreaIDCancelled with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *EmergencyAreaIDCancelledComplete) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "EmergencyAreaIDCancelled")
	}
	bb.EnterComponent("EmergencyAreaIDCancelled")
	value, err := BridgeUnmarshalAPEREmergencyAreaIDCancelledFrom(bb)
	if err != nil {
		return runtime.WrapDecodePath(err, "EmergencyAreaIDCancelled")
	}
	padding, err := aper.CaptureFinalBits(bb, "EmergencyAreaIDCancelled")
	if err != nil {
		return runtime.WrapDecodePath(err, "EmergencyAreaIDCancelled")
	}
	v.Value, v.perPadding = value, padding.Padding()
	return nil
}

// MarshalAPEREmergencyAreaIDCancelled encodes a EmergencyAreaIDCancelled list to APER.
func BridgeMarshalAPEREmergencyAreaIDCancelled(list EmergencyAreaIDCancelledComplete) ([]byte, error) {
	return list.marshalAPERLegacy()
}

// UnmarshalAPEREmergencyAreaIDCancelled decodes a EmergencyAreaIDCancelled list from APER.
func BridgeUnmarshalAPEREmergencyAreaIDCancelled(data []byte) (EmergencyAreaIDCancelledComplete, error) {
	var value EmergencyAreaIDCancelledComplete
	if err := value.unmarshalAPERLegacy(data); err != nil {
		return value, err
	}
	return value, nil
}

// UnmarshalAPEREmergencyAreaIDCancelledFrom decodes a EmergencyAreaIDCancelled list from bb.
func BridgeUnmarshalAPEREmergencyAreaIDCancelledFrom(bb *aper.BitBuffer) (s22.EmergencyAreaIDCancelled, error) {
	if err := bb.EnterDecodeValue(); err != nil {
		return nil, err
	}
	defer bb.LeaveDecodeValue()
	var v s22.BridgeAsn1cAPEREmergencyAreaIDCancelledListValue
	if err := BridgeUnmarshalAPEREmergencyAreaIDCancelledInto(&v, bb); err != nil {
		return nil, err
	}
	return v.Value, nil
}
func BridgeUnmarshalAPEREmergencyAreaIDCancelledInto(v *s22.BridgeAsn1cAPEREmergencyAreaIDCancelledListValue, bb *aper.BitBuffer) error {
	toleranceMark_value := bb.EnterComponent("Value")
	v.Value = make(s22.EmergencyAreaIDCancelled, 0)
	_, errCollection_value := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1128
		if fragmentOffset_value < 0 || fragmentLength_value < 0 || fragmentLength_value > int64(^uint(0)>>1) || fragmentOffset_value > int64(^uint(0)>>1)-fragmentLength_value {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_value; i++ {
			var elem s22.EmergencyAreaIDCancelledItem
			elementMark := bb.EnterIndex(fragmentOffset_value + i)
			if err := s22.BridgeEmergencyAreaIDCancelledItemMethodUnmarshalAPERFrom(&elem, bb); err != nil {
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

// IEsECGIListComplete carries a complete IEsECGIList encoding, including observed terminal bits.
// ITU-T X.691 (02/2021) 11.1.3.1 and 11.1.4 require new encodings to pad with zero bits.
type IEsECGIListComplete struct {
	replay           aper.Snapshot
	stream           aper.WireSpan
	received         bool
	withoutReplay    bool
	receivedAbsolute bool
	receivedBytes    aper.WireSpan
	receivedLocation aper.Location
	Value            s18.IEsECGIList
	perPadding       aper.CompletePadding `json:"-"`
}

func (v *IEsECGIListComplete) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := s26.BridgeMarshalAPERIEsECGIListTo(v.Value, bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.perPadding)
}

// UnmarshalAPER decodes IEsECGIList from APER format.
func (v *IEsECGIListComplete) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes IEsECGIList with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *IEsECGIListComplete) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "IEsECGIList")
	}
	bb.EnterComponent("IEsECGIList")
	value, err := BridgeUnmarshalAPERIEsECGIListFrom(bb)
	if err != nil {
		return runtime.WrapDecodePath(err, "IEsECGIList")
	}
	padding, err := aper.CaptureFinalBits(bb, "IEsECGIList")
	if err != nil {
		return runtime.WrapDecodePath(err, "IEsECGIList")
	}
	v.Value, v.perPadding = value, padding.Padding()
	return nil
}

// MarshalAPERIEsECGIList encodes a IEsECGIList list to APER.
func BridgeMarshalAPERIEsECGIList(list IEsECGIListComplete) ([]byte, error) {
	return list.marshalAPERLegacy()
}

// UnmarshalAPERIEsECGIList decodes a IEsECGIList list from APER.
func BridgeUnmarshalAPERIEsECGIList(data []byte) (IEsECGIListComplete, error) {
	var value IEsECGIListComplete
	if err := value.unmarshalAPERLegacy(data); err != nil {
		return value, err
	}
	return value, nil
}

// UnmarshalAPERIEsECGIListFrom decodes a IEsECGIList list from bb.
func BridgeUnmarshalAPERIEsECGIListFrom(bb *aper.BitBuffer) (s18.IEsECGIList, error) {
	if err := bb.EnterDecodeValue(); err != nil {
		return nil, err
	}
	defer bb.LeaveDecodeValue()
	var v s21.BridgeAsn1cAPERIEsECGIListListValue
	if err := BridgeUnmarshalAPERIEsECGIListInto(&v, bb); err != nil {
		return nil, err
	}
	return v.Value, nil
}
func BridgeUnmarshalAPERIEsECGIListInto(v *s21.BridgeAsn1cAPERIEsECGIListListValue, bb *aper.BitBuffer) error {
	toleranceMark_value := bb.EnterComponent("Value")
	v.Value = make(s18.IEsECGIList, 0)
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

// EmergencyAreaIDListForRestartComplete carries a complete EmergencyAreaIDListForRestart encoding, including observed terminal bits.
// ITU-T X.691 (02/2021) 11.1.3.1 and 11.1.4 require new encodings to pad with zero bits.
type EmergencyAreaIDListForRestartComplete struct {
	replay           aper.Snapshot
	stream           aper.WireSpan
	received         bool
	withoutReplay    bool
	receivedAbsolute bool
	receivedBytes    aper.WireSpan
	receivedLocation aper.Location
	Value            s00.EmergencyAreaIDListForRestart
	perPadding       aper.CompletePadding `json:"-"`
}

func (v *EmergencyAreaIDListForRestartComplete) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := s13.BridgeMarshalAPEREmergencyAreaIDListForRestartTo(v.Value, bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.perPadding)
}

// UnmarshalAPER decodes EmergencyAreaIDListForRestart from APER format.
func (v *EmergencyAreaIDListForRestartComplete) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes EmergencyAreaIDListForRestart with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *EmergencyAreaIDListForRestartComplete) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "EmergencyAreaIDListForRestart")
	}
	bb.EnterComponent("EmergencyAreaIDListForRestart")
	value, err := BridgeUnmarshalAPEREmergencyAreaIDListForRestartFrom(bb)
	if err != nil {
		return runtime.WrapDecodePath(err, "EmergencyAreaIDListForRestart")
	}
	padding, err := aper.CaptureFinalBits(bb, "EmergencyAreaIDListForRestart")
	if err != nil {
		return runtime.WrapDecodePath(err, "EmergencyAreaIDListForRestart")
	}
	v.Value, v.perPadding = value, padding.Padding()
	return nil
}

// MarshalAPEREmergencyAreaIDListForRestart encodes a EmergencyAreaIDListForRestart list to APER.
func BridgeMarshalAPEREmergencyAreaIDListForRestart(list EmergencyAreaIDListForRestartComplete) ([]byte, error) {
	return list.marshalAPERLegacy()
}

// UnmarshalAPEREmergencyAreaIDListForRestart decodes a EmergencyAreaIDListForRestart list from APER.
func BridgeUnmarshalAPEREmergencyAreaIDListForRestart(data []byte) (EmergencyAreaIDListForRestartComplete, error) {
	var value EmergencyAreaIDListForRestartComplete
	if err := value.unmarshalAPERLegacy(data); err != nil {
		return value, err
	}
	return value, nil
}

// UnmarshalAPEREmergencyAreaIDListForRestartFrom decodes a EmergencyAreaIDListForRestart list from bb.
func BridgeUnmarshalAPEREmergencyAreaIDListForRestartFrom(bb *aper.BitBuffer) (s00.EmergencyAreaIDListForRestart, error) {
	if err := bb.EnterDecodeValue(); err != nil {
		return nil, err
	}
	defer bb.LeaveDecodeValue()
	var v s00.BridgeAsn1cAPEREmergencyAreaIDListForRestartListValue
	if err := BridgeUnmarshalAPEREmergencyAreaIDListForRestartInto(&v, bb); err != nil {
		return nil, err
	}
	return v.Value, nil
}
func BridgeUnmarshalAPEREmergencyAreaIDListForRestartInto(v *s00.BridgeAsn1cAPEREmergencyAreaIDListForRestartListValue, bb *aper.BitBuffer) error {
	toleranceMark_value := bb.EnterComponent("Value")
	v.Value = make(s00.EmergencyAreaIDListForRestart, 0)
	_, errCollection_value := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 256, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
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

// GUMMEIListComplete carries a complete GUMMEIList encoding, including observed terminal bits.
// ITU-T X.691 (02/2021) 11.1.3.1 and 11.1.4 require new encodings to pad with zero bits.
type GUMMEIListComplete struct {
	replay           aper.Snapshot
	stream           aper.WireSpan
	received         bool
	withoutReplay    bool
	receivedAbsolute bool
	receivedBytes    aper.WireSpan
	receivedLocation aper.Location
	Value            s18.GUMMEIList
	perPadding       aper.CompletePadding `json:"-"`
}

func (v *GUMMEIListComplete) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := s26.BridgeMarshalAPERGUMMEIListTo(v.Value, bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.perPadding)
}

// UnmarshalAPER decodes GUMMEIList from APER format.
func (v *GUMMEIListComplete) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes GUMMEIList with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *GUMMEIListComplete) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "GUMMEIList")
	}
	bb.EnterComponent("GUMMEIList")
	value, err := BridgeUnmarshalAPERGUMMEIListFrom(bb)
	if err != nil {
		return runtime.WrapDecodePath(err, "GUMMEIList")
	}
	padding, err := aper.CaptureFinalBits(bb, "GUMMEIList")
	if err != nil {
		return runtime.WrapDecodePath(err, "GUMMEIList")
	}
	v.Value, v.perPadding = value, padding.Padding()
	return nil
}

// MarshalAPERGUMMEIList encodes a GUMMEIList list to APER.
func BridgeMarshalAPERGUMMEIList(list GUMMEIListComplete) ([]byte, error) {
	return list.marshalAPERLegacy()
}

// UnmarshalAPERGUMMEIList decodes a GUMMEIList list from APER.
func BridgeUnmarshalAPERGUMMEIList(data []byte) (GUMMEIListComplete, error) {
	var value GUMMEIListComplete
	if err := value.unmarshalAPERLegacy(data); err != nil {
		return value, err
	}
	return value, nil
}

// UnmarshalAPERGUMMEIListFrom decodes a GUMMEIList list from bb.
func BridgeUnmarshalAPERGUMMEIListFrom(bb *aper.BitBuffer) (s18.GUMMEIList, error) {
	if err := bb.EnterDecodeValue(); err != nil {
		return nil, err
	}
	defer bb.LeaveDecodeValue()
	var v s21.BridgeAsn1cAPERGUMMEIListListValue
	if err := BridgeUnmarshalAPERGUMMEIListInto(&v, bb); err != nil {
		return nil, err
	}
	return v.Value, nil
}
func BridgeUnmarshalAPERGUMMEIListInto(v *s21.BridgeAsn1cAPERGUMMEIListListValue, bb *aper.BitBuffer) error {
	toleranceMark_value := bb.EnterComponent("Value")
	v.Value = make(s18.GUMMEIList, 0)
	_, errCollection_value := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 256, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1128
		if fragmentOffset_value < 0 || fragmentLength_value < 0 || fragmentLength_value > int64(^uint(0)>>1) || fragmentOffset_value > int64(^uint(0)>>1)-fragmentLength_value {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_value; i++ {
			var elem s18.GUMMEI
			elementMark := bb.EnterIndex(fragmentOffset_value + i)
			if err := s18.BridgeGUMMEIMethodUnmarshalAPERFrom(&elem, bb); err != nil {
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

// ERABUsageReportListComplete carries a complete ERABUsageReportList encoding, including observed terminal bits.
// ITU-T X.691 (02/2021) 11.1.3.1 and 11.1.4 require new encodings to pad with zero bits.
type ERABUsageReportListComplete struct {
	replay           aper.Snapshot
	stream           aper.WireSpan
	received         bool
	withoutReplay    bool
	receivedAbsolute bool
	receivedBytes    aper.WireSpan
	receivedLocation aper.Location
	Value            s17.ERABUsageReportList
	perPadding       aper.CompletePadding `json:"-"`
}

func (v *ERABUsageReportListComplete) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := s26.BridgeMarshalAPERERABUsageReportListTo(v.Value, bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.perPadding)
}

// UnmarshalAPER decodes ERABUsageReportList from APER format.
func (v *ERABUsageReportListComplete) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes ERABUsageReportList with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *ERABUsageReportListComplete) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "ERABUsageReportList")
	}
	bb.EnterComponent("ERABUsageReportList")
	value, err := BridgeUnmarshalAPERERABUsageReportListFrom(bb)
	if err != nil {
		return runtime.WrapDecodePath(err, "ERABUsageReportList")
	}
	padding, err := aper.CaptureFinalBits(bb, "ERABUsageReportList")
	if err != nil {
		return runtime.WrapDecodePath(err, "ERABUsageReportList")
	}
	v.Value, v.perPadding = value, padding.Padding()
	return nil
}

// MarshalAPERERABUsageReportList encodes a ERABUsageReportList list to APER.
func BridgeMarshalAPERERABUsageReportList(list ERABUsageReportListComplete) ([]byte, error) {
	return list.marshalAPERLegacy()
}

// UnmarshalAPERERABUsageReportList decodes a ERABUsageReportList list from APER.
func BridgeUnmarshalAPERERABUsageReportList(data []byte) (ERABUsageReportListComplete, error) {
	var value ERABUsageReportListComplete
	if err := value.unmarshalAPERLegacy(data); err != nil {
		return value, err
	}
	return value, nil
}

// UnmarshalAPERERABUsageReportListFrom decodes a ERABUsageReportList list from bb.
func BridgeUnmarshalAPERERABUsageReportListFrom(bb *aper.BitBuffer) (s17.ERABUsageReportList, error) {
	if err := bb.EnterDecodeValue(); err != nil {
		return nil, err
	}
	defer bb.LeaveDecodeValue()
	var v s21.BridgeAsn1cAPERERABUsageReportListListValue
	if err := BridgeUnmarshalAPERERABUsageReportListInto(&v, bb); err != nil {
		return nil, err
	}
	return v.Value, nil
}
func BridgeUnmarshalAPERERABUsageReportListInto(v *s21.BridgeAsn1cAPERERABUsageReportListListValue, bb *aper.BitBuffer) error {
	toleranceMark_value := bb.EnterComponent("Value")
	v.Value = make(s17.ERABUsageReportList, 0)
	_, errCollection_value := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 2, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1128
		if fragmentOffset_value < 0 || fragmentLength_value < 0 || fragmentLength_value > int64(^uint(0)>>1) || fragmentOffset_value > int64(^uint(0)>>1)-fragmentLength_value {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_value; i++ {
			var elem s17.ERABUsageReportItemIEValueProtocolIESingleContainer
			elementMark := bb.EnterIndex(fragmentOffset_value + i)
			if err := s17.BridgeERABUsageReportItemIEFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
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

// ForbiddenTAsComplete carries a complete ForbiddenTAs encoding, including observed terminal bits.
// ITU-T X.691 (02/2021) 11.1.3.1 and 11.1.4 require new encodings to pad with zero bits.
type ForbiddenTAsComplete struct {
	replay           aper.Snapshot
	stream           aper.WireSpan
	received         bool
	withoutReplay    bool
	receivedAbsolute bool
	receivedBytes    aper.WireSpan
	receivedLocation aper.Location
	Value            s18.ForbiddenTAs
	perPadding       aper.CompletePadding `json:"-"`
}

func (v *ForbiddenTAsComplete) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := s26.BridgeMarshalAPERForbiddenTAsTo(v.Value, bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.perPadding)
}

// UnmarshalAPER decodes ForbiddenTAs from APER format.
func (v *ForbiddenTAsComplete) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes ForbiddenTAs with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *ForbiddenTAsComplete) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "ForbiddenTAs")
	}
	bb.EnterComponent("ForbiddenTAs")
	value, err := BridgeUnmarshalAPERForbiddenTAsFrom(bb)
	if err != nil {
		return runtime.WrapDecodePath(err, "ForbiddenTAs")
	}
	padding, err := aper.CaptureFinalBits(bb, "ForbiddenTAs")
	if err != nil {
		return runtime.WrapDecodePath(err, "ForbiddenTAs")
	}
	v.Value, v.perPadding = value, padding.Padding()
	return nil
}

// MarshalAPERForbiddenTAs encodes a ForbiddenTAs list to APER.
func BridgeMarshalAPERForbiddenTAs(list ForbiddenTAsComplete) ([]byte, error) {
	return list.marshalAPERLegacy()
}

// UnmarshalAPERForbiddenTAs decodes a ForbiddenTAs list from APER.
func BridgeUnmarshalAPERForbiddenTAs(data []byte) (ForbiddenTAsComplete, error) {
	var value ForbiddenTAsComplete
	if err := value.unmarshalAPERLegacy(data); err != nil {
		return value, err
	}
	return value, nil
}

// UnmarshalAPERForbiddenTAsFrom decodes a ForbiddenTAs list from bb.
func BridgeUnmarshalAPERForbiddenTAsFrom(bb *aper.BitBuffer) (s18.ForbiddenTAs, error) {
	if err := bb.EnterDecodeValue(); err != nil {
		return nil, err
	}
	defer bb.LeaveDecodeValue()
	var v s21.BridgeAsn1cAPERForbiddenTAsListValue
	if err := BridgeUnmarshalAPERForbiddenTAsInto(&v, bb); err != nil {
		return nil, err
	}
	return v.Value, nil
}
func BridgeUnmarshalAPERForbiddenTAsInto(v *s21.BridgeAsn1cAPERForbiddenTAsListValue, bb *aper.BitBuffer) error {
	toleranceMark_value := bb.EnterComponent("Value")
	v.Value = make(s18.ForbiddenTAs, 0)
	_, errCollection_value := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 16, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1128
		if fragmentOffset_value < 0 || fragmentLength_value < 0 || fragmentLength_value > int64(^uint(0)>>1) || fragmentOffset_value > int64(^uint(0)>>1)-fragmentLength_value {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_value; i++ {
			var elem s18.ForbiddenTAsItem
			elementMark := bb.EnterIndex(fragmentOffset_value + i)
			if err := s18.BridgeForbiddenTAsItemMethodUnmarshalAPERFrom(&elem, bb); err != nil {
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

// ForbiddenTACsComplete carries a complete ForbiddenTACs encoding, including observed terminal bits.
// ITU-T X.691 (02/2021) 11.1.3.1 and 11.1.4 require new encodings to pad with zero bits.
type ForbiddenTACsComplete struct {
	replay           aper.Snapshot
	stream           aper.WireSpan
	received         bool
	withoutReplay    bool
	receivedAbsolute bool
	receivedBytes    aper.WireSpan
	receivedLocation aper.Location
	Value            s00.ForbiddenTACs
	perPadding       aper.CompletePadding `json:"-"`
}

func (v *ForbiddenTACsComplete) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := s13.BridgeMarshalAPERForbiddenTACsTo(v.Value, bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.perPadding)
}

// UnmarshalAPER decodes ForbiddenTACs from APER format.
func (v *ForbiddenTACsComplete) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes ForbiddenTACs with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *ForbiddenTACsComplete) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "ForbiddenTACs")
	}
	bb.EnterComponent("ForbiddenTACs")
	value, err := BridgeUnmarshalAPERForbiddenTACsFrom(bb)
	if err != nil {
		return runtime.WrapDecodePath(err, "ForbiddenTACs")
	}
	padding, err := aper.CaptureFinalBits(bb, "ForbiddenTACs")
	if err != nil {
		return runtime.WrapDecodePath(err, "ForbiddenTACs")
	}
	v.Value, v.perPadding = value, padding.Padding()
	return nil
}

// MarshalAPERForbiddenTACs encodes a ForbiddenTACs list to APER.
func BridgeMarshalAPERForbiddenTACs(list ForbiddenTACsComplete) ([]byte, error) {
	return list.marshalAPERLegacy()
}

// UnmarshalAPERForbiddenTACs decodes a ForbiddenTACs list from APER.
func BridgeUnmarshalAPERForbiddenTACs(data []byte) (ForbiddenTACsComplete, error) {
	var value ForbiddenTACsComplete
	if err := value.unmarshalAPERLegacy(data); err != nil {
		return value, err
	}
	return value, nil
}

// UnmarshalAPERForbiddenTACsFrom decodes a ForbiddenTACs list from bb.
func BridgeUnmarshalAPERForbiddenTACsFrom(bb *aper.BitBuffer) (s00.ForbiddenTACs, error) {
	if err := bb.EnterDecodeValue(); err != nil {
		return nil, err
	}
	defer bb.LeaveDecodeValue()
	var v s00.BridgeAsn1cAPERForbiddenTACsListValue
	if err := BridgeUnmarshalAPERForbiddenTACsInto(&v, bb); err != nil {
		return nil, err
	}
	return v.Value, nil
}
func BridgeUnmarshalAPERForbiddenTACsInto(v *s00.BridgeAsn1cAPERForbiddenTACsListValue, bb *aper.BitBuffer) error {
	toleranceMark_value := bb.EnterComponent("Value")
	v.Value = make(s00.ForbiddenTACs, 0)
	_, errCollection_value := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 4096, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
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

// ForbiddenLAsComplete carries a complete ForbiddenLAs encoding, including observed terminal bits.
// ITU-T X.691 (02/2021) 11.1.3.1 and 11.1.4 require new encodings to pad with zero bits.
type ForbiddenLAsComplete struct {
	replay           aper.Snapshot
	stream           aper.WireSpan
	received         bool
	withoutReplay    bool
	receivedAbsolute bool
	receivedBytes    aper.WireSpan
	receivedLocation aper.Location
	Value            s18.ForbiddenLAs
	perPadding       aper.CompletePadding `json:"-"`
}

func (v *ForbiddenLAsComplete) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := s26.BridgeMarshalAPERForbiddenLAsTo(v.Value, bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.perPadding)
}

// UnmarshalAPER decodes ForbiddenLAs from APER format.
func (v *ForbiddenLAsComplete) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes ForbiddenLAs with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *ForbiddenLAsComplete) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "ForbiddenLAs")
	}
	bb.EnterComponent("ForbiddenLAs")
	value, err := BridgeUnmarshalAPERForbiddenLAsFrom(bb)
	if err != nil {
		return runtime.WrapDecodePath(err, "ForbiddenLAs")
	}
	padding, err := aper.CaptureFinalBits(bb, "ForbiddenLAs")
	if err != nil {
		return runtime.WrapDecodePath(err, "ForbiddenLAs")
	}
	v.Value, v.perPadding = value, padding.Padding()
	return nil
}

// MarshalAPERForbiddenLAs encodes a ForbiddenLAs list to APER.
func BridgeMarshalAPERForbiddenLAs(list ForbiddenLAsComplete) ([]byte, error) {
	return list.marshalAPERLegacy()
}

// UnmarshalAPERForbiddenLAs decodes a ForbiddenLAs list from APER.
func BridgeUnmarshalAPERForbiddenLAs(data []byte) (ForbiddenLAsComplete, error) {
	var value ForbiddenLAsComplete
	if err := value.unmarshalAPERLegacy(data); err != nil {
		return value, err
	}
	return value, nil
}

// UnmarshalAPERForbiddenLAsFrom decodes a ForbiddenLAs list from bb.
func BridgeUnmarshalAPERForbiddenLAsFrom(bb *aper.BitBuffer) (s18.ForbiddenLAs, error) {
	if err := bb.EnterDecodeValue(); err != nil {
		return nil, err
	}
	defer bb.LeaveDecodeValue()
	var v s21.BridgeAsn1cAPERForbiddenLAsListValue
	if err := BridgeUnmarshalAPERForbiddenLAsInto(&v, bb); err != nil {
		return nil, err
	}
	return v.Value, nil
}
func BridgeUnmarshalAPERForbiddenLAsInto(v *s21.BridgeAsn1cAPERForbiddenLAsListValue, bb *aper.BitBuffer) error {
	toleranceMark_value := bb.EnterComponent("Value")
	v.Value = make(s18.ForbiddenLAs, 0)
	_, errCollection_value := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 16, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1128
		if fragmentOffset_value < 0 || fragmentLength_value < 0 || fragmentLength_value > int64(^uint(0)>>1) || fragmentOffset_value > int64(^uint(0)>>1)-fragmentLength_value {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_value; i++ {
			var elem s18.ForbiddenLAsItem
			elementMark := bb.EnterIndex(fragmentOffset_value + i)
			if err := s18.BridgeForbiddenLAsItemMethodUnmarshalAPERFrom(&elem, bb); err != nil {
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

// ForbiddenLACsComplete carries a complete ForbiddenLACs encoding, including observed terminal bits.
// ITU-T X.691 (02/2021) 11.1.3.1 and 11.1.4 require new encodings to pad with zero bits.
type ForbiddenLACsComplete struct {
	replay           aper.Snapshot
	stream           aper.WireSpan
	received         bool
	withoutReplay    bool
	receivedAbsolute bool
	receivedBytes    aper.WireSpan
	receivedLocation aper.Location
	Value            s00.ForbiddenLACs
	perPadding       aper.CompletePadding `json:"-"`
}

func (v *ForbiddenLACsComplete) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := s13.BridgeMarshalAPERForbiddenLACsTo(v.Value, bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.perPadding)
}

// UnmarshalAPER decodes ForbiddenLACs from APER format.
func (v *ForbiddenLACsComplete) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes ForbiddenLACs with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *ForbiddenLACsComplete) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "ForbiddenLACs")
	}
	bb.EnterComponent("ForbiddenLACs")
	value, err := BridgeUnmarshalAPERForbiddenLACsFrom(bb)
	if err != nil {
		return runtime.WrapDecodePath(err, "ForbiddenLACs")
	}
	padding, err := aper.CaptureFinalBits(bb, "ForbiddenLACs")
	if err != nil {
		return runtime.WrapDecodePath(err, "ForbiddenLACs")
	}
	v.Value, v.perPadding = value, padding.Padding()
	return nil
}

// MarshalAPERForbiddenLACs encodes a ForbiddenLACs list to APER.
func BridgeMarshalAPERForbiddenLACs(list ForbiddenLACsComplete) ([]byte, error) {
	return list.marshalAPERLegacy()
}

// UnmarshalAPERForbiddenLACs decodes a ForbiddenLACs list from APER.
func BridgeUnmarshalAPERForbiddenLACs(data []byte) (ForbiddenLACsComplete, error) {
	var value ForbiddenLACsComplete
	if err := value.unmarshalAPERLegacy(data); err != nil {
		return value, err
	}
	return value, nil
}

// UnmarshalAPERForbiddenLACsFrom decodes a ForbiddenLACs list from bb.
func BridgeUnmarshalAPERForbiddenLACsFrom(bb *aper.BitBuffer) (s00.ForbiddenLACs, error) {
	if err := bb.EnterDecodeValue(); err != nil {
		return nil, err
	}
	defer bb.LeaveDecodeValue()
	var v s00.BridgeAsn1cAPERForbiddenLACsListValue
	if err := BridgeUnmarshalAPERForbiddenLACsInto(&v, bb); err != nil {
		return nil, err
	}
	return v.Value, nil
}
func BridgeUnmarshalAPERForbiddenLACsInto(v *s00.BridgeAsn1cAPERForbiddenLACsListValue, bb *aper.BitBuffer) error {
	toleranceMark_value := bb.EnterComponent("Value")
	v.Value = make(s00.ForbiddenLACs, 0)
	_, errCollection_value := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 4096, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
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

// InterSystemMeasurementListComplete carries a complete InterSystemMeasurementList encoding, including observed terminal bits.
// ITU-T X.691 (02/2021) 11.1.3.1 and 11.1.4 require new encodings to pad with zero bits.
type InterSystemMeasurementListComplete struct {
	replay           aper.Snapshot
	stream           aper.WireSpan
	received         bool
	withoutReplay    bool
	receivedAbsolute bool
	receivedBytes    aper.WireSpan
	receivedLocation aper.Location
	Value            s18.InterSystemMeasurementList
	perPadding       aper.CompletePadding `json:"-"`
}

func (v *InterSystemMeasurementListComplete) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := s26.BridgeMarshalAPERInterSystemMeasurementListTo(v.Value, bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.perPadding)
}

// UnmarshalAPER decodes InterSystemMeasurementList from APER format.
func (v *InterSystemMeasurementListComplete) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes InterSystemMeasurementList with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *InterSystemMeasurementListComplete) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "InterSystemMeasurementList")
	}
	bb.EnterComponent("InterSystemMeasurementList")
	value, err := BridgeUnmarshalAPERInterSystemMeasurementListFrom(bb)
	if err != nil {
		return runtime.WrapDecodePath(err, "InterSystemMeasurementList")
	}
	padding, err := aper.CaptureFinalBits(bb, "InterSystemMeasurementList")
	if err != nil {
		return runtime.WrapDecodePath(err, "InterSystemMeasurementList")
	}
	v.Value, v.perPadding = value, padding.Padding()
	return nil
}

// MarshalAPERInterSystemMeasurementList encodes a InterSystemMeasurementList list to APER.
func BridgeMarshalAPERInterSystemMeasurementList(list InterSystemMeasurementListComplete) ([]byte, error) {
	return list.marshalAPERLegacy()
}

// UnmarshalAPERInterSystemMeasurementList decodes a InterSystemMeasurementList list from APER.
func BridgeUnmarshalAPERInterSystemMeasurementList(data []byte) (InterSystemMeasurementListComplete, error) {
	var value InterSystemMeasurementListComplete
	if err := value.unmarshalAPERLegacy(data); err != nil {
		return value, err
	}
	return value, nil
}

// UnmarshalAPERInterSystemMeasurementListFrom decodes a InterSystemMeasurementList list from bb.
func BridgeUnmarshalAPERInterSystemMeasurementListFrom(bb *aper.BitBuffer) (s18.InterSystemMeasurementList, error) {
	if err := bb.EnterDecodeValue(); err != nil {
		return nil, err
	}
	defer bb.LeaveDecodeValue()
	var v s21.BridgeAsn1cAPERInterSystemMeasurementListListValue
	if err := BridgeUnmarshalAPERInterSystemMeasurementListInto(&v, bb); err != nil {
		return nil, err
	}
	return v.Value, nil
}
func BridgeUnmarshalAPERInterSystemMeasurementListInto(v *s21.BridgeAsn1cAPERInterSystemMeasurementListListValue, bb *aper.BitBuffer) error {
	toleranceMark_value := bb.EnterComponent("Value")
	v.Value = make(s18.InterSystemMeasurementList, 0)
	_, errCollection_value := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 64, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1128
		if fragmentOffset_value < 0 || fragmentLength_value < 0 || fragmentLength_value > int64(^uint(0)>>1) || fragmentOffset_value > int64(^uint(0)>>1)-fragmentLength_value {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_value; i++ {
			var elem s18.InterSystemMeasurementItem
			elementMark := bb.EnterIndex(fragmentOffset_value + i)
			if err := s18.BridgeInterSystemMeasurementItemMethodUnmarshalAPERFrom(&elem, bb); err != nil {
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

// MarshalAPER encodes LastVisitedCellItem to APER format.
func (v *LastVisitedCellItem) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.perPadding)
}
func (v *LastVisitedCellItem) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
			return fmt.Errorf("%s known choice %d and unknown extension are both selected", "LastVisitedCellItem:", v.Choice)
		}
		if v.UnknownExtension.Index() < 0 {
			return fmt.Errorf("%s extension index %d must be non-negative", "LastVisitedCellItem:", v.UnknownExtension.Index())
		}
		if v.UnknownExtension.Index() < 1 {
			return fmt.Errorf("%s extension index %d is known to this schema", "LastVisitedCellItem:", v.UnknownExtension.Index())
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
		return fmt.Errorf("%s choice %d must be positive", "LastVisitedCellItem:", v.Choice)
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
		case s00.LastVisitedCellItemChoiceNGRANCell:
			if v.NGRANCell == nil {
				return fmt.Errorf("choice alternative nG-RAN-Cell is nil")
			}
			if err := aper.EncodeOctetStringAligned(inner, []byte(*v.NGRANCell), 0, 0, false); err != nil {
				return fmt.Errorf("encoding nG-RAN-Cell: %w", err)
			}
		default:
			return fmt.Errorf("unknown LastVisitedCellItem extension choice %d", v.Choice)
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
	case s00.LastVisitedCellItemChoiceEUTRANCell:
		if v.EUTRANCell == nil {
			return fmt.Errorf("choice alternative e-UTRAN-Cell is nil")
		}
		if err := v.EUTRANCell.marshalAPERTo(bb, len(fresh) != 0 && fresh[0]); err != nil {
			return fmt.Errorf("encoding e-UTRAN-Cell: %w", err)
		}
	case s00.LastVisitedCellItemChoiceUTRANCell:
		if v.UTRANCell == nil {
			return fmt.Errorf("choice alternative uTRAN-Cell is nil")
		}
		if err := aper.EncodeOctetStringAligned(bb, []byte(*v.UTRANCell), 0, 0, false); err != nil {
			return fmt.Errorf("encoding uTRAN-Cell: %w", err)
		}
	case s00.LastVisitedCellItemChoiceGERANCell:
		if v.GERANCell == nil {
			return fmt.Errorf("choice alternative gERAN-Cell is nil")
		}
		if err := s18.BridgeLastVisitedGERANCellInformationMethodMarshalAPERTo(v.GERANCell, bb, len(fresh) != 0 && fresh[0]); err != nil {
			return fmt.Errorf("encoding gERAN-Cell: %w", err)
		}
	default:
		return fmt.Errorf("unknown LastVisitedCellItem choice %d", v.Choice)
	}
	return nil
}

// UnmarshalAPER decodes LastVisitedCellItem from APER format.
func (v *LastVisitedCellItem) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes LastVisitedCellItem with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *LastVisitedCellItem) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "LastVisitedCellItem")
	}
	bb.EnterComponent("LastVisitedCellItem")
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "LastVisitedCellItem")
	}
	padding, err := aper.CaptureFinalBits(bb, "LastVisitedCellItem")
	if err != nil {
		return runtime.WrapDecodePath(err, "LastVisitedCellItem")
	}
	v.perPadding = padding.Padding()
	return nil
}
func (v *LastVisitedCellItem) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = LastVisitedCellItem{}
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
		case s00.LastVisitedCellItemChoiceNGRANCell:
			extensionPath = "NGRANCell"
			val_ngrancell, err := aper.DecodeOctetStringAligned(inner, 0, 0, false)
			if err != nil {
				return runtime.WrapDecodePath(err, "NGRANCell")
			}
			tmp_ngrancell := s00.LastVisitedNGRANCellInformation(val_ngrancell)
			if err := aper.ChargeValue(inner, tmp_ngrancell); err != nil {
				return err
			}
			v.NGRANCell = &tmp_ngrancell
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
	case s00.LastVisitedCellItemChoiceEUTRANCell:
		toleranceMark_eutrancell := bb.EnterComponent("EUTRANCell")
		var dec_eutrancell LastVisitedEUTRANCellInformation
		if err := dec_eutrancell.unmarshalAPERFrom(bb); err != nil {
			return runtime.WrapDecodePath(err, "EUTRANCell")
		}
		if err := aper.ChargeValue(bb, dec_eutrancell); err != nil {
			return err
		}
		v.EUTRANCell = &dec_eutrancell
		bb.LeaveComponent(toleranceMark_eutrancell)
	case s00.LastVisitedCellItemChoiceUTRANCell:
		val_utrancell, err := aper.DecodeOctetStringAligned(bb, 0, 0, false)
		if err != nil {
			return runtime.WrapDecodePath(err, "UTRANCell")
		}
		tmp_utrancell := s00.LastVisitedUTRANCellInformation(val_utrancell)
		if err := aper.ChargeValue(bb, tmp_utrancell); err != nil {
			return err
		}
		v.UTRANCell = &tmp_utrancell
	case s00.LastVisitedCellItemChoiceGERANCell:
		toleranceMark_gerancell := bb.EnterComponent("GERANCell")
		var dec_gerancell s18.LastVisitedGERANCellInformation
		if err := s18.BridgeLastVisitedGERANCellInformationMethodUnmarshalAPERFrom(&dec_gerancell, bb); err != nil {
			return runtime.WrapDecodePath(err, "GERANCell")
		}
		if err := aper.ChargeValue(bb, dec_gerancell); err != nil {
			return err
		}
		v.GERANCell = &dec_gerancell
		bb.LeaveComponent(toleranceMark_gerancell)
	}
	v.stream = bb.CaptureWireSpan(replayStart)

	return nil
}

// MarshalAPER encodes LastVisitedEUTRANCellInformation to APER format.
func (v *LastVisitedEUTRANCellInformation) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *LastVisitedEUTRANCellInformation) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
	if err := s17.BridgeEUTRANCGIMethodMarshalAPERTo(&v.GlobalCellID, bb, len(fresh) != 0 && fresh[0]); err != nil {
		return fmt.Errorf("encoding global-Cell-ID: %w", err)
	}
	if err := s14.BridgeCellTypeMethodMarshalAPERTo(&v.CellType, bb, len(fresh) != 0 && fresh[0]); err != nil {
		return fmt.Errorf("encoding cellType: %w", err)
	}
	if err := aper.EncodeIntegerAligned(bb, int64(v.TimeUEStayedInCell), s07.BridgeInt64Ptr(0), s07.BridgeInt64Ptr(4095), false); err != nil {
		return fmt.Errorf("encoding time-UE-StayedInCell: %w", err)
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

// UnmarshalAPER decodes LastVisitedEUTRANCellInformation from APER format.
func (v *LastVisitedEUTRANCellInformation) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes LastVisitedEUTRANCellInformation with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *LastVisitedEUTRANCellInformation) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "LastVisitedEUTRANCellInformation")
	}
	bb.EnterComponent("LastVisitedEUTRANCellInformation")
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "LastVisitedEUTRANCellInformation")
	}
	padding, err := aper.CaptureFinalBits(bb, "LastVisitedEUTRANCellInformation")
	if err != nil {
		return runtime.WrapDecodePath(err, "LastVisitedEUTRANCellInformation")
	}
	v.perPadding = padding.WithRecords(v.perPadding)
	return nil
}
func (v *LastVisitedEUTRANCellInformation) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = LastVisitedEUTRANCellInformation{}
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
	toleranceMark_globalcellid := bb.EnterComponent("GlobalCellID")
	if err := s17.BridgeEUTRANCGIMethodUnmarshalAPERFrom(&v.GlobalCellID, bb); err != nil {
		return runtime.WrapDecodePath(err, "GlobalCellID")
	}
	bb.LeaveComponent(toleranceMark_globalcellid)
	toleranceMark_celltype := bb.EnterComponent("CellType")
	if err := s14.BridgeCellTypeMethodUnmarshalAPERFrom(&v.CellType, bb); err != nil {
		return runtime.WrapDecodePath(err, "CellType")
	}
	bb.LeaveComponent(toleranceMark_celltype)
	val_timeuestayedincell, err := aper.DecodeIntegerAligned(bb, s07.BridgeInt64Ptr(0), s07.BridgeInt64Ptr(4095), false)
	if err != nil {
		return runtime.WrapDecodePath(err, "TimeUEStayedInCell")
	}
	v.TimeUEStayedInCell = s00.TimeUEStayedInCell(val_timeuestayedincell)
	if opt_ieextensions {
		toleranceMark_ieextensions := bb.EnterComponent("IEExtensions")
		tmp_ieextensions := make(LastVisitedEUTRANCellInformationExtIEsExtContainer, 0)
		_, errCollection_ieextensions := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1128
			if fragmentOffset_ieextensions < 0 || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(^uint(0)>>1) || fragmentOffset_ieextensions > int64(^uint(0)>>1)-fragmentLength_ieextensions {
				return fmt.Errorf("collection fragment count out of range")
			}
			for i := int64(0); i < fragmentLength_ieextensions; i++ {
				var elem LastVisitedEUTRANCellInformationExtIEsExtField
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

// LastVisitedPSCellListComplete carries a complete LastVisitedPSCellList encoding, including observed terminal bits.
// ITU-T X.691 (02/2021) 11.1.3.1 and 11.1.4 require new encodings to pad with zero bits.
type LastVisitedPSCellListComplete struct {
	replay           aper.Snapshot
	stream           aper.WireSpan
	received         bool
	withoutReplay    bool
	receivedAbsolute bool
	receivedBytes    aper.WireSpan
	receivedLocation aper.Location
	Value            s20.LastVisitedPSCellList
	perPadding       aper.CompletePadding `json:"-"`
}

func (v *LastVisitedPSCellListComplete) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := s26.BridgeMarshalAPERLastVisitedPSCellListTo(v.Value, bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.perPadding)
}

// UnmarshalAPER decodes LastVisitedPSCellList from APER format.
func (v *LastVisitedPSCellListComplete) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes LastVisitedPSCellList with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *LastVisitedPSCellListComplete) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "LastVisitedPSCellList")
	}
	bb.EnterComponent("LastVisitedPSCellList")
	value, err := BridgeUnmarshalAPERLastVisitedPSCellListFrom(bb)
	if err != nil {
		return runtime.WrapDecodePath(err, "LastVisitedPSCellList")
	}
	padding, err := aper.CaptureFinalBits(bb, "LastVisitedPSCellList")
	if err != nil {
		return runtime.WrapDecodePath(err, "LastVisitedPSCellList")
	}
	v.Value, v.perPadding = value, padding.Padding()
	return nil
}

// MarshalAPERLastVisitedPSCellList encodes a LastVisitedPSCellList list to APER.
func BridgeMarshalAPERLastVisitedPSCellList(list LastVisitedPSCellListComplete) ([]byte, error) {
	return list.marshalAPERLegacy()
}

// UnmarshalAPERLastVisitedPSCellList decodes a LastVisitedPSCellList list from APER.
func BridgeUnmarshalAPERLastVisitedPSCellList(data []byte) (LastVisitedPSCellListComplete, error) {
	var value LastVisitedPSCellListComplete
	if err := value.unmarshalAPERLegacy(data); err != nil {
		return value, err
	}
	return value, nil
}

// UnmarshalAPERLastVisitedPSCellListFrom decodes a LastVisitedPSCellList list from bb.
func BridgeUnmarshalAPERLastVisitedPSCellListFrom(bb *aper.BitBuffer) (s20.LastVisitedPSCellList, error) {
	if err := bb.EnterDecodeValue(); err != nil {
		return nil, err
	}
	defer bb.LeaveDecodeValue()
	var v s21.BridgeAsn1cAPERLastVisitedPSCellListListValue
	if err := BridgeUnmarshalAPERLastVisitedPSCellListInto(&v, bb); err != nil {
		return nil, err
	}
	return v.Value, nil
}
func BridgeUnmarshalAPERLastVisitedPSCellListInto(v *s21.BridgeAsn1cAPERLastVisitedPSCellListListValue, bb *aper.BitBuffer) error {
	toleranceMark_value := bb.EnterComponent("Value")
	v.Value = make(s20.LastVisitedPSCellList, 0)
	_, errCollection_value := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 8, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1128
		if fragmentOffset_value < 0 || fragmentLength_value < 0 || fragmentLength_value > int64(^uint(0)>>1) || fragmentOffset_value > int64(^uint(0)>>1)-fragmentLength_value {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_value; i++ {
			var elem s20.LastVisitedPSCellInformation
			elementMark := bb.EnterIndex(fragmentOffset_value + i)
			if err := s20.BridgeLastVisitedPSCellInformationMethodUnmarshalAPERFrom(&elem, bb); err != nil {
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

// MBSFNResultToLogComplete carries a complete MBSFNResultToLog encoding, including observed terminal bits.
// ITU-T X.691 (02/2021) 11.1.3.1 and 11.1.4 require new encodings to pad with zero bits.
type MBSFNResultToLogComplete struct {
	replay           aper.Snapshot
	stream           aper.WireSpan
	received         bool
	withoutReplay    bool
	receivedAbsolute bool
	receivedBytes    aper.WireSpan
	receivedLocation aper.Location
	Value            s19.MBSFNResultToLog
	perPadding       aper.CompletePadding `json:"-"`
}

func (v *MBSFNResultToLogComplete) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := s26.BridgeMarshalAPERMBSFNResultToLogTo(v.Value, bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.perPadding)
}

// UnmarshalAPER decodes MBSFNResultToLog from APER format.
func (v *MBSFNResultToLogComplete) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes MBSFNResultToLog with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *MBSFNResultToLogComplete) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "MBSFNResultToLog")
	}
	bb.EnterComponent("MBSFNResultToLog")
	value, err := BridgeUnmarshalAPERMBSFNResultToLogFrom(bb)
	if err != nil {
		return runtime.WrapDecodePath(err, "MBSFNResultToLog")
	}
	padding, err := aper.CaptureFinalBits(bb, "MBSFNResultToLog")
	if err != nil {
		return runtime.WrapDecodePath(err, "MBSFNResultToLog")
	}
	v.Value, v.perPadding = value, padding.Padding()
	return nil
}

// MarshalAPERMBSFNResultToLog encodes a MBSFNResultToLog list to APER.
func BridgeMarshalAPERMBSFNResultToLog(list MBSFNResultToLogComplete) ([]byte, error) {
	return list.marshalAPERLegacy()
}

// UnmarshalAPERMBSFNResultToLog decodes a MBSFNResultToLog list from APER.
func BridgeUnmarshalAPERMBSFNResultToLog(data []byte) (MBSFNResultToLogComplete, error) {
	var value MBSFNResultToLogComplete
	if err := value.unmarshalAPERLegacy(data); err != nil {
		return value, err
	}
	return value, nil
}

// UnmarshalAPERMBSFNResultToLogFrom decodes a MBSFNResultToLog list from bb.
func BridgeUnmarshalAPERMBSFNResultToLogFrom(bb *aper.BitBuffer) (s19.MBSFNResultToLog, error) {
	if err := bb.EnterDecodeValue(); err != nil {
		return nil, err
	}
	defer bb.LeaveDecodeValue()
	var v s21.BridgeAsn1cAPERMBSFNResultToLogListValue
	if err := BridgeUnmarshalAPERMBSFNResultToLogInto(&v, bb); err != nil {
		return nil, err
	}
	return v.Value, nil
}
func BridgeUnmarshalAPERMBSFNResultToLogInto(v *s21.BridgeAsn1cAPERMBSFNResultToLogListValue, bb *aper.BitBuffer) error {
	toleranceMark_value := bb.EnterComponent("Value")
	v.Value = make(s19.MBSFNResultToLog, 0)
	_, errCollection_value := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 8, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1128
		if fragmentOffset_value < 0 || fragmentLength_value < 0 || fragmentLength_value > int64(^uint(0)>>1) || fragmentOffset_value > int64(^uint(0)>>1)-fragmentLength_value {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_value; i++ {
			var elem s19.MBSFNResultToLogInfo
			elementMark := bb.EnterIndex(fragmentOffset_value + i)
			if err := s19.BridgeMBSFNResultToLogInfoMethodUnmarshalAPERFrom(&elem, bb); err != nil {
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

// MDTPLMNListComplete carries a complete MDTPLMNList encoding, including observed terminal bits.
// ITU-T X.691 (02/2021) 11.1.3.1 and 11.1.4 require new encodings to pad with zero bits.
type MDTPLMNListComplete struct {
	replay           aper.Snapshot
	stream           aper.WireSpan
	received         bool
	withoutReplay    bool
	receivedAbsolute bool
	receivedBytes    aper.WireSpan
	receivedLocation aper.Location
	Value            s00.MDTPLMNList
	perPadding       aper.CompletePadding `json:"-"`
}

func (v *MDTPLMNListComplete) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := s13.BridgeMarshalAPERMDTPLMNListTo(v.Value, bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.perPadding)
}

// UnmarshalAPER decodes MDTPLMNList from APER format.
func (v *MDTPLMNListComplete) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes MDTPLMNList with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *MDTPLMNListComplete) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "MDTPLMNList")
	}
	bb.EnterComponent("MDTPLMNList")
	value, err := BridgeUnmarshalAPERMDTPLMNListFrom(bb)
	if err != nil {
		return runtime.WrapDecodePath(err, "MDTPLMNList")
	}
	padding, err := aper.CaptureFinalBits(bb, "MDTPLMNList")
	if err != nil {
		return runtime.WrapDecodePath(err, "MDTPLMNList")
	}
	v.Value, v.perPadding = value, padding.Padding()
	return nil
}

// MarshalAPERMDTPLMNList encodes a MDTPLMNList list to APER.
func BridgeMarshalAPERMDTPLMNList(list MDTPLMNListComplete) ([]byte, error) {
	return list.marshalAPERLegacy()
}

// UnmarshalAPERMDTPLMNList decodes a MDTPLMNList list from APER.
func BridgeUnmarshalAPERMDTPLMNList(data []byte) (MDTPLMNListComplete, error) {
	var value MDTPLMNListComplete
	if err := value.unmarshalAPERLegacy(data); err != nil {
		return value, err
	}
	return value, nil
}

// UnmarshalAPERMDTPLMNListFrom decodes a MDTPLMNList list from bb.
func BridgeUnmarshalAPERMDTPLMNListFrom(bb *aper.BitBuffer) (s00.MDTPLMNList, error) {
	if err := bb.EnterDecodeValue(); err != nil {
		return nil, err
	}
	defer bb.LeaveDecodeValue()
	var v s00.BridgeAsn1cAPERMDTPLMNListListValue
	if err := BridgeUnmarshalAPERMDTPLMNListInto(&v, bb); err != nil {
		return nil, err
	}
	return v.Value, nil
}
func BridgeUnmarshalAPERMDTPLMNListInto(v *s00.BridgeAsn1cAPERMDTPLMNListListValue, bb *aper.BitBuffer) error {
	toleranceMark_value := bb.EnterComponent("Value")
	v.Value = make(s00.MDTPLMNList, 0)
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
	bb.LeaveComponent(toleranceMark_value)
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
	if err := s26.BridgeMarshalAPERPC5QoSFlowListTo(v.Value, bb); err != nil {
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
	bb.EnterComponent("PC5QoSFlowList")
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
	bb.EnterComponent("PLMNListforQMC")
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
	toleranceMark_value := bb.EnterComponent("Value")
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
	bb.LeaveComponent(toleranceMark_value)
	return nil
}

// MarshalAPER encodes SourceeNBToTargeteNBTransparentContainer to APER format.
func (v *SourceeNBToTargeteNBTransparentContainer) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *SourceeNBToTargeteNBTransparentContainer) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
	if err := aper.EncodeBoolean(bb, v.ERABInformationList != nil); err != nil {
		return err
	}
	if err := aper.EncodeBoolean(bb, v.SubscriberProfileIDforRFP != nil); err != nil {
		return err
	}
	if err := aper.EncodeBoolean(bb, v.IEExtensions != nil); err != nil {
		return err
	}
	if err := aper.EncodeOctetStringAligned(bb, []byte(v.RRCContainer), 0, 0, false); err != nil {
		return fmt.Errorf("encoding rRC-Container: %w", err)
	}
	if v.ERABInformationList != nil {
		if err := aper.EncodeCollection(bb, int64(len(v.ERABInformationList)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 256, HasUpper: true}, true, func(fragmentOffset_erabinformationlist, fragmentLength_erabinformationlist int64) error {
			// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
			if fragmentOffset_erabinformationlist < 0 || fragmentOffset_erabinformationlist > int64(len(v.ERABInformationList)) || fragmentLength_erabinformationlist < 0 || fragmentLength_erabinformationlist > int64(len(v.ERABInformationList[fragmentOffset_erabinformationlist:])) {
				return fmt.Errorf("collection fragment outside value")
			}
			for _, elem := range v.ERABInformationList[fragmentOffset_erabinformationlist : fragmentOffset_erabinformationlist+fragmentLength_erabinformationlist] {
				if err := s29.BridgeERABInformationListIEFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
					return fmt.Errorf("encoding e-RABInformationList element: %w", err)
				}
			}
			return nil
		}); err != nil {
			return fmt.Errorf("encoding e-RABInformationList: %w", err)
		}
	}
	if err := s17.BridgeEUTRANCGIMethodMarshalAPERTo(&v.TargetCellID, bb, len(fresh) != 0 && fresh[0]); err != nil {
		return fmt.Errorf("encoding targetCell-ID: %w", err)
	}
	if v.SubscriberProfileIDforRFP != nil {
		if err := aper.EncodeIntegerAligned(bb, int64(*v.SubscriberProfileIDforRFP), s07.BridgeInt64Ptr(1), s07.BridgeInt64Ptr(256), false); err != nil {
			return fmt.Errorf("encoding subscriberProfileIDforRFP: %w", err)
		}
	}
	if err := aper.EncodeCollection(bb, int64(len(v.UEHistoryInformation)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 16, HasUpper: true}, true, func(fragmentOffset_uehistoryinformation, fragmentLength_uehistoryinformation int64) error {
		// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
		if fragmentOffset_uehistoryinformation < 0 || fragmentOffset_uehistoryinformation > int64(len(v.UEHistoryInformation)) || fragmentLength_uehistoryinformation < 0 || fragmentLength_uehistoryinformation > int64(len(v.UEHistoryInformation[fragmentOffset_uehistoryinformation:])) {
			return fmt.Errorf("collection fragment outside value")
		}
		for _, elem := range v.UEHistoryInformation[fragmentOffset_uehistoryinformation : fragmentOffset_uehistoryinformation+fragmentLength_uehistoryinformation] {
			if err := elem.marshalAPERTo(bb, len(fresh) != 0 && fresh[0]); err != nil {
				return fmt.Errorf("encoding uE-HistoryInformation element: %w", err)
			}
		}
		return nil
	}); err != nil {
		return fmt.Errorf("encoding uE-HistoryInformation: %w", err)
	}
	if v.IEExtensions != nil {
		if err := aper.EncodeCollection(bb, int64(len(v.IEExtensions)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
			if fragmentOffset_ieextensions < 0 || fragmentOffset_ieextensions > int64(len(v.IEExtensions)) || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(len(v.IEExtensions[fragmentOffset_ieextensions:])) {
				return fmt.Errorf("collection fragment outside value")
			}
			for _, elem := range v.IEExtensions[fragmentOffset_ieextensions : fragmentOffset_ieextensions+fragmentLength_ieextensions] {
				if err := s35.BridgeSourceeNBToTargeteNBTransparentContainerExtIEsExtFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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

// UnmarshalAPER decodes SourceeNBToTargeteNBTransparentContainer from APER format.
func (v *SourceeNBToTargeteNBTransparentContainer) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes SourceeNBToTargeteNBTransparentContainer with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *SourceeNBToTargeteNBTransparentContainer) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "SourceeNBToTargeteNBTransparentContainer")
	}
	bb.EnterComponent("SourceeNBToTargeteNBTransparentContainer")
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "SourceeNBToTargeteNBTransparentContainer")
	}
	padding, err := aper.CaptureFinalBits(bb, "SourceeNBToTargeteNBTransparentContainer")
	if err != nil {
		return runtime.WrapDecodePath(err, "SourceeNBToTargeteNBTransparentContainer")
	}
	v.perPadding = padding.WithRecords(v.perPadding)
	return nil
}
func (v *SourceeNBToTargeteNBTransparentContainer) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = SourceeNBToTargeteNBTransparentContainer{}
	extAdditions := aper.BeginExtensionAdditions(bb)
	hasExtensions, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	// Read preamble bitmap for optional root fields
	opt_erabinformationlist, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	opt_subscriberprofileidforrfp, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	opt_ieextensions, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	val_rrccontainer, err := aper.DecodeOctetStringAligned(bb, 0, 0, false)
	if err != nil {
		return runtime.WrapDecodePath(err, "RRCContainer")
	}
	v.RRCContainer = s00.RRCContainer(val_rrccontainer)
	if opt_erabinformationlist {
		toleranceMark_erabinformationlist := bb.EnterComponent("ERABInformationList")
		tmp_erabinformationlist := make(s29.ERABInformationList, 0)
		_, errCollection_erabinformationlist := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 256, HasUpper: true}, true, func(fragmentOffset_erabinformationlist, fragmentLength_erabinformationlist int64) error {
			// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1128
			if fragmentOffset_erabinformationlist < 0 || fragmentLength_erabinformationlist < 0 || fragmentLength_erabinformationlist > int64(^uint(0)>>1) || fragmentOffset_erabinformationlist > int64(^uint(0)>>1)-fragmentLength_erabinformationlist {
				return fmt.Errorf("collection fragment count out of range")
			}
			for i := int64(0); i < fragmentLength_erabinformationlist; i++ {
				var elem s29.ERABInformationListIEValueProtocolIESingleContainer
				elementMark := bb.EnterIndex(fragmentOffset_erabinformationlist + i)
				if err := s29.BridgeERABInformationListIEFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
					return runtime.WrapDecodePath(err, fmt.Sprintf("ERABInformationList[%d]", fragmentOffset_erabinformationlist+i))
				}
				bb.LeaveComponent(elementMark)
				if next, err := aper.AppendValues(bb, tmp_erabinformationlist, elem); err != nil {
					return err
				} else {
					tmp_erabinformationlist = next
				}
			}
			return nil
		})
		if errCollection_erabinformationlist != nil {
			return runtime.WrapDecodePath(errCollection_erabinformationlist, "ERABInformationList")
		}
		v.ERABInformationList = tmp_erabinformationlist
		bb.LeaveComponent(toleranceMark_erabinformationlist)
	}
	toleranceMark_targetcellid := bb.EnterComponent("TargetCellID")
	if err := s17.BridgeEUTRANCGIMethodUnmarshalAPERFrom(&v.TargetCellID, bb); err != nil {
		return runtime.WrapDecodePath(err, "TargetCellID")
	}
	bb.LeaveComponent(toleranceMark_targetcellid)
	if opt_subscriberprofileidforrfp {
		val_subscriberprofileidforrfp, err := aper.DecodeIntegerAligned(bb, s07.BridgeInt64Ptr(1), s07.BridgeInt64Ptr(256), false)
		if err != nil {
			return runtime.WrapDecodePath(err, "SubscriberProfileIDforRFP")
		}
		tmp_subscriberprofileidforrfp := s00.SubscriberProfileIDforRFP(val_subscriberprofileidforrfp)
		if err := aper.ChargeValue(bb, tmp_subscriberprofileidforrfp); err != nil {
			return err
		}
		v.SubscriberProfileIDforRFP = (*s00.SubscriberProfileIDforRFP)(bb.OwnInt64(int64(tmp_subscriberprofileidforrfp)))

	}
	toleranceMark_uehistoryinformation := bb.EnterComponent("UEHistoryInformation")
	v.UEHistoryInformation = make(UEHistoryInformation, 0)
	_, errCollection_uehistoryinformation := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 16, HasUpper: true}, true, func(fragmentOffset_uehistoryinformation, fragmentLength_uehistoryinformation int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1128
		if fragmentOffset_uehistoryinformation < 0 || fragmentLength_uehistoryinformation < 0 || fragmentLength_uehistoryinformation > int64(^uint(0)>>1) || fragmentOffset_uehistoryinformation > int64(^uint(0)>>1)-fragmentLength_uehistoryinformation {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_uehistoryinformation; i++ {
			var elem LastVisitedCellItem
			elementMark := bb.EnterIndex(fragmentOffset_uehistoryinformation + i)
			if err := elem.unmarshalAPERFrom(bb); err != nil {
				return runtime.WrapDecodePath(err, fmt.Sprintf("UEHistoryInformation[%d]", fragmentOffset_uehistoryinformation+i))
			}
			bb.LeaveComponent(elementMark)
			if next, err := aper.AppendValues(bb, v.UEHistoryInformation, elem); err != nil {
				return err
			} else {
				v.UEHistoryInformation = next
			}
		}
		return nil
	})
	if errCollection_uehistoryinformation != nil {
		return runtime.WrapDecodePath(errCollection_uehistoryinformation, "UEHistoryInformation")
	}
	bb.LeaveComponent(toleranceMark_uehistoryinformation)
	if opt_ieextensions {
		toleranceMark_ieextensions := bb.EnterComponent("IEExtensions")
		tmp_ieextensions := make(s35.SourceeNBToTargeteNBTransparentContainerExtIEsExtContainer, 0)
		_, errCollection_ieextensions := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1128
			if fragmentOffset_ieextensions < 0 || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(^uint(0)>>1) || fragmentOffset_ieextensions > int64(^uint(0)>>1)-fragmentLength_ieextensions {
				return fmt.Errorf("collection fragment count out of range")
			}
			for i := int64(0); i < fragmentLength_ieextensions; i++ {
				var elem s35.SourceeNBToTargeteNBTransparentContainerExtIEsExtField
				elementMark := bb.EnterIndex(fragmentOffset_ieextensions + i)
				if err := s35.BridgeSourceeNBToTargeteNBTransparentContainerExtIEsExtFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
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

type BridgeAsn1cAPERUEHistoryInformationListValue struct{ Value UEHistoryInformation }

// MarshalAPERUEHistoryInformationTo appends a UEHistoryInformation list to bb.
func BridgeMarshalAPERUEHistoryInformationTo(list UEHistoryInformation, bb *aper.BitBuffer, fresh ...bool) error {
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()

	v := BridgeAsn1cAPERUEHistoryInformationListValue{Value: list}
	if err := aper.EncodeCollection(bb, int64(len(v.Value)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 16, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
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

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *ERABUsageReportListComplete) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s14.BridgeReceivedFormAt(v.received, v.receivedBytes, "ERABUsageReportListComplete", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "ERABUsageReportListComplete", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v ERABUsageReportListComplete) WithoutReplay() ERABUsageReportListComplete {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero ERABUsageReportListComplete
	v.perPadding = zero.perPadding
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *EmergencyAreaIDBroadcastComplete) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s14.BridgeReceivedFormAt(v.received, v.receivedBytes, "EmergencyAreaIDBroadcastComplete", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "EmergencyAreaIDBroadcastComplete", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v EmergencyAreaIDBroadcastComplete) WithoutReplay() EmergencyAreaIDBroadcastComplete {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero EmergencyAreaIDBroadcastComplete
	v.perPadding = zero.perPadding
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *EmergencyAreaIDCancelledComplete) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s14.BridgeReceivedFormAt(v.received, v.receivedBytes, "EmergencyAreaIDCancelledComplete", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "EmergencyAreaIDCancelledComplete", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v EmergencyAreaIDCancelledComplete) WithoutReplay() EmergencyAreaIDCancelledComplete {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero EmergencyAreaIDCancelledComplete
	v.perPadding = zero.perPadding
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *EmergencyAreaIDListComplete) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s14.BridgeReceivedFormAt(v.received, v.receivedBytes, "EmergencyAreaIDListComplete", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "EmergencyAreaIDListComplete", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v EmergencyAreaIDListComplete) WithoutReplay() EmergencyAreaIDListComplete {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero EmergencyAreaIDListComplete
	v.perPadding = zero.perPadding
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *EmergencyAreaIDListForRestartComplete) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s14.BridgeReceivedFormAt(v.received, v.receivedBytes, "EmergencyAreaIDListForRestartComplete", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "EmergencyAreaIDListForRestartComplete", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v EmergencyAreaIDListForRestartComplete) WithoutReplay() EmergencyAreaIDListForRestartComplete {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero EmergencyAreaIDListForRestartComplete
	v.perPadding = zero.perPadding
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *ForbiddenLACsComplete) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s14.BridgeReceivedFormAt(v.received, v.receivedBytes, "ForbiddenLACsComplete", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "ForbiddenLACsComplete", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v ForbiddenLACsComplete) WithoutReplay() ForbiddenLACsComplete {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero ForbiddenLACsComplete
	v.perPadding = zero.perPadding
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *ForbiddenLAsComplete) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s14.BridgeReceivedFormAt(v.received, v.receivedBytes, "ForbiddenLAsComplete", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "ForbiddenLAsComplete", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v ForbiddenLAsComplete) WithoutReplay() ForbiddenLAsComplete {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero ForbiddenLAsComplete
	v.perPadding = zero.perPadding
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *ForbiddenTACsComplete) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s14.BridgeReceivedFormAt(v.received, v.receivedBytes, "ForbiddenTACsComplete", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "ForbiddenTACsComplete", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v ForbiddenTACsComplete) WithoutReplay() ForbiddenTACsComplete {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero ForbiddenTACsComplete
	v.perPadding = zero.perPadding
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *ForbiddenTAsComplete) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s14.BridgeReceivedFormAt(v.received, v.receivedBytes, "ForbiddenTAsComplete", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "ForbiddenTAsComplete", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v ForbiddenTAsComplete) WithoutReplay() ForbiddenTAsComplete {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero ForbiddenTAsComplete
	v.perPadding = zero.perPadding
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *GUMMEIListComplete) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s14.BridgeReceivedFormAt(v.received, v.receivedBytes, "GUMMEIListComplete", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "GUMMEIListComplete", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v GUMMEIListComplete) WithoutReplay() GUMMEIListComplete {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero GUMMEIListComplete
	v.perPadding = zero.perPadding
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *IEsECGIListComplete) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s14.BridgeReceivedFormAt(v.received, v.receivedBytes, "IEsECGIListComplete", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "IEsECGIListComplete", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v IEsECGIListComplete) WithoutReplay() IEsECGIListComplete {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero IEsECGIListComplete
	v.perPadding = zero.perPadding
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *InterSystemMeasurementListComplete) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s14.BridgeReceivedFormAt(v.received, v.receivedBytes, "InterSystemMeasurementListComplete", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "InterSystemMeasurementListComplete", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v InterSystemMeasurementListComplete) WithoutReplay() InterSystemMeasurementListComplete {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero InterSystemMeasurementListComplete
	v.perPadding = zero.perPadding
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *LastVisitedCellItem) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s14.BridgeReceivedFormAt(v.received, v.receivedBytes, "LastVisitedCellItem", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "LastVisitedCellItem", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v LastVisitedCellItem) WithoutReplay() LastVisitedCellItem {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero LastVisitedCellItem
	v.perPadding = zero.perPadding
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *LastVisitedEUTRANCellInformation) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s14.BridgeReceivedFormAt(v.received, v.receivedBytes, "LastVisitedEUTRANCellInformation", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "LastVisitedEUTRANCellInformation", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v LastVisitedEUTRANCellInformation) WithoutReplay() LastVisitedEUTRANCellInformation {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero LastVisitedEUTRANCellInformation
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *LastVisitedPSCellListComplete) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s14.BridgeReceivedFormAt(v.received, v.receivedBytes, "LastVisitedPSCellListComplete", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "LastVisitedPSCellListComplete", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v LastVisitedPSCellListComplete) WithoutReplay() LastVisitedPSCellListComplete {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero LastVisitedPSCellListComplete
	v.perPadding = zero.perPadding
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *MBSFNResultToLogComplete) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s14.BridgeReceivedFormAt(v.received, v.receivedBytes, "MBSFNResultToLogComplete", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "MBSFNResultToLogComplete", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v MBSFNResultToLogComplete) WithoutReplay() MBSFNResultToLogComplete {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero MBSFNResultToLogComplete
	v.perPadding = zero.perPadding
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *MDTPLMNListComplete) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s14.BridgeReceivedFormAt(v.received, v.receivedBytes, "MDTPLMNListComplete", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "MDTPLMNListComplete", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v MDTPLMNListComplete) WithoutReplay() MDTPLMNListComplete {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero MDTPLMNListComplete
	v.perPadding = zero.perPadding
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
func (v *SourceeNBToTargeteNBTransparentContainer) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s14.BridgeReceivedFormAt(v.received, v.receivedBytes, "SourceeNBToTargeteNBTransparentContainer", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "SourceeNBToTargeteNBTransparentContainer", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v SourceeNBToTargeteNBTransparentContainer) WithoutReplay() SourceeNBToTargeteNBTransparentContainer {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero SourceeNBToTargeteNBTransparentContainer
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// Extensions returns owned unknown sequence additions.
func (v *LastVisitedEUTRANCellInformation) Extensions() []aper.SequenceExtension {
	if v == nil {
		return nil
	}
	views := aper.SequenceExtensionViews(v.extPresent, aper.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *LastVisitedEUTRANCellInformation) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("LastVisitedEUTRANCellInformation.Extensions[%d]", index))
	}
	if err := aper.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("LastVisitedEUTRANCellInformation.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *LastVisitedEUTRANCellInformation) RemoveExtension(index uint64) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("LastVisitedEUTRANCellInformation.Extensions[%d]", index))
	}
	if err := aper.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("LastVisitedEUTRANCellInformation.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// Extensions returns owned unknown sequence additions.
func (v *SourceeNBToTargeteNBTransparentContainer) Extensions() []aper.SequenceExtension {
	if v == nil {
		return nil
	}
	views := aper.SequenceExtensionViews(v.extPresent, aper.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *SourceeNBToTargeteNBTransparentContainer) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("SourceeNBToTargeteNBTransparentContainer.Extensions[%d]", index))
	}
	if err := aper.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("SourceeNBToTargeteNBTransparentContainer.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *SourceeNBToTargeteNBTransparentContainer) RemoveExtension(index uint64) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("SourceeNBToTargeteNBTransparentContainer.Extensions[%d]", index))
	}
	if err := aper.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("SourceeNBToTargeteNBTransparentContainer.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// MarshalAPER encodes a complete value using one per-call change plan.
func (v *ERABUsageReportListComplete) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "ERABUsageReportListComplete")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *ERABUsageReportListComplete) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "ERABUsageReportListComplete")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APERABUsageReportListComplete(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "ERABUsageReportListComplete")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "ERABUsageReportListComplete")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *ERABUsageReportListComplete) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "ERABUsageReportListComplete")
}
func (v *ERABUsageReportListComplete) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "ERABUsageReportListComplete")
}
func (v *ERABUsageReportListComplete) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APERABUsageReportListComplete(v, &s)
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
func (v *ERABUsageReportListComplete) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *ERABUsageReportListComplete) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
	if err := s26.BridgeMarshalAPERERABUsageReportListTo(v.Value, bb, fresh); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.perPadding)
}

// MarshalAPER encodes a complete value using one per-call change plan.
func (v *EmergencyAreaIDBroadcastComplete) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "EmergencyAreaIDBroadcastComplete")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *EmergencyAreaIDBroadcastComplete) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "EmergencyAreaIDBroadcastComplete")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APEmergencyAreaIDBroadcastComplete(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "EmergencyAreaIDBroadcastComplete")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "EmergencyAreaIDBroadcastComplete")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *EmergencyAreaIDBroadcastComplete) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "EmergencyAreaIDBroadcastComplete")
}
func (v *EmergencyAreaIDBroadcastComplete) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "EmergencyAreaIDBroadcastComplete")
}
func (v *EmergencyAreaIDBroadcastComplete) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APEmergencyAreaIDBroadcastComplete(v, &s)
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
func (v *EmergencyAreaIDBroadcastComplete) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *EmergencyAreaIDBroadcastComplete) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
	if err := s26.BridgeMarshalAPEREmergencyAreaIDBroadcastTo(v.Value, bb, fresh); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.perPadding)
}

// MarshalAPER encodes a complete value using one per-call change plan.
func (v *EmergencyAreaIDCancelledComplete) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "EmergencyAreaIDCancelledComplete")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *EmergencyAreaIDCancelledComplete) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "EmergencyAreaIDCancelledComplete")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APEmergencyAreaIDCancelledComplete(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "EmergencyAreaIDCancelledComplete")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "EmergencyAreaIDCancelledComplete")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *EmergencyAreaIDCancelledComplete) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "EmergencyAreaIDCancelledComplete")
}
func (v *EmergencyAreaIDCancelledComplete) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "EmergencyAreaIDCancelledComplete")
}
func (v *EmergencyAreaIDCancelledComplete) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APEmergencyAreaIDCancelledComplete(v, &s)
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
func (v *EmergencyAreaIDCancelledComplete) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *EmergencyAreaIDCancelledComplete) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
	if err := s26.BridgeMarshalAPEREmergencyAreaIDCancelledTo(v.Value, bb, fresh); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.perPadding)
}

// MarshalAPER encodes a complete value using one per-call change plan.
func (v *EmergencyAreaIDListComplete) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "EmergencyAreaIDListComplete")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *EmergencyAreaIDListComplete) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "EmergencyAreaIDListComplete")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APEmergencyAreaIDListComplete(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "EmergencyAreaIDListComplete")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "EmergencyAreaIDListComplete")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *EmergencyAreaIDListComplete) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "EmergencyAreaIDListComplete")
}
func (v *EmergencyAreaIDListComplete) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "EmergencyAreaIDListComplete")
}
func (v *EmergencyAreaIDListComplete) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APEmergencyAreaIDListComplete(v, &s)
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
func (v *EmergencyAreaIDListComplete) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *EmergencyAreaIDListComplete) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
	if err := s13.BridgeMarshalAPEREmergencyAreaIDListTo(v.Value, bb, fresh); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.perPadding)
}

// MarshalAPER encodes a complete value using one per-call change plan.
func (v *EmergencyAreaIDListForRestartComplete) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "EmergencyAreaIDListForRestartComplete")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *EmergencyAreaIDListForRestartComplete) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "EmergencyAreaIDListForRestartComplete")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APEmergencyAreaIDListForRestartComplete(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "EmergencyAreaIDListForRestartComplete")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "EmergencyAreaIDListForRestartComplete")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *EmergencyAreaIDListForRestartComplete) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "EmergencyAreaIDListForRestartComplete")
}
func (v *EmergencyAreaIDListForRestartComplete) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "EmergencyAreaIDListForRestartComplete")
}
func (v *EmergencyAreaIDListForRestartComplete) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APEmergencyAreaIDListForRestartComplete(v, &s)
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
func (v *EmergencyAreaIDListForRestartComplete) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *EmergencyAreaIDListForRestartComplete) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
	if err := s13.BridgeMarshalAPEREmergencyAreaIDListForRestartTo(v.Value, bb, fresh); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.perPadding)
}

// MarshalAPER encodes a complete value using one per-call change plan.
func (v *ForbiddenLACsComplete) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "ForbiddenLACsComplete")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *ForbiddenLACsComplete) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "ForbiddenLACsComplete")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APForbiddenLACsComplete(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "ForbiddenLACsComplete")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "ForbiddenLACsComplete")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *ForbiddenLACsComplete) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "ForbiddenLACsComplete")
}
func (v *ForbiddenLACsComplete) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "ForbiddenLACsComplete")
}
func (v *ForbiddenLACsComplete) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APForbiddenLACsComplete(v, &s)
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
func (v *ForbiddenLACsComplete) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *ForbiddenLACsComplete) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
	if err := s13.BridgeMarshalAPERForbiddenLACsTo(v.Value, bb, fresh); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.perPadding)
}

// MarshalAPER encodes a complete value using one per-call change plan.
func (v *ForbiddenLAsComplete) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "ForbiddenLAsComplete")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *ForbiddenLAsComplete) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "ForbiddenLAsComplete")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APForbiddenLAsComplete(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "ForbiddenLAsComplete")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "ForbiddenLAsComplete")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *ForbiddenLAsComplete) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "ForbiddenLAsComplete")
}
func (v *ForbiddenLAsComplete) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "ForbiddenLAsComplete")
}
func (v *ForbiddenLAsComplete) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APForbiddenLAsComplete(v, &s)
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
func (v *ForbiddenLAsComplete) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *ForbiddenLAsComplete) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
	if err := s26.BridgeMarshalAPERForbiddenLAsTo(v.Value, bb, fresh); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.perPadding)
}

// MarshalAPER encodes a complete value using one per-call change plan.
func (v *ForbiddenTACsComplete) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "ForbiddenTACsComplete")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *ForbiddenTACsComplete) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "ForbiddenTACsComplete")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APForbiddenTACsComplete(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "ForbiddenTACsComplete")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "ForbiddenTACsComplete")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *ForbiddenTACsComplete) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "ForbiddenTACsComplete")
}
func (v *ForbiddenTACsComplete) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "ForbiddenTACsComplete")
}
func (v *ForbiddenTACsComplete) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APForbiddenTACsComplete(v, &s)
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
func (v *ForbiddenTACsComplete) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *ForbiddenTACsComplete) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
	if err := s13.BridgeMarshalAPERForbiddenTACsTo(v.Value, bb, fresh); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.perPadding)
}

// MarshalAPER encodes a complete value using one per-call change plan.
func (v *ForbiddenTAsComplete) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "ForbiddenTAsComplete")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *ForbiddenTAsComplete) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "ForbiddenTAsComplete")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APForbiddenTAsComplete(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "ForbiddenTAsComplete")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "ForbiddenTAsComplete")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *ForbiddenTAsComplete) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "ForbiddenTAsComplete")
}
func (v *ForbiddenTAsComplete) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "ForbiddenTAsComplete")
}
func (v *ForbiddenTAsComplete) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APForbiddenTAsComplete(v, &s)
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
func (v *ForbiddenTAsComplete) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *ForbiddenTAsComplete) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
	if err := s26.BridgeMarshalAPERForbiddenTAsTo(v.Value, bb, fresh); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.perPadding)
}

// MarshalAPER encodes a complete value using one per-call change plan.
func (v *GUMMEIListComplete) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "GUMMEIListComplete")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *GUMMEIListComplete) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "GUMMEIListComplete")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APGUMMEIListComplete(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "GUMMEIListComplete")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "GUMMEIListComplete")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *GUMMEIListComplete) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "GUMMEIListComplete")
}
func (v *GUMMEIListComplete) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "GUMMEIListComplete")
}
func (v *GUMMEIListComplete) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APGUMMEIListComplete(v, &s)
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
func (v *GUMMEIListComplete) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *GUMMEIListComplete) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
	if err := s26.BridgeMarshalAPERGUMMEIListTo(v.Value, bb, fresh); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.perPadding)
}

// MarshalAPER encodes a complete value using one per-call change plan.
func (v *IEsECGIListComplete) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "IEsECGIListComplete")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *IEsECGIListComplete) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "IEsECGIListComplete")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APIEsECGIListComplete(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "IEsECGIListComplete")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "IEsECGIListComplete")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *IEsECGIListComplete) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "IEsECGIListComplete")
}
func (v *IEsECGIListComplete) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "IEsECGIListComplete")
}
func (v *IEsECGIListComplete) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APIEsECGIListComplete(v, &s)
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
func (v *IEsECGIListComplete) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *IEsECGIListComplete) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
	if err := s26.BridgeMarshalAPERIEsECGIListTo(v.Value, bb, fresh); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.perPadding)
}

// MarshalAPER encodes a complete value using one per-call change plan.
func (v *InterSystemMeasurementListComplete) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "InterSystemMeasurementListComplete")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *InterSystemMeasurementListComplete) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "InterSystemMeasurementListComplete")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APInterSystemMeasurementListComplete(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "InterSystemMeasurementListComplete")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "InterSystemMeasurementListComplete")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *InterSystemMeasurementListComplete) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "InterSystemMeasurementListComplete")
}
func (v *InterSystemMeasurementListComplete) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "InterSystemMeasurementListComplete")
}
func (v *InterSystemMeasurementListComplete) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APInterSystemMeasurementListComplete(v, &s)
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
func (v *InterSystemMeasurementListComplete) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *InterSystemMeasurementListComplete) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
	if err := s26.BridgeMarshalAPERInterSystemMeasurementListTo(v.Value, bb, fresh); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.perPadding)
}

// MarshalAPER encodes a complete value using one per-call change plan.
func (v *LastVisitedCellItem) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "LastVisitedCellItem")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *LastVisitedCellItem) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "LastVisitedCellItem")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APLastVisitedCellItem(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "LastVisitedCellItem")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "LastVisitedCellItem")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *LastVisitedCellItem) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "LastVisitedCellItem")
}
func (v *LastVisitedCellItem) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "LastVisitedCellItem")
}
func (v *LastVisitedCellItem) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APLastVisitedCellItem(v, &s)
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
func (v *LastVisitedCellItem) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *LastVisitedCellItem) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
func (v *LastVisitedEUTRANCellInformation) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "LastVisitedEUTRANCellInformation")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *LastVisitedEUTRANCellInformation) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "LastVisitedEUTRANCellInformation")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APLastVisitedEUTRANCellInformation(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "LastVisitedEUTRANCellInformation")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "LastVisitedEUTRANCellInformation")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *LastVisitedEUTRANCellInformation) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "LastVisitedEUTRANCellInformation")
}
func (v *LastVisitedEUTRANCellInformation) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "LastVisitedEUTRANCellInformation")
}
func (v *LastVisitedEUTRANCellInformation) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APLastVisitedEUTRANCellInformation(v, &s)
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
func (v *LastVisitedEUTRANCellInformation) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *LastVisitedEUTRANCellInformation) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
func (v *LastVisitedPSCellListComplete) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "LastVisitedPSCellListComplete")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *LastVisitedPSCellListComplete) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "LastVisitedPSCellListComplete")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APLastVisitedPSCellListComplete(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "LastVisitedPSCellListComplete")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "LastVisitedPSCellListComplete")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *LastVisitedPSCellListComplete) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "LastVisitedPSCellListComplete")
}
func (v *LastVisitedPSCellListComplete) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "LastVisitedPSCellListComplete")
}
func (v *LastVisitedPSCellListComplete) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APLastVisitedPSCellListComplete(v, &s)
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
func (v *LastVisitedPSCellListComplete) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *LastVisitedPSCellListComplete) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
	if err := s26.BridgeMarshalAPERLastVisitedPSCellListTo(v.Value, bb, fresh); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.perPadding)
}

// MarshalAPER encodes a complete value using one per-call change plan.
func (v *MBSFNResultToLogComplete) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "MBSFNResultToLogComplete")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *MBSFNResultToLogComplete) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "MBSFNResultToLogComplete")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APMBSFNResultToLogComplete(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "MBSFNResultToLogComplete")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "MBSFNResultToLogComplete")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *MBSFNResultToLogComplete) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "MBSFNResultToLogComplete")
}
func (v *MBSFNResultToLogComplete) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "MBSFNResultToLogComplete")
}
func (v *MBSFNResultToLogComplete) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APMBSFNResultToLogComplete(v, &s)
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
func (v *MBSFNResultToLogComplete) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *MBSFNResultToLogComplete) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
	if err := s26.BridgeMarshalAPERMBSFNResultToLogTo(v.Value, bb, fresh); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.perPadding)
}

// MarshalAPER encodes a complete value using one per-call change plan.
func (v *MDTPLMNListComplete) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "MDTPLMNListComplete")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *MDTPLMNListComplete) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "MDTPLMNListComplete")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APMDTPLMNListComplete(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "MDTPLMNListComplete")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "MDTPLMNListComplete")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *MDTPLMNListComplete) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "MDTPLMNListComplete")
}
func (v *MDTPLMNListComplete) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "MDTPLMNListComplete")
}
func (v *MDTPLMNListComplete) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APMDTPLMNListComplete(v, &s)
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
func (v *MDTPLMNListComplete) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *MDTPLMNListComplete) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
	if err := s13.BridgeMarshalAPERMDTPLMNListTo(v.Value, bb, fresh); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.perPadding)
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
	if err := s26.BridgeMarshalAPERPC5QoSFlowListTo(v.Value, bb, fresh); err != nil {
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
	if err := s26.BridgeMarshalAPERPWSfailedECGIListTo(v.Value, bb, fresh); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.perPadding)
}

// MarshalAPER encodes a complete value using one per-call change plan.
func (v *SourceeNBToTargeteNBTransparentContainer) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "SourceeNBToTargeteNBTransparentContainer")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *SourceeNBToTargeteNBTransparentContainer) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "SourceeNBToTargeteNBTransparentContainer")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APSourceeNBToTargeteNBTransparentContainer(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "SourceeNBToTargeteNBTransparentContainer")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "SourceeNBToTargeteNBTransparentContainer")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *SourceeNBToTargeteNBTransparentContainer) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "SourceeNBToTargeteNBTransparentContainer")
}
func (v *SourceeNBToTargeteNBTransparentContainer) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "SourceeNBToTargeteNBTransparentContainer")
}
func (v *SourceeNBToTargeteNBTransparentContainer) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APSourceeNBToTargeteNBTransparentContainer(v, &s)
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
func (v *SourceeNBToTargeteNBTransparentContainer) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *SourceeNBToTargeteNBTransparentContainer) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
func (v *ERABUsageReportListComplete) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "ERABUsageReportListComplete")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded ERABUsageReportListComplete
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APERABUsageReportListComplete(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = ERABUsageReportListComplete{}
		return report, aper.OperationError(err, "ERABUsageReportListComplete")
	}
	*v = decoded
	return report, aper.OperationError(nil, "ERABUsageReportListComplete")
}

// UnmarshalAPER decodes one complete value and returns its report.
func (v *EmergencyAreaIDBroadcastComplete) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "EmergencyAreaIDBroadcastComplete")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded EmergencyAreaIDBroadcastComplete
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APEmergencyAreaIDBroadcastComplete(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = EmergencyAreaIDBroadcastComplete{}
		return report, aper.OperationError(err, "EmergencyAreaIDBroadcastComplete")
	}
	*v = decoded
	return report, aper.OperationError(nil, "EmergencyAreaIDBroadcastComplete")
}

// UnmarshalAPER decodes one complete value and returns its report.
func (v *EmergencyAreaIDCancelledComplete) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "EmergencyAreaIDCancelledComplete")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded EmergencyAreaIDCancelledComplete
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APEmergencyAreaIDCancelledComplete(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = EmergencyAreaIDCancelledComplete{}
		return report, aper.OperationError(err, "EmergencyAreaIDCancelledComplete")
	}
	*v = decoded
	return report, aper.OperationError(nil, "EmergencyAreaIDCancelledComplete")
}

// UnmarshalAPER decodes one complete value and returns its report.
func (v *EmergencyAreaIDListComplete) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "EmergencyAreaIDListComplete")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded EmergencyAreaIDListComplete
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APEmergencyAreaIDListComplete(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = EmergencyAreaIDListComplete{}
		return report, aper.OperationError(err, "EmergencyAreaIDListComplete")
	}
	*v = decoded
	return report, aper.OperationError(nil, "EmergencyAreaIDListComplete")
}

// UnmarshalAPER decodes one complete value and returns its report.
func (v *EmergencyAreaIDListForRestartComplete) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "EmergencyAreaIDListForRestartComplete")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded EmergencyAreaIDListForRestartComplete
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APEmergencyAreaIDListForRestartComplete(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = EmergencyAreaIDListForRestartComplete{}
		return report, aper.OperationError(err, "EmergencyAreaIDListForRestartComplete")
	}
	*v = decoded
	return report, aper.OperationError(nil, "EmergencyAreaIDListForRestartComplete")
}

// UnmarshalAPER decodes one complete value and returns its report.
func (v *ForbiddenLACsComplete) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "ForbiddenLACsComplete")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded ForbiddenLACsComplete
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APForbiddenLACsComplete(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = ForbiddenLACsComplete{}
		return report, aper.OperationError(err, "ForbiddenLACsComplete")
	}
	*v = decoded
	return report, aper.OperationError(nil, "ForbiddenLACsComplete")
}

// UnmarshalAPER decodes one complete value and returns its report.
func (v *ForbiddenLAsComplete) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "ForbiddenLAsComplete")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded ForbiddenLAsComplete
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APForbiddenLAsComplete(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = ForbiddenLAsComplete{}
		return report, aper.OperationError(err, "ForbiddenLAsComplete")
	}
	*v = decoded
	return report, aper.OperationError(nil, "ForbiddenLAsComplete")
}

// UnmarshalAPER decodes one complete value and returns its report.
func (v *ForbiddenTACsComplete) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "ForbiddenTACsComplete")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded ForbiddenTACsComplete
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APForbiddenTACsComplete(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = ForbiddenTACsComplete{}
		return report, aper.OperationError(err, "ForbiddenTACsComplete")
	}
	*v = decoded
	return report, aper.OperationError(nil, "ForbiddenTACsComplete")
}

// UnmarshalAPER decodes one complete value and returns its report.
func (v *ForbiddenTAsComplete) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "ForbiddenTAsComplete")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded ForbiddenTAsComplete
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APForbiddenTAsComplete(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = ForbiddenTAsComplete{}
		return report, aper.OperationError(err, "ForbiddenTAsComplete")
	}
	*v = decoded
	return report, aper.OperationError(nil, "ForbiddenTAsComplete")
}

// UnmarshalAPER decodes one complete value and returns its report.
func (v *GUMMEIListComplete) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "GUMMEIListComplete")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded GUMMEIListComplete
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APGUMMEIListComplete(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = GUMMEIListComplete{}
		return report, aper.OperationError(err, "GUMMEIListComplete")
	}
	*v = decoded
	return report, aper.OperationError(nil, "GUMMEIListComplete")
}

// UnmarshalAPER decodes one complete value and returns its report.
func (v *IEsECGIListComplete) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "IEsECGIListComplete")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded IEsECGIListComplete
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APIEsECGIListComplete(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = IEsECGIListComplete{}
		return report, aper.OperationError(err, "IEsECGIListComplete")
	}
	*v = decoded
	return report, aper.OperationError(nil, "IEsECGIListComplete")
}

// UnmarshalAPER decodes one complete value and returns its report.
func (v *InterSystemMeasurementListComplete) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "InterSystemMeasurementListComplete")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded InterSystemMeasurementListComplete
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APInterSystemMeasurementListComplete(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = InterSystemMeasurementListComplete{}
		return report, aper.OperationError(err, "InterSystemMeasurementListComplete")
	}
	*v = decoded
	return report, aper.OperationError(nil, "InterSystemMeasurementListComplete")
}

// UnmarshalAPER decodes one complete value and returns its report.
func (v *LastVisitedCellItem) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "LastVisitedCellItem")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded LastVisitedCellItem
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APLastVisitedCellItem(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = LastVisitedCellItem{}
		return report, aper.OperationError(err, "LastVisitedCellItem")
	}
	*v = decoded
	return report, aper.OperationError(nil, "LastVisitedCellItem")
}

// UnmarshalAPER decodes one complete value and returns its report.
func (v *LastVisitedEUTRANCellInformation) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "LastVisitedEUTRANCellInformation")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded LastVisitedEUTRANCellInformation
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APLastVisitedEUTRANCellInformation(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = LastVisitedEUTRANCellInformation{}
		return report, aper.OperationError(err, "LastVisitedEUTRANCellInformation")
	}
	*v = decoded
	return report, aper.OperationError(nil, "LastVisitedEUTRANCellInformation")
}

// UnmarshalAPER decodes one complete value and returns its report.
func (v *LastVisitedPSCellListComplete) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "LastVisitedPSCellListComplete")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded LastVisitedPSCellListComplete
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APLastVisitedPSCellListComplete(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = LastVisitedPSCellListComplete{}
		return report, aper.OperationError(err, "LastVisitedPSCellListComplete")
	}
	*v = decoded
	return report, aper.OperationError(nil, "LastVisitedPSCellListComplete")
}

// UnmarshalAPER decodes one complete value and returns its report.
func (v *MBSFNResultToLogComplete) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "MBSFNResultToLogComplete")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded MBSFNResultToLogComplete
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APMBSFNResultToLogComplete(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = MBSFNResultToLogComplete{}
		return report, aper.OperationError(err, "MBSFNResultToLogComplete")
	}
	*v = decoded
	return report, aper.OperationError(nil, "MBSFNResultToLogComplete")
}

// UnmarshalAPER decodes one complete value and returns its report.
func (v *MDTPLMNListComplete) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "MDTPLMNListComplete")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded MDTPLMNListComplete
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APMDTPLMNListComplete(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = MDTPLMNListComplete{}
		return report, aper.OperationError(err, "MDTPLMNListComplete")
	}
	*v = decoded
	return report, aper.OperationError(nil, "MDTPLMNListComplete")
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
func (v *SourceeNBToTargeteNBTransparentContainer) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "SourceeNBToTargeteNBTransparentContainer")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded SourceeNBToTargeteNBTransparentContainer
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APSourceeNBToTargeteNBTransparentContainer(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = SourceeNBToTargeteNBTransparentContainer{}
		return report, aper.OperationError(err, "SourceeNBToTargeteNBTransparentContainer")
	}
	*v = decoded
	return report, aper.OperationError(nil, "SourceeNBToTargeteNBTransparentContainer")
}

// NewLastVisitedCellItemEUTRANCell constructs a checked complete value.
func NewLastVisitedCellItemEUTRANCell(v LastVisitedEUTRANCellInformation, options ...aper.BuildOption) (LastVisitedCellItem, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return LastVisitedCellItem{}, aper.OperationError(err, "LastVisitedCellItemEUTRANCell")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), v); err != nil {
		return LastVisitedCellItem{}, aper.OperationError(err, "LastVisitedCellItemEUTRANCell")
	}
	value := BridgeNewLastVisitedCellItemEUTRANCellLegacy(v)
	if _, err := (&value).marshalAPERBudget(budget, false); err != nil {
		return LastVisitedCellItem{}, aper.OperationError(err, "LastVisitedCellItemEUTRANCell")
	}
	return value, aper.OperationError(nil, "LastVisitedCellItemEUTRANCell")
}

// NewLastVisitedCellItemUTRANCell constructs a checked complete value.
func NewLastVisitedCellItemUTRANCell(v s00.LastVisitedUTRANCellInformation, options ...aper.BuildOption) (LastVisitedCellItem, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return LastVisitedCellItem{}, aper.OperationError(err, "LastVisitedCellItemUTRANCell")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), v); err != nil {
		return LastVisitedCellItem{}, aper.OperationError(err, "LastVisitedCellItemUTRANCell")
	}
	value := BridgeNewLastVisitedCellItemUTRANCellLegacy(v)
	if _, err := (&value).marshalAPERBudget(budget, false); err != nil {
		return LastVisitedCellItem{}, aper.OperationError(err, "LastVisitedCellItemUTRANCell")
	}
	return value, aper.OperationError(nil, "LastVisitedCellItemUTRANCell")
}

// NewLastVisitedCellItemGERANCell constructs a checked complete value.
func NewLastVisitedCellItemGERANCell(v s18.LastVisitedGERANCellInformation, options ...aper.BuildOption) (LastVisitedCellItem, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return LastVisitedCellItem{}, aper.OperationError(err, "LastVisitedCellItemGERANCell")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), v); err != nil {
		return LastVisitedCellItem{}, aper.OperationError(err, "LastVisitedCellItemGERANCell")
	}
	value := BridgeNewLastVisitedCellItemGERANCellLegacy(v)
	if _, err := (&value).marshalAPERBudget(budget, false); err != nil {
		return LastVisitedCellItem{}, aper.OperationError(err, "LastVisitedCellItemGERANCell")
	}
	return value, aper.OperationError(nil, "LastVisitedCellItemGERANCell")
}

// NewLastVisitedCellItemNGRANCell constructs a checked complete value.
func NewLastVisitedCellItemNGRANCell(v s00.LastVisitedNGRANCellInformation, options ...aper.BuildOption) (LastVisitedCellItem, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return LastVisitedCellItem{}, aper.OperationError(err, "LastVisitedCellItemNGRANCell")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), v); err != nil {
		return LastVisitedCellItem{}, aper.OperationError(err, "LastVisitedCellItemNGRANCell")
	}
	value := BridgeNewLastVisitedCellItemNGRANCellLegacy(v)
	if _, err := (&value).marshalAPERBudget(budget, false); err != nil {
		return LastVisitedCellItem{}, aper.OperationError(err, "LastVisitedCellItemNGRANCell")
	}
	return value, aper.OperationError(nil, "LastVisitedCellItemNGRANCell")
}

// NewLastVisitedCellItemUnknownExtension builds a checked, owned unknown CHOICE alternative.
func NewLastVisitedCellItemUnknownExtension(index uint64, contents []byte, options ...aper.BuildOption) (LastVisitedCellItem, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return LastVisitedCellItem{}, aper.OperationError(err, "LastVisitedCellItemUnknownExtension")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), aper.ChoiceExtension{}); err != nil {
		return LastVisitedCellItem{}, aper.OperationError(err, "LastVisitedCellItemUnknownExtension")
	}
	extension, err := aper.BuildChoiceExtension(index, contents, budget)
	if err != nil {
		return LastVisitedCellItem{}, aper.OperationError(err, "LastVisitedCellItemUnknownExtension")
	}
	value := LastVisitedCellItem{UnknownExtension: &extension}
	if _, err := value.marshalAPERBudget(budget, false); err != nil {
		return LastVisitedCellItem{}, aper.OperationError(err, "LastVisitedCellItemUnknownExtension")
	}
	return value, aper.OperationError(nil, "LastVisitedCellItemUnknownExtension")
}

// MarshalAPERPWSfailedECGIList encodes a complete named list.
func MarshalAPERPWSfailedECGIList(v PWSfailedECGIListComplete, options ...aper.EncodeOption) ([]byte, error) {
	return v.MarshalAPER(options...)
}

// MarshalAPEREmergencyAreaIDList encodes a complete named list.
func MarshalAPEREmergencyAreaIDList(v EmergencyAreaIDListComplete, options ...aper.EncodeOption) ([]byte, error) {
	return v.MarshalAPER(options...)
}

// MarshalAPEREmergencyAreaIDBroadcast encodes a complete named list.
func MarshalAPEREmergencyAreaIDBroadcast(v EmergencyAreaIDBroadcastComplete, options ...aper.EncodeOption) ([]byte, error) {
	return v.MarshalAPER(options...)
}

// MarshalAPEREmergencyAreaIDCancelled encodes a complete named list.
func MarshalAPEREmergencyAreaIDCancelled(v EmergencyAreaIDCancelledComplete, options ...aper.EncodeOption) ([]byte, error) {
	return v.MarshalAPER(options...)
}

// MarshalAPERIEsECGIList encodes a complete named list.
func MarshalAPERIEsECGIList(v IEsECGIListComplete, options ...aper.EncodeOption) ([]byte, error) {
	return v.MarshalAPER(options...)
}

// MarshalAPEREmergencyAreaIDListForRestart encodes a complete named list.
func MarshalAPEREmergencyAreaIDListForRestart(v EmergencyAreaIDListForRestartComplete, options ...aper.EncodeOption) ([]byte, error) {
	return v.MarshalAPER(options...)
}

// MarshalAPERGUMMEIList encodes a complete named list.
func MarshalAPERGUMMEIList(v GUMMEIListComplete, options ...aper.EncodeOption) ([]byte, error) {
	return v.MarshalAPER(options...)
}

// MarshalAPERERABUsageReportList encodes a complete named list.
func MarshalAPERERABUsageReportList(v ERABUsageReportListComplete, options ...aper.EncodeOption) ([]byte, error) {
	return v.MarshalAPER(options...)
}

// MarshalAPERForbiddenTAs encodes a complete named list.
func MarshalAPERForbiddenTAs(v ForbiddenTAsComplete, options ...aper.EncodeOption) ([]byte, error) {
	return v.MarshalAPER(options...)
}

// MarshalAPERForbiddenTACs encodes a complete named list.
func MarshalAPERForbiddenTACs(v ForbiddenTACsComplete, options ...aper.EncodeOption) ([]byte, error) {
	return v.MarshalAPER(options...)
}

// MarshalAPERForbiddenLAs encodes a complete named list.
func MarshalAPERForbiddenLAs(v ForbiddenLAsComplete, options ...aper.EncodeOption) ([]byte, error) {
	return v.MarshalAPER(options...)
}

// MarshalAPERForbiddenLACs encodes a complete named list.
func MarshalAPERForbiddenLACs(v ForbiddenLACsComplete, options ...aper.EncodeOption) ([]byte, error) {
	return v.MarshalAPER(options...)
}

// MarshalAPERInterSystemMeasurementList encodes a complete named list.
func MarshalAPERInterSystemMeasurementList(v InterSystemMeasurementListComplete, options ...aper.EncodeOption) ([]byte, error) {
	return v.MarshalAPER(options...)
}

// MarshalAPERLastVisitedPSCellList encodes a complete named list.
func MarshalAPERLastVisitedPSCellList(v LastVisitedPSCellListComplete, options ...aper.EncodeOption) ([]byte, error) {
	return v.MarshalAPER(options...)
}

// MarshalAPERMBSFNResultToLog encodes a complete named list.
func MarshalAPERMBSFNResultToLog(v MBSFNResultToLogComplete, options ...aper.EncodeOption) ([]byte, error) {
	return v.MarshalAPER(options...)
}

// MarshalAPERMDTPLMNList encodes a complete named list.
func MarshalAPERMDTPLMNList(v MDTPLMNListComplete, options ...aper.EncodeOption) ([]byte, error) {
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

// UnmarshalAPEREmergencyAreaIDList decodes a complete named list.
func UnmarshalAPEREmergencyAreaIDList(data []byte, options ...aper.DecodeOption) (EmergencyAreaIDListComplete, aper.DecodeReport, error) {
	var v EmergencyAreaIDListComplete
	report, err := v.UnmarshalAPER(data, options...)
	return v, report, err
}

// UnmarshalAPEREmergencyAreaIDBroadcast decodes a complete named list.
func UnmarshalAPEREmergencyAreaIDBroadcast(data []byte, options ...aper.DecodeOption) (EmergencyAreaIDBroadcastComplete, aper.DecodeReport, error) {
	var v EmergencyAreaIDBroadcastComplete
	report, err := v.UnmarshalAPER(data, options...)
	return v, report, err
}

// UnmarshalAPEREmergencyAreaIDCancelled decodes a complete named list.
func UnmarshalAPEREmergencyAreaIDCancelled(data []byte, options ...aper.DecodeOption) (EmergencyAreaIDCancelledComplete, aper.DecodeReport, error) {
	var v EmergencyAreaIDCancelledComplete
	report, err := v.UnmarshalAPER(data, options...)
	return v, report, err
}

// UnmarshalAPERIEsECGIList decodes a complete named list.
func UnmarshalAPERIEsECGIList(data []byte, options ...aper.DecodeOption) (IEsECGIListComplete, aper.DecodeReport, error) {
	var v IEsECGIListComplete
	report, err := v.UnmarshalAPER(data, options...)
	return v, report, err
}

// UnmarshalAPEREmergencyAreaIDListForRestart decodes a complete named list.
func UnmarshalAPEREmergencyAreaIDListForRestart(data []byte, options ...aper.DecodeOption) (EmergencyAreaIDListForRestartComplete, aper.DecodeReport, error) {
	var v EmergencyAreaIDListForRestartComplete
	report, err := v.UnmarshalAPER(data, options...)
	return v, report, err
}

// UnmarshalAPERGUMMEIList decodes a complete named list.
func UnmarshalAPERGUMMEIList(data []byte, options ...aper.DecodeOption) (GUMMEIListComplete, aper.DecodeReport, error) {
	var v GUMMEIListComplete
	report, err := v.UnmarshalAPER(data, options...)
	return v, report, err
}

// UnmarshalAPERERABUsageReportList decodes a complete named list.
func UnmarshalAPERERABUsageReportList(data []byte, options ...aper.DecodeOption) (ERABUsageReportListComplete, aper.DecodeReport, error) {
	var v ERABUsageReportListComplete
	report, err := v.UnmarshalAPER(data, options...)
	return v, report, err
}

// UnmarshalAPERForbiddenTAs decodes a complete named list.
func UnmarshalAPERForbiddenTAs(data []byte, options ...aper.DecodeOption) (ForbiddenTAsComplete, aper.DecodeReport, error) {
	var v ForbiddenTAsComplete
	report, err := v.UnmarshalAPER(data, options...)
	return v, report, err
}

// UnmarshalAPERForbiddenTACs decodes a complete named list.
func UnmarshalAPERForbiddenTACs(data []byte, options ...aper.DecodeOption) (ForbiddenTACsComplete, aper.DecodeReport, error) {
	var v ForbiddenTACsComplete
	report, err := v.UnmarshalAPER(data, options...)
	return v, report, err
}

// UnmarshalAPERForbiddenLAs decodes a complete named list.
func UnmarshalAPERForbiddenLAs(data []byte, options ...aper.DecodeOption) (ForbiddenLAsComplete, aper.DecodeReport, error) {
	var v ForbiddenLAsComplete
	report, err := v.UnmarshalAPER(data, options...)
	return v, report, err
}

// UnmarshalAPERForbiddenLACs decodes a complete named list.
func UnmarshalAPERForbiddenLACs(data []byte, options ...aper.DecodeOption) (ForbiddenLACsComplete, aper.DecodeReport, error) {
	var v ForbiddenLACsComplete
	report, err := v.UnmarshalAPER(data, options...)
	return v, report, err
}

// UnmarshalAPERInterSystemMeasurementList decodes a complete named list.
func UnmarshalAPERInterSystemMeasurementList(data []byte, options ...aper.DecodeOption) (InterSystemMeasurementListComplete, aper.DecodeReport, error) {
	var v InterSystemMeasurementListComplete
	report, err := v.UnmarshalAPER(data, options...)
	return v, report, err
}

// UnmarshalAPERLastVisitedPSCellList decodes a complete named list.
func UnmarshalAPERLastVisitedPSCellList(data []byte, options ...aper.DecodeOption) (LastVisitedPSCellListComplete, aper.DecodeReport, error) {
	var v LastVisitedPSCellListComplete
	report, err := v.UnmarshalAPER(data, options...)
	return v, report, err
}

// UnmarshalAPERMBSFNResultToLog decodes a complete named list.
func UnmarshalAPERMBSFNResultToLog(data []byte, options ...aper.DecodeOption) (MBSFNResultToLogComplete, aper.DecodeReport, error) {
	var v MBSFNResultToLogComplete
	report, err := v.UnmarshalAPER(data, options...)
	return v, report, err
}

// UnmarshalAPERMDTPLMNList decodes a complete named list.
func UnmarshalAPERMDTPLMNList(data []byte, options ...aper.DecodeOption) (MDTPLMNListComplete, aper.DecodeReport, error) {
	var v MDTPLMNListComplete
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

// OverloadStart represents the ASN.1 type OverloadStart (SEQUENCE).
type OverloadStart struct {
	replay           aper.Snapshot
	stream           aper.WireSpan
	received         bool
	withoutReplay    bool
	receivedAbsolute bool
	receivedBytes    aper.WireSpan
	receivedLocation aper.Location
	ProtocolIEs      OverloadStartIEContainer `asn1:"tag:0,context,implicit"`
	protocolIEsIndef bool                     `asn1:"-" json:"-"`
	extCount         int64                    `asn1:"-" json:"-"`
	extPresent       []bool                   `asn1:"-" json:"-"`
	extData          [][]byte                 `asn1:"-" json:"-"`
	perPadding       aper.FinalPadding        `asn1:"-" json:"-"`
	perExtPadding    []aper.CompletePadding   `asn1:"-" json:"-"`
	extOrigin        []aper.OpaqueOrigin
	extWire          []aper.WireSpan
}

// OverloadStop represents the ASN.1 type OverloadStop (SEQUENCE).
type OverloadStop struct {
	replay           aper.Snapshot
	stream           aper.WireSpan
	received         bool
	withoutReplay    bool
	receivedAbsolute bool
	receivedBytes    aper.WireSpan
	receivedLocation aper.Location
	ProtocolIEs      OverloadStopIEContainer `asn1:"tag:0,context,implicit"`
	protocolIEsIndef bool                    `asn1:"-" json:"-"`
	extCount         int64                   `asn1:"-" json:"-"`
	extPresent       []bool                  `asn1:"-" json:"-"`
	extData          [][]byte                `asn1:"-" json:"-"`
	perPadding       aper.FinalPadding       `asn1:"-" json:"-"`
	perExtPadding    []aper.CompletePadding  `asn1:"-" json:"-"`
	extOrigin        []aper.OpaqueOrigin
	extWire          []aper.WireSpan
}

// UnmarshalAPERERABToBeSwitchedDLList decodes a ERABToBeSwitchedDLList list from APER.
func BridgeUnmarshalAPERERABToBeSwitchedDLList(data []byte) (s41.ERABToBeSwitchedDLListComplete, error) {
	var value s41.ERABToBeSwitchedDLListComplete
	if err := s41.BridgeERABToBeSwitchedDLListCompleteMethodUnmarshalAPERLegacy(&value, data); err != nil {
		return value, err
	}
	return value, nil
}

// ERABToBeSwitchedULListComplete carries a complete ERABToBeSwitchedULList encoding, including observed terminal bits.
// ITU-T X.691 (02/2021) 11.1.3.1 and 11.1.4 require new encodings to pad with zero bits.
type ERABToBeSwitchedULListComplete struct {
	replay           aper.Snapshot
	stream           aper.WireSpan
	received         bool
	withoutReplay    bool
	receivedAbsolute bool
	receivedBytes    aper.WireSpan
	receivedLocation aper.Location
	Value            s17.ERABToBeSwitchedULList
	perPadding       aper.CompletePadding `json:"-"`
}

func (v *ERABToBeSwitchedULListComplete) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := s26.BridgeMarshalAPERERABToBeSwitchedULListTo(v.Value, bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.perPadding)
}

// UnmarshalAPER decodes ERABToBeSwitchedULList from APER format.
func (v *ERABToBeSwitchedULListComplete) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes ERABToBeSwitchedULList with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *ERABToBeSwitchedULListComplete) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "ERABToBeSwitchedULList")
	}
	bb.EnterComponent("ERABToBeSwitchedULList")
	value, err := BridgeUnmarshalAPERERABToBeSwitchedULListFrom(bb)
	if err != nil {
		return runtime.WrapDecodePath(err, "ERABToBeSwitchedULList")
	}
	padding, err := aper.CaptureFinalBits(bb, "ERABToBeSwitchedULList")
	if err != nil {
		return runtime.WrapDecodePath(err, "ERABToBeSwitchedULList")
	}
	v.Value, v.perPadding = value, padding.Padding()
	return nil
}

// MarshalAPERERABToBeSwitchedULList encodes a ERABToBeSwitchedULList list to APER.
func BridgeMarshalAPERERABToBeSwitchedULList(list ERABToBeSwitchedULListComplete) ([]byte, error) {
	return list.marshalAPERLegacy()
}

// UnmarshalAPERERABToBeSwitchedULList decodes a ERABToBeSwitchedULList list from APER.
func BridgeUnmarshalAPERERABToBeSwitchedULList(data []byte) (ERABToBeSwitchedULListComplete, error) {
	var value ERABToBeSwitchedULListComplete
	if err := value.unmarshalAPERLegacy(data); err != nil {
		return value, err
	}
	return value, nil
}

// UnmarshalAPERERABToBeSwitchedULListFrom decodes a ERABToBeSwitchedULList list from bb.
func BridgeUnmarshalAPERERABToBeSwitchedULListFrom(bb *aper.BitBuffer) (s17.ERABToBeSwitchedULList, error) {
	if err := bb.EnterDecodeValue(); err != nil {
		return nil, err
	}
	defer bb.LeaveDecodeValue()
	var v s21.BridgeAsn1cAPERERABToBeSwitchedULListListValue
	if err := BridgeUnmarshalAPERERABToBeSwitchedULListInto(&v, bb); err != nil {
		return nil, err
	}
	return v.Value, nil
}
func BridgeUnmarshalAPERERABToBeSwitchedULListInto(v *s21.BridgeAsn1cAPERERABToBeSwitchedULListListValue, bb *aper.BitBuffer) error {
	toleranceMark_value := bb.EnterComponent("Value")
	v.Value = make(s17.ERABToBeSwitchedULList, 0)
	_, errCollection_value := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 256, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1128
		if fragmentOffset_value < 0 || fragmentLength_value < 0 || fragmentLength_value > int64(^uint(0)>>1) || fragmentOffset_value > int64(^uint(0)>>1)-fragmentLength_value {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_value; i++ {
			var elem s17.ERABToBeSwitchedULItemIEValueProtocolIESingleContainer
			elementMark := bb.EnterIndex(fragmentOffset_value + i)
			if err := s17.BridgeERABToBeSwitchedULItemIEFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
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

// ERABToBeUpdatedListComplete carries a complete ERABToBeUpdatedList encoding, including observed terminal bits.
// ITU-T X.691 (02/2021) 11.1.3.1 and 11.1.4 require new encodings to pad with zero bits.
type ERABToBeUpdatedListComplete struct {
	replay           aper.Snapshot
	stream           aper.WireSpan
	received         bool
	withoutReplay    bool
	receivedAbsolute bool
	receivedBytes    aper.WireSpan
	receivedLocation aper.Location
	Value            s29.ERABToBeUpdatedList
	perPadding       aper.CompletePadding `json:"-"`
}

func (v *ERABToBeUpdatedListComplete) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := s30.BridgeMarshalAPERERABToBeUpdatedListTo(v.Value, bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.perPadding)
}

// UnmarshalAPER decodes ERABToBeUpdatedList from APER format.
func (v *ERABToBeUpdatedListComplete) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes ERABToBeUpdatedList with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *ERABToBeUpdatedListComplete) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "ERABToBeUpdatedList")
	}
	bb.EnterComponent("ERABToBeUpdatedList")
	value, err := BridgeUnmarshalAPERERABToBeUpdatedListFrom(bb)
	if err != nil {
		return runtime.WrapDecodePath(err, "ERABToBeUpdatedList")
	}
	padding, err := aper.CaptureFinalBits(bb, "ERABToBeUpdatedList")
	if err != nil {
		return runtime.WrapDecodePath(err, "ERABToBeUpdatedList")
	}
	v.Value, v.perPadding = value, padding.Padding()
	return nil
}

// MarshalAPERERABToBeUpdatedList encodes a ERABToBeUpdatedList list to APER.
func BridgeMarshalAPERERABToBeUpdatedList(list ERABToBeUpdatedListComplete) ([]byte, error) {
	return list.marshalAPERLegacy()
}

// UnmarshalAPERERABToBeUpdatedList decodes a ERABToBeUpdatedList list from APER.
func BridgeUnmarshalAPERERABToBeUpdatedList(data []byte) (ERABToBeUpdatedListComplete, error) {
	var value ERABToBeUpdatedListComplete
	if err := value.unmarshalAPERLegacy(data); err != nil {
		return value, err
	}
	return value, nil
}

// UnmarshalAPERERABToBeUpdatedListFrom decodes a ERABToBeUpdatedList list from bb.
func BridgeUnmarshalAPERERABToBeUpdatedListFrom(bb *aper.BitBuffer) (s29.ERABToBeUpdatedList, error) {
	if err := bb.EnterDecodeValue(); err != nil {
		return nil, err
	}
	defer bb.LeaveDecodeValue()
	var v s29.BridgeAsn1cAPERERABToBeUpdatedListListValue
	if err := BridgeUnmarshalAPERERABToBeUpdatedListInto(&v, bb); err != nil {
		return nil, err
	}
	return v.Value, nil
}
func BridgeUnmarshalAPERERABToBeUpdatedListInto(v *s29.BridgeAsn1cAPERERABToBeUpdatedListListValue, bb *aper.BitBuffer) error {
	toleranceMark_value := bb.EnterComponent("Value")
	v.Value = make(s29.ERABToBeUpdatedList, 0)
	_, errCollection_value := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 256, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1128
		if fragmentOffset_value < 0 || fragmentLength_value < 0 || fragmentLength_value > int64(^uint(0)>>1) || fragmentOffset_value > int64(^uint(0)>>1)-fragmentLength_value {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_value; i++ {
			var elem s29.ERABToBeUpdatedItemIEValueProtocolIESingleContainer
			elementMark := bb.EnterIndex(fragmentOffset_value + i)
			if err := s29.BridgeERABToBeUpdatedItemIEFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
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

// MarshalAPER encodes OverloadStart to APER format.
func (v *OverloadStart) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *OverloadStart) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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

// UnmarshalAPER decodes OverloadStart from APER format.
func (v *OverloadStart) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes OverloadStart with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *OverloadStart) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "OverloadStart")
	}
	bb.EnterComponent("OverloadStart")
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "OverloadStart")
	}
	padding, err := aper.CaptureFinalBits(bb, "OverloadStart")
	if err != nil {
		return runtime.WrapDecodePath(err, "OverloadStart")
	}
	v.perPadding = padding.WithRecords(v.perPadding)
	return nil
}
func (v *OverloadStart) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = OverloadStart{}
	extAdditions := aper.BeginExtensionAdditions(bb)
	hasExtensions, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	toleranceMark_protocolies := bb.EnterComponent("ProtocolIEs")
	v.ProtocolIEs = make(OverloadStartIEContainer, 0)
	_, errCollection_protocolies := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1128
		if fragmentOffset_protocolies < 0 || fragmentLength_protocolies < 0 || fragmentLength_protocolies > int64(^uint(0)>>1) || fragmentOffset_protocolies > int64(^uint(0)>>1)-fragmentLength_protocolies {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_protocolies; i++ {
			var elem OverloadStartIEField
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

// MarshalAPER encodes OverloadStop to APER format.
func (v *OverloadStop) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *OverloadStop) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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

// UnmarshalAPER decodes OverloadStop from APER format.
func (v *OverloadStop) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes OverloadStop with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *OverloadStop) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "OverloadStop")
	}
	bb.EnterComponent("OverloadStop")
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "OverloadStop")
	}
	padding, err := aper.CaptureFinalBits(bb, "OverloadStop")
	if err != nil {
		return runtime.WrapDecodePath(err, "OverloadStop")
	}
	v.perPadding = padding.WithRecords(v.perPadding)
	return nil
}
func (v *OverloadStop) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = OverloadStop{}
	extAdditions := aper.BeginExtensionAdditions(bb)
	hasExtensions, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	toleranceMark_protocolies := bb.EnterComponent("ProtocolIEs")
	v.ProtocolIEs = make(OverloadStopIEContainer, 0)
	_, errCollection_protocolies := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1128
		if fragmentOffset_protocolies < 0 || fragmentLength_protocolies < 0 || fragmentLength_protocolies > int64(^uint(0)>>1) || fragmentOffset_protocolies > int64(^uint(0)>>1)-fragmentLength_protocolies {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_protocolies; i++ {
			var elem OverloadStopIEField
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
func (v *ERABToBeSwitchedULListComplete) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s14.BridgeReceivedFormAt(v.received, v.receivedBytes, "ERABToBeSwitchedULListComplete", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "ERABToBeSwitchedULListComplete", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v ERABToBeSwitchedULListComplete) WithoutReplay() ERABToBeSwitchedULListComplete {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero ERABToBeSwitchedULListComplete
	v.perPadding = zero.perPadding
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *ERABToBeUpdatedListComplete) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s14.BridgeReceivedFormAt(v.received, v.receivedBytes, "ERABToBeUpdatedListComplete", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "ERABToBeUpdatedListComplete", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v ERABToBeUpdatedListComplete) WithoutReplay() ERABToBeUpdatedListComplete {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero ERABToBeUpdatedListComplete
	v.perPadding = zero.perPadding
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *OverloadStart) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s14.BridgeReceivedFormAt(v.received, v.receivedBytes, "OverloadStart", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "OverloadStart", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v OverloadStart) WithoutReplay() OverloadStart {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero OverloadStart
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *OverloadStop) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s14.BridgeReceivedFormAt(v.received, v.receivedBytes, "OverloadStop", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "OverloadStop", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v OverloadStop) WithoutReplay() OverloadStop {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero OverloadStop
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// Extensions returns owned unknown sequence additions.
func (v *OverloadStart) Extensions() []aper.SequenceExtension {
	if v == nil {
		return nil
	}
	views := aper.SequenceExtensionViews(v.extPresent, aper.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *OverloadStart) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("OverloadStart.Extensions[%d]", index))
	}
	if err := aper.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("OverloadStart.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *OverloadStart) RemoveExtension(index uint64) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("OverloadStart.Extensions[%d]", index))
	}
	if err := aper.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("OverloadStart.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// Extensions returns owned unknown sequence additions.
func (v *OverloadStop) Extensions() []aper.SequenceExtension {
	if v == nil {
		return nil
	}
	views := aper.SequenceExtensionViews(v.extPresent, aper.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *OverloadStop) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("OverloadStop.Extensions[%d]", index))
	}
	if err := aper.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("OverloadStop.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *OverloadStop) RemoveExtension(index uint64) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("OverloadStop.Extensions[%d]", index))
	}
	if err := aper.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("OverloadStop.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// MarshalAPER encodes a complete value using one per-call change plan.
func (v *ERABToBeSwitchedULListComplete) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "ERABToBeSwitchedULListComplete")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *ERABToBeSwitchedULListComplete) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "ERABToBeSwitchedULListComplete")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APERABToBeSwitchedULListComplete(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "ERABToBeSwitchedULListComplete")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "ERABToBeSwitchedULListComplete")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *ERABToBeSwitchedULListComplete) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "ERABToBeSwitchedULListComplete")
}
func (v *ERABToBeSwitchedULListComplete) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "ERABToBeSwitchedULListComplete")
}
func (v *ERABToBeSwitchedULListComplete) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APERABToBeSwitchedULListComplete(v, &s)
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
func (v *ERABToBeSwitchedULListComplete) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *ERABToBeSwitchedULListComplete) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
	if err := s26.BridgeMarshalAPERERABToBeSwitchedULListTo(v.Value, bb, fresh); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.perPadding)
}

// MarshalAPER encodes a complete value using one per-call change plan.
func (v *ERABToBeUpdatedListComplete) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "ERABToBeUpdatedListComplete")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *ERABToBeUpdatedListComplete) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "ERABToBeUpdatedListComplete")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APERABToBeUpdatedListComplete(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "ERABToBeUpdatedListComplete")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "ERABToBeUpdatedListComplete")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *ERABToBeUpdatedListComplete) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "ERABToBeUpdatedListComplete")
}
func (v *ERABToBeUpdatedListComplete) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "ERABToBeUpdatedListComplete")
}
func (v *ERABToBeUpdatedListComplete) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APERABToBeUpdatedListComplete(v, &s)
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
func (v *ERABToBeUpdatedListComplete) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *ERABToBeUpdatedListComplete) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
	if err := s30.BridgeMarshalAPERERABToBeUpdatedListTo(v.Value, bb, fresh); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.perPadding)
}

// MarshalAPER encodes a complete value using one per-call change plan.
func (v *OverloadStart) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "OverloadStart")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *OverloadStart) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "OverloadStart")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APOverloadStart(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "OverloadStart")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "OverloadStart")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *OverloadStart) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "OverloadStart")
}
func (v *OverloadStart) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "OverloadStart")
}
func (v *OverloadStart) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APOverloadStart(v, &s)
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
func (v *OverloadStart) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *OverloadStart) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
func (v *OverloadStop) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "OverloadStop")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *OverloadStop) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "OverloadStop")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APOverloadStop(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "OverloadStop")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "OverloadStop")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *OverloadStop) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "OverloadStop")
}
func (v *OverloadStop) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "OverloadStop")
}
func (v *OverloadStop) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APOverloadStop(v, &s)
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
func (v *OverloadStop) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *OverloadStop) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
func (v *ERABToBeSwitchedULListComplete) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "ERABToBeSwitchedULListComplete")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded ERABToBeSwitchedULListComplete
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APERABToBeSwitchedULListComplete(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = ERABToBeSwitchedULListComplete{}
		return report, aper.OperationError(err, "ERABToBeSwitchedULListComplete")
	}
	*v = decoded
	return report, aper.OperationError(nil, "ERABToBeSwitchedULListComplete")
}

// UnmarshalAPER decodes one complete value and returns its report.
func (v *ERABToBeUpdatedListComplete) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "ERABToBeUpdatedListComplete")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded ERABToBeUpdatedListComplete
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APERABToBeUpdatedListComplete(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = ERABToBeUpdatedListComplete{}
		return report, aper.OperationError(err, "ERABToBeUpdatedListComplete")
	}
	*v = decoded
	return report, aper.OperationError(nil, "ERABToBeUpdatedListComplete")
}

// UnmarshalAPER decodes one complete value and returns its report.
func (v *OverloadStart) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "OverloadStart")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded OverloadStart
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APOverloadStart(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = OverloadStart{}
		return report, aper.OperationError(err, "OverloadStart")
	}
	*v = decoded
	return report, aper.OperationError(nil, "OverloadStart")
}

// UnmarshalAPER decodes one complete value and returns its report.
func (v *OverloadStop) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "OverloadStop")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded OverloadStop
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APOverloadStop(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = OverloadStop{}
		return report, aper.OperationError(err, "OverloadStop")
	}
	*v = decoded
	return report, aper.OperationError(nil, "OverloadStop")
}

// MarshalAPERERABToBeSwitchedULList encodes a complete named list.
func MarshalAPERERABToBeSwitchedULList(v ERABToBeSwitchedULListComplete, options ...aper.EncodeOption) ([]byte, error) {
	return v.MarshalAPER(options...)
}

// MarshalAPERERABToBeUpdatedList encodes a complete named list.
func MarshalAPERERABToBeUpdatedList(v ERABToBeUpdatedListComplete, options ...aper.EncodeOption) ([]byte, error) {
	return v.MarshalAPER(options...)
}

// UnmarshalAPERERABToBeSwitchedULList decodes a complete named list.
func UnmarshalAPERERABToBeSwitchedULList(data []byte, options ...aper.DecodeOption) (ERABToBeSwitchedULListComplete, aper.DecodeReport, error) {
	var v ERABToBeSwitchedULListComplete
	report, err := v.UnmarshalAPER(data, options...)
	return v, report, err
}

// UnmarshalAPERERABToBeUpdatedList decodes a complete named list.
func UnmarshalAPERERABToBeUpdatedList(data []byte, options ...aper.DecodeOption) (ERABToBeUpdatedListComplete, aper.DecodeReport, error) {
	var v ERABToBeUpdatedListComplete
	report, err := v.UnmarshalAPER(data, options...)
	return v, report, err
}

// MultiCellLoadReportingResponseComplete carries a complete MultiCellLoadReportingResponse encoding, including observed terminal bits.
// ITU-T X.691 (02/2021) 11.1.3.1 and 11.1.4 require new encodings to pad with zero bits.
type MultiCellLoadReportingResponseComplete struct {
	replay           aper.Snapshot
	stream           aper.WireSpan
	received         bool
	withoutReplay    bool
	receivedAbsolute bool
	receivedBytes    aper.WireSpan
	receivedLocation aper.Location
	Value            s19.MultiCellLoadReportingResponse
	perPadding       aper.CompletePadding `json:"-"`
}

func (v *MultiCellLoadReportingResponseComplete) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := s26.BridgeMarshalAPERMultiCellLoadReportingResponseTo(v.Value, bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.perPadding)
}

// UnmarshalAPER decodes MultiCellLoadReportingResponse from APER format.
func (v *MultiCellLoadReportingResponseComplete) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes MultiCellLoadReportingResponse with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *MultiCellLoadReportingResponseComplete) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "MultiCellLoadReportingResponse")
	}
	bb.EnterComponent("MultiCellLoadReportingResponse")
	value, err := BridgeUnmarshalAPERMultiCellLoadReportingResponseFrom(bb)
	if err != nil {
		return runtime.WrapDecodePath(err, "MultiCellLoadReportingResponse")
	}
	padding, err := aper.CaptureFinalBits(bb, "MultiCellLoadReportingResponse")
	if err != nil {
		return runtime.WrapDecodePath(err, "MultiCellLoadReportingResponse")
	}
	v.Value, v.perPadding = value, padding.Padding()
	return nil
}

// MarshalAPERMultiCellLoadReportingResponse encodes a MultiCellLoadReportingResponse list to APER.
func BridgeMarshalAPERMultiCellLoadReportingResponse(list MultiCellLoadReportingResponseComplete) ([]byte, error) {
	return list.marshalAPERLegacy()
}

// UnmarshalAPERMultiCellLoadReportingResponse decodes a MultiCellLoadReportingResponse list from APER.
func BridgeUnmarshalAPERMultiCellLoadReportingResponse(data []byte) (MultiCellLoadReportingResponseComplete, error) {
	var value MultiCellLoadReportingResponseComplete
	if err := value.unmarshalAPERLegacy(data); err != nil {
		return value, err
	}
	return value, nil
}

// UnmarshalAPERMultiCellLoadReportingResponseFrom decodes a MultiCellLoadReportingResponse list from bb.
func BridgeUnmarshalAPERMultiCellLoadReportingResponseFrom(bb *aper.BitBuffer) (s19.MultiCellLoadReportingResponse, error) {
	if err := bb.EnterDecodeValue(); err != nil {
		return nil, err
	}
	defer bb.LeaveDecodeValue()
	var v s21.BridgeAsn1cAPERMultiCellLoadReportingResponseListValue
	if err := BridgeUnmarshalAPERMultiCellLoadReportingResponseInto(&v, bb); err != nil {
		return nil, err
	}
	return v.Value, nil
}
func BridgeUnmarshalAPERMultiCellLoadReportingResponseInto(v *s21.BridgeAsn1cAPERMultiCellLoadReportingResponseListValue, bb *aper.BitBuffer) error {
	toleranceMark_value := bb.EnterComponent("Value")
	v.Value = make(s19.MultiCellLoadReportingResponse, 0)
	_, errCollection_value := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 128, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1128
		if fragmentOffset_value < 0 || fragmentLength_value < 0 || fragmentLength_value > int64(^uint(0)>>1) || fragmentOffset_value > int64(^uint(0)>>1)-fragmentLength_value {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_value; i++ {
			var elem s19.MultiCellLoadReportingResponseItem
			elementMark := bb.EnterIndex(fragmentOffset_value + i)
			if err := s19.BridgeMultiCellLoadReportingResponseItemMethodUnmarshalAPERFrom(&elem, bb); err != nil {
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
	Value            s20.NotificationCellList
	perPadding       aper.CompletePadding `json:"-"`
}

func (v *NotificationCellListComplete) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := s26.BridgeMarshalAPERNotificationCellListTo(v.Value, bb); err != nil {
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
	bb.EnterComponent("NotificationCellList")
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
func BridgeUnmarshalAPERNotificationCellListFrom(bb *aper.BitBuffer) (s20.NotificationCellList, error) {
	if err := bb.EnterDecodeValue(); err != nil {
		return nil, err
	}
	defer bb.LeaveDecodeValue()
	var v s21.BridgeAsn1cAPERNotificationCellListListValue
	if err := BridgeUnmarshalAPERNotificationCellListInto(&v, bb); err != nil {
		return nil, err
	}
	return v.Value, nil
}
func BridgeUnmarshalAPERNotificationCellListInto(v *s21.BridgeAsn1cAPERNotificationCellListListValue, bb *aper.BitBuffer) error {
	toleranceMark_value := bb.EnterComponent("Value")
	v.Value = make(s20.NotificationCellList, 0)
	_, errCollection_value := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 256, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1128
		if fragmentOffset_value < 0 || fragmentLength_value < 0 || fragmentLength_value > int64(^uint(0)>>1) || fragmentOffset_value > int64(^uint(0)>>1)-fragmentLength_value {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_value; i++ {
			var elem s20.NotificationCellListItem
			elementMark := bb.EnterIndex(fragmentOffset_value + i)
			if err := s20.BridgeNotificationCellListItemMethodUnmarshalAPERFrom(&elem, bb); err != nil {
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
func (v *MultiCellLoadReportingResponseComplete) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s14.BridgeReceivedFormAt(v.received, v.receivedBytes, "MultiCellLoadReportingResponseComplete", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "MultiCellLoadReportingResponseComplete", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v MultiCellLoadReportingResponseComplete) WithoutReplay() MultiCellLoadReportingResponseComplete {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero MultiCellLoadReportingResponseComplete
	v.perPadding = zero.perPadding
	return v
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

// MarshalAPER encodes a complete value using one per-call change plan.
func (v *MultiCellLoadReportingResponseComplete) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "MultiCellLoadReportingResponseComplete")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *MultiCellLoadReportingResponseComplete) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "MultiCellLoadReportingResponseComplete")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APMultiCellLoadReportingResponseComplete(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "MultiCellLoadReportingResponseComplete")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "MultiCellLoadReportingResponseComplete")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *MultiCellLoadReportingResponseComplete) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "MultiCellLoadReportingResponseComplete")
}
func (v *MultiCellLoadReportingResponseComplete) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "MultiCellLoadReportingResponseComplete")
}
func (v *MultiCellLoadReportingResponseComplete) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APMultiCellLoadReportingResponseComplete(v, &s)
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
func (v *MultiCellLoadReportingResponseComplete) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *MultiCellLoadReportingResponseComplete) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
	if err := s26.BridgeMarshalAPERMultiCellLoadReportingResponseTo(v.Value, bb, fresh); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.perPadding)
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
	if err := s26.BridgeMarshalAPERNotificationCellListTo(v.Value, bb, fresh); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.perPadding)
}

// UnmarshalAPER decodes one complete value and returns its report.
func (v *MultiCellLoadReportingResponseComplete) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "MultiCellLoadReportingResponseComplete")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded MultiCellLoadReportingResponseComplete
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APMultiCellLoadReportingResponseComplete(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = MultiCellLoadReportingResponseComplete{}
		return report, aper.OperationError(err, "MultiCellLoadReportingResponseComplete")
	}
	*v = decoded
	return report, aper.OperationError(nil, "MultiCellLoadReportingResponseComplete")
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

// MarshalAPERMultiCellLoadReportingResponse encodes a complete named list.
func MarshalAPERMultiCellLoadReportingResponse(v MultiCellLoadReportingResponseComplete, options ...aper.EncodeOption) ([]byte, error) {
	return v.MarshalAPER(options...)
}

// MarshalAPERNotificationCellList encodes a complete named list.
func MarshalAPERNotificationCellList(v NotificationCellListComplete, options ...aper.EncodeOption) ([]byte, error) {
	return v.MarshalAPER(options...)
}

// UnmarshalAPERMultiCellLoadReportingResponse decodes a complete named list.
func UnmarshalAPERMultiCellLoadReportingResponse(data []byte, options ...aper.DecodeOption) (MultiCellLoadReportingResponseComplete, aper.DecodeReport, error) {
	var v MultiCellLoadReportingResponseComplete
	report, err := v.UnmarshalAPER(data, options...)
	return v, report, err
}

// UnmarshalAPERNotificationCellList decodes a complete named list.
func UnmarshalAPERNotificationCellList(data []byte, options ...aper.DecodeOption) (NotificationCellListComplete, aper.DecodeReport, error) {
	var v NotificationCellListComplete
	report, err := v.UnmarshalAPER(data, options...)
	return v, report, err
}

type LastVisitedEUTRANCellInformationExtIEsValue struct {
	id                                       s00.ProtocolIEID
	received                                 aper.WireSpan
	replay                                   aper.Snapshot
	opaque                                   aper.OpaqueOpenType
	isOpaque                                 bool
	rowTimeUEStayedInCellEnhancedGranularity *s00.TimeUEStayedInCellEnhancedGranularity
	rowHOCause                               *s14.Cause
	rowLastVisitedPSCellList                 *s20.LastVisitedPSCellList
}

func (v LastVisitedEUTRANCellInformationExtIEsValue) matchesID(id s00.ProtocolIEID, _ ...*aper.DecodeBudget) bool {
	if v.id != id {
		return false
	}
	if v.isOpaque {
		return true
	}
	switch id {
	case s00.ProtocolIEID(167):
		return v.rowTimeUEStayedInCellEnhancedGranularity != nil
	case s00.ProtocolIEID(168):
		return v.rowHOCause != nil
	case s00.ProtocolIEID(329):
		return v.rowLastVisitedPSCellList != nil
	}
	return false
}

// Opaque returns the retained opaque open value of LastVisitedEUTRANCellInformationExtIEsValue and reports whether the opaque alternative is selected.
func (v *LastVisitedEUTRANCellInformationExtIEsValue) Opaque() (aper.OpaqueOpenType, bool) {
	if v == nil || !v.isOpaque {
		return aper.OpaqueOpenType{}, false
	}
	return v.opaque, true
}
func (LastVisitedEUTRANCellInformationExtIEsValue) rule() aper.SourceRule {
	return aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.4", Assignment: aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "LastVisitedEUTRANCellInformation-ExtIEs"}}
}
func (LastVisitedEUTRANCellInformationExtIEsValue) reason(id s00.ProtocolIEID) aper.OpaqueReason {
	switch id {
	case s00.ProtocolIEID(167):
		return aper.UnknownSelector
	case s00.ProtocolIEID(168):
		return aper.UnknownSelector
	case s00.ProtocolIEID(329):
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

// AsTimeUEStayedInCellEnhancedGranularity returns the selected TimeUEStayedInCellEnhancedGranularity value of LastVisitedEUTRANCellInformationExtIEsValue and reports whether that alternative is active.
func (v *LastVisitedEUTRANCellInformationExtIEsValue) AsTimeUEStayedInCellEnhancedGranularity() (*s00.TimeUEStayedInCellEnhancedGranularity, bool) {
	if v == nil || v.id != s00.ProtocolIEID(167) || v.rowTimeUEStayedInCellEnhancedGranularity == nil {
		return nil, false
	}
	return v.rowTimeUEStayedInCellEnhancedGranularity, true
}

// AsHOCause returns the selected HOCause value of LastVisitedEUTRANCellInformationExtIEsValue and reports whether that alternative is active.
func (v *LastVisitedEUTRANCellInformationExtIEsValue) AsHOCause() (*s14.Cause, bool) {
	if v == nil || v.id != s00.ProtocolIEID(168) || v.rowHOCause == nil {
		return nil, false
	}
	return v.rowHOCause, true
}

// AsLastVisitedPSCellList returns the selected LastVisitedPSCellList value of LastVisitedEUTRANCellInformationExtIEsValue and reports whether that alternative is active.
func (v *LastVisitedEUTRANCellInformationExtIEsValue) AsLastVisitedPSCellList() (*s20.LastVisitedPSCellList, bool) {
	if v == nil || v.id != s00.ProtocolIEID(329) || v.rowLastVisitedPSCellList == nil {
		return nil, false
	}
	return v.rowLastVisitedPSCellList, true
}
func (v LastVisitedEUTRANCellInformationExtIEsValue) decode(id s00.ProtocolIEID, raw aper.OpaqueOpenType) (LastVisitedEUTRANCellInformationExtIEsValue, error) {
	out := LastVisitedEUTRANCellInformationExtIEsValue{id: id}
	switch id {
	case s00.ProtocolIEID(167):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		bb := scope
		decoded, err := aper.DecodeIntegerAligned(bb, s07.BridgeInt64Ptr(0), s07.BridgeInt64Ptr(40950), false)
		value := s00.TimeUEStayedInCellEnhancedGranularity(decoded)
		if err != nil {
			return out, fmt.Errorf("%s %w", "TimeUEStayedInCellEnhancedGranularity:", err)
		}
		if _, err := aper.CompleteOpenTypeValue(bb, value); err != nil {
			return out, err
		}
		out.rowTimeUEStayedInCellEnhancedGranularity = &value
		raw.RetainContents(&out.received)
	case s00.ProtocolIEID(168):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		var value s14.Cause
		child := scope
		if err := s14.BridgeCauseMethodUnmarshalAPERFrom(&value, child); err != nil {
			return out, fmt.Errorf("%s %w", "HOCause:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "Cause")
		if err != nil {
			return out, err
		}
		*s14.BridgeCauseFieldPerPadding(&value) = padding.Padding()
		*s14.BridgeCauseFieldReceived(&value) = true
		raw.RetainContents(s14.BridgeCauseFieldReceivedBytes(&value))
		*s14.BridgeCauseFieldReceivedLocation(&value) = raw.ContentLocation()
		out.rowHOCause = &value
		raw.RetainContents(&out.received)
	case s00.ProtocolIEID(329):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		child := scope
		list, err := BridgeUnmarshalAPERLastVisitedPSCellListFrom(child)
		if err != nil {
			return out, fmt.Errorf("%s %w", "LastVisitedPSCellList:", err)
		}
		padding, err := aper.CaptureOpenTypePadding(child)
		if err != nil {
			return out, err
		}
		_ = padding
		value := list
		out.rowLastVisitedPSCellList = &value
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
func (v LastVisitedEUTRANCellInformationExtIEsValue) encode() ([]byte, error) {
	return v.encodeFresh(false, nil)
}
func (v LastVisitedEUTRANCellInformationExtIEsValue) encodeFresh(fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
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
	case s00.ProtocolIEID(167):
		if v.rowTimeUEStayedInCellEnhancedGranularity == nil {
			return nil, fmt.Errorf("%s missing value", "LastVisitedEUTRANCellInformation-ExtIEs.id-Time-UE-StayedInCell-EnhancedGranularity:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		encodeBB := aper.NewBudgetBuffer(budget)
		if err := aper.EncodeIntegerAligned(encodeBB, int64(*v.rowTimeUEStayedInCellEnhancedGranularity), s07.BridgeInt64Ptr(0), s07.BridgeInt64Ptr(40950), false); err != nil {
			return nil, err
		}
		candidate := encodeBB.CompleteBytes()
		return candidate, nil
	case s00.ProtocolIEID(168):
		if v.rowHOCause == nil {
			return nil, fmt.Errorf("%s missing value", "LastVisitedEUTRANCellInformation-ExtIEs.id-HO-Cause:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		candidate, err := s14.BridgeCauseMethodMarshalAPERBudget(v.rowHOCause, budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	case s00.ProtocolIEID(329):
		if v.rowLastVisitedPSCellList == nil {
			return nil, fmt.Errorf("%s missing value", "LastVisitedEUTRANCellInformation-ExtIEs.id-lastVisitedPSCellList:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		complete := LastVisitedPSCellListComplete{Value: *v.rowLastVisitedPSCellList}
		candidate, err := complete.marshalAPERBudget(budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	default:
		return nil, fmt.Errorf("%s id %d has no value", "LastVisitedEUTRANCellInformationExtIEsValue:", v.id)
	}
}

type MDTConfigurationExtIEsValue struct {
	id                            s00.ProtocolIEID
	received                      aper.WireSpan
	replay                        aper.Snapshot
	opaque                        aper.OpaqueOpenType
	isOpaque                      bool
	rowSignallingBasedMDTPLMNList *s00.MDTPLMNList
}

func (v MDTConfigurationExtIEsValue) matchesID(id s00.ProtocolIEID, _ ...*aper.DecodeBudget) bool {
	if v.id != id {
		return false
	}
	if v.isOpaque {
		return true
	}
	switch id {
	case s00.ProtocolIEID(178):
		return v.rowSignallingBasedMDTPLMNList != nil
	}
	return false
}

// Opaque returns the retained opaque open value of MDTConfigurationExtIEsValue and reports whether the opaque alternative is selected.
func (v *MDTConfigurationExtIEsValue) Opaque() (aper.OpaqueOpenType, bool) {
	if v == nil || !v.isOpaque {
		return aper.OpaqueOpenType{}, false
	}
	return v.opaque, true
}
func (MDTConfigurationExtIEsValue) rule() aper.SourceRule {
	return aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.4", Assignment: aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "MDT-Configuration-ExtIEs"}}
}
func (MDTConfigurationExtIEsValue) reason(id s00.ProtocolIEID) aper.OpaqueReason {
	switch id {
	case s00.ProtocolIEID(178):
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

// AsSignallingBasedMDTPLMNList returns the selected SignallingBasedMDTPLMNList value of MDTConfigurationExtIEsValue and reports whether that alternative is active.
func (v *MDTConfigurationExtIEsValue) AsSignallingBasedMDTPLMNList() (*s00.MDTPLMNList, bool) {
	if v == nil || v.id != s00.ProtocolIEID(178) || v.rowSignallingBasedMDTPLMNList == nil {
		return nil, false
	}
	return v.rowSignallingBasedMDTPLMNList, true
}
func (v MDTConfigurationExtIEsValue) decode(id s00.ProtocolIEID, raw aper.OpaqueOpenType) (MDTConfigurationExtIEsValue, error) {
	out := MDTConfigurationExtIEsValue{id: id}
	switch id {
	case s00.ProtocolIEID(178):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		child := scope
		list, err := BridgeUnmarshalAPERMDTPLMNListFrom(child)
		if err != nil {
			return out, fmt.Errorf("%s %w", "SignallingBasedMDTPLMNList:", err)
		}
		padding, err := aper.CaptureOpenTypePadding(child)
		if err != nil {
			return out, err
		}
		_ = padding
		value := list
		out.rowSignallingBasedMDTPLMNList = &value
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
func (v MDTConfigurationExtIEsValue) encode() ([]byte, error) { return v.encodeFresh(false, nil) }
func (v MDTConfigurationExtIEsValue) encodeFresh(fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
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
	case s00.ProtocolIEID(178):
		if v.rowSignallingBasedMDTPLMNList == nil {
			return nil, fmt.Errorf("%s missing value", "MDT-Configuration-ExtIEs.id-SignallingBasedMDTPLMNList:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		complete := MDTPLMNListComplete{Value: *v.rowSignallingBasedMDTPLMNList}
		candidate, err := complete.marshalAPERBudget(budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	default:
		return nil, fmt.Errorf("%s id %d has no value", "MDTConfigurationExtIEsValue:", v.id)
	}
}

type OverloadStartIEValue struct {
	id                                s00.ProtocolIEID
	received                          aper.WireSpan
	replay                            aper.Snapshot
	opaque                            aper.OpaqueOpenType
	isOpaque                          bool
	rowOverloadResponse               *s20.OverloadResponse
	rowGUMMEIList                     *s18.GUMMEIList
	rowTrafficLoadReductionIndication *s00.TrafficLoadReductionIndication
}

func (v OverloadStartIEValue) matchesID(id s00.ProtocolIEID, _ ...*aper.DecodeBudget) bool {
	if v.id != id {
		return false
	}
	if v.isOpaque {
		return true
	}
	switch id {
	case s00.ProtocolIEID(101):
		return v.rowOverloadResponse != nil
	case s00.ProtocolIEID(154):
		return v.rowGUMMEIList != nil
	case s00.ProtocolIEID(161):
		return v.rowTrafficLoadReductionIndication != nil
	}
	return false
}

// Opaque returns the retained opaque open value of OverloadStartIEValue and reports whether the opaque alternative is selected.
func (v *OverloadStartIEValue) Opaque() (aper.OpaqueOpenType, bool) {
	if v == nil || !v.isOpaque {
		return aper.OpaqueOpenType{}, false
	}
	return v.opaque, true
}
func (OverloadStartIEValue) rule() aper.SourceRule {
	return aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "OverloadStartIEs"}}
}
func (OverloadStartIEValue) reason(id s00.ProtocolIEID) aper.OpaqueReason {
	switch id {
	case s00.ProtocolIEID(101):
		return aper.UnknownSelector
	case s00.ProtocolIEID(154):
		return aper.UnknownSelector
	case s00.ProtocolIEID(161):
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

// AsOverloadResponse returns the selected OverloadResponse value of OverloadStartIEValue and reports whether that alternative is active.
func (v *OverloadStartIEValue) AsOverloadResponse() (*s20.OverloadResponse, bool) {
	if v == nil || v.id != s00.ProtocolIEID(101) || v.rowOverloadResponse == nil {
		return nil, false
	}
	return v.rowOverloadResponse, true
}

// AsGUMMEIList returns the selected GUMMEIList value of OverloadStartIEValue and reports whether that alternative is active.
func (v *OverloadStartIEValue) AsGUMMEIList() (*s18.GUMMEIList, bool) {
	if v == nil || v.id != s00.ProtocolIEID(154) || v.rowGUMMEIList == nil {
		return nil, false
	}
	return v.rowGUMMEIList, true
}

// AsTrafficLoadReductionIndication returns the selected TrafficLoadReductionIndication value of OverloadStartIEValue and reports whether that alternative is active.
func (v *OverloadStartIEValue) AsTrafficLoadReductionIndication() (*s00.TrafficLoadReductionIndication, bool) {
	if v == nil || v.id != s00.ProtocolIEID(161) || v.rowTrafficLoadReductionIndication == nil {
		return nil, false
	}
	return v.rowTrafficLoadReductionIndication, true
}
func (v OverloadStartIEValue) decode(id s00.ProtocolIEID, raw aper.OpaqueOpenType) (OverloadStartIEValue, error) {
	out := OverloadStartIEValue{id: id}
	switch id {
	case s00.ProtocolIEID(101):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		var value s20.OverloadResponse
		child := scope
		if err := s20.BridgeOverloadResponseMethodUnmarshalAPERFrom(&value, child); err != nil {
			return out, fmt.Errorf("%s %w", "OverloadResponse:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "OverloadResponse")
		if err != nil {
			return out, err
		}
		*s20.BridgeOverloadResponseFieldPerPadding(&value) = padding.Padding()
		*s20.BridgeOverloadResponseFieldReceived(&value) = true
		raw.RetainContents(s20.BridgeOverloadResponseFieldReceivedBytes(&value))
		*s20.BridgeOverloadResponseFieldReceivedLocation(&value) = raw.ContentLocation()
		out.rowOverloadResponse = &value
		raw.RetainContents(&out.received)
	case s00.ProtocolIEID(154):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		child := scope
		list, err := BridgeUnmarshalAPERGUMMEIListFrom(child)
		if err != nil {
			return out, fmt.Errorf("%s %w", "GUMMEIList:", err)
		}
		padding, err := aper.CaptureOpenTypePadding(child)
		if err != nil {
			return out, err
		}
		_ = padding
		value := list
		out.rowGUMMEIList = &value
		raw.RetainContents(&out.received)
	case s00.ProtocolIEID(161):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		bb := scope
		decoded, err := aper.DecodeIntegerAligned(bb, s07.BridgeInt64Ptr(1), s07.BridgeInt64Ptr(99), false)
		value := s00.TrafficLoadReductionIndication(decoded)
		if err != nil {
			return out, fmt.Errorf("%s %w", "TrafficLoadReductionIndication:", err)
		}
		if _, err := aper.CompleteOpenTypeValue(bb, value); err != nil {
			return out, err
		}
		out.rowTrafficLoadReductionIndication = &value
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
func (v OverloadStartIEValue) encode() ([]byte, error) { return v.encodeFresh(false, nil) }
func (v OverloadStartIEValue) encodeFresh(fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
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
	case s00.ProtocolIEID(101):
		if v.rowOverloadResponse == nil {
			return nil, fmt.Errorf("%s missing value", "OverloadStartIEs.id-OverloadResponse:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		candidate, err := s20.BridgeOverloadResponseMethodMarshalAPERBudget(v.rowOverloadResponse, budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	case s00.ProtocolIEID(154):
		if v.rowGUMMEIList == nil {
			return nil, fmt.Errorf("%s missing value", "OverloadStartIEs.id-GUMMEIList:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		complete := GUMMEIListComplete{Value: *v.rowGUMMEIList}
		candidate, err := complete.marshalAPERBudget(budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	case s00.ProtocolIEID(161):
		if v.rowTrafficLoadReductionIndication == nil {
			return nil, fmt.Errorf("%s missing value", "OverloadStartIEs.id-TrafficLoadReductionIndication:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		encodeBB := aper.NewBudgetBuffer(budget)
		if err := aper.EncodeIntegerAligned(encodeBB, int64(*v.rowTrafficLoadReductionIndication), s07.BridgeInt64Ptr(1), s07.BridgeInt64Ptr(99), false); err != nil {
			return nil, err
		}
		candidate := encodeBB.CompleteBytes()
		return candidate, nil
	default:
		return nil, fmt.Errorf("%s id %d has no value", "OverloadStartIEValue:", v.id)
	}
}

type OverloadStopIEValue struct {
	id            s00.ProtocolIEID
	received      aper.WireSpan
	replay        aper.Snapshot
	opaque        aper.OpaqueOpenType
	isOpaque      bool
	rowGUMMEIList *s18.GUMMEIList
}

func (v OverloadStopIEValue) matchesID(id s00.ProtocolIEID, _ ...*aper.DecodeBudget) bool {
	if v.id != id {
		return false
	}
	if v.isOpaque {
		return true
	}
	switch id {
	case s00.ProtocolIEID(154):
		return v.rowGUMMEIList != nil
	}
	return false
}

// Opaque returns the retained opaque open value of OverloadStopIEValue and reports whether the opaque alternative is selected.
func (v *OverloadStopIEValue) Opaque() (aper.OpaqueOpenType, bool) {
	if v == nil || !v.isOpaque {
		return aper.OpaqueOpenType{}, false
	}
	return v.opaque, true
}
func (OverloadStopIEValue) rule() aper.SourceRule {
	return aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "OverloadStopIEs"}}
}
func (OverloadStopIEValue) reason(id s00.ProtocolIEID) aper.OpaqueReason {
	switch id {
	case s00.ProtocolIEID(154):
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

// AsGUMMEIList returns the selected GUMMEIList value of OverloadStopIEValue and reports whether that alternative is active.
func (v *OverloadStopIEValue) AsGUMMEIList() (*s18.GUMMEIList, bool) {
	if v == nil || v.id != s00.ProtocolIEID(154) || v.rowGUMMEIList == nil {
		return nil, false
	}
	return v.rowGUMMEIList, true
}
func (v OverloadStopIEValue) decode(id s00.ProtocolIEID, raw aper.OpaqueOpenType) (OverloadStopIEValue, error) {
	out := OverloadStopIEValue{id: id}
	switch id {
	case s00.ProtocolIEID(154):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		child := scope
		list, err := BridgeUnmarshalAPERGUMMEIListFrom(child)
		if err != nil {
			return out, fmt.Errorf("%s %w", "GUMMEIList:", err)
		}
		padding, err := aper.CaptureOpenTypePadding(child)
		if err != nil {
			return out, err
		}
		_ = padding
		value := list
		out.rowGUMMEIList = &value
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
func (v OverloadStopIEValue) encode() ([]byte, error) { return v.encodeFresh(false, nil) }
func (v OverloadStopIEValue) encodeFresh(fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
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
	case s00.ProtocolIEID(154):
		if v.rowGUMMEIList == nil {
			return nil, fmt.Errorf("%s missing value", "OverloadStopIEs.id-GUMMEIList:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		complete := GUMMEIListComplete{Value: *v.rowGUMMEIList}
		candidate, err := complete.marshalAPERBudget(budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	default:
		return nil, fmt.Errorf("%s id %d has no value", "OverloadStopIEValue:", v.id)
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

// Opaque returns the retained opaque open value of PWSFailureIndicationIEValue and reports whether the opaque alternative is selected.
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

// AsPWSfailedECGIList returns the selected PWSfailedECGIList value of PWSFailureIndicationIEValue and reports whether that alternative is active.
func (v *PWSFailureIndicationIEValue) AsPWSfailedECGIList() (*s20.PWSfailedECGIList, bool) {
	if v == nil || v.id != s00.ProtocolIEID(222) || v.rowPWSfailedECGIList == nil {
		return nil, false
	}
	return v.rowPWSfailedECGIList, true
}

// AsGlobalENBID returns the selected GlobalENBID value of PWSFailureIndicationIEValue and reports whether that alternative is active.
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

type LastVisitedEUTRANCellInformationExtIETable struct{}

func LastVisitedEUTRANCellInformationExtIEs() LastVisitedEUTRANCellInformationExtIETable {
	return LastVisitedEUTRANCellInformationExtIETable{}
}

// ID returns the ASN.1 object-set identity of LastVisitedEUTRANCellInformationExtIETable.
func (LastVisitedEUTRANCellInformationExtIETable) ID() s00.TableID {
	return func() s00.TableID {
		sealed := s00.TableID{}
		*s00.BridgeTableIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "LastVisitedEUTRANCellInformation-ExtIEs"}
		return sealed
	}()
}

// Table returns the ASN.1 object-set table described by LastVisitedEUTRANCellInformationExtIETable.
func (LastVisitedEUTRANCellInformationExtIETable) Table() s00.LastVisitedEUTRANCellInformationExtIEsValueExtensionTable {
	return func() s00.LastVisitedEUTRANCellInformationExtIEsValueExtensionTable {
		sealed := s00.LastVisitedEUTRANCellInformationExtIEsValueExtensionTable{}
		*s00.BridgeLastVisitedEUTRANCellInformationExtIEsValueExtensionTableFieldBound(&sealed) = true
		return sealed
	}()
}
func (LastVisitedEUTRANCellInformationExtIETable) infoTimeUEStayedInCellEnhancedGranularity() s00.ExtensionInfo {
	return s00.ExtensionInfo{Table: LastVisitedEUTRANCellInformationExtIEs().ID(), ID: s00.ProtocolExtensionID(167), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "Time-UE-StayedInCell-EnhancedGranularity"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.4", Assignment: aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "LastVisitedEUTRANCellInformation-ExtIEs", Row: "id-Time-UE-StayedInCell-EnhancedGranularity"}}}
}

// TimeUEStayedInCellEnhancedGranularity returns the typed binding for the TimeUEStayedInCellEnhancedGranularity row of LastVisitedEUTRANCellInformationExtIETable.
func (t LastVisitedEUTRANCellInformationExtIETable) TimeUEStayedInCellEnhancedGranularity() LastVisitedEUTRANCellInformationExtIEsTimeUEStayedInCellEnhancedGranularityExtBinding {
	return LastVisitedEUTRANCellInformationExtIEsTimeUEStayedInCellEnhancedGranularityExtBinding{info: t.infoTimeUEStayedInCellEnhancedGranularity(), codec: func() s02.TimeUEStayedInCellEnhancedGranularityValueCodec {
		sealed := s02.TimeUEStayedInCellEnhancedGranularityValueCodec{}
		*s02.BridgeTimeUEStayedInCellEnhancedGranularityValueCodecFieldPath(&sealed) = "TimeUEStayedInCellEnhancedGranularity"
		*s02.BridgeTimeUEStayedInCellEnhancedGranularityValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.TimeUEStayedInCellEnhancedGranularity, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s00.TimeUEStayedInCellEnhancedGranularity
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("TimeUEStayedInCellEnhancedGranularity")
			var zero LastVisitedEUTRANCellInformationExtIEsValue
			decoded, err := zero.decode(s00.ProtocolIEID(167), raw)
			if err != nil {
				var empty s00.TimeUEStayedInCellEnhancedGranularity
				return empty, runtime.WrapDecodePath(err, "TimeUEStayedInCellEnhancedGranularity")
			}
			value, ok := decoded.AsTimeUEStayedInCellEnhancedGranularity()
			if !ok {
				var empty s00.TimeUEStayedInCellEnhancedGranularity
				return empty, fmt.Errorf("binding LastVisitedEUTRANCellInformation-ExtIEs.id-Time-UE-StayedInCell-EnhancedGranularity: no selected value")
			}
			return *value, nil
		}
		*s02.BridgeTimeUEStayedInCellEnhancedGranularityValueCodecFieldEncode(&sealed) = func(value s00.TimeUEStayedInCellEnhancedGranularity, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (LastVisitedEUTRANCellInformationExtIEsValue{id: s00.ProtocolIEID(167), rowTimeUEStayedInCellEnhancedGranularity: &value}).encodeFresh(fresh, budget)
		}
		*s02.BridgeTimeUEStayedInCellEnhancedGranularityValueCodecFieldCapture(&sealed) = func(v s00.TimeUEStayedInCellEnhancedGranularity, options aper.DecodeState) (s00.TimeUEStayedInCellEnhancedGranularity, aper.Snapshot,

		) {
			s := aper.SemanticCaptureFor(options)
			f :=
				s.Begin()
			s00.BridgeCaptureS1APTimeUEStayedInCellEnhancedGranularity(
				&v,

				&s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s02.BridgeTimeUEStayedInCellEnhancedGranularityValueCodecFieldCompare(&sealed) = func(v s00.TimeUEStayedInCellEnhancedGranularity, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s07.BridgeCompareS1APTimeUEStayedInCellEnhancedGranularity(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s02.BridgeTimeUEStayedInCellEnhancedGranularityValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:TimeUEStayedInCellEnhancedGranularity"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s00.TimeUEStayedInCellEnhancedGranularity) LastVisitedEUTRANCellInformationExtIEsValue {
			return LastVisitedEUTRANCellInformationExtIEsValue{id: s00.ProtocolIEID(167), rowTimeUEStayedInCellEnhancedGranularity: &value}
		}, get: func(value *LastVisitedEUTRANCellInformationExtIEsValue) (*s00.TimeUEStayedInCellEnhancedGranularity, bool) {
			return value.AsTimeUEStayedInCellEnhancedGranularity()
		}}
}
func (LastVisitedEUTRANCellInformationExtIETable) infoHOCause() s00.ExtensionInfo {
	return s00.ExtensionInfo{Table: LastVisitedEUTRANCellInformationExtIEs().ID(), ID: s00.ProtocolExtensionID(168), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "Cause"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.4", Assignment: aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "LastVisitedEUTRANCellInformation-ExtIEs", Row: "id-HO-Cause"}}}
}

// HOCause returns the typed binding for the HOCause row of LastVisitedEUTRANCellInformationExtIETable.
func (t LastVisitedEUTRANCellInformationExtIETable) HOCause() LastVisitedEUTRANCellInformationExtIEsCauseExtBinding {
	return LastVisitedEUTRANCellInformationExtIEsCauseExtBinding{info: t.infoHOCause(), codec: func() s14.CauseValueCodec {
		sealed := s14.CauseValueCodec{}
		*s14.BridgeCauseValueCodecFieldPath(&sealed) = "Cause"
		*s14.BridgeCauseValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s14.Cause, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s14.Cause
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("Cause")
			var zero LastVisitedEUTRANCellInformationExtIEsValue
			decoded, err := zero.decode(s00.ProtocolIEID(168), raw)
			if err != nil {
				var empty s14.Cause
				return empty, runtime.WrapDecodePath(err, "Cause")
			}
			value, ok := decoded.AsHOCause()
			if !ok {
				var empty s14.Cause
				return empty, fmt.Errorf("binding LastVisitedEUTRANCellInformation-ExtIEs.id-HO-Cause: no selected value")
			}
			return *value, nil
		}
		*s14.BridgeCauseValueCodecFieldEncode(&sealed) = func(value s14.Cause, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (LastVisitedEUTRANCellInformationExtIEsValue{id: s00.ProtocolIEID(168), rowHOCause: &value}).encodeFresh(fresh, budget)
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
		inject: func(value s14.Cause) LastVisitedEUTRANCellInformationExtIEsValue {
			return LastVisitedEUTRANCellInformationExtIEsValue{id: s00.ProtocolIEID(168), rowHOCause: &value}
		}, get: func(value *LastVisitedEUTRANCellInformationExtIEsValue) (*s14.Cause, bool) { return value.AsHOCause() }}
}
func (LastVisitedEUTRANCellInformationExtIETable) infoLastVisitedPSCellList() s00.ExtensionInfo {
	return s00.ExtensionInfo{Table: LastVisitedEUTRANCellInformationExtIEs().ID(), ID: s00.ProtocolExtensionID(329), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "LastVisitedPSCellList"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.4", Assignment: aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "LastVisitedEUTRANCellInformation-ExtIEs", Row: "id-lastVisitedPSCellList"}}}
}

// LastVisitedPSCellList returns the typed binding for the LastVisitedPSCellList row of LastVisitedEUTRANCellInformationExtIETable.
func (t LastVisitedEUTRANCellInformationExtIETable) LastVisitedPSCellList() LastVisitedEUTRANCellInformationExtIEsLastVisitedPSCellListExtBinding {
	return LastVisitedEUTRANCellInformationExtIEsLastVisitedPSCellListExtBinding{info: t.infoLastVisitedPSCellList(), codec: func() s20.LastVisitedPSCellListValueCodec {
		sealed := s20.LastVisitedPSCellListValueCodec{}
		*s20.BridgeLastVisitedPSCellListValueCodecFieldPath(&sealed) = "LastVisitedPSCellList"
		*s20.BridgeLastVisitedPSCellListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s20.LastVisitedPSCellList, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s20.LastVisitedPSCellList
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("LastVisitedPSCellList")
			var zero LastVisitedEUTRANCellInformationExtIEsValue
			decoded, err := zero.decode(s00.ProtocolIEID(329), raw)
			if err != nil {
				var empty s20.LastVisitedPSCellList
				return empty, runtime.WrapDecodePath(err, "LastVisitedPSCellList")
			}
			value, ok := decoded.AsLastVisitedPSCellList()
			if !ok {
				var empty s20.LastVisitedPSCellList
				return empty, fmt.Errorf("binding LastVisitedEUTRANCellInformation-ExtIEs.id-lastVisitedPSCellList: no selected value")
			}
			return *value, nil
		}
		*s20.BridgeLastVisitedPSCellListValueCodecFieldEncode(&sealed) = func(value s20.LastVisitedPSCellList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (LastVisitedEUTRANCellInformationExtIEsValue{id: s00.ProtocolIEID(329), rowLastVisitedPSCellList: &value}).encodeFresh(fresh, budget)
		}
		*s20.BridgeLastVisitedPSCellListValueCodecFieldCapture(&sealed) = func(v s20.LastVisitedPSCellList, options aper.DecodeState) (s20.LastVisitedPSCellList, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s21.BridgeCaptureS1APLastVisitedPSCellList(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)

			return v, root
		}
		*s20.BridgeLastVisitedPSCellListValueCodecFieldCompare(&sealed) = func(v s20.LastVisitedPSCellList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s24.BridgeCompareS1APLastVisitedPSCellList(&v, &s)
			s.End(f, root, false)

			return s.Plan(), s.BudgetValue()
		}
		*s20.BridgeLastVisitedPSCellListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:LastVisitedPSCellList"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s20.LastVisitedPSCellList) LastVisitedEUTRANCellInformationExtIEsValue {
			return LastVisitedEUTRANCellInformationExtIEsValue{id: s00.ProtocolIEID(329), rowLastVisitedPSCellList: &value}
		}, get: func(value *LastVisitedEUTRANCellInformationExtIEsValue) (*s20.LastVisitedPSCellList, bool) {
			return value.AsLastVisitedPSCellList()
		}}
}

// NewOpaque constructs an owned opaque field for an identifier without a typed row in LastVisitedEUTRANCellInformationExtIETable.
func (t LastVisitedEUTRANCellInformationExtIETable) NewOpaque(id s00.ProtocolExtensionID, criticality s00.Criticality, data []byte) (LastVisitedEUTRANCellInformationExtIEsExtField, error) {
	if id < 0 || id > 65535 || criticality < 0 || criticality > 2 {
		return LastVisitedEUTRANCellInformationExtIEsExtField{}, aper.OperationError(fmt.Errorf("invalid opaque extension selector or criticality"), "Opaque")
	}
	switch id {
	case s00.ProtocolIEID(167):
		return LastVisitedEUTRANCellInformationExtIEsExtField{}, aper.OperationError(fmt.Errorf("known extension id-Time-UE-StayedInCell-EnhancedGranularity requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(168):
		return LastVisitedEUTRANCellInformationExtIEsExtField{}, aper.OperationError(fmt.Errorf("known extension id-HO-Cause requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(329):
		return LastVisitedEUTRANCellInformationExtIEsExtField{}, aper.OperationError(fmt.Errorf("known extension id-lastVisitedPSCellList requires its typed binding"), "Opaque")
	default:
		budget, err := aper.BuildBudget()
		if err != nil {
			return LastVisitedEUTRANCellInformationExtIEsExtField{}, aper.OperationError(err, "Opaque")
		}
		opaque, err := aper.BuildOpaqueOpenType(data, budget)
		if err != nil {
			return LastVisitedEUTRANCellInformationExtIEsExtField{}, aper.OperationError(err, "Opaque")
		}
		return LastVisitedEUTRANCellInformationExtIEsExtField{Id: id, Criticality: criticality, ExtensionValue: LastVisitedEUTRANCellInformationExtIEsValue{id: id, opaque: opaque, isOpaque: true}}, aper.OperationError(nil, "Opaque")
	}
}

type MDTConfigurationExtIETable struct{}

func MDTConfigurationExtIEs() MDTConfigurationExtIETable { return MDTConfigurationExtIETable{} }

// ID returns the ASN.1 object-set identity of MDTConfigurationExtIETable.
func (MDTConfigurationExtIETable) ID() s00.TableID {
	return func() s00.TableID {
		sealed := s00.TableID{}
		*s00.BridgeTableIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "MDT-Configuration-ExtIEs"}
		return sealed
	}()
}

// Table returns the ASN.1 object-set table described by MDTConfigurationExtIETable.
func (MDTConfigurationExtIETable) Table() s00.MDTConfigurationExtIEsValueExtensionTable {
	return func() s00.MDTConfigurationExtIEsValueExtensionTable {
		sealed := s00.MDTConfigurationExtIEsValueExtensionTable{}
		*s00.BridgeMDTConfigurationExtIEsValueExtensionTableFieldBound(&sealed) = true
		return sealed
	}()
}
func (MDTConfigurationExtIETable) infoSignallingBasedMDTPLMNList() s00.ExtensionInfo {
	return s00.ExtensionInfo{Table: MDTConfigurationExtIEs().ID(), ID: s00.ProtocolExtensionID(178), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "MDTPLMNList"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.4", Assignment: aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "MDT-Configuration-ExtIEs", Row: "id-SignallingBasedMDTPLMNList"}}}
}

// SignallingBasedMDTPLMNList returns the typed binding for the SignallingBasedMDTPLMNList row of MDTConfigurationExtIETable.
func (t MDTConfigurationExtIETable) SignallingBasedMDTPLMNList() MDTConfigurationExtIEsMDTPLMNListExtBinding {
	return MDTConfigurationExtIEsMDTPLMNListExtBinding{info: t.infoSignallingBasedMDTPLMNList(), codec: func() s01.MDTPLMNListValueCodec {
		sealed := s01.MDTPLMNListValueCodec{}
		*s01.BridgeMDTPLMNListValueCodecFieldPath(&sealed) = "MDTPLMNList"
		*s01.BridgeMDTPLMNListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.MDTPLMNList, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s00.MDTPLMNList
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("MDTPLMNList")
			var zero MDTConfigurationExtIEsValue
			decoded, err := zero.decode(s00.ProtocolIEID(178), raw)
			if err != nil {
				var empty s00.MDTPLMNList
				return empty, runtime.WrapDecodePath(err, "MDTPLMNList")
			}
			value, ok := decoded.AsSignallingBasedMDTPLMNList()
			if !ok {
				var empty s00.MDTPLMNList
				return empty, fmt.Errorf("binding MDT-Configuration-ExtIEs.id-SignallingBasedMDTPLMNList: no selected value")
			}
			return *value, nil
		}
		*s01.BridgeMDTPLMNListValueCodecFieldEncode(&sealed) = func(value s00.MDTPLMNList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (MDTConfigurationExtIEsValue{id: s00.ProtocolIEID(178), rowSignallingBasedMDTPLMNList: &value}).encodeFresh(fresh, budget)
		}
		*s01.BridgeMDTPLMNListValueCodecFieldCapture(&sealed) = func(v s00.MDTPLMNList, options aper.DecodeState) (s00.MDTPLMNList, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s00.BridgeCaptureS1APMDTPLMNList(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s01.BridgeMDTPLMNListValueCodecFieldCompare(&sealed) = func(v s00.MDTPLMNList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s07.BridgeCompareS1APMDTPLMNList(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.
				BudgetValue()
		}
		*s01.BridgeMDTPLMNListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:MDTPLMNList"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s00.MDTPLMNList) MDTConfigurationExtIEsValue {
			return MDTConfigurationExtIEsValue{id: s00.ProtocolIEID(178), rowSignallingBasedMDTPLMNList: &value}
		}, get: func(value *MDTConfigurationExtIEsValue) (*s00.MDTPLMNList, bool) {
			return value.AsSignallingBasedMDTPLMNList()
		}}
}

// NewOpaque constructs an owned opaque field for an identifier without a typed row in MDTConfigurationExtIETable.
func (t MDTConfigurationExtIETable) NewOpaque(id s00.ProtocolExtensionID, criticality s00.Criticality, data []byte) (MDTConfigurationExtIEsExtField, error) {
	if id < 0 || id > 65535 || criticality < 0 || criticality > 2 {
		return MDTConfigurationExtIEsExtField{}, aper.OperationError(fmt.Errorf("invalid opaque extension selector or criticality"), "Opaque")
	}
	switch id {
	case s00.ProtocolIEID(178):
		return MDTConfigurationExtIEsExtField{}, aper.OperationError(fmt.Errorf("known extension id-SignallingBasedMDTPLMNList requires its typed binding"), "Opaque")
	default:
		budget, err := aper.BuildBudget()
		if err != nil {
			return MDTConfigurationExtIEsExtField{}, aper.OperationError(err, "Opaque")
		}
		opaque, err := aper.BuildOpaqueOpenType(data, budget)
		if err != nil {
			return MDTConfigurationExtIEsExtField{}, aper.OperationError(err, "Opaque")
		}
		return MDTConfigurationExtIEsExtField{Id: id, Criticality: criticality, ExtensionValue: MDTConfigurationExtIEsValue{id: id, opaque: opaque, isOpaque: true}}, aper.OperationError(nil, "Opaque")
	}
}

type OverloadStartIETable struct{}

func OverloadStartIEs() OverloadStartIETable { return OverloadStartIETable{} }

// ID returns the ASN.1 object-set identity of OverloadStartIETable.
func (OverloadStartIETable) ID() s00.TableID {
	return func() s00.TableID {
		sealed := s00.TableID{}
		*s00.BridgeTableIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "OverloadStartIEs"}
		return sealed
	}()
}

// Table returns the ASN.1 object-set table described by OverloadStartIETable.
func (OverloadStartIETable) Table() s00.OverloadStartIEValueIETable {
	return func() s00.OverloadStartIEValueIETable {
		sealed := s00.OverloadStartIEValueIETable{}
		*s00.BridgeOverloadStartIEValueIETableFieldBound(&sealed) = true
		return sealed
	}()
}
func (OverloadStartIETable) infoOverloadResponse() s00.FieldInfo {
	return s00.FieldInfo{Table: OverloadStartIEs().ID(), ID: s00.ProtocolIEID(101), Criticality: s00.CriticalityReject, Presence: s00.PresenceMandatory, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "OverloadResponse"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "OverloadStartIEs", Row: "id-OverloadResponse"}}}
}

// OverloadResponse returns the typed binding for the OverloadResponse row of OverloadStartIETable.
func (t OverloadStartIETable) OverloadResponse() OverloadStartOverloadResponseIEBinding {
	return OverloadStartOverloadResponseIEBinding{info: t.infoOverloadResponse(), codec: func() s20.OverloadResponseValueCodec {
		sealed := s20.OverloadResponseValueCodec{}
		*s20.BridgeOverloadResponseValueCodecFieldPath(&sealed) = "OverloadResponse"
		*s20.BridgeOverloadResponseValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s20.OverloadResponse, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s20.OverloadResponse
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("OverloadResponse")
			var zero OverloadStartIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(101), raw)
			if err != nil {
				var empty s20.OverloadResponse
				return empty, runtime.WrapDecodePath(err, "OverloadResponse")
			}
			value, ok := decoded.AsOverloadResponse()
			if !ok {
				var empty s20.OverloadResponse
				return empty, fmt.Errorf("binding OverloadStartIEs.id-OverloadResponse: no selected value")
			}
			return *value, nil
		}
		*s20.BridgeOverloadResponseValueCodecFieldEncode(&sealed) = func(value s20.OverloadResponse, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (OverloadStartIEValue{id: s00.ProtocolIEID(101), rowOverloadResponse: &value}).encodeFresh(fresh, budget)
		}
		*s20.BridgeOverloadResponseValueCodecFieldCapture(&sealed) = func(v s20.OverloadResponse, options aper.DecodeState) (s20.OverloadResponse, aper.Snapshot) {
			s := aper.SemanticCaptureFor(
				options)
			f := s.Begin()
			s20.BridgeCaptureS1APOverloadResponse(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s20.BridgeOverloadResponseValueCodecFieldCompare(&sealed) = func(v s20.OverloadResponse, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s20.BridgeCompareS1APOverloadResponse(&v, &s)
			s.End(f, root, false)
			return s.
				Plan(), s.BudgetValue()
		}
		*s20.BridgeOverloadResponseValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:OverloadResponse"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s20.OverloadResponse) OverloadStartIEValue {
			return OverloadStartIEValue{id: s00.ProtocolIEID(101), rowOverloadResponse: &value}
		}, get: func(value *OverloadStartIEValue) (*s20.OverloadResponse, bool) { return value.AsOverloadResponse() }}
}
func (OverloadStartIETable) infoGUMMEIList() s00.FieldInfo {
	return s00.FieldInfo{Table: OverloadStartIEs().ID(), ID: s00.ProtocolIEID(154), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "GUMMEIList"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "OverloadStartIEs", Row: "id-GUMMEIList"}}}
}

// GUMMEIList returns the typed binding for the GUMMEIList row of OverloadStartIETable.
func (t OverloadStartIETable) GUMMEIList() OverloadStartGUMMEIListIEBinding {
	return OverloadStartGUMMEIListIEBinding{info: t.infoGUMMEIList(), codec: func() s18.GUMMEIListValueCodec {
		sealed := s18.GUMMEIListValueCodec{}
		*s18.BridgeGUMMEIListValueCodecFieldPath(&sealed) = "GUMMEIList"
		*s18.BridgeGUMMEIListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s18.GUMMEIList, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s18.GUMMEIList
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("GUMMEIList")
			var zero OverloadStartIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(154), raw)
			if err != nil {
				var empty s18.GUMMEIList
				return empty, runtime.WrapDecodePath(err, "GUMMEIList")
			}
			value, ok := decoded.AsGUMMEIList()
			if !ok {
				var empty s18.GUMMEIList
				return empty, fmt.Errorf("binding OverloadStartIEs.id-GUMMEIList: no selected value")
			}
			return *value, nil
		}
		*s18.BridgeGUMMEIListValueCodecFieldEncode(&sealed) = func(value s18.GUMMEIList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (OverloadStartIEValue{id: s00.ProtocolIEID(154), rowGUMMEIList: &value}).encodeFresh(fresh, budget)
		}
		*s18.BridgeGUMMEIListValueCodecFieldCapture(&sealed) = func(v s18.GUMMEIList, options aper.DecodeState) (s18.GUMMEIList, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f :=
				s.Begin()
			s21.BridgeCaptureS1APGUMMEIList(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s18.BridgeGUMMEIListValueCodecFieldCompare(&sealed) = func(v s18.GUMMEIList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s24.BridgeCompareS1APGUMMEIList(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s18.BridgeGUMMEIListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:GUMMEIList"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s18.GUMMEIList) OverloadStartIEValue {
			return OverloadStartIEValue{id: s00.ProtocolIEID(154), rowGUMMEIList: &value}
		}, get: func(value *OverloadStartIEValue) (*s18.GUMMEIList, bool) { return value.AsGUMMEIList() }}
}
func (OverloadStartIETable) infoTrafficLoadReductionIndication() s00.FieldInfo {
	return s00.FieldInfo{Table: OverloadStartIEs().ID(), ID: s00.ProtocolIEID(161), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "TrafficLoadReductionIndication"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "OverloadStartIEs", Row: "id-TrafficLoadReductionIndication"}}}
}

// TrafficLoadReductionIndication returns the typed binding for the TrafficLoadReductionIndication row of OverloadStartIETable.
func (t OverloadStartIETable) TrafficLoadReductionIndication() OverloadStartTrafficLoadReductionIndicationIEBinding {
	return OverloadStartTrafficLoadReductionIndicationIEBinding{info: t.infoTrafficLoadReductionIndication(), codec: func() s02.TrafficLoadReductionIndicationValueCodec {
		sealed := s02.TrafficLoadReductionIndicationValueCodec{}
		*s02.BridgeTrafficLoadReductionIndicationValueCodecFieldPath(&sealed) = "TrafficLoadReductionIndication"
		*s02.BridgeTrafficLoadReductionIndicationValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.TrafficLoadReductionIndication, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s00.TrafficLoadReductionIndication
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("TrafficLoadReductionIndication")
			var zero OverloadStartIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(161), raw)
			if err != nil {
				var empty s00.TrafficLoadReductionIndication
				return empty, runtime.WrapDecodePath(err, "TrafficLoadReductionIndication")
			}
			value, ok := decoded.AsTrafficLoadReductionIndication()
			if !ok {
				var empty s00.TrafficLoadReductionIndication
				return empty, fmt.Errorf("binding OverloadStartIEs.id-TrafficLoadReductionIndication: no selected value")
			}
			return *value, nil
		}
		*s02.BridgeTrafficLoadReductionIndicationValueCodecFieldEncode(&sealed) = func(value s00.TrafficLoadReductionIndication, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (OverloadStartIEValue{id: s00.ProtocolIEID(161), rowTrafficLoadReductionIndication: &value}).encodeFresh(fresh, budget)
		}
		*s02.BridgeTrafficLoadReductionIndicationValueCodecFieldCapture(&sealed) = func(v s00.TrafficLoadReductionIndication, options aper.DecodeState) (s00.TrafficLoadReductionIndication, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s00.BridgeCaptureS1APTrafficLoadReductionIndication(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s02.BridgeTrafficLoadReductionIndicationValueCodecFieldCompare(&sealed) = func(v s00.TrafficLoadReductionIndication, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f :=
				s.Begin()
			s07.BridgeCompareS1APTrafficLoadReductionIndication(&v, &s)
			s.
				End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s02.BridgeTrafficLoadReductionIndicationValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:TrafficLoadReductionIndication"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s00.TrafficLoadReductionIndication) OverloadStartIEValue {
			return OverloadStartIEValue{id: s00.ProtocolIEID(161), rowTrafficLoadReductionIndication: &value}
		}, get: func(value *OverloadStartIEValue) (*s00.TrafficLoadReductionIndication, bool) {
			return value.AsTrafficLoadReductionIndication()
		}}
}

// NewOpaque constructs an owned opaque field for an identifier without a typed row in OverloadStartIETable.
func (t OverloadStartIETable) NewOpaque(id s00.ProtocolIEID, criticality s00.Criticality, data []byte) (OverloadStartIEField, error) {
	if id < 0 || id > 65535 || criticality < 0 || criticality > 2 {
		return OverloadStartIEField{}, aper.OperationError(fmt.Errorf("invalid opaque IE selector or criticality"), "Opaque")
	}
	switch id {
	case s00.ProtocolIEID(101):
		return OverloadStartIEField{}, aper.OperationError(fmt.Errorf("known IE id-OverloadResponse requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(154):
		return OverloadStartIEField{}, aper.OperationError(fmt.Errorf("known IE id-GUMMEIList requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(161):
		return OverloadStartIEField{}, aper.OperationError(fmt.Errorf("known IE id-TrafficLoadReductionIndication requires its typed binding"), "Opaque")
	default:
		budget, err := aper.BuildBudget()
		if err != nil {
			return OverloadStartIEField{}, aper.OperationError(err, "Opaque")
		}
		opaque, err := aper.BuildOpaqueOpenType(data, budget)
		if err != nil {
			return OverloadStartIEField{}, aper.OperationError(err, "Opaque")
		}
		return OverloadStartIEField{Id: id, Criticality: criticality, Value: OverloadStartIEValue{id: id, opaque: opaque, isOpaque: true}}, aper.OperationError(nil, "Opaque")
	}
}

type OverloadStopIETable struct{}

func OverloadStopIEs() OverloadStopIETable { return OverloadStopIETable{} }

// ID returns the ASN.1 object-set identity of OverloadStopIETable.
func (OverloadStopIETable) ID() s00.TableID {
	return func() s00.TableID {
		sealed := s00.TableID{}
		*s00.BridgeTableIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "OverloadStopIEs"}
		return sealed
	}()
}

// Table returns the ASN.1 object-set table described by OverloadStopIETable.
func (OverloadStopIETable) Table() s00.OverloadStopIEValueIETable {
	return func() s00.OverloadStopIEValueIETable {
		sealed := s00.OverloadStopIEValueIETable{}
		*s00.BridgeOverloadStopIEValueIETableFieldBound(&sealed) = true
		return sealed
	}()
}
func (OverloadStopIETable) infoGUMMEIList() s00.FieldInfo {
	return s00.FieldInfo{Table: OverloadStopIEs().ID(), ID: s00.ProtocolIEID(154), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "GUMMEIList"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "OverloadStopIEs", Row: "id-GUMMEIList"}}}
}

// GUMMEIList returns the typed binding for the GUMMEIList row of OverloadStopIETable.
func (t OverloadStopIETable) GUMMEIList() OverloadStopGUMMEIListIEBinding {
	return OverloadStopGUMMEIListIEBinding{info: t.infoGUMMEIList(), codec: func() s18.GUMMEIListValueCodec {
		sealed := s18.GUMMEIListValueCodec{}
		*s18.BridgeGUMMEIListValueCodecFieldPath(&sealed) = "GUMMEIList"
		*s18.BridgeGUMMEIListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s18.GUMMEIList, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s18.GUMMEIList
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("GUMMEIList")
			var zero OverloadStopIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(154), raw)
			if err != nil {
				var empty s18.GUMMEIList
				return empty, runtime.WrapDecodePath(err, "GUMMEIList")
			}
			value, ok := decoded.AsGUMMEIList()
			if !ok {
				var empty s18.GUMMEIList
				return empty, fmt.Errorf("binding OverloadStopIEs.id-GUMMEIList: no selected value")
			}
			return *value, nil
		}
		*s18.BridgeGUMMEIListValueCodecFieldEncode(&sealed) = func(value s18.GUMMEIList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (OverloadStopIEValue{id: s00.ProtocolIEID(154), rowGUMMEIList: &value}).encodeFresh(fresh, budget)
		}
		*s18.BridgeGUMMEIListValueCodecFieldCapture(&sealed) = func(v s18.GUMMEIList, options aper.DecodeState) (s18.GUMMEIList, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f :=
				s.Begin()
			s21.BridgeCaptureS1APGUMMEIList(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s18.BridgeGUMMEIListValueCodecFieldCompare(&sealed) = func(v s18.GUMMEIList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s24.BridgeCompareS1APGUMMEIList(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s18.BridgeGUMMEIListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:GUMMEIList"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s18.GUMMEIList) OverloadStopIEValue {
			return OverloadStopIEValue{id: s00.ProtocolIEID(154), rowGUMMEIList: &value}
		}, get: func(value *OverloadStopIEValue) (*s18.GUMMEIList, bool) { return value.AsGUMMEIList() }}
}

// NewOpaque constructs an owned opaque field for an identifier without a typed row in OverloadStopIETable.
func (t OverloadStopIETable) NewOpaque(id s00.ProtocolIEID, criticality s00.Criticality, data []byte) (OverloadStopIEField, error) {
	if id < 0 || id > 65535 || criticality < 0 || criticality > 2 {
		return OverloadStopIEField{}, aper.OperationError(fmt.Errorf("invalid opaque IE selector or criticality"), "Opaque")
	}
	switch id {
	case s00.ProtocolIEID(154):
		return OverloadStopIEField{}, aper.OperationError(fmt.Errorf("known IE id-GUMMEIList requires its typed binding"), "Opaque")
	default:
		budget, err := aper.BuildBudget()
		if err != nil {
			return OverloadStopIEField{}, aper.OperationError(err, "Opaque")
		}
		opaque, err := aper.BuildOpaqueOpenType(data, budget)
		if err != nil {
			return OverloadStopIEField{}, aper.OperationError(err, "Opaque")
		}
		return OverloadStopIEField{Id: id, Criticality: criticality, Value: OverloadStopIEValue{id: id, opaque: opaque, isOpaque: true}}, aper.OperationError(nil, "Opaque")
	}
}

// CauseCodec binds the complete APER value type.
func CauseCodec() s14.CauseValueCodec {
	return LastVisitedEUTRANCellInformationExtIEs().HOCause().Codec()
}

// ERABUsageReportListCodec binds the complete source value type.
func ERABUsageReportListCodec() s17.ERABUsageReportListValueCodec {
	return func() s17.ERABUsageReportListValueCodec {
		sealed := s17.ERABUsageReportListValueCodec{}
		*s17.BridgeERABUsageReportListValueCodecFieldPath(&sealed) = "ERABUsageReportList"
		*s17.BridgeERABUsageReportListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s17.ERABUsageReportList, error) {
			var complete ERABUsageReportListComplete
			if err := complete.unmarshalAPERWithOptions(data, options); err != nil {
				var zero s17.ERABUsageReportList
				return zero, err
			}
			return complete.Value, nil
		}
		*s17.BridgeERABUsageReportListValueCodecFieldEncode(&sealed) = func(value s17.ERABUsageReportList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			complete := ERABUsageReportListComplete{Value: value}
			return complete.marshalAPERBudget(budget, fresh)
		}
		*s17.BridgeERABUsageReportListValueCodecFieldCapture(&sealed) = func(v s17.ERABUsageReportList, options aper.DecodeState) (s17.ERABUsageReportList, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s25.BridgeCaptureS1APERABUsageReportList(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s17.BridgeERABUsageReportListValueCodecFieldCompare(&sealed) = func(v s17.ERABUsageReportList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s25.BridgeCompareS1APERABUsageReportList(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s17.BridgeERABUsageReportListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ERABUsageReportList"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// EmergencyAreaIDBroadcastCodec binds the complete source value type.
func EmergencyAreaIDBroadcastCodec() s22.EmergencyAreaIDBroadcastValueCodec {
	return func() s22.EmergencyAreaIDBroadcastValueCodec {
		sealed := s22.EmergencyAreaIDBroadcastValueCodec{}
		*s22.BridgeEmergencyAreaIDBroadcastValueCodecFieldPath(&sealed) = "EmergencyAreaIDBroadcast"
		*s22.BridgeEmergencyAreaIDBroadcastValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s22.EmergencyAreaIDBroadcast, error) {
			var complete EmergencyAreaIDBroadcastComplete
			if err := complete.unmarshalAPERWithOptions(data, options); err != nil {
				var zero s22.EmergencyAreaIDBroadcast
				return zero, err
			}
			return complete.Value, nil
		}
		*s22.BridgeEmergencyAreaIDBroadcastValueCodecFieldEncode(&sealed) = func(value s22.EmergencyAreaIDBroadcast, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			complete := EmergencyAreaIDBroadcastComplete{Value: value}
			return complete.marshalAPERBudget(budget, fresh)
		}
		*s22.BridgeEmergencyAreaIDBroadcastValueCodecFieldCapture(&sealed) = func(v s22.EmergencyAreaIDBroadcast, options aper.DecodeState) (s22.EmergencyAreaIDBroadcast, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s22.BridgeCaptureS1APEmergencyAreaIDBroadcast(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,

				false)
			return v, root
		}
		*s22.BridgeEmergencyAreaIDBroadcastValueCodecFieldCompare(&sealed) = func(v s22.EmergencyAreaIDBroadcast, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s24.BridgeCompareS1APEmergencyAreaIDBroadcast(&v, &s)
			s.End(f, root,

				false,
			)
			return s.Plan(), s.BudgetValue()
		}
		*s22.BridgeEmergencyAreaIDBroadcastValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:EmergencyAreaIDBroadcast"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// EmergencyAreaIDCancelledCodec binds the complete source value type.
func EmergencyAreaIDCancelledCodec() s22.EmergencyAreaIDCancelledValueCodec {
	return func() s22.EmergencyAreaIDCancelledValueCodec {
		sealed := s22.EmergencyAreaIDCancelledValueCodec{}
		*s22.BridgeEmergencyAreaIDCancelledValueCodecFieldPath(&sealed) = "EmergencyAreaIDCancelled"
		*s22.BridgeEmergencyAreaIDCancelledValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s22.EmergencyAreaIDCancelled, error) {
			var complete EmergencyAreaIDCancelledComplete
			if err := complete.unmarshalAPERWithOptions(data, options); err != nil {
				var zero s22.EmergencyAreaIDCancelled
				return zero, err
			}
			return complete.Value, nil
		}
		*s22.BridgeEmergencyAreaIDCancelledValueCodecFieldEncode(&sealed) = func(value s22.EmergencyAreaIDCancelled, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			complete := EmergencyAreaIDCancelledComplete{Value: value}
			return complete.marshalAPERBudget(budget, fresh)
		}
		*s22.BridgeEmergencyAreaIDCancelledValueCodecFieldCapture(&sealed) = func(v s22.EmergencyAreaIDCancelled, options aper.DecodeState) (s22.EmergencyAreaIDCancelled, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s22.BridgeCaptureS1APEmergencyAreaIDCancelled(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,

				false)
			return v, root
		}
		*s22.BridgeEmergencyAreaIDCancelledValueCodecFieldCompare(&sealed) = func(v s22.EmergencyAreaIDCancelled, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s24.BridgeCompareS1APEmergencyAreaIDCancelled(&v, &s)
			s.End(f, root,

				false,
			)
			return s.Plan(), s.BudgetValue()
		}
		*s22.BridgeEmergencyAreaIDCancelledValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:EmergencyAreaIDCancelled"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// EmergencyAreaIDListCodec binds the complete source value type.
func EmergencyAreaIDListCodec() s00.EmergencyAreaIDListValueCodec {
	return func() s00.EmergencyAreaIDListValueCodec {
		sealed := s00.EmergencyAreaIDListValueCodec{}
		*s00.BridgeEmergencyAreaIDListValueCodecFieldPath(&sealed) = "EmergencyAreaIDList"
		*s00.BridgeEmergencyAreaIDListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.EmergencyAreaIDList, error) {
			var complete EmergencyAreaIDListComplete
			if err := complete.unmarshalAPERWithOptions(data, options); err != nil {
				var zero s00.EmergencyAreaIDList
				return zero, err
			}
			return complete.Value, nil
		}
		*s00.BridgeEmergencyAreaIDListValueCodecFieldEncode(&sealed) = func(value s00.EmergencyAreaIDList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			complete := EmergencyAreaIDListComplete{Value: value}
			return complete.marshalAPERBudget(budget, fresh)
		}
		*s00.BridgeEmergencyAreaIDListValueCodecFieldCapture(&sealed) = func(v s00.EmergencyAreaIDList, options aper.DecodeState) (s00.EmergencyAreaIDList, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s00.BridgeCaptureS1APEmergencyAreaIDList(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s00.BridgeEmergencyAreaIDListValueCodecFieldCompare(&sealed) = func(v s00.EmergencyAreaIDList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s02.BridgeCompareS1APEmergencyAreaIDList(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s00.BridgeEmergencyAreaIDListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:EmergencyAreaIDList"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// ForbiddenLACsCodec binds the complete source value type.
func ForbiddenLACsCodec() s00.ForbiddenLACsValueCodec {
	return func() s00.ForbiddenLACsValueCodec {
		sealed := s00.ForbiddenLACsValueCodec{}
		*s00.BridgeForbiddenLACsValueCodecFieldPath(&sealed) = "ForbiddenLACs"
		*s00.BridgeForbiddenLACsValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.ForbiddenLACs, error) {
			var complete ForbiddenLACsComplete
			if err := complete.unmarshalAPERWithOptions(data, options); err != nil {
				var zero s00.ForbiddenLACs
				return zero, err
			}
			return complete.Value, nil
		}
		*s00.BridgeForbiddenLACsValueCodecFieldEncode(&sealed) = func(value s00.ForbiddenLACs, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			complete := ForbiddenLACsComplete{Value: value}
			return complete.marshalAPERBudget(budget, fresh)
		}
		*s00.BridgeForbiddenLACsValueCodecFieldCapture(&sealed) = func(v s00.ForbiddenLACs, options aper.DecodeState) (s00.ForbiddenLACs, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s00.BridgeCaptureS1APForbiddenLACs(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s00.BridgeForbiddenLACsValueCodecFieldCompare(&sealed) = func(v s00.ForbiddenLACs, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s02.BridgeCompareS1APForbiddenLACs(&v, &s)
			s.End(f, root, false)
			return s.Plan(),

				s.BudgetValue()
		}
		*s00.BridgeForbiddenLACsValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ForbiddenLACs"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// ForbiddenLAsCodec binds the complete source value type.
func ForbiddenLAsCodec() s18.ForbiddenLAsValueCodec {
	return func() s18.ForbiddenLAsValueCodec {
		sealed := s18.ForbiddenLAsValueCodec{}
		*s18.BridgeForbiddenLAsValueCodecFieldPath(&sealed) = "ForbiddenLAs"
		*s18.BridgeForbiddenLAsValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s18.ForbiddenLAs, error) {
			var complete ForbiddenLAsComplete
			if err := complete.unmarshalAPERWithOptions(data, options); err != nil {
				var zero s18.ForbiddenLAs
				return zero, err
			}
			return complete.Value, nil
		}
		*s18.BridgeForbiddenLAsValueCodecFieldEncode(&sealed) = func(value s18.ForbiddenLAs, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			complete := ForbiddenLAsComplete{Value: value}
			return complete.marshalAPERBudget(budget, fresh)
		}
		*s18.BridgeForbiddenLAsValueCodecFieldCapture(&sealed) = func(v s18.ForbiddenLAs, options aper.DecodeState) (s18.ForbiddenLAs, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s21.BridgeCaptureS1APForbiddenLAs(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s18.BridgeForbiddenLAsValueCodecFieldCompare(&sealed) = func(v s18.ForbiddenLAs, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s24.BridgeCompareS1APForbiddenLAs(&v, &s)
			s.End(f, root, false)
			return s.Plan(),
				s.
					BudgetValue()
		}
		*s18.BridgeForbiddenLAsValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ForbiddenLAs"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// ForbiddenTACsCodec binds the complete source value type.
func ForbiddenTACsCodec() s00.ForbiddenTACsValueCodec {
	return func() s00.ForbiddenTACsValueCodec {
		sealed := s00.ForbiddenTACsValueCodec{}
		*s00.BridgeForbiddenTACsValueCodecFieldPath(&sealed) = "ForbiddenTACs"
		*s00.BridgeForbiddenTACsValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.ForbiddenTACs, error) {
			var complete ForbiddenTACsComplete
			if err := complete.unmarshalAPERWithOptions(data, options); err != nil {
				var zero s00.ForbiddenTACs
				return zero, err
			}
			return complete.Value, nil
		}
		*s00.BridgeForbiddenTACsValueCodecFieldEncode(&sealed) = func(value s00.ForbiddenTACs, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			complete := ForbiddenTACsComplete{Value: value}
			return complete.marshalAPERBudget(budget, fresh)
		}
		*s00.BridgeForbiddenTACsValueCodecFieldCapture(&sealed) = func(v s00.ForbiddenTACs, options aper.DecodeState) (s00.ForbiddenTACs, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s00.BridgeCaptureS1APForbiddenTACs(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s00.BridgeForbiddenTACsValueCodecFieldCompare(&sealed) = func(v s00.ForbiddenTACs, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s07.BridgeCompareS1APForbiddenTACs(&v, &s)
			s.End(f, root, false)
			return s.Plan(),

				s.BudgetValue()
		}
		*s00.BridgeForbiddenTACsValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ForbiddenTACs"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// ForbiddenTAsCodec binds the complete source value type.
func ForbiddenTAsCodec() s18.ForbiddenTAsValueCodec {
	return func() s18.ForbiddenTAsValueCodec {
		sealed := s18.ForbiddenTAsValueCodec{}
		*s18.BridgeForbiddenTAsValueCodecFieldPath(&sealed) = "ForbiddenTAs"
		*s18.BridgeForbiddenTAsValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s18.ForbiddenTAs, error) {
			var complete ForbiddenTAsComplete
			if err := complete.unmarshalAPERWithOptions(data, options); err != nil {
				var zero s18.ForbiddenTAs
				return zero, err
			}
			return complete.Value, nil
		}
		*s18.BridgeForbiddenTAsValueCodecFieldEncode(&sealed) = func(value s18.ForbiddenTAs, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			complete := ForbiddenTAsComplete{Value: value}
			return complete.marshalAPERBudget(budget, fresh)
		}
		*s18.BridgeForbiddenTAsValueCodecFieldCapture(&sealed) = func(v s18.ForbiddenTAs, options aper.DecodeState) (s18.ForbiddenTAs, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s21.BridgeCaptureS1APForbiddenTAs(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s18.BridgeForbiddenTAsValueCodecFieldCompare(&sealed) = func(v s18.ForbiddenTAs, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s24.BridgeCompareS1APForbiddenTAs(&v, &s)
			s.End(f, root, false)
			return s.Plan(),
				s.
					BudgetValue()
		}
		*s18.BridgeForbiddenTAsValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ForbiddenTAs"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// GUMMEIListCodec binds the complete APER value type.
func GUMMEIListCodec() s18.GUMMEIListValueCodec { return OverloadStartIEs().GUMMEIList().Codec() }

// IEsECGIListCodec binds the complete source value type.
func IEsECGIListCodec() s18.IEsECGIListValueCodec {
	return func() s18.IEsECGIListValueCodec {
		sealed := s18.IEsECGIListValueCodec{}
		*s18.BridgeIEsECGIListValueCodecFieldPath(&sealed) = "IEsECGIList"
		*s18.BridgeIEsECGIListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s18.IEsECGIList, error) {
			var complete IEsECGIListComplete
			if err := complete.unmarshalAPERWithOptions(data, options); err != nil {
				var zero s18.IEsECGIList
				return zero, err
			}
			return complete.Value, nil
		}
		*s18.BridgeIEsECGIListValueCodecFieldEncode(&sealed) = func(value s18.IEsECGIList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			complete := IEsECGIListComplete{Value: value}
			return complete.marshalAPERBudget(budget, fresh)
		}
		*s18.BridgeIEsECGIListValueCodecFieldCapture(&sealed) = func(v s18.IEsECGIList, options aper.DecodeState) (s18.IEsECGIList, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s21.BridgeCaptureS1APIEsECGIList(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s18.BridgeIEsECGIListValueCodecFieldCompare(&sealed) = func(v s18.IEsECGIList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s24.BridgeCompareS1APIEsECGIList(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.
				BudgetValue()
		}
		*s18.BridgeIEsECGIListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:IEsECGIList"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// InterSystemMeasurementListCodec binds the complete source value type.
func InterSystemMeasurementListCodec() s18.InterSystemMeasurementListValueCodec {
	return func() s18.InterSystemMeasurementListValueCodec {
		sealed := s18.InterSystemMeasurementListValueCodec{}
		*s18.BridgeInterSystemMeasurementListValueCodecFieldPath(&sealed) = "InterSystemMeasurementList"
		*s18.BridgeInterSystemMeasurementListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s18.InterSystemMeasurementList, error) {
			var complete InterSystemMeasurementListComplete
			if err := complete.unmarshalAPERWithOptions(data, options); err != nil {
				var zero s18.InterSystemMeasurementList
				return zero, err
			}
			return complete.Value, nil
		}
		*s18.BridgeInterSystemMeasurementListValueCodecFieldEncode(&sealed) = func(value s18.InterSystemMeasurementList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			complete := InterSystemMeasurementListComplete{Value: value}
			return complete.marshalAPERBudget(budget, fresh)
		}
		*s18.BridgeInterSystemMeasurementListValueCodecFieldCapture(&sealed) = func(v s18.InterSystemMeasurementList, options aper.DecodeState) (s18.InterSystemMeasurementList, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s21.BridgeCaptureS1APInterSystemMeasurementList(&v, &s)
			var root aper.Snapshot
			s.End(
				f, &root, false)
			return v, root
		}
		*s18.BridgeInterSystemMeasurementListValueCodecFieldCompare(&sealed) = func(v s18.InterSystemMeasurementList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s24.BridgeCompareS1APInterSystemMeasurementList(&v, &s)
			s.End(f,
				root,

				false)
			return s.Plan(), s.BudgetValue()
		}
		*s18.BridgeInterSystemMeasurementListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:InterSystemMeasurementList"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// LastVisitedCellItemCodec binds the complete source value type.
func LastVisitedCellItemCodec() LastVisitedCellItemValueCodec {
	return LastVisitedCellItemValueCodec{path: "LastVisitedCellItem", decode: func(data []byte, options aper.DecodeState) (LastVisitedCellItem, error) {
		var value LastVisitedCellItem
		if err := value.unmarshalAPERWithOptions(data, options); err != nil {
			return LastVisitedCellItem{}, err
		}
		value.received = true
		value.receivedAbsolute = true
		value.receivedBytes = aper.OriginalWire(data)
		return value, nil
	}, encode: func(value LastVisitedCellItem, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return (&value).marshalAPERBudget(budget, fresh)
	}, capture: func(v LastVisitedCellItem, options aper.DecodeState) (LastVisitedCellItem, aper.Snapshot,
	) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeCaptureS1APLastVisitedCellItem(&v, &s)
		var root aper.Snapshot
		s.End(f, &root, false)
		return v, root
	}, compare: func(v LastVisitedCellItem, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
	) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		BridgeCompareS1APLastVisitedCellItem(&v, &s)
		s.End(f, root, false)
		return s.Plan(), s.BudgetValue()
	}, context: func() s00.BridgeCodecContext {
		sealed := s00.BridgeCodecContext{}
		*s00.BridgecodecContextFieldSource(&sealed) = "source-value:LastVisitedCellItem"
		*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
		return sealed
	}(),
	}
}

// LastVisitedEUTRANCellInformationCodec binds the complete source value type.
func LastVisitedEUTRANCellInformationCodec() LastVisitedEUTRANCellInformationValueCodec {
	return LastVisitedEUTRANCellInformationValueCodec{path: "LastVisitedEUTRANCellInformation", decode: func(data []byte, options aper.DecodeState) (LastVisitedEUTRANCellInformation, error) {
		var value LastVisitedEUTRANCellInformation
		if err := value.unmarshalAPERWithOptions(data, options); err != nil {
			return LastVisitedEUTRANCellInformation{}, err
		}
		value.received = true
		value.receivedAbsolute = true
		value.receivedBytes = aper.OriginalWire(data)
		return value, nil
	}, encode: func(value LastVisitedEUTRANCellInformation, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return (&value).marshalAPERBudget(budget, fresh)
	}, capture: func(v LastVisitedEUTRANCellInformation, options aper.DecodeState) (LastVisitedEUTRANCellInformation, aper.Snapshot,
	) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeCaptureS1APLastVisitedEUTRANCellInformation(&v, &s)
		var root aper.Snapshot

		s.End(f, &root, false)
		return v, root
	}, compare: func(v LastVisitedEUTRANCellInformation, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
	) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		BridgeCompareS1APLastVisitedEUTRANCellInformation(&v,
			&s,
		)
		s.End(f, root, false)
		return s.Plan(), s.BudgetValue()
	}, context: func() s00.BridgeCodecContext {
		sealed := s00.BridgeCodecContext{}
		*s00.BridgecodecContextFieldSource(&sealed) = "source-value:LastVisitedEUTRANCellInformation"
		*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
		return sealed
	}(),
	}
}

// LastVisitedPSCellListCodec binds the complete APER value type.
func LastVisitedPSCellListCodec() s20.LastVisitedPSCellListValueCodec {
	return LastVisitedEUTRANCellInformationExtIEs().LastVisitedPSCellList().Codec()
}

// MBSFNResultToLogCodec binds the complete source value type.
func MBSFNResultToLogCodec() s19.MBSFNResultToLogValueCodec {
	return func() s19.MBSFNResultToLogValueCodec {
		sealed := s19.MBSFNResultToLogValueCodec{}
		*s19.BridgeMBSFNResultToLogValueCodecFieldPath(&sealed) = "MBSFNResultToLog"
		*s19.BridgeMBSFNResultToLogValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s19.MBSFNResultToLog, error) {
			var complete MBSFNResultToLogComplete
			if err := complete.unmarshalAPERWithOptions(data, options); err != nil {
				var zero s19.MBSFNResultToLog
				return zero, err
			}
			return complete.Value, nil
		}
		*s19.BridgeMBSFNResultToLogValueCodecFieldEncode(&sealed) = func(value s19.MBSFNResultToLog, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			complete := MBSFNResultToLogComplete{Value: value}
			return complete.marshalAPERBudget(budget, fresh)
		}
		*s19.BridgeMBSFNResultToLogValueCodecFieldCapture(&sealed) = func(v s19.MBSFNResultToLog, options aper.DecodeState) (s19.MBSFNResultToLog, aper.Snapshot) {
			s := aper.SemanticCaptureFor(
				options)
			f := s.Begin()
			s21.BridgeCaptureS1APMBSFNResultToLog(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s19.BridgeMBSFNResultToLogValueCodecFieldCompare(&sealed) = func(v s19.MBSFNResultToLog, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s24.BridgeCompareS1APMBSFNResultToLog(&v, &s)
			s.End(f, root, false)
			return s.
				Plan(), s.BudgetValue()
		}
		*s19.BridgeMBSFNResultToLogValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:MBSFNResultToLog"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// MDTPLMNListCodec binds the complete APER value type.
func MDTPLMNListCodec() s01.MDTPLMNListValueCodec {
	return MDTConfigurationExtIEs().SignallingBasedMDTPLMNList().Codec()
}

// MultiCellLoadReportingResponseCodec binds the complete source value type.
func MultiCellLoadReportingResponseCodec() s19.MultiCellLoadReportingResponseValueCodec {
	return func() s19.MultiCellLoadReportingResponseValueCodec {
		sealed := s19.MultiCellLoadReportingResponseValueCodec{}
		*s19.BridgeMultiCellLoadReportingResponseValueCodecFieldPath(&sealed) = "MultiCellLoadReportingResponse"
		*s19.BridgeMultiCellLoadReportingResponseValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s19.MultiCellLoadReportingResponse, error) {
			var complete MultiCellLoadReportingResponseComplete
			if err := complete.unmarshalAPERWithOptions(data, options); err != nil {
				var zero s19.MultiCellLoadReportingResponse
				return zero, err
			}
			return complete.Value, nil
		}
		*s19.BridgeMultiCellLoadReportingResponseValueCodecFieldEncode(&sealed) = func(value s19.MultiCellLoadReportingResponse, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			complete := MultiCellLoadReportingResponseComplete{Value: value}
			return complete.marshalAPERBudget(budget, fresh)
		}
		*s19.BridgeMultiCellLoadReportingResponseValueCodecFieldCapture(&sealed) = func(v s19.MultiCellLoadReportingResponse, options aper.DecodeState) (s19.MultiCellLoadReportingResponse, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s21.BridgeCaptureS1APMultiCellLoadReportingResponse(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s19.BridgeMultiCellLoadReportingResponseValueCodecFieldCompare(&sealed) = func(v s19.MultiCellLoadReportingResponse, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f :=
				s.Begin()
			s24.BridgeCompareS1APMultiCellLoadReportingResponse(&v, &s)
			s.
				End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s19.BridgeMultiCellLoadReportingResponseValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:MultiCellLoadReportingResponse"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// NotificationCellListCodec binds the complete source value type.
func NotificationCellListCodec() s20.NotificationCellListValueCodec {
	return func() s20.NotificationCellListValueCodec {
		sealed := s20.NotificationCellListValueCodec{}
		*s20.BridgeNotificationCellListValueCodecFieldPath(&sealed) = "NotificationCellList"
		*s20.BridgeNotificationCellListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s20.NotificationCellList, error) {
			var complete NotificationCellListComplete
			if err := complete.unmarshalAPERWithOptions(data, options); err != nil {
				var zero s20.NotificationCellList
				return zero, err
			}
			return complete.Value, nil
		}
		*s20.BridgeNotificationCellListValueCodecFieldEncode(&sealed) = func(value s20.NotificationCellList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			complete := NotificationCellListComplete{Value: value}
			return complete.marshalAPERBudget(budget, fresh)
		}
		*s20.BridgeNotificationCellListValueCodecFieldCapture(&sealed) = func(v s20.NotificationCellList, options aper.DecodeState) (s20.NotificationCellList, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s21.BridgeCaptureS1APNotificationCellList(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s20.BridgeNotificationCellListValueCodecFieldCompare(&sealed) = func(v s20.NotificationCellList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s24.BridgeCompareS1APNotificationCellList(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s20.BridgeNotificationCellListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:NotificationCellList"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// OverloadResponseCodec binds the complete APER value type.
func OverloadResponseCodec() s20.OverloadResponseValueCodec {
	return OverloadStartIEs().OverloadResponse().Codec()
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

// SourceeNBToTargeteNBTransparentContainerCodec binds the complete source value type.
func SourceeNBToTargeteNBTransparentContainerCodec() SourceeNBToTargeteNBTransparentContainerValueCodec {
	return SourceeNBToTargeteNBTransparentContainerValueCodec{path: "SourceeNBToTargeteNBTransparentContainer", decode: func(data []byte, options aper.DecodeState) (SourceeNBToTargeteNBTransparentContainer, error) {
		var value SourceeNBToTargeteNBTransparentContainer
		if err := value.unmarshalAPERWithOptions(data, options); err != nil {
			return SourceeNBToTargeteNBTransparentContainer{}, err
		}
		value.received = true
		value.receivedAbsolute = true
		value.receivedBytes = aper.OriginalWire(data)
		return value, nil
	}, encode: func(value SourceeNBToTargeteNBTransparentContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return (&value).marshalAPERBudget(budget, fresh)
	}, capture: func(v SourceeNBToTargeteNBTransparentContainer, options aper.DecodeState) (SourceeNBToTargeteNBTransparentContainer, aper.Snapshot) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeCaptureS1APSourceeNBToTargeteNBTransparentContainer(&v, &s)
		var root aper.Snapshot
		s.End(f, &root, false)
		return v, root
	}, compare: func(v SourceeNBToTargeteNBTransparentContainer, root aper.Snapshot, budget aper.DecodeBudget,
	) (aper.ReplayPlan, aper.DecodeBudget,

	) {
		s := aper.NewSemanticComparison(root,
			budget)
		f := s.Begin()
		BridgeCompareS1APSourceeNBToTargeteNBTransparentContainer(&v, &s)
		s.End(f, root, false)
		return s.Plan(),
			s.BudgetValue()
	}, context: func() s00.BridgeCodecContext {
		sealed := s00.BridgeCodecContext{}
		*s00.BridgecodecContextFieldSource(&sealed) = "source-value:SourceeNBToTargeteNBTransparentContainer"
		*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
		return sealed
	}(),
	}
}

// TimeUEStayedInCellEnhancedGranularityCodec binds the complete APER value type.
func TimeUEStayedInCellEnhancedGranularityCodec() s02.TimeUEStayedInCellEnhancedGranularityValueCodec {
	return LastVisitedEUTRANCellInformationExtIEs().TimeUEStayedInCellEnhancedGranularity().Codec()
}

// TrafficLoadReductionIndicationCodec binds the complete APER value type.
func TrafficLoadReductionIndicationCodec() s02.TrafficLoadReductionIndicationValueCodec {
	return OverloadStartIEs().TrafficLoadReductionIndication().Codec()
}
func BridgeERABToBeSwitchedULListCompleteFieldPerPadding(v *ERABToBeSwitchedULListComplete) *aper.CompletePadding {
	return &v.perPadding
}
func BridgeERABToBeSwitchedULListCompleteFieldReceived(v *ERABToBeSwitchedULListComplete) *bool {
	return &v.received
}
func BridgeERABToBeSwitchedULListCompleteFieldReceivedAbsolute(v *ERABToBeSwitchedULListComplete) *bool {
	return &v.receivedAbsolute
}
func BridgeERABToBeSwitchedULListCompleteFieldReceivedBytes(v *ERABToBeSwitchedULListComplete) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeERABToBeSwitchedULListCompleteFieldReceivedLocation(v *ERABToBeSwitchedULListComplete) *aper.Location {
	return &v.receivedLocation
}
func BridgeERABToBeSwitchedULListCompleteFieldReplay(v *ERABToBeSwitchedULListComplete) *aper.Snapshot {
	return &v.replay
}
func BridgeERABToBeSwitchedULListCompleteFieldStream(v *ERABToBeSwitchedULListComplete) *aper.WireSpan {
	return &v.stream
}
func BridgeERABToBeSwitchedULListCompleteFieldWithoutReplay(v *ERABToBeSwitchedULListComplete) *bool {
	return &v.withoutReplay
}
func BridgeERABToBeSwitchedULListCompleteMethodMarshalAPERBudget(v *ERABToBeSwitchedULListComplete, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeERABToBeSwitchedULListCompleteMethodMarshalAPERBudgetValue(v *ERABToBeSwitchedULListComplete, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudgetValue(a0, a1)
}
func BridgeERABToBeSwitchedULListCompleteMethodMarshalAPERChanged(v *ERABToBeSwitchedULListComplete, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeERABToBeSwitchedULListCompleteMethodMarshalAPERChangedValue(v *ERABToBeSwitchedULListComplete, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeERABToBeSwitchedULListCompleteMethodMarshalAPERLegacy(v *ERABToBeSwitchedULListComplete) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeERABToBeSwitchedULListCompleteMethodMarshalAPERNewValue(v *ERABToBeSwitchedULListComplete, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERNewValue(a0, a1)
}
func BridgeERABToBeSwitchedULListCompleteMethodMarshalAPERPlanned(v *ERABToBeSwitchedULListComplete, a0 *aper.DecodeBudget, a1 bool, a2 *aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1, a2)
}
func BridgeERABToBeSwitchedULListCompleteMethodUnmarshalAPERLegacy(v *ERABToBeSwitchedULListComplete, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeERABToBeSwitchedULListCompleteMethodUnmarshalAPERWithOptions(v *ERABToBeSwitchedULListComplete, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeERABToBeUpdatedListCompleteFieldPerPadding(v *ERABToBeUpdatedListComplete) *aper.CompletePadding {
	return &v.perPadding
}
func BridgeERABToBeUpdatedListCompleteFieldReceived(v *ERABToBeUpdatedListComplete) *bool {
	return &v.received
}
func BridgeERABToBeUpdatedListCompleteFieldReceivedAbsolute(v *ERABToBeUpdatedListComplete) *bool {
	return &v.receivedAbsolute
}
func BridgeERABToBeUpdatedListCompleteFieldReceivedBytes(v *ERABToBeUpdatedListComplete) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeERABToBeUpdatedListCompleteFieldReceivedLocation(v *ERABToBeUpdatedListComplete) *aper.Location {
	return &v.receivedLocation
}
func BridgeERABToBeUpdatedListCompleteFieldReplay(v *ERABToBeUpdatedListComplete) *aper.Snapshot {
	return &v.replay
}
func BridgeERABToBeUpdatedListCompleteFieldStream(v *ERABToBeUpdatedListComplete) *aper.WireSpan {
	return &v.stream
}
func BridgeERABToBeUpdatedListCompleteFieldWithoutReplay(v *ERABToBeUpdatedListComplete) *bool {
	return &v.withoutReplay
}
func BridgeERABToBeUpdatedListCompleteMethodMarshalAPERBudget(v *ERABToBeUpdatedListComplete, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeERABToBeUpdatedListCompleteMethodMarshalAPERBudgetValue(v *ERABToBeUpdatedListComplete, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudgetValue(a0, a1)
}
func BridgeERABToBeUpdatedListCompleteMethodMarshalAPERChanged(v *ERABToBeUpdatedListComplete, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeERABToBeUpdatedListCompleteMethodMarshalAPERChangedValue(v *ERABToBeUpdatedListComplete, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeERABToBeUpdatedListCompleteMethodMarshalAPERLegacy(v *ERABToBeUpdatedListComplete) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeERABToBeUpdatedListCompleteMethodMarshalAPERNewValue(v *ERABToBeUpdatedListComplete, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERNewValue(a0, a1)
}
func BridgeERABToBeUpdatedListCompleteMethodMarshalAPERPlanned(v *ERABToBeUpdatedListComplete, a0 *aper.DecodeBudget, a1 bool, a2 *aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1, a2)
}
func BridgeERABToBeUpdatedListCompleteMethodUnmarshalAPERLegacy(v *ERABToBeUpdatedListComplete, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeERABToBeUpdatedListCompleteMethodUnmarshalAPERWithOptions(v *ERABToBeUpdatedListComplete, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeERABUsageReportListCompleteFieldPerPadding(v *ERABUsageReportListComplete) *aper.CompletePadding {
	return &v.perPadding
}
func BridgeERABUsageReportListCompleteFieldReceived(v *ERABUsageReportListComplete) *bool {
	return &v.received
}
func BridgeERABUsageReportListCompleteFieldReceivedAbsolute(v *ERABUsageReportListComplete) *bool {
	return &v.receivedAbsolute
}
func BridgeERABUsageReportListCompleteFieldReceivedBytes(v *ERABUsageReportListComplete) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeERABUsageReportListCompleteFieldReceivedLocation(v *ERABUsageReportListComplete) *aper.Location {
	return &v.receivedLocation
}
func BridgeERABUsageReportListCompleteFieldReplay(v *ERABUsageReportListComplete) *aper.Snapshot {
	return &v.replay
}
func BridgeERABUsageReportListCompleteFieldStream(v *ERABUsageReportListComplete) *aper.WireSpan {
	return &v.stream
}
func BridgeERABUsageReportListCompleteFieldWithoutReplay(v *ERABUsageReportListComplete) *bool {
	return &v.withoutReplay
}
func BridgeERABUsageReportListCompleteMethodMarshalAPERBudget(v *ERABUsageReportListComplete, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeERABUsageReportListCompleteMethodMarshalAPERBudgetValue(v *ERABUsageReportListComplete, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudgetValue(a0, a1)
}
func BridgeERABUsageReportListCompleteMethodMarshalAPERChanged(v *ERABUsageReportListComplete, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeERABUsageReportListCompleteMethodMarshalAPERChangedValue(v *ERABUsageReportListComplete, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeERABUsageReportListCompleteMethodMarshalAPERLegacy(v *ERABUsageReportListComplete) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeERABUsageReportListCompleteMethodMarshalAPERNewValue(v *ERABUsageReportListComplete, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERNewValue(a0, a1)
}
func BridgeERABUsageReportListCompleteMethodMarshalAPERPlanned(v *ERABUsageReportListComplete, a0 *aper.DecodeBudget, a1 bool, a2 *aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1, a2)
}
func BridgeERABUsageReportListCompleteMethodUnmarshalAPERLegacy(v *ERABUsageReportListComplete, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeERABUsageReportListCompleteMethodUnmarshalAPERWithOptions(v *ERABUsageReportListComplete, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeEmergencyAreaIDBroadcastCompleteFieldPerPadding(v *EmergencyAreaIDBroadcastComplete) *aper.CompletePadding {
	return &v.perPadding
}
func BridgeEmergencyAreaIDBroadcastCompleteFieldReceived(v *EmergencyAreaIDBroadcastComplete) *bool {
	return &v.received
}
func BridgeEmergencyAreaIDBroadcastCompleteFieldReceivedAbsolute(v *EmergencyAreaIDBroadcastComplete) *bool {
	return &v.receivedAbsolute
}
func BridgeEmergencyAreaIDBroadcastCompleteFieldReceivedBytes(v *EmergencyAreaIDBroadcastComplete) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeEmergencyAreaIDBroadcastCompleteFieldReceivedLocation(v *EmergencyAreaIDBroadcastComplete) *aper.Location {
	return &v.receivedLocation
}
func BridgeEmergencyAreaIDBroadcastCompleteFieldReplay(v *EmergencyAreaIDBroadcastComplete) *aper.Snapshot {
	return &v.replay
}
func BridgeEmergencyAreaIDBroadcastCompleteFieldStream(v *EmergencyAreaIDBroadcastComplete) *aper.WireSpan {
	return &v.stream
}
func BridgeEmergencyAreaIDBroadcastCompleteFieldWithoutReplay(v *EmergencyAreaIDBroadcastComplete) *bool {
	return &v.withoutReplay
}
func BridgeEmergencyAreaIDBroadcastCompleteMethodMarshalAPERBudget(v *EmergencyAreaIDBroadcastComplete, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeEmergencyAreaIDBroadcastCompleteMethodMarshalAPERBudgetValue(v *EmergencyAreaIDBroadcastComplete, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudgetValue(a0, a1)
}
func BridgeEmergencyAreaIDBroadcastCompleteMethodMarshalAPERChanged(v *EmergencyAreaIDBroadcastComplete, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeEmergencyAreaIDBroadcastCompleteMethodMarshalAPERChangedValue(v *EmergencyAreaIDBroadcastComplete, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeEmergencyAreaIDBroadcastCompleteMethodMarshalAPERLegacy(v *EmergencyAreaIDBroadcastComplete) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeEmergencyAreaIDBroadcastCompleteMethodMarshalAPERNewValue(v *EmergencyAreaIDBroadcastComplete, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERNewValue(a0, a1)
}
func BridgeEmergencyAreaIDBroadcastCompleteMethodMarshalAPERPlanned(v *EmergencyAreaIDBroadcastComplete, a0 *aper.DecodeBudget, a1 bool, a2 *aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1, a2)
}
func BridgeEmergencyAreaIDBroadcastCompleteMethodUnmarshalAPERLegacy(v *EmergencyAreaIDBroadcastComplete, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeEmergencyAreaIDBroadcastCompleteMethodUnmarshalAPERWithOptions(v *EmergencyAreaIDBroadcastComplete, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeEmergencyAreaIDCancelledCompleteFieldPerPadding(v *EmergencyAreaIDCancelledComplete) *aper.CompletePadding {
	return &v.perPadding
}
func BridgeEmergencyAreaIDCancelledCompleteFieldReceived(v *EmergencyAreaIDCancelledComplete) *bool {
	return &v.received
}
func BridgeEmergencyAreaIDCancelledCompleteFieldReceivedAbsolute(v *EmergencyAreaIDCancelledComplete) *bool {
	return &v.receivedAbsolute
}
func BridgeEmergencyAreaIDCancelledCompleteFieldReceivedBytes(v *EmergencyAreaIDCancelledComplete) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeEmergencyAreaIDCancelledCompleteFieldReceivedLocation(v *EmergencyAreaIDCancelledComplete) *aper.Location {
	return &v.receivedLocation
}
func BridgeEmergencyAreaIDCancelledCompleteFieldReplay(v *EmergencyAreaIDCancelledComplete) *aper.Snapshot {
	return &v.replay
}
func BridgeEmergencyAreaIDCancelledCompleteFieldStream(v *EmergencyAreaIDCancelledComplete) *aper.WireSpan {
	return &v.stream
}
func BridgeEmergencyAreaIDCancelledCompleteFieldWithoutReplay(v *EmergencyAreaIDCancelledComplete) *bool {
	return &v.withoutReplay
}
func BridgeEmergencyAreaIDCancelledCompleteMethodMarshalAPERBudget(v *EmergencyAreaIDCancelledComplete, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeEmergencyAreaIDCancelledCompleteMethodMarshalAPERBudgetValue(v *EmergencyAreaIDCancelledComplete, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudgetValue(a0, a1)
}
func BridgeEmergencyAreaIDCancelledCompleteMethodMarshalAPERChanged(v *EmergencyAreaIDCancelledComplete, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeEmergencyAreaIDCancelledCompleteMethodMarshalAPERChangedValue(v *EmergencyAreaIDCancelledComplete, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeEmergencyAreaIDCancelledCompleteMethodMarshalAPERLegacy(v *EmergencyAreaIDCancelledComplete) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeEmergencyAreaIDCancelledCompleteMethodMarshalAPERNewValue(v *EmergencyAreaIDCancelledComplete, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERNewValue(a0, a1)
}
func BridgeEmergencyAreaIDCancelledCompleteMethodMarshalAPERPlanned(v *EmergencyAreaIDCancelledComplete, a0 *aper.DecodeBudget, a1 bool, a2 *aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1, a2)
}
func BridgeEmergencyAreaIDCancelledCompleteMethodUnmarshalAPERLegacy(v *EmergencyAreaIDCancelledComplete, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeEmergencyAreaIDCancelledCompleteMethodUnmarshalAPERWithOptions(v *EmergencyAreaIDCancelledComplete, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeEmergencyAreaIDListCompleteFieldPerPadding(v *EmergencyAreaIDListComplete) *aper.CompletePadding {
	return &v.perPadding
}
func BridgeEmergencyAreaIDListCompleteFieldReceived(v *EmergencyAreaIDListComplete) *bool {
	return &v.received
}
func BridgeEmergencyAreaIDListCompleteFieldReceivedAbsolute(v *EmergencyAreaIDListComplete) *bool {
	return &v.receivedAbsolute
}
func BridgeEmergencyAreaIDListCompleteFieldReceivedBytes(v *EmergencyAreaIDListComplete) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeEmergencyAreaIDListCompleteFieldReceivedLocation(v *EmergencyAreaIDListComplete) *aper.Location {
	return &v.receivedLocation
}
func BridgeEmergencyAreaIDListCompleteFieldReplay(v *EmergencyAreaIDListComplete) *aper.Snapshot {
	return &v.replay
}
func BridgeEmergencyAreaIDListCompleteFieldStream(v *EmergencyAreaIDListComplete) *aper.WireSpan {
	return &v.stream
}
func BridgeEmergencyAreaIDListCompleteFieldWithoutReplay(v *EmergencyAreaIDListComplete) *bool {
	return &v.withoutReplay
}
func BridgeEmergencyAreaIDListCompleteMethodMarshalAPERBudget(v *EmergencyAreaIDListComplete, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeEmergencyAreaIDListCompleteMethodMarshalAPERBudgetValue(v *EmergencyAreaIDListComplete, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudgetValue(a0, a1)
}
func BridgeEmergencyAreaIDListCompleteMethodMarshalAPERChanged(v *EmergencyAreaIDListComplete, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeEmergencyAreaIDListCompleteMethodMarshalAPERChangedValue(v *EmergencyAreaIDListComplete, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeEmergencyAreaIDListCompleteMethodMarshalAPERLegacy(v *EmergencyAreaIDListComplete) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeEmergencyAreaIDListCompleteMethodMarshalAPERNewValue(v *EmergencyAreaIDListComplete, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERNewValue(a0, a1)
}
func BridgeEmergencyAreaIDListCompleteMethodMarshalAPERPlanned(v *EmergencyAreaIDListComplete, a0 *aper.DecodeBudget, a1 bool, a2 *aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1, a2)
}
func BridgeEmergencyAreaIDListCompleteMethodUnmarshalAPERLegacy(v *EmergencyAreaIDListComplete, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeEmergencyAreaIDListCompleteMethodUnmarshalAPERWithOptions(v *EmergencyAreaIDListComplete, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeEmergencyAreaIDListForRestartCompleteFieldPerPadding(v *EmergencyAreaIDListForRestartComplete) *aper.CompletePadding {
	return &v.perPadding
}
func BridgeEmergencyAreaIDListForRestartCompleteFieldReceived(v *EmergencyAreaIDListForRestartComplete) *bool {
	return &v.received
}
func BridgeEmergencyAreaIDListForRestartCompleteFieldReceivedAbsolute(v *EmergencyAreaIDListForRestartComplete) *bool {
	return &v.receivedAbsolute
}
func BridgeEmergencyAreaIDListForRestartCompleteFieldReceivedBytes(v *EmergencyAreaIDListForRestartComplete) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeEmergencyAreaIDListForRestartCompleteFieldReceivedLocation(v *EmergencyAreaIDListForRestartComplete) *aper.Location {
	return &v.receivedLocation
}
func BridgeEmergencyAreaIDListForRestartCompleteFieldReplay(v *EmergencyAreaIDListForRestartComplete) *aper.Snapshot {
	return &v.replay
}
func BridgeEmergencyAreaIDListForRestartCompleteFieldStream(v *EmergencyAreaIDListForRestartComplete) *aper.WireSpan {
	return &v.stream
}
func BridgeEmergencyAreaIDListForRestartCompleteFieldWithoutReplay(v *EmergencyAreaIDListForRestartComplete) *bool {
	return &v.withoutReplay
}
func BridgeEmergencyAreaIDListForRestartCompleteMethodMarshalAPERBudget(v *EmergencyAreaIDListForRestartComplete, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeEmergencyAreaIDListForRestartCompleteMethodMarshalAPERBudgetValue(v *EmergencyAreaIDListForRestartComplete, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudgetValue(a0, a1)
}
func BridgeEmergencyAreaIDListForRestartCompleteMethodMarshalAPERChanged(v *EmergencyAreaIDListForRestartComplete, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeEmergencyAreaIDListForRestartCompleteMethodMarshalAPERChangedValue(v *EmergencyAreaIDListForRestartComplete, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeEmergencyAreaIDListForRestartCompleteMethodMarshalAPERLegacy(v *EmergencyAreaIDListForRestartComplete) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeEmergencyAreaIDListForRestartCompleteMethodMarshalAPERNewValue(v *EmergencyAreaIDListForRestartComplete, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERNewValue(a0, a1)
}
func BridgeEmergencyAreaIDListForRestartCompleteMethodMarshalAPERPlanned(v *EmergencyAreaIDListForRestartComplete, a0 *aper.DecodeBudget, a1 bool, a2 *aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1, a2)
}
func BridgeEmergencyAreaIDListForRestartCompleteMethodUnmarshalAPERLegacy(v *EmergencyAreaIDListForRestartComplete, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeEmergencyAreaIDListForRestartCompleteMethodUnmarshalAPERWithOptions(v *EmergencyAreaIDListForRestartComplete, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeForbiddenLACsCompleteFieldPerPadding(v *ForbiddenLACsComplete) *aper.CompletePadding {
	return &v.perPadding
}
func BridgeForbiddenLACsCompleteFieldReceived(v *ForbiddenLACsComplete) *bool { return &v.received }
func BridgeForbiddenLACsCompleteFieldReceivedAbsolute(v *ForbiddenLACsComplete) *bool {
	return &v.receivedAbsolute
}
func BridgeForbiddenLACsCompleteFieldReceivedBytes(v *ForbiddenLACsComplete) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeForbiddenLACsCompleteFieldReceivedLocation(v *ForbiddenLACsComplete) *aper.Location {
	return &v.receivedLocation
}
func BridgeForbiddenLACsCompleteFieldReplay(v *ForbiddenLACsComplete) *aper.Snapshot {
	return &v.replay
}
func BridgeForbiddenLACsCompleteFieldStream(v *ForbiddenLACsComplete) *aper.WireSpan {
	return &v.stream
}
func BridgeForbiddenLACsCompleteFieldWithoutReplay(v *ForbiddenLACsComplete) *bool {
	return &v.withoutReplay
}
func BridgeForbiddenLACsCompleteMethodMarshalAPERBudget(v *ForbiddenLACsComplete, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeForbiddenLACsCompleteMethodMarshalAPERBudgetValue(v *ForbiddenLACsComplete, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudgetValue(a0, a1)
}
func BridgeForbiddenLACsCompleteMethodMarshalAPERChanged(v *ForbiddenLACsComplete, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeForbiddenLACsCompleteMethodMarshalAPERChangedValue(v *ForbiddenLACsComplete, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeForbiddenLACsCompleteMethodMarshalAPERLegacy(v *ForbiddenLACsComplete) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeForbiddenLACsCompleteMethodMarshalAPERNewValue(v *ForbiddenLACsComplete, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERNewValue(a0, a1)
}
func BridgeForbiddenLACsCompleteMethodMarshalAPERPlanned(v *ForbiddenLACsComplete, a0 *aper.DecodeBudget, a1 bool, a2 *aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1, a2)
}
func BridgeForbiddenLACsCompleteMethodUnmarshalAPERLegacy(v *ForbiddenLACsComplete, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeForbiddenLACsCompleteMethodUnmarshalAPERWithOptions(v *ForbiddenLACsComplete, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeForbiddenLAsCompleteFieldPerPadding(v *ForbiddenLAsComplete) *aper.CompletePadding {
	return &v.perPadding
}
func BridgeForbiddenLAsCompleteFieldReceived(v *ForbiddenLAsComplete) *bool { return &v.received }
func BridgeForbiddenLAsCompleteFieldReceivedAbsolute(v *ForbiddenLAsComplete) *bool {
	return &v.receivedAbsolute
}
func BridgeForbiddenLAsCompleteFieldReceivedBytes(v *ForbiddenLAsComplete) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeForbiddenLAsCompleteFieldReceivedLocation(v *ForbiddenLAsComplete) *aper.Location {
	return &v.receivedLocation
}
func BridgeForbiddenLAsCompleteFieldReplay(v *ForbiddenLAsComplete) *aper.Snapshot { return &v.replay }
func BridgeForbiddenLAsCompleteFieldStream(v *ForbiddenLAsComplete) *aper.WireSpan { return &v.stream }
func BridgeForbiddenLAsCompleteFieldWithoutReplay(v *ForbiddenLAsComplete) *bool {
	return &v.withoutReplay
}
func BridgeForbiddenLAsCompleteMethodMarshalAPERBudget(v *ForbiddenLAsComplete, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeForbiddenLAsCompleteMethodMarshalAPERBudgetValue(v *ForbiddenLAsComplete, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudgetValue(a0, a1)
}
func BridgeForbiddenLAsCompleteMethodMarshalAPERChanged(v *ForbiddenLAsComplete, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeForbiddenLAsCompleteMethodMarshalAPERChangedValue(v *ForbiddenLAsComplete, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeForbiddenLAsCompleteMethodMarshalAPERLegacy(v *ForbiddenLAsComplete) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeForbiddenLAsCompleteMethodMarshalAPERNewValue(v *ForbiddenLAsComplete, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERNewValue(a0, a1)
}
func BridgeForbiddenLAsCompleteMethodMarshalAPERPlanned(v *ForbiddenLAsComplete, a0 *aper.DecodeBudget, a1 bool, a2 *aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1, a2)
}
func BridgeForbiddenLAsCompleteMethodUnmarshalAPERLegacy(v *ForbiddenLAsComplete, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeForbiddenLAsCompleteMethodUnmarshalAPERWithOptions(v *ForbiddenLAsComplete, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeForbiddenTACsCompleteFieldPerPadding(v *ForbiddenTACsComplete) *aper.CompletePadding {
	return &v.perPadding
}
func BridgeForbiddenTACsCompleteFieldReceived(v *ForbiddenTACsComplete) *bool { return &v.received }
func BridgeForbiddenTACsCompleteFieldReceivedAbsolute(v *ForbiddenTACsComplete) *bool {
	return &v.receivedAbsolute
}
func BridgeForbiddenTACsCompleteFieldReceivedBytes(v *ForbiddenTACsComplete) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeForbiddenTACsCompleteFieldReceivedLocation(v *ForbiddenTACsComplete) *aper.Location {
	return &v.receivedLocation
}
func BridgeForbiddenTACsCompleteFieldReplay(v *ForbiddenTACsComplete) *aper.Snapshot {
	return &v.replay
}
func BridgeForbiddenTACsCompleteFieldStream(v *ForbiddenTACsComplete) *aper.WireSpan {
	return &v.stream
}
func BridgeForbiddenTACsCompleteFieldWithoutReplay(v *ForbiddenTACsComplete) *bool {
	return &v.withoutReplay
}
func BridgeForbiddenTACsCompleteMethodMarshalAPERBudget(v *ForbiddenTACsComplete, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeForbiddenTACsCompleteMethodMarshalAPERBudgetValue(v *ForbiddenTACsComplete, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudgetValue(a0, a1)
}
func BridgeForbiddenTACsCompleteMethodMarshalAPERChanged(v *ForbiddenTACsComplete, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeForbiddenTACsCompleteMethodMarshalAPERChangedValue(v *ForbiddenTACsComplete, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeForbiddenTACsCompleteMethodMarshalAPERLegacy(v *ForbiddenTACsComplete) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeForbiddenTACsCompleteMethodMarshalAPERNewValue(v *ForbiddenTACsComplete, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERNewValue(a0, a1)
}
func BridgeForbiddenTACsCompleteMethodMarshalAPERPlanned(v *ForbiddenTACsComplete, a0 *aper.DecodeBudget, a1 bool, a2 *aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1, a2)
}
func BridgeForbiddenTACsCompleteMethodUnmarshalAPERLegacy(v *ForbiddenTACsComplete, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeForbiddenTACsCompleteMethodUnmarshalAPERWithOptions(v *ForbiddenTACsComplete, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeForbiddenTAsCompleteFieldPerPadding(v *ForbiddenTAsComplete) *aper.CompletePadding {
	return &v.perPadding
}
func BridgeForbiddenTAsCompleteFieldReceived(v *ForbiddenTAsComplete) *bool { return &v.received }
func BridgeForbiddenTAsCompleteFieldReceivedAbsolute(v *ForbiddenTAsComplete) *bool {
	return &v.receivedAbsolute
}
func BridgeForbiddenTAsCompleteFieldReceivedBytes(v *ForbiddenTAsComplete) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeForbiddenTAsCompleteFieldReceivedLocation(v *ForbiddenTAsComplete) *aper.Location {
	return &v.receivedLocation
}
func BridgeForbiddenTAsCompleteFieldReplay(v *ForbiddenTAsComplete) *aper.Snapshot { return &v.replay }
func BridgeForbiddenTAsCompleteFieldStream(v *ForbiddenTAsComplete) *aper.WireSpan { return &v.stream }
func BridgeForbiddenTAsCompleteFieldWithoutReplay(v *ForbiddenTAsComplete) *bool {
	return &v.withoutReplay
}
func BridgeForbiddenTAsCompleteMethodMarshalAPERBudget(v *ForbiddenTAsComplete, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeForbiddenTAsCompleteMethodMarshalAPERBudgetValue(v *ForbiddenTAsComplete, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudgetValue(a0, a1)
}
func BridgeForbiddenTAsCompleteMethodMarshalAPERChanged(v *ForbiddenTAsComplete, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeForbiddenTAsCompleteMethodMarshalAPERChangedValue(v *ForbiddenTAsComplete, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeForbiddenTAsCompleteMethodMarshalAPERLegacy(v *ForbiddenTAsComplete) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeForbiddenTAsCompleteMethodMarshalAPERNewValue(v *ForbiddenTAsComplete, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERNewValue(a0, a1)
}
func BridgeForbiddenTAsCompleteMethodMarshalAPERPlanned(v *ForbiddenTAsComplete, a0 *aper.DecodeBudget, a1 bool, a2 *aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1, a2)
}
func BridgeForbiddenTAsCompleteMethodUnmarshalAPERLegacy(v *ForbiddenTAsComplete, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeForbiddenTAsCompleteMethodUnmarshalAPERWithOptions(v *ForbiddenTAsComplete, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeGUMMEIListCompleteFieldPerPadding(v *GUMMEIListComplete) *aper.CompletePadding {
	return &v.perPadding
}
func BridgeGUMMEIListCompleteFieldReceived(v *GUMMEIListComplete) *bool { return &v.received }
func BridgeGUMMEIListCompleteFieldReceivedAbsolute(v *GUMMEIListComplete) *bool {
	return &v.receivedAbsolute
}
func BridgeGUMMEIListCompleteFieldReceivedBytes(v *GUMMEIListComplete) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeGUMMEIListCompleteFieldReceivedLocation(v *GUMMEIListComplete) *aper.Location {
	return &v.receivedLocation
}
func BridgeGUMMEIListCompleteFieldReplay(v *GUMMEIListComplete) *aper.Snapshot { return &v.replay }
func BridgeGUMMEIListCompleteFieldStream(v *GUMMEIListComplete) *aper.WireSpan { return &v.stream }
func BridgeGUMMEIListCompleteFieldWithoutReplay(v *GUMMEIListComplete) *bool   { return &v.withoutReplay }
func BridgeGUMMEIListCompleteMethodMarshalAPERBudget(v *GUMMEIListComplete, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeGUMMEIListCompleteMethodMarshalAPERBudgetValue(v *GUMMEIListComplete, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudgetValue(a0, a1)
}
func BridgeGUMMEIListCompleteMethodMarshalAPERChanged(v *GUMMEIListComplete, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeGUMMEIListCompleteMethodMarshalAPERChangedValue(v *GUMMEIListComplete, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeGUMMEIListCompleteMethodMarshalAPERLegacy(v *GUMMEIListComplete) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeGUMMEIListCompleteMethodMarshalAPERNewValue(v *GUMMEIListComplete, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERNewValue(a0, a1)
}
func BridgeGUMMEIListCompleteMethodMarshalAPERPlanned(v *GUMMEIListComplete, a0 *aper.DecodeBudget, a1 bool, a2 *aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1, a2)
}
func BridgeGUMMEIListCompleteMethodUnmarshalAPERLegacy(v *GUMMEIListComplete, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeGUMMEIListCompleteMethodUnmarshalAPERWithOptions(v *GUMMEIListComplete, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeIEsECGIListCompleteFieldPerPadding(v *IEsECGIListComplete) *aper.CompletePadding {
	return &v.perPadding
}
func BridgeIEsECGIListCompleteFieldReceived(v *IEsECGIListComplete) *bool { return &v.received }
func BridgeIEsECGIListCompleteFieldReceivedAbsolute(v *IEsECGIListComplete) *bool {
	return &v.receivedAbsolute
}
func BridgeIEsECGIListCompleteFieldReceivedBytes(v *IEsECGIListComplete) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeIEsECGIListCompleteFieldReceivedLocation(v *IEsECGIListComplete) *aper.Location {
	return &v.receivedLocation
}
func BridgeIEsECGIListCompleteFieldReplay(v *IEsECGIListComplete) *aper.Snapshot { return &v.replay }
func BridgeIEsECGIListCompleteFieldStream(v *IEsECGIListComplete) *aper.WireSpan { return &v.stream }
func BridgeIEsECGIListCompleteFieldWithoutReplay(v *IEsECGIListComplete) *bool {
	return &v.withoutReplay
}
func BridgeIEsECGIListCompleteMethodMarshalAPERBudget(v *IEsECGIListComplete, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeIEsECGIListCompleteMethodMarshalAPERBudgetValue(v *IEsECGIListComplete, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudgetValue(a0, a1)
}
func BridgeIEsECGIListCompleteMethodMarshalAPERChanged(v *IEsECGIListComplete, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeIEsECGIListCompleteMethodMarshalAPERChangedValue(v *IEsECGIListComplete, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeIEsECGIListCompleteMethodMarshalAPERLegacy(v *IEsECGIListComplete) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeIEsECGIListCompleteMethodMarshalAPERNewValue(v *IEsECGIListComplete, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERNewValue(a0, a1)
}
func BridgeIEsECGIListCompleteMethodMarshalAPERPlanned(v *IEsECGIListComplete, a0 *aper.DecodeBudget, a1 bool, a2 *aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1, a2)
}
func BridgeIEsECGIListCompleteMethodUnmarshalAPERLegacy(v *IEsECGIListComplete, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeIEsECGIListCompleteMethodUnmarshalAPERWithOptions(v *IEsECGIListComplete, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeInterSystemMeasurementListCompleteFieldPerPadding(v *InterSystemMeasurementListComplete) *aper.CompletePadding {
	return &v.perPadding
}
func BridgeInterSystemMeasurementListCompleteFieldReceived(v *InterSystemMeasurementListComplete) *bool {
	return &v.received
}
func BridgeInterSystemMeasurementListCompleteFieldReceivedAbsolute(v *InterSystemMeasurementListComplete) *bool {
	return &v.receivedAbsolute
}
func BridgeInterSystemMeasurementListCompleteFieldReceivedBytes(v *InterSystemMeasurementListComplete) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeInterSystemMeasurementListCompleteFieldReceivedLocation(v *InterSystemMeasurementListComplete) *aper.Location {
	return &v.receivedLocation
}
func BridgeInterSystemMeasurementListCompleteFieldReplay(v *InterSystemMeasurementListComplete) *aper.Snapshot {
	return &v.replay
}
func BridgeInterSystemMeasurementListCompleteFieldStream(v *InterSystemMeasurementListComplete) *aper.WireSpan {
	return &v.stream
}
func BridgeInterSystemMeasurementListCompleteFieldWithoutReplay(v *InterSystemMeasurementListComplete) *bool {
	return &v.withoutReplay
}
func BridgeInterSystemMeasurementListCompleteMethodMarshalAPERBudget(v *InterSystemMeasurementListComplete, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeInterSystemMeasurementListCompleteMethodMarshalAPERBudgetValue(v *InterSystemMeasurementListComplete, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudgetValue(a0, a1)
}
func BridgeInterSystemMeasurementListCompleteMethodMarshalAPERChanged(v *InterSystemMeasurementListComplete, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeInterSystemMeasurementListCompleteMethodMarshalAPERChangedValue(v *InterSystemMeasurementListComplete, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeInterSystemMeasurementListCompleteMethodMarshalAPERLegacy(v *InterSystemMeasurementListComplete) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeInterSystemMeasurementListCompleteMethodMarshalAPERNewValue(v *InterSystemMeasurementListComplete, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERNewValue(a0, a1)
}
func BridgeInterSystemMeasurementListCompleteMethodMarshalAPERPlanned(v *InterSystemMeasurementListComplete, a0 *aper.DecodeBudget, a1 bool, a2 *aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1, a2)
}
func BridgeInterSystemMeasurementListCompleteMethodUnmarshalAPERLegacy(v *InterSystemMeasurementListComplete, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeInterSystemMeasurementListCompleteMethodUnmarshalAPERWithOptions(v *InterSystemMeasurementListComplete, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeLastVisitedCellItemAPERValueFieldContext(v *LastVisitedCellItemAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeLastVisitedCellItemAPERValueFieldReceived(v *LastVisitedCellItemAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeLastVisitedCellItemAPERValueFieldReplay(v *LastVisitedCellItemAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeLastVisitedCellItemAPERValueFieldWithoutReplay(v *LastVisitedCellItemAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeLastVisitedCellItemFieldPerOpenTypePadding(v *LastVisitedCellItem) *aper.CompletePadding {
	return &v.perOpenTypePadding
}
func BridgeLastVisitedCellItemFieldPerPadding(v *LastVisitedCellItem) *aper.CompletePadding {
	return &v.perPadding
}
func BridgeLastVisitedCellItemFieldReceived(v *LastVisitedCellItem) *bool { return &v.received }
func BridgeLastVisitedCellItemFieldReceivedAbsolute(v *LastVisitedCellItem) *bool {
	return &v.receivedAbsolute
}
func BridgeLastVisitedCellItemFieldReceivedBytes(v *LastVisitedCellItem) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeLastVisitedCellItemFieldReceivedLocation(v *LastVisitedCellItem) *aper.Location {
	return &v.receivedLocation
}
func BridgeLastVisitedCellItemFieldReplay(v *LastVisitedCellItem) *aper.Snapshot { return &v.replay }
func BridgeLastVisitedCellItemFieldStream(v *LastVisitedCellItem) *aper.WireSpan { return &v.stream }
func BridgeLastVisitedCellItemFieldWithoutReplay(v *LastVisitedCellItem) *bool {
	return &v.withoutReplay
}
func BridgeLastVisitedCellItemMethodMarshalAPERBudget(v *LastVisitedCellItem, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeLastVisitedCellItemMethodMarshalAPERBudgetValue(v *LastVisitedCellItem, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudgetValue(a0, a1)
}
func BridgeLastVisitedCellItemMethodMarshalAPERChanged(v *LastVisitedCellItem, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeLastVisitedCellItemMethodMarshalAPERChangedValue(v *LastVisitedCellItem, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeLastVisitedCellItemMethodMarshalAPERLegacy(v *LastVisitedCellItem) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeLastVisitedCellItemMethodMarshalAPERNewValue(v *LastVisitedCellItem, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERNewValue(a0, a1)
}
func BridgeLastVisitedCellItemMethodMarshalAPERPlanned(v *LastVisitedCellItem, a0 *aper.DecodeBudget, a1 bool, a2 *aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1, a2)
}
func BridgeLastVisitedCellItemMethodMarshalAPERTo(v *LastVisitedCellItem, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeLastVisitedCellItemMethodUnmarshalAPERFrom(v *LastVisitedCellItem, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeLastVisitedCellItemMethodUnmarshalAPERLegacy(v *LastVisitedCellItem, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeLastVisitedCellItemMethodUnmarshalAPERWithOptions(v *LastVisitedCellItem, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeLastVisitedCellItemValueCodecFieldCapture(v *LastVisitedCellItemValueCodec) *func(LastVisitedCellItem, aper.DecodeState) (LastVisitedCellItem, aper.Snapshot) {
	return &v.capture
}
func BridgeLastVisitedCellItemValueCodecFieldCompare(v *LastVisitedCellItemValueCodec) *func(LastVisitedCellItem, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeLastVisitedCellItemValueCodecFieldContext(v *LastVisitedCellItemValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeLastVisitedCellItemValueCodecFieldDecode(v *LastVisitedCellItemValueCodec) *func([]byte, aper.DecodeState) (LastVisitedCellItem, error) {
	return &v.decode
}
func BridgeLastVisitedCellItemValueCodecFieldEncode(v *LastVisitedCellItemValueCodec) *func(LastVisitedCellItem, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeLastVisitedCellItemValueCodecFieldPath(v *LastVisitedCellItemValueCodec) *aper.Path {
	return &v.path
}
func BridgeLastVisitedCellItemValueCodecMethodEncodeBudgetValue(v LastVisitedCellItemValueCodec, a0 LastVisitedCellItem, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeLastVisitedCellItemValueCodecMethodEncodeChanged(v LastVisitedCellItemValueCodec, a0 LastVisitedCellItem, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeLastVisitedEUTRANCellInformationAPERValueFieldContext(v *LastVisitedEUTRANCellInformationAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeLastVisitedEUTRANCellInformationAPERValueFieldReceived(v *LastVisitedEUTRANCellInformationAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeLastVisitedEUTRANCellInformationAPERValueFieldReplay(v *LastVisitedEUTRANCellInformationAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeLastVisitedEUTRANCellInformationAPERValueFieldWithoutReplay(v *LastVisitedEUTRANCellInformationAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeLastVisitedEUTRANCellInformationExtIETableMethodInfoHOCause(v LastVisitedEUTRANCellInformationExtIETable) s00.ExtensionInfo {
	return v.infoHOCause()
}
func BridgeLastVisitedEUTRANCellInformationExtIETableMethodInfoLastVisitedPSCellList(v LastVisitedEUTRANCellInformationExtIETable) s00.ExtensionInfo {
	return v.infoLastVisitedPSCellList()
}
func BridgeLastVisitedEUTRANCellInformationExtIETableMethodInfoTimeUEStayedInCellEnhancedGranularity(v LastVisitedEUTRANCellInformationExtIETable) s00.ExtensionInfo {
	return v.infoTimeUEStayedInCellEnhancedGranularity()
}
func BridgeLastVisitedEUTRANCellInformationExtIEsCauseExtBindingFieldCodec(v *LastVisitedEUTRANCellInformationExtIEsCauseExtBinding) *s14.CauseValueCodec {
	return &v.codec
}
func BridgeLastVisitedEUTRANCellInformationExtIEsCauseExtBindingFieldGet(v *LastVisitedEUTRANCellInformationExtIEsCauseExtBinding) *func(*LastVisitedEUTRANCellInformationExtIEsValue) (*s14.Cause, bool) {
	return &v.get
}
func BridgeLastVisitedEUTRANCellInformationExtIEsCauseExtBindingFieldInfo(v *LastVisitedEUTRANCellInformationExtIEsCauseExtBinding) *s00.ExtensionInfo {
	return &v.info
}
func BridgeLastVisitedEUTRANCellInformationExtIEsCauseExtBindingFieldInject(v *LastVisitedEUTRANCellInformationExtIEsCauseExtBinding) *func(s14.Cause) LastVisitedEUTRANCellInformationExtIEsValue {
	return &v.inject
}
func BridgeLastVisitedEUTRANCellInformationExtIEsExtContainerAPERValueFieldContext(v *LastVisitedEUTRANCellInformationExtIEsExtContainerAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeLastVisitedEUTRANCellInformationExtIEsExtContainerAPERValueFieldReceived(v *LastVisitedEUTRANCellInformationExtIEsExtContainerAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeLastVisitedEUTRANCellInformationExtIEsExtContainerAPERValueFieldReplay(v *LastVisitedEUTRANCellInformationExtIEsExtContainerAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeLastVisitedEUTRANCellInformationExtIEsExtContainerAPERValueFieldWithoutReplay(v *LastVisitedEUTRANCellInformationExtIEsExtContainerAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeLastVisitedEUTRANCellInformationExtIEsExtContainerValueCodecFieldCapture(v *LastVisitedEUTRANCellInformationExtIEsExtContainerValueCodec) *func(LastVisitedEUTRANCellInformationExtIEsExtContainer, aper.DecodeState) (LastVisitedEUTRANCellInformationExtIEsExtContainer, aper.Snapshot) {
	return &v.capture
}
func BridgeLastVisitedEUTRANCellInformationExtIEsExtContainerValueCodecFieldCompare(v *LastVisitedEUTRANCellInformationExtIEsExtContainerValueCodec) *func(LastVisitedEUTRANCellInformationExtIEsExtContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeLastVisitedEUTRANCellInformationExtIEsExtContainerValueCodecFieldContext(v *LastVisitedEUTRANCellInformationExtIEsExtContainerValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeLastVisitedEUTRANCellInformationExtIEsExtContainerValueCodecFieldDecode(v *LastVisitedEUTRANCellInformationExtIEsExtContainerValueCodec) *func([]byte, aper.DecodeState) (LastVisitedEUTRANCellInformationExtIEsExtContainer, error) {
	return &v.decode
}
func BridgeLastVisitedEUTRANCellInformationExtIEsExtContainerValueCodecFieldEncode(v *LastVisitedEUTRANCellInformationExtIEsExtContainerValueCodec) *func(LastVisitedEUTRANCellInformationExtIEsExtContainer, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeLastVisitedEUTRANCellInformationExtIEsExtContainerValueCodecFieldPath(v *LastVisitedEUTRANCellInformationExtIEsExtContainerValueCodec) *aper.Path {
	return &v.path
}
func BridgeLastVisitedEUTRANCellInformationExtIEsExtContainerValueCodecMethodEncodeBudgetValue(v LastVisitedEUTRANCellInformationExtIEsExtContainerValueCodec, a0 LastVisitedEUTRANCellInformationExtIEsExtContainer, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeLastVisitedEUTRANCellInformationExtIEsExtContainerValueCodecMethodEncodeChanged(v LastVisitedEUTRANCellInformationExtIEsExtContainerValueCodec, a0 LastVisitedEUTRANCellInformationExtIEsExtContainer, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeLastVisitedEUTRANCellInformationExtIEsExtFieldAPERValueFieldContext(v *LastVisitedEUTRANCellInformationExtIEsExtFieldAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeLastVisitedEUTRANCellInformationExtIEsExtFieldAPERValueFieldReceived(v *LastVisitedEUTRANCellInformationExtIEsExtFieldAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeLastVisitedEUTRANCellInformationExtIEsExtFieldAPERValueFieldReplay(v *LastVisitedEUTRANCellInformationExtIEsExtFieldAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeLastVisitedEUTRANCellInformationExtIEsExtFieldAPERValueFieldWithoutReplay(v *LastVisitedEUTRANCellInformationExtIEsExtFieldAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeLastVisitedEUTRANCellInformationExtIEsExtFieldFieldReceived(v *LastVisitedEUTRANCellInformationExtIEsExtField) *aper.CompletePadding {
	return &v.received
}
func BridgeLastVisitedEUTRANCellInformationExtIEsExtFieldFieldReplay(v *LastVisitedEUTRANCellInformationExtIEsExtField) *aper.Snapshot {
	return &v.replay
}
func BridgeLastVisitedEUTRANCellInformationExtIEsExtFieldFieldStream(v *LastVisitedEUTRANCellInformationExtIEsExtField) *aper.WireSpan {
	return &v.stream
}
func BridgeLastVisitedEUTRANCellInformationExtIEsExtFieldFieldWithoutReplay(v *LastVisitedEUTRANCellInformationExtIEsExtField) *bool {
	return &v.withoutReplay
}
func BridgeLastVisitedEUTRANCellInformationExtIEsExtFieldMethodMarshalAPERTo(v *LastVisitedEUTRANCellInformationExtIEsExtField, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeLastVisitedEUTRANCellInformationExtIEsExtFieldMethodUnmarshalAPERFrom(v *LastVisitedEUTRANCellInformationExtIEsExtField, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeLastVisitedEUTRANCellInformationExtIEsExtFieldValueCodecFieldCapture(v *LastVisitedEUTRANCellInformationExtIEsExtFieldValueCodec) *func(LastVisitedEUTRANCellInformationExtIEsExtField, aper.DecodeState) (LastVisitedEUTRANCellInformationExtIEsExtField, aper.Snapshot) {
	return &v.capture
}
func BridgeLastVisitedEUTRANCellInformationExtIEsExtFieldValueCodecFieldCompare(v *LastVisitedEUTRANCellInformationExtIEsExtFieldValueCodec) *func(LastVisitedEUTRANCellInformationExtIEsExtField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeLastVisitedEUTRANCellInformationExtIEsExtFieldValueCodecFieldContext(v *LastVisitedEUTRANCellInformationExtIEsExtFieldValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeLastVisitedEUTRANCellInformationExtIEsExtFieldValueCodecFieldDecode(v *LastVisitedEUTRANCellInformationExtIEsExtFieldValueCodec) *func([]byte, aper.DecodeState) (LastVisitedEUTRANCellInformationExtIEsExtField, error) {
	return &v.decode
}
func BridgeLastVisitedEUTRANCellInformationExtIEsExtFieldValueCodecFieldEncode(v *LastVisitedEUTRANCellInformationExtIEsExtFieldValueCodec) *func(LastVisitedEUTRANCellInformationExtIEsExtField, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeLastVisitedEUTRANCellInformationExtIEsExtFieldValueCodecFieldPath(v *LastVisitedEUTRANCellInformationExtIEsExtFieldValueCodec) *aper.Path {
	return &v.path
}
func BridgeLastVisitedEUTRANCellInformationExtIEsExtFieldValueCodecMethodEncodeBudgetValue(v LastVisitedEUTRANCellInformationExtIEsExtFieldValueCodec, a0 LastVisitedEUTRANCellInformationExtIEsExtField, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeLastVisitedEUTRANCellInformationExtIEsExtFieldValueCodecMethodEncodeChanged(v LastVisitedEUTRANCellInformationExtIEsExtFieldValueCodec, a0 LastVisitedEUTRANCellInformationExtIEsExtField, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeLastVisitedEUTRANCellInformationExtIEsIEFieldFieldReceived(v *LastVisitedEUTRANCellInformationExtIEsIEField) *aper.CompletePadding {
	return &v.received
}
func BridgeLastVisitedEUTRANCellInformationExtIEsIEFieldFieldReplay(v *LastVisitedEUTRANCellInformationExtIEsIEField) *aper.Snapshot {
	return &v.replay
}
func BridgeLastVisitedEUTRANCellInformationExtIEsIEFieldFieldStream(v *LastVisitedEUTRANCellInformationExtIEsIEField) *aper.WireSpan {
	return &v.stream
}
func BridgeLastVisitedEUTRANCellInformationExtIEsIEFieldFieldWithoutReplay(v *LastVisitedEUTRANCellInformationExtIEsIEField) *bool {
	return &v.withoutReplay
}
func BridgeLastVisitedEUTRANCellInformationExtIEsIEFieldMethodMarshalAPERTo(v *LastVisitedEUTRANCellInformationExtIEsIEField, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeLastVisitedEUTRANCellInformationExtIEsIEFieldMethodUnmarshalAPERFrom(v *LastVisitedEUTRANCellInformationExtIEsIEField, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeLastVisitedEUTRANCellInformationExtIEsLastVisitedPSCellListExtBindingFieldCodec(v *LastVisitedEUTRANCellInformationExtIEsLastVisitedPSCellListExtBinding) *s20.LastVisitedPSCellListValueCodec {
	return &v.codec
}
func BridgeLastVisitedEUTRANCellInformationExtIEsLastVisitedPSCellListExtBindingFieldGet(v *LastVisitedEUTRANCellInformationExtIEsLastVisitedPSCellListExtBinding) *func(*LastVisitedEUTRANCellInformationExtIEsValue) (*s20.LastVisitedPSCellList, bool) {
	return &v.get
}
func BridgeLastVisitedEUTRANCellInformationExtIEsLastVisitedPSCellListExtBindingFieldInfo(v *LastVisitedEUTRANCellInformationExtIEsLastVisitedPSCellListExtBinding) *s00.ExtensionInfo {
	return &v.info
}
func BridgeLastVisitedEUTRANCellInformationExtIEsLastVisitedPSCellListExtBindingFieldInject(v *LastVisitedEUTRANCellInformationExtIEsLastVisitedPSCellListExtBinding) *func(s20.LastVisitedPSCellList) LastVisitedEUTRANCellInformationExtIEsValue {
	return &v.inject
}
func BridgeLastVisitedEUTRANCellInformationExtIEsTimeUEStayedInCellEnhancedGranularityExtBindingFieldCodec(v *LastVisitedEUTRANCellInformationExtIEsTimeUEStayedInCellEnhancedGranularityExtBinding) *s02.TimeUEStayedInCellEnhancedGranularityValueCodec {
	return &v.codec
}
func BridgeLastVisitedEUTRANCellInformationExtIEsTimeUEStayedInCellEnhancedGranularityExtBindingFieldGet(v *LastVisitedEUTRANCellInformationExtIEsTimeUEStayedInCellEnhancedGranularityExtBinding) *func(*LastVisitedEUTRANCellInformationExtIEsValue) (*s00.TimeUEStayedInCellEnhancedGranularity, bool) {
	return &v.get
}
func BridgeLastVisitedEUTRANCellInformationExtIEsTimeUEStayedInCellEnhancedGranularityExtBindingFieldInfo(v *LastVisitedEUTRANCellInformationExtIEsTimeUEStayedInCellEnhancedGranularityExtBinding) *s00.ExtensionInfo {
	return &v.info
}
func BridgeLastVisitedEUTRANCellInformationExtIEsTimeUEStayedInCellEnhancedGranularityExtBindingFieldInject(v *LastVisitedEUTRANCellInformationExtIEsTimeUEStayedInCellEnhancedGranularityExtBinding) *func(s00.TimeUEStayedInCellEnhancedGranularity) LastVisitedEUTRANCellInformationExtIEsValue {
	return &v.inject
}
func BridgeLastVisitedEUTRANCellInformationExtIEsValueFieldId(v *LastVisitedEUTRANCellInformationExtIEsValue) *s00.ProtocolIEID {
	return &v.id
}
func BridgeLastVisitedEUTRANCellInformationExtIEsValueFieldIsOpaque(v *LastVisitedEUTRANCellInformationExtIEsValue) *bool {
	return &v.isOpaque
}
func BridgeLastVisitedEUTRANCellInformationExtIEsValueFieldOpaque(v *LastVisitedEUTRANCellInformationExtIEsValue) *aper.OpaqueOpenType {
	return &v.opaque
}
func BridgeLastVisitedEUTRANCellInformationExtIEsValueFieldReceived(v *LastVisitedEUTRANCellInformationExtIEsValue) *aper.WireSpan {
	return &v.received
}
func BridgeLastVisitedEUTRANCellInformationExtIEsValueFieldReplay(v *LastVisitedEUTRANCellInformationExtIEsValue) *aper.Snapshot {
	return &v.replay
}
func BridgeLastVisitedEUTRANCellInformationExtIEsValueFieldRowHOCause(v *LastVisitedEUTRANCellInformationExtIEsValue) **s14.Cause {
	return &v.rowHOCause
}
func BridgeLastVisitedEUTRANCellInformationExtIEsValueFieldRowLastVisitedPSCellList(v *LastVisitedEUTRANCellInformationExtIEsValue) **s20.LastVisitedPSCellList {
	return &v.rowLastVisitedPSCellList
}
func BridgeLastVisitedEUTRANCellInformationExtIEsValueFieldRowTimeUEStayedInCellEnhancedGranularity(v *LastVisitedEUTRANCellInformationExtIEsValue) **s00.TimeUEStayedInCellEnhancedGranularity {
	return &v.rowTimeUEStayedInCellEnhancedGranularity
}
func BridgeLastVisitedEUTRANCellInformationExtIEsValueMethodCaptureSemantics(v LastVisitedEUTRANCellInformationExtIEsValue, a0 aper.SemanticCapture) LastVisitedEUTRANCellInformationExtIEsValue {
	return v.captureSemantics(a0)
}
func BridgeLastVisitedEUTRANCellInformationExtIEsValueMethodCompareSemantics(v LastVisitedEUTRANCellInformationExtIEsValue, a0 aper.SemanticComparison) aper.SemanticComparison {
	return v.compareSemantics(a0)
}
func BridgeLastVisitedEUTRANCellInformationExtIEsValueMethodDecode(v LastVisitedEUTRANCellInformationExtIEsValue, a0 s00.ProtocolIEID, a1 aper.OpaqueOpenType) (LastVisitedEUTRANCellInformationExtIEsValue, error) {
	return v.decode(a0, a1)
}
func BridgeLastVisitedEUTRANCellInformationExtIEsValueMethodEncode(v LastVisitedEUTRANCellInformationExtIEsValue) ([]byte, error) {
	return v.encode()
}
func BridgeLastVisitedEUTRANCellInformationExtIEsValueMethodEncodeFresh(v LastVisitedEUTRANCellInformationExtIEsValue, a0 bool, a1 *aper.DecodeBudget) ([]byte, error) {
	return v.encodeFresh(a0, a1)
}
func BridgeLastVisitedEUTRANCellInformationExtIEsValueMethodMatchesID(v LastVisitedEUTRANCellInformationExtIEsValue, a0 s00.ProtocolIEID, a1 ...*aper.DecodeBudget) bool {
	return v.matchesID(a0, a1...)
}
func BridgeLastVisitedEUTRANCellInformationExtIEsValueMethodReason(v LastVisitedEUTRANCellInformationExtIEsValue, a0 s00.ProtocolIEID) aper.OpaqueReason {
	return v.reason(a0)
}
func BridgeLastVisitedEUTRANCellInformationExtIEsValueMethodRule(v LastVisitedEUTRANCellInformationExtIEsValue) aper.SourceRule {
	return v.rule()
}
func BridgeLastVisitedEUTRANCellInformationFieldExtCount(v *LastVisitedEUTRANCellInformation) *int64 {
	return &v.extCount
}
func BridgeLastVisitedEUTRANCellInformationFieldExtData(v *LastVisitedEUTRANCellInformation) *[][]byte {
	return &v.extData
}
func BridgeLastVisitedEUTRANCellInformationFieldExtOrigin(v *LastVisitedEUTRANCellInformation) *[]aper.OpaqueOrigin {
	return &v.extOrigin
}
func BridgeLastVisitedEUTRANCellInformationFieldExtPresent(v *LastVisitedEUTRANCellInformation) *[]bool {
	return &v.extPresent
}
func BridgeLastVisitedEUTRANCellInformationFieldExtWire(v *LastVisitedEUTRANCellInformation) *[]aper.WireSpan {
	return &v.extWire
}
func BridgeLastVisitedEUTRANCellInformationFieldIEExtensionsIndef(v *LastVisitedEUTRANCellInformation) *bool {
	return &v.iEExtensionsIndef
}
func BridgeLastVisitedEUTRANCellInformationFieldPerExtPadding(v *LastVisitedEUTRANCellInformation) *[]aper.CompletePadding {
	return &v.perExtPadding
}
func BridgeLastVisitedEUTRANCellInformationFieldPerPadding(v *LastVisitedEUTRANCellInformation) *aper.FinalPadding {
	return &v.perPadding
}
func BridgeLastVisitedEUTRANCellInformationFieldReceived(v *LastVisitedEUTRANCellInformation) *bool {
	return &v.received
}
func BridgeLastVisitedEUTRANCellInformationFieldReceivedAbsolute(v *LastVisitedEUTRANCellInformation) *bool {
	return &v.receivedAbsolute
}
func BridgeLastVisitedEUTRANCellInformationFieldReceivedBytes(v *LastVisitedEUTRANCellInformation) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeLastVisitedEUTRANCellInformationFieldReceivedLocation(v *LastVisitedEUTRANCellInformation) *aper.Location {
	return &v.receivedLocation
}
func BridgeLastVisitedEUTRANCellInformationFieldReplay(v *LastVisitedEUTRANCellInformation) *aper.Snapshot {
	return &v.replay
}
func BridgeLastVisitedEUTRANCellInformationFieldStream(v *LastVisitedEUTRANCellInformation) *aper.WireSpan {
	return &v.stream
}
func BridgeLastVisitedEUTRANCellInformationFieldWithoutReplay(v *LastVisitedEUTRANCellInformation) *bool {
	return &v.withoutReplay
}
func BridgeLastVisitedEUTRANCellInformationMethodMarshalAPERBudget(v *LastVisitedEUTRANCellInformation, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeLastVisitedEUTRANCellInformationMethodMarshalAPERBudgetValue(v *LastVisitedEUTRANCellInformation, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudgetValue(a0, a1)
}
func BridgeLastVisitedEUTRANCellInformationMethodMarshalAPERChanged(v *LastVisitedEUTRANCellInformation, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeLastVisitedEUTRANCellInformationMethodMarshalAPERChangedValue(v *LastVisitedEUTRANCellInformation, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeLastVisitedEUTRANCellInformationMethodMarshalAPERLegacy(v *LastVisitedEUTRANCellInformation) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeLastVisitedEUTRANCellInformationMethodMarshalAPERNewValue(v *LastVisitedEUTRANCellInformation, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERNewValue(a0, a1)
}
func BridgeLastVisitedEUTRANCellInformationMethodMarshalAPERPlanned(v *LastVisitedEUTRANCellInformation, a0 *aper.DecodeBudget, a1 bool, a2 *aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1, a2)
}
func BridgeLastVisitedEUTRANCellInformationMethodMarshalAPERTo(v *LastVisitedEUTRANCellInformation, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeLastVisitedEUTRANCellInformationMethodUnmarshalAPERFrom(v *LastVisitedEUTRANCellInformation, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeLastVisitedEUTRANCellInformationMethodUnmarshalAPERLegacy(v *LastVisitedEUTRANCellInformation, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeLastVisitedEUTRANCellInformationMethodUnmarshalAPERWithOptions(v *LastVisitedEUTRANCellInformation, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeLastVisitedEUTRANCellInformationValueCodecFieldCapture(v *LastVisitedEUTRANCellInformationValueCodec) *func(LastVisitedEUTRANCellInformation, aper.DecodeState) (LastVisitedEUTRANCellInformation, aper.Snapshot) {
	return &v.capture
}
func BridgeLastVisitedEUTRANCellInformationValueCodecFieldCompare(v *LastVisitedEUTRANCellInformationValueCodec) *func(LastVisitedEUTRANCellInformation, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeLastVisitedEUTRANCellInformationValueCodecFieldContext(v *LastVisitedEUTRANCellInformationValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeLastVisitedEUTRANCellInformationValueCodecFieldDecode(v *LastVisitedEUTRANCellInformationValueCodec) *func([]byte, aper.DecodeState) (LastVisitedEUTRANCellInformation, error) {
	return &v.decode
}
func BridgeLastVisitedEUTRANCellInformationValueCodecFieldEncode(v *LastVisitedEUTRANCellInformationValueCodec) *func(LastVisitedEUTRANCellInformation, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeLastVisitedEUTRANCellInformationValueCodecFieldPath(v *LastVisitedEUTRANCellInformationValueCodec) *aper.Path {
	return &v.path
}
func BridgeLastVisitedEUTRANCellInformationValueCodecMethodEncodeBudgetValue(v LastVisitedEUTRANCellInformationValueCodec, a0 LastVisitedEUTRANCellInformation, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeLastVisitedEUTRANCellInformationValueCodecMethodEncodeChanged(v LastVisitedEUTRANCellInformationValueCodec, a0 LastVisitedEUTRANCellInformation, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeLastVisitedPSCellListCompleteFieldPerPadding(v *LastVisitedPSCellListComplete) *aper.CompletePadding {
	return &v.perPadding
}
func BridgeLastVisitedPSCellListCompleteFieldReceived(v *LastVisitedPSCellListComplete) *bool {
	return &v.received
}
func BridgeLastVisitedPSCellListCompleteFieldReceivedAbsolute(v *LastVisitedPSCellListComplete) *bool {
	return &v.receivedAbsolute
}
func BridgeLastVisitedPSCellListCompleteFieldReceivedBytes(v *LastVisitedPSCellListComplete) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeLastVisitedPSCellListCompleteFieldReceivedLocation(v *LastVisitedPSCellListComplete) *aper.Location {
	return &v.receivedLocation
}
func BridgeLastVisitedPSCellListCompleteFieldReplay(v *LastVisitedPSCellListComplete) *aper.Snapshot {
	return &v.replay
}
func BridgeLastVisitedPSCellListCompleteFieldStream(v *LastVisitedPSCellListComplete) *aper.WireSpan {
	return &v.stream
}
func BridgeLastVisitedPSCellListCompleteFieldWithoutReplay(v *LastVisitedPSCellListComplete) *bool {
	return &v.withoutReplay
}
func BridgeLastVisitedPSCellListCompleteMethodMarshalAPERBudget(v *LastVisitedPSCellListComplete, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeLastVisitedPSCellListCompleteMethodMarshalAPERBudgetValue(v *LastVisitedPSCellListComplete, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudgetValue(a0, a1)
}
func BridgeLastVisitedPSCellListCompleteMethodMarshalAPERChanged(v *LastVisitedPSCellListComplete, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeLastVisitedPSCellListCompleteMethodMarshalAPERChangedValue(v *LastVisitedPSCellListComplete, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeLastVisitedPSCellListCompleteMethodMarshalAPERLegacy(v *LastVisitedPSCellListComplete) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeLastVisitedPSCellListCompleteMethodMarshalAPERNewValue(v *LastVisitedPSCellListComplete, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERNewValue(a0, a1)
}
func BridgeLastVisitedPSCellListCompleteMethodMarshalAPERPlanned(v *LastVisitedPSCellListComplete, a0 *aper.DecodeBudget, a1 bool, a2 *aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1, a2)
}
func BridgeLastVisitedPSCellListCompleteMethodUnmarshalAPERLegacy(v *LastVisitedPSCellListComplete, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeLastVisitedPSCellListCompleteMethodUnmarshalAPERWithOptions(v *LastVisitedPSCellListComplete, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeMBSFNResultToLogCompleteFieldPerPadding(v *MBSFNResultToLogComplete) *aper.CompletePadding {
	return &v.perPadding
}
func BridgeMBSFNResultToLogCompleteFieldReceived(v *MBSFNResultToLogComplete) *bool {
	return &v.received
}
func BridgeMBSFNResultToLogCompleteFieldReceivedAbsolute(v *MBSFNResultToLogComplete) *bool {
	return &v.receivedAbsolute
}
func BridgeMBSFNResultToLogCompleteFieldReceivedBytes(v *MBSFNResultToLogComplete) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeMBSFNResultToLogCompleteFieldReceivedLocation(v *MBSFNResultToLogComplete) *aper.Location {
	return &v.receivedLocation
}
func BridgeMBSFNResultToLogCompleteFieldReplay(v *MBSFNResultToLogComplete) *aper.Snapshot {
	return &v.replay
}
func BridgeMBSFNResultToLogCompleteFieldStream(v *MBSFNResultToLogComplete) *aper.WireSpan {
	return &v.stream
}
func BridgeMBSFNResultToLogCompleteFieldWithoutReplay(v *MBSFNResultToLogComplete) *bool {
	return &v.withoutReplay
}
func BridgeMBSFNResultToLogCompleteMethodMarshalAPERBudget(v *MBSFNResultToLogComplete, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeMBSFNResultToLogCompleteMethodMarshalAPERBudgetValue(v *MBSFNResultToLogComplete, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudgetValue(a0, a1)
}
func BridgeMBSFNResultToLogCompleteMethodMarshalAPERChanged(v *MBSFNResultToLogComplete, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeMBSFNResultToLogCompleteMethodMarshalAPERChangedValue(v *MBSFNResultToLogComplete, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeMBSFNResultToLogCompleteMethodMarshalAPERLegacy(v *MBSFNResultToLogComplete) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeMBSFNResultToLogCompleteMethodMarshalAPERNewValue(v *MBSFNResultToLogComplete, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERNewValue(a0, a1)
}
func BridgeMBSFNResultToLogCompleteMethodMarshalAPERPlanned(v *MBSFNResultToLogComplete, a0 *aper.DecodeBudget, a1 bool, a2 *aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1, a2)
}
func BridgeMBSFNResultToLogCompleteMethodUnmarshalAPERLegacy(v *MBSFNResultToLogComplete, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeMBSFNResultToLogCompleteMethodUnmarshalAPERWithOptions(v *MBSFNResultToLogComplete, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeMDTConfigurationExtIETableMethodInfoSignallingBasedMDTPLMNList(v MDTConfigurationExtIETable) s00.ExtensionInfo {
	return v.infoSignallingBasedMDTPLMNList()
}
func BridgeMDTConfigurationExtIEsExtContainerAPERValueFieldContext(v *MDTConfigurationExtIEsExtContainerAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeMDTConfigurationExtIEsExtContainerAPERValueFieldReceived(v *MDTConfigurationExtIEsExtContainerAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeMDTConfigurationExtIEsExtContainerAPERValueFieldReplay(v *MDTConfigurationExtIEsExtContainerAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeMDTConfigurationExtIEsExtContainerAPERValueFieldWithoutReplay(v *MDTConfigurationExtIEsExtContainerAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeMDTConfigurationExtIEsExtContainerValueCodecFieldCapture(v *MDTConfigurationExtIEsExtContainerValueCodec) *func(MDTConfigurationExtIEsExtContainer, aper.DecodeState) (MDTConfigurationExtIEsExtContainer, aper.Snapshot) {
	return &v.capture
}
func BridgeMDTConfigurationExtIEsExtContainerValueCodecFieldCompare(v *MDTConfigurationExtIEsExtContainerValueCodec) *func(MDTConfigurationExtIEsExtContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeMDTConfigurationExtIEsExtContainerValueCodecFieldContext(v *MDTConfigurationExtIEsExtContainerValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeMDTConfigurationExtIEsExtContainerValueCodecFieldDecode(v *MDTConfigurationExtIEsExtContainerValueCodec) *func([]byte, aper.DecodeState) (MDTConfigurationExtIEsExtContainer, error) {
	return &v.decode
}
func BridgeMDTConfigurationExtIEsExtContainerValueCodecFieldEncode(v *MDTConfigurationExtIEsExtContainerValueCodec) *func(MDTConfigurationExtIEsExtContainer, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeMDTConfigurationExtIEsExtContainerValueCodecFieldPath(v *MDTConfigurationExtIEsExtContainerValueCodec) *aper.Path {
	return &v.path
}
func BridgeMDTConfigurationExtIEsExtContainerValueCodecMethodEncodeBudgetValue(v MDTConfigurationExtIEsExtContainerValueCodec, a0 MDTConfigurationExtIEsExtContainer, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeMDTConfigurationExtIEsExtContainerValueCodecMethodEncodeChanged(v MDTConfigurationExtIEsExtContainerValueCodec, a0 MDTConfigurationExtIEsExtContainer, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeMDTConfigurationExtIEsExtFieldAPERValueFieldContext(v *MDTConfigurationExtIEsExtFieldAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeMDTConfigurationExtIEsExtFieldAPERValueFieldReceived(v *MDTConfigurationExtIEsExtFieldAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeMDTConfigurationExtIEsExtFieldAPERValueFieldReplay(v *MDTConfigurationExtIEsExtFieldAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeMDTConfigurationExtIEsExtFieldAPERValueFieldWithoutReplay(v *MDTConfigurationExtIEsExtFieldAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeMDTConfigurationExtIEsExtFieldFieldReceived(v *MDTConfigurationExtIEsExtField) *aper.CompletePadding {
	return &v.received
}
func BridgeMDTConfigurationExtIEsExtFieldFieldReplay(v *MDTConfigurationExtIEsExtField) *aper.Snapshot {
	return &v.replay
}
func BridgeMDTConfigurationExtIEsExtFieldFieldStream(v *MDTConfigurationExtIEsExtField) *aper.WireSpan {
	return &v.stream
}
func BridgeMDTConfigurationExtIEsExtFieldFieldWithoutReplay(v *MDTConfigurationExtIEsExtField) *bool {
	return &v.withoutReplay
}
func BridgeMDTConfigurationExtIEsExtFieldMethodMarshalAPERTo(v *MDTConfigurationExtIEsExtField, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeMDTConfigurationExtIEsExtFieldMethodUnmarshalAPERFrom(v *MDTConfigurationExtIEsExtField, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeMDTConfigurationExtIEsExtFieldValueCodecFieldCapture(v *MDTConfigurationExtIEsExtFieldValueCodec) *func(MDTConfigurationExtIEsExtField, aper.DecodeState) (MDTConfigurationExtIEsExtField, aper.Snapshot) {
	return &v.capture
}
func BridgeMDTConfigurationExtIEsExtFieldValueCodecFieldCompare(v *MDTConfigurationExtIEsExtFieldValueCodec) *func(MDTConfigurationExtIEsExtField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeMDTConfigurationExtIEsExtFieldValueCodecFieldContext(v *MDTConfigurationExtIEsExtFieldValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeMDTConfigurationExtIEsExtFieldValueCodecFieldDecode(v *MDTConfigurationExtIEsExtFieldValueCodec) *func([]byte, aper.DecodeState) (MDTConfigurationExtIEsExtField, error) {
	return &v.decode
}
func BridgeMDTConfigurationExtIEsExtFieldValueCodecFieldEncode(v *MDTConfigurationExtIEsExtFieldValueCodec) *func(MDTConfigurationExtIEsExtField, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeMDTConfigurationExtIEsExtFieldValueCodecFieldPath(v *MDTConfigurationExtIEsExtFieldValueCodec) *aper.Path {
	return &v.path
}
func BridgeMDTConfigurationExtIEsExtFieldValueCodecMethodEncodeBudgetValue(v MDTConfigurationExtIEsExtFieldValueCodec, a0 MDTConfigurationExtIEsExtField, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeMDTConfigurationExtIEsExtFieldValueCodecMethodEncodeChanged(v MDTConfigurationExtIEsExtFieldValueCodec, a0 MDTConfigurationExtIEsExtField, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeMDTConfigurationExtIEsIEFieldFieldReceived(v *MDTConfigurationExtIEsIEField) *aper.CompletePadding {
	return &v.received
}
func BridgeMDTConfigurationExtIEsIEFieldFieldReplay(v *MDTConfigurationExtIEsIEField) *aper.Snapshot {
	return &v.replay
}
func BridgeMDTConfigurationExtIEsIEFieldFieldStream(v *MDTConfigurationExtIEsIEField) *aper.WireSpan {
	return &v.stream
}
func BridgeMDTConfigurationExtIEsIEFieldFieldWithoutReplay(v *MDTConfigurationExtIEsIEField) *bool {
	return &v.withoutReplay
}
func BridgeMDTConfigurationExtIEsIEFieldMethodMarshalAPERTo(v *MDTConfigurationExtIEsIEField, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeMDTConfigurationExtIEsIEFieldMethodUnmarshalAPERFrom(v *MDTConfigurationExtIEsIEField, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeMDTConfigurationExtIEsMDTPLMNListExtBindingFieldCodec(v *MDTConfigurationExtIEsMDTPLMNListExtBinding) *s01.MDTPLMNListValueCodec {
	return &v.codec
}
func BridgeMDTConfigurationExtIEsMDTPLMNListExtBindingFieldGet(v *MDTConfigurationExtIEsMDTPLMNListExtBinding) *func(*MDTConfigurationExtIEsValue) (*s00.MDTPLMNList, bool) {
	return &v.get
}
func BridgeMDTConfigurationExtIEsMDTPLMNListExtBindingFieldInfo(v *MDTConfigurationExtIEsMDTPLMNListExtBinding) *s00.ExtensionInfo {
	return &v.info
}
func BridgeMDTConfigurationExtIEsMDTPLMNListExtBindingFieldInject(v *MDTConfigurationExtIEsMDTPLMNListExtBinding) *func(s00.MDTPLMNList) MDTConfigurationExtIEsValue {
	return &v.inject
}
func BridgeMDTConfigurationExtIEsValueFieldId(v *MDTConfigurationExtIEsValue) *s00.ProtocolIEID {
	return &v.id
}
func BridgeMDTConfigurationExtIEsValueFieldIsOpaque(v *MDTConfigurationExtIEsValue) *bool {
	return &v.isOpaque
}
func BridgeMDTConfigurationExtIEsValueFieldOpaque(v *MDTConfigurationExtIEsValue) *aper.OpaqueOpenType {
	return &v.opaque
}
func BridgeMDTConfigurationExtIEsValueFieldReceived(v *MDTConfigurationExtIEsValue) *aper.WireSpan {
	return &v.received
}
func BridgeMDTConfigurationExtIEsValueFieldReplay(v *MDTConfigurationExtIEsValue) *aper.Snapshot {
	return &v.replay
}
func BridgeMDTConfigurationExtIEsValueFieldRowSignallingBasedMDTPLMNList(v *MDTConfigurationExtIEsValue) **s00.MDTPLMNList {
	return &v.rowSignallingBasedMDTPLMNList
}
func BridgeMDTConfigurationExtIEsValueMethodCaptureSemantics(v MDTConfigurationExtIEsValue, a0 aper.SemanticCapture) MDTConfigurationExtIEsValue {
	return v.captureSemantics(a0)
}
func BridgeMDTConfigurationExtIEsValueMethodCompareSemantics(v MDTConfigurationExtIEsValue, a0 aper.SemanticComparison) aper.SemanticComparison {
	return v.compareSemantics(a0)
}
func BridgeMDTConfigurationExtIEsValueMethodDecode(v MDTConfigurationExtIEsValue, a0 s00.ProtocolIEID, a1 aper.OpaqueOpenType) (MDTConfigurationExtIEsValue, error) {
	return v.decode(a0, a1)
}
func BridgeMDTConfigurationExtIEsValueMethodEncode(v MDTConfigurationExtIEsValue) ([]byte, error) {
	return v.encode()
}
func BridgeMDTConfigurationExtIEsValueMethodEncodeFresh(v MDTConfigurationExtIEsValue, a0 bool, a1 *aper.DecodeBudget) ([]byte, error) {
	return v.encodeFresh(a0, a1)
}
func BridgeMDTConfigurationExtIEsValueMethodMatchesID(v MDTConfigurationExtIEsValue, a0 s00.ProtocolIEID, a1 ...*aper.DecodeBudget) bool {
	return v.matchesID(a0, a1...)
}
func BridgeMDTConfigurationExtIEsValueMethodReason(v MDTConfigurationExtIEsValue, a0 s00.ProtocolIEID) aper.OpaqueReason {
	return v.reason(a0)
}
func BridgeMDTConfigurationExtIEsValueMethodRule(v MDTConfigurationExtIEsValue) aper.SourceRule {
	return v.rule()
}
func BridgeMDTPLMNListCompleteFieldPerPadding(v *MDTPLMNListComplete) *aper.CompletePadding {
	return &v.perPadding
}
func BridgeMDTPLMNListCompleteFieldReceived(v *MDTPLMNListComplete) *bool { return &v.received }
func BridgeMDTPLMNListCompleteFieldReceivedAbsolute(v *MDTPLMNListComplete) *bool {
	return &v.receivedAbsolute
}
func BridgeMDTPLMNListCompleteFieldReceivedBytes(v *MDTPLMNListComplete) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeMDTPLMNListCompleteFieldReceivedLocation(v *MDTPLMNListComplete) *aper.Location {
	return &v.receivedLocation
}
func BridgeMDTPLMNListCompleteFieldReplay(v *MDTPLMNListComplete) *aper.Snapshot { return &v.replay }
func BridgeMDTPLMNListCompleteFieldStream(v *MDTPLMNListComplete) *aper.WireSpan { return &v.stream }
func BridgeMDTPLMNListCompleteFieldWithoutReplay(v *MDTPLMNListComplete) *bool {
	return &v.withoutReplay
}
func BridgeMDTPLMNListCompleteMethodMarshalAPERBudget(v *MDTPLMNListComplete, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeMDTPLMNListCompleteMethodMarshalAPERBudgetValue(v *MDTPLMNListComplete, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudgetValue(a0, a1)
}
func BridgeMDTPLMNListCompleteMethodMarshalAPERChanged(v *MDTPLMNListComplete, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeMDTPLMNListCompleteMethodMarshalAPERChangedValue(v *MDTPLMNListComplete, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeMDTPLMNListCompleteMethodMarshalAPERLegacy(v *MDTPLMNListComplete) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeMDTPLMNListCompleteMethodMarshalAPERNewValue(v *MDTPLMNListComplete, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERNewValue(a0, a1)
}
func BridgeMDTPLMNListCompleteMethodMarshalAPERPlanned(v *MDTPLMNListComplete, a0 *aper.DecodeBudget, a1 bool, a2 *aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1, a2)
}
func BridgeMDTPLMNListCompleteMethodUnmarshalAPERLegacy(v *MDTPLMNListComplete, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeMDTPLMNListCompleteMethodUnmarshalAPERWithOptions(v *MDTPLMNListComplete, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeMultiCellLoadReportingResponseCompleteFieldPerPadding(v *MultiCellLoadReportingResponseComplete) *aper.CompletePadding {
	return &v.perPadding
}
func BridgeMultiCellLoadReportingResponseCompleteFieldReceived(v *MultiCellLoadReportingResponseComplete) *bool {
	return &v.received
}
func BridgeMultiCellLoadReportingResponseCompleteFieldReceivedAbsolute(v *MultiCellLoadReportingResponseComplete) *bool {
	return &v.receivedAbsolute
}
func BridgeMultiCellLoadReportingResponseCompleteFieldReceivedBytes(v *MultiCellLoadReportingResponseComplete) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeMultiCellLoadReportingResponseCompleteFieldReceivedLocation(v *MultiCellLoadReportingResponseComplete) *aper.Location {
	return &v.receivedLocation
}
func BridgeMultiCellLoadReportingResponseCompleteFieldReplay(v *MultiCellLoadReportingResponseComplete) *aper.Snapshot {
	return &v.replay
}
func BridgeMultiCellLoadReportingResponseCompleteFieldStream(v *MultiCellLoadReportingResponseComplete) *aper.WireSpan {
	return &v.stream
}
func BridgeMultiCellLoadReportingResponseCompleteFieldWithoutReplay(v *MultiCellLoadReportingResponseComplete) *bool {
	return &v.withoutReplay
}
func BridgeMultiCellLoadReportingResponseCompleteMethodMarshalAPERBudget(v *MultiCellLoadReportingResponseComplete, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeMultiCellLoadReportingResponseCompleteMethodMarshalAPERBudgetValue(v *MultiCellLoadReportingResponseComplete, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudgetValue(a0, a1)
}
func BridgeMultiCellLoadReportingResponseCompleteMethodMarshalAPERChanged(v *MultiCellLoadReportingResponseComplete, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeMultiCellLoadReportingResponseCompleteMethodMarshalAPERChangedValue(v *MultiCellLoadReportingResponseComplete, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeMultiCellLoadReportingResponseCompleteMethodMarshalAPERLegacy(v *MultiCellLoadReportingResponseComplete) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeMultiCellLoadReportingResponseCompleteMethodMarshalAPERNewValue(v *MultiCellLoadReportingResponseComplete, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERNewValue(a0, a1)
}
func BridgeMultiCellLoadReportingResponseCompleteMethodMarshalAPERPlanned(v *MultiCellLoadReportingResponseComplete, a0 *aper.DecodeBudget, a1 bool, a2 *aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1, a2)
}
func BridgeMultiCellLoadReportingResponseCompleteMethodUnmarshalAPERLegacy(v *MultiCellLoadReportingResponseComplete, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeMultiCellLoadReportingResponseCompleteMethodUnmarshalAPERWithOptions(v *MultiCellLoadReportingResponseComplete, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
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
func BridgeOverloadStartAPERValueFieldContext(v *OverloadStartAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeOverloadStartAPERValueFieldReceived(v *OverloadStartAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeOverloadStartAPERValueFieldReplay(v *OverloadStartAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeOverloadStartAPERValueFieldWithoutReplay(v *OverloadStartAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeOverloadStartFieldExtCount(v *OverloadStart) *int64                { return &v.extCount }
func BridgeOverloadStartFieldExtData(v *OverloadStart) *[][]byte              { return &v.extData }
func BridgeOverloadStartFieldExtOrigin(v *OverloadStart) *[]aper.OpaqueOrigin { return &v.extOrigin }
func BridgeOverloadStartFieldExtPresent(v *OverloadStart) *[]bool             { return &v.extPresent }
func BridgeOverloadStartFieldExtWire(v *OverloadStart) *[]aper.WireSpan       { return &v.extWire }
func BridgeOverloadStartFieldPerExtPadding(v *OverloadStart) *[]aper.CompletePadding {
	return &v.perExtPadding
}
func BridgeOverloadStartFieldPerPadding(v *OverloadStart) *aper.FinalPadding { return &v.perPadding }
func BridgeOverloadStartFieldProtocolIEsIndef(v *OverloadStart) *bool        { return &v.protocolIEsIndef }
func BridgeOverloadStartFieldReceived(v *OverloadStart) *bool                { return &v.received }
func BridgeOverloadStartFieldReceivedAbsolute(v *OverloadStart) *bool        { return &v.receivedAbsolute }
func BridgeOverloadStartFieldReceivedBytes(v *OverloadStart) *aper.WireSpan  { return &v.receivedBytes }
func BridgeOverloadStartFieldReceivedLocation(v *OverloadStart) *aper.Location {
	return &v.receivedLocation
}
func BridgeOverloadStartFieldReplay(v *OverloadStart) *aper.Snapshot { return &v.replay }
func BridgeOverloadStartFieldStream(v *OverloadStart) *aper.WireSpan { return &v.stream }
func BridgeOverloadStartFieldWithoutReplay(v *OverloadStart) *bool   { return &v.withoutReplay }
func BridgeOverloadStartGUMMEIListIEBindingFieldCodec(v *OverloadStartGUMMEIListIEBinding) *s18.GUMMEIListValueCodec {
	return &v.codec
}
func BridgeOverloadStartGUMMEIListIEBindingFieldGet(v *OverloadStartGUMMEIListIEBinding) *func(*OverloadStartIEValue) (*s18.GUMMEIList, bool) {
	return &v.get
}
func BridgeOverloadStartGUMMEIListIEBindingFieldInfo(v *OverloadStartGUMMEIListIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeOverloadStartGUMMEIListIEBindingFieldInject(v *OverloadStartGUMMEIListIEBinding) *func(s18.GUMMEIList) OverloadStartIEValue {
	return &v.inject
}
func BridgeOverloadStartIEContainerAPERValueFieldContext(v *OverloadStartIEContainerAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeOverloadStartIEContainerAPERValueFieldReceived(v *OverloadStartIEContainerAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeOverloadStartIEContainerAPERValueFieldReplay(v *OverloadStartIEContainerAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeOverloadStartIEContainerAPERValueFieldWithoutReplay(v *OverloadStartIEContainerAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeOverloadStartIEContainerValueCodecFieldCapture(v *OverloadStartIEContainerValueCodec) *func(OverloadStartIEContainer, aper.DecodeState) (OverloadStartIEContainer, aper.Snapshot) {
	return &v.capture
}
func BridgeOverloadStartIEContainerValueCodecFieldCompare(v *OverloadStartIEContainerValueCodec) *func(OverloadStartIEContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeOverloadStartIEContainerValueCodecFieldContext(v *OverloadStartIEContainerValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeOverloadStartIEContainerValueCodecFieldDecode(v *OverloadStartIEContainerValueCodec) *func([]byte, aper.DecodeState) (OverloadStartIEContainer, error) {
	return &v.decode
}
func BridgeOverloadStartIEContainerValueCodecFieldEncode(v *OverloadStartIEContainerValueCodec) *func(OverloadStartIEContainer, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeOverloadStartIEContainerValueCodecFieldPath(v *OverloadStartIEContainerValueCodec) *aper.Path {
	return &v.path
}
func BridgeOverloadStartIEContainerValueCodecMethodEncodeBudgetValue(v OverloadStartIEContainerValueCodec, a0 OverloadStartIEContainer, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeOverloadStartIEContainerValueCodecMethodEncodeChanged(v OverloadStartIEContainerValueCodec, a0 OverloadStartIEContainer, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeOverloadStartIEFieldAPERValueFieldContext(v *OverloadStartIEFieldAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeOverloadStartIEFieldAPERValueFieldReceived(v *OverloadStartIEFieldAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeOverloadStartIEFieldAPERValueFieldReplay(v *OverloadStartIEFieldAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeOverloadStartIEFieldAPERValueFieldWithoutReplay(v *OverloadStartIEFieldAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeOverloadStartIEFieldFieldReceived(v *OverloadStartIEField) *aper.CompletePadding {
	return &v.received
}
func BridgeOverloadStartIEFieldFieldReplay(v *OverloadStartIEField) *aper.Snapshot { return &v.replay }
func BridgeOverloadStartIEFieldFieldStream(v *OverloadStartIEField) *aper.WireSpan { return &v.stream }
func BridgeOverloadStartIEFieldFieldWithoutReplay(v *OverloadStartIEField) *bool {
	return &v.withoutReplay
}
func BridgeOverloadStartIEFieldMethodMarshalAPERTo(v *OverloadStartIEField, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeOverloadStartIEFieldMethodUnmarshalAPERFrom(v *OverloadStartIEField, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeOverloadStartIEFieldValueCodecFieldCapture(v *OverloadStartIEFieldValueCodec) *func(OverloadStartIEField, aper.DecodeState) (OverloadStartIEField, aper.Snapshot) {
	return &v.capture
}
func BridgeOverloadStartIEFieldValueCodecFieldCompare(v *OverloadStartIEFieldValueCodec) *func(OverloadStartIEField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeOverloadStartIEFieldValueCodecFieldContext(v *OverloadStartIEFieldValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeOverloadStartIEFieldValueCodecFieldDecode(v *OverloadStartIEFieldValueCodec) *func([]byte, aper.DecodeState) (OverloadStartIEField, error) {
	return &v.decode
}
func BridgeOverloadStartIEFieldValueCodecFieldEncode(v *OverloadStartIEFieldValueCodec) *func(OverloadStartIEField, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeOverloadStartIEFieldValueCodecFieldPath(v *OverloadStartIEFieldValueCodec) *aper.Path {
	return &v.path
}
func BridgeOverloadStartIEFieldValueCodecMethodEncodeBudgetValue(v OverloadStartIEFieldValueCodec, a0 OverloadStartIEField, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeOverloadStartIEFieldValueCodecMethodEncodeChanged(v OverloadStartIEFieldValueCodec, a0 OverloadStartIEField, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeOverloadStartIETableMethodInfoGUMMEIList(v OverloadStartIETable) s00.FieldInfo {
	return v.infoGUMMEIList()
}
func BridgeOverloadStartIETableMethodInfoOverloadResponse(v OverloadStartIETable) s00.FieldInfo {
	return v.infoOverloadResponse()
}
func BridgeOverloadStartIETableMethodInfoTrafficLoadReductionIndication(v OverloadStartIETable) s00.FieldInfo {
	return v.infoTrafficLoadReductionIndication()
}
func BridgeOverloadStartIEValueERABIEContainerListAPERValueFieldContext(v *OverloadStartIEValueERABIEContainerListAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeOverloadStartIEValueERABIEContainerListAPERValueFieldReceived(v *OverloadStartIEValueERABIEContainerListAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeOverloadStartIEValueERABIEContainerListAPERValueFieldReplay(v *OverloadStartIEValueERABIEContainerListAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeOverloadStartIEValueERABIEContainerListAPERValueFieldWithoutReplay(v *OverloadStartIEValueERABIEContainerListAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeOverloadStartIEValueERABIEContainerListValueCodecFieldCapture(v *OverloadStartIEValueERABIEContainerListValueCodec) *func(OverloadStartIEValueERABIEContainerList, aper.DecodeState) (OverloadStartIEValueERABIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgeOverloadStartIEValueERABIEContainerListValueCodecFieldCompare(v *OverloadStartIEValueERABIEContainerListValueCodec) *func(OverloadStartIEValueERABIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeOverloadStartIEValueERABIEContainerListValueCodecFieldContext(v *OverloadStartIEValueERABIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeOverloadStartIEValueERABIEContainerListValueCodecFieldDecode(v *OverloadStartIEValueERABIEContainerListValueCodec) *func([]byte, aper.DecodeState) (OverloadStartIEValueERABIEContainerList, error) {
	return &v.decode
}
func BridgeOverloadStartIEValueERABIEContainerListValueCodecFieldEncode(v *OverloadStartIEValueERABIEContainerListValueCodec) *func(OverloadStartIEValueERABIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeOverloadStartIEValueERABIEContainerListValueCodecFieldPath(v *OverloadStartIEValueERABIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgeOverloadStartIEValueERABIEContainerListValueCodecMethodEncodeBudgetValue(v OverloadStartIEValueERABIEContainerListValueCodec, a0 OverloadStartIEValueERABIEContainerList, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeOverloadStartIEValueERABIEContainerListValueCodecMethodEncodeChanged(v OverloadStartIEValueERABIEContainerListValueCodec, a0 OverloadStartIEValueERABIEContainerList, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeOverloadStartIEValueFieldId(v *OverloadStartIEValue) *s00.ProtocolIEID { return &v.id }
func BridgeOverloadStartIEValueFieldIsOpaque(v *OverloadStartIEValue) *bool       { return &v.isOpaque }
func BridgeOverloadStartIEValueFieldOpaque(v *OverloadStartIEValue) *aper.OpaqueOpenType {
	return &v.opaque
}
func BridgeOverloadStartIEValueFieldReceived(v *OverloadStartIEValue) *aper.WireSpan {
	return &v.received
}
func BridgeOverloadStartIEValueFieldReplay(v *OverloadStartIEValue) *aper.Snapshot { return &v.replay }
func BridgeOverloadStartIEValueFieldRowGUMMEIList(v *OverloadStartIEValue) **s18.GUMMEIList {
	return &v.rowGUMMEIList
}
func BridgeOverloadStartIEValueFieldRowOverloadResponse(v *OverloadStartIEValue) **s20.OverloadResponse {
	return &v.rowOverloadResponse
}
func BridgeOverloadStartIEValueFieldRowTrafficLoadReductionIndication(v *OverloadStartIEValue) **s00.TrafficLoadReductionIndication {
	return &v.rowTrafficLoadReductionIndication
}
func BridgeOverloadStartIEValueMethodCaptureSemantics(v OverloadStartIEValue, a0 aper.SemanticCapture) OverloadStartIEValue {
	return v.captureSemantics(a0)
}
func BridgeOverloadStartIEValueMethodCompareSemantics(v OverloadStartIEValue, a0 aper.SemanticComparison) aper.SemanticComparison {
	return v.compareSemantics(a0)
}
func BridgeOverloadStartIEValueMethodDecode(v OverloadStartIEValue, a0 s00.ProtocolIEID, a1 aper.OpaqueOpenType) (OverloadStartIEValue, error) {
	return v.decode(a0, a1)
}
func BridgeOverloadStartIEValueMethodEncode(v OverloadStartIEValue) ([]byte, error) {
	return v.encode()
}
func BridgeOverloadStartIEValueMethodEncodeFresh(v OverloadStartIEValue, a0 bool, a1 *aper.DecodeBudget) ([]byte, error) {
	return v.encodeFresh(a0, a1)
}
func BridgeOverloadStartIEValueMethodMatchesID(v OverloadStartIEValue, a0 s00.ProtocolIEID, a1 ...*aper.DecodeBudget) bool {
	return v.matchesID(a0, a1...)
}
func BridgeOverloadStartIEValueMethodReason(v OverloadStartIEValue, a0 s00.ProtocolIEID) aper.OpaqueReason {
	return v.reason(a0)
}
func BridgeOverloadStartIEValueMethodRule(v OverloadStartIEValue) aper.SourceRule { return v.rule() }
func BridgeOverloadStartIEValueProtocolErrorIEContainerListAPERValueFieldContext(v *OverloadStartIEValueProtocolErrorIEContainerListAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeOverloadStartIEValueProtocolErrorIEContainerListAPERValueFieldReceived(v *OverloadStartIEValueProtocolErrorIEContainerListAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeOverloadStartIEValueProtocolErrorIEContainerListAPERValueFieldReplay(v *OverloadStartIEValueProtocolErrorIEContainerListAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeOverloadStartIEValueProtocolErrorIEContainerListAPERValueFieldWithoutReplay(v *OverloadStartIEValueProtocolErrorIEContainerListAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeOverloadStartIEValueProtocolErrorIEContainerListValueCodecFieldCapture(v *OverloadStartIEValueProtocolErrorIEContainerListValueCodec) *func(OverloadStartIEValueProtocolErrorIEContainerList, aper.DecodeState) (OverloadStartIEValueProtocolErrorIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgeOverloadStartIEValueProtocolErrorIEContainerListValueCodecFieldCompare(v *OverloadStartIEValueProtocolErrorIEContainerListValueCodec) *func(OverloadStartIEValueProtocolErrorIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeOverloadStartIEValueProtocolErrorIEContainerListValueCodecFieldContext(v *OverloadStartIEValueProtocolErrorIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeOverloadStartIEValueProtocolErrorIEContainerListValueCodecFieldDecode(v *OverloadStartIEValueProtocolErrorIEContainerListValueCodec) *func([]byte, aper.DecodeState) (OverloadStartIEValueProtocolErrorIEContainerList, error) {
	return &v.decode
}
func BridgeOverloadStartIEValueProtocolErrorIEContainerListValueCodecFieldEncode(v *OverloadStartIEValueProtocolErrorIEContainerListValueCodec) *func(OverloadStartIEValueProtocolErrorIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeOverloadStartIEValueProtocolErrorIEContainerListValueCodecFieldPath(v *OverloadStartIEValueProtocolErrorIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgeOverloadStartIEValueProtocolErrorIEContainerListValueCodecMethodEncodeBudgetValue(v OverloadStartIEValueProtocolErrorIEContainerListValueCodec, a0 OverloadStartIEValueProtocolErrorIEContainerList, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeOverloadStartIEValueProtocolErrorIEContainerListValueCodecMethodEncodeChanged(v OverloadStartIEValueProtocolErrorIEContainerListValueCodec, a0 OverloadStartIEValueProtocolErrorIEContainerList, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeOverloadStartIEValueProtocolIEContainerListAPERValueFieldContext(v *OverloadStartIEValueProtocolIEContainerListAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeOverloadStartIEValueProtocolIEContainerListAPERValueFieldReceived(v *OverloadStartIEValueProtocolIEContainerListAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeOverloadStartIEValueProtocolIEContainerListAPERValueFieldReplay(v *OverloadStartIEValueProtocolIEContainerListAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeOverloadStartIEValueProtocolIEContainerListAPERValueFieldWithoutReplay(v *OverloadStartIEValueProtocolIEContainerListAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeOverloadStartIEValueProtocolIEContainerListValueCodecFieldCapture(v *OverloadStartIEValueProtocolIEContainerListValueCodec) *func(OverloadStartIEValueProtocolIEContainerList, aper.DecodeState) (OverloadStartIEValueProtocolIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgeOverloadStartIEValueProtocolIEContainerListValueCodecFieldCompare(v *OverloadStartIEValueProtocolIEContainerListValueCodec) *func(OverloadStartIEValueProtocolIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeOverloadStartIEValueProtocolIEContainerListValueCodecFieldContext(v *OverloadStartIEValueProtocolIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeOverloadStartIEValueProtocolIEContainerListValueCodecFieldDecode(v *OverloadStartIEValueProtocolIEContainerListValueCodec) *func([]byte, aper.DecodeState) (OverloadStartIEValueProtocolIEContainerList, error) {
	return &v.decode
}
func BridgeOverloadStartIEValueProtocolIEContainerListValueCodecFieldEncode(v *OverloadStartIEValueProtocolIEContainerListValueCodec) *func(OverloadStartIEValueProtocolIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeOverloadStartIEValueProtocolIEContainerListValueCodecFieldPath(v *OverloadStartIEValueProtocolIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgeOverloadStartIEValueProtocolIEContainerListValueCodecMethodEncodeBudgetValue(v OverloadStartIEValueProtocolIEContainerListValueCodec, a0 OverloadStartIEValueProtocolIEContainerList, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeOverloadStartIEValueProtocolIEContainerListValueCodecMethodEncodeChanged(v OverloadStartIEValueProtocolIEContainerListValueCodec, a0 OverloadStartIEValueProtocolIEContainerList, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeOverloadStartMethodMarshalAPERBudget(v *OverloadStart, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeOverloadStartMethodMarshalAPERBudgetValue(v *OverloadStart, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudgetValue(a0, a1)
}
func BridgeOverloadStartMethodMarshalAPERChanged(v *OverloadStart, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeOverloadStartMethodMarshalAPERChangedValue(v *OverloadStart, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeOverloadStartMethodMarshalAPERLegacy(v *OverloadStart) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeOverloadStartMethodMarshalAPERNewValue(v *OverloadStart, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERNewValue(a0, a1)
}
func BridgeOverloadStartMethodMarshalAPERPlanned(v *OverloadStart, a0 *aper.DecodeBudget, a1 bool, a2 *aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1, a2)
}
func BridgeOverloadStartMethodMarshalAPERTo(v *OverloadStart, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeOverloadStartMethodUnmarshalAPERFrom(v *OverloadStart, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeOverloadStartMethodUnmarshalAPERLegacy(v *OverloadStart, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeOverloadStartMethodUnmarshalAPERWithOptions(v *OverloadStart, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeOverloadStartOverloadResponseIEBindingFieldCodec(v *OverloadStartOverloadResponseIEBinding) *s20.OverloadResponseValueCodec {
	return &v.codec
}
func BridgeOverloadStartOverloadResponseIEBindingFieldGet(v *OverloadStartOverloadResponseIEBinding) *func(*OverloadStartIEValue) (*s20.OverloadResponse, bool) {
	return &v.get
}
func BridgeOverloadStartOverloadResponseIEBindingFieldInfo(v *OverloadStartOverloadResponseIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeOverloadStartOverloadResponseIEBindingFieldInject(v *OverloadStartOverloadResponseIEBinding) *func(s20.OverloadResponse) OverloadStartIEValue {
	return &v.inject
}
func BridgeOverloadStartTrafficLoadReductionIndicationIEBindingFieldCodec(v *OverloadStartTrafficLoadReductionIndicationIEBinding) *s02.TrafficLoadReductionIndicationValueCodec {
	return &v.codec
}
func BridgeOverloadStartTrafficLoadReductionIndicationIEBindingFieldGet(v *OverloadStartTrafficLoadReductionIndicationIEBinding) *func(*OverloadStartIEValue) (*s00.TrafficLoadReductionIndication, bool) {
	return &v.get
}
func BridgeOverloadStartTrafficLoadReductionIndicationIEBindingFieldInfo(v *OverloadStartTrafficLoadReductionIndicationIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeOverloadStartTrafficLoadReductionIndicationIEBindingFieldInject(v *OverloadStartTrafficLoadReductionIndicationIEBinding) *func(s00.TrafficLoadReductionIndication) OverloadStartIEValue {
	return &v.inject
}
func BridgeOverloadStartValueCodecFieldCapture(v *OverloadStartValueCodec) *func(OverloadStart, aper.DecodeState) (OverloadStart, aper.Snapshot) {
	return &v.capture
}
func BridgeOverloadStartValueCodecFieldCompare(v *OverloadStartValueCodec) *func(OverloadStart, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeOverloadStartValueCodecFieldContext(v *OverloadStartValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeOverloadStartValueCodecFieldDecode(v *OverloadStartValueCodec) *func([]byte, aper.DecodeState) (OverloadStart, error) {
	return &v.decode
}
func BridgeOverloadStartValueCodecFieldEncode(v *OverloadStartValueCodec) *func(OverloadStart, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeOverloadStartValueCodecFieldPath(v *OverloadStartValueCodec) *aper.Path { return &v.path }
func BridgeOverloadStartValueCodecMethodEncodeBudgetValue(v OverloadStartValueCodec, a0 OverloadStart, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeOverloadStartValueCodecMethodEncodeChanged(v OverloadStartValueCodec, a0 OverloadStart, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeOverloadStopAPERValueFieldContext(v *OverloadStopAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeOverloadStopAPERValueFieldReceived(v *OverloadStopAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeOverloadStopAPERValueFieldReplay(v *OverloadStopAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeOverloadStopAPERValueFieldWithoutReplay(v *OverloadStopAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeOverloadStopFieldExtCount(v *OverloadStop) *int64                { return &v.extCount }
func BridgeOverloadStopFieldExtData(v *OverloadStop) *[][]byte              { return &v.extData }
func BridgeOverloadStopFieldExtOrigin(v *OverloadStop) *[]aper.OpaqueOrigin { return &v.extOrigin }
func BridgeOverloadStopFieldExtPresent(v *OverloadStop) *[]bool             { return &v.extPresent }
func BridgeOverloadStopFieldExtWire(v *OverloadStop) *[]aper.WireSpan       { return &v.extWire }
func BridgeOverloadStopFieldPerExtPadding(v *OverloadStop) *[]aper.CompletePadding {
	return &v.perExtPadding
}
func BridgeOverloadStopFieldPerPadding(v *OverloadStop) *aper.FinalPadding { return &v.perPadding }
func BridgeOverloadStopFieldProtocolIEsIndef(v *OverloadStop) *bool        { return &v.protocolIEsIndef }
func BridgeOverloadStopFieldReceived(v *OverloadStop) *bool                { return &v.received }
func BridgeOverloadStopFieldReceivedAbsolute(v *OverloadStop) *bool        { return &v.receivedAbsolute }
func BridgeOverloadStopFieldReceivedBytes(v *OverloadStop) *aper.WireSpan  { return &v.receivedBytes }
func BridgeOverloadStopFieldReceivedLocation(v *OverloadStop) *aper.Location {
	return &v.receivedLocation
}
func BridgeOverloadStopFieldReplay(v *OverloadStop) *aper.Snapshot { return &v.replay }
func BridgeOverloadStopFieldStream(v *OverloadStop) *aper.WireSpan { return &v.stream }
func BridgeOverloadStopFieldWithoutReplay(v *OverloadStop) *bool   { return &v.withoutReplay }
func BridgeOverloadStopGUMMEIListIEBindingFieldCodec(v *OverloadStopGUMMEIListIEBinding) *s18.GUMMEIListValueCodec {
	return &v.codec
}
func BridgeOverloadStopGUMMEIListIEBindingFieldGet(v *OverloadStopGUMMEIListIEBinding) *func(*OverloadStopIEValue) (*s18.GUMMEIList, bool) {
	return &v.get
}
func BridgeOverloadStopGUMMEIListIEBindingFieldInfo(v *OverloadStopGUMMEIListIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeOverloadStopGUMMEIListIEBindingFieldInject(v *OverloadStopGUMMEIListIEBinding) *func(s18.GUMMEIList) OverloadStopIEValue {
	return &v.inject
}
func BridgeOverloadStopIEContainerAPERValueFieldContext(v *OverloadStopIEContainerAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeOverloadStopIEContainerAPERValueFieldReceived(v *OverloadStopIEContainerAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeOverloadStopIEContainerAPERValueFieldReplay(v *OverloadStopIEContainerAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeOverloadStopIEContainerAPERValueFieldWithoutReplay(v *OverloadStopIEContainerAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeOverloadStopIEContainerValueCodecFieldCapture(v *OverloadStopIEContainerValueCodec) *func(OverloadStopIEContainer, aper.DecodeState) (OverloadStopIEContainer, aper.Snapshot) {
	return &v.capture
}
func BridgeOverloadStopIEContainerValueCodecFieldCompare(v *OverloadStopIEContainerValueCodec) *func(OverloadStopIEContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeOverloadStopIEContainerValueCodecFieldContext(v *OverloadStopIEContainerValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeOverloadStopIEContainerValueCodecFieldDecode(v *OverloadStopIEContainerValueCodec) *func([]byte, aper.DecodeState) (OverloadStopIEContainer, error) {
	return &v.decode
}
func BridgeOverloadStopIEContainerValueCodecFieldEncode(v *OverloadStopIEContainerValueCodec) *func(OverloadStopIEContainer, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeOverloadStopIEContainerValueCodecFieldPath(v *OverloadStopIEContainerValueCodec) *aper.Path {
	return &v.path
}
func BridgeOverloadStopIEContainerValueCodecMethodEncodeBudgetValue(v OverloadStopIEContainerValueCodec, a0 OverloadStopIEContainer, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeOverloadStopIEContainerValueCodecMethodEncodeChanged(v OverloadStopIEContainerValueCodec, a0 OverloadStopIEContainer, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeOverloadStopIEFieldAPERValueFieldContext(v *OverloadStopIEFieldAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeOverloadStopIEFieldAPERValueFieldReceived(v *OverloadStopIEFieldAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeOverloadStopIEFieldAPERValueFieldReplay(v *OverloadStopIEFieldAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeOverloadStopIEFieldAPERValueFieldWithoutReplay(v *OverloadStopIEFieldAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeOverloadStopIEFieldFieldReceived(v *OverloadStopIEField) *aper.CompletePadding {
	return &v.received
}
func BridgeOverloadStopIEFieldFieldReplay(v *OverloadStopIEField) *aper.Snapshot { return &v.replay }
func BridgeOverloadStopIEFieldFieldStream(v *OverloadStopIEField) *aper.WireSpan { return &v.stream }
func BridgeOverloadStopIEFieldFieldWithoutReplay(v *OverloadStopIEField) *bool {
	return &v.withoutReplay
}
func BridgeOverloadStopIEFieldMethodMarshalAPERTo(v *OverloadStopIEField, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeOverloadStopIEFieldMethodUnmarshalAPERFrom(v *OverloadStopIEField, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeOverloadStopIEFieldValueCodecFieldCapture(v *OverloadStopIEFieldValueCodec) *func(OverloadStopIEField, aper.DecodeState) (OverloadStopIEField, aper.Snapshot) {
	return &v.capture
}
func BridgeOverloadStopIEFieldValueCodecFieldCompare(v *OverloadStopIEFieldValueCodec) *func(OverloadStopIEField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeOverloadStopIEFieldValueCodecFieldContext(v *OverloadStopIEFieldValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeOverloadStopIEFieldValueCodecFieldDecode(v *OverloadStopIEFieldValueCodec) *func([]byte, aper.DecodeState) (OverloadStopIEField, error) {
	return &v.decode
}
func BridgeOverloadStopIEFieldValueCodecFieldEncode(v *OverloadStopIEFieldValueCodec) *func(OverloadStopIEField, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeOverloadStopIEFieldValueCodecFieldPath(v *OverloadStopIEFieldValueCodec) *aper.Path {
	return &v.path
}
func BridgeOverloadStopIEFieldValueCodecMethodEncodeBudgetValue(v OverloadStopIEFieldValueCodec, a0 OverloadStopIEField, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeOverloadStopIEFieldValueCodecMethodEncodeChanged(v OverloadStopIEFieldValueCodec, a0 OverloadStopIEField, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeOverloadStopIETableMethodInfoGUMMEIList(v OverloadStopIETable) s00.FieldInfo {
	return v.infoGUMMEIList()
}
func BridgeOverloadStopIEValueERABIEContainerListAPERValueFieldContext(v *OverloadStopIEValueERABIEContainerListAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeOverloadStopIEValueERABIEContainerListAPERValueFieldReceived(v *OverloadStopIEValueERABIEContainerListAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeOverloadStopIEValueERABIEContainerListAPERValueFieldReplay(v *OverloadStopIEValueERABIEContainerListAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeOverloadStopIEValueERABIEContainerListAPERValueFieldWithoutReplay(v *OverloadStopIEValueERABIEContainerListAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeOverloadStopIEValueERABIEContainerListValueCodecFieldCapture(v *OverloadStopIEValueERABIEContainerListValueCodec) *func(OverloadStopIEValueERABIEContainerList, aper.DecodeState) (OverloadStopIEValueERABIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgeOverloadStopIEValueERABIEContainerListValueCodecFieldCompare(v *OverloadStopIEValueERABIEContainerListValueCodec) *func(OverloadStopIEValueERABIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeOverloadStopIEValueERABIEContainerListValueCodecFieldContext(v *OverloadStopIEValueERABIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeOverloadStopIEValueERABIEContainerListValueCodecFieldDecode(v *OverloadStopIEValueERABIEContainerListValueCodec) *func([]byte, aper.DecodeState) (OverloadStopIEValueERABIEContainerList, error) {
	return &v.decode
}
func BridgeOverloadStopIEValueERABIEContainerListValueCodecFieldEncode(v *OverloadStopIEValueERABIEContainerListValueCodec) *func(OverloadStopIEValueERABIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeOverloadStopIEValueERABIEContainerListValueCodecFieldPath(v *OverloadStopIEValueERABIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgeOverloadStopIEValueERABIEContainerListValueCodecMethodEncodeBudgetValue(v OverloadStopIEValueERABIEContainerListValueCodec, a0 OverloadStopIEValueERABIEContainerList, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeOverloadStopIEValueERABIEContainerListValueCodecMethodEncodeChanged(v OverloadStopIEValueERABIEContainerListValueCodec, a0 OverloadStopIEValueERABIEContainerList, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeOverloadStopIEValueFieldId(v *OverloadStopIEValue) *s00.ProtocolIEID { return &v.id }
func BridgeOverloadStopIEValueFieldIsOpaque(v *OverloadStopIEValue) *bool       { return &v.isOpaque }
func BridgeOverloadStopIEValueFieldOpaque(v *OverloadStopIEValue) *aper.OpaqueOpenType {
	return &v.opaque
}
func BridgeOverloadStopIEValueFieldReceived(v *OverloadStopIEValue) *aper.WireSpan {
	return &v.received
}
func BridgeOverloadStopIEValueFieldReplay(v *OverloadStopIEValue) *aper.Snapshot { return &v.replay }
func BridgeOverloadStopIEValueFieldRowGUMMEIList(v *OverloadStopIEValue) **s18.GUMMEIList {
	return &v.rowGUMMEIList
}
func BridgeOverloadStopIEValueMethodCaptureSemantics(v OverloadStopIEValue, a0 aper.SemanticCapture) OverloadStopIEValue {
	return v.captureSemantics(a0)
}
func BridgeOverloadStopIEValueMethodCompareSemantics(v OverloadStopIEValue, a0 aper.SemanticComparison) aper.SemanticComparison {
	return v.compareSemantics(a0)
}
func BridgeOverloadStopIEValueMethodDecode(v OverloadStopIEValue, a0 s00.ProtocolIEID, a1 aper.OpaqueOpenType) (OverloadStopIEValue, error) {
	return v.decode(a0, a1)
}
func BridgeOverloadStopIEValueMethodEncode(v OverloadStopIEValue) ([]byte, error) { return v.encode() }
func BridgeOverloadStopIEValueMethodEncodeFresh(v OverloadStopIEValue, a0 bool, a1 *aper.DecodeBudget) ([]byte, error) {
	return v.encodeFresh(a0, a1)
}
func BridgeOverloadStopIEValueMethodMatchesID(v OverloadStopIEValue, a0 s00.ProtocolIEID, a1 ...*aper.DecodeBudget) bool {
	return v.matchesID(a0, a1...)
}
func BridgeOverloadStopIEValueMethodReason(v OverloadStopIEValue, a0 s00.ProtocolIEID) aper.OpaqueReason {
	return v.reason(a0)
}
func BridgeOverloadStopIEValueMethodRule(v OverloadStopIEValue) aper.SourceRule { return v.rule() }
func BridgeOverloadStopIEValueProtocolErrorIEContainerListAPERValueFieldContext(v *OverloadStopIEValueProtocolErrorIEContainerListAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeOverloadStopIEValueProtocolErrorIEContainerListAPERValueFieldReceived(v *OverloadStopIEValueProtocolErrorIEContainerListAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeOverloadStopIEValueProtocolErrorIEContainerListAPERValueFieldReplay(v *OverloadStopIEValueProtocolErrorIEContainerListAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeOverloadStopIEValueProtocolErrorIEContainerListAPERValueFieldWithoutReplay(v *OverloadStopIEValueProtocolErrorIEContainerListAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeOverloadStopIEValueProtocolErrorIEContainerListValueCodecFieldCapture(v *OverloadStopIEValueProtocolErrorIEContainerListValueCodec) *func(OverloadStopIEValueProtocolErrorIEContainerList, aper.DecodeState) (OverloadStopIEValueProtocolErrorIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgeOverloadStopIEValueProtocolErrorIEContainerListValueCodecFieldCompare(v *OverloadStopIEValueProtocolErrorIEContainerListValueCodec) *func(OverloadStopIEValueProtocolErrorIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeOverloadStopIEValueProtocolErrorIEContainerListValueCodecFieldContext(v *OverloadStopIEValueProtocolErrorIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeOverloadStopIEValueProtocolErrorIEContainerListValueCodecFieldDecode(v *OverloadStopIEValueProtocolErrorIEContainerListValueCodec) *func([]byte, aper.DecodeState) (OverloadStopIEValueProtocolErrorIEContainerList, error) {
	return &v.decode
}
func BridgeOverloadStopIEValueProtocolErrorIEContainerListValueCodecFieldEncode(v *OverloadStopIEValueProtocolErrorIEContainerListValueCodec) *func(OverloadStopIEValueProtocolErrorIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeOverloadStopIEValueProtocolErrorIEContainerListValueCodecFieldPath(v *OverloadStopIEValueProtocolErrorIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgeOverloadStopIEValueProtocolErrorIEContainerListValueCodecMethodEncodeBudgetValue(v OverloadStopIEValueProtocolErrorIEContainerListValueCodec, a0 OverloadStopIEValueProtocolErrorIEContainerList, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeOverloadStopIEValueProtocolErrorIEContainerListValueCodecMethodEncodeChanged(v OverloadStopIEValueProtocolErrorIEContainerListValueCodec, a0 OverloadStopIEValueProtocolErrorIEContainerList, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeOverloadStopIEValueProtocolIEContainerListAPERValueFieldContext(v *OverloadStopIEValueProtocolIEContainerListAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeOverloadStopIEValueProtocolIEContainerListAPERValueFieldReceived(v *OverloadStopIEValueProtocolIEContainerListAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeOverloadStopIEValueProtocolIEContainerListAPERValueFieldReplay(v *OverloadStopIEValueProtocolIEContainerListAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeOverloadStopIEValueProtocolIEContainerListAPERValueFieldWithoutReplay(v *OverloadStopIEValueProtocolIEContainerListAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeOverloadStopIEValueProtocolIEContainerListValueCodecFieldCapture(v *OverloadStopIEValueProtocolIEContainerListValueCodec) *func(OverloadStopIEValueProtocolIEContainerList, aper.DecodeState) (OverloadStopIEValueProtocolIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgeOverloadStopIEValueProtocolIEContainerListValueCodecFieldCompare(v *OverloadStopIEValueProtocolIEContainerListValueCodec) *func(OverloadStopIEValueProtocolIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeOverloadStopIEValueProtocolIEContainerListValueCodecFieldContext(v *OverloadStopIEValueProtocolIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeOverloadStopIEValueProtocolIEContainerListValueCodecFieldDecode(v *OverloadStopIEValueProtocolIEContainerListValueCodec) *func([]byte, aper.DecodeState) (OverloadStopIEValueProtocolIEContainerList, error) {
	return &v.decode
}
func BridgeOverloadStopIEValueProtocolIEContainerListValueCodecFieldEncode(v *OverloadStopIEValueProtocolIEContainerListValueCodec) *func(OverloadStopIEValueProtocolIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeOverloadStopIEValueProtocolIEContainerListValueCodecFieldPath(v *OverloadStopIEValueProtocolIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgeOverloadStopIEValueProtocolIEContainerListValueCodecMethodEncodeBudgetValue(v OverloadStopIEValueProtocolIEContainerListValueCodec, a0 OverloadStopIEValueProtocolIEContainerList, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeOverloadStopIEValueProtocolIEContainerListValueCodecMethodEncodeChanged(v OverloadStopIEValueProtocolIEContainerListValueCodec, a0 OverloadStopIEValueProtocolIEContainerList, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeOverloadStopMethodMarshalAPERBudget(v *OverloadStop, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeOverloadStopMethodMarshalAPERBudgetValue(v *OverloadStop, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudgetValue(a0, a1)
}
func BridgeOverloadStopMethodMarshalAPERChanged(v *OverloadStop, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeOverloadStopMethodMarshalAPERChangedValue(v *OverloadStop, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeOverloadStopMethodMarshalAPERLegacy(v *OverloadStop) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeOverloadStopMethodMarshalAPERNewValue(v *OverloadStop, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERNewValue(a0, a1)
}
func BridgeOverloadStopMethodMarshalAPERPlanned(v *OverloadStop, a0 *aper.DecodeBudget, a1 bool, a2 *aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1, a2)
}
func BridgeOverloadStopMethodMarshalAPERTo(v *OverloadStop, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeOverloadStopMethodUnmarshalAPERFrom(v *OverloadStop, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeOverloadStopMethodUnmarshalAPERLegacy(v *OverloadStop, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeOverloadStopMethodUnmarshalAPERWithOptions(v *OverloadStop, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeOverloadStopValueCodecFieldCapture(v *OverloadStopValueCodec) *func(OverloadStop, aper.DecodeState) (OverloadStop, aper.Snapshot) {
	return &v.capture
}
func BridgeOverloadStopValueCodecFieldCompare(v *OverloadStopValueCodec) *func(OverloadStop, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeOverloadStopValueCodecFieldContext(v *OverloadStopValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeOverloadStopValueCodecFieldDecode(v *OverloadStopValueCodec) *func([]byte, aper.DecodeState) (OverloadStop, error) {
	return &v.decode
}
func BridgeOverloadStopValueCodecFieldEncode(v *OverloadStopValueCodec) *func(OverloadStop, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeOverloadStopValueCodecFieldPath(v *OverloadStopValueCodec) *aper.Path { return &v.path }
func BridgeOverloadStopValueCodecMethodEncodeBudgetValue(v OverloadStopValueCodec, a0 OverloadStop, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeOverloadStopValueCodecMethodEncodeChanged(v OverloadStopValueCodec, a0 OverloadStop, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
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
func BridgeSourceeNBToTargeteNBTransparentContainerAPERValueFieldContext(v *SourceeNBToTargeteNBTransparentContainerAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeSourceeNBToTargeteNBTransparentContainerAPERValueFieldReceived(v *SourceeNBToTargeteNBTransparentContainerAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeSourceeNBToTargeteNBTransparentContainerAPERValueFieldReplay(v *SourceeNBToTargeteNBTransparentContainerAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeSourceeNBToTargeteNBTransparentContainerAPERValueFieldWithoutReplay(v *SourceeNBToTargeteNBTransparentContainerAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeSourceeNBToTargeteNBTransparentContainerFieldERABInformationListIndef(v *SourceeNBToTargeteNBTransparentContainer) *bool {
	return &v.eRABInformationListIndef
}
func BridgeSourceeNBToTargeteNBTransparentContainerFieldExtCount(v *SourceeNBToTargeteNBTransparentContainer) *int64 {
	return &v.extCount
}
func BridgeSourceeNBToTargeteNBTransparentContainerFieldExtData(v *SourceeNBToTargeteNBTransparentContainer) *[][]byte {
	return &v.extData
}
func BridgeSourceeNBToTargeteNBTransparentContainerFieldExtOrigin(v *SourceeNBToTargeteNBTransparentContainer) *[]aper.OpaqueOrigin {
	return &v.extOrigin
}
func BridgeSourceeNBToTargeteNBTransparentContainerFieldExtPresent(v *SourceeNBToTargeteNBTransparentContainer) *[]bool {
	return &v.extPresent
}
func BridgeSourceeNBToTargeteNBTransparentContainerFieldExtWire(v *SourceeNBToTargeteNBTransparentContainer) *[]aper.WireSpan {
	return &v.extWire
}
func BridgeSourceeNBToTargeteNBTransparentContainerFieldIEExtensionsIndef(v *SourceeNBToTargeteNBTransparentContainer) *bool {
	return &v.iEExtensionsIndef
}
func BridgeSourceeNBToTargeteNBTransparentContainerFieldPerExtPadding(v *SourceeNBToTargeteNBTransparentContainer) *[]aper.CompletePadding {
	return &v.perExtPadding
}
func BridgeSourceeNBToTargeteNBTransparentContainerFieldPerPadding(v *SourceeNBToTargeteNBTransparentContainer) *aper.FinalPadding {
	return &v.perPadding
}
func BridgeSourceeNBToTargeteNBTransparentContainerFieldReceived(v *SourceeNBToTargeteNBTransparentContainer) *bool {
	return &v.received
}
func BridgeSourceeNBToTargeteNBTransparentContainerFieldReceivedAbsolute(v *SourceeNBToTargeteNBTransparentContainer) *bool {
	return &v.receivedAbsolute
}
func BridgeSourceeNBToTargeteNBTransparentContainerFieldReceivedBytes(v *SourceeNBToTargeteNBTransparentContainer) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeSourceeNBToTargeteNBTransparentContainerFieldReceivedLocation(v *SourceeNBToTargeteNBTransparentContainer) *aper.Location {
	return &v.receivedLocation
}
func BridgeSourceeNBToTargeteNBTransparentContainerFieldReplay(v *SourceeNBToTargeteNBTransparentContainer) *aper.Snapshot {
	return &v.replay
}
func BridgeSourceeNBToTargeteNBTransparentContainerFieldStream(v *SourceeNBToTargeteNBTransparentContainer) *aper.WireSpan {
	return &v.stream
}
func BridgeSourceeNBToTargeteNBTransparentContainerFieldUEHistoryInformationIndef(v *SourceeNBToTargeteNBTransparentContainer) *bool {
	return &v.uEHistoryInformationIndef
}
func BridgeSourceeNBToTargeteNBTransparentContainerFieldWithoutReplay(v *SourceeNBToTargeteNBTransparentContainer) *bool {
	return &v.withoutReplay
}
func BridgeSourceeNBToTargeteNBTransparentContainerMethodMarshalAPERBudget(v *SourceeNBToTargeteNBTransparentContainer, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeSourceeNBToTargeteNBTransparentContainerMethodMarshalAPERBudgetValue(v *SourceeNBToTargeteNBTransparentContainer, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudgetValue(a0, a1)
}
func BridgeSourceeNBToTargeteNBTransparentContainerMethodMarshalAPERChanged(v *SourceeNBToTargeteNBTransparentContainer, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeSourceeNBToTargeteNBTransparentContainerMethodMarshalAPERChangedValue(v *SourceeNBToTargeteNBTransparentContainer, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeSourceeNBToTargeteNBTransparentContainerMethodMarshalAPERLegacy(v *SourceeNBToTargeteNBTransparentContainer) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeSourceeNBToTargeteNBTransparentContainerMethodMarshalAPERNewValue(v *SourceeNBToTargeteNBTransparentContainer, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERNewValue(a0, a1)
}
func BridgeSourceeNBToTargeteNBTransparentContainerMethodMarshalAPERPlanned(v *SourceeNBToTargeteNBTransparentContainer, a0 *aper.DecodeBudget, a1 bool, a2 *aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1, a2)
}
func BridgeSourceeNBToTargeteNBTransparentContainerMethodMarshalAPERTo(v *SourceeNBToTargeteNBTransparentContainer, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeSourceeNBToTargeteNBTransparentContainerMethodUnmarshalAPERFrom(v *SourceeNBToTargeteNBTransparentContainer, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeSourceeNBToTargeteNBTransparentContainerMethodUnmarshalAPERLegacy(v *SourceeNBToTargeteNBTransparentContainer, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeSourceeNBToTargeteNBTransparentContainerMethodUnmarshalAPERWithOptions(v *SourceeNBToTargeteNBTransparentContainer, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeSourceeNBToTargeteNBTransparentContainerValueCodecFieldCapture(v *SourceeNBToTargeteNBTransparentContainerValueCodec) *func(SourceeNBToTargeteNBTransparentContainer, aper.DecodeState) (SourceeNBToTargeteNBTransparentContainer, aper.Snapshot) {
	return &v.capture
}
func BridgeSourceeNBToTargeteNBTransparentContainerValueCodecFieldCompare(v *SourceeNBToTargeteNBTransparentContainerValueCodec) *func(SourceeNBToTargeteNBTransparentContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeSourceeNBToTargeteNBTransparentContainerValueCodecFieldContext(v *SourceeNBToTargeteNBTransparentContainerValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeSourceeNBToTargeteNBTransparentContainerValueCodecFieldDecode(v *SourceeNBToTargeteNBTransparentContainerValueCodec) *func([]byte, aper.DecodeState) (SourceeNBToTargeteNBTransparentContainer, error) {
	return &v.decode
}
func BridgeSourceeNBToTargeteNBTransparentContainerValueCodecFieldEncode(v *SourceeNBToTargeteNBTransparentContainerValueCodec) *func(SourceeNBToTargeteNBTransparentContainer, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeSourceeNBToTargeteNBTransparentContainerValueCodecFieldPath(v *SourceeNBToTargeteNBTransparentContainerValueCodec) *aper.Path {
	return &v.path
}
func BridgeSourceeNBToTargeteNBTransparentContainerValueCodecMethodEncodeBudgetValue(v SourceeNBToTargeteNBTransparentContainerValueCodec, a0 SourceeNBToTargeteNBTransparentContainer, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeSourceeNBToTargeteNBTransparentContainerValueCodecMethodEncodeChanged(v SourceeNBToTargeteNBTransparentContainerValueCodec, a0 SourceeNBToTargeteNBTransparentContainer, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeUEHistoryInformationAPERValueFieldContext(v *UEHistoryInformationAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeUEHistoryInformationAPERValueFieldReceived(v *UEHistoryInformationAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeUEHistoryInformationAPERValueFieldReplay(v *UEHistoryInformationAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeUEHistoryInformationAPERValueFieldWithoutReplay(v *UEHistoryInformationAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeUEHistoryInformationValueCodecFieldCapture(v *UEHistoryInformationValueCodec) *func(UEHistoryInformation, aper.DecodeState) (UEHistoryInformation, aper.Snapshot) {
	return &v.capture
}
func BridgeUEHistoryInformationValueCodecFieldCompare(v *UEHistoryInformationValueCodec) *func(UEHistoryInformation, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeUEHistoryInformationValueCodecFieldContext(v *UEHistoryInformationValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeUEHistoryInformationValueCodecFieldDecode(v *UEHistoryInformationValueCodec) *func([]byte, aper.DecodeState) (UEHistoryInformation, error) {
	return &v.decode
}
func BridgeUEHistoryInformationValueCodecFieldEncode(v *UEHistoryInformationValueCodec) *func(UEHistoryInformation, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeUEHistoryInformationValueCodecFieldPath(v *UEHistoryInformationValueCodec) *aper.Path {
	return &v.path
}
func BridgeUEHistoryInformationValueCodecMethodEncodeBudgetValue(v UEHistoryInformationValueCodec, a0 UEHistoryInformation, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeUEHistoryInformationValueCodecMethodEncodeChanged(v UEHistoryInformationValueCodec, a0 UEHistoryInformation, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}

// Selected returns the decoded value of the active alternative, as the matching As method returns it, or false when the value is opaque or empty.
func (v *LastVisitedEUTRANCellInformationExtIEsValue) Selected() (any, bool) {
	if v == nil || v.isOpaque {
		return nil, false
	}
	switch v.id {
	case 167:
		if value, ok := v.AsTimeUEStayedInCellEnhancedGranularity(); ok {
			return value, true
		}
	case 168:
		if value, ok := v.AsHOCause(); ok {
			return value, true
		}
	case 329:
		if value, ok := v.AsLastVisitedPSCellList(); ok {
			return value, true
		}
	}
	return nil, false
}

// Selected returns the decoded value of the active alternative, as the matching As method returns it, or false when the value is opaque or empty.
func (v *MDTConfigurationExtIEsValue) Selected() (any, bool) {
	if v == nil || v.isOpaque {
		return nil, false
	}
	switch v.id {
	case 178:
		if value, ok := v.AsSignallingBasedMDTPLMNList(); ok {
			return value, true
		}
	}
	return nil, false
}

// Selected returns the decoded value of the active alternative, as the matching As method returns it, or false when the value is opaque or empty.
func (v *OverloadStartIEValue) Selected() (any, bool) {
	if v == nil || v.isOpaque {
		return nil, false
	}
	switch v.id {
	case 101:
		if value, ok := v.AsOverloadResponse(); ok {
			return value, true
		}
	case 154:
		if value, ok := v.AsGUMMEIList(); ok {
			return value, true
		}
	case 161:
		if value, ok := v.AsTrafficLoadReductionIndication(); ok {
			return value, true
		}
	}
	return nil, false
}

// Selected returns the decoded value of the active alternative, as the matching As method returns it, or false when the value is opaque or empty.
func (v *OverloadStopIEValue) Selected() (any, bool) {
	if v == nil || v.isOpaque {
		return nil, false
	}
	switch v.id {
	case 154:
		if value, ok := v.AsGUMMEIList(); ok {
			return value, true
		}
	}
	return nil, false
}

// Selected returns the decoded value of the active alternative, as the matching As method returns it, or false when the value is opaque or empty.
func (v *PWSFailureIndicationIEValue) Selected() (any, bool) {
	if v == nil || v.isOpaque {
		return nil, false
	}
	switch v.id {
	case 222:
		if value, ok := v.AsPWSfailedECGIList(); ok {
			return value, true
		}
	case 59:
		if value, ok := v.AsGlobalENBID(); ok {
			return value, true
		}
	}
	return nil, false
}
