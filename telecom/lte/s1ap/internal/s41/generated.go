// Code generated from the pinned S1AP source closure. DO NOT EDIT.

// Package s41 implements the github.com/gomaja/go-asn1/telecom/lte/s1ap root package.
package s41

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
	s29 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s29"
	s30 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s30"
	s31 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s31"
	s32 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s32"
	s35 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s35"
	s37 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s37"
	s40 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s40"
	runtime "github.com/gomaja/go-asn1/telecom/lte/s1ap/runtime"
	aper "github.com/gomaja/go-asn1/telecom/lte/s1ap/runtime/aper"
)

// PathSwitchRequestIEContainer is ProtocolIE-Container {{PathSwitchRequestIEs}} of TS 36.413: a list of PathSwitchRequestIEField values.
type PathSwitchRequestIEContainer []PathSwitchRequestIEField

// PathSwitchRequestIEField is ProtocolIE-Field {{PathSwitchRequestIEs}} of TS 36.413: an information element field.
type PathSwitchRequestIEField struct {
	withoutReplay bool
	replay        aper.Snapshot
	stream        aper.WireSpan
	Id            s00.ProtocolIEID
	Criticality   s00.Criticality
	Value         PathSwitchRequestIEValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v PathSwitchRequestIEField) WithoutReplay() PathSwitchRequestIEField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *PathSwitchRequestIEField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *PathSwitchRequestIEField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
func (v *PathSwitchRequestIEField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolIEField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = PathSwitchRequestIEField{}
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
	var zero PathSwitchRequestIEValue

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
func BridgePathSwitchRequestIEValueCaptureS1APProtocolIEContainer(v *PathSwitchRequestIEContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgePathSwitchRequestIEValueCaptureS1APProtocolIEField(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgePathSwitchRequestIEValueCompareS1APProtocolIEContainer(v *PathSwitchRequestIEContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgePathSwitchRequestIEValueCompareS1APProtocolIEField(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}

// LastVisitedEUTRANCellInformationExtIEsExtContainer is ProtocolExtensionContainer {{LastVisitedEUTRANCellInformation-ExtIEs}} of TS 36.413: a list of LastVisitedEUTRANCellInformationExtIEsExtField values.
type LastVisitedEUTRANCellInformationExtIEsExtContainer []LastVisitedEUTRANCellInformationExtIEsExtField

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

// PathSwitchRequestENBUES1APIDIEBinding binds ENBUES1APID to the PathSwitchRequestIEs object set of TS 36.413.
type PathSwitchRequestENBUES1APIDIEBinding struct {
	info   s00.FieldInfo
	codec  s00.ENBUES1APIDValueCodec
	inject func(s00.ENBUES1APID,

	) PathSwitchRequestIEValue

	get func(*PathSwitchRequestIEValue,

	) (*s00.ENBUES1APID,

		bool)
}

// Info returns the source descriptor for this binding.
func (b PathSwitchRequestENBUES1APIDIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b PathSwitchRequestENBUES1APIDIEBinding) Codec() s00.ENBUES1APIDValueCodec { return b.codec }

// New validates a source value and constructs its bound field.
func (b PathSwitchRequestENBUES1APIDIEBinding) New(value s00.ENBUES1APID,

) (PathSwitchRequestIEField, error) {
	if b.inject == nil {
		return PathSwitchRequestIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return PathSwitchRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s00.BridgeENBUES1APIDValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return PathSwitchRequestIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return PathSwitchRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	return PathSwitchRequestIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b PathSwitchRequestENBUES1APIDIEBinding) Get(field *PathSwitchRequestIEField) (*s00.ENBUES1APID,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// PathSwitchRequestERABToBeSwitchedDLListIEBinding binds ERABToBeSwitchedDLList to the PathSwitchRequestIEs object set of TS 36.413.
type PathSwitchRequestERABToBeSwitchedDLListIEBinding struct {
	info   s00.FieldInfo
	codec  s30.ERABToBeSwitchedDLListValueCodec
	inject func(s30.ERABToBeSwitchedDLList,

	) PathSwitchRequestIEValue

	get func(*PathSwitchRequestIEValue,

	) (*s30.ERABToBeSwitchedDLList,

		bool)
}

// Info returns the source descriptor for this binding.
func (b PathSwitchRequestERABToBeSwitchedDLListIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b PathSwitchRequestERABToBeSwitchedDLListIEBinding) Codec() s30.ERABToBeSwitchedDLListValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b PathSwitchRequestERABToBeSwitchedDLListIEBinding) New(value s30.ERABToBeSwitchedDLList,

) (PathSwitchRequestIEField, error) {
	if b.inject == nil {
		return PathSwitchRequestIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return PathSwitchRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s30.BridgeERABToBeSwitchedDLListValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return PathSwitchRequestIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return PathSwitchRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	return PathSwitchRequestIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b PathSwitchRequestERABToBeSwitchedDLListIEBinding) Get(field *PathSwitchRequestIEField) (*s30.ERABToBeSwitchedDLList,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// PathSwitchRequestMMEUES1APIDIEBinding binds MMEUES1APID to the PathSwitchRequestIEs object set of TS 36.413.
type PathSwitchRequestMMEUES1APIDIEBinding struct {
	info   s00.FieldInfo
	codec  s01.MMEUES1APIDValueCodec
	inject func(s00.MMEUES1APID,

	) PathSwitchRequestIEValue

	get func(*PathSwitchRequestIEValue,

	) (*s00.MMEUES1APID,

		bool)
}

// Info returns the source descriptor for this binding.
func (b PathSwitchRequestMMEUES1APIDIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b PathSwitchRequestMMEUES1APIDIEBinding) Codec() s01.MMEUES1APIDValueCodec { return b.codec }

// New validates a source value and constructs its bound field.
func (b PathSwitchRequestMMEUES1APIDIEBinding) New(value s00.MMEUES1APID,

) (PathSwitchRequestIEField, error) {
	if b.inject == nil {
		return PathSwitchRequestIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return PathSwitchRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s01.BridgeMMEUES1APIDValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return PathSwitchRequestIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return PathSwitchRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	return PathSwitchRequestIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b PathSwitchRequestMMEUES1APIDIEBinding) Get(field *PathSwitchRequestIEField) (*s00.MMEUES1APID,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// PathSwitchRequestEUTRANCGIIEBinding binds EUTRANCGI to the PathSwitchRequestIEs object set of TS 36.413.
type PathSwitchRequestEUTRANCGIIEBinding struct {
	info   s00.FieldInfo
	codec  s17.EUTRANCGIValueCodec
	inject func(s17.EUTRANCGI,

	) PathSwitchRequestIEValue

	get func(*PathSwitchRequestIEValue,

	) (*s17.EUTRANCGI,

		bool)
}

// Info returns the source descriptor for this binding.
func (b PathSwitchRequestEUTRANCGIIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b PathSwitchRequestEUTRANCGIIEBinding) Codec() s17.EUTRANCGIValueCodec { return b.codec }

// New validates a source value and constructs its bound field.
func (b PathSwitchRequestEUTRANCGIIEBinding) New(value s17.EUTRANCGI,

) (PathSwitchRequestIEField, error) {
	if b.inject == nil {
		return PathSwitchRequestIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return PathSwitchRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s17.BridgeEUTRANCGIValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return PathSwitchRequestIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return PathSwitchRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	return PathSwitchRequestIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b PathSwitchRequestEUTRANCGIIEBinding) Get(field *PathSwitchRequestIEField) (*s17.EUTRANCGI,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// PathSwitchRequestTAIIEBinding binds TAI to the PathSwitchRequestIEs object set of TS 36.413.
type PathSwitchRequestTAIIEBinding struct {
	info   s00.FieldInfo
	codec  s32.TAIValueCodec
	inject func(s31.TAI,

	) PathSwitchRequestIEValue

	get func(*PathSwitchRequestIEValue,

	) (*s31.TAI,

		bool)
}

// Info returns the source descriptor for this binding.
func (b PathSwitchRequestTAIIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b PathSwitchRequestTAIIEBinding) Codec() s32.TAIValueCodec { return b.codec }

// New validates a source value and constructs its bound field.
func (b PathSwitchRequestTAIIEBinding) New(value s31.TAI,

) (PathSwitchRequestIEField, error) {
	if b.inject == nil {
		return PathSwitchRequestIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return PathSwitchRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s32.BridgeTAIValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return PathSwitchRequestIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return PathSwitchRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	return PathSwitchRequestIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b PathSwitchRequestTAIIEBinding) Get(field *PathSwitchRequestIEField) (*s31.TAI,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// PathSwitchRequestUESecurityCapabilitiesIEBinding binds UESecurityCapabilities to the PathSwitchRequestIEs object set of TS 36.413.
type PathSwitchRequestUESecurityCapabilitiesIEBinding struct {
	info   s00.FieldInfo
	codec  s37.UESecurityCapabilitiesValueCodec
	inject func(s37.UESecurityCapabilities,

	) PathSwitchRequestIEValue

	get func(*PathSwitchRequestIEValue,

	) (*s37.UESecurityCapabilities,

		bool)
}

// Info returns the source descriptor for this binding.
func (b PathSwitchRequestUESecurityCapabilitiesIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b PathSwitchRequestUESecurityCapabilitiesIEBinding) Codec() s37.UESecurityCapabilitiesValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b PathSwitchRequestUESecurityCapabilitiesIEBinding) New(value s37.UESecurityCapabilities,

) (PathSwitchRequestIEField, error) {
	if b.inject == nil {
		return PathSwitchRequestIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return PathSwitchRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s37.BridgeUESecurityCapabilitiesValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return PathSwitchRequestIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return PathSwitchRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	return PathSwitchRequestIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b PathSwitchRequestUESecurityCapabilitiesIEBinding) Get(field *PathSwitchRequestIEField) (*s37.UESecurityCapabilities,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// PathSwitchRequestCSGIdIEBinding binds CSGId to the PathSwitchRequestIEs object set of TS 36.413.
type PathSwitchRequestCSGIdIEBinding struct {
	info   s00.FieldInfo
	codec  s00.CSGIdValueCodec
	inject func(s00.CSGId,

	) PathSwitchRequestIEValue

	get func(*PathSwitchRequestIEValue,

	) (*s00.CSGId,

		bool)
}

// Info returns the source descriptor for this binding.
func (b PathSwitchRequestCSGIdIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b PathSwitchRequestCSGIdIEBinding) Codec() s00.CSGIdValueCodec { return b.codec }

// New validates a source value and constructs its bound field.
func (b PathSwitchRequestCSGIdIEBinding) New(value s00.CSGId,

) (PathSwitchRequestIEField, error) {
	if b.inject == nil {
		return PathSwitchRequestIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return PathSwitchRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s00.BridgeCSGIdValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return PathSwitchRequestIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return PathSwitchRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	return PathSwitchRequestIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b PathSwitchRequestCSGIdIEBinding) Get(field *PathSwitchRequestIEField) (*s00.CSGId,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// PathSwitchRequestCellAccessModeIEBinding binds CellAccessMode to the PathSwitchRequestIEs object set of TS 36.413.
type PathSwitchRequestCellAccessModeIEBinding struct {
	info   s00.FieldInfo
	codec  s00.CellAccessModeValueCodec
	inject func(s00.CellAccessMode,

	) PathSwitchRequestIEValue

	get func(*PathSwitchRequestIEValue,

	) (*s00.CellAccessMode,

		bool)
}

// Info returns the source descriptor for this binding.
func (b PathSwitchRequestCellAccessModeIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b PathSwitchRequestCellAccessModeIEBinding) Codec() s00.CellAccessModeValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b PathSwitchRequestCellAccessModeIEBinding) New(value s00.CellAccessMode,

) (PathSwitchRequestIEField, error) {
	if b.inject == nil {
		return PathSwitchRequestIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return PathSwitchRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s00.BridgeCellAccessModeValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return PathSwitchRequestIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return PathSwitchRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	return PathSwitchRequestIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b PathSwitchRequestCellAccessModeIEBinding) Get(field *PathSwitchRequestIEField) (*s00.CellAccessMode,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// PathSwitchRequestGUMMEIIEBinding binds GUMMEI to the PathSwitchRequestIEs object set of TS 36.413.
type PathSwitchRequestGUMMEIIEBinding struct {
	info   s00.FieldInfo
	codec  s18.GUMMEIValueCodec
	inject func(s18.GUMMEI,

	) PathSwitchRequestIEValue

	get func(*PathSwitchRequestIEValue,

	) (*s18.GUMMEI,

		bool)
}

// Info returns the source descriptor for this binding.
func (b PathSwitchRequestGUMMEIIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b PathSwitchRequestGUMMEIIEBinding) Codec() s18.GUMMEIValueCodec { return b.codec }

// New validates a source value and constructs its bound field.
func (b PathSwitchRequestGUMMEIIEBinding) New(value s18.GUMMEI,

) (PathSwitchRequestIEField, error) {
	if b.inject == nil {
		return PathSwitchRequestIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return PathSwitchRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s18.BridgeGUMMEIValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return PathSwitchRequestIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return PathSwitchRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	return PathSwitchRequestIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b PathSwitchRequestGUMMEIIEBinding) Get(field *PathSwitchRequestIEField) (*s18.GUMMEI,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// PathSwitchRequestCSGMembershipStatusIEBinding binds CSGMembershipStatus to the PathSwitchRequestIEs object set of TS 36.413.
type PathSwitchRequestCSGMembershipStatusIEBinding struct {
	info   s00.FieldInfo
	codec  s00.CSGMembershipStatusValueCodec
	inject func(s00.CSGMembershipStatus,

	) PathSwitchRequestIEValue

	get func(*PathSwitchRequestIEValue,

	) (*s00.CSGMembershipStatus,

		bool)
}

// Info returns the source descriptor for this binding.
func (b PathSwitchRequestCSGMembershipStatusIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b PathSwitchRequestCSGMembershipStatusIEBinding) Codec() s00.CSGMembershipStatusValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b PathSwitchRequestCSGMembershipStatusIEBinding) New(value s00.CSGMembershipStatus,

) (PathSwitchRequestIEField, error) {
	if b.inject == nil {
		return PathSwitchRequestIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return PathSwitchRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s00.BridgeCSGMembershipStatusValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return PathSwitchRequestIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return PathSwitchRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	return PathSwitchRequestIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b PathSwitchRequestCSGMembershipStatusIEBinding) Get(field *PathSwitchRequestIEField) (*s00.CSGMembershipStatus,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// PathSwitchRequestTunnelInformationIEBinding binds TunnelInformation to the PathSwitchRequestIEs object set of TS 36.413.
type PathSwitchRequestTunnelInformationIEBinding struct {
	info   s00.FieldInfo
	codec  s35.TunnelInformationValueCodec
	inject func(s35.TunnelInformation,

	) PathSwitchRequestIEValue

	get func(*PathSwitchRequestIEValue,

	) (*s35.TunnelInformation,

		bool)
}

// Info returns the source descriptor for this binding.
func (b PathSwitchRequestTunnelInformationIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b PathSwitchRequestTunnelInformationIEBinding) Codec() s35.TunnelInformationValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b PathSwitchRequestTunnelInformationIEBinding) New(value s35.TunnelInformation,

) (PathSwitchRequestIEField, error) {
	if b.inject == nil {
		return PathSwitchRequestIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return PathSwitchRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s35.BridgeTunnelInformationValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return PathSwitchRequestIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return PathSwitchRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	return PathSwitchRequestIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b PathSwitchRequestTunnelInformationIEBinding) Get(field *PathSwitchRequestIEField) (*s35.TunnelInformation,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// PathSwitchRequestLHNIDIEBinding binds LHNID to the PathSwitchRequestIEs object set of TS 36.413.
type PathSwitchRequestLHNIDIEBinding struct {
	info   s00.FieldInfo
	codec  s01.LHNIDValueCodec
	inject func(s00.LHNID,

	) PathSwitchRequestIEValue

	get func(*PathSwitchRequestIEValue,

	) (*s00.LHNID,

		bool)
}

// Info returns the source descriptor for this binding.
func (b PathSwitchRequestLHNIDIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b PathSwitchRequestLHNIDIEBinding) Codec() s01.LHNIDValueCodec { return b.codec }

// New validates a source value and constructs its bound field.
func (b PathSwitchRequestLHNIDIEBinding) New(value s00.LHNID,

) (PathSwitchRequestIEField, error) {
	if b.inject == nil {
		return PathSwitchRequestIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return PathSwitchRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s01.BridgeLHNIDValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return PathSwitchRequestIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return PathSwitchRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	return PathSwitchRequestIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b PathSwitchRequestLHNIDIEBinding) Get(field *PathSwitchRequestIEField) (*s00.LHNID,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// PathSwitchRequestRRCEstablishmentCauseIEBinding binds RRCEstablishmentCause to the PathSwitchRequestIEs object set of TS 36.413.
type PathSwitchRequestRRCEstablishmentCauseIEBinding struct {
	info   s00.FieldInfo
	codec  s01.RRCEstablishmentCauseValueCodec
	inject func(s00.RRCEstablishmentCause,

	) PathSwitchRequestIEValue

	get func(*PathSwitchRequestIEValue,

	) (*s00.RRCEstablishmentCause,

		bool)
}

// Info returns the source descriptor for this binding.
func (b PathSwitchRequestRRCEstablishmentCauseIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b PathSwitchRequestRRCEstablishmentCauseIEBinding) Codec() s01.RRCEstablishmentCauseValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b PathSwitchRequestRRCEstablishmentCauseIEBinding) New(value s00.RRCEstablishmentCause,

) (PathSwitchRequestIEField, error) {
	if b.inject == nil {
		return PathSwitchRequestIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return PathSwitchRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s01.BridgeRRCEstablishmentCauseValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return PathSwitchRequestIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return PathSwitchRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	return PathSwitchRequestIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b PathSwitchRequestRRCEstablishmentCauseIEBinding) Get(field *PathSwitchRequestIEField) (*s00.RRCEstablishmentCause,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// PathSwitchRequestNRUESecurityCapabilitiesIEBinding binds NRUESecurityCapabilities to the PathSwitchRequestIEs object set of TS 36.413.
type PathSwitchRequestNRUESecurityCapabilitiesIEBinding struct {
	info   s00.FieldInfo
	codec  s19.NRUESecurityCapabilitiesValueCodec
	inject func(s19.NRUESecurityCapabilities,

	) PathSwitchRequestIEValue

	get func(*PathSwitchRequestIEValue,

	) (*s19.NRUESecurityCapabilities,

		bool)
}

// Info returns the source descriptor for this binding.
func (b PathSwitchRequestNRUESecurityCapabilitiesIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b PathSwitchRequestNRUESecurityCapabilitiesIEBinding) Codec() s19.NRUESecurityCapabilitiesValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b PathSwitchRequestNRUESecurityCapabilitiesIEBinding) New(value s19.NRUESecurityCapabilities,

) (PathSwitchRequestIEField, error) {
	if b.inject == nil {
		return PathSwitchRequestIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return PathSwitchRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s19.BridgeNRUESecurityCapabilitiesValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return PathSwitchRequestIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return PathSwitchRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	return PathSwitchRequestIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b PathSwitchRequestNRUESecurityCapabilitiesIEBinding) Get(field *PathSwitchRequestIEField) (*s19.NRUESecurityCapabilities,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// PathSwitchRequestPSCellInformationIEBinding binds PSCellInformation to the PathSwitchRequestIEs object set of TS 36.413.
type PathSwitchRequestPSCellInformationIEBinding struct {
	info   s00.FieldInfo
	codec  s20.PSCellInformationValueCodec
	inject func(s20.PSCellInformation,

	) PathSwitchRequestIEValue

	get func(*PathSwitchRequestIEValue,

	) (*s20.PSCellInformation,

		bool)
}

// Info returns the source descriptor for this binding.
func (b PathSwitchRequestPSCellInformationIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b PathSwitchRequestPSCellInformationIEBinding) Codec() s20.PSCellInformationValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b PathSwitchRequestPSCellInformationIEBinding) New(value s20.PSCellInformation,

) (PathSwitchRequestIEField, error) {
	if b.inject == nil {
		return PathSwitchRequestIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return PathSwitchRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s20.BridgePSCellInformationValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return PathSwitchRequestIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return PathSwitchRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	return PathSwitchRequestIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b PathSwitchRequestPSCellInformationIEBinding) Get(field *PathSwitchRequestIEField) (*s20.PSCellInformation,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// PathSwitchRequestLTENTNTAIInformationIEBinding binds LTENTNTAIInformation to the PathSwitchRequestIEs object set of TS 36.413.
type PathSwitchRequestLTENTNTAIInformationIEBinding struct {
	info   s00.FieldInfo
	codec  s18.LTENTNTAIInformationValueCodec
	inject func(s18.LTENTNTAIInformation,

	) PathSwitchRequestIEValue

	get func(*PathSwitchRequestIEValue,

	) (*s18.LTENTNTAIInformation,

		bool)
}

// Info returns the source descriptor for this binding.
func (b PathSwitchRequestLTENTNTAIInformationIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b PathSwitchRequestLTENTNTAIInformationIEBinding) Codec() s18.LTENTNTAIInformationValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b PathSwitchRequestLTENTNTAIInformationIEBinding) New(value s18.LTENTNTAIInformation,

) (PathSwitchRequestIEField, error) {
	if b.inject == nil {
		return PathSwitchRequestIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return PathSwitchRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s18.BridgeLTENTNTAIInformationValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return PathSwitchRequestIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return PathSwitchRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	return PathSwitchRequestIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b PathSwitchRequestLTENTNTAIInformationIEBinding) Get(field *PathSwitchRequestIEField) (*s18.LTENTNTAIInformation,

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

// PathSwitchRequestValueCodec is the concrete ValueCodec[PathSwitchRequest].
type PathSwitchRequestValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (PathSwitchRequest,

		error)
	encode func(PathSwitchRequest,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(PathSwitchRequest, aper.DecodeState,

	) (PathSwitchRequest, aper.Snapshot,

	)
	compare func(PathSwitchRequest, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c PathSwitchRequestValueCodec) New(value PathSwitchRequest,

) (PathSwitchRequestAPERValue, error) {
	if c.encode == nil {
		return PathSwitchRequestAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return PathSwitchRequestAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return PathSwitchRequestAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return PathSwitchRequestAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c PathSwitchRequestValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (PathSwitchRequestAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return PathSwitchRequestAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return PathSwitchRequestAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return PathSwitchRequestAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return PathSwitchRequestAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c PathSwitchRequestValueCodec) EncodeAPER(value PathSwitchRequestAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c PathSwitchRequestValueCodec) encodeBudgetValue(value PathSwitchRequest,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c PathSwitchRequestValueCodec) encodeChanged(value PathSwitchRequest,

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
func BridgePathSwitchRequestIEValueValidateS1APIEContainer(fields PathSwitchRequestIEContainer, rows []s00.FieldInfo, path string, budget *aper.DecodeBudget,

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

// OverloadStartIEValueERABIEContainerListCodec constructs the E-RAB-IE-ContainerList {{OverloadStartIEs}} codec of TS 36.413.
func OverloadStartIEValueERABIEContainerListCodec(table s00.OverloadStartIEValueIETable) OverloadStartIEValueERABIEContainerListValueCodec {
	codec := OverloadStartIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if codec.decode == nil {
		return OverloadStartIEValueERABIEContainerListValueCodec{}
	}
	return OverloadStartIEValueERABIEContainerListValueCodec{decode: func(data []byte, options aper.DecodeState) (OverloadStartIEValueERABIEContainerList, error) {
		value, err := codec.decode(data, options)
		return OverloadStartIEValueERABIEContainerList(value), err
	}, encode: func(value OverloadStartIEValueERABIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return codec.encode(OverloadStartIEContainer(value), fresh, budget)
	}, capture: func(v OverloadStartIEValueERABIEContainerList, options aper.DecodeState) (OverloadStartIEValueERABIEContainerList, aper.Snapshot) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeOverloadStartIEValueCaptureS1APERABIEContainerList(&v, &s)
		var root aper.Snapshot
		s.End(f, &root, false)
		return v, root
	}, compare: func(v OverloadStartIEValueERABIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
	) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		BridgeOverloadStartIEValueCompareS1APERABIEContainerList(&v, &s)
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

// OverloadStopIEValueERABIEContainerListCodec constructs the E-RAB-IE-ContainerList {{OverloadStopIEs}} codec of TS 36.413.
func OverloadStopIEValueERABIEContainerListCodec(table s00.OverloadStopIEValueIETable) OverloadStopIEValueERABIEContainerListValueCodec {
	codec := OverloadStopIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if codec.decode == nil {
		return OverloadStopIEValueERABIEContainerListValueCodec{}
	}
	return OverloadStopIEValueERABIEContainerListValueCodec{decode: func(data []byte, options aper.DecodeState) (OverloadStopIEValueERABIEContainerList, error) {
		value, err := codec.decode(data, options)
		return OverloadStopIEValueERABIEContainerList(value), err
	}, encode: func(value OverloadStopIEValueERABIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return codec.encode(OverloadStopIEContainer(value), fresh, budget)
	}, capture: func(v OverloadStopIEValueERABIEContainerList, options aper.DecodeState) (OverloadStopIEValueERABIEContainerList, aper.Snapshot) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeOverloadStopIEValueCaptureS1APERABIEContainerList(&v, &s)
		var root aper.Snapshot
		s.End(f, &root, false)
		return v, root
	}, compare: func(v OverloadStopIEValueERABIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
	) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		BridgeOverloadStopIEValueCompareS1APERABIEContainerList(&v, &s)
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

// PathSwitchRequestIEValueERABIEContainerListCodec constructs the E-RAB-IE-ContainerList {{PathSwitchRequestIEs}} codec of TS 36.413.
func PathSwitchRequestIEValueERABIEContainerListCodec(table s00.PathSwitchRequestIEValueIETable) PathSwitchRequestIEValueERABIEContainerListValueCodec {
	codec := PathSwitchRequestIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if codec.decode == nil {
		return PathSwitchRequestIEValueERABIEContainerListValueCodec{}
	}
	return PathSwitchRequestIEValueERABIEContainerListValueCodec{decode: func(data []byte, options aper.DecodeState) (PathSwitchRequestIEValueERABIEContainerList, error) {
		value, err := codec.decode(data, options)
		return PathSwitchRequestIEValueERABIEContainerList(value), err
	}, encode: func(value PathSwitchRequestIEValueERABIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return codec.encode(PathSwitchRequestIEContainer(value), fresh, budget)
	}, capture: func(v PathSwitchRequestIEValueERABIEContainerList, options aper.DecodeState) (PathSwitchRequestIEValueERABIEContainerList, aper.Snapshot) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		BridgePathSwitchRequestIEValueCaptureS1APERABIEContainerList(&v, &s)
		var root aper.Snapshot
		s.End(f, &root, false)
		return v, root
	}, compare: func(v PathSwitchRequestIEValueERABIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
	) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		BridgePathSwitchRequestIEValueCompareS1APERABIEContainerList(&v, &s)
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
			return field, err
		}
		if _, err := aper.CaptureFinalBits(bb, "ProtocolExtensionField"); err != nil {
			return field, err
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
		s.End(f, &root,
			false)
		return v, root
	}, compare: func(v LastVisitedEUTRANCellInformationExtIEsExtField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
	) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		BridgeLastVisitedEUTRANCellInformationExtIEsValueCompareS1APProtocolExtensionField(&v, &s)
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
			f := s.
				Begin()
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
			return field, err
		}
		if _, err := aper.CaptureFinalBits(bb, "ProtocolIEField"); err != nil {
			return field, err
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
		BridgeOverloadStartIEValueCaptureS1APProtocolIEField(&v,
			&s)
		var root aper.Snapshot
		s.End(f, &root, false)
		return v,
			root
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
			return field, err
		}
		if _, err := aper.CaptureFinalBits(bb, "ProtocolIEField"); err != nil {
			return field, err
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
		BridgeOverloadStopIEValueCaptureS1APProtocolIEField(&v,
			&s)
		var root aper.Snapshot
		s.End(f, &root, false)
		return v,
			root
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

// PathSwitchRequestIEValueIEFieldTableCodec constructs the ProtocolIE-Field {{PathSwitchRequestIEs}} codec of TS 36.413.
func PathSwitchRequestIEValueIEFieldTableCodec(table s00.PathSwitchRequestIEValueIETable) PathSwitchRequestIEFieldValueCodec {
	if !*s00.BridgePathSwitchRequestIEValueIETableFieldBound(&table) {
		return PathSwitchRequestIEFieldValueCodec{}
	}
	return PathSwitchRequestIEFieldValueCodec{decode: func(data []byte, options aper.DecodeState) (PathSwitchRequestIEField, error) {
		var field PathSwitchRequestIEField
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
	}, encode: func(field PathSwitchRequestIEField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		bb := aper.NewBudgetBuffer(budget)
		if err := field.marshalAPERTo(bb, fresh); err != nil {
			return nil, err
		}
		return bb.CompleteBytes(), nil
	}, capture: func(v PathSwitchRequestIEField, options aper.DecodeState) (PathSwitchRequestIEField, aper.Snapshot,
	) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		BridgePathSwitchRequestIEValueCaptureS1APProtocolIEField(&v,
			&s)
		var root aper.Snapshot
		s.End(f, &root, false)
		return v,
			root
	}, compare: func(v PathSwitchRequestIEField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

	) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		BridgePathSwitchRequestIEValueCompareS1APProtocolIEField(&v, &s)
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
			s.End(f, &root, false)
			return v, root
		}, compare: func(v OverloadStartIEContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeOverloadStartIEValueCompareS1APProtocolIEContainer(&v, &s)
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
			s.End(f, &root, false)
			return v, root
		}, compare: func(v OverloadStopIEContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeOverloadStopIEValueCompareS1APProtocolIEContainer(&v, &s)
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

// PathSwitchRequestIEValueIETableCodec constructs the ProtocolIE-Container {{PathSwitchRequestIEs}} codec of TS 36.413.
func PathSwitchRequestIEValueIETableCodec(table s00.PathSwitchRequestIEValueIETable, bounds aper.ListBounds) PathSwitchRequestIEContainerValueCodec {
	if !*s00.BridgePathSwitchRequestIEValueIETableFieldBound(&table) {
		return PathSwitchRequestIEContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return PathSwitchRequestIEContainerValueCodec{decode: func(data []byte, options aper.DecodeState) (PathSwitchRequestIEContainer, error) {
		bb := aper.NewCompleteDecodeBuffer(data, options)
		if err := bb.SetDecodeOptionsAligned(options); err != nil {
			return nil, err
		}
		var fields PathSwitchRequestIEContainer
		_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
			for i := int64(0); i < length; i++ {
				var field PathSwitchRequestIEField
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
		encode: func(fields PathSwitchRequestIEContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
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
		}, capture: func(v PathSwitchRequestIEContainer, options aper.DecodeState) (PathSwitchRequestIEContainer, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgePathSwitchRequestIEValueCaptureS1APProtocolIEContainer(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}, compare: func(v PathSwitchRequestIEContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgePathSwitchRequestIEValueCompareS1APProtocolIEContainer(&v, &s)
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

// OverloadStartIEValueProtocolErrorIEContainerListCodec constructs the ProtocolError-IE-ContainerList {{OverloadStartIEs}} codec of TS 36.413.
func OverloadStartIEValueProtocolErrorIEContainerListCodec(table s00.OverloadStartIEValueIETable) OverloadStartIEValueProtocolErrorIEContainerListValueCodec {
	codec := OverloadStartIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if codec.decode == nil {
		return OverloadStartIEValueProtocolErrorIEContainerListValueCodec{}
	}
	return OverloadStartIEValueProtocolErrorIEContainerListValueCodec{decode: func(data []byte, options aper.DecodeState) (OverloadStartIEValueProtocolErrorIEContainerList, error) {
		value, err := codec.decode(data, options)
		return OverloadStartIEValueProtocolErrorIEContainerList(value), err
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
		f :=
			s.
				Begin()
		BridgeOverloadStartIEValueCompareS1APProtocolErrorIEContainerList(&v, &s)
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

// OverloadStopIEValueProtocolErrorIEContainerListCodec constructs the ProtocolError-IE-ContainerList {{OverloadStopIEs}} codec of TS 36.413.
func OverloadStopIEValueProtocolErrorIEContainerListCodec(table s00.OverloadStopIEValueIETable) OverloadStopIEValueProtocolErrorIEContainerListValueCodec {
	codec := OverloadStopIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if codec.decode == nil {
		return OverloadStopIEValueProtocolErrorIEContainerListValueCodec{}
	}
	return OverloadStopIEValueProtocolErrorIEContainerListValueCodec{decode: func(data []byte, options aper.DecodeState) (OverloadStopIEValueProtocolErrorIEContainerList, error) {
		value, err := codec.decode(data, options)
		return OverloadStopIEValueProtocolErrorIEContainerList(value), err
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
		f :=
			s.
				Begin()
		BridgeOverloadStopIEValueCompareS1APProtocolErrorIEContainerList(&v, &s)
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

// PathSwitchRequestIEValueProtocolErrorIEContainerListCodec constructs the ProtocolError-IE-ContainerList {{PathSwitchRequestIEs}} codec of TS 36.413.
func PathSwitchRequestIEValueProtocolErrorIEContainerListCodec(table s00.PathSwitchRequestIEValueIETable) PathSwitchRequestIEValueProtocolErrorIEContainerListValueCodec {
	codec := PathSwitchRequestIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if codec.decode == nil {
		return PathSwitchRequestIEValueProtocolErrorIEContainerListValueCodec{}
	}
	return PathSwitchRequestIEValueProtocolErrorIEContainerListValueCodec{decode: func(data []byte, options aper.DecodeState) (PathSwitchRequestIEValueProtocolErrorIEContainerList, error) {
		value, err := codec.decode(data, options)
		return PathSwitchRequestIEValueProtocolErrorIEContainerList(value), err
	}, encode: func(value PathSwitchRequestIEValueProtocolErrorIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return codec.encode(PathSwitchRequestIEContainer(value), fresh, budget)
	}, capture: func(v PathSwitchRequestIEValueProtocolErrorIEContainerList, options aper.DecodeState) (PathSwitchRequestIEValueProtocolErrorIEContainerList, aper.Snapshot,
	) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		BridgePathSwitchRequestIEValueCaptureS1APProtocolErrorIEContainerList(&v, &s)
		var root aper.Snapshot

		s.End(f, &root, false)
		return v, root
	}, compare: func(v PathSwitchRequestIEValueProtocolErrorIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

	) {
		s := aper.NewSemanticComparison(root, budget)
		f :=
			s.
				Begin()
		BridgePathSwitchRequestIEValueCompareS1APProtocolErrorIEContainerList(&v, &s)
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

// OverloadStartIEValueProtocolIEContainerListCodec constructs a codec for ProtocolIE-ContainerList with IEsSetParam = {OverloadStartIEs} of TS 36.413, with lowerBound and upperBound supplied by its arguments.
func OverloadStartIEValueProtocolIEContainerListCodec(table s00.OverloadStartIEValueIETable, bounds aper.ListBounds) OverloadStartIEValueProtocolIEContainerListValueCodec {
	codec := OverloadStartIEValueIETableCodec(table, bounds)
	if codec.decode == nil {
		return OverloadStartIEValueProtocolIEContainerListValueCodec{}
	}
	return OverloadStartIEValueProtocolIEContainerListValueCodec{decode: func(data []byte, options aper.DecodeState) (OverloadStartIEValueProtocolIEContainerList, error) {
		value, err := codec.decode(data, options)
		return OverloadStartIEValueProtocolIEContainerList(value), err
	}, encode: func(value OverloadStartIEValueProtocolIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return codec.encode(OverloadStartIEContainer(value), fresh, budget)
	}, capture: func(v OverloadStartIEValueProtocolIEContainerList, options aper.DecodeState) (OverloadStartIEValueProtocolIEContainerList, aper.Snapshot,
	) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeOverloadStartIEValueCaptureS1APProtocolIEContainerList(&v, &s)
		var root aper.Snapshot
		s.End(
			f,
			&root, false)
		return v, root
	}, compare: func(v OverloadStartIEValueProtocolIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
	) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		BridgeOverloadStartIEValueCompareS1APProtocolIEContainerList(&v, &s)
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

// OverloadStopIEValueProtocolIEContainerListCodec constructs a codec for ProtocolIE-ContainerList with IEsSetParam = {OverloadStopIEs} of TS 36.413, with lowerBound and upperBound supplied by its arguments.
func OverloadStopIEValueProtocolIEContainerListCodec(table s00.OverloadStopIEValueIETable, bounds aper.ListBounds) OverloadStopIEValueProtocolIEContainerListValueCodec {
	codec := OverloadStopIEValueIETableCodec(table, bounds)
	if codec.decode == nil {
		return OverloadStopIEValueProtocolIEContainerListValueCodec{}
	}
	return OverloadStopIEValueProtocolIEContainerListValueCodec{decode: func(data []byte, options aper.DecodeState) (OverloadStopIEValueProtocolIEContainerList, error) {
		value, err := codec.decode(data, options)
		return OverloadStopIEValueProtocolIEContainerList(value), err
	}, encode: func(value OverloadStopIEValueProtocolIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return codec.encode(OverloadStopIEContainer(value), fresh, budget)
	}, capture: func(v OverloadStopIEValueProtocolIEContainerList, options aper.DecodeState) (OverloadStopIEValueProtocolIEContainerList, aper.Snapshot,
	) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeOverloadStopIEValueCaptureS1APProtocolIEContainerList(&v, &s)
		var root aper.Snapshot
		s.End(
			f,
			&root, false)
		return v, root
	}, compare: func(v OverloadStopIEValueProtocolIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
	) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		BridgeOverloadStopIEValueCompareS1APProtocolIEContainerList(&v, &s)
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

// PathSwitchRequestIEValueProtocolIEContainerListCodec constructs a codec for ProtocolIE-ContainerList with IEsSetParam = {PathSwitchRequestIEs} of TS 36.413, with lowerBound and upperBound supplied by its arguments.
func PathSwitchRequestIEValueProtocolIEContainerListCodec(table s00.PathSwitchRequestIEValueIETable, bounds aper.ListBounds) PathSwitchRequestIEValueProtocolIEContainerListValueCodec {
	codec := PathSwitchRequestIEValueIETableCodec(table, bounds)
	if codec.decode == nil {
		return PathSwitchRequestIEValueProtocolIEContainerListValueCodec{}
	}
	return PathSwitchRequestIEValueProtocolIEContainerListValueCodec{decode: func(data []byte, options aper.DecodeState) (PathSwitchRequestIEValueProtocolIEContainerList, error) {
		value, err := codec.decode(data, options)
		return PathSwitchRequestIEValueProtocolIEContainerList(value), err
	}, encode: func(value PathSwitchRequestIEValueProtocolIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return codec.encode(PathSwitchRequestIEContainer(value), fresh, budget)
	}, capture: func(v PathSwitchRequestIEValueProtocolIEContainerList, options aper.DecodeState) (PathSwitchRequestIEValueProtocolIEContainerList, aper.Snapshot,
	) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		BridgePathSwitchRequestIEValueCaptureS1APProtocolIEContainerList(&v, &s)
		var root aper.Snapshot
		s.End(
			f,
			&root, false)
		return v, root
	}, compare: func(v PathSwitchRequestIEValueProtocolIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
	) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		BridgePathSwitchRequestIEValueCompareS1APProtocolIEContainerList(&v, &s)
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

// pathSwitchRequestIEValueProtocolOpenValue is the concrete protocolOpenValue[PathSwitchRequestIEValue].
type PathSwitchRequestIEValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) PathSwitchRequestIEValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (PathSwitchRequestIEValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

func BridgePathSwitchRequestIEValueCaptureS1APProtocolIEField(v *PathSwitchRequestIEField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolIEID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.Value = v.Value.captureSemantics(*s)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgePathSwitchRequestIEValueCompareS1APProtocolIEField(v *PathSwitchRequestIEField, s *aper.SemanticComparison) {
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

// PathSwitchRequestAPERValue is the concrete APERValue[PathSwitchRequest].
type PathSwitchRequestAPERValue struct {
	context s00.BridgeCodecContext
	Value   PathSwitchRequest

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v PathSwitchRequestAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v PathSwitchRequestAPERValue) WithoutReplay() PathSwitchRequestAPERValue {
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

// PathSwitchRequestIEValueERABIEContainerListValueCodec is the concrete ValueCodec[PathSwitchRequestIEValueERABIEContainerList].
type PathSwitchRequestIEValueERABIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (PathSwitchRequestIEValueERABIEContainerList, error)
	encode  func(PathSwitchRequestIEValueERABIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(PathSwitchRequestIEValueERABIEContainerList, aper.DecodeState) (PathSwitchRequestIEValueERABIEContainerList, aper.Snapshot)
	compare func(PathSwitchRequestIEValueERABIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c PathSwitchRequestIEValueERABIEContainerListValueCodec) New(value PathSwitchRequestIEValueERABIEContainerList) (PathSwitchRequestIEValueERABIEContainerListAPERValue, error) {
	if c.encode == nil {
		return PathSwitchRequestIEValueERABIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return PathSwitchRequestIEValueERABIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return PathSwitchRequestIEValueERABIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return PathSwitchRequestIEValueERABIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c PathSwitchRequestIEValueERABIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (PathSwitchRequestIEValueERABIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return PathSwitchRequestIEValueERABIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return PathSwitchRequestIEValueERABIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return PathSwitchRequestIEValueERABIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return PathSwitchRequestIEValueERABIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c PathSwitchRequestIEValueERABIEContainerListValueCodec) EncodeAPER(value PathSwitchRequestIEValueERABIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c PathSwitchRequestIEValueERABIEContainerListValueCodec) encodeBudgetValue(value PathSwitchRequestIEValueERABIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c PathSwitchRequestIEValueERABIEContainerListValueCodec) encodeChanged(value PathSwitchRequestIEValueERABIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// PathSwitchRequestIEValueERABIEContainerList is E-RAB-IE-ContainerList {{PathSwitchRequestIEs}} of TS 36.413: a list of information element fields.
type PathSwitchRequestIEValueERABIEContainerList []PathSwitchRequestIEValueProtocolIESingleContainer

func BridgePathSwitchRequestIEValueCaptureS1APERABIEContainerList(v *PathSwitchRequestIEValueERABIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgePathSwitchRequestIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgePathSwitchRequestIEValueCompareS1APERABIEContainerList(v *PathSwitchRequestIEValueERABIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgePathSwitchRequestIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
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

// PathSwitchRequestIEFieldValueCodec is the concrete ValueCodec[PathSwitchRequestIEField].
type PathSwitchRequestIEFieldValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (PathSwitchRequestIEField, error)
	encode  func(PathSwitchRequestIEField, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(PathSwitchRequestIEField, aper.DecodeState) (PathSwitchRequestIEField, aper.Snapshot)
	compare func(PathSwitchRequestIEField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c PathSwitchRequestIEFieldValueCodec) New(value PathSwitchRequestIEField) (PathSwitchRequestIEFieldAPERValue, error) {
	if c.encode == nil {
		return PathSwitchRequestIEFieldAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return PathSwitchRequestIEFieldAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return PathSwitchRequestIEFieldAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return PathSwitchRequestIEFieldAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c PathSwitchRequestIEFieldValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (PathSwitchRequestIEFieldAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return PathSwitchRequestIEFieldAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return PathSwitchRequestIEFieldAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return PathSwitchRequestIEFieldAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return PathSwitchRequestIEFieldAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c PathSwitchRequestIEFieldValueCodec) EncodeAPER(value PathSwitchRequestIEFieldAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c PathSwitchRequestIEFieldValueCodec) encodeBudgetValue(value PathSwitchRequestIEField, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c PathSwitchRequestIEFieldValueCodec) encodeChanged(value PathSwitchRequestIEField, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
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

// PathSwitchRequestIEContainerValueCodec is the concrete ValueCodec[PathSwitchRequestIEContainer].
type PathSwitchRequestIEContainerValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (PathSwitchRequestIEContainer, error)
	encode  func(PathSwitchRequestIEContainer, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(PathSwitchRequestIEContainer, aper.DecodeState) (PathSwitchRequestIEContainer, aper.Snapshot)
	compare func(PathSwitchRequestIEContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c PathSwitchRequestIEContainerValueCodec) New(value PathSwitchRequestIEContainer) (PathSwitchRequestIEContainerAPERValue, error) {
	if c.encode == nil {
		return PathSwitchRequestIEContainerAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return PathSwitchRequestIEContainerAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return PathSwitchRequestIEContainerAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return PathSwitchRequestIEContainerAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c PathSwitchRequestIEContainerValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (PathSwitchRequestIEContainerAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return PathSwitchRequestIEContainerAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return PathSwitchRequestIEContainerAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return PathSwitchRequestIEContainerAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return PathSwitchRequestIEContainerAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c PathSwitchRequestIEContainerValueCodec) EncodeAPER(value PathSwitchRequestIEContainerAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c PathSwitchRequestIEContainerValueCodec) encodeBudgetValue(value PathSwitchRequestIEContainer, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c PathSwitchRequestIEContainerValueCodec) encodeChanged(value PathSwitchRequestIEContainer, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
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

// PathSwitchRequestIEValueProtocolErrorIEContainerListValueCodec is the concrete ValueCodec[PathSwitchRequestIEValueProtocolErrorIEContainerList].
type PathSwitchRequestIEValueProtocolErrorIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (PathSwitchRequestIEValueProtocolErrorIEContainerList, error)
	encode  func(PathSwitchRequestIEValueProtocolErrorIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(PathSwitchRequestIEValueProtocolErrorIEContainerList, aper.DecodeState) (PathSwitchRequestIEValueProtocolErrorIEContainerList, aper.Snapshot)
	compare func(PathSwitchRequestIEValueProtocolErrorIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c PathSwitchRequestIEValueProtocolErrorIEContainerListValueCodec) New(value PathSwitchRequestIEValueProtocolErrorIEContainerList) (PathSwitchRequestIEValueProtocolErrorIEContainerListAPERValue, error) {
	if c.encode == nil {
		return PathSwitchRequestIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return PathSwitchRequestIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return PathSwitchRequestIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return PathSwitchRequestIEValueProtocolErrorIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c PathSwitchRequestIEValueProtocolErrorIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (PathSwitchRequestIEValueProtocolErrorIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return PathSwitchRequestIEValueProtocolErrorIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return PathSwitchRequestIEValueProtocolErrorIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return PathSwitchRequestIEValueProtocolErrorIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return PathSwitchRequestIEValueProtocolErrorIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c PathSwitchRequestIEValueProtocolErrorIEContainerListValueCodec) EncodeAPER(value PathSwitchRequestIEValueProtocolErrorIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c PathSwitchRequestIEValueProtocolErrorIEContainerListValueCodec) encodeBudgetValue(value PathSwitchRequestIEValueProtocolErrorIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c PathSwitchRequestIEValueProtocolErrorIEContainerListValueCodec) encodeChanged(value PathSwitchRequestIEValueProtocolErrorIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// PathSwitchRequestIEValueProtocolErrorIEContainerList is ProtocolError-IE-ContainerList {{PathSwitchRequestIEs}} of TS 36.413: a list of information element fields.
type PathSwitchRequestIEValueProtocolErrorIEContainerList []PathSwitchRequestIEValueProtocolIESingleContainer

func BridgePathSwitchRequestIEValueCaptureS1APProtocolErrorIEContainerList(v *PathSwitchRequestIEValueProtocolErrorIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgePathSwitchRequestIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgePathSwitchRequestIEValueCompareS1APProtocolErrorIEContainerList(v *PathSwitchRequestIEValueProtocolErrorIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgePathSwitchRequestIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
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

// PathSwitchRequestIEValueProtocolIEContainerListValueCodec is the concrete ValueCodec[PathSwitchRequestIEValueProtocolIEContainerList].
type PathSwitchRequestIEValueProtocolIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (PathSwitchRequestIEValueProtocolIEContainerList, error)
	encode  func(PathSwitchRequestIEValueProtocolIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(PathSwitchRequestIEValueProtocolIEContainerList, aper.DecodeState) (PathSwitchRequestIEValueProtocolIEContainerList, aper.Snapshot)
	compare func(PathSwitchRequestIEValueProtocolIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c PathSwitchRequestIEValueProtocolIEContainerListValueCodec) New(value PathSwitchRequestIEValueProtocolIEContainerList) (PathSwitchRequestIEValueProtocolIEContainerListAPERValue, error) {
	if c.encode == nil {
		return PathSwitchRequestIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return PathSwitchRequestIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return PathSwitchRequestIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return PathSwitchRequestIEValueProtocolIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c PathSwitchRequestIEValueProtocolIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (PathSwitchRequestIEValueProtocolIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return PathSwitchRequestIEValueProtocolIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return PathSwitchRequestIEValueProtocolIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return PathSwitchRequestIEValueProtocolIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return PathSwitchRequestIEValueProtocolIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c PathSwitchRequestIEValueProtocolIEContainerListValueCodec) EncodeAPER(value PathSwitchRequestIEValueProtocolIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c PathSwitchRequestIEValueProtocolIEContainerListValueCodec) encodeBudgetValue(value PathSwitchRequestIEValueProtocolIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c PathSwitchRequestIEValueProtocolIEContainerListValueCodec) encodeChanged(value PathSwitchRequestIEValueProtocolIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// PathSwitchRequestIEValueProtocolIEContainerList is ProtocolIE-ContainerList with IEsSetParam = {PathSwitchRequestIEs} of TS 36.413: a list of information element fields with lowerBound and upperBound supplied by its concrete factory.
type PathSwitchRequestIEValueProtocolIEContainerList []PathSwitchRequestIEValueProtocolIESingleContainer

func BridgePathSwitchRequestIEValueCaptureS1APProtocolIEContainerList(v *PathSwitchRequestIEValueProtocolIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgePathSwitchRequestIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgePathSwitchRequestIEValueCompareS1APProtocolIEContainerList(v *PathSwitchRequestIEValueProtocolIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgePathSwitchRequestIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
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

// PathSwitchRequestIEValueERABIEContainerListAPERValue is the concrete APERValue[PathSwitchRequestIEValueERABIEContainerList].
type PathSwitchRequestIEValueERABIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         PathSwitchRequestIEValueERABIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v PathSwitchRequestIEValueERABIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v PathSwitchRequestIEValueERABIEContainerListAPERValue) WithoutReplay() PathSwitchRequestIEValueERABIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// PathSwitchRequestIEValueProtocolIESingleContainer is ProtocolIE-SingleContainer {{PathSwitchRequestIEs}} of TS 36.413: a single information element field.
type PathSwitchRequestIEValueProtocolIESingleContainer = PathSwitchRequestIEField

func BridgePathSwitchRequestIEValueCaptureS1APProtocolIESingleContainer(v *PathSwitchRequestIEValueProtocolIESingleContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgePathSwitchRequestIEValueCaptureS1APProtocolIEField(v, s)
	s.End(f, nil, false)
}
func BridgePathSwitchRequestIEValueCompareS1APProtocolIESingleContainer(v *PathSwitchRequestIEValueProtocolIESingleContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgePathSwitchRequestIEValueCompareS1APProtocolIEField(v, s)
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

// PathSwitchRequestIEFieldAPERValue is the concrete APERValue[PathSwitchRequestIEField].
type PathSwitchRequestIEFieldAPERValue struct {
	context       s00.BridgeCodecContext
	Value         PathSwitchRequestIEField
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v PathSwitchRequestIEFieldAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v PathSwitchRequestIEFieldAPERValue) WithoutReplay() PathSwitchRequestIEFieldAPERValue {
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

// PathSwitchRequestIEContainerAPERValue is the concrete APERValue[PathSwitchRequestIEContainer].
type PathSwitchRequestIEContainerAPERValue struct {
	context       s00.BridgeCodecContext
	Value         PathSwitchRequestIEContainer
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v PathSwitchRequestIEContainerAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v PathSwitchRequestIEContainerAPERValue) WithoutReplay() PathSwitchRequestIEContainerAPERValue {
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

// PathSwitchRequestIEValueProtocolErrorIEContainerListAPERValue is the concrete APERValue[PathSwitchRequestIEValueProtocolErrorIEContainerList].
type PathSwitchRequestIEValueProtocolErrorIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         PathSwitchRequestIEValueProtocolErrorIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v PathSwitchRequestIEValueProtocolErrorIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v PathSwitchRequestIEValueProtocolErrorIEContainerListAPERValue) WithoutReplay() PathSwitchRequestIEValueProtocolErrorIEContainerListAPERValue {
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

// PathSwitchRequestIEValueProtocolIEContainerListAPERValue is the concrete APERValue[PathSwitchRequestIEValueProtocolIEContainerList].
type PathSwitchRequestIEValueProtocolIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         PathSwitchRequestIEValueProtocolIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v PathSwitchRequestIEValueProtocolIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v PathSwitchRequestIEValueProtocolIEContainerListAPERValue) WithoutReplay() PathSwitchRequestIEValueProtocolIEContainerListAPERValue {
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
func BridgeCaptureS1APPathSwitchRequest(v *PathSwitchRequest, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgePathSwitchRequestIEValueCaptureS1APProtocolIEContainer(&v.ProtocolIEs, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APPathSwitchRequest(v *PathSwitchRequest, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgePathSwitchRequestIEValueCompareS1APProtocolIEContainer(&v.ProtocolIEs, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APPathSwitchRequestIEValue(v *PathSwitchRequestIEValue, s *aper.SemanticCapture) {
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
		case s00.ProtocolIEID(22):
			{
				f := s.Begin()
				s.Bool(v.rowERABToBeSwitchedDLList == nil)
				if v.rowERABToBeSwitchedDLList != nil {
					s30.BridgeCaptureS1APERABToBeSwitchedDLList(v.rowERABToBeSwitchedDLList, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(88):
			{
				f := s.Begin()
				s.Bool(v.rowSourceMMEUES1APID == nil)
				if v.rowSourceMMEUES1APID != nil {
					s00.BridgeCaptureS1APMMEUES1APID(v.rowSourceMMEUES1APID, s)
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
					s31.BridgeCaptureS1APTAI(v.rowTAI, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(107):
			{
				f := s.Begin()
				s.Bool(v.rowUESecurityCapabilities == nil)
				if v.rowUESecurityCapabilities != nil {
					s37.BridgeCaptureS1APUESecurityCapabilities(v.rowUESecurityCapabilities, s)
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
		case s00.ProtocolIEID(157):
			{
				f := s.Begin()
				s.Bool(v.rowSourceMMEGUMMEI == nil)
				if v.rowSourceMMEGUMMEI != nil {
					s18.BridgeCaptureS1APGUMMEI(v.rowSourceMMEGUMMEI, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(146):
			{
				f := s.Begin()
				s.Bool(v.rowCSGMembershipStatus == nil)
				if v.rowCSGMembershipStatus != nil {
					s00.BridgeCaptureS1APCSGMembershipStatus(v.rowCSGMembershipStatus, s)
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
		case s00.ProtocolIEID(186):
			{
				f := s.Begin()
				s.Bool(v.rowLHNID == nil)
				if v.rowLHNID != nil {
					s00.BridgeCaptureS1APLHNID(v.rowLHNID, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(245):
			{
				f := s.Begin()
				s.Bool(v.rowRRCResumeCause == nil)
				if v.rowRRCResumeCause != nil {
					s00.BridgeCaptureS1APRRCEstablishmentCause(v.rowRRCResumeCause, s)
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
func (v PathSwitchRequestIEValue) captureSemantics(s aper.SemanticCapture) PathSwitchRequestIEValue {
	BridgeCaptureS1APPathSwitchRequestIEValue(&v, &s)
	return v
}
func BridgeCompareS1APPathSwitchRequestIEValue(v *PathSwitchRequestIEValue, s *aper.SemanticComparison) {
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
		case s00.ProtocolIEID(22):
			{
				f := s.Begin()
				s.Bool(v.rowERABToBeSwitchedDLList == nil)
				if v.rowERABToBeSwitchedDLList != nil {
					s30.BridgeCompareS1APERABToBeSwitchedDLList(v.rowERABToBeSwitchedDLList, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(88):
			{
				f := s.Begin()
				s.Bool(v.rowSourceMMEUES1APID == nil)
				if v.rowSourceMMEUES1APID != nil {
					s02.BridgeCompareS1APMMEUES1APID(v.rowSourceMMEUES1APID, s)
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
					s31.BridgeCompareS1APTAI(v.rowTAI, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(107):
			{
				f := s.Begin()
				s.Bool(v.rowUESecurityCapabilities == nil)
				if v.rowUESecurityCapabilities != nil {
					s37.BridgeCompareS1APUESecurityCapabilities(v.rowUESecurityCapabilities, s)
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
		case s00.ProtocolIEID(157):
			{
				f := s.Begin()
				s.Bool(v.rowSourceMMEGUMMEI == nil)
				if v.rowSourceMMEGUMMEI != nil {
					s18.BridgeCompareS1APGUMMEI(v.rowSourceMMEGUMMEI, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(146):
			{
				f := s.Begin()
				s.Bool(v.rowCSGMembershipStatus == nil)
				if v.rowCSGMembershipStatus != nil {
					s02.BridgeCompareS1APCSGMembershipStatus(v.rowCSGMembershipStatus, s)
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
		case s00.ProtocolIEID(186):
			{
				f := s.Begin()
				s.Bool(v.rowLHNID == nil)
				if v.rowLHNID != nil {
					s02.BridgeCompareS1APLHNID(v.rowLHNID, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(245):
			{
				f := s.Begin()
				s.Bool(v.rowRRCResumeCause == nil)
				if v.rowRRCResumeCause != nil {
					s06.BridgeCompareS1APRRCEstablishmentCause(v.rowRRCResumeCause, s)
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
func (v PathSwitchRequestIEValue) compareSemantics(s aper.SemanticComparison) aper.SemanticComparison {
	BridgeCompareS1APPathSwitchRequestIEValue(&v, &s)
	return s
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
type UEHistoryInformation = []LastVisitedCellItem

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
	if err := s25.BridgeMarshalAPEREmergencyAreaIDBroadcastTo(v.Value, bb); err != nil {
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
	if err := s25.BridgeMarshalAPEREmergencyAreaIDCancelledTo(v.Value, bb); err != nil {
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
	if err := s25.BridgeMarshalAPERIEsECGIListTo(v.Value, bb); err != nil {
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
	if err := s25.BridgeMarshalAPERGUMMEIListTo(v.Value, bb); err != nil {
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
	if err := s25.BridgeMarshalAPERERABUsageReportListTo(v.Value, bb); err != nil {
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
	if err := s25.BridgeMarshalAPERForbiddenTAsTo(v.Value, bb); err != nil {
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
	if err := s25.BridgeMarshalAPERForbiddenLAsTo(v.Value, bb); err != nil {
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
	if err := s25.BridgeMarshalAPERInterSystemMeasurementListTo(v.Value, bb); err != nil {
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
	if err := s25.BridgeMarshalAPERLastVisitedPSCellListTo(v.Value, bb); err != nil {
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

type BridgeAsn1cAPERUEHistoryInformationListValue struct{ Value UEHistoryInformation }

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
	if err := s25.BridgeMarshalAPERERABUsageReportListTo(v.Value, bb, fresh); err != nil {
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
	if err := s25.BridgeMarshalAPEREmergencyAreaIDBroadcastTo(v.Value, bb, fresh); err != nil {
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
	if err := s25.BridgeMarshalAPEREmergencyAreaIDCancelledTo(v.Value, bb, fresh); err != nil {
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
	if err := s25.BridgeMarshalAPERForbiddenLAsTo(v.Value, bb, fresh); err != nil {
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
	if err := s25.BridgeMarshalAPERForbiddenTAsTo(v.Value, bb, fresh); err != nil {
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
	if err := s25.BridgeMarshalAPERGUMMEIListTo(v.Value, bb, fresh); err != nil {
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
	if err := s25.BridgeMarshalAPERIEsECGIListTo(v.Value, bb, fresh); err != nil {
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
	if err := s25.BridgeMarshalAPERInterSystemMeasurementListTo(v.Value, bb, fresh); err != nil {
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
	if err := s25.BridgeMarshalAPERLastVisitedPSCellListTo(v.Value, bb, fresh); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.perPadding)
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

// PathSwitchRequest represents the ASN.1 type PathSwitchRequest (SEQUENCE).
type PathSwitchRequest struct {
	replay           aper.Snapshot
	stream           aper.WireSpan
	received         bool
	withoutReplay    bool
	receivedAbsolute bool
	receivedBytes    aper.WireSpan
	receivedLocation aper.Location
	ProtocolIEs      PathSwitchRequestIEContainer `asn1:"tag:0,context,implicit"`
	protocolIEsIndef bool                         `asn1:"-" json:"-"`
	extCount         int64                        `asn1:"-" json:"-"`
	extPresent       []bool                       `asn1:"-" json:"-"`
	extData          [][]byte                     `asn1:"-" json:"-"`
	perPadding       aper.FinalPadding            `asn1:"-" json:"-"`
	perExtPadding    []aper.CompletePadding       `asn1:"-" json:"-"`
	extOrigin        []aper.OpaqueOrigin
	extWire          []aper.WireSpan
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

// MarshalAPER encodes PathSwitchRequest to APER format.
func (v *PathSwitchRequest) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *PathSwitchRequest) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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

// UnmarshalAPER decodes PathSwitchRequest from APER format.
func (v *PathSwitchRequest) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes PathSwitchRequest with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *PathSwitchRequest) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "PathSwitchRequest")
	}
	bb.EnterComponent("PathSwitchRequest")
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "PathSwitchRequest")
	}
	padding, err := aper.CaptureFinalBits(bb, "PathSwitchRequest")
	if err != nil {
		return runtime.WrapDecodePath(err, "PathSwitchRequest")
	}
	v.perPadding = padding.WithRecords(v.perPadding)
	return nil
}
func (v *PathSwitchRequest) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = PathSwitchRequest{}
	extAdditions := aper.BeginExtensionAdditions(bb)
	hasExtensions, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	toleranceMark_protocolies := bb.EnterComponent("ProtocolIEs")
	v.ProtocolIEs = make(PathSwitchRequestIEContainer, 0)
	_, errCollection_protocolies := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1128
		if fragmentOffset_protocolies < 0 || fragmentLength_protocolies < 0 || fragmentLength_protocolies > int64(^uint(0)>>1) || fragmentOffset_protocolies > int64(^uint(0)>>1)-fragmentLength_protocolies {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_protocolies; i++ {
			var elem PathSwitchRequestIEField
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

// MarshalAPERERABToBeSwitchedDLList encodes a ERABToBeSwitchedDLList list to APER.
func BridgeMarshalAPERERABToBeSwitchedDLList(list s40.ERABToBeSwitchedDLListComplete) ([]byte, error) {
	return s40.BridgeERABToBeSwitchedDLListCompleteMethodMarshalAPERLegacy(&list)
}

// UnmarshalAPERERABToBeSwitchedDLList decodes a ERABToBeSwitchedDLList list from APER.
func BridgeUnmarshalAPERERABToBeSwitchedDLList(data []byte) (s40.ERABToBeSwitchedDLListComplete, error) {
	var value s40.ERABToBeSwitchedDLListComplete
	if err := s40.BridgeERABToBeSwitchedDLListCompleteMethodUnmarshalAPERLegacy(&value, data); err != nil {
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
	if err := s25.BridgeMarshalAPERERABToBeSwitchedULListTo(v.Value, bb); err != nil {
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

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *PathSwitchRequest) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s14.BridgeReceivedFormAt(v.received, v.receivedBytes, "PathSwitchRequest", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "PathSwitchRequest", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v PathSwitchRequest) WithoutReplay() PathSwitchRequest {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero PathSwitchRequest
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

// Extensions returns owned unknown sequence additions.
func (v *PathSwitchRequest) Extensions() []aper.SequenceExtension {
	if v == nil {
		return nil
	}
	views := aper.SequenceExtensionViews(v.extPresent, aper.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *PathSwitchRequest) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("PathSwitchRequest.Extensions[%d]", index))
	}
	if err := aper.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("PathSwitchRequest.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *PathSwitchRequest) RemoveExtension(index uint64) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("PathSwitchRequest.Extensions[%d]", index))
	}
	if err := aper.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("PathSwitchRequest.Extensions[%d]", index))
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
	if err := s25.BridgeMarshalAPERERABToBeSwitchedULListTo(v.Value, bb, fresh); err != nil {
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

// MarshalAPER encodes a complete value using one per-call change plan.
func (v *PathSwitchRequest) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "PathSwitchRequest")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *PathSwitchRequest) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "PathSwitchRequest")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APPathSwitchRequest(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "PathSwitchRequest")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "PathSwitchRequest")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *PathSwitchRequest) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "PathSwitchRequest")
}
func (v *PathSwitchRequest) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "PathSwitchRequest")
}
func (v *PathSwitchRequest) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APPathSwitchRequest(v, &s)
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
func (v *PathSwitchRequest) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *PathSwitchRequest) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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

// UnmarshalAPER decodes one complete value and returns its report.
func (v *PathSwitchRequest) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "PathSwitchRequest")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded PathSwitchRequest
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APPathSwitchRequest(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = PathSwitchRequest{}
		return report, aper.OperationError(err, "PathSwitchRequest")
	}
	*v = decoded
	return report, aper.OperationError(nil, "PathSwitchRequest")
}

// MarshalAPERERABToBeSwitchedULList encodes a complete named list.
func MarshalAPERERABToBeSwitchedULList(v ERABToBeSwitchedULListComplete, options ...aper.EncodeOption) ([]byte, error) {
	return v.MarshalAPER(options...)
}

// MarshalAPERERABToBeUpdatedList encodes a complete named list.
func MarshalAPERERABToBeUpdatedList(v ERABToBeUpdatedListComplete, options ...aper.EncodeOption) ([]byte, error) {
	return v.MarshalAPER(options...)
}

// UnmarshalAPERERABToBeSwitchedDLList decodes a complete named list.
func UnmarshalAPERERABToBeSwitchedDLList(data []byte, options ...aper.DecodeOption) (s40.ERABToBeSwitchedDLListComplete, aper.DecodeReport, error) {
	var v s40.ERABToBeSwitchedDLListComplete
	report, err := v.UnmarshalAPER(data, options...)
	return v, report, err
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

type PathSwitchRequestIEValue struct {
	id                          s00.ProtocolIEID
	received                    aper.WireSpan
	replay                      aper.Snapshot
	opaque                      aper.OpaqueOpenType
	isOpaque                    bool
	rowENBUES1APID              *s00.ENBUES1APID
	rowERABToBeSwitchedDLList   *s30.ERABToBeSwitchedDLList
	rowSourceMMEUES1APID        *s00.MMEUES1APID
	rowEUTRANCGI                *s17.EUTRANCGI
	rowTAI                      *s31.TAI
	rowUESecurityCapabilities   *s37.UESecurityCapabilities
	rowCSGId                    *s00.CSGId
	rowCellAccessMode           *s00.CellAccessMode
	rowSourceMMEGUMMEI          *s18.GUMMEI
	rowCSGMembershipStatus      *s00.CSGMembershipStatus
	rowTunnelInformationForBBF  *s35.TunnelInformation
	rowLHNID                    *s00.LHNID
	rowRRCResumeCause           *s00.RRCEstablishmentCause
	rowNRUESecurityCapabilities *s19.NRUESecurityCapabilities
	rowPSCellInformation        *s20.PSCellInformation
	rowLTENTNTAIInformation     *s18.LTENTNTAIInformation
}

func (v PathSwitchRequestIEValue) matchesID(id s00.ProtocolIEID, _ ...*aper.DecodeBudget) bool {
	if v.id != id {
		return false
	}
	if v.isOpaque {
		return true
	}
	switch id {
	case s00.ProtocolIEID(8):
		return v.rowENBUES1APID != nil
	case s00.ProtocolIEID(22):
		return v.rowERABToBeSwitchedDLList != nil
	case s00.ProtocolIEID(88):
		return v.rowSourceMMEUES1APID != nil
	case s00.ProtocolIEID(100):
		return v.rowEUTRANCGI != nil
	case s00.ProtocolIEID(67):
		return v.rowTAI != nil
	case s00.ProtocolIEID(107):
		return v.rowUESecurityCapabilities != nil
	case s00.ProtocolIEID(127):
		return v.rowCSGId != nil
	case s00.ProtocolIEID(145):
		return v.rowCellAccessMode != nil
	case s00.ProtocolIEID(157):
		return v.rowSourceMMEGUMMEI != nil
	case s00.ProtocolIEID(146):
		return v.rowCSGMembershipStatus != nil
	case s00.ProtocolIEID(176):
		return v.rowTunnelInformationForBBF != nil
	case s00.ProtocolIEID(186):
		return v.rowLHNID != nil
	case s00.ProtocolIEID(245):
		return v.rowRRCResumeCause != nil
	case s00.ProtocolIEID(269):
		return v.rowNRUESecurityCapabilities != nil
	case s00.ProtocolIEID(288):
		return v.rowPSCellInformation != nil
	case s00.ProtocolIEID(339):
		return v.rowLTENTNTAIInformation != nil
	}
	return false
}

// Opaque returns the retained opaque open value of PathSwitchRequestIEValue and reports whether the opaque alternative is selected.
func (v *PathSwitchRequestIEValue) Opaque() (aper.OpaqueOpenType, bool) {
	if v == nil || !v.isOpaque {
		return aper.OpaqueOpenType{}, false
	}
	return v.opaque, true
}
func (PathSwitchRequestIEValue) rule() aper.SourceRule {
	return aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "PathSwitchRequestIEs"}}
}
func (PathSwitchRequestIEValue) reason(id s00.ProtocolIEID) aper.OpaqueReason {
	switch id {
	case s00.ProtocolIEID(8):
		return aper.UnknownSelector
	case s00.ProtocolIEID(22):
		return aper.UnknownSelector
	case s00.ProtocolIEID(88):
		return aper.UnknownSelector
	case s00.ProtocolIEID(100):
		return aper.UnknownSelector
	case s00.ProtocolIEID(67):
		return aper.UnknownSelector
	case s00.ProtocolIEID(107):
		return aper.UnknownSelector
	case s00.ProtocolIEID(127):
		return aper.UnknownSelector
	case s00.ProtocolIEID(145):
		return aper.UnknownSelector
	case s00.ProtocolIEID(157):
		return aper.UnknownSelector
	case s00.ProtocolIEID(146):
		return aper.UnknownSelector
	case s00.ProtocolIEID(176):
		return aper.UnknownSelector
	case s00.ProtocolIEID(186):
		return aper.UnknownSelector
	case s00.ProtocolIEID(245):
		return aper.UnknownSelector
	case s00.ProtocolIEID(269):
		return aper.UnknownSelector
	case s00.ProtocolIEID(288):
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

// AsENBUES1APID returns the selected ENBUES1APID value of PathSwitchRequestIEValue and reports whether that alternative is active.
func (v *PathSwitchRequestIEValue) AsENBUES1APID() (*s00.ENBUES1APID, bool) {
	if v == nil || v.id != s00.ProtocolIEID(8) || v.rowENBUES1APID == nil {
		return nil, false
	}
	return v.rowENBUES1APID, true
}

// AsERABToBeSwitchedDLList returns the selected ERABToBeSwitchedDLList value of PathSwitchRequestIEValue and reports whether that alternative is active.
func (v *PathSwitchRequestIEValue) AsERABToBeSwitchedDLList() (*s30.ERABToBeSwitchedDLList, bool) {
	if v == nil || v.id != s00.ProtocolIEID(22) || v.rowERABToBeSwitchedDLList == nil {
		return nil, false
	}
	return v.rowERABToBeSwitchedDLList, true
}

// AsSourceMMEUES1APID returns the selected SourceMMEUES1APID value of PathSwitchRequestIEValue and reports whether that alternative is active.
func (v *PathSwitchRequestIEValue) AsSourceMMEUES1APID() (*s00.MMEUES1APID, bool) {
	if v == nil || v.id != s00.ProtocolIEID(88) || v.rowSourceMMEUES1APID == nil {
		return nil, false
	}
	return v.rowSourceMMEUES1APID, true
}

// AsEUTRANCGI returns the selected EUTRANCGI value of PathSwitchRequestIEValue and reports whether that alternative is active.
func (v *PathSwitchRequestIEValue) AsEUTRANCGI() (*s17.EUTRANCGI, bool) {
	if v == nil || v.id != s00.ProtocolIEID(100) || v.rowEUTRANCGI == nil {
		return nil, false
	}
	return v.rowEUTRANCGI, true
}

// AsTAI returns the selected TAI value of PathSwitchRequestIEValue and reports whether that alternative is active.
func (v *PathSwitchRequestIEValue) AsTAI() (*s31.TAI, bool) {
	if v == nil || v.id != s00.ProtocolIEID(67) || v.rowTAI == nil {
		return nil, false
	}
	return v.rowTAI, true
}

// AsUESecurityCapabilities returns the selected UESecurityCapabilities value of PathSwitchRequestIEValue and reports whether that alternative is active.
func (v *PathSwitchRequestIEValue) AsUESecurityCapabilities() (*s37.UESecurityCapabilities, bool) {
	if v == nil || v.id != s00.ProtocolIEID(107) || v.rowUESecurityCapabilities == nil {
		return nil, false
	}
	return v.rowUESecurityCapabilities, true
}

// AsCSGId returns the selected CSGId value of PathSwitchRequestIEValue and reports whether that alternative is active.
func (v *PathSwitchRequestIEValue) AsCSGId() (*s00.CSGId, bool) {
	if v == nil || v.id != s00.ProtocolIEID(127) || v.rowCSGId == nil {
		return nil, false
	}
	return v.rowCSGId, true
}

// AsCellAccessMode returns the selected CellAccessMode value of PathSwitchRequestIEValue and reports whether that alternative is active.
func (v *PathSwitchRequestIEValue) AsCellAccessMode() (*s00.CellAccessMode, bool) {
	if v == nil || v.id != s00.ProtocolIEID(145) || v.rowCellAccessMode == nil {
		return nil, false
	}
	return v.rowCellAccessMode, true
}

// AsSourceMMEGUMMEI returns the selected SourceMMEGUMMEI value of PathSwitchRequestIEValue and reports whether that alternative is active.
func (v *PathSwitchRequestIEValue) AsSourceMMEGUMMEI() (*s18.GUMMEI, bool) {
	if v == nil || v.id != s00.ProtocolIEID(157) || v.rowSourceMMEGUMMEI == nil {
		return nil, false
	}
	return v.rowSourceMMEGUMMEI, true
}

// AsCSGMembershipStatus returns the selected CSGMembershipStatus value of PathSwitchRequestIEValue and reports whether that alternative is active.
func (v *PathSwitchRequestIEValue) AsCSGMembershipStatus() (*s00.CSGMembershipStatus, bool) {
	if v == nil || v.id != s00.ProtocolIEID(146) || v.rowCSGMembershipStatus == nil {
		return nil, false
	}
	return v.rowCSGMembershipStatus, true
}

// AsTunnelInformationForBBF returns the selected TunnelInformationForBBF value of PathSwitchRequestIEValue and reports whether that alternative is active.
func (v *PathSwitchRequestIEValue) AsTunnelInformationForBBF() (*s35.TunnelInformation, bool) {
	if v == nil || v.id != s00.ProtocolIEID(176) || v.rowTunnelInformationForBBF == nil {
		return nil, false
	}
	return v.rowTunnelInformationForBBF, true
}

// AsLHNID returns the selected LHNID value of PathSwitchRequestIEValue and reports whether that alternative is active.
func (v *PathSwitchRequestIEValue) AsLHNID() (*s00.LHNID, bool) {
	if v == nil || v.id != s00.ProtocolIEID(186) || v.rowLHNID == nil {
		return nil, false
	}
	return v.rowLHNID, true
}

// AsRRCResumeCause returns the selected RRCResumeCause value of PathSwitchRequestIEValue and reports whether that alternative is active.
func (v *PathSwitchRequestIEValue) AsRRCResumeCause() (*s00.RRCEstablishmentCause, bool) {
	if v == nil || v.id != s00.ProtocolIEID(245) || v.rowRRCResumeCause == nil {
		return nil, false
	}
	return v.rowRRCResumeCause, true
}

// AsNRUESecurityCapabilities returns the selected NRUESecurityCapabilities value of PathSwitchRequestIEValue and reports whether that alternative is active.
func (v *PathSwitchRequestIEValue) AsNRUESecurityCapabilities() (*s19.NRUESecurityCapabilities, bool) {
	if v == nil || v.id != s00.ProtocolIEID(269) || v.rowNRUESecurityCapabilities == nil {
		return nil, false
	}
	return v.rowNRUESecurityCapabilities, true
}

// AsPSCellInformation returns the selected PSCellInformation value of PathSwitchRequestIEValue and reports whether that alternative is active.
func (v *PathSwitchRequestIEValue) AsPSCellInformation() (*s20.PSCellInformation, bool) {
	if v == nil || v.id != s00.ProtocolIEID(288) || v.rowPSCellInformation == nil {
		return nil, false
	}
	return v.rowPSCellInformation, true
}

// AsLTENTNTAIInformation returns the selected LTENTNTAIInformation value of PathSwitchRequestIEValue and reports whether that alternative is active.
func (v *PathSwitchRequestIEValue) AsLTENTNTAIInformation() (*s18.LTENTNTAIInformation, bool) {
	if v == nil || v.id != s00.ProtocolIEID(339) || v.rowLTENTNTAIInformation == nil {
		return nil, false
	}
	return v.rowLTENTNTAIInformation, true
}
func (v PathSwitchRequestIEValue) decode(id s00.ProtocolIEID, raw aper.OpaqueOpenType) (PathSwitchRequestIEValue, error) {
	out := PathSwitchRequestIEValue{id: id}
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
	case s00.ProtocolIEID(22):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		child := scope
		list, err := s40.BridgeUnmarshalAPERERABToBeSwitchedDLListFrom(child)
		if err != nil {
			return out, fmt.Errorf("%s %w", "ERABToBeSwitchedDLList:", err)
		}
		padding, err := aper.CaptureOpenTypePadding(child)
		if err != nil {
			return out, err
		}
		_ = padding
		value := list
		out.rowERABToBeSwitchedDLList = &value
		raw.RetainContents(&out.received)
	case s00.ProtocolIEID(88):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		bb := scope
		decoded, err := aper.DecodeIntegerAligned(bb, s07.BridgeInt64Ptr(0), s07.BridgeInt64Ptr(4294967295), false)
		value := s00.MMEUES1APID(decoded)
		if err != nil {
			return out, fmt.Errorf("%s %w", "SourceMMEUES1APID:", err)
		}
		if _, err := aper.CompleteOpenTypeValue(bb, value); err != nil {
			return out, err
		}
		out.rowSourceMMEUES1APID = &value
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
		var value s31.TAI
		child := scope
		if err := s31.BridgeTAIMethodUnmarshalAPERFrom(&value, child); err != nil {
			return out, fmt.Errorf("%s %w", "TAI:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "TAI")
		if err != nil {
			return out, err
		}
		*s31.BridgeTAIFieldPerPadding(&value) = padding
		*s31.BridgeTAIFieldReceived(&value) = true
		raw.RetainContents(s31.BridgeTAIFieldReceivedBytes(&value))
		*s31.BridgeTAIFieldReceivedLocation(&value) = raw.ContentLocation()
		out.rowTAI = &value
		raw.RetainContents(&out.received)
	case s00.ProtocolIEID(107):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		var value s37.UESecurityCapabilities
		child := scope
		if err := s37.BridgeUESecurityCapabilitiesMethodUnmarshalAPERFrom(&value, child); err != nil {
			return out, fmt.Errorf("%s %w", "UESecurityCapabilities:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "UESecurityCapabilities")
		if err != nil {
			return out, err
		}
		*s37.BridgeUESecurityCapabilitiesFieldPerPadding(&value) = padding
		*s37.BridgeUESecurityCapabilitiesFieldReceived(&value) = true
		raw.RetainContents(s37.BridgeUESecurityCapabilitiesFieldReceivedBytes(&value))
		*s37.BridgeUESecurityCapabilitiesFieldReceivedLocation(&value) = raw.ContentLocation()
		out.rowUESecurityCapabilities = &value
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
	case s00.ProtocolIEID(157):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		var value s18.GUMMEI
		child := scope
		if err := s18.BridgeGUMMEIMethodUnmarshalAPERFrom(&value, child); err != nil {
			return out, fmt.Errorf("%s %w", "SourceMMEGUMMEI:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "GUMMEI")
		if err != nil {
			return out, err
		}
		*s18.BridgeGUMMEIFieldPerPadding(&value) = padding
		*s18.BridgeGUMMEIFieldReceived(&value) = true
		raw.RetainContents(s18.BridgeGUMMEIFieldReceivedBytes(&value))
		*s18.BridgeGUMMEIFieldReceivedLocation(&value) = raw.ContentLocation()
		out.rowSourceMMEGUMMEI = &value
		raw.RetainContents(&out.received)
	case s00.ProtocolIEID(146):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		bb := scope
		decoded, err := aper.DecodeEnumeratedAligned(bb, 2, false, aper.EnumerationSource{KnownExtensions: 0, Path: "CSGMembershipStatus"})
		value := s00.CSGMembershipStatus(decoded)
		if err != nil {
			return out, fmt.Errorf("%s %w", "CSGMembershipStatus:", err)
		}
		if _, err := aper.CompleteOpenTypeValue(bb, value); err != nil {
			return out, err
		}
		out.rowCSGMembershipStatus = &value
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
	case s00.ProtocolIEID(245):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		bb := scope
		decoded, err := aper.DecodeEnumeratedAligned(bb, 5, true, aper.EnumerationSource{KnownExtensions: 3, Path: "RRCEstablishmentCause"})
		value := s00.RRCEstablishmentCause(decoded)
		if err != nil {
			return out, fmt.Errorf("%s %w", "RRCResumeCause:", err)
		}
		if _, err := aper.CompleteOpenTypeValue(bb, value); err != nil {
			return out, err
		}
		out.rowRRCResumeCause = &value
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
func (v PathSwitchRequestIEValue) encode() ([]byte, error) { return v.encodeFresh(false, nil) }
func (v PathSwitchRequestIEValue) encodeFresh(fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
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
			return nil, fmt.Errorf("%s missing value", "PathSwitchRequestIEs.id-eNB-UE-S1AP-ID:")
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
	case s00.ProtocolIEID(22):
		if v.rowERABToBeSwitchedDLList == nil {
			return nil, fmt.Errorf("%s missing value", "PathSwitchRequestIEs.id-E-RABToBeSwitchedDLList:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		complete := s40.ERABToBeSwitchedDLListComplete{Value: *v.rowERABToBeSwitchedDLList}
		candidate, err := s40.BridgeERABToBeSwitchedDLListCompleteMethodMarshalAPERBudget(&complete, budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	case s00.ProtocolIEID(88):
		if v.rowSourceMMEUES1APID == nil {
			return nil, fmt.Errorf("%s missing value", "PathSwitchRequestIEs.id-SourceMME-UE-S1AP-ID:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		encodeBB := aper.NewBudgetBuffer(budget)
		if err := aper.EncodeIntegerAligned(encodeBB, int64(*v.rowSourceMMEUES1APID), s07.BridgeInt64Ptr(0), s07.BridgeInt64Ptr(4294967295), false); err != nil {
			return nil, err
		}
		candidate := encodeBB.CompleteBytes()
		return candidate, nil
	case s00.ProtocolIEID(100):
		if v.rowEUTRANCGI == nil {
			return nil, fmt.Errorf("%s missing value", "PathSwitchRequestIEs.id-EUTRAN-CGI:")
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
			return nil, fmt.Errorf("%s missing value", "PathSwitchRequestIEs.id-TAI:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		candidate, err := s31.BridgeTAIMethodMarshalAPERBudget(v.rowTAI, budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	case s00.ProtocolIEID(107):
		if v.rowUESecurityCapabilities == nil {
			return nil, fmt.Errorf("%s missing value", "PathSwitchRequestIEs.id-UESecurityCapabilities:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		candidate, err := s37.BridgeUESecurityCapabilitiesMethodMarshalAPERBudget(v.rowUESecurityCapabilities, budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	case s00.ProtocolIEID(127):
		if v.rowCSGId == nil {
			return nil, fmt.Errorf("%s missing value", "PathSwitchRequestIEs.id-CSG-Id:")
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
			return nil, fmt.Errorf("%s missing value", "PathSwitchRequestIEs.id-CellAccessMode:")
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
	case s00.ProtocolIEID(157):
		if v.rowSourceMMEGUMMEI == nil {
			return nil, fmt.Errorf("%s missing value", "PathSwitchRequestIEs.id-SourceMME-GUMMEI:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		candidate, err := s18.BridgeGUMMEIMethodMarshalAPERBudget(v.rowSourceMMEGUMMEI, budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	case s00.ProtocolIEID(146):
		if v.rowCSGMembershipStatus == nil {
			return nil, fmt.Errorf("%s missing value", "PathSwitchRequestIEs.id-CSGMembershipStatus:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		encodeBB := aper.NewBudgetBuffer(budget)
		if err := aper.EncodeEnumeratedAligned(encodeBB, int64(*v.rowCSGMembershipStatus), 2, false); err != nil {
			return nil, err
		}
		candidate := encodeBB.CompleteBytes()
		return candidate, nil
	case s00.ProtocolIEID(176):
		if v.rowTunnelInformationForBBF == nil {
			return nil, fmt.Errorf("%s missing value", "PathSwitchRequestIEs.id-Tunnel-Information-for-BBF:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		candidate, err := s35.BridgeTunnelInformationMethodMarshalAPERBudget(v.rowTunnelInformationForBBF, budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	case s00.ProtocolIEID(186):
		if v.rowLHNID == nil {
			return nil, fmt.Errorf("%s missing value", "PathSwitchRequestIEs.id-LHN-ID:")
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
	case s00.ProtocolIEID(245):
		if v.rowRRCResumeCause == nil {
			return nil, fmt.Errorf("%s missing value", "PathSwitchRequestIEs.id-RRC-Resume-Cause:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		encodeBB := aper.NewBudgetBuffer(budget)
		if err := aper.EncodeEnumeratedAligned(encodeBB, int64(*v.rowRRCResumeCause), 5, true); err != nil {
			return nil, err
		}
		candidate := encodeBB.CompleteBytes()
		return candidate, nil
	case s00.ProtocolIEID(269):
		if v.rowNRUESecurityCapabilities == nil {
			return nil, fmt.Errorf("%s missing value", "PathSwitchRequestIEs.id-NRUESecurityCapabilities:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		candidate, err := s19.BridgeNRUESecurityCapabilitiesMethodMarshalAPERBudget(v.rowNRUESecurityCapabilities, budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	case s00.ProtocolIEID(288):
		if v.rowPSCellInformation == nil {
			return nil, fmt.Errorf("%s missing value", "PathSwitchRequestIEs.id-PSCellInformation:")
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
			return nil, fmt.Errorf("%s missing value", "PathSwitchRequestIEs.id-LTE-NTN-TAI-Information:")
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
		return nil, fmt.Errorf("%s id %d has no value", "PathSwitchRequestIEValue:", v.id)
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

type PathSwitchRequestIETable struct{}

func PathSwitchRequestIEs() PathSwitchRequestIETable { return PathSwitchRequestIETable{} }

// ID returns the ASN.1 object-set identity of PathSwitchRequestIETable.
func (PathSwitchRequestIETable) ID() s00.TableID {
	return func() s00.TableID {
		sealed := s00.TableID{}
		*s00.BridgeTableIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "PathSwitchRequestIEs"}
		return sealed
	}()
}

// Table returns the ASN.1 object-set table described by PathSwitchRequestIETable.
func (PathSwitchRequestIETable) Table() s00.PathSwitchRequestIEValueIETable {
	return func() s00.PathSwitchRequestIEValueIETable {
		sealed := s00.PathSwitchRequestIEValueIETable{}
		*s00.BridgePathSwitchRequestIEValueIETableFieldBound(&sealed) = true
		return sealed
	}()
}
func (PathSwitchRequestIETable) infoENBUES1APID() s00.FieldInfo {
	return s00.FieldInfo{Table: PathSwitchRequestIEs().ID(), ID: s00.ProtocolIEID(8), Criticality: s00.CriticalityReject, Presence: s00.PresenceMandatory, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "ENB-UE-S1AP-ID"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "PathSwitchRequestIEs", Row: "id-eNB-UE-S1AP-ID"}}}
}

// ENBUES1APID returns the typed binding for the ENBUES1APID row of PathSwitchRequestIETable.
func (t PathSwitchRequestIETable) ENBUES1APID() PathSwitchRequestENBUES1APIDIEBinding {
	return PathSwitchRequestENBUES1APIDIEBinding{info: t.infoENBUES1APID(), codec: func() s00.ENBUES1APIDValueCodec {
		sealed := s00.ENBUES1APIDValueCodec{}
		*s00.BridgeENBUES1APIDValueCodecFieldPath(&sealed) = "ENBUES1APID"
		*s00.BridgeENBUES1APIDValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.ENBUES1APID, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s00.ENBUES1APID
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("ENBUES1APID")
			var zero PathSwitchRequestIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(8), raw)
			if err != nil {
				var empty s00.ENBUES1APID
				return empty, runtime.WrapDecodePath(err, "ENBUES1APID")
			}
			value, ok := decoded.AsENBUES1APID()
			if !ok {
				var empty s00.ENBUES1APID
				return empty, fmt.Errorf("binding PathSwitchRequestIEs.id-eNB-UE-S1AP-ID: no selected value")
			}
			return *value, nil
		}
		*s00.BridgeENBUES1APIDValueCodecFieldEncode(&sealed) = func(value s00.ENBUES1APID, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (PathSwitchRequestIEValue{id: s00.ProtocolIEID(8), rowENBUES1APID: &value}).encodeFresh(fresh, budget)
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
		inject: func(value s00.ENBUES1APID) PathSwitchRequestIEValue {
			return PathSwitchRequestIEValue{id: s00.ProtocolIEID(8), rowENBUES1APID: &value}
		}, get: func(value *PathSwitchRequestIEValue) (*s00.ENBUES1APID, bool) { return value.AsENBUES1APID() }}
}
func (PathSwitchRequestIETable) infoERABToBeSwitchedDLList() s00.FieldInfo {
	return s00.FieldInfo{Table: PathSwitchRequestIEs().ID(), ID: s00.ProtocolIEID(22), Criticality: s00.CriticalityReject, Presence: s00.PresenceMandatory, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "E-RABToBeSwitchedDLList"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "PathSwitchRequestIEs", Row: "id-E-RABToBeSwitchedDLList"}}}
}

// ERABToBeSwitchedDLList returns the typed binding for the ERABToBeSwitchedDLList row of PathSwitchRequestIETable.
func (t PathSwitchRequestIETable) ERABToBeSwitchedDLList() PathSwitchRequestERABToBeSwitchedDLListIEBinding {
	return PathSwitchRequestERABToBeSwitchedDLListIEBinding{info: t.infoERABToBeSwitchedDLList(), codec: func() s30.ERABToBeSwitchedDLListValueCodec {
		sealed := s30.ERABToBeSwitchedDLListValueCodec{}
		*s30.BridgeERABToBeSwitchedDLListValueCodecFieldPath(&sealed) = "ERABToBeSwitchedDLList"
		*s30.BridgeERABToBeSwitchedDLListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s30.ERABToBeSwitchedDLList, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s30.ERABToBeSwitchedDLList
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("ERABToBeSwitchedDLList")
			var zero PathSwitchRequestIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(22), raw)
			if err != nil {
				var empty s30.ERABToBeSwitchedDLList
				return empty, runtime.WrapDecodePath(err, "ERABToBeSwitchedDLList")
			}
			value, ok := decoded.AsERABToBeSwitchedDLList()
			if !ok {
				var empty s30.ERABToBeSwitchedDLList
				return empty, fmt.Errorf("binding PathSwitchRequestIEs.id-E-RABToBeSwitchedDLList: no selected value")
			}
			return *value, nil
		}
		*s30.BridgeERABToBeSwitchedDLListValueCodecFieldEncode(&sealed) = func(value s30.ERABToBeSwitchedDLList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (PathSwitchRequestIEValue{id: s00.ProtocolIEID(22), rowERABToBeSwitchedDLList: &value}).encodeFresh(fresh, budget)
		}
		*s30.BridgeERABToBeSwitchedDLListValueCodecFieldCapture(&sealed) = func(v s30.ERABToBeSwitchedDLList, options aper.DecodeState) (s30.ERABToBeSwitchedDLList, aper.Snapshot,

		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s30.BridgeCaptureS1APERABToBeSwitchedDLList(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s30.BridgeERABToBeSwitchedDLListValueCodecFieldCompare(&sealed) = func(v s30.ERABToBeSwitchedDLList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s30.BridgeCompareS1APERABToBeSwitchedDLList(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s30.BridgeERABToBeSwitchedDLListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ERABToBeSwitchedDLList"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s30.ERABToBeSwitchedDLList) PathSwitchRequestIEValue {
			return PathSwitchRequestIEValue{id: s00.ProtocolIEID(22), rowERABToBeSwitchedDLList: &value}
		}, get: func(value *PathSwitchRequestIEValue) (*s30.ERABToBeSwitchedDLList, bool) {
			return value.AsERABToBeSwitchedDLList()
		}}
}
func (PathSwitchRequestIETable) infoSourceMMEUES1APID() s00.FieldInfo {
	return s00.FieldInfo{Table: PathSwitchRequestIEs().ID(), ID: s00.ProtocolIEID(88), Criticality: s00.CriticalityReject, Presence: s00.PresenceMandatory, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "MME-UE-S1AP-ID"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "PathSwitchRequestIEs", Row: "id-SourceMME-UE-S1AP-ID"}}}
}

// SourceMMEUES1APID returns the typed binding for the SourceMMEUES1APID row of PathSwitchRequestIETable.
func (t PathSwitchRequestIETable) SourceMMEUES1APID() PathSwitchRequestMMEUES1APIDIEBinding {
	return PathSwitchRequestMMEUES1APIDIEBinding{info: t.infoSourceMMEUES1APID(), codec: func() s01.MMEUES1APIDValueCodec {
		sealed := s01.MMEUES1APIDValueCodec{}
		*s01.BridgeMMEUES1APIDValueCodecFieldPath(&sealed) = "MMEUES1APID"
		*s01.BridgeMMEUES1APIDValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.MMEUES1APID, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s00.MMEUES1APID
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("MMEUES1APID")
			var zero PathSwitchRequestIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(88), raw)
			if err != nil {
				var empty s00.MMEUES1APID
				return empty, runtime.WrapDecodePath(err, "MMEUES1APID")
			}
			value, ok := decoded.AsSourceMMEUES1APID()
			if !ok {
				var empty s00.MMEUES1APID
				return empty, fmt.Errorf("binding PathSwitchRequestIEs.id-SourceMME-UE-S1AP-ID: no selected value")
			}
			return *value, nil
		}
		*s01.BridgeMMEUES1APIDValueCodecFieldEncode(&sealed) = func(value s00.MMEUES1APID, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (PathSwitchRequestIEValue{id: s00.ProtocolIEID(88), rowSourceMMEUES1APID: &value}).encodeFresh(fresh, budget)
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
		inject: func(value s00.MMEUES1APID) PathSwitchRequestIEValue {
			return PathSwitchRequestIEValue{id: s00.ProtocolIEID(88), rowSourceMMEUES1APID: &value}
		}, get: func(value *PathSwitchRequestIEValue) (*s00.MMEUES1APID, bool) { return value.AsSourceMMEUES1APID() }}
}
func (PathSwitchRequestIETable) infoEUTRANCGI() s00.FieldInfo {
	return s00.FieldInfo{Table: PathSwitchRequestIEs().ID(), ID: s00.ProtocolIEID(100), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceMandatory, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "EUTRAN-CGI"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "PathSwitchRequestIEs", Row: "id-EUTRAN-CGI"}}}
}

// EUTRANCGI returns the typed binding for the EUTRANCGI row of PathSwitchRequestIETable.
func (t PathSwitchRequestIETable) EUTRANCGI() PathSwitchRequestEUTRANCGIIEBinding {
	return PathSwitchRequestEUTRANCGIIEBinding{info: t.infoEUTRANCGI(), codec: func() s17.EUTRANCGIValueCodec {
		sealed := s17.EUTRANCGIValueCodec{}
		*s17.BridgeEUTRANCGIValueCodecFieldPath(&sealed) = "EUTRANCGI"
		*s17.BridgeEUTRANCGIValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s17.EUTRANCGI, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s17.EUTRANCGI
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("EUTRANCGI")
			var zero PathSwitchRequestIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(100), raw)
			if err != nil {
				var empty s17.EUTRANCGI
				return empty, runtime.WrapDecodePath(err, "EUTRANCGI")
			}
			value, ok := decoded.AsEUTRANCGI()
			if !ok {
				var empty s17.EUTRANCGI
				return empty, fmt.Errorf("binding PathSwitchRequestIEs.id-EUTRAN-CGI: no selected value")
			}
			return *value, nil
		}
		*s17.BridgeEUTRANCGIValueCodecFieldEncode(&sealed) = func(value s17.EUTRANCGI, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (PathSwitchRequestIEValue{id: s00.ProtocolIEID(100), rowEUTRANCGI: &value}).encodeFresh(fresh, budget)
		}
		*s17.BridgeEUTRANCGIValueCodecFieldCapture(&sealed) = func(v s17.EUTRANCGI, options aper.DecodeState) (s17.EUTRANCGI, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.
				Begin()
			s17.BridgeCaptureS1APEUTRANCGI(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s17.BridgeEUTRANCGIValueCodecFieldCompare(&sealed) = func(v s17.EUTRANCGI, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s17.BridgeCompareS1APEUTRANCGI(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s17.BridgeEUTRANCGIValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:EUTRANCGI"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s17.EUTRANCGI) PathSwitchRequestIEValue {
			return PathSwitchRequestIEValue{id: s00.ProtocolIEID(100), rowEUTRANCGI: &value}
		}, get: func(value *PathSwitchRequestIEValue) (*s17.EUTRANCGI, bool) { return value.AsEUTRANCGI() }}
}
func (PathSwitchRequestIETable) infoTAI() s00.FieldInfo {
	return s00.FieldInfo{Table: PathSwitchRequestIEs().ID(), ID: s00.ProtocolIEID(67), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceMandatory, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "TAI"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "PathSwitchRequestIEs", Row: "id-TAI"}}}
}

// TAI returns the typed binding for the TAI row of PathSwitchRequestIETable.
func (t PathSwitchRequestIETable) TAI() PathSwitchRequestTAIIEBinding {
	return PathSwitchRequestTAIIEBinding{info: t.infoTAI(), codec: func() s32.TAIValueCodec {
		sealed := s32.TAIValueCodec{}
		*s32.BridgeTAIValueCodecFieldPath(&sealed) = "TAI"
		*s32.BridgeTAIValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s31.TAI, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s31.TAI
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("TAI")
			var zero PathSwitchRequestIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(67), raw)
			if err != nil {
				var empty s31.TAI
				return empty, runtime.WrapDecodePath(err, "TAI")
			}
			value, ok := decoded.AsTAI()
			if !ok {
				var empty s31.TAI
				return empty, fmt.Errorf("binding PathSwitchRequestIEs.id-TAI: no selected value")
			}
			return *value, nil
		}
		*s32.BridgeTAIValueCodecFieldEncode(&sealed) = func(value s31.TAI, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (PathSwitchRequestIEValue{id: s00.ProtocolIEID(67), rowTAI: &value}).encodeFresh(fresh, budget)
		}
		*s32.BridgeTAIValueCodecFieldCapture(&sealed) = func(v s31.TAI, options aper.DecodeState) (s31.TAI, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s31.BridgeCaptureS1APTAI(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,
				false)
			return v, root
		}
		*s32.BridgeTAIValueCodecFieldCompare(&sealed) = func(v s31.TAI, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s31.BridgeCompareS1APTAI(&v, &s)
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
		inject: func(value s31.TAI) PathSwitchRequestIEValue {
			return PathSwitchRequestIEValue{id: s00.ProtocolIEID(67), rowTAI: &value}
		}, get: func(value *PathSwitchRequestIEValue) (*s31.TAI, bool) { return value.AsTAI() }}
}
func (PathSwitchRequestIETable) infoUESecurityCapabilities() s00.FieldInfo {
	return s00.FieldInfo{Table: PathSwitchRequestIEs().ID(), ID: s00.ProtocolIEID(107), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceMandatory, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "UESecurityCapabilities"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "PathSwitchRequestIEs", Row: "id-UESecurityCapabilities"}}}
}

// UESecurityCapabilities returns the typed binding for the UESecurityCapabilities row of PathSwitchRequestIETable.
func (t PathSwitchRequestIETable) UESecurityCapabilities() PathSwitchRequestUESecurityCapabilitiesIEBinding {
	return PathSwitchRequestUESecurityCapabilitiesIEBinding{info: t.infoUESecurityCapabilities(), codec: func() s37.UESecurityCapabilitiesValueCodec {
		sealed := s37.UESecurityCapabilitiesValueCodec{}
		*s37.BridgeUESecurityCapabilitiesValueCodecFieldPath(&sealed) = "UESecurityCapabilities"
		*s37.BridgeUESecurityCapabilitiesValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s37.UESecurityCapabilities, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s37.UESecurityCapabilities
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("UESecurityCapabilities")
			var zero PathSwitchRequestIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(107), raw)
			if err != nil {
				var empty s37.UESecurityCapabilities
				return empty, runtime.WrapDecodePath(err, "UESecurityCapabilities")
			}
			value, ok := decoded.AsUESecurityCapabilities()
			if !ok {
				var empty s37.UESecurityCapabilities
				return empty, fmt.Errorf("binding PathSwitchRequestIEs.id-UESecurityCapabilities: no selected value")
			}
			return *value, nil
		}
		*s37.BridgeUESecurityCapabilitiesValueCodecFieldEncode(&sealed) = func(value s37.UESecurityCapabilities, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (PathSwitchRequestIEValue{id: s00.ProtocolIEID(107), rowUESecurityCapabilities: &value}).encodeFresh(fresh, budget)
		}
		*s37.BridgeUESecurityCapabilitiesValueCodecFieldCapture(&sealed) = func(v s37.UESecurityCapabilities, options aper.DecodeState) (s37.UESecurityCapabilities, aper.Snapshot,

		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s37.BridgeCaptureS1APUESecurityCapabilities(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s37.BridgeUESecurityCapabilitiesValueCodecFieldCompare(&sealed) = func(v s37.UESecurityCapabilities, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s37.BridgeCompareS1APUESecurityCapabilities(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s37.BridgeUESecurityCapabilitiesValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:UESecurityCapabilities"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s37.UESecurityCapabilities) PathSwitchRequestIEValue {
			return PathSwitchRequestIEValue{id: s00.ProtocolIEID(107), rowUESecurityCapabilities: &value}
		}, get: func(value *PathSwitchRequestIEValue) (*s37.UESecurityCapabilities, bool) {
			return value.AsUESecurityCapabilities()
		}}
}
func (PathSwitchRequestIETable) infoCSGId() s00.FieldInfo {
	return s00.FieldInfo{Table: PathSwitchRequestIEs().ID(), ID: s00.ProtocolIEID(127), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "CSG-Id"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "PathSwitchRequestIEs", Row: "id-CSG-Id"}}}
}

// CSGId returns the typed binding for the CSGId row of PathSwitchRequestIETable.
func (t PathSwitchRequestIETable) CSGId() PathSwitchRequestCSGIdIEBinding {
	return PathSwitchRequestCSGIdIEBinding{info: t.infoCSGId(), codec: func() s00.CSGIdValueCodec {
		sealed := s00.CSGIdValueCodec{}
		*s00.BridgeCSGIdValueCodecFieldPath(&sealed) = "CSGId"
		*s00.BridgeCSGIdValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.CSGId, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s00.CSGId
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("CSGId")
			var zero PathSwitchRequestIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(127), raw)
			if err != nil {
				var empty s00.CSGId
				return empty, runtime.WrapDecodePath(err, "CSGId")
			}
			value, ok := decoded.AsCSGId()
			if !ok {
				var empty s00.CSGId
				return empty, fmt.Errorf("binding PathSwitchRequestIEs.id-CSG-Id: no selected value")
			}
			return *value, nil
		}
		*s00.BridgeCSGIdValueCodecFieldEncode(&sealed) = func(value s00.CSGId, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (PathSwitchRequestIEValue{id: s00.ProtocolIEID(127), rowCSGId: &value}).encodeFresh(fresh, budget)
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
		inject: func(value s00.CSGId) PathSwitchRequestIEValue {
			return PathSwitchRequestIEValue{id: s00.ProtocolIEID(127), rowCSGId: &value}
		}, get: func(value *PathSwitchRequestIEValue) (*s00.CSGId, bool) { return value.AsCSGId() }}
}
func (PathSwitchRequestIETable) infoCellAccessMode() s00.FieldInfo {
	return s00.FieldInfo{Table: PathSwitchRequestIEs().ID(), ID: s00.ProtocolIEID(145), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "CellAccessMode"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "PathSwitchRequestIEs", Row: "id-CellAccessMode"}}}
}

// CellAccessMode returns the typed binding for the CellAccessMode row of PathSwitchRequestIETable.
func (t PathSwitchRequestIETable) CellAccessMode() PathSwitchRequestCellAccessModeIEBinding {
	return PathSwitchRequestCellAccessModeIEBinding{info: t.infoCellAccessMode(), codec: func() s00.CellAccessModeValueCodec {
		sealed := s00.CellAccessModeValueCodec{}
		*s00.BridgeCellAccessModeValueCodecFieldPath(&sealed) = "CellAccessMode"
		*s00.BridgeCellAccessModeValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.CellAccessMode, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s00.CellAccessMode
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("CellAccessMode")
			var zero PathSwitchRequestIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(145), raw)
			if err != nil {
				var empty s00.CellAccessMode
				return empty, runtime.WrapDecodePath(err, "CellAccessMode")
			}
			value, ok := decoded.AsCellAccessMode()
			if !ok {
				var empty s00.CellAccessMode
				return empty, fmt.Errorf("binding PathSwitchRequestIEs.id-CellAccessMode: no selected value")
			}
			return *value, nil
		}
		*s00.BridgeCellAccessModeValueCodecFieldEncode(&sealed) = func(value s00.CellAccessMode, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (PathSwitchRequestIEValue{id: s00.ProtocolIEID(145), rowCellAccessMode: &value}).encodeFresh(fresh, budget)
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
		inject: func(value s00.CellAccessMode) PathSwitchRequestIEValue {
			return PathSwitchRequestIEValue{id: s00.ProtocolIEID(145), rowCellAccessMode: &value}
		}, get: func(value *PathSwitchRequestIEValue) (*s00.CellAccessMode, bool) { return value.AsCellAccessMode() }}
}
func (PathSwitchRequestIETable) infoSourceMMEGUMMEI() s00.FieldInfo {
	return s00.FieldInfo{Table: PathSwitchRequestIEs().ID(), ID: s00.ProtocolIEID(157), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "GUMMEI"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "PathSwitchRequestIEs", Row: "id-SourceMME-GUMMEI"}}}
}

// SourceMMEGUMMEI returns the typed binding for the SourceMMEGUMMEI row of PathSwitchRequestIETable.
func (t PathSwitchRequestIETable) SourceMMEGUMMEI() PathSwitchRequestGUMMEIIEBinding {
	return PathSwitchRequestGUMMEIIEBinding{info: t.infoSourceMMEGUMMEI(), codec: func() s18.GUMMEIValueCodec {
		sealed := s18.GUMMEIValueCodec{}
		*s18.BridgeGUMMEIValueCodecFieldPath(&sealed) = "GUMMEI"
		*s18.BridgeGUMMEIValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s18.GUMMEI, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s18.GUMMEI
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("GUMMEI")
			var zero PathSwitchRequestIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(157), raw)
			if err != nil {
				var empty s18.GUMMEI
				return empty, runtime.WrapDecodePath(err, "GUMMEI")
			}
			value, ok := decoded.AsSourceMMEGUMMEI()
			if !ok {
				var empty s18.GUMMEI
				return empty, fmt.Errorf("binding PathSwitchRequestIEs.id-SourceMME-GUMMEI: no selected value")
			}
			return *value, nil
		}
		*s18.BridgeGUMMEIValueCodecFieldEncode(&sealed) = func(value s18.GUMMEI, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (PathSwitchRequestIEValue{id: s00.ProtocolIEID(157), rowSourceMMEGUMMEI: &value}).encodeFresh(fresh, budget)
		}
		*s18.BridgeGUMMEIValueCodecFieldCapture(&sealed) = func(v s18.GUMMEI, options aper.DecodeState) (s18.GUMMEI, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.
				Begin()
			s18.BridgeCaptureS1APGUMMEI(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s18.BridgeGUMMEIValueCodecFieldCompare(&sealed) = func(v s18.GUMMEI, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s18.BridgeCompareS1APGUMMEI(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s18.BridgeGUMMEIValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:GUMMEI"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s18.GUMMEI) PathSwitchRequestIEValue {
			return PathSwitchRequestIEValue{id: s00.ProtocolIEID(157), rowSourceMMEGUMMEI: &value}
		}, get: func(value *PathSwitchRequestIEValue) (*s18.GUMMEI, bool) { return value.AsSourceMMEGUMMEI() }}
}
func (PathSwitchRequestIETable) infoCSGMembershipStatus() s00.FieldInfo {
	return s00.FieldInfo{Table: PathSwitchRequestIEs().ID(), ID: s00.ProtocolIEID(146), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "CSGMembershipStatus"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "PathSwitchRequestIEs", Row: "id-CSGMembershipStatus"}}}
}

// CSGMembershipStatus returns the typed binding for the CSGMembershipStatus row of PathSwitchRequestIETable.
func (t PathSwitchRequestIETable) CSGMembershipStatus() PathSwitchRequestCSGMembershipStatusIEBinding {
	return PathSwitchRequestCSGMembershipStatusIEBinding{info: t.infoCSGMembershipStatus(), codec: func() s00.CSGMembershipStatusValueCodec {
		sealed := s00.CSGMembershipStatusValueCodec{}
		*s00.BridgeCSGMembershipStatusValueCodecFieldPath(&sealed) = "CSGMembershipStatus"
		*s00.BridgeCSGMembershipStatusValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.CSGMembershipStatus, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s00.CSGMembershipStatus
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("CSGMembershipStatus")
			var zero PathSwitchRequestIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(146), raw)
			if err != nil {
				var empty s00.CSGMembershipStatus
				return empty, runtime.WrapDecodePath(err, "CSGMembershipStatus")
			}
			value, ok := decoded.AsCSGMembershipStatus()
			if !ok {
				var empty s00.CSGMembershipStatus
				return empty, fmt.Errorf("binding PathSwitchRequestIEs.id-CSGMembershipStatus: no selected value")
			}
			return *value, nil
		}
		*s00.BridgeCSGMembershipStatusValueCodecFieldEncode(&sealed) = func(value s00.CSGMembershipStatus, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (PathSwitchRequestIEValue{id: s00.ProtocolIEID(146), rowCSGMembershipStatus: &value}).encodeFresh(fresh, budget)
		}
		*s00.BridgeCSGMembershipStatusValueCodecFieldCapture(&sealed) = func(v s00.CSGMembershipStatus, options aper.DecodeState) (s00.CSGMembershipStatus, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s00.BridgeCaptureS1APCSGMembershipStatus(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s00.BridgeCSGMembershipStatusValueCodecFieldCompare(&sealed) = func(v s00.CSGMembershipStatus, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s02.BridgeCompareS1APCSGMembershipStatus(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s00.BridgeCSGMembershipStatusValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:CSGMembershipStatus"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s00.CSGMembershipStatus) PathSwitchRequestIEValue {
			return PathSwitchRequestIEValue{id: s00.ProtocolIEID(146), rowCSGMembershipStatus: &value}
		}, get: func(value *PathSwitchRequestIEValue) (*s00.CSGMembershipStatus, bool) {
			return value.AsCSGMembershipStatus()
		}}
}
func (PathSwitchRequestIETable) infoTunnelInformationForBBF() s00.FieldInfo {
	return s00.FieldInfo{Table: PathSwitchRequestIEs().ID(), ID: s00.ProtocolIEID(176), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "TunnelInformation"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "PathSwitchRequestIEs", Row: "id-Tunnel-Information-for-BBF"}}}
}

// TunnelInformationForBBF returns the typed binding for the TunnelInformationForBBF row of PathSwitchRequestIETable.
func (t PathSwitchRequestIETable) TunnelInformationForBBF() PathSwitchRequestTunnelInformationIEBinding {
	return PathSwitchRequestTunnelInformationIEBinding{info: t.infoTunnelInformationForBBF(), codec: func() s35.TunnelInformationValueCodec {
		sealed := s35.TunnelInformationValueCodec{}
		*s35.BridgeTunnelInformationValueCodecFieldPath(&sealed) = "TunnelInformation"
		*s35.BridgeTunnelInformationValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s35.TunnelInformation, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s35.TunnelInformation
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("TunnelInformation")
			var zero PathSwitchRequestIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(176), raw)
			if err != nil {
				var empty s35.TunnelInformation
				return empty, runtime.WrapDecodePath(err, "TunnelInformation")
			}
			value, ok := decoded.AsTunnelInformationForBBF()
			if !ok {
				var empty s35.TunnelInformation
				return empty, fmt.Errorf("binding PathSwitchRequestIEs.id-Tunnel-Information-for-BBF: no selected value")
			}
			return *value, nil
		}
		*s35.BridgeTunnelInformationValueCodecFieldEncode(&sealed) = func(value s35.TunnelInformation, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (PathSwitchRequestIEValue{id: s00.ProtocolIEID(176), rowTunnelInformationForBBF: &value}).encodeFresh(fresh, budget)
		}
		*s35.BridgeTunnelInformationValueCodecFieldCapture(&sealed) = func(v s35.TunnelInformation, options aper.DecodeState) (s35.TunnelInformation, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s35.BridgeCaptureS1APTunnelInformation(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v,
				root

		}
		*s35.BridgeTunnelInformationValueCodecFieldCompare(&sealed) = func(v s35.TunnelInformation, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s35.BridgeCompareS1APTunnelInformation(&v, &s)
			s.End(f, root, false)
			return s.
				Plan(), s.BudgetValue()
		}
		*s35.BridgeTunnelInformationValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:TunnelInformation"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s35.TunnelInformation) PathSwitchRequestIEValue {
			return PathSwitchRequestIEValue{id: s00.ProtocolIEID(176), rowTunnelInformationForBBF: &value}
		}, get: func(value *PathSwitchRequestIEValue) (*s35.TunnelInformation, bool) {
			return value.AsTunnelInformationForBBF()
		}}
}
func (PathSwitchRequestIETable) infoLHNID() s00.FieldInfo {
	return s00.FieldInfo{Table: PathSwitchRequestIEs().ID(), ID: s00.ProtocolIEID(186), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "LHN-ID"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "PathSwitchRequestIEs", Row: "id-LHN-ID"}}}
}

// LHNID returns the typed binding for the LHNID row of PathSwitchRequestIETable.
func (t PathSwitchRequestIETable) LHNID() PathSwitchRequestLHNIDIEBinding {
	return PathSwitchRequestLHNIDIEBinding{info: t.infoLHNID(), codec: func() s01.LHNIDValueCodec {
		sealed := s01.LHNIDValueCodec{}
		*s01.BridgeLHNIDValueCodecFieldPath(&sealed) = "LHNID"
		*s01.BridgeLHNIDValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.LHNID, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s00.LHNID
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("LHNID")
			var zero PathSwitchRequestIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(186), raw)
			if err != nil {
				var empty s00.LHNID
				return empty, runtime.WrapDecodePath(err, "LHNID")
			}
			value, ok := decoded.AsLHNID()
			if !ok {
				var empty s00.LHNID
				return empty, fmt.Errorf("binding PathSwitchRequestIEs.id-LHN-ID: no selected value")
			}
			return *value, nil
		}
		*s01.BridgeLHNIDValueCodecFieldEncode(&sealed) = func(value s00.LHNID, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (PathSwitchRequestIEValue{id: s00.ProtocolIEID(186), rowLHNID: &value}).encodeFresh(fresh, budget)
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
		inject: func(value s00.LHNID) PathSwitchRequestIEValue {
			return PathSwitchRequestIEValue{id: s00.ProtocolIEID(186), rowLHNID: &value}
		}, get: func(value *PathSwitchRequestIEValue) (*s00.LHNID, bool) { return value.AsLHNID() }}
}
func (PathSwitchRequestIETable) infoRRCResumeCause() s00.FieldInfo {
	return s00.FieldInfo{Table: PathSwitchRequestIEs().ID(), ID: s00.ProtocolIEID(245), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "RRC-Establishment-Cause"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "PathSwitchRequestIEs", Row: "id-RRC-Resume-Cause"}}}
}

// RRCResumeCause returns the typed binding for the RRCResumeCause row of PathSwitchRequestIETable.
func (t PathSwitchRequestIETable) RRCResumeCause() PathSwitchRequestRRCEstablishmentCauseIEBinding {
	return PathSwitchRequestRRCEstablishmentCauseIEBinding{info: t.infoRRCResumeCause(), codec: func() s01.RRCEstablishmentCauseValueCodec {
		sealed := s01.RRCEstablishmentCauseValueCodec{}
		*s01.BridgeRRCEstablishmentCauseValueCodecFieldPath(&sealed) = "RRCEstablishmentCause"
		*s01.BridgeRRCEstablishmentCauseValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.RRCEstablishmentCause, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s00.RRCEstablishmentCause
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("RRCEstablishmentCause")
			var zero PathSwitchRequestIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(245), raw)
			if err != nil {
				var empty s00.RRCEstablishmentCause
				return empty, runtime.WrapDecodePath(err, "RRCEstablishmentCause")
			}
			value, ok := decoded.AsRRCResumeCause()
			if !ok {
				var empty s00.RRCEstablishmentCause
				return empty, fmt.Errorf("binding PathSwitchRequestIEs.id-RRC-Resume-Cause: no selected value")
			}
			return *value, nil
		}
		*s01.BridgeRRCEstablishmentCauseValueCodecFieldEncode(&sealed) = func(value s00.RRCEstablishmentCause, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (PathSwitchRequestIEValue{id: s00.ProtocolIEID(245), rowRRCResumeCause: &value}).encodeFresh(fresh, budget)
		}
		*s01.BridgeRRCEstablishmentCauseValueCodecFieldCapture(&sealed) = func(v s00.RRCEstablishmentCause, options aper.DecodeState) (s00.RRCEstablishmentCause, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s00.BridgeCaptureS1APRRCEstablishmentCause(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)

			return v, root
		}
		*s01.BridgeRRCEstablishmentCauseValueCodecFieldCompare(&sealed) = func(v s00.RRCEstablishmentCause, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s06.BridgeCompareS1APRRCEstablishmentCause(&v, &s)
			s.End(f, root, false)

			return s.Plan(), s.BudgetValue()
		}
		*s01.BridgeRRCEstablishmentCauseValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:RRCEstablishmentCause"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s00.RRCEstablishmentCause) PathSwitchRequestIEValue {
			return PathSwitchRequestIEValue{id: s00.ProtocolIEID(245), rowRRCResumeCause: &value}
		}, get: func(value *PathSwitchRequestIEValue) (*s00.RRCEstablishmentCause, bool) {
			return value.AsRRCResumeCause()
		}}
}
func (PathSwitchRequestIETable) infoNRUESecurityCapabilities() s00.FieldInfo {
	return s00.FieldInfo{Table: PathSwitchRequestIEs().ID(), ID: s00.ProtocolIEID(269), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "NRUESecurityCapabilities"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "PathSwitchRequestIEs", Row: "id-NRUESecurityCapabilities"}}}
}

// NRUESecurityCapabilities returns the typed binding for the NRUESecurityCapabilities row of PathSwitchRequestIETable.
func (t PathSwitchRequestIETable) NRUESecurityCapabilities() PathSwitchRequestNRUESecurityCapabilitiesIEBinding {
	return PathSwitchRequestNRUESecurityCapabilitiesIEBinding{info: t.infoNRUESecurityCapabilities(), codec: func() s19.NRUESecurityCapabilitiesValueCodec {
		sealed := s19.NRUESecurityCapabilitiesValueCodec{}
		*s19.BridgeNRUESecurityCapabilitiesValueCodecFieldPath(&sealed) = "NRUESecurityCapabilities"
		*s19.BridgeNRUESecurityCapabilitiesValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s19.NRUESecurityCapabilities, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s19.NRUESecurityCapabilities
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("NRUESecurityCapabilities")
			var zero PathSwitchRequestIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(269), raw)
			if err != nil {
				var empty s19.NRUESecurityCapabilities
				return empty, runtime.WrapDecodePath(err, "NRUESecurityCapabilities")
			}
			value, ok := decoded.AsNRUESecurityCapabilities()
			if !ok {
				var empty s19.NRUESecurityCapabilities
				return empty, fmt.Errorf("binding PathSwitchRequestIEs.id-NRUESecurityCapabilities: no selected value")
			}
			return *value, nil
		}
		*s19.BridgeNRUESecurityCapabilitiesValueCodecFieldEncode(&sealed) = func(value s19.NRUESecurityCapabilities, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (PathSwitchRequestIEValue{id: s00.ProtocolIEID(269), rowNRUESecurityCapabilities: &value}).encodeFresh(fresh, budget)
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
		inject: func(value s19.NRUESecurityCapabilities) PathSwitchRequestIEValue {
			return PathSwitchRequestIEValue{id: s00.ProtocolIEID(269), rowNRUESecurityCapabilities: &value}
		}, get: func(value *PathSwitchRequestIEValue) (*s19.NRUESecurityCapabilities, bool) {
			return value.AsNRUESecurityCapabilities()
		}}
}
func (PathSwitchRequestIETable) infoPSCellInformation() s00.FieldInfo {
	return s00.FieldInfo{Table: PathSwitchRequestIEs().ID(), ID: s00.ProtocolIEID(288), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "PSCellInformation"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "PathSwitchRequestIEs", Row: "id-PSCellInformation"}}}
}

// PSCellInformation returns the typed binding for the PSCellInformation row of PathSwitchRequestIETable.
func (t PathSwitchRequestIETable) PSCellInformation() PathSwitchRequestPSCellInformationIEBinding {
	return PathSwitchRequestPSCellInformationIEBinding{info: t.infoPSCellInformation(), codec: func() s20.PSCellInformationValueCodec {
		sealed := s20.PSCellInformationValueCodec{}
		*s20.BridgePSCellInformationValueCodecFieldPath(&sealed) = "PSCellInformation"
		*s20.BridgePSCellInformationValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s20.PSCellInformation, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s20.PSCellInformation
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("PSCellInformation")
			var zero PathSwitchRequestIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(288), raw)
			if err != nil {
				var empty s20.PSCellInformation
				return empty, runtime.WrapDecodePath(err, "PSCellInformation")
			}
			value, ok := decoded.AsPSCellInformation()
			if !ok {
				var empty s20.PSCellInformation
				return empty, fmt.Errorf("binding PathSwitchRequestIEs.id-PSCellInformation: no selected value")
			}
			return *value, nil
		}
		*s20.BridgePSCellInformationValueCodecFieldEncode(&sealed) = func(value s20.PSCellInformation, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (PathSwitchRequestIEValue{id: s00.ProtocolIEID(288), rowPSCellInformation: &value}).encodeFresh(fresh, budget)
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
		inject: func(value s20.PSCellInformation) PathSwitchRequestIEValue {
			return PathSwitchRequestIEValue{id: s00.ProtocolIEID(288), rowPSCellInformation: &value}
		}, get: func(value *PathSwitchRequestIEValue) (*s20.PSCellInformation, bool) {
			return value.AsPSCellInformation()
		}}
}
func (PathSwitchRequestIETable) infoLTENTNTAIInformation() s00.FieldInfo {
	return s00.FieldInfo{Table: PathSwitchRequestIEs().ID(), ID: s00.ProtocolIEID(339), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "LTE-NTN-TAI-Information"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "PathSwitchRequestIEs", Row: "id-LTE-NTN-TAI-Information"}}}
}

// LTENTNTAIInformation returns the typed binding for the LTENTNTAIInformation row of PathSwitchRequestIETable.
func (t PathSwitchRequestIETable) LTENTNTAIInformation() PathSwitchRequestLTENTNTAIInformationIEBinding {
	return PathSwitchRequestLTENTNTAIInformationIEBinding{info: t.infoLTENTNTAIInformation(), codec: func() s18.LTENTNTAIInformationValueCodec {
		sealed := s18.LTENTNTAIInformationValueCodec{}
		*s18.BridgeLTENTNTAIInformationValueCodecFieldPath(&sealed) = "LTENTNTAIInformation"
		*s18.BridgeLTENTNTAIInformationValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s18.LTENTNTAIInformation, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s18.LTENTNTAIInformation
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("LTENTNTAIInformation")
			var zero PathSwitchRequestIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(339), raw)
			if err != nil {
				var empty s18.LTENTNTAIInformation
				return empty, runtime.WrapDecodePath(err, "LTENTNTAIInformation")
			}
			value, ok := decoded.AsLTENTNTAIInformation()
			if !ok {
				var empty s18.LTENTNTAIInformation
				return empty, fmt.Errorf("binding PathSwitchRequestIEs.id-LTE-NTN-TAI-Information: no selected value")
			}
			return *value, nil
		}
		*s18.BridgeLTENTNTAIInformationValueCodecFieldEncode(&sealed) = func(value s18.LTENTNTAIInformation, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (PathSwitchRequestIEValue{id: s00.ProtocolIEID(339), rowLTENTNTAIInformation: &value}).encodeFresh(fresh, budget)
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
		inject: func(value s18.LTENTNTAIInformation) PathSwitchRequestIEValue {
			return PathSwitchRequestIEValue{id: s00.ProtocolIEID(339), rowLTENTNTAIInformation: &value}
		}, get: func(value *PathSwitchRequestIEValue) (*s18.LTENTNTAIInformation, bool) {
			return value.AsLTENTNTAIInformation()
		}}
}

// NewOpaque constructs an owned opaque field for an identifier without a typed row in PathSwitchRequestIETable.
func (t PathSwitchRequestIETable) NewOpaque(id s00.ProtocolIEID, criticality s00.Criticality, data []byte) (PathSwitchRequestIEField, error) {
	if id < 0 || id > 65535 || criticality < 0 || criticality > 2 {
		return PathSwitchRequestIEField{}, aper.OperationError(fmt.Errorf("invalid opaque IE selector or criticality"), "Opaque")
	}
	switch id {
	case s00.ProtocolIEID(8):
		return PathSwitchRequestIEField{}, aper.OperationError(fmt.Errorf("known IE id-eNB-UE-S1AP-ID requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(22):
		return PathSwitchRequestIEField{}, aper.OperationError(fmt.Errorf("known IE id-E-RABToBeSwitchedDLList requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(88):
		return PathSwitchRequestIEField{}, aper.OperationError(fmt.Errorf("known IE id-SourceMME-UE-S1AP-ID requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(100):
		return PathSwitchRequestIEField{}, aper.OperationError(fmt.Errorf("known IE id-EUTRAN-CGI requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(67):
		return PathSwitchRequestIEField{}, aper.OperationError(fmt.Errorf("known IE id-TAI requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(107):
		return PathSwitchRequestIEField{}, aper.OperationError(fmt.Errorf("known IE id-UESecurityCapabilities requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(127):
		return PathSwitchRequestIEField{}, aper.OperationError(fmt.Errorf("known IE id-CSG-Id requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(145):
		return PathSwitchRequestIEField{}, aper.OperationError(fmt.Errorf("known IE id-CellAccessMode requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(157):
		return PathSwitchRequestIEField{}, aper.OperationError(fmt.Errorf("known IE id-SourceMME-GUMMEI requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(146):
		return PathSwitchRequestIEField{}, aper.OperationError(fmt.Errorf("known IE id-CSGMembershipStatus requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(176):
		return PathSwitchRequestIEField{}, aper.OperationError(fmt.Errorf("known IE id-Tunnel-Information-for-BBF requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(186):
		return PathSwitchRequestIEField{}, aper.OperationError(fmt.Errorf("known IE id-LHN-ID requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(245):
		return PathSwitchRequestIEField{}, aper.OperationError(fmt.Errorf("known IE id-RRC-Resume-Cause requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(269):
		return PathSwitchRequestIEField{}, aper.OperationError(fmt.Errorf("known IE id-NRUESecurityCapabilities requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(288):
		return PathSwitchRequestIEField{}, aper.OperationError(fmt.Errorf("known IE id-PSCellInformation requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(339):
		return PathSwitchRequestIEField{}, aper.OperationError(fmt.Errorf("known IE id-LTE-NTN-TAI-Information requires its typed binding"), "Opaque")
	default:
		budget, err := aper.BuildBudget()
		if err != nil {
			return PathSwitchRequestIEField{}, aper.OperationError(err, "Opaque")
		}
		opaque, err := aper.BuildOpaqueOpenType(data, budget)
		if err != nil {
			return PathSwitchRequestIEField{}, aper.OperationError(err, "Opaque")
		}
		return PathSwitchRequestIEField{Id: id, Criticality: criticality, Value: PathSwitchRequestIEValue{id: id, opaque: opaque, isOpaque: true}}, aper.OperationError(nil, "Opaque")
	}
}

// CauseCodec binds the complete APER value type.
func CauseCodec() s14.CauseValueCodec {
	return LastVisitedEUTRANCellInformationExtIEs().HOCause().Codec()
}

// ERABToBeSwitchedDLListCodec binds the complete APER value type.
func ERABToBeSwitchedDLListCodec() s30.ERABToBeSwitchedDLListValueCodec {
	return PathSwitchRequestIEs().ERABToBeSwitchedDLList().Codec()
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

// OverloadResponseCodec binds the complete APER value type.
func OverloadResponseCodec() s20.OverloadResponseValueCodec {
	return OverloadStartIEs().OverloadResponse().Codec()
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
func BridgePathSwitchRequestAPERValueFieldContext(v *PathSwitchRequestAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgePathSwitchRequestAPERValueFieldReceived(v *PathSwitchRequestAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgePathSwitchRequestAPERValueFieldReplay(v *PathSwitchRequestAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgePathSwitchRequestAPERValueFieldWithoutReplay(v *PathSwitchRequestAPERValue) *bool {
	return &v.withoutReplay
}
func BridgePathSwitchRequestCSGIdIEBindingFieldCodec(v *PathSwitchRequestCSGIdIEBinding) *s00.CSGIdValueCodec {
	return &v.codec
}
func BridgePathSwitchRequestCSGIdIEBindingFieldGet(v *PathSwitchRequestCSGIdIEBinding) *func(*PathSwitchRequestIEValue) (*s00.CSGId, bool) {
	return &v.get
}
func BridgePathSwitchRequestCSGIdIEBindingFieldInfo(v *PathSwitchRequestCSGIdIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgePathSwitchRequestCSGIdIEBindingFieldInject(v *PathSwitchRequestCSGIdIEBinding) *func(s00.CSGId) PathSwitchRequestIEValue {
	return &v.inject
}
func BridgePathSwitchRequestCSGMembershipStatusIEBindingFieldCodec(v *PathSwitchRequestCSGMembershipStatusIEBinding) *s00.CSGMembershipStatusValueCodec {
	return &v.codec
}
func BridgePathSwitchRequestCSGMembershipStatusIEBindingFieldGet(v *PathSwitchRequestCSGMembershipStatusIEBinding) *func(*PathSwitchRequestIEValue) (*s00.CSGMembershipStatus, bool) {
	return &v.get
}
func BridgePathSwitchRequestCSGMembershipStatusIEBindingFieldInfo(v *PathSwitchRequestCSGMembershipStatusIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgePathSwitchRequestCSGMembershipStatusIEBindingFieldInject(v *PathSwitchRequestCSGMembershipStatusIEBinding) *func(s00.CSGMembershipStatus) PathSwitchRequestIEValue {
	return &v.inject
}
func BridgePathSwitchRequestCellAccessModeIEBindingFieldCodec(v *PathSwitchRequestCellAccessModeIEBinding) *s00.CellAccessModeValueCodec {
	return &v.codec
}
func BridgePathSwitchRequestCellAccessModeIEBindingFieldGet(v *PathSwitchRequestCellAccessModeIEBinding) *func(*PathSwitchRequestIEValue) (*s00.CellAccessMode, bool) {
	return &v.get
}
func BridgePathSwitchRequestCellAccessModeIEBindingFieldInfo(v *PathSwitchRequestCellAccessModeIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgePathSwitchRequestCellAccessModeIEBindingFieldInject(v *PathSwitchRequestCellAccessModeIEBinding) *func(s00.CellAccessMode) PathSwitchRequestIEValue {
	return &v.inject
}
func BridgePathSwitchRequestENBUES1APIDIEBindingFieldCodec(v *PathSwitchRequestENBUES1APIDIEBinding) *s00.ENBUES1APIDValueCodec {
	return &v.codec
}
func BridgePathSwitchRequestENBUES1APIDIEBindingFieldGet(v *PathSwitchRequestENBUES1APIDIEBinding) *func(*PathSwitchRequestIEValue) (*s00.ENBUES1APID, bool) {
	return &v.get
}
func BridgePathSwitchRequestENBUES1APIDIEBindingFieldInfo(v *PathSwitchRequestENBUES1APIDIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgePathSwitchRequestENBUES1APIDIEBindingFieldInject(v *PathSwitchRequestENBUES1APIDIEBinding) *func(s00.ENBUES1APID) PathSwitchRequestIEValue {
	return &v.inject
}
func BridgePathSwitchRequestERABToBeSwitchedDLListIEBindingFieldCodec(v *PathSwitchRequestERABToBeSwitchedDLListIEBinding) *s30.ERABToBeSwitchedDLListValueCodec {
	return &v.codec
}
func BridgePathSwitchRequestERABToBeSwitchedDLListIEBindingFieldGet(v *PathSwitchRequestERABToBeSwitchedDLListIEBinding) *func(*PathSwitchRequestIEValue) (*s30.ERABToBeSwitchedDLList, bool) {
	return &v.get
}
func BridgePathSwitchRequestERABToBeSwitchedDLListIEBindingFieldInfo(v *PathSwitchRequestERABToBeSwitchedDLListIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgePathSwitchRequestERABToBeSwitchedDLListIEBindingFieldInject(v *PathSwitchRequestERABToBeSwitchedDLListIEBinding) *func(s30.ERABToBeSwitchedDLList) PathSwitchRequestIEValue {
	return &v.inject
}
func BridgePathSwitchRequestEUTRANCGIIEBindingFieldCodec(v *PathSwitchRequestEUTRANCGIIEBinding) *s17.EUTRANCGIValueCodec {
	return &v.codec
}
func BridgePathSwitchRequestEUTRANCGIIEBindingFieldGet(v *PathSwitchRequestEUTRANCGIIEBinding) *func(*PathSwitchRequestIEValue) (*s17.EUTRANCGI, bool) {
	return &v.get
}
func BridgePathSwitchRequestEUTRANCGIIEBindingFieldInfo(v *PathSwitchRequestEUTRANCGIIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgePathSwitchRequestEUTRANCGIIEBindingFieldInject(v *PathSwitchRequestEUTRANCGIIEBinding) *func(s17.EUTRANCGI) PathSwitchRequestIEValue {
	return &v.inject
}
func BridgePathSwitchRequestFieldExtCount(v *PathSwitchRequest) *int64   { return &v.extCount }
func BridgePathSwitchRequestFieldExtData(v *PathSwitchRequest) *[][]byte { return &v.extData }
func BridgePathSwitchRequestFieldExtOrigin(v *PathSwitchRequest) *[]aper.OpaqueOrigin {
	return &v.extOrigin
}
func BridgePathSwitchRequestFieldExtPresent(v *PathSwitchRequest) *[]bool       { return &v.extPresent }
func BridgePathSwitchRequestFieldExtWire(v *PathSwitchRequest) *[]aper.WireSpan { return &v.extWire }
func BridgePathSwitchRequestFieldPerExtPadding(v *PathSwitchRequest) *[]aper.CompletePadding {
	return &v.perExtPadding
}
func BridgePathSwitchRequestFieldPerPadding(v *PathSwitchRequest) *aper.FinalPadding {
	return &v.perPadding
}
func BridgePathSwitchRequestFieldProtocolIEsIndef(v *PathSwitchRequest) *bool {
	return &v.protocolIEsIndef
}
func BridgePathSwitchRequestFieldReceived(v *PathSwitchRequest) *bool { return &v.received }
func BridgePathSwitchRequestFieldReceivedAbsolute(v *PathSwitchRequest) *bool {
	return &v.receivedAbsolute
}
func BridgePathSwitchRequestFieldReceivedBytes(v *PathSwitchRequest) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgePathSwitchRequestFieldReceivedLocation(v *PathSwitchRequest) *aper.Location {
	return &v.receivedLocation
}
func BridgePathSwitchRequestFieldReplay(v *PathSwitchRequest) *aper.Snapshot { return &v.replay }
func BridgePathSwitchRequestFieldStream(v *PathSwitchRequest) *aper.WireSpan { return &v.stream }
func BridgePathSwitchRequestFieldWithoutReplay(v *PathSwitchRequest) *bool   { return &v.withoutReplay }
func BridgePathSwitchRequestGUMMEIIEBindingFieldCodec(v *PathSwitchRequestGUMMEIIEBinding) *s18.GUMMEIValueCodec {
	return &v.codec
}
func BridgePathSwitchRequestGUMMEIIEBindingFieldGet(v *PathSwitchRequestGUMMEIIEBinding) *func(*PathSwitchRequestIEValue) (*s18.GUMMEI, bool) {
	return &v.get
}
func BridgePathSwitchRequestGUMMEIIEBindingFieldInfo(v *PathSwitchRequestGUMMEIIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgePathSwitchRequestGUMMEIIEBindingFieldInject(v *PathSwitchRequestGUMMEIIEBinding) *func(s18.GUMMEI) PathSwitchRequestIEValue {
	return &v.inject
}
func BridgePathSwitchRequestIEContainerAPERValueFieldContext(v *PathSwitchRequestIEContainerAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgePathSwitchRequestIEContainerAPERValueFieldReceived(v *PathSwitchRequestIEContainerAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgePathSwitchRequestIEContainerAPERValueFieldReplay(v *PathSwitchRequestIEContainerAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgePathSwitchRequestIEContainerAPERValueFieldWithoutReplay(v *PathSwitchRequestIEContainerAPERValue) *bool {
	return &v.withoutReplay
}
func BridgePathSwitchRequestIEContainerValueCodecFieldCapture(v *PathSwitchRequestIEContainerValueCodec) *func(PathSwitchRequestIEContainer, aper.DecodeState) (PathSwitchRequestIEContainer, aper.Snapshot) {
	return &v.capture
}
func BridgePathSwitchRequestIEContainerValueCodecFieldCompare(v *PathSwitchRequestIEContainerValueCodec) *func(PathSwitchRequestIEContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgePathSwitchRequestIEContainerValueCodecFieldContext(v *PathSwitchRequestIEContainerValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgePathSwitchRequestIEContainerValueCodecFieldDecode(v *PathSwitchRequestIEContainerValueCodec) *func([]byte, aper.DecodeState) (PathSwitchRequestIEContainer, error) {
	return &v.decode
}
func BridgePathSwitchRequestIEContainerValueCodecFieldEncode(v *PathSwitchRequestIEContainerValueCodec) *func(PathSwitchRequestIEContainer, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgePathSwitchRequestIEContainerValueCodecFieldPath(v *PathSwitchRequestIEContainerValueCodec) *aper.Path {
	return &v.path
}
func BridgePathSwitchRequestIEContainerValueCodecMethodEncodeBudgetValue(v PathSwitchRequestIEContainerValueCodec, a0 PathSwitchRequestIEContainer, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgePathSwitchRequestIEContainerValueCodecMethodEncodeChanged(v PathSwitchRequestIEContainerValueCodec, a0 PathSwitchRequestIEContainer, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgePathSwitchRequestIEFieldAPERValueFieldContext(v *PathSwitchRequestIEFieldAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgePathSwitchRequestIEFieldAPERValueFieldReceived(v *PathSwitchRequestIEFieldAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgePathSwitchRequestIEFieldAPERValueFieldReplay(v *PathSwitchRequestIEFieldAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgePathSwitchRequestIEFieldAPERValueFieldWithoutReplay(v *PathSwitchRequestIEFieldAPERValue) *bool {
	return &v.withoutReplay
}
func BridgePathSwitchRequestIEFieldFieldReceived(v *PathSwitchRequestIEField) *aper.CompletePadding {
	return &v.received
}
func BridgePathSwitchRequestIEFieldFieldReplay(v *PathSwitchRequestIEField) *aper.Snapshot {
	return &v.replay
}
func BridgePathSwitchRequestIEFieldFieldStream(v *PathSwitchRequestIEField) *aper.WireSpan {
	return &v.stream
}
func BridgePathSwitchRequestIEFieldFieldWithoutReplay(v *PathSwitchRequestIEField) *bool {
	return &v.withoutReplay
}
func BridgePathSwitchRequestIEFieldMethodMarshalAPERTo(v *PathSwitchRequestIEField, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgePathSwitchRequestIEFieldMethodUnmarshalAPERFrom(v *PathSwitchRequestIEField, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgePathSwitchRequestIEFieldValueCodecFieldCapture(v *PathSwitchRequestIEFieldValueCodec) *func(PathSwitchRequestIEField, aper.DecodeState) (PathSwitchRequestIEField, aper.Snapshot) {
	return &v.capture
}
func BridgePathSwitchRequestIEFieldValueCodecFieldCompare(v *PathSwitchRequestIEFieldValueCodec) *func(PathSwitchRequestIEField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgePathSwitchRequestIEFieldValueCodecFieldContext(v *PathSwitchRequestIEFieldValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgePathSwitchRequestIEFieldValueCodecFieldDecode(v *PathSwitchRequestIEFieldValueCodec) *func([]byte, aper.DecodeState) (PathSwitchRequestIEField, error) {
	return &v.decode
}
func BridgePathSwitchRequestIEFieldValueCodecFieldEncode(v *PathSwitchRequestIEFieldValueCodec) *func(PathSwitchRequestIEField, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgePathSwitchRequestIEFieldValueCodecFieldPath(v *PathSwitchRequestIEFieldValueCodec) *aper.Path {
	return &v.path
}
func BridgePathSwitchRequestIEFieldValueCodecMethodEncodeBudgetValue(v PathSwitchRequestIEFieldValueCodec, a0 PathSwitchRequestIEField, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgePathSwitchRequestIEFieldValueCodecMethodEncodeChanged(v PathSwitchRequestIEFieldValueCodec, a0 PathSwitchRequestIEField, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgePathSwitchRequestIETableMethodInfoCSGId(v PathSwitchRequestIETable) s00.FieldInfo {
	return v.infoCSGId()
}
func BridgePathSwitchRequestIETableMethodInfoCSGMembershipStatus(v PathSwitchRequestIETable) s00.FieldInfo {
	return v.infoCSGMembershipStatus()
}
func BridgePathSwitchRequestIETableMethodInfoCellAccessMode(v PathSwitchRequestIETable) s00.FieldInfo {
	return v.infoCellAccessMode()
}
func BridgePathSwitchRequestIETableMethodInfoENBUES1APID(v PathSwitchRequestIETable) s00.FieldInfo {
	return v.infoENBUES1APID()
}
func BridgePathSwitchRequestIETableMethodInfoERABToBeSwitchedDLList(v PathSwitchRequestIETable) s00.FieldInfo {
	return v.infoERABToBeSwitchedDLList()
}
func BridgePathSwitchRequestIETableMethodInfoEUTRANCGI(v PathSwitchRequestIETable) s00.FieldInfo {
	return v.infoEUTRANCGI()
}
func BridgePathSwitchRequestIETableMethodInfoLHNID(v PathSwitchRequestIETable) s00.FieldInfo {
	return v.infoLHNID()
}
func BridgePathSwitchRequestIETableMethodInfoLTENTNTAIInformation(v PathSwitchRequestIETable) s00.FieldInfo {
	return v.infoLTENTNTAIInformation()
}
func BridgePathSwitchRequestIETableMethodInfoNRUESecurityCapabilities(v PathSwitchRequestIETable) s00.FieldInfo {
	return v.infoNRUESecurityCapabilities()
}
func BridgePathSwitchRequestIETableMethodInfoPSCellInformation(v PathSwitchRequestIETable) s00.FieldInfo {
	return v.infoPSCellInformation()
}
func BridgePathSwitchRequestIETableMethodInfoRRCResumeCause(v PathSwitchRequestIETable) s00.FieldInfo {
	return v.infoRRCResumeCause()
}
func BridgePathSwitchRequestIETableMethodInfoSourceMMEGUMMEI(v PathSwitchRequestIETable) s00.FieldInfo {
	return v.infoSourceMMEGUMMEI()
}
func BridgePathSwitchRequestIETableMethodInfoSourceMMEUES1APID(v PathSwitchRequestIETable) s00.FieldInfo {
	return v.infoSourceMMEUES1APID()
}
func BridgePathSwitchRequestIETableMethodInfoTAI(v PathSwitchRequestIETable) s00.FieldInfo {
	return v.infoTAI()
}
func BridgePathSwitchRequestIETableMethodInfoTunnelInformationForBBF(v PathSwitchRequestIETable) s00.FieldInfo {
	return v.infoTunnelInformationForBBF()
}
func BridgePathSwitchRequestIETableMethodInfoUESecurityCapabilities(v PathSwitchRequestIETable) s00.FieldInfo {
	return v.infoUESecurityCapabilities()
}
func BridgePathSwitchRequestIEValueERABIEContainerListAPERValueFieldContext(v *PathSwitchRequestIEValueERABIEContainerListAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgePathSwitchRequestIEValueERABIEContainerListAPERValueFieldReceived(v *PathSwitchRequestIEValueERABIEContainerListAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgePathSwitchRequestIEValueERABIEContainerListAPERValueFieldReplay(v *PathSwitchRequestIEValueERABIEContainerListAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgePathSwitchRequestIEValueERABIEContainerListAPERValueFieldWithoutReplay(v *PathSwitchRequestIEValueERABIEContainerListAPERValue) *bool {
	return &v.withoutReplay
}
func BridgePathSwitchRequestIEValueERABIEContainerListValueCodecFieldCapture(v *PathSwitchRequestIEValueERABIEContainerListValueCodec) *func(PathSwitchRequestIEValueERABIEContainerList, aper.DecodeState) (PathSwitchRequestIEValueERABIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgePathSwitchRequestIEValueERABIEContainerListValueCodecFieldCompare(v *PathSwitchRequestIEValueERABIEContainerListValueCodec) *func(PathSwitchRequestIEValueERABIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgePathSwitchRequestIEValueERABIEContainerListValueCodecFieldContext(v *PathSwitchRequestIEValueERABIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgePathSwitchRequestIEValueERABIEContainerListValueCodecFieldDecode(v *PathSwitchRequestIEValueERABIEContainerListValueCodec) *func([]byte, aper.DecodeState) (PathSwitchRequestIEValueERABIEContainerList, error) {
	return &v.decode
}
func BridgePathSwitchRequestIEValueERABIEContainerListValueCodecFieldEncode(v *PathSwitchRequestIEValueERABIEContainerListValueCodec) *func(PathSwitchRequestIEValueERABIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgePathSwitchRequestIEValueERABIEContainerListValueCodecFieldPath(v *PathSwitchRequestIEValueERABIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgePathSwitchRequestIEValueERABIEContainerListValueCodecMethodEncodeBudgetValue(v PathSwitchRequestIEValueERABIEContainerListValueCodec, a0 PathSwitchRequestIEValueERABIEContainerList, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgePathSwitchRequestIEValueERABIEContainerListValueCodecMethodEncodeChanged(v PathSwitchRequestIEValueERABIEContainerListValueCodec, a0 PathSwitchRequestIEValueERABIEContainerList, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgePathSwitchRequestIEValueFieldId(v *PathSwitchRequestIEValue) *s00.ProtocolIEID {
	return &v.id
}
func BridgePathSwitchRequestIEValueFieldIsOpaque(v *PathSwitchRequestIEValue) *bool {
	return &v.isOpaque
}
func BridgePathSwitchRequestIEValueFieldOpaque(v *PathSwitchRequestIEValue) *aper.OpaqueOpenType {
	return &v.opaque
}
func BridgePathSwitchRequestIEValueFieldReceived(v *PathSwitchRequestIEValue) *aper.WireSpan {
	return &v.received
}
func BridgePathSwitchRequestIEValueFieldReplay(v *PathSwitchRequestIEValue) *aper.Snapshot {
	return &v.replay
}
func BridgePathSwitchRequestIEValueFieldRowCSGId(v *PathSwitchRequestIEValue) **s00.CSGId {
	return &v.rowCSGId
}
func BridgePathSwitchRequestIEValueFieldRowCSGMembershipStatus(v *PathSwitchRequestIEValue) **s00.CSGMembershipStatus {
	return &v.rowCSGMembershipStatus
}
func BridgePathSwitchRequestIEValueFieldRowCellAccessMode(v *PathSwitchRequestIEValue) **s00.CellAccessMode {
	return &v.rowCellAccessMode
}
func BridgePathSwitchRequestIEValueFieldRowENBUES1APID(v *PathSwitchRequestIEValue) **s00.ENBUES1APID {
	return &v.rowENBUES1APID
}
func BridgePathSwitchRequestIEValueFieldRowERABToBeSwitchedDLList(v *PathSwitchRequestIEValue) **s30.ERABToBeSwitchedDLList {
	return &v.rowERABToBeSwitchedDLList
}
func BridgePathSwitchRequestIEValueFieldRowEUTRANCGI(v *PathSwitchRequestIEValue) **s17.EUTRANCGI {
	return &v.rowEUTRANCGI
}
func BridgePathSwitchRequestIEValueFieldRowLHNID(v *PathSwitchRequestIEValue) **s00.LHNID {
	return &v.rowLHNID
}
func BridgePathSwitchRequestIEValueFieldRowLTENTNTAIInformation(v *PathSwitchRequestIEValue) **s18.LTENTNTAIInformation {
	return &v.rowLTENTNTAIInformation
}
func BridgePathSwitchRequestIEValueFieldRowNRUESecurityCapabilities(v *PathSwitchRequestIEValue) **s19.NRUESecurityCapabilities {
	return &v.rowNRUESecurityCapabilities
}
func BridgePathSwitchRequestIEValueFieldRowPSCellInformation(v *PathSwitchRequestIEValue) **s20.PSCellInformation {
	return &v.rowPSCellInformation
}
func BridgePathSwitchRequestIEValueFieldRowRRCResumeCause(v *PathSwitchRequestIEValue) **s00.RRCEstablishmentCause {
	return &v.rowRRCResumeCause
}
func BridgePathSwitchRequestIEValueFieldRowSourceMMEGUMMEI(v *PathSwitchRequestIEValue) **s18.GUMMEI {
	return &v.rowSourceMMEGUMMEI
}
func BridgePathSwitchRequestIEValueFieldRowSourceMMEUES1APID(v *PathSwitchRequestIEValue) **s00.MMEUES1APID {
	return &v.rowSourceMMEUES1APID
}
func BridgePathSwitchRequestIEValueFieldRowTAI(v *PathSwitchRequestIEValue) **s31.TAI {
	return &v.rowTAI
}
func BridgePathSwitchRequestIEValueFieldRowTunnelInformationForBBF(v *PathSwitchRequestIEValue) **s35.TunnelInformation {
	return &v.rowTunnelInformationForBBF
}
func BridgePathSwitchRequestIEValueFieldRowUESecurityCapabilities(v *PathSwitchRequestIEValue) **s37.UESecurityCapabilities {
	return &v.rowUESecurityCapabilities
}
func BridgePathSwitchRequestIEValueMethodCaptureSemantics(v PathSwitchRequestIEValue, a0 aper.SemanticCapture) PathSwitchRequestIEValue {
	return v.captureSemantics(a0)
}
func BridgePathSwitchRequestIEValueMethodCompareSemantics(v PathSwitchRequestIEValue, a0 aper.SemanticComparison) aper.SemanticComparison {
	return v.compareSemantics(a0)
}
func BridgePathSwitchRequestIEValueMethodDecode(v PathSwitchRequestIEValue, a0 s00.ProtocolIEID, a1 aper.OpaqueOpenType) (PathSwitchRequestIEValue, error) {
	return v.decode(a0, a1)
}
func BridgePathSwitchRequestIEValueMethodEncode(v PathSwitchRequestIEValue) ([]byte, error) {
	return v.encode()
}
func BridgePathSwitchRequestIEValueMethodEncodeFresh(v PathSwitchRequestIEValue, a0 bool, a1 *aper.DecodeBudget) ([]byte, error) {
	return v.encodeFresh(a0, a1)
}
func BridgePathSwitchRequestIEValueMethodMatchesID(v PathSwitchRequestIEValue, a0 s00.ProtocolIEID, a1 ...*aper.DecodeBudget) bool {
	return v.matchesID(a0, a1...)
}
func BridgePathSwitchRequestIEValueMethodReason(v PathSwitchRequestIEValue, a0 s00.ProtocolIEID) aper.OpaqueReason {
	return v.reason(a0)
}
func BridgePathSwitchRequestIEValueMethodRule(v PathSwitchRequestIEValue) aper.SourceRule {
	return v.rule()
}
func BridgePathSwitchRequestIEValueProtocolErrorIEContainerListAPERValueFieldContext(v *PathSwitchRequestIEValueProtocolErrorIEContainerListAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgePathSwitchRequestIEValueProtocolErrorIEContainerListAPERValueFieldReceived(v *PathSwitchRequestIEValueProtocolErrorIEContainerListAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgePathSwitchRequestIEValueProtocolErrorIEContainerListAPERValueFieldReplay(v *PathSwitchRequestIEValueProtocolErrorIEContainerListAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgePathSwitchRequestIEValueProtocolErrorIEContainerListAPERValueFieldWithoutReplay(v *PathSwitchRequestIEValueProtocolErrorIEContainerListAPERValue) *bool {
	return &v.withoutReplay
}
func BridgePathSwitchRequestIEValueProtocolErrorIEContainerListValueCodecFieldCapture(v *PathSwitchRequestIEValueProtocolErrorIEContainerListValueCodec) *func(PathSwitchRequestIEValueProtocolErrorIEContainerList, aper.DecodeState) (PathSwitchRequestIEValueProtocolErrorIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgePathSwitchRequestIEValueProtocolErrorIEContainerListValueCodecFieldCompare(v *PathSwitchRequestIEValueProtocolErrorIEContainerListValueCodec) *func(PathSwitchRequestIEValueProtocolErrorIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgePathSwitchRequestIEValueProtocolErrorIEContainerListValueCodecFieldContext(v *PathSwitchRequestIEValueProtocolErrorIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgePathSwitchRequestIEValueProtocolErrorIEContainerListValueCodecFieldDecode(v *PathSwitchRequestIEValueProtocolErrorIEContainerListValueCodec) *func([]byte, aper.DecodeState) (PathSwitchRequestIEValueProtocolErrorIEContainerList, error) {
	return &v.decode
}
func BridgePathSwitchRequestIEValueProtocolErrorIEContainerListValueCodecFieldEncode(v *PathSwitchRequestIEValueProtocolErrorIEContainerListValueCodec) *func(PathSwitchRequestIEValueProtocolErrorIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgePathSwitchRequestIEValueProtocolErrorIEContainerListValueCodecFieldPath(v *PathSwitchRequestIEValueProtocolErrorIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgePathSwitchRequestIEValueProtocolErrorIEContainerListValueCodecMethodEncodeBudgetValue(v PathSwitchRequestIEValueProtocolErrorIEContainerListValueCodec, a0 PathSwitchRequestIEValueProtocolErrorIEContainerList, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgePathSwitchRequestIEValueProtocolErrorIEContainerListValueCodecMethodEncodeChanged(v PathSwitchRequestIEValueProtocolErrorIEContainerListValueCodec, a0 PathSwitchRequestIEValueProtocolErrorIEContainerList, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgePathSwitchRequestIEValueProtocolIEContainerListAPERValueFieldContext(v *PathSwitchRequestIEValueProtocolIEContainerListAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgePathSwitchRequestIEValueProtocolIEContainerListAPERValueFieldReceived(v *PathSwitchRequestIEValueProtocolIEContainerListAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgePathSwitchRequestIEValueProtocolIEContainerListAPERValueFieldReplay(v *PathSwitchRequestIEValueProtocolIEContainerListAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgePathSwitchRequestIEValueProtocolIEContainerListAPERValueFieldWithoutReplay(v *PathSwitchRequestIEValueProtocolIEContainerListAPERValue) *bool {
	return &v.withoutReplay
}
func BridgePathSwitchRequestIEValueProtocolIEContainerListValueCodecFieldCapture(v *PathSwitchRequestIEValueProtocolIEContainerListValueCodec) *func(PathSwitchRequestIEValueProtocolIEContainerList, aper.DecodeState) (PathSwitchRequestIEValueProtocolIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgePathSwitchRequestIEValueProtocolIEContainerListValueCodecFieldCompare(v *PathSwitchRequestIEValueProtocolIEContainerListValueCodec) *func(PathSwitchRequestIEValueProtocolIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgePathSwitchRequestIEValueProtocolIEContainerListValueCodecFieldContext(v *PathSwitchRequestIEValueProtocolIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgePathSwitchRequestIEValueProtocolIEContainerListValueCodecFieldDecode(v *PathSwitchRequestIEValueProtocolIEContainerListValueCodec) *func([]byte, aper.DecodeState) (PathSwitchRequestIEValueProtocolIEContainerList, error) {
	return &v.decode
}
func BridgePathSwitchRequestIEValueProtocolIEContainerListValueCodecFieldEncode(v *PathSwitchRequestIEValueProtocolIEContainerListValueCodec) *func(PathSwitchRequestIEValueProtocolIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgePathSwitchRequestIEValueProtocolIEContainerListValueCodecFieldPath(v *PathSwitchRequestIEValueProtocolIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgePathSwitchRequestIEValueProtocolIEContainerListValueCodecMethodEncodeBudgetValue(v PathSwitchRequestIEValueProtocolIEContainerListValueCodec, a0 PathSwitchRequestIEValueProtocolIEContainerList, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgePathSwitchRequestIEValueProtocolIEContainerListValueCodecMethodEncodeChanged(v PathSwitchRequestIEValueProtocolIEContainerListValueCodec, a0 PathSwitchRequestIEValueProtocolIEContainerList, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgePathSwitchRequestLHNIDIEBindingFieldCodec(v *PathSwitchRequestLHNIDIEBinding) *s01.LHNIDValueCodec {
	return &v.codec
}
func BridgePathSwitchRequestLHNIDIEBindingFieldGet(v *PathSwitchRequestLHNIDIEBinding) *func(*PathSwitchRequestIEValue) (*s00.LHNID, bool) {
	return &v.get
}
func BridgePathSwitchRequestLHNIDIEBindingFieldInfo(v *PathSwitchRequestLHNIDIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgePathSwitchRequestLHNIDIEBindingFieldInject(v *PathSwitchRequestLHNIDIEBinding) *func(s00.LHNID) PathSwitchRequestIEValue {
	return &v.inject
}
func BridgePathSwitchRequestLTENTNTAIInformationIEBindingFieldCodec(v *PathSwitchRequestLTENTNTAIInformationIEBinding) *s18.LTENTNTAIInformationValueCodec {
	return &v.codec
}
func BridgePathSwitchRequestLTENTNTAIInformationIEBindingFieldGet(v *PathSwitchRequestLTENTNTAIInformationIEBinding) *func(*PathSwitchRequestIEValue) (*s18.LTENTNTAIInformation, bool) {
	return &v.get
}
func BridgePathSwitchRequestLTENTNTAIInformationIEBindingFieldInfo(v *PathSwitchRequestLTENTNTAIInformationIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgePathSwitchRequestLTENTNTAIInformationIEBindingFieldInject(v *PathSwitchRequestLTENTNTAIInformationIEBinding) *func(s18.LTENTNTAIInformation) PathSwitchRequestIEValue {
	return &v.inject
}
func BridgePathSwitchRequestMMEUES1APIDIEBindingFieldCodec(v *PathSwitchRequestMMEUES1APIDIEBinding) *s01.MMEUES1APIDValueCodec {
	return &v.codec
}
func BridgePathSwitchRequestMMEUES1APIDIEBindingFieldGet(v *PathSwitchRequestMMEUES1APIDIEBinding) *func(*PathSwitchRequestIEValue) (*s00.MMEUES1APID, bool) {
	return &v.get
}
func BridgePathSwitchRequestMMEUES1APIDIEBindingFieldInfo(v *PathSwitchRequestMMEUES1APIDIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgePathSwitchRequestMMEUES1APIDIEBindingFieldInject(v *PathSwitchRequestMMEUES1APIDIEBinding) *func(s00.MMEUES1APID) PathSwitchRequestIEValue {
	return &v.inject
}
func BridgePathSwitchRequestMethodMarshalAPERBudget(v *PathSwitchRequest, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgePathSwitchRequestMethodMarshalAPERBudgetValue(v *PathSwitchRequest, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudgetValue(a0, a1)
}
func BridgePathSwitchRequestMethodMarshalAPERChanged(v *PathSwitchRequest, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgePathSwitchRequestMethodMarshalAPERChangedValue(v *PathSwitchRequest, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgePathSwitchRequestMethodMarshalAPERLegacy(v *PathSwitchRequest) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgePathSwitchRequestMethodMarshalAPERNewValue(v *PathSwitchRequest, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERNewValue(a0, a1)
}
func BridgePathSwitchRequestMethodMarshalAPERPlanned(v *PathSwitchRequest, a0 *aper.DecodeBudget, a1 bool, a2 *aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1, a2)
}
func BridgePathSwitchRequestMethodMarshalAPERTo(v *PathSwitchRequest, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgePathSwitchRequestMethodUnmarshalAPERFrom(v *PathSwitchRequest, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgePathSwitchRequestMethodUnmarshalAPERLegacy(v *PathSwitchRequest, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgePathSwitchRequestMethodUnmarshalAPERWithOptions(v *PathSwitchRequest, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgePathSwitchRequestNRUESecurityCapabilitiesIEBindingFieldCodec(v *PathSwitchRequestNRUESecurityCapabilitiesIEBinding) *s19.NRUESecurityCapabilitiesValueCodec {
	return &v.codec
}
func BridgePathSwitchRequestNRUESecurityCapabilitiesIEBindingFieldGet(v *PathSwitchRequestNRUESecurityCapabilitiesIEBinding) *func(*PathSwitchRequestIEValue) (*s19.NRUESecurityCapabilities, bool) {
	return &v.get
}
func BridgePathSwitchRequestNRUESecurityCapabilitiesIEBindingFieldInfo(v *PathSwitchRequestNRUESecurityCapabilitiesIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgePathSwitchRequestNRUESecurityCapabilitiesIEBindingFieldInject(v *PathSwitchRequestNRUESecurityCapabilitiesIEBinding) *func(s19.NRUESecurityCapabilities) PathSwitchRequestIEValue {
	return &v.inject
}
func BridgePathSwitchRequestPSCellInformationIEBindingFieldCodec(v *PathSwitchRequestPSCellInformationIEBinding) *s20.PSCellInformationValueCodec {
	return &v.codec
}
func BridgePathSwitchRequestPSCellInformationIEBindingFieldGet(v *PathSwitchRequestPSCellInformationIEBinding) *func(*PathSwitchRequestIEValue) (*s20.PSCellInformation, bool) {
	return &v.get
}
func BridgePathSwitchRequestPSCellInformationIEBindingFieldInfo(v *PathSwitchRequestPSCellInformationIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgePathSwitchRequestPSCellInformationIEBindingFieldInject(v *PathSwitchRequestPSCellInformationIEBinding) *func(s20.PSCellInformation) PathSwitchRequestIEValue {
	return &v.inject
}
func BridgePathSwitchRequestRRCEstablishmentCauseIEBindingFieldCodec(v *PathSwitchRequestRRCEstablishmentCauseIEBinding) *s01.RRCEstablishmentCauseValueCodec {
	return &v.codec
}
func BridgePathSwitchRequestRRCEstablishmentCauseIEBindingFieldGet(v *PathSwitchRequestRRCEstablishmentCauseIEBinding) *func(*PathSwitchRequestIEValue) (*s00.RRCEstablishmentCause, bool) {
	return &v.get
}
func BridgePathSwitchRequestRRCEstablishmentCauseIEBindingFieldInfo(v *PathSwitchRequestRRCEstablishmentCauseIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgePathSwitchRequestRRCEstablishmentCauseIEBindingFieldInject(v *PathSwitchRequestRRCEstablishmentCauseIEBinding) *func(s00.RRCEstablishmentCause) PathSwitchRequestIEValue {
	return &v.inject
}
func BridgePathSwitchRequestTAIIEBindingFieldCodec(v *PathSwitchRequestTAIIEBinding) *s32.TAIValueCodec {
	return &v.codec
}
func BridgePathSwitchRequestTAIIEBindingFieldGet(v *PathSwitchRequestTAIIEBinding) *func(*PathSwitchRequestIEValue) (*s31.TAI, bool) {
	return &v.get
}
func BridgePathSwitchRequestTAIIEBindingFieldInfo(v *PathSwitchRequestTAIIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgePathSwitchRequestTAIIEBindingFieldInject(v *PathSwitchRequestTAIIEBinding) *func(s31.TAI) PathSwitchRequestIEValue {
	return &v.inject
}
func BridgePathSwitchRequestTunnelInformationIEBindingFieldCodec(v *PathSwitchRequestTunnelInformationIEBinding) *s35.TunnelInformationValueCodec {
	return &v.codec
}
func BridgePathSwitchRequestTunnelInformationIEBindingFieldGet(v *PathSwitchRequestTunnelInformationIEBinding) *func(*PathSwitchRequestIEValue) (*s35.TunnelInformation, bool) {
	return &v.get
}
func BridgePathSwitchRequestTunnelInformationIEBindingFieldInfo(v *PathSwitchRequestTunnelInformationIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgePathSwitchRequestTunnelInformationIEBindingFieldInject(v *PathSwitchRequestTunnelInformationIEBinding) *func(s35.TunnelInformation) PathSwitchRequestIEValue {
	return &v.inject
}
func BridgePathSwitchRequestUESecurityCapabilitiesIEBindingFieldCodec(v *PathSwitchRequestUESecurityCapabilitiesIEBinding) *s37.UESecurityCapabilitiesValueCodec {
	return &v.codec
}
func BridgePathSwitchRequestUESecurityCapabilitiesIEBindingFieldGet(v *PathSwitchRequestUESecurityCapabilitiesIEBinding) *func(*PathSwitchRequestIEValue) (*s37.UESecurityCapabilities, bool) {
	return &v.get
}
func BridgePathSwitchRequestUESecurityCapabilitiesIEBindingFieldInfo(v *PathSwitchRequestUESecurityCapabilitiesIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgePathSwitchRequestUESecurityCapabilitiesIEBindingFieldInject(v *PathSwitchRequestUESecurityCapabilitiesIEBinding) *func(s37.UESecurityCapabilities) PathSwitchRequestIEValue {
	return &v.inject
}
func BridgePathSwitchRequestValueCodecFieldCapture(v *PathSwitchRequestValueCodec) *func(PathSwitchRequest, aper.DecodeState) (PathSwitchRequest, aper.Snapshot) {
	return &v.capture
}
func BridgePathSwitchRequestValueCodecFieldCompare(v *PathSwitchRequestValueCodec) *func(PathSwitchRequest, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgePathSwitchRequestValueCodecFieldContext(v *PathSwitchRequestValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgePathSwitchRequestValueCodecFieldDecode(v *PathSwitchRequestValueCodec) *func([]byte, aper.DecodeState) (PathSwitchRequest, error) {
	return &v.decode
}
func BridgePathSwitchRequestValueCodecFieldEncode(v *PathSwitchRequestValueCodec) *func(PathSwitchRequest, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgePathSwitchRequestValueCodecFieldPath(v *PathSwitchRequestValueCodec) *aper.Path {
	return &v.path
}
func BridgePathSwitchRequestValueCodecMethodEncodeBudgetValue(v PathSwitchRequestValueCodec, a0 PathSwitchRequest, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgePathSwitchRequestValueCodecMethodEncodeChanged(v PathSwitchRequestValueCodec, a0 PathSwitchRequest, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
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
// The field's Id distinguishes alternatives with the same Go type.
func (v *PathSwitchRequestIEValue) Selected() (any, bool) {
	if v == nil || v.isOpaque {
		return nil, false
	}
	switch v.id {
	case 8:
		if value, ok := v.AsENBUES1APID(); ok {
			return value, true
		}
	case 22:
		if value, ok := v.AsERABToBeSwitchedDLList(); ok {
			return value, true
		}
	case 88:
		if value, ok := v.AsSourceMMEUES1APID(); ok {
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
	case 107:
		if value, ok := v.AsUESecurityCapabilities(); ok {
			return value, true
		}
	case 127:
		if value, ok := v.AsCSGId(); ok {
			return value, true
		}
	case 145:
		if value, ok := v.AsCellAccessMode(); ok {
			return value, true
		}
	case 157:
		if value, ok := v.AsSourceMMEGUMMEI(); ok {
			return value, true
		}
	case 146:
		if value, ok := v.AsCSGMembershipStatus(); ok {
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
	case 245:
		if value, ok := v.AsRRCResumeCause(); ok {
			return value, true
		}
	case 269:
		if value, ok := v.AsNRUESecurityCapabilities(); ok {
			return value, true
		}
	case 288:
		if value, ok := v.AsPSCellInformation(); ok {
			return value, true
		}
	case 339:
		if value, ok := v.AsLTENTNTAIInformation(); ok {
			return value, true
		}
	}
	return nil, false
}
