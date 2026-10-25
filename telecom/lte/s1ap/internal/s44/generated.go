// Code generated from the pinned S1AP source closure. DO NOT EDIT.

// Package s44 implements the github.com/gomaja/go-asn1/telecom/lte/s1ap root package.
package s44

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
	s21 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s21"
	s22 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s22"
	s24 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s24"
	s27 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s27"
	s31 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s31"
	s32 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s32"
	s33 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s33"
	s38 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s38"
	s39 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s39"
	s42 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s42"
	s43 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s43"
	runtime "github.com/gomaja/go-asn1/telecom/lte/s1ap/runtime"
	aper "github.com/gomaja/go-asn1/telecom/lte/s1ap/runtime/aper"
)

// S1SetupRequestIEContainer is ProtocolIE-Container {{S1SetupRequestIEs}} of TS 36.413: a list of S1SetupRequestIEField values.
type S1SetupRequestIEContainer []S1SetupRequestIEField

// S1SetupRequestIEField is ProtocolIE-Field {{S1SetupRequestIEs}} of TS 36.413: an information element field.
type S1SetupRequestIEField struct {
	withoutReplay bool
	replay        aper.Snapshot
	stream        aper.WireSpan
	Id            s00.ProtocolIEID
	Criticality   s00.Criticality
	Value         S1SetupRequestIEValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v S1SetupRequestIEField) WithoutReplay() S1SetupRequestIEField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *S1SetupRequestIEField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *S1SetupRequestIEField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
func (v *S1SetupRequestIEField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolIEField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = S1SetupRequestIEField{}
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
	var zero S1SetupRequestIEValue

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

// S1SetupResponseIEContainer is ProtocolIE-Container {{S1SetupResponseIEs}} of TS 36.413: a list of S1SetupResponseIEField values.
type S1SetupResponseIEContainer []S1SetupResponseIEField

// S1SetupResponseIEField is ProtocolIE-Field {{S1SetupResponseIEs}} of TS 36.413: an information element field.
type S1SetupResponseIEField struct {
	withoutReplay bool
	replay        aper.Snapshot
	stream        aper.WireSpan
	Id            s00.ProtocolIEID
	Criticality   s00.Criticality
	Value         S1SetupResponseIEValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v S1SetupResponseIEField) WithoutReplay() S1SetupResponseIEField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *S1SetupResponseIEField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *S1SetupResponseIEField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
func (v *S1SetupResponseIEField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolIEField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = S1SetupResponseIEField{}
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
	var zero S1SetupResponseIEValue

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

// ENBConfigurationUpdateIEContainer is ProtocolIE-Container {{ENBConfigurationUpdateIEs}} of TS 36.413: a list of ENBConfigurationUpdateIEField values.
type ENBConfigurationUpdateIEContainer []ENBConfigurationUpdateIEField

// ENBConfigurationUpdateIEField is ProtocolIE-Field {{ENBConfigurationUpdateIEs}} of TS 36.413: an information element field.
type ENBConfigurationUpdateIEField struct {
	withoutReplay bool
	replay        aper.Snapshot
	stream        aper.WireSpan
	Id            s00.ProtocolIEID
	Criticality   s00.Criticality
	Value         ENBConfigurationUpdateIEValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ENBConfigurationUpdateIEField) WithoutReplay() ENBConfigurationUpdateIEField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *ENBConfigurationUpdateIEField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *ENBConfigurationUpdateIEField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
func (v *ENBConfigurationUpdateIEField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolIEField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = ENBConfigurationUpdateIEField{}
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
	var zero ENBConfigurationUpdateIEValue

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
func BridgeENBConfigurationUpdateIEValueCaptureS1APProtocolIEContainer(v *ENBConfigurationUpdateIEContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeENBConfigurationUpdateIEValueCaptureS1APProtocolIEField(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeENBConfigurationUpdateIEValueCompareS1APProtocolIEContainer(v *ENBConfigurationUpdateIEContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeENBConfigurationUpdateIEValueCompareS1APProtocolIEField(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeMMEConfigurationUpdateIEValueCaptureS1APProtocolIEContainer(v *s43.MMEConfigurationUpdateIEContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeMMEConfigurationUpdateIEValueCaptureS1APProtocolIEField(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeMMEConfigurationUpdateIEValueCompareS1APProtocolIEContainer(v *s43.MMEConfigurationUpdateIEContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeMMEConfigurationUpdateIEValueCompareS1APProtocolIEField(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
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
func BridgeS1SetupRequestIEValueCaptureS1APProtocolIEContainer(v *S1SetupRequestIEContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeS1SetupRequestIEValueCaptureS1APProtocolIEField(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeS1SetupRequestIEValueCompareS1APProtocolIEContainer(v *S1SetupRequestIEContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeS1SetupRequestIEValueCompareS1APProtocolIEField(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeS1SetupResponseIEValueCaptureS1APProtocolIEContainer(v *S1SetupResponseIEContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeS1SetupResponseIEValueCaptureS1APProtocolIEField(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeS1SetupResponseIEValueCompareS1APProtocolIEContainer(v *S1SetupResponseIEContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeS1SetupResponseIEValueCompareS1APProtocolIEField(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}

// ENBConfigurationUpdateENBnameIEBinding binds ENBname to the ENBConfigurationUpdateIEs object set of TS 36.413.
type ENBConfigurationUpdateENBnameIEBinding struct {
	info   s00.FieldInfo
	codec  s00.ENBnameValueCodec
	inject func(s00.ENBname,

	) ENBConfigurationUpdateIEValue

	get func(*ENBConfigurationUpdateIEValue,

	) (*s00.ENBname,

		bool)
}

// Info returns the source descriptor for this binding.
func (b ENBConfigurationUpdateENBnameIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b ENBConfigurationUpdateENBnameIEBinding) Codec() s00.ENBnameValueCodec { return b.codec }

// New validates a source value and constructs its bound field.
func (b ENBConfigurationUpdateENBnameIEBinding) New(value s00.ENBname,

) (ENBConfigurationUpdateIEField, error) {
	if b.inject == nil {
		return ENBConfigurationUpdateIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ENBConfigurationUpdateIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s00.BridgeENBnameValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return ENBConfigurationUpdateIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return ENBConfigurationUpdateIEField{}, aper.OperationError(err, "Value.New")
	}
	return ENBConfigurationUpdateIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b ENBConfigurationUpdateENBnameIEBinding) Get(field *ENBConfigurationUpdateIEField) (*s00.ENBname,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// ENBConfigurationUpdateSupportedTAsIEBinding binds SupportedTAs to the ENBConfigurationUpdateIEs object set of TS 36.413.
type ENBConfigurationUpdateSupportedTAsIEBinding struct {
	info   s00.FieldInfo
	codec  s31.SupportedTAsValueCodec
	inject func(s31.SupportedTAs,

	) ENBConfigurationUpdateIEValue

	get func(*ENBConfigurationUpdateIEValue,

	) (*s31.SupportedTAs,

		bool)
}

// Info returns the source descriptor for this binding.
func (b ENBConfigurationUpdateSupportedTAsIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b ENBConfigurationUpdateSupportedTAsIEBinding) Codec() s31.SupportedTAsValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b ENBConfigurationUpdateSupportedTAsIEBinding) New(value s31.SupportedTAs,

) (ENBConfigurationUpdateIEField, error) {
	if b.inject == nil {
		return ENBConfigurationUpdateIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ENBConfigurationUpdateIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s31.BridgeSupportedTAsValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return ENBConfigurationUpdateIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return ENBConfigurationUpdateIEField{}, aper.OperationError(err, "Value.New")
	}
	return ENBConfigurationUpdateIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b ENBConfigurationUpdateSupportedTAsIEBinding) Get(field *ENBConfigurationUpdateIEField) (*s31.SupportedTAs,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// ENBConfigurationUpdateCSGIdListIEBinding binds CSGIdList to the ENBConfigurationUpdateIEs object set of TS 36.413.
type ENBConfigurationUpdateCSGIdListIEBinding struct {
	info   s00.FieldInfo
	codec  s14.CSGIdListValueCodec
	inject func(s14.CSGIdList,

	) ENBConfigurationUpdateIEValue

	get func(*ENBConfigurationUpdateIEValue,

	) (*s14.CSGIdList,

		bool)
}

// Info returns the source descriptor for this binding.
func (b ENBConfigurationUpdateCSGIdListIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b ENBConfigurationUpdateCSGIdListIEBinding) Codec() s14.CSGIdListValueCodec { return b.codec }

// New validates a source value and constructs its bound field.
func (b ENBConfigurationUpdateCSGIdListIEBinding) New(value s14.CSGIdList,

) (ENBConfigurationUpdateIEField, error) {
	if b.inject == nil {
		return ENBConfigurationUpdateIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ENBConfigurationUpdateIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s14.BridgeCSGIdListValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return ENBConfigurationUpdateIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return ENBConfigurationUpdateIEField{}, aper.OperationError(err, "Value.New")
	}
	return ENBConfigurationUpdateIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b ENBConfigurationUpdateCSGIdListIEBinding) Get(field *ENBConfigurationUpdateIEField) (*s14.CSGIdList,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// ENBConfigurationUpdatePagingDRXIEBinding binds PagingDRX to the ENBConfigurationUpdateIEs object set of TS 36.413.
type ENBConfigurationUpdatePagingDRXIEBinding struct {
	info   s00.FieldInfo
	codec  s01.PagingDRXValueCodec
	inject func(s00.PagingDRX,

	) ENBConfigurationUpdateIEValue

	get func(*ENBConfigurationUpdateIEValue,

	) (*s00.PagingDRX,

		bool)
}

// Info returns the source descriptor for this binding.
func (b ENBConfigurationUpdatePagingDRXIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b ENBConfigurationUpdatePagingDRXIEBinding) Codec() s01.PagingDRXValueCodec { return b.codec }

// New validates a source value and constructs its bound field.
func (b ENBConfigurationUpdatePagingDRXIEBinding) New(value s00.PagingDRX,

) (ENBConfigurationUpdateIEField, error) {
	if b.inject == nil {
		return ENBConfigurationUpdateIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ENBConfigurationUpdateIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s01.BridgePagingDRXValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return ENBConfigurationUpdateIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return ENBConfigurationUpdateIEField{}, aper.OperationError(err, "Value.New")
	}
	return ENBConfigurationUpdateIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b ENBConfigurationUpdatePagingDRXIEBinding) Get(field *ENBConfigurationUpdateIEField) (*s00.PagingDRX,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// ENBConfigurationUpdateNBIoTDefaultPagingDRXIEBinding binds NBIoTDefaultPagingDRX to the ENBConfigurationUpdateIEs object set of TS 36.413.
type ENBConfigurationUpdateNBIoTDefaultPagingDRXIEBinding struct {
	info   s00.FieldInfo
	codec  s01.NBIoTDefaultPagingDRXValueCodec
	inject func(s00.NBIoTDefaultPagingDRX,

	) ENBConfigurationUpdateIEValue

	get func(*ENBConfigurationUpdateIEValue,

	) (*s00.NBIoTDefaultPagingDRX,

		bool)
}

// Info returns the source descriptor for this binding.
func (b ENBConfigurationUpdateNBIoTDefaultPagingDRXIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b ENBConfigurationUpdateNBIoTDefaultPagingDRXIEBinding) Codec() s01.NBIoTDefaultPagingDRXValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b ENBConfigurationUpdateNBIoTDefaultPagingDRXIEBinding) New(value s00.NBIoTDefaultPagingDRX,

) (ENBConfigurationUpdateIEField, error) {
	if b.inject == nil {
		return ENBConfigurationUpdateIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ENBConfigurationUpdateIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s01.BridgeNBIoTDefaultPagingDRXValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return ENBConfigurationUpdateIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return ENBConfigurationUpdateIEField{}, aper.OperationError(err, "Value.New")
	}
	return ENBConfigurationUpdateIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b ENBConfigurationUpdateNBIoTDefaultPagingDRXIEBinding) Get(field *ENBConfigurationUpdateIEField) (*s00.NBIoTDefaultPagingDRX,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// ENBConfigurationUpdateConnectedengNBListIEBinding binds ConnectedengNBList to the ENBConfigurationUpdateIEs object set of TS 36.413.
type ENBConfigurationUpdateConnectedengNBListIEBinding struct {
	info   s00.FieldInfo
	codec  s31.ConnectedengNBListValueCodec
	inject func(s31.ConnectedengNBList,

	) ENBConfigurationUpdateIEValue

	get func(*ENBConfigurationUpdateIEValue,

	) (*s31.ConnectedengNBList,

		bool)
}

// Info returns the source descriptor for this binding.
func (b ENBConfigurationUpdateConnectedengNBListIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b ENBConfigurationUpdateConnectedengNBListIEBinding) Codec() s31.ConnectedengNBListValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b ENBConfigurationUpdateConnectedengNBListIEBinding) New(value s31.ConnectedengNBList,

) (ENBConfigurationUpdateIEField, error) {
	if b.inject == nil {
		return ENBConfigurationUpdateIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ENBConfigurationUpdateIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s31.BridgeConnectedengNBListValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return ENBConfigurationUpdateIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return ENBConfigurationUpdateIEField{}, aper.OperationError(err, "Value.New")
	}
	return ENBConfigurationUpdateIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b ENBConfigurationUpdateConnectedengNBListIEBinding) Get(field *ENBConfigurationUpdateIEField) (*s31.ConnectedengNBList,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// MMEConfigurationUpdateMMEnameIEBinding binds MMEname to the MMEConfigurationUpdateIEs object set of TS 36.413.
type MMEConfigurationUpdateMMEnameIEBinding struct {
	info   s00.FieldInfo
	codec  s01.MMEnameValueCodec
	inject func(s00.MMEname,

	) s43.MMEConfigurationUpdateIEValue

	get func(*s43.MMEConfigurationUpdateIEValue,

	) (*s00.MMEname,

		bool)
}

// Info returns the source descriptor for this binding.
func (b MMEConfigurationUpdateMMEnameIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b MMEConfigurationUpdateMMEnameIEBinding) Codec() s01.MMEnameValueCodec { return b.codec }

// New validates a source value and constructs its bound field.
func (b MMEConfigurationUpdateMMEnameIEBinding) New(value s00.MMEname,

) (s43.MMEConfigurationUpdateIEField, error) {
	if b.inject == nil {
		return s43.MMEConfigurationUpdateIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return s43.MMEConfigurationUpdateIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s01.BridgeMMEnameValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return s43.MMEConfigurationUpdateIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return s43.MMEConfigurationUpdateIEField{}, aper.OperationError(err, "Value.New")
	}
	return s43.MMEConfigurationUpdateIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b MMEConfigurationUpdateMMEnameIEBinding) Get(field *s43.MMEConfigurationUpdateIEField) (*s00.MMEname,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// MMEConfigurationUpdateServedGUMMEIsIEBinding binds ServedGUMMEIs to the MMEConfigurationUpdateIEs object set of TS 36.413.
type MMEConfigurationUpdateServedGUMMEIsIEBinding struct {
	info   s00.FieldInfo
	codec  s31.ServedGUMMEIsValueCodec
	inject func(s31.ServedGUMMEIs,

	) s43.MMEConfigurationUpdateIEValue

	get func(*s43.MMEConfigurationUpdateIEValue,

	) (*s31.ServedGUMMEIs,

		bool)
}

// Info returns the source descriptor for this binding.
func (b MMEConfigurationUpdateServedGUMMEIsIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b MMEConfigurationUpdateServedGUMMEIsIEBinding) Codec() s31.ServedGUMMEIsValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b MMEConfigurationUpdateServedGUMMEIsIEBinding) New(value s31.ServedGUMMEIs,

) (s43.MMEConfigurationUpdateIEField, error) {
	if b.inject == nil {
		return s43.MMEConfigurationUpdateIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return s43.MMEConfigurationUpdateIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s31.BridgeServedGUMMEIsValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return s43.MMEConfigurationUpdateIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return s43.MMEConfigurationUpdateIEField{}, aper.OperationError(err, "Value.New")
	}
	return s43.MMEConfigurationUpdateIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b MMEConfigurationUpdateServedGUMMEIsIEBinding) Get(field *s43.MMEConfigurationUpdateIEField) (*s31.ServedGUMMEIs,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// MMEConfigurationUpdateRelativeMMECapacityIEBinding binds RelativeMMECapacity to the MMEConfigurationUpdateIEs object set of TS 36.413.
type MMEConfigurationUpdateRelativeMMECapacityIEBinding struct {
	info   s00.FieldInfo
	codec  s01.RelativeMMECapacityValueCodec
	inject func(s00.RelativeMMECapacity,

	) s43.MMEConfigurationUpdateIEValue

	get func(*s43.MMEConfigurationUpdateIEValue,

	) (*s00.RelativeMMECapacity,

		bool)
}

// Info returns the source descriptor for this binding.
func (b MMEConfigurationUpdateRelativeMMECapacityIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b MMEConfigurationUpdateRelativeMMECapacityIEBinding) Codec() s01.RelativeMMECapacityValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b MMEConfigurationUpdateRelativeMMECapacityIEBinding) New(value s00.RelativeMMECapacity,

) (s43.MMEConfigurationUpdateIEField, error) {
	if b.inject == nil {
		return s43.MMEConfigurationUpdateIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return s43.MMEConfigurationUpdateIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s01.BridgeRelativeMMECapacityValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return s43.MMEConfigurationUpdateIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return s43.MMEConfigurationUpdateIEField{}, aper.OperationError(err, "Value.New")
	}
	return s43.MMEConfigurationUpdateIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b MMEConfigurationUpdateRelativeMMECapacityIEBinding) Get(field *s43.MMEConfigurationUpdateIEField) (*s00.RelativeMMECapacity,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// MMEConfigurationUpdateServedDCNsIEBinding binds ServedDCNs to the MMEConfigurationUpdateIEs object set of TS 36.413.
type MMEConfigurationUpdateServedDCNsIEBinding struct {
	info   s00.FieldInfo
	codec  s31.ServedDCNsValueCodec
	inject func(s31.ServedDCNs,

	) s43.MMEConfigurationUpdateIEValue

	get func(*s43.MMEConfigurationUpdateIEValue,

	) (*s31.ServedDCNs,

		bool)
}

// Info returns the source descriptor for this binding.
func (b MMEConfigurationUpdateServedDCNsIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b MMEConfigurationUpdateServedDCNsIEBinding) Codec() s31.ServedDCNsValueCodec { return b.codec }

// New validates a source value and constructs its bound field.
func (b MMEConfigurationUpdateServedDCNsIEBinding) New(value s31.ServedDCNs,

) (s43.MMEConfigurationUpdateIEField, error) {
	if b.inject == nil {
		return s43.MMEConfigurationUpdateIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return s43.MMEConfigurationUpdateIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s31.BridgeServedDCNsValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return s43.MMEConfigurationUpdateIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return s43.MMEConfigurationUpdateIEField{}, aper.OperationError(err, "Value.New")
	}
	return s43.MMEConfigurationUpdateIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b MMEConfigurationUpdateServedDCNsIEBinding) Get(field *s43.MMEConfigurationUpdateIEField) (*s31.ServedDCNs,

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

// S1SetupRequestGlobalENBIDIEBinding binds GlobalENBID to the S1SetupRequestIEs object set of TS 36.413.
type S1SetupRequestGlobalENBIDIEBinding struct {
	info   s00.FieldInfo
	codec  s18.GlobalENBIDValueCodec
	inject func(s18.GlobalENBID,

	) S1SetupRequestIEValue

	get func(*S1SetupRequestIEValue,

	) (*s18.GlobalENBID,

		bool)
}

// Info returns the source descriptor for this binding.
func (b S1SetupRequestGlobalENBIDIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b S1SetupRequestGlobalENBIDIEBinding) Codec() s18.GlobalENBIDValueCodec { return b.codec }

// New validates a source value and constructs its bound field.
func (b S1SetupRequestGlobalENBIDIEBinding) New(value s18.GlobalENBID,

) (S1SetupRequestIEField, error) {
	if b.inject == nil {
		return S1SetupRequestIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return S1SetupRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s18.BridgeGlobalENBIDValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return S1SetupRequestIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return S1SetupRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	return S1SetupRequestIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b S1SetupRequestGlobalENBIDIEBinding) Get(field *S1SetupRequestIEField) (*s18.GlobalENBID,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// S1SetupRequestENBnameIEBinding binds ENBname to the S1SetupRequestIEs object set of TS 36.413.
type S1SetupRequestENBnameIEBinding struct {
	info   s00.FieldInfo
	codec  s00.ENBnameValueCodec
	inject func(s00.ENBname,

	) S1SetupRequestIEValue

	get func(*S1SetupRequestIEValue,

	) (*s00.ENBname,

		bool)
}

// Info returns the source descriptor for this binding.
func (b S1SetupRequestENBnameIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b S1SetupRequestENBnameIEBinding) Codec() s00.ENBnameValueCodec { return b.codec }

// New validates a source value and constructs its bound field.
func (b S1SetupRequestENBnameIEBinding) New(value s00.ENBname,

) (S1SetupRequestIEField, error) {
	if b.inject == nil {
		return S1SetupRequestIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return S1SetupRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s00.BridgeENBnameValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return S1SetupRequestIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return S1SetupRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	return S1SetupRequestIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b S1SetupRequestENBnameIEBinding) Get(field *S1SetupRequestIEField) (*s00.ENBname,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// S1SetupRequestSupportedTAsIEBinding binds SupportedTAs to the S1SetupRequestIEs object set of TS 36.413.
type S1SetupRequestSupportedTAsIEBinding struct {
	info   s00.FieldInfo
	codec  s31.SupportedTAsValueCodec
	inject func(s31.SupportedTAs,

	) S1SetupRequestIEValue

	get func(*S1SetupRequestIEValue,

	) (*s31.SupportedTAs,

		bool)
}

// Info returns the source descriptor for this binding.
func (b S1SetupRequestSupportedTAsIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b S1SetupRequestSupportedTAsIEBinding) Codec() s31.SupportedTAsValueCodec { return b.codec }

// New validates a source value and constructs its bound field.
func (b S1SetupRequestSupportedTAsIEBinding) New(value s31.SupportedTAs,

) (S1SetupRequestIEField, error) {
	if b.inject == nil {
		return S1SetupRequestIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return S1SetupRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s31.BridgeSupportedTAsValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return S1SetupRequestIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return S1SetupRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	return S1SetupRequestIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b S1SetupRequestSupportedTAsIEBinding) Get(field *S1SetupRequestIEField) (*s31.SupportedTAs,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// S1SetupRequestPagingDRXIEBinding binds PagingDRX to the S1SetupRequestIEs object set of TS 36.413.
type S1SetupRequestPagingDRXIEBinding struct {
	info   s00.FieldInfo
	codec  s01.PagingDRXValueCodec
	inject func(s00.PagingDRX,

	) S1SetupRequestIEValue

	get func(*S1SetupRequestIEValue,

	) (*s00.PagingDRX,

		bool)
}

// Info returns the source descriptor for this binding.
func (b S1SetupRequestPagingDRXIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b S1SetupRequestPagingDRXIEBinding) Codec() s01.PagingDRXValueCodec { return b.codec }

// New validates a source value and constructs its bound field.
func (b S1SetupRequestPagingDRXIEBinding) New(value s00.PagingDRX,

) (S1SetupRequestIEField, error) {
	if b.inject == nil {
		return S1SetupRequestIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return S1SetupRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s01.BridgePagingDRXValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return S1SetupRequestIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return S1SetupRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	return S1SetupRequestIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b S1SetupRequestPagingDRXIEBinding) Get(field *S1SetupRequestIEField) (*s00.PagingDRX,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// S1SetupRequestCSGIdListIEBinding binds CSGIdList to the S1SetupRequestIEs object set of TS 36.413.
type S1SetupRequestCSGIdListIEBinding struct {
	info   s00.FieldInfo
	codec  s14.CSGIdListValueCodec
	inject func(s14.CSGIdList,

	) S1SetupRequestIEValue

	get func(*S1SetupRequestIEValue,

	) (*s14.CSGIdList,

		bool)
}

// Info returns the source descriptor for this binding.
func (b S1SetupRequestCSGIdListIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b S1SetupRequestCSGIdListIEBinding) Codec() s14.CSGIdListValueCodec { return b.codec }

// New validates a source value and constructs its bound field.
func (b S1SetupRequestCSGIdListIEBinding) New(value s14.CSGIdList,

) (S1SetupRequestIEField, error) {
	if b.inject == nil {
		return S1SetupRequestIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return S1SetupRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s14.BridgeCSGIdListValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return S1SetupRequestIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return S1SetupRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	return S1SetupRequestIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b S1SetupRequestCSGIdListIEBinding) Get(field *S1SetupRequestIEField) (*s14.CSGIdList,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// S1SetupRequestUERetentionInformationIEBinding binds UERetentionInformation to the S1SetupRequestIEs object set of TS 36.413.
type S1SetupRequestUERetentionInformationIEBinding struct {
	info   s00.FieldInfo
	codec  s02.UERetentionInformationValueCodec
	inject func(s00.UERetentionInformation,

	) S1SetupRequestIEValue

	get func(*S1SetupRequestIEValue,

	) (*s00.UERetentionInformation,

		bool)
}

// Info returns the source descriptor for this binding.
func (b S1SetupRequestUERetentionInformationIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b S1SetupRequestUERetentionInformationIEBinding) Codec() s02.UERetentionInformationValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b S1SetupRequestUERetentionInformationIEBinding) New(value s00.UERetentionInformation,

) (S1SetupRequestIEField, error) {
	if b.inject == nil {
		return S1SetupRequestIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return S1SetupRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s02.BridgeUERetentionInformationValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return S1SetupRequestIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return S1SetupRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	return S1SetupRequestIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b S1SetupRequestUERetentionInformationIEBinding) Get(field *S1SetupRequestIEField) (*s00.UERetentionInformation,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// S1SetupRequestNBIoTDefaultPagingDRXIEBinding binds NBIoTDefaultPagingDRX to the S1SetupRequestIEs object set of TS 36.413.
type S1SetupRequestNBIoTDefaultPagingDRXIEBinding struct {
	info   s00.FieldInfo
	codec  s01.NBIoTDefaultPagingDRXValueCodec
	inject func(s00.NBIoTDefaultPagingDRX,

	) S1SetupRequestIEValue

	get func(*S1SetupRequestIEValue,

	) (*s00.NBIoTDefaultPagingDRX,

		bool)
}

// Info returns the source descriptor for this binding.
func (b S1SetupRequestNBIoTDefaultPagingDRXIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b S1SetupRequestNBIoTDefaultPagingDRXIEBinding) Codec() s01.NBIoTDefaultPagingDRXValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b S1SetupRequestNBIoTDefaultPagingDRXIEBinding) New(value s00.NBIoTDefaultPagingDRX,

) (S1SetupRequestIEField, error) {
	if b.inject == nil {
		return S1SetupRequestIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return S1SetupRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s01.BridgeNBIoTDefaultPagingDRXValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return S1SetupRequestIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return S1SetupRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	return S1SetupRequestIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b S1SetupRequestNBIoTDefaultPagingDRXIEBinding) Get(field *S1SetupRequestIEField) (*s00.NBIoTDefaultPagingDRX,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// S1SetupRequestConnectedengNBListIEBinding binds ConnectedengNBList to the S1SetupRequestIEs object set of TS 36.413.
type S1SetupRequestConnectedengNBListIEBinding struct {
	info   s00.FieldInfo
	codec  s31.ConnectedengNBListValueCodec
	inject func(s31.ConnectedengNBList,

	) S1SetupRequestIEValue

	get func(*S1SetupRequestIEValue,

	) (*s31.ConnectedengNBList,

		bool)
}

// Info returns the source descriptor for this binding.
func (b S1SetupRequestConnectedengNBListIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b S1SetupRequestConnectedengNBListIEBinding) Codec() s31.ConnectedengNBListValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b S1SetupRequestConnectedengNBListIEBinding) New(value s31.ConnectedengNBList,

) (S1SetupRequestIEField, error) {
	if b.inject == nil {
		return S1SetupRequestIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return S1SetupRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s31.BridgeConnectedengNBListValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return S1SetupRequestIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return S1SetupRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	return S1SetupRequestIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b S1SetupRequestConnectedengNBListIEBinding) Get(field *S1SetupRequestIEField) (*s31.ConnectedengNBList,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// S1SetupResponseMMEnameIEBinding binds MMEname to the S1SetupResponseIEs object set of TS 36.413.
type S1SetupResponseMMEnameIEBinding struct {
	info   s00.FieldInfo
	codec  s01.MMEnameValueCodec
	inject func(s00.MMEname,

	) S1SetupResponseIEValue

	get func(*S1SetupResponseIEValue,

	) (*s00.MMEname,

		bool)
}

// Info returns the source descriptor for this binding.
func (b S1SetupResponseMMEnameIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b S1SetupResponseMMEnameIEBinding) Codec() s01.MMEnameValueCodec { return b.codec }

// New validates a source value and constructs its bound field.
func (b S1SetupResponseMMEnameIEBinding) New(value s00.MMEname,

) (S1SetupResponseIEField, error) {
	if b.inject == nil {
		return S1SetupResponseIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return S1SetupResponseIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s01.BridgeMMEnameValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return S1SetupResponseIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return S1SetupResponseIEField{}, aper.OperationError(err, "Value.New")
	}
	return S1SetupResponseIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b S1SetupResponseMMEnameIEBinding) Get(field *S1SetupResponseIEField) (*s00.MMEname,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// S1SetupResponseServedGUMMEIsIEBinding binds ServedGUMMEIs to the S1SetupResponseIEs object set of TS 36.413.
type S1SetupResponseServedGUMMEIsIEBinding struct {
	info   s00.FieldInfo
	codec  s31.ServedGUMMEIsValueCodec
	inject func(s31.ServedGUMMEIs,

	) S1SetupResponseIEValue

	get func(*S1SetupResponseIEValue,

	) (*s31.ServedGUMMEIs,

		bool)
}

// Info returns the source descriptor for this binding.
func (b S1SetupResponseServedGUMMEIsIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b S1SetupResponseServedGUMMEIsIEBinding) Codec() s31.ServedGUMMEIsValueCodec { return b.codec }

// New validates a source value and constructs its bound field.
func (b S1SetupResponseServedGUMMEIsIEBinding) New(value s31.ServedGUMMEIs,

) (S1SetupResponseIEField, error) {
	if b.inject == nil {
		return S1SetupResponseIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return S1SetupResponseIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s31.BridgeServedGUMMEIsValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return S1SetupResponseIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return S1SetupResponseIEField{}, aper.OperationError(err, "Value.New")
	}
	return S1SetupResponseIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b S1SetupResponseServedGUMMEIsIEBinding) Get(field *S1SetupResponseIEField) (*s31.ServedGUMMEIs,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// S1SetupResponseRelativeMMECapacityIEBinding binds RelativeMMECapacity to the S1SetupResponseIEs object set of TS 36.413.
type S1SetupResponseRelativeMMECapacityIEBinding struct {
	info   s00.FieldInfo
	codec  s01.RelativeMMECapacityValueCodec
	inject func(s00.RelativeMMECapacity,

	) S1SetupResponseIEValue

	get func(*S1SetupResponseIEValue,

	) (*s00.RelativeMMECapacity,

		bool)
}

// Info returns the source descriptor for this binding.
func (b S1SetupResponseRelativeMMECapacityIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b S1SetupResponseRelativeMMECapacityIEBinding) Codec() s01.RelativeMMECapacityValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b S1SetupResponseRelativeMMECapacityIEBinding) New(value s00.RelativeMMECapacity,

) (S1SetupResponseIEField, error) {
	if b.inject == nil {
		return S1SetupResponseIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return S1SetupResponseIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s01.BridgeRelativeMMECapacityValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return S1SetupResponseIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return S1SetupResponseIEField{}, aper.OperationError(err, "Value.New")
	}
	return S1SetupResponseIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b S1SetupResponseRelativeMMECapacityIEBinding) Get(field *S1SetupResponseIEField) (*s00.RelativeMMECapacity,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// S1SetupResponseMMERelaySupportIndicatorIEBinding binds MMERelaySupportIndicator to the S1SetupResponseIEs object set of TS 36.413.
type S1SetupResponseMMERelaySupportIndicatorIEBinding struct {
	info   s00.FieldInfo
	codec  s01.MMERelaySupportIndicatorValueCodec
	inject func(s00.MMERelaySupportIndicator,

	) S1SetupResponseIEValue

	get func(*S1SetupResponseIEValue,

	) (*s00.MMERelaySupportIndicator,

		bool)
}

// Info returns the source descriptor for this binding.
func (b S1SetupResponseMMERelaySupportIndicatorIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b S1SetupResponseMMERelaySupportIndicatorIEBinding) Codec() s01.MMERelaySupportIndicatorValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b S1SetupResponseMMERelaySupportIndicatorIEBinding) New(value s00.MMERelaySupportIndicator,

) (S1SetupResponseIEField, error) {
	if b.inject == nil {
		return S1SetupResponseIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return S1SetupResponseIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s01.BridgeMMERelaySupportIndicatorValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return S1SetupResponseIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return S1SetupResponseIEField{}, aper.OperationError(err, "Value.New")
	}
	return S1SetupResponseIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b S1SetupResponseMMERelaySupportIndicatorIEBinding) Get(field *S1SetupResponseIEField) (*s00.MMERelaySupportIndicator,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// S1SetupResponseCriticalityDiagnosticsIEBinding binds CriticalityDiagnostics to the S1SetupResponseIEs object set of TS 36.413.
type S1SetupResponseCriticalityDiagnosticsIEBinding struct {
	info   s00.FieldInfo
	codec  s22.CriticalityDiagnosticsValueCodec
	inject func(s22.CriticalityDiagnostics,

	) S1SetupResponseIEValue

	get func(*S1SetupResponseIEValue,

	) (*s22.CriticalityDiagnostics,

		bool)
}

// Info returns the source descriptor for this binding.
func (b S1SetupResponseCriticalityDiagnosticsIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b S1SetupResponseCriticalityDiagnosticsIEBinding) Codec() s22.CriticalityDiagnosticsValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b S1SetupResponseCriticalityDiagnosticsIEBinding) New(value s22.CriticalityDiagnostics,

) (S1SetupResponseIEField, error) {
	if b.inject == nil {
		return S1SetupResponseIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return S1SetupResponseIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s22.BridgeCriticalityDiagnosticsValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return S1SetupResponseIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return S1SetupResponseIEField{}, aper.OperationError(err, "Value.New")
	}
	return S1SetupResponseIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b S1SetupResponseCriticalityDiagnosticsIEBinding) Get(field *S1SetupResponseIEField) (*s22.CriticalityDiagnostics,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// S1SetupResponseUERetentionInformationIEBinding binds UERetentionInformation to the S1SetupResponseIEs object set of TS 36.413.
type S1SetupResponseUERetentionInformationIEBinding struct {
	info   s00.FieldInfo
	codec  s02.UERetentionInformationValueCodec
	inject func(s00.UERetentionInformation,

	) S1SetupResponseIEValue

	get func(*S1SetupResponseIEValue,

	) (*s00.UERetentionInformation,

		bool)
}

// Info returns the source descriptor for this binding.
func (b S1SetupResponseUERetentionInformationIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b S1SetupResponseUERetentionInformationIEBinding) Codec() s02.UERetentionInformationValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b S1SetupResponseUERetentionInformationIEBinding) New(value s00.UERetentionInformation,

) (S1SetupResponseIEField, error) {
	if b.inject == nil {
		return S1SetupResponseIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return S1SetupResponseIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s02.BridgeUERetentionInformationValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return S1SetupResponseIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return S1SetupResponseIEField{}, aper.OperationError(err, "Value.New")
	}
	return S1SetupResponseIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b S1SetupResponseUERetentionInformationIEBinding) Get(field *S1SetupResponseIEField) (*s00.UERetentionInformation,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// S1SetupResponseServedDCNsIEBinding binds ServedDCNs to the S1SetupResponseIEs object set of TS 36.413.
type S1SetupResponseServedDCNsIEBinding struct {
	info   s00.FieldInfo
	codec  s31.ServedDCNsValueCodec
	inject func(s31.ServedDCNs,

	) S1SetupResponseIEValue

	get func(*S1SetupResponseIEValue,

	) (*s31.ServedDCNs,

		bool)
}

// Info returns the source descriptor for this binding.
func (b S1SetupResponseServedDCNsIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b S1SetupResponseServedDCNsIEBinding) Codec() s31.ServedDCNsValueCodec { return b.codec }

// New validates a source value and constructs its bound field.
func (b S1SetupResponseServedDCNsIEBinding) New(value s31.ServedDCNs,

) (S1SetupResponseIEField, error) {
	if b.inject == nil {
		return S1SetupResponseIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return S1SetupResponseIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s31.BridgeServedDCNsValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return S1SetupResponseIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return S1SetupResponseIEField{}, aper.OperationError(err, "Value.New")
	}
	return S1SetupResponseIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b S1SetupResponseServedDCNsIEBinding) Get(field *S1SetupResponseIEField) (*s31.ServedDCNs,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// S1SetupResponseIABSupportedIEBinding binds IABSupported to the S1SetupResponseIEs object set of TS 36.413.
type S1SetupResponseIABSupportedIEBinding struct {
	info   s00.FieldInfo
	codec  s01.IABSupportedValueCodec
	inject func(s00.IABSupported,

	) S1SetupResponseIEValue

	get func(*S1SetupResponseIEValue,

	) (*s00.IABSupported,

		bool)
}

// Info returns the source descriptor for this binding.
func (b S1SetupResponseIABSupportedIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b S1SetupResponseIABSupportedIEBinding) Codec() s01.IABSupportedValueCodec { return b.codec }

// New validates a source value and constructs its bound field.
func (b S1SetupResponseIABSupportedIEBinding) New(value s00.IABSupported,

) (S1SetupResponseIEField, error) {
	if b.inject == nil {
		return S1SetupResponseIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return S1SetupResponseIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s01.BridgeIABSupportedValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return S1SetupResponseIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return S1SetupResponseIEField{}, aper.OperationError(err, "Value.New")
	}
	return S1SetupResponseIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b S1SetupResponseIABSupportedIEBinding) Get(field *S1SetupResponseIEField) (*s00.IABSupported,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// ENBConfigurationUpdateValueCodec is the concrete ValueCodec[ENBConfigurationUpdate].
type ENBConfigurationUpdateValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ENBConfigurationUpdate,

		error)
	encode func(ENBConfigurationUpdate,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ENBConfigurationUpdate, aper.DecodeState,

	) (ENBConfigurationUpdate, aper.Snapshot,

	)
	compare func(ENBConfigurationUpdate, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ENBConfigurationUpdateValueCodec) New(value ENBConfigurationUpdate,

) (ENBConfigurationUpdateAPERValue, error) {
	if c.encode == nil {
		return ENBConfigurationUpdateAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ENBConfigurationUpdateAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ENBConfigurationUpdateAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ENBConfigurationUpdateAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ENBConfigurationUpdateValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ENBConfigurationUpdateAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ENBConfigurationUpdateAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ENBConfigurationUpdateAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ENBConfigurationUpdateAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ENBConfigurationUpdateAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ENBConfigurationUpdateValueCodec) EncodeAPER(value ENBConfigurationUpdateAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c ENBConfigurationUpdateValueCodec) encodeBudgetValue(value ENBConfigurationUpdate,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ENBConfigurationUpdateValueCodec) encodeChanged(value ENBConfigurationUpdate,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// MMEConfigurationUpdateValueCodec is the concrete ValueCodec[MMEConfigurationUpdate].
type MMEConfigurationUpdateValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (MMEConfigurationUpdate,

		error)
	encode func(MMEConfigurationUpdate,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(MMEConfigurationUpdate, aper.DecodeState,

	) (MMEConfigurationUpdate, aper.Snapshot,

	)
	compare func(MMEConfigurationUpdate, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c MMEConfigurationUpdateValueCodec) New(value MMEConfigurationUpdate,

) (MMEConfigurationUpdateAPERValue, error) {
	if c.encode == nil {
		return MMEConfigurationUpdateAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return MMEConfigurationUpdateAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return MMEConfigurationUpdateAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return MMEConfigurationUpdateAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c MMEConfigurationUpdateValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (MMEConfigurationUpdateAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return MMEConfigurationUpdateAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return MMEConfigurationUpdateAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return MMEConfigurationUpdateAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return MMEConfigurationUpdateAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c MMEConfigurationUpdateValueCodec) EncodeAPER(value MMEConfigurationUpdateAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c MMEConfigurationUpdateValueCodec) encodeBudgetValue(value MMEConfigurationUpdate,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c MMEConfigurationUpdateValueCodec) encodeChanged(value MMEConfigurationUpdate,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
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

// S1SetupResponseValueCodec is the concrete ValueCodec[S1SetupResponse].
type S1SetupResponseValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (S1SetupResponse,

		error)
	encode func(S1SetupResponse,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(S1SetupResponse, aper.DecodeState,

	) (S1SetupResponse, aper.Snapshot,

	)
	compare func(S1SetupResponse, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c S1SetupResponseValueCodec) New(value S1SetupResponse,

) (S1SetupResponseAPERValue, error) {
	if c.encode == nil {
		return S1SetupResponseAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return S1SetupResponseAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return S1SetupResponseAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return S1SetupResponseAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c S1SetupResponseValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (S1SetupResponseAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return S1SetupResponseAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return S1SetupResponseAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return S1SetupResponseAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return S1SetupResponseAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c S1SetupResponseValueCodec) EncodeAPER(value S1SetupResponseAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c S1SetupResponseValueCodec) encodeBudgetValue(value S1SetupResponse,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c S1SetupResponseValueCodec) encodeChanged(value S1SetupResponse,

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
func BridgeS1SetupRequestIEValueValidateS1APIEContainer(fields S1SetupRequestIEContainer, rows []s00.FieldInfo, path string, budget *aper.DecodeBudget,

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
func BridgeS1SetupResponseIEValueValidateS1APIEContainer(fields S1SetupResponseIEContainer, rows []s00.FieldInfo, path string, budget *aper.DecodeBudget,

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
func BridgeENBConfigurationUpdateIEValueValidateS1APIEContainer(fields ENBConfigurationUpdateIEContainer, rows []s00.FieldInfo, path string, budget *aper.DecodeBudget,

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
func BridgeMMEConfigurationUpdateIEValueValidateS1APIEContainer(fields s43.MMEConfigurationUpdateIEContainer, rows []s00.FieldInfo, path string, budget *aper.DecodeBudget,

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
		if !s43.BridgeMMEConfigurationUpdateIEValueMethodMatchesID(field.Value, field.Id, budget) {
			rule := s43.BridgeMMEConfigurationUpdateIEValueMethodRule(field.Value)
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.ValueIDMismatch, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: aper.Path(fmt.Sprintf("%s.id", location.Path))}, Table: func() s00.TableID {
				sealed := s00.TableID{}
				*s00.BridgeTableIDFieldSource(&sealed) = rule.Assignment
				return sealed
			}(), IEID: field.Id, HasIEID: true, Rule: s27.BridgeS1apValidationRule(s00.ValueIDMismatch), RelatedRules: []aper.SourceRule{rule}})
		}
		rank, allowed := byID[field.Id]
		table := func() s00.TableID {
			sealed := s00.TableID{}
			*s00.BridgeTableIDFieldSource(&sealed) = s43.BridgeMMEConfigurationUpdateIEValueMethodRule(field.Value).Assignment
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

// ENBConfigurationUpdateIEValueERABIEContainerListCodec constructs the E-RAB-IE-ContainerList {{ENBConfigurationUpdateIEs}} codec of TS 36.413.
func ENBConfigurationUpdateIEValueERABIEContainerListCodec(table s00.ENBConfigurationUpdateIEValueIETable) ENBConfigurationUpdateIEValueERABIEContainerListValueCodec {
	codec := ENBConfigurationUpdateIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if codec.decode == nil {
		return ENBConfigurationUpdateIEValueERABIEContainerListValueCodec{}
	}
	size := aper.SizeConstraint{Lower: (aper.ListBounds{Lower: 1, Upper: 256}).Lower, Upper: (aper.ListBounds{Lower: 1, Upper: 256}).Upper, HasLower: true, HasUpper: true}
	return ENBConfigurationUpdateIEValueERABIEContainerListValueCodec{decode: func(data []byte, options aper.DecodeState) (ENBConfigurationUpdateIEValueERABIEContainerList, error) {
		bb := aper.NewCompleteDecodeBuffer(data, options)
		if err := bb.SetDecodeOptionsAligned(options); err != nil {
			return nil, err
		}
		var fields ENBConfigurationUpdateIEValueERABIEContainerList
		_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
			for i := int64(0); i < length; i++ {
				var field ENBConfigurationUpdateIEField
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
			return nil, runtime.WrapDecodePath(err, "ENBConfigurationUpdateIEValueERABIEContainerList")
		}
		if _, err := aper.CaptureFinalBits(bb, "ENBConfigurationUpdateIEValueERABIEContainerList"); err != nil {
			return nil, runtime.WrapDecodePath(err, "ENBConfigurationUpdateIEValueERABIEContainerList")
		}
		return fields, nil
	}, encode: func(value ENBConfigurationUpdateIEValueERABIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return codec.encode(ENBConfigurationUpdateIEContainer(value), fresh, budget)
	}, capture: func(v ENBConfigurationUpdateIEValueERABIEContainerList, options aper.DecodeState) (ENBConfigurationUpdateIEValueERABIEContainerList, aper.Snapshot) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeENBConfigurationUpdateIEValueCaptureS1APERABIEContainerList(&v, &s)
		var root aper.Snapshot
		s.End(f, &root,

			false)
		return v, root
	}, compare: func(v ENBConfigurationUpdateIEValueERABIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
	) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		BridgeENBConfigurationUpdateIEValueCompareS1APERABIEContainerList(&v, &s)
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

// MMEConfigurationUpdateIEValueERABIEContainerListCodec constructs the E-RAB-IE-ContainerList {{MMEConfigurationUpdateIEs}} codec of TS 36.413.
func MMEConfigurationUpdateIEValueERABIEContainerListCodec(table s00.MMEConfigurationUpdateIEValueIETable) MMEConfigurationUpdateIEValueERABIEContainerListValueCodec {
	codec := MMEConfigurationUpdateIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if *s43.BridgeMMEConfigurationUpdateIEContainerValueCodecFieldDecode(&codec) == nil {
		return MMEConfigurationUpdateIEValueERABIEContainerListValueCodec{}
	}
	size := aper.SizeConstraint{Lower: (aper.ListBounds{Lower: 1, Upper: 256}).Lower, Upper: (aper.ListBounds{Lower: 1, Upper: 256}).Upper, HasLower: true, HasUpper: true}
	return MMEConfigurationUpdateIEValueERABIEContainerListValueCodec{decode: func(data []byte, options aper.DecodeState) (MMEConfigurationUpdateIEValueERABIEContainerList, error) {
		bb := aper.NewCompleteDecodeBuffer(data, options)
		if err := bb.SetDecodeOptionsAligned(options); err != nil {
			return nil, err
		}
		var fields MMEConfigurationUpdateIEValueERABIEContainerList
		_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
			for i := int64(0); i < length; i++ {
				var field s43.MMEConfigurationUpdateIEField
				mark := bb.EnterIndex(int64(len(fields)))
				err := s43.BridgeMMEConfigurationUpdateIEFieldMethodUnmarshalAPERFrom(&field, bb)
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
			return nil, runtime.WrapDecodePath(err, "MMEConfigurationUpdateIEValueERABIEContainerList")
		}
		if _, err := aper.CaptureFinalBits(bb, "MMEConfigurationUpdateIEValueERABIEContainerList"); err != nil {
			return nil, runtime.WrapDecodePath(err, "MMEConfigurationUpdateIEValueERABIEContainerList")
		}
		return fields, nil
	}, encode: func(value MMEConfigurationUpdateIEValueERABIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return (*s43.BridgeMMEConfigurationUpdateIEContainerValueCodecFieldEncode(&codec))(s43.MMEConfigurationUpdateIEContainer(value), fresh, budget)
	}, capture: func(v MMEConfigurationUpdateIEValueERABIEContainerList, options aper.DecodeState) (MMEConfigurationUpdateIEValueERABIEContainerList, aper.Snapshot) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeMMEConfigurationUpdateIEValueCaptureS1APERABIEContainerList(&v, &s)
		var root aper.Snapshot
		s.End(f, &root,

			false)
		return v, root
	}, compare: func(v MMEConfigurationUpdateIEValueERABIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
	) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		BridgeMMEConfigurationUpdateIEValueCompareS1APERABIEContainerList(&v, &s)
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

// S1SetupRequestIEValueERABIEContainerListCodec constructs the E-RAB-IE-ContainerList {{S1SetupRequestIEs}} codec of TS 36.413.
func S1SetupRequestIEValueERABIEContainerListCodec(table s00.S1SetupRequestIEValueIETable) S1SetupRequestIEValueERABIEContainerListValueCodec {
	codec := S1SetupRequestIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if codec.decode == nil {
		return S1SetupRequestIEValueERABIEContainerListValueCodec{}
	}
	size := aper.SizeConstraint{Lower: (aper.ListBounds{Lower: 1, Upper: 256}).Lower, Upper: (aper.ListBounds{Lower: 1, Upper: 256}).Upper, HasLower: true, HasUpper: true}
	return S1SetupRequestIEValueERABIEContainerListValueCodec{decode: func(data []byte, options aper.DecodeState) (S1SetupRequestIEValueERABIEContainerList, error) {
		bb := aper.NewCompleteDecodeBuffer(data, options)
		if err := bb.SetDecodeOptionsAligned(options); err != nil {
			return nil, err
		}
		var fields S1SetupRequestIEValueERABIEContainerList
		_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
			for i := int64(0); i < length; i++ {
				var field S1SetupRequestIEField
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
			return nil, runtime.WrapDecodePath(err, "S1SetupRequestIEValueERABIEContainerList")
		}
		if _, err := aper.CaptureFinalBits(bb, "S1SetupRequestIEValueERABIEContainerList"); err != nil {
			return nil, runtime.WrapDecodePath(err, "S1SetupRequestIEValueERABIEContainerList")
		}
		return fields, nil
	}, encode: func(value S1SetupRequestIEValueERABIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return codec.encode(S1SetupRequestIEContainer(value), fresh, budget)
	}, capture: func(v S1SetupRequestIEValueERABIEContainerList, options aper.DecodeState) (S1SetupRequestIEValueERABIEContainerList, aper.Snapshot) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeS1SetupRequestIEValueCaptureS1APERABIEContainerList(&v, &s)
		var root aper.Snapshot
		s.End(f, &root,

			false)
		return v, root
	}, compare: func(v S1SetupRequestIEValueERABIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
	) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		BridgeS1SetupRequestIEValueCompareS1APERABIEContainerList(&v, &s)
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

// S1SetupResponseIEValueERABIEContainerListCodec constructs the E-RAB-IE-ContainerList {{S1SetupResponseIEs}} codec of TS 36.413.
func S1SetupResponseIEValueERABIEContainerListCodec(table s00.S1SetupResponseIEValueIETable) S1SetupResponseIEValueERABIEContainerListValueCodec {
	codec := S1SetupResponseIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if codec.decode == nil {
		return S1SetupResponseIEValueERABIEContainerListValueCodec{}
	}
	size := aper.SizeConstraint{Lower: (aper.ListBounds{Lower: 1, Upper: 256}).Lower, Upper: (aper.ListBounds{Lower: 1, Upper: 256}).Upper, HasLower: true, HasUpper: true}
	return S1SetupResponseIEValueERABIEContainerListValueCodec{decode: func(data []byte, options aper.DecodeState) (S1SetupResponseIEValueERABIEContainerList, error) {
		bb := aper.NewCompleteDecodeBuffer(data, options)
		if err := bb.SetDecodeOptionsAligned(options); err != nil {
			return nil, err
		}
		var fields S1SetupResponseIEValueERABIEContainerList
		_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
			for i := int64(0); i < length; i++ {
				var field S1SetupResponseIEField
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
			return nil, runtime.WrapDecodePath(err, "S1SetupResponseIEValueERABIEContainerList")
		}
		if _, err := aper.CaptureFinalBits(bb, "S1SetupResponseIEValueERABIEContainerList"); err != nil {
			return nil, runtime.WrapDecodePath(err, "S1SetupResponseIEValueERABIEContainerList")
		}
		return fields, nil
	}, encode: func(value S1SetupResponseIEValueERABIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return codec.encode(S1SetupResponseIEContainer(value), fresh, budget)
	}, capture: func(v S1SetupResponseIEValueERABIEContainerList, options aper.DecodeState) (S1SetupResponseIEValueERABIEContainerList, aper.Snapshot) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeS1SetupResponseIEValueCaptureS1APERABIEContainerList(&v, &s)
		var root aper.Snapshot
		s.End(f, &root,

			false)
		return v, root
	}, compare: func(v S1SetupResponseIEValueERABIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
	) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		BridgeS1SetupResponseIEValueCompareS1APERABIEContainerList(&v, &s)
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

// ENBConfigurationUpdateIEValueIEFieldTableCodec constructs the ProtocolIE-Field {{ENBConfigurationUpdateIEs}} codec of TS 36.413.
func ENBConfigurationUpdateIEValueIEFieldTableCodec(table s00.ENBConfigurationUpdateIEValueIETable) ENBConfigurationUpdateIEFieldValueCodec {
	if !*s00.BridgeENBConfigurationUpdateIEValueIETableFieldBound(&table) {
		return ENBConfigurationUpdateIEFieldValueCodec{}
	}
	return ENBConfigurationUpdateIEFieldValueCodec{decode: func(data []byte, options aper.DecodeState) (ENBConfigurationUpdateIEField, error) {
		var field ENBConfigurationUpdateIEField
		bb := aper.NewCompleteDecodeBuffer(data, options)
		if err := bb.SetDecodeOptionsAligned(options); err != nil {
			return field, err
		}
		if err := field.unmarshalAPERFrom(bb); err != nil {
			return field, runtime.WrapDecodePath(err, "ENBConfigurationUpdateIEField")
		}
		if _, err := aper.CaptureFinalBits(bb, "ENBConfigurationUpdateIEField"); err != nil {
			return field, runtime.WrapDecodePath(err, "ENBConfigurationUpdateIEField")
		}
		return field, nil
	}, encode: func(field ENBConfigurationUpdateIEField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		bb := aper.NewBudgetBuffer(budget)
		if err := field.marshalAPERTo(bb, fresh); err != nil {
			return nil, err
		}
		return bb.CompleteBytes(), nil
	}, capture: func(v ENBConfigurationUpdateIEField, options aper.DecodeState) (ENBConfigurationUpdateIEField, aper.Snapshot,
	) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeENBConfigurationUpdateIEValueCaptureS1APProtocolIEField(&v, &s)
		var root aper.Snapshot
		s.End(f, &root, false)
		return v, root
	}, compare: func(v ENBConfigurationUpdateIEField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

	) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		BridgeENBConfigurationUpdateIEValueCompareS1APProtocolIEField(&v, &s)
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

// MMEConfigurationUpdateIEValueIEFieldTableCodec constructs the ProtocolIE-Field {{MMEConfigurationUpdateIEs}} codec of TS 36.413.
func MMEConfigurationUpdateIEValueIEFieldTableCodec(table s00.MMEConfigurationUpdateIEValueIETable) MMEConfigurationUpdateIEFieldValueCodec {
	if !*s00.BridgeMMEConfigurationUpdateIEValueIETableFieldBound(&table) {
		return MMEConfigurationUpdateIEFieldValueCodec{}
	}
	return MMEConfigurationUpdateIEFieldValueCodec{decode: func(data []byte, options aper.DecodeState) (s43.MMEConfigurationUpdateIEField, error) {
		var field s43.MMEConfigurationUpdateIEField
		bb := aper.NewCompleteDecodeBuffer(data, options)
		if err := bb.SetDecodeOptionsAligned(options); err != nil {
			return field, err
		}
		if err := s43.BridgeMMEConfigurationUpdateIEFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
			return field, runtime.WrapDecodePath(err, "MMEConfigurationUpdateIEField")
		}
		if _, err := aper.CaptureFinalBits(bb, "MMEConfigurationUpdateIEField"); err != nil {
			return field, runtime.WrapDecodePath(err, "MMEConfigurationUpdateIEField")
		}
		return field, nil
	}, encode: func(field s43.MMEConfigurationUpdateIEField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		bb := aper.NewBudgetBuffer(budget)
		if err := s43.BridgeMMEConfigurationUpdateIEFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
			return nil, err
		}
		return bb.CompleteBytes(), nil
	}, capture: func(v s43.MMEConfigurationUpdateIEField, options aper.DecodeState) (s43.MMEConfigurationUpdateIEField, aper.Snapshot,
	) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeMMEConfigurationUpdateIEValueCaptureS1APProtocolIEField(&v, &s)
		var root aper.Snapshot
		s.End(f, &root, false)
		return v, root
	}, compare: func(v s43.MMEConfigurationUpdateIEField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

	) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		BridgeMMEConfigurationUpdateIEValueCompareS1APProtocolIEField(&v, &s)
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
			return field, runtime.WrapDecodePath(err, "PWSRestartIndicationIEField")
		}
		if _, err := aper.CaptureFinalBits(bb, "PWSRestartIndicationIEField"); err != nil {
			return field, runtime.WrapDecodePath(err, "PWSRestartIndicationIEField")
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
		BridgePWSRestartIndicationIEValueCaptureS1APProtocolIEField(&v, &s)
		var root aper.Snapshot
		s.End(f, &root, false)
		return v, root
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

// S1SetupRequestIEValueIEFieldTableCodec constructs the ProtocolIE-Field {{S1SetupRequestIEs}} codec of TS 36.413.
func S1SetupRequestIEValueIEFieldTableCodec(table s00.S1SetupRequestIEValueIETable) S1SetupRequestIEFieldValueCodec {
	if !*s00.BridgeS1SetupRequestIEValueIETableFieldBound(&table) {
		return S1SetupRequestIEFieldValueCodec{}
	}
	return S1SetupRequestIEFieldValueCodec{decode: func(data []byte, options aper.DecodeState) (S1SetupRequestIEField, error) {
		var field S1SetupRequestIEField
		bb := aper.NewCompleteDecodeBuffer(data, options)
		if err := bb.SetDecodeOptionsAligned(options); err != nil {
			return field, err
		}
		if err := field.unmarshalAPERFrom(bb); err != nil {
			return field, runtime.WrapDecodePath(err, "S1SetupRequestIEField")
		}
		if _, err := aper.CaptureFinalBits(bb, "S1SetupRequestIEField"); err != nil {
			return field, runtime.WrapDecodePath(err, "S1SetupRequestIEField")
		}
		return field, nil
	}, encode: func(field S1SetupRequestIEField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		bb := aper.NewBudgetBuffer(budget)
		if err := field.marshalAPERTo(bb, fresh); err != nil {
			return nil, err
		}
		return bb.CompleteBytes(), nil
	}, capture: func(v S1SetupRequestIEField, options aper.DecodeState) (S1SetupRequestIEField, aper.Snapshot,
	) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeS1SetupRequestIEValueCaptureS1APProtocolIEField(&v, &s)
		var root aper.Snapshot
		s.End(f, &root, false)
		return v, root
	}, compare: func(v S1SetupRequestIEField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

	) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		BridgeS1SetupRequestIEValueCompareS1APProtocolIEField(&v, &s)
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

// S1SetupResponseIEValueIEFieldTableCodec constructs the ProtocolIE-Field {{S1SetupResponseIEs}} codec of TS 36.413.
func S1SetupResponseIEValueIEFieldTableCodec(table s00.S1SetupResponseIEValueIETable) S1SetupResponseIEFieldValueCodec {
	if !*s00.BridgeS1SetupResponseIEValueIETableFieldBound(&table) {
		return S1SetupResponseIEFieldValueCodec{}
	}
	return S1SetupResponseIEFieldValueCodec{decode: func(data []byte, options aper.DecodeState) (S1SetupResponseIEField, error) {
		var field S1SetupResponseIEField
		bb := aper.NewCompleteDecodeBuffer(data, options)
		if err := bb.SetDecodeOptionsAligned(options); err != nil {
			return field, err
		}
		if err := field.unmarshalAPERFrom(bb); err != nil {
			return field, runtime.WrapDecodePath(err, "S1SetupResponseIEField")
		}
		if _, err := aper.CaptureFinalBits(bb, "S1SetupResponseIEField"); err != nil {
			return field, runtime.WrapDecodePath(err, "S1SetupResponseIEField")
		}
		return field, nil
	}, encode: func(field S1SetupResponseIEField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		bb := aper.NewBudgetBuffer(budget)
		if err := field.marshalAPERTo(bb, fresh); err != nil {
			return nil, err
		}
		return bb.CompleteBytes(), nil
	}, capture: func(v S1SetupResponseIEField, options aper.DecodeState) (S1SetupResponseIEField, aper.Snapshot,
	) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeS1SetupResponseIEValueCaptureS1APProtocolIEField(&v, &s)
		var root aper.Snapshot
		s.End(f, &root, false)
		return v, root
	}, compare: func(v S1SetupResponseIEField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

	) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		BridgeS1SetupResponseIEValueCompareS1APProtocolIEField(&v, &s)
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

// ENBConfigurationUpdateIEValueIETableCodec constructs the ProtocolIE-Container {{ENBConfigurationUpdateIEs}} codec of TS 36.413.
func ENBConfigurationUpdateIEValueIETableCodec(table s00.ENBConfigurationUpdateIEValueIETable, bounds aper.ListBounds) ENBConfigurationUpdateIEContainerValueCodec {
	if !*s00.BridgeENBConfigurationUpdateIEValueIETableFieldBound(&table) {
		return ENBConfigurationUpdateIEContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return ENBConfigurationUpdateIEContainerValueCodec{decode: func(data []byte, options aper.DecodeState) (ENBConfigurationUpdateIEContainer, error) {
		bb := aper.NewCompleteDecodeBuffer(data, options)
		if err := bb.SetDecodeOptionsAligned(options); err != nil {
			return nil, err
		}
		var fields ENBConfigurationUpdateIEContainer
		_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
			for i := int64(0); i < length; i++ {
				var field ENBConfigurationUpdateIEField
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
			return nil, runtime.WrapDecodePath(err, "ENBConfigurationUpdateIEContainer")
		}
		if _, err := aper.CaptureFinalBits(bb, "ENBConfigurationUpdateIEContainer"); err != nil {
			return nil, runtime.WrapDecodePath(err, "ENBConfigurationUpdateIEContainer")
		}
		return fields, nil
	},
		encode: func(fields ENBConfigurationUpdateIEContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
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
		}, capture: func(v ENBConfigurationUpdateIEContainer, options aper.DecodeState) (ENBConfigurationUpdateIEContainer, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeENBConfigurationUpdateIEValueCaptureS1APProtocolIEContainer(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,

				false)
			return v, root
		}, compare: func(v ENBConfigurationUpdateIEContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeENBConfigurationUpdateIEValueCompareS1APProtocolIEContainer(&v, &s)
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

// MMEConfigurationUpdateIEValueIETableCodec constructs the ProtocolIE-Container {{MMEConfigurationUpdateIEs}} codec of TS 36.413.
func MMEConfigurationUpdateIEValueIETableCodec(table s00.MMEConfigurationUpdateIEValueIETable, bounds aper.ListBounds) s43.MMEConfigurationUpdateIEContainerValueCodec {
	if !*s00.BridgeMMEConfigurationUpdateIEValueIETableFieldBound(&table) {
		return s43.MMEConfigurationUpdateIEContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s43.MMEConfigurationUpdateIEContainerValueCodec {
		sealed := s43.MMEConfigurationUpdateIEContainerValueCodec{}
		*s43.BridgeMMEConfigurationUpdateIEContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s43.MMEConfigurationUpdateIEContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s43.MMEConfigurationUpdateIEContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s43.MMEConfigurationUpdateIEField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s43.BridgeMMEConfigurationUpdateIEFieldMethodUnmarshalAPERFrom(&field, bb)
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
				return nil, runtime.WrapDecodePath(err, "MMEConfigurationUpdateIEContainer")
			}
			if _, err := aper.CaptureFinalBits(bb, "MMEConfigurationUpdateIEContainer"); err != nil {
				return nil, runtime.WrapDecodePath(err, "MMEConfigurationUpdateIEContainer")
			}
			return fields, nil
		}
		*s43.BridgeMMEConfigurationUpdateIEContainerValueCodecFieldEncode(&sealed) = func(fields s43.MMEConfigurationUpdateIEContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s43.BridgeMMEConfigurationUpdateIEFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
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
		*s43.BridgeMMEConfigurationUpdateIEContainerValueCodecFieldCapture(&sealed) = func(v s43.MMEConfigurationUpdateIEContainer, options aper.DecodeState) (s43.MMEConfigurationUpdateIEContainer, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeMMEConfigurationUpdateIEValueCaptureS1APProtocolIEContainer(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,

				false)
			return v, root
		}
		*s43.BridgeMMEConfigurationUpdateIEContainerValueCodecFieldCompare(&sealed) = func(v s43.MMEConfigurationUpdateIEContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeMMEConfigurationUpdateIEValueCompareS1APProtocolIEContainer(&v, &s)
			s.End(f, root,

				false,
			)
			return s.Plan(), s.BudgetValue()
		}
		*s43.BridgeMMEConfigurationUpdateIEContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
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
			return nil, runtime.WrapDecodePath(err, "PWSRestartIndicationIEContainer")
		}
		if _, err := aper.CaptureFinalBits(bb, "PWSRestartIndicationIEContainer"); err != nil {
			return nil, runtime.WrapDecodePath(err, "PWSRestartIndicationIEContainer")
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
			s.End(f, &root,

				false)
			return v, root
		}, compare: func(v PWSRestartIndicationIEContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgePWSRestartIndicationIEValueCompareS1APProtocolIEContainer(&v, &s)
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

// S1SetupRequestIEValueIETableCodec constructs the ProtocolIE-Container {{S1SetupRequestIEs}} codec of TS 36.413.
func S1SetupRequestIEValueIETableCodec(table s00.S1SetupRequestIEValueIETable, bounds aper.ListBounds) S1SetupRequestIEContainerValueCodec {
	if !*s00.BridgeS1SetupRequestIEValueIETableFieldBound(&table) {
		return S1SetupRequestIEContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return S1SetupRequestIEContainerValueCodec{decode: func(data []byte, options aper.DecodeState) (S1SetupRequestIEContainer, error) {
		bb := aper.NewCompleteDecodeBuffer(data, options)
		if err := bb.SetDecodeOptionsAligned(options); err != nil {
			return nil, err
		}
		var fields S1SetupRequestIEContainer
		_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
			for i := int64(0); i < length; i++ {
				var field S1SetupRequestIEField
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
			return nil, runtime.WrapDecodePath(err, "S1SetupRequestIEContainer")
		}
		if _, err := aper.CaptureFinalBits(bb, "S1SetupRequestIEContainer"); err != nil {
			return nil, runtime.WrapDecodePath(err, "S1SetupRequestIEContainer")
		}
		return fields, nil
	},
		encode: func(fields S1SetupRequestIEContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
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
		}, capture: func(v S1SetupRequestIEContainer, options aper.DecodeState) (S1SetupRequestIEContainer, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeS1SetupRequestIEValueCaptureS1APProtocolIEContainer(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,

				false)
			return v, root
		}, compare: func(v S1SetupRequestIEContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeS1SetupRequestIEValueCompareS1APProtocolIEContainer(&v, &s)
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

// S1SetupResponseIEValueIETableCodec constructs the ProtocolIE-Container {{S1SetupResponseIEs}} codec of TS 36.413.
func S1SetupResponseIEValueIETableCodec(table s00.S1SetupResponseIEValueIETable, bounds aper.ListBounds) S1SetupResponseIEContainerValueCodec {
	if !*s00.BridgeS1SetupResponseIEValueIETableFieldBound(&table) {
		return S1SetupResponseIEContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return S1SetupResponseIEContainerValueCodec{decode: func(data []byte, options aper.DecodeState) (S1SetupResponseIEContainer, error) {
		bb := aper.NewCompleteDecodeBuffer(data, options)
		if err := bb.SetDecodeOptionsAligned(options); err != nil {
			return nil, err
		}
		var fields S1SetupResponseIEContainer
		_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
			for i := int64(0); i < length; i++ {
				var field S1SetupResponseIEField
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
			return nil, runtime.WrapDecodePath(err, "S1SetupResponseIEContainer")
		}
		if _, err := aper.CaptureFinalBits(bb, "S1SetupResponseIEContainer"); err != nil {
			return nil, runtime.WrapDecodePath(err, "S1SetupResponseIEContainer")
		}
		return fields, nil
	},
		encode: func(fields S1SetupResponseIEContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
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
		}, capture: func(v S1SetupResponseIEContainer, options aper.DecodeState) (S1SetupResponseIEContainer, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeS1SetupResponseIEValueCaptureS1APProtocolIEContainer(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,

				false)
			return v, root
		}, compare: func(v S1SetupResponseIEContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeS1SetupResponseIEValueCompareS1APProtocolIEContainer(&v, &s)
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

// ENBConfigurationUpdateIEValueProtocolErrorIEContainerListCodec constructs the ProtocolError-IE-ContainerList {{ENBConfigurationUpdateIEs}} codec of TS 36.413.
func ENBConfigurationUpdateIEValueProtocolErrorIEContainerListCodec(table s00.ENBConfigurationUpdateIEValueIETable) ENBConfigurationUpdateIEValueProtocolErrorIEContainerListValueCodec {
	codec := ENBConfigurationUpdateIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if codec.decode == nil {
		return ENBConfigurationUpdateIEValueProtocolErrorIEContainerListValueCodec{}
	}
	size := aper.SizeConstraint{Lower: (aper.ListBounds{Lower: 1, Upper: 256}).Lower, Upper: (aper.ListBounds{Lower: 1, Upper: 256}).Upper, HasLower: true, HasUpper: true}
	return ENBConfigurationUpdateIEValueProtocolErrorIEContainerListValueCodec{decode: func(data []byte, options aper.DecodeState) (ENBConfigurationUpdateIEValueProtocolErrorIEContainerList, error) {
		bb := aper.NewCompleteDecodeBuffer(data, options)
		if err := bb.SetDecodeOptionsAligned(options); err != nil {
			return nil, err
		}
		var fields ENBConfigurationUpdateIEValueProtocolErrorIEContainerList
		_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
			for i := int64(0); i < length; i++ {
				var field ENBConfigurationUpdateIEField
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
			return nil, runtime.WrapDecodePath(err, "ENBConfigurationUpdateIEValueProtocolErrorIEContainerList")
		}
		if _, err := aper.CaptureFinalBits(bb, "ENBConfigurationUpdateIEValueProtocolErrorIEContainerList"); err != nil {
			return nil, runtime.WrapDecodePath(err, "ENBConfigurationUpdateIEValueProtocolErrorIEContainerList")
		}
		return fields, nil
	}, encode: func(value ENBConfigurationUpdateIEValueProtocolErrorIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return codec.encode(ENBConfigurationUpdateIEContainer(value), fresh, budget)
	}, capture: func(v ENBConfigurationUpdateIEValueProtocolErrorIEContainerList, options aper.DecodeState) (ENBConfigurationUpdateIEValueProtocolErrorIEContainerList, aper.Snapshot,
	) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeENBConfigurationUpdateIEValueCaptureS1APProtocolErrorIEContainerList(&v, &s)
		var root aper.Snapshot

		s.End(f, &root, false)
		return v, root
	}, compare: func(v ENBConfigurationUpdateIEValueProtocolErrorIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

	) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		BridgeENBConfigurationUpdateIEValueCompareS1APProtocolErrorIEContainerList(
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

// MMEConfigurationUpdateIEValueProtocolErrorIEContainerListCodec constructs the ProtocolError-IE-ContainerList {{MMEConfigurationUpdateIEs}} codec of TS 36.413.
func MMEConfigurationUpdateIEValueProtocolErrorIEContainerListCodec(table s00.MMEConfigurationUpdateIEValueIETable) MMEConfigurationUpdateIEValueProtocolErrorIEContainerListValueCodec {
	codec := MMEConfigurationUpdateIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if *s43.BridgeMMEConfigurationUpdateIEContainerValueCodecFieldDecode(&codec) == nil {
		return MMEConfigurationUpdateIEValueProtocolErrorIEContainerListValueCodec{}
	}
	size := aper.SizeConstraint{Lower: (aper.ListBounds{Lower: 1, Upper: 256}).Lower, Upper: (aper.ListBounds{Lower: 1, Upper: 256}).Upper, HasLower: true, HasUpper: true}
	return MMEConfigurationUpdateIEValueProtocolErrorIEContainerListValueCodec{decode: func(data []byte, options aper.DecodeState) (MMEConfigurationUpdateIEValueProtocolErrorIEContainerList, error) {
		bb := aper.NewCompleteDecodeBuffer(data, options)
		if err := bb.SetDecodeOptionsAligned(options); err != nil {
			return nil, err
		}
		var fields MMEConfigurationUpdateIEValueProtocolErrorIEContainerList
		_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
			for i := int64(0); i < length; i++ {
				var field s43.MMEConfigurationUpdateIEField
				mark := bb.EnterIndex(int64(len(fields)))
				err := s43.BridgeMMEConfigurationUpdateIEFieldMethodUnmarshalAPERFrom(&field, bb)
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
			return nil, runtime.WrapDecodePath(err, "MMEConfigurationUpdateIEValueProtocolErrorIEContainerList")
		}
		if _, err := aper.CaptureFinalBits(bb, "MMEConfigurationUpdateIEValueProtocolErrorIEContainerList"); err != nil {
			return nil, runtime.WrapDecodePath(err, "MMEConfigurationUpdateIEValueProtocolErrorIEContainerList")
		}
		return fields, nil
	}, encode: func(value MMEConfigurationUpdateIEValueProtocolErrorIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return (*s43.BridgeMMEConfigurationUpdateIEContainerValueCodecFieldEncode(&codec))(s43.MMEConfigurationUpdateIEContainer(value), fresh, budget)
	}, capture: func(v MMEConfigurationUpdateIEValueProtocolErrorIEContainerList, options aper.DecodeState) (MMEConfigurationUpdateIEValueProtocolErrorIEContainerList, aper.Snapshot,
	) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeMMEConfigurationUpdateIEValueCaptureS1APProtocolErrorIEContainerList(&v, &s)
		var root aper.Snapshot

		s.End(f, &root, false)
		return v, root
	}, compare: func(v MMEConfigurationUpdateIEValueProtocolErrorIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

	) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		BridgeMMEConfigurationUpdateIEValueCompareS1APProtocolErrorIEContainerList(
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

// S1SetupRequestIEValueProtocolErrorIEContainerListCodec constructs the ProtocolError-IE-ContainerList {{S1SetupRequestIEs}} codec of TS 36.413.
func S1SetupRequestIEValueProtocolErrorIEContainerListCodec(table s00.S1SetupRequestIEValueIETable) S1SetupRequestIEValueProtocolErrorIEContainerListValueCodec {
	codec := S1SetupRequestIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if codec.decode == nil {
		return S1SetupRequestIEValueProtocolErrorIEContainerListValueCodec{}
	}
	size := aper.SizeConstraint{Lower: (aper.ListBounds{Lower: 1, Upper: 256}).Lower, Upper: (aper.ListBounds{Lower: 1, Upper: 256}).Upper, HasLower: true, HasUpper: true}
	return S1SetupRequestIEValueProtocolErrorIEContainerListValueCodec{decode: func(data []byte, options aper.DecodeState) (S1SetupRequestIEValueProtocolErrorIEContainerList, error) {
		bb := aper.NewCompleteDecodeBuffer(data, options)
		if err := bb.SetDecodeOptionsAligned(options); err != nil {
			return nil, err
		}
		var fields S1SetupRequestIEValueProtocolErrorIEContainerList
		_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
			for i := int64(0); i < length; i++ {
				var field S1SetupRequestIEField
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
			return nil, runtime.WrapDecodePath(err, "S1SetupRequestIEValueProtocolErrorIEContainerList")
		}
		if _, err := aper.CaptureFinalBits(bb, "S1SetupRequestIEValueProtocolErrorIEContainerList"); err != nil {
			return nil, runtime.WrapDecodePath(err, "S1SetupRequestIEValueProtocolErrorIEContainerList")
		}
		return fields, nil
	}, encode: func(value S1SetupRequestIEValueProtocolErrorIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return codec.encode(S1SetupRequestIEContainer(value), fresh, budget)
	}, capture: func(v S1SetupRequestIEValueProtocolErrorIEContainerList, options aper.DecodeState) (S1SetupRequestIEValueProtocolErrorIEContainerList, aper.Snapshot,
	) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeS1SetupRequestIEValueCaptureS1APProtocolErrorIEContainerList(&v, &s)
		var root aper.Snapshot

		s.End(f, &root, false)
		return v, root
	}, compare: func(v S1SetupRequestIEValueProtocolErrorIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

	) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		BridgeS1SetupRequestIEValueCompareS1APProtocolErrorIEContainerList(
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

// S1SetupResponseIEValueProtocolErrorIEContainerListCodec constructs the ProtocolError-IE-ContainerList {{S1SetupResponseIEs}} codec of TS 36.413.
func S1SetupResponseIEValueProtocolErrorIEContainerListCodec(table s00.S1SetupResponseIEValueIETable) S1SetupResponseIEValueProtocolErrorIEContainerListValueCodec {
	codec := S1SetupResponseIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if codec.decode == nil {
		return S1SetupResponseIEValueProtocolErrorIEContainerListValueCodec{}
	}
	size := aper.SizeConstraint{Lower: (aper.ListBounds{Lower: 1, Upper: 256}).Lower, Upper: (aper.ListBounds{Lower: 1, Upper: 256}).Upper, HasLower: true, HasUpper: true}
	return S1SetupResponseIEValueProtocolErrorIEContainerListValueCodec{decode: func(data []byte, options aper.DecodeState) (S1SetupResponseIEValueProtocolErrorIEContainerList, error) {
		bb := aper.NewCompleteDecodeBuffer(data, options)
		if err := bb.SetDecodeOptionsAligned(options); err != nil {
			return nil, err
		}
		var fields S1SetupResponseIEValueProtocolErrorIEContainerList
		_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
			for i := int64(0); i < length; i++ {
				var field S1SetupResponseIEField
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
			return nil, runtime.WrapDecodePath(err, "S1SetupResponseIEValueProtocolErrorIEContainerList")
		}
		if _, err := aper.CaptureFinalBits(bb, "S1SetupResponseIEValueProtocolErrorIEContainerList"); err != nil {
			return nil, runtime.WrapDecodePath(err, "S1SetupResponseIEValueProtocolErrorIEContainerList")
		}
		return fields, nil
	}, encode: func(value S1SetupResponseIEValueProtocolErrorIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return codec.encode(S1SetupResponseIEContainer(value), fresh, budget)
	}, capture: func(v S1SetupResponseIEValueProtocolErrorIEContainerList, options aper.DecodeState) (S1SetupResponseIEValueProtocolErrorIEContainerList, aper.Snapshot,
	) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeS1SetupResponseIEValueCaptureS1APProtocolErrorIEContainerList(&v, &s)
		var root aper.Snapshot

		s.End(f, &root, false)
		return v, root
	}, compare: func(v S1SetupResponseIEValueProtocolErrorIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

	) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		BridgeS1SetupResponseIEValueCompareS1APProtocolErrorIEContainerList(
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

// ENBConfigurationUpdateIEValueProtocolIEContainerListCodec constructs a codec for ProtocolIE-ContainerList with IEsSetParam = {ENBConfigurationUpdateIEs} of TS 36.413, with lowerBound and upperBound supplied by its arguments.
func ENBConfigurationUpdateIEValueProtocolIEContainerListCodec(table s00.ENBConfigurationUpdateIEValueIETable, bounds aper.ListBounds) ENBConfigurationUpdateIEValueProtocolIEContainerListValueCodec {
	codec := ENBConfigurationUpdateIEValueIETableCodec(table, bounds)
	if codec.decode == nil {
		return ENBConfigurationUpdateIEValueProtocolIEContainerListValueCodec{}
	}
	size := aper.SizeConstraint{Lower: (bounds).Lower, Upper: (bounds).Upper, HasLower: true, HasUpper: true}
	return ENBConfigurationUpdateIEValueProtocolIEContainerListValueCodec{decode: func(data []byte, options aper.DecodeState) (ENBConfigurationUpdateIEValueProtocolIEContainerList, error) {
		bb := aper.NewCompleteDecodeBuffer(data, options)
		if err := bb.SetDecodeOptionsAligned(options); err != nil {
			return nil, err
		}
		var fields ENBConfigurationUpdateIEValueProtocolIEContainerList
		_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
			for i := int64(0); i < length; i++ {
				var field ENBConfigurationUpdateIEField
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
			return nil, runtime.WrapDecodePath(err, "ENBConfigurationUpdateIEValueProtocolIEContainerList")
		}
		if _, err := aper.CaptureFinalBits(bb, "ENBConfigurationUpdateIEValueProtocolIEContainerList"); err != nil {
			return nil, runtime.WrapDecodePath(err, "ENBConfigurationUpdateIEValueProtocolIEContainerList")
		}
		return fields, nil
	}, encode: func(value ENBConfigurationUpdateIEValueProtocolIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return codec.encode(ENBConfigurationUpdateIEContainer(value), fresh, budget)
	}, capture: func(v ENBConfigurationUpdateIEValueProtocolIEContainerList, options aper.DecodeState) (ENBConfigurationUpdateIEValueProtocolIEContainerList, aper.Snapshot,
	) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeENBConfigurationUpdateIEValueCaptureS1APProtocolIEContainerList(&v, &s)
		var root aper.Snapshot
		s.
			End(f, &root, false)
		return v, root
	}, compare: func(v ENBConfigurationUpdateIEValueProtocolIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
	) {
		s := aper.NewSemanticComparison(root, budget)
		f :=
			s.Begin()
		BridgeENBConfigurationUpdateIEValueCompareS1APProtocolIEContainerList(&v, &s)
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

// MMEConfigurationUpdateIEValueProtocolIEContainerListCodec constructs a codec for ProtocolIE-ContainerList with IEsSetParam = {MMEConfigurationUpdateIEs} of TS 36.413, with lowerBound and upperBound supplied by its arguments.
func MMEConfigurationUpdateIEValueProtocolIEContainerListCodec(table s00.MMEConfigurationUpdateIEValueIETable, bounds aper.ListBounds) MMEConfigurationUpdateIEValueProtocolIEContainerListValueCodec {
	codec := MMEConfigurationUpdateIEValueIETableCodec(table, bounds)
	if *s43.BridgeMMEConfigurationUpdateIEContainerValueCodecFieldDecode(&codec) == nil {
		return MMEConfigurationUpdateIEValueProtocolIEContainerListValueCodec{}
	}
	size := aper.SizeConstraint{Lower: (bounds).Lower, Upper: (bounds).Upper, HasLower: true, HasUpper: true}
	return MMEConfigurationUpdateIEValueProtocolIEContainerListValueCodec{decode: func(data []byte, options aper.DecodeState) (MMEConfigurationUpdateIEValueProtocolIEContainerList, error) {
		bb := aper.NewCompleteDecodeBuffer(data, options)
		if err := bb.SetDecodeOptionsAligned(options); err != nil {
			return nil, err
		}
		var fields MMEConfigurationUpdateIEValueProtocolIEContainerList
		_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
			for i := int64(0); i < length; i++ {
				var field s43.MMEConfigurationUpdateIEField
				mark := bb.EnterIndex(int64(len(fields)))
				err := s43.BridgeMMEConfigurationUpdateIEFieldMethodUnmarshalAPERFrom(&field, bb)
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
			return nil, runtime.WrapDecodePath(err, "MMEConfigurationUpdateIEValueProtocolIEContainerList")
		}
		if _, err := aper.CaptureFinalBits(bb, "MMEConfigurationUpdateIEValueProtocolIEContainerList"); err != nil {
			return nil, runtime.WrapDecodePath(err, "MMEConfigurationUpdateIEValueProtocolIEContainerList")
		}
		return fields, nil
	}, encode: func(value MMEConfigurationUpdateIEValueProtocolIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return (*s43.BridgeMMEConfigurationUpdateIEContainerValueCodecFieldEncode(&codec))(s43.MMEConfigurationUpdateIEContainer(value), fresh, budget)
	}, capture: func(v MMEConfigurationUpdateIEValueProtocolIEContainerList, options aper.DecodeState) (MMEConfigurationUpdateIEValueProtocolIEContainerList, aper.Snapshot,
	) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeMMEConfigurationUpdateIEValueCaptureS1APProtocolIEContainerList(&v, &s)
		var root aper.Snapshot
		s.
			End(f, &root, false)
		return v, root
	}, compare: func(v MMEConfigurationUpdateIEValueProtocolIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
	) {
		s := aper.NewSemanticComparison(root, budget)
		f :=
			s.Begin()
		BridgeMMEConfigurationUpdateIEValueCompareS1APProtocolIEContainerList(&v, &s)
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

// S1SetupRequestIEValueProtocolIEContainerListCodec constructs a codec for ProtocolIE-ContainerList with IEsSetParam = {S1SetupRequestIEs} of TS 36.413, with lowerBound and upperBound supplied by its arguments.
func S1SetupRequestIEValueProtocolIEContainerListCodec(table s00.S1SetupRequestIEValueIETable, bounds aper.ListBounds) S1SetupRequestIEValueProtocolIEContainerListValueCodec {
	codec := S1SetupRequestIEValueIETableCodec(table, bounds)
	if codec.decode == nil {
		return S1SetupRequestIEValueProtocolIEContainerListValueCodec{}
	}
	size := aper.SizeConstraint{Lower: (bounds).Lower, Upper: (bounds).Upper, HasLower: true, HasUpper: true}
	return S1SetupRequestIEValueProtocolIEContainerListValueCodec{decode: func(data []byte, options aper.DecodeState) (S1SetupRequestIEValueProtocolIEContainerList, error) {
		bb := aper.NewCompleteDecodeBuffer(data, options)
		if err := bb.SetDecodeOptionsAligned(options); err != nil {
			return nil, err
		}
		var fields S1SetupRequestIEValueProtocolIEContainerList
		_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
			for i := int64(0); i < length; i++ {
				var field S1SetupRequestIEField
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
			return nil, runtime.WrapDecodePath(err, "S1SetupRequestIEValueProtocolIEContainerList")
		}
		if _, err := aper.CaptureFinalBits(bb, "S1SetupRequestIEValueProtocolIEContainerList"); err != nil {
			return nil, runtime.WrapDecodePath(err, "S1SetupRequestIEValueProtocolIEContainerList")
		}
		return fields, nil
	}, encode: func(value S1SetupRequestIEValueProtocolIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return codec.encode(S1SetupRequestIEContainer(value), fresh, budget)
	}, capture: func(v S1SetupRequestIEValueProtocolIEContainerList, options aper.DecodeState) (S1SetupRequestIEValueProtocolIEContainerList, aper.Snapshot,
	) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeS1SetupRequestIEValueCaptureS1APProtocolIEContainerList(&v, &s)
		var root aper.Snapshot
		s.
			End(f, &root, false)
		return v, root
	}, compare: func(v S1SetupRequestIEValueProtocolIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
	) {
		s := aper.NewSemanticComparison(root, budget)
		f :=
			s.Begin()
		BridgeS1SetupRequestIEValueCompareS1APProtocolIEContainerList(&v, &s)
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

// S1SetupResponseIEValueProtocolIEContainerListCodec constructs a codec for ProtocolIE-ContainerList with IEsSetParam = {S1SetupResponseIEs} of TS 36.413, with lowerBound and upperBound supplied by its arguments.
func S1SetupResponseIEValueProtocolIEContainerListCodec(table s00.S1SetupResponseIEValueIETable, bounds aper.ListBounds) S1SetupResponseIEValueProtocolIEContainerListValueCodec {
	codec := S1SetupResponseIEValueIETableCodec(table, bounds)
	if codec.decode == nil {
		return S1SetupResponseIEValueProtocolIEContainerListValueCodec{}
	}
	size := aper.SizeConstraint{Lower: (bounds).Lower, Upper: (bounds).Upper, HasLower: true, HasUpper: true}
	return S1SetupResponseIEValueProtocolIEContainerListValueCodec{decode: func(data []byte, options aper.DecodeState) (S1SetupResponseIEValueProtocolIEContainerList, error) {
		bb := aper.NewCompleteDecodeBuffer(data, options)
		if err := bb.SetDecodeOptionsAligned(options); err != nil {
			return nil, err
		}
		var fields S1SetupResponseIEValueProtocolIEContainerList
		_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
			for i := int64(0); i < length; i++ {
				var field S1SetupResponseIEField
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
			return nil, runtime.WrapDecodePath(err, "S1SetupResponseIEValueProtocolIEContainerList")
		}
		if _, err := aper.CaptureFinalBits(bb, "S1SetupResponseIEValueProtocolIEContainerList"); err != nil {
			return nil, runtime.WrapDecodePath(err, "S1SetupResponseIEValueProtocolIEContainerList")
		}
		return fields, nil
	}, encode: func(value S1SetupResponseIEValueProtocolIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return codec.encode(S1SetupResponseIEContainer(value), fresh, budget)
	}, capture: func(v S1SetupResponseIEValueProtocolIEContainerList, options aper.DecodeState) (S1SetupResponseIEValueProtocolIEContainerList, aper.Snapshot,
	) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeS1SetupResponseIEValueCaptureS1APProtocolIEContainerList(&v, &s)
		var root aper.Snapshot
		s.
			End(f, &root, false)
		return v, root
	}, compare: func(v S1SetupResponseIEValueProtocolIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
	) {
		s := aper.NewSemanticComparison(root, budget)
		f :=
			s.Begin()
		BridgeS1SetupResponseIEValueCompareS1APProtocolIEContainerList(&v, &s)
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

// eNBConfigurationUpdateIEValueProtocolOpenValue is the concrete protocolOpenValue[ENBConfigurationUpdateIEValue].
type ENBConfigurationUpdateIEValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) ENBConfigurationUpdateIEValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (ENBConfigurationUpdateIEValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

func BridgeENBConfigurationUpdateIEValueCaptureS1APProtocolIEField(v *ENBConfigurationUpdateIEField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolIEID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.Value = v.Value.captureSemantics(*s)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeENBConfigurationUpdateIEValueCompareS1APProtocolIEField(v *ENBConfigurationUpdateIEField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s02.BridgeCompareS1APProtocolIEID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = v.Value.compareSemantics(*s)
	s.End(f, v.replay, v.withoutReplay)
}

// mMEConfigurationUpdateIEValueProtocolOpenValue is the concrete protocolOpenValue[MMEConfigurationUpdateIEValue].
type MMEConfigurationUpdateIEValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) s43.MMEConfigurationUpdateIEValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (s43.MMEConfigurationUpdateIEValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

func BridgeMMEConfigurationUpdateIEValueCaptureS1APProtocolIEField(v *s43.MMEConfigurationUpdateIEField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolIEID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.Value = s43.BridgeMMEConfigurationUpdateIEValueMethodCaptureSemantics(v.Value, *s)
	s.End(f, s43.BridgeMMEConfigurationUpdateIEFieldFieldReplay(v), *s43.BridgeMMEConfigurationUpdateIEFieldFieldWithoutReplay(v))
}
func BridgeMMEConfigurationUpdateIEValueCompareS1APProtocolIEField(v *s43.MMEConfigurationUpdateIEField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s02.BridgeCompareS1APProtocolIEID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s43.BridgeMMEConfigurationUpdateIEValueMethodCompareSemantics(v.Value, *s)
	s.End(f, *s43.BridgeMMEConfigurationUpdateIEFieldFieldReplay(v), *s43.BridgeMMEConfigurationUpdateIEFieldFieldWithoutReplay(v))
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

// s1SetupRequestIEValueProtocolOpenValue is the concrete protocolOpenValue[S1SetupRequestIEValue].
type S1SetupRequestIEValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) S1SetupRequestIEValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (S1SetupRequestIEValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

func BridgeS1SetupRequestIEValueCaptureS1APProtocolIEField(v *S1SetupRequestIEField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolIEID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.Value = v.Value.captureSemantics(*s)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeS1SetupRequestIEValueCompareS1APProtocolIEField(v *S1SetupRequestIEField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s02.BridgeCompareS1APProtocolIEID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = v.Value.compareSemantics(*s)
	s.End(f, v.replay, v.withoutReplay)
}

// s1SetupResponseIEValueProtocolOpenValue is the concrete protocolOpenValue[S1SetupResponseIEValue].
type S1SetupResponseIEValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) S1SetupResponseIEValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (S1SetupResponseIEValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

func BridgeS1SetupResponseIEValueCaptureS1APProtocolIEField(v *S1SetupResponseIEField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolIEID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.Value = v.Value.captureSemantics(*s)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeS1SetupResponseIEValueCompareS1APProtocolIEField(v *S1SetupResponseIEField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s02.BridgeCompareS1APProtocolIEID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = v.Value.compareSemantics(*s)
	s.End(f, v.replay, v.withoutReplay)
}

// ENBConfigurationUpdateAPERValue is the concrete APERValue[ENBConfigurationUpdate].
type ENBConfigurationUpdateAPERValue struct {
	context s00.BridgeCodecContext
	Value   ENBConfigurationUpdate

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ENBConfigurationUpdateAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ENBConfigurationUpdateAPERValue) WithoutReplay() ENBConfigurationUpdateAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// MMEConfigurationUpdateAPERValue is the concrete APERValue[MMEConfigurationUpdate].
type MMEConfigurationUpdateAPERValue struct {
	context s00.BridgeCodecContext
	Value   MMEConfigurationUpdate

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v MMEConfigurationUpdateAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v MMEConfigurationUpdateAPERValue) WithoutReplay() MMEConfigurationUpdateAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
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

// S1SetupResponseAPERValue is the concrete APERValue[S1SetupResponse].
type S1SetupResponseAPERValue struct {
	context s00.BridgeCodecContext
	Value   S1SetupResponse

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v S1SetupResponseAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v S1SetupResponseAPERValue) WithoutReplay() S1SetupResponseAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ENBConfigurationUpdateIEValueERABIEContainerListValueCodec is the concrete ValueCodec[ENBConfigurationUpdateIEValueERABIEContainerList].
type ENBConfigurationUpdateIEValueERABIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ENBConfigurationUpdateIEValueERABIEContainerList, error)
	encode  func(ENBConfigurationUpdateIEValueERABIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ENBConfigurationUpdateIEValueERABIEContainerList, aper.DecodeState) (ENBConfigurationUpdateIEValueERABIEContainerList, aper.Snapshot)
	compare func(ENBConfigurationUpdateIEValueERABIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ENBConfigurationUpdateIEValueERABIEContainerListValueCodec) New(value ENBConfigurationUpdateIEValueERABIEContainerList) (ENBConfigurationUpdateIEValueERABIEContainerListAPERValue, error) {
	if c.encode == nil {
		return ENBConfigurationUpdateIEValueERABIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ENBConfigurationUpdateIEValueERABIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ENBConfigurationUpdateIEValueERABIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ENBConfigurationUpdateIEValueERABIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ENBConfigurationUpdateIEValueERABIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ENBConfigurationUpdateIEValueERABIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ENBConfigurationUpdateIEValueERABIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ENBConfigurationUpdateIEValueERABIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ENBConfigurationUpdateIEValueERABIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ENBConfigurationUpdateIEValueERABIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ENBConfigurationUpdateIEValueERABIEContainerListValueCodec) EncodeAPER(value ENBConfigurationUpdateIEValueERABIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c ENBConfigurationUpdateIEValueERABIEContainerListValueCodec) encodeBudgetValue(value ENBConfigurationUpdateIEValueERABIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ENBConfigurationUpdateIEValueERABIEContainerListValueCodec) encodeChanged(value ENBConfigurationUpdateIEValueERABIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ENBConfigurationUpdateIEValueERABIEContainerList is E-RAB-IE-ContainerList {{ENBConfigurationUpdateIEs}} of TS 36.413: a list of information element fields.
type ENBConfigurationUpdateIEValueERABIEContainerList []ENBConfigurationUpdateIEValueProtocolIESingleContainer

func BridgeENBConfigurationUpdateIEValueCaptureS1APERABIEContainerList(v *ENBConfigurationUpdateIEValueERABIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeENBConfigurationUpdateIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeENBConfigurationUpdateIEValueCompareS1APERABIEContainerList(v *ENBConfigurationUpdateIEValueERABIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeENBConfigurationUpdateIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}

// MMEConfigurationUpdateIEValueERABIEContainerListValueCodec is the concrete ValueCodec[MMEConfigurationUpdateIEValueERABIEContainerList].
type MMEConfigurationUpdateIEValueERABIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (MMEConfigurationUpdateIEValueERABIEContainerList, error)
	encode  func(MMEConfigurationUpdateIEValueERABIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(MMEConfigurationUpdateIEValueERABIEContainerList, aper.DecodeState) (MMEConfigurationUpdateIEValueERABIEContainerList, aper.Snapshot)
	compare func(MMEConfigurationUpdateIEValueERABIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c MMEConfigurationUpdateIEValueERABIEContainerListValueCodec) New(value MMEConfigurationUpdateIEValueERABIEContainerList) (MMEConfigurationUpdateIEValueERABIEContainerListAPERValue, error) {
	if c.encode == nil {
		return MMEConfigurationUpdateIEValueERABIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return MMEConfigurationUpdateIEValueERABIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return MMEConfigurationUpdateIEValueERABIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return MMEConfigurationUpdateIEValueERABIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c MMEConfigurationUpdateIEValueERABIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (MMEConfigurationUpdateIEValueERABIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return MMEConfigurationUpdateIEValueERABIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return MMEConfigurationUpdateIEValueERABIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return MMEConfigurationUpdateIEValueERABIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return MMEConfigurationUpdateIEValueERABIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c MMEConfigurationUpdateIEValueERABIEContainerListValueCodec) EncodeAPER(value MMEConfigurationUpdateIEValueERABIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c MMEConfigurationUpdateIEValueERABIEContainerListValueCodec) encodeBudgetValue(value MMEConfigurationUpdateIEValueERABIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c MMEConfigurationUpdateIEValueERABIEContainerListValueCodec) encodeChanged(value MMEConfigurationUpdateIEValueERABIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// MMEConfigurationUpdateIEValueERABIEContainerList is E-RAB-IE-ContainerList {{MMEConfigurationUpdateIEs}} of TS 36.413: a list of information element fields.
type MMEConfigurationUpdateIEValueERABIEContainerList []MMEConfigurationUpdateIEValueProtocolIESingleContainer

func BridgeMMEConfigurationUpdateIEValueCaptureS1APERABIEContainerList(v *MMEConfigurationUpdateIEValueERABIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeMMEConfigurationUpdateIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeMMEConfigurationUpdateIEValueCompareS1APERABIEContainerList(v *MMEConfigurationUpdateIEValueERABIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeMMEConfigurationUpdateIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}

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

// S1SetupRequestIEValueERABIEContainerListValueCodec is the concrete ValueCodec[S1SetupRequestIEValueERABIEContainerList].
type S1SetupRequestIEValueERABIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (S1SetupRequestIEValueERABIEContainerList, error)
	encode  func(S1SetupRequestIEValueERABIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(S1SetupRequestIEValueERABIEContainerList, aper.DecodeState) (S1SetupRequestIEValueERABIEContainerList, aper.Snapshot)
	compare func(S1SetupRequestIEValueERABIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c S1SetupRequestIEValueERABIEContainerListValueCodec) New(value S1SetupRequestIEValueERABIEContainerList) (S1SetupRequestIEValueERABIEContainerListAPERValue, error) {
	if c.encode == nil {
		return S1SetupRequestIEValueERABIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return S1SetupRequestIEValueERABIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return S1SetupRequestIEValueERABIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return S1SetupRequestIEValueERABIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c S1SetupRequestIEValueERABIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (S1SetupRequestIEValueERABIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return S1SetupRequestIEValueERABIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return S1SetupRequestIEValueERABIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return S1SetupRequestIEValueERABIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return S1SetupRequestIEValueERABIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c S1SetupRequestIEValueERABIEContainerListValueCodec) EncodeAPER(value S1SetupRequestIEValueERABIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c S1SetupRequestIEValueERABIEContainerListValueCodec) encodeBudgetValue(value S1SetupRequestIEValueERABIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c S1SetupRequestIEValueERABIEContainerListValueCodec) encodeChanged(value S1SetupRequestIEValueERABIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// S1SetupRequestIEValueERABIEContainerList is E-RAB-IE-ContainerList {{S1SetupRequestIEs}} of TS 36.413: a list of information element fields.
type S1SetupRequestIEValueERABIEContainerList []S1SetupRequestIEValueProtocolIESingleContainer

func BridgeS1SetupRequestIEValueCaptureS1APERABIEContainerList(v *S1SetupRequestIEValueERABIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeS1SetupRequestIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeS1SetupRequestIEValueCompareS1APERABIEContainerList(v *S1SetupRequestIEValueERABIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
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

// S1SetupResponseIEValueERABIEContainerListValueCodec is the concrete ValueCodec[S1SetupResponseIEValueERABIEContainerList].
type S1SetupResponseIEValueERABIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (S1SetupResponseIEValueERABIEContainerList, error)
	encode  func(S1SetupResponseIEValueERABIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(S1SetupResponseIEValueERABIEContainerList, aper.DecodeState) (S1SetupResponseIEValueERABIEContainerList, aper.Snapshot)
	compare func(S1SetupResponseIEValueERABIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c S1SetupResponseIEValueERABIEContainerListValueCodec) New(value S1SetupResponseIEValueERABIEContainerList) (S1SetupResponseIEValueERABIEContainerListAPERValue, error) {
	if c.encode == nil {
		return S1SetupResponseIEValueERABIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return S1SetupResponseIEValueERABIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return S1SetupResponseIEValueERABIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return S1SetupResponseIEValueERABIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c S1SetupResponseIEValueERABIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (S1SetupResponseIEValueERABIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return S1SetupResponseIEValueERABIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return S1SetupResponseIEValueERABIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return S1SetupResponseIEValueERABIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return S1SetupResponseIEValueERABIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c S1SetupResponseIEValueERABIEContainerListValueCodec) EncodeAPER(value S1SetupResponseIEValueERABIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c S1SetupResponseIEValueERABIEContainerListValueCodec) encodeBudgetValue(value S1SetupResponseIEValueERABIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c S1SetupResponseIEValueERABIEContainerListValueCodec) encodeChanged(value S1SetupResponseIEValueERABIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// S1SetupResponseIEValueERABIEContainerList is E-RAB-IE-ContainerList {{S1SetupResponseIEs}} of TS 36.413: a list of information element fields.
type S1SetupResponseIEValueERABIEContainerList []S1SetupResponseIEValueProtocolIESingleContainer

func BridgeS1SetupResponseIEValueCaptureS1APERABIEContainerList(v *S1SetupResponseIEValueERABIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeS1SetupResponseIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeS1SetupResponseIEValueCompareS1APERABIEContainerList(v *S1SetupResponseIEValueERABIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeS1SetupResponseIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}

// ENBConfigurationUpdateIEFieldValueCodec is the concrete ValueCodec[ENBConfigurationUpdateIEField].
type ENBConfigurationUpdateIEFieldValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ENBConfigurationUpdateIEField, error)
	encode  func(ENBConfigurationUpdateIEField, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ENBConfigurationUpdateIEField, aper.DecodeState) (ENBConfigurationUpdateIEField, aper.Snapshot)
	compare func(ENBConfigurationUpdateIEField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ENBConfigurationUpdateIEFieldValueCodec) New(value ENBConfigurationUpdateIEField) (ENBConfigurationUpdateIEFieldAPERValue, error) {
	if c.encode == nil {
		return ENBConfigurationUpdateIEFieldAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ENBConfigurationUpdateIEFieldAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ENBConfigurationUpdateIEFieldAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ENBConfigurationUpdateIEFieldAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ENBConfigurationUpdateIEFieldValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ENBConfigurationUpdateIEFieldAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ENBConfigurationUpdateIEFieldAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ENBConfigurationUpdateIEFieldAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ENBConfigurationUpdateIEFieldAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ENBConfigurationUpdateIEFieldAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ENBConfigurationUpdateIEFieldValueCodec) EncodeAPER(value ENBConfigurationUpdateIEFieldAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c ENBConfigurationUpdateIEFieldValueCodec) encodeBudgetValue(value ENBConfigurationUpdateIEField, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ENBConfigurationUpdateIEFieldValueCodec) encodeChanged(value ENBConfigurationUpdateIEField, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// MMEConfigurationUpdateIEFieldValueCodec is the concrete ValueCodec[MMEConfigurationUpdateIEField].
type MMEConfigurationUpdateIEFieldValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (s43.MMEConfigurationUpdateIEField, error)
	encode  func(s43.MMEConfigurationUpdateIEField, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(s43.MMEConfigurationUpdateIEField, aper.DecodeState) (s43.MMEConfigurationUpdateIEField, aper.Snapshot)
	compare func(s43.MMEConfigurationUpdateIEField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c MMEConfigurationUpdateIEFieldValueCodec) New(value s43.MMEConfigurationUpdateIEField) (s43.MMEConfigurationUpdateIEFieldAPERValue, error) {
	if c.encode == nil {
		return s43.MMEConfigurationUpdateIEFieldAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return s43.MMEConfigurationUpdateIEFieldAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return s43.MMEConfigurationUpdateIEFieldAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return s43.MMEConfigurationUpdateIEFieldAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c MMEConfigurationUpdateIEFieldValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (s43.MMEConfigurationUpdateIEFieldAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return s43.MMEConfigurationUpdateIEFieldAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return s43.MMEConfigurationUpdateIEFieldAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return func() s43.MMEConfigurationUpdateIEFieldAPERValue {
			sealed := s43.MMEConfigurationUpdateIEFieldAPERValue{Value: value}
			*s43.BridgeMMEConfigurationUpdateIEFieldAPERValueFieldReceived(&sealed) = aper.OriginalWire(data)
			*s43.BridgeMMEConfigurationUpdateIEFieldAPERValueFieldReplay(&sealed) = replay
			*s43.BridgeMMEConfigurationUpdateIEFieldAPERValueFieldContext(&sealed) = c.context
			return sealed
		}(), report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return s43.MMEConfigurationUpdateIEFieldAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c MMEConfigurationUpdateIEFieldValueCodec) EncodeAPER(value s43.MMEConfigurationUpdateIEFieldAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := *s43.BridgeMMEConfigurationUpdateIEFieldAPERValueFieldWithoutReplay(&value) || aper.EncodeWithoutReplay(options...)
	if *s43.BridgeMMEConfigurationUpdateIEFieldAPERValueFieldContext(&value) == c.context && !fresh && (*s43.BridgeMMEConfigurationUpdateIEFieldAPERValueFieldReplay(&value)).Present() {
		plan, next := c.compare(value.Value, *s43.BridgeMMEConfigurationUpdateIEFieldAPERValueFieldReplay(&value), budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(*s43.BridgeMMEConfigurationUpdateIEFieldAPERValueFieldReplay(&value)) {
			out, err := aper.CopyReplay(*s43.BridgeMMEConfigurationUpdateIEFieldAPERValueFieldReceived(&value), &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c MMEConfigurationUpdateIEFieldValueCodec) encodeBudgetValue(value s43.MMEConfigurationUpdateIEField, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c MMEConfigurationUpdateIEFieldValueCodec) encodeChanged(value s43.MMEConfigurationUpdateIEField, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
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

// S1SetupRequestIEFieldValueCodec is the concrete ValueCodec[S1SetupRequestIEField].
type S1SetupRequestIEFieldValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (S1SetupRequestIEField, error)
	encode  func(S1SetupRequestIEField, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(S1SetupRequestIEField, aper.DecodeState) (S1SetupRequestIEField, aper.Snapshot)
	compare func(S1SetupRequestIEField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c S1SetupRequestIEFieldValueCodec) New(value S1SetupRequestIEField) (S1SetupRequestIEFieldAPERValue, error) {
	if c.encode == nil {
		return S1SetupRequestIEFieldAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return S1SetupRequestIEFieldAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return S1SetupRequestIEFieldAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return S1SetupRequestIEFieldAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c S1SetupRequestIEFieldValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (S1SetupRequestIEFieldAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return S1SetupRequestIEFieldAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return S1SetupRequestIEFieldAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return S1SetupRequestIEFieldAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return S1SetupRequestIEFieldAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c S1SetupRequestIEFieldValueCodec) EncodeAPER(value S1SetupRequestIEFieldAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c S1SetupRequestIEFieldValueCodec) encodeBudgetValue(value S1SetupRequestIEField, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c S1SetupRequestIEFieldValueCodec) encodeChanged(value S1SetupRequestIEField, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// S1SetupResponseIEFieldValueCodec is the concrete ValueCodec[S1SetupResponseIEField].
type S1SetupResponseIEFieldValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (S1SetupResponseIEField, error)
	encode  func(S1SetupResponseIEField, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(S1SetupResponseIEField, aper.DecodeState) (S1SetupResponseIEField, aper.Snapshot)
	compare func(S1SetupResponseIEField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c S1SetupResponseIEFieldValueCodec) New(value S1SetupResponseIEField) (S1SetupResponseIEFieldAPERValue, error) {
	if c.encode == nil {
		return S1SetupResponseIEFieldAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return S1SetupResponseIEFieldAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return S1SetupResponseIEFieldAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return S1SetupResponseIEFieldAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c S1SetupResponseIEFieldValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (S1SetupResponseIEFieldAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return S1SetupResponseIEFieldAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return S1SetupResponseIEFieldAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return S1SetupResponseIEFieldAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return S1SetupResponseIEFieldAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c S1SetupResponseIEFieldValueCodec) EncodeAPER(value S1SetupResponseIEFieldAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c S1SetupResponseIEFieldValueCodec) encodeBudgetValue(value S1SetupResponseIEField, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c S1SetupResponseIEFieldValueCodec) encodeChanged(value S1SetupResponseIEField, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ENBConfigurationUpdateIEContainerValueCodec is the concrete ValueCodec[ENBConfigurationUpdateIEContainer].
type ENBConfigurationUpdateIEContainerValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ENBConfigurationUpdateIEContainer, error)
	encode  func(ENBConfigurationUpdateIEContainer, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ENBConfigurationUpdateIEContainer, aper.DecodeState) (ENBConfigurationUpdateIEContainer, aper.Snapshot)
	compare func(ENBConfigurationUpdateIEContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ENBConfigurationUpdateIEContainerValueCodec) New(value ENBConfigurationUpdateIEContainer) (ENBConfigurationUpdateIEContainerAPERValue, error) {
	if c.encode == nil {
		return ENBConfigurationUpdateIEContainerAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ENBConfigurationUpdateIEContainerAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ENBConfigurationUpdateIEContainerAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ENBConfigurationUpdateIEContainerAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ENBConfigurationUpdateIEContainerValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ENBConfigurationUpdateIEContainerAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ENBConfigurationUpdateIEContainerAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ENBConfigurationUpdateIEContainerAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ENBConfigurationUpdateIEContainerAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ENBConfigurationUpdateIEContainerAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ENBConfigurationUpdateIEContainerValueCodec) EncodeAPER(value ENBConfigurationUpdateIEContainerAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c ENBConfigurationUpdateIEContainerValueCodec) encodeBudgetValue(value ENBConfigurationUpdateIEContainer, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ENBConfigurationUpdateIEContainerValueCodec) encodeChanged(value ENBConfigurationUpdateIEContainer, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
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

// S1SetupRequestIEContainerValueCodec is the concrete ValueCodec[S1SetupRequestIEContainer].
type S1SetupRequestIEContainerValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (S1SetupRequestIEContainer, error)
	encode  func(S1SetupRequestIEContainer, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(S1SetupRequestIEContainer, aper.DecodeState) (S1SetupRequestIEContainer, aper.Snapshot)
	compare func(S1SetupRequestIEContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c S1SetupRequestIEContainerValueCodec) New(value S1SetupRequestIEContainer) (S1SetupRequestIEContainerAPERValue, error) {
	if c.encode == nil {
		return S1SetupRequestIEContainerAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return S1SetupRequestIEContainerAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return S1SetupRequestIEContainerAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return S1SetupRequestIEContainerAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c S1SetupRequestIEContainerValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (S1SetupRequestIEContainerAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return S1SetupRequestIEContainerAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return S1SetupRequestIEContainerAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return S1SetupRequestIEContainerAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return S1SetupRequestIEContainerAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c S1SetupRequestIEContainerValueCodec) EncodeAPER(value S1SetupRequestIEContainerAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c S1SetupRequestIEContainerValueCodec) encodeBudgetValue(value S1SetupRequestIEContainer, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c S1SetupRequestIEContainerValueCodec) encodeChanged(value S1SetupRequestIEContainer, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// S1SetupResponseIEContainerValueCodec is the concrete ValueCodec[S1SetupResponseIEContainer].
type S1SetupResponseIEContainerValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (S1SetupResponseIEContainer, error)
	encode  func(S1SetupResponseIEContainer, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(S1SetupResponseIEContainer, aper.DecodeState) (S1SetupResponseIEContainer, aper.Snapshot)
	compare func(S1SetupResponseIEContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c S1SetupResponseIEContainerValueCodec) New(value S1SetupResponseIEContainer) (S1SetupResponseIEContainerAPERValue, error) {
	if c.encode == nil {
		return S1SetupResponseIEContainerAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return S1SetupResponseIEContainerAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return S1SetupResponseIEContainerAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return S1SetupResponseIEContainerAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c S1SetupResponseIEContainerValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (S1SetupResponseIEContainerAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return S1SetupResponseIEContainerAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return S1SetupResponseIEContainerAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return S1SetupResponseIEContainerAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return S1SetupResponseIEContainerAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c S1SetupResponseIEContainerValueCodec) EncodeAPER(value S1SetupResponseIEContainerAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c S1SetupResponseIEContainerValueCodec) encodeBudgetValue(value S1SetupResponseIEContainer, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c S1SetupResponseIEContainerValueCodec) encodeChanged(value S1SetupResponseIEContainer, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ENBConfigurationUpdateIEValueProtocolErrorIEContainerListValueCodec is the concrete ValueCodec[ENBConfigurationUpdateIEValueProtocolErrorIEContainerList].
type ENBConfigurationUpdateIEValueProtocolErrorIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ENBConfigurationUpdateIEValueProtocolErrorIEContainerList, error)
	encode  func(ENBConfigurationUpdateIEValueProtocolErrorIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ENBConfigurationUpdateIEValueProtocolErrorIEContainerList, aper.DecodeState) (ENBConfigurationUpdateIEValueProtocolErrorIEContainerList, aper.Snapshot)
	compare func(ENBConfigurationUpdateIEValueProtocolErrorIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ENBConfigurationUpdateIEValueProtocolErrorIEContainerListValueCodec) New(value ENBConfigurationUpdateIEValueProtocolErrorIEContainerList) (ENBConfigurationUpdateIEValueProtocolErrorIEContainerListAPERValue, error) {
	if c.encode == nil {
		return ENBConfigurationUpdateIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ENBConfigurationUpdateIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ENBConfigurationUpdateIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ENBConfigurationUpdateIEValueProtocolErrorIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ENBConfigurationUpdateIEValueProtocolErrorIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ENBConfigurationUpdateIEValueProtocolErrorIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ENBConfigurationUpdateIEValueProtocolErrorIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ENBConfigurationUpdateIEValueProtocolErrorIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ENBConfigurationUpdateIEValueProtocolErrorIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ENBConfigurationUpdateIEValueProtocolErrorIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ENBConfigurationUpdateIEValueProtocolErrorIEContainerListValueCodec) EncodeAPER(value ENBConfigurationUpdateIEValueProtocolErrorIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c ENBConfigurationUpdateIEValueProtocolErrorIEContainerListValueCodec) encodeBudgetValue(value ENBConfigurationUpdateIEValueProtocolErrorIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ENBConfigurationUpdateIEValueProtocolErrorIEContainerListValueCodec) encodeChanged(value ENBConfigurationUpdateIEValueProtocolErrorIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ENBConfigurationUpdateIEValueProtocolErrorIEContainerList is ProtocolError-IE-ContainerList {{ENBConfigurationUpdateIEs}} of TS 36.413: a list of information element fields.
type ENBConfigurationUpdateIEValueProtocolErrorIEContainerList []ENBConfigurationUpdateIEValueProtocolIESingleContainer

func BridgeENBConfigurationUpdateIEValueCaptureS1APProtocolErrorIEContainerList(v *ENBConfigurationUpdateIEValueProtocolErrorIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeENBConfigurationUpdateIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeENBConfigurationUpdateIEValueCompareS1APProtocolErrorIEContainerList(v *ENBConfigurationUpdateIEValueProtocolErrorIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeENBConfigurationUpdateIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}

// MMEConfigurationUpdateIEValueProtocolErrorIEContainerListValueCodec is the concrete ValueCodec[MMEConfigurationUpdateIEValueProtocolErrorIEContainerList].
type MMEConfigurationUpdateIEValueProtocolErrorIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (MMEConfigurationUpdateIEValueProtocolErrorIEContainerList, error)
	encode  func(MMEConfigurationUpdateIEValueProtocolErrorIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(MMEConfigurationUpdateIEValueProtocolErrorIEContainerList, aper.DecodeState) (MMEConfigurationUpdateIEValueProtocolErrorIEContainerList, aper.Snapshot)
	compare func(MMEConfigurationUpdateIEValueProtocolErrorIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c MMEConfigurationUpdateIEValueProtocolErrorIEContainerListValueCodec) New(value MMEConfigurationUpdateIEValueProtocolErrorIEContainerList) (MMEConfigurationUpdateIEValueProtocolErrorIEContainerListAPERValue, error) {
	if c.encode == nil {
		return MMEConfigurationUpdateIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return MMEConfigurationUpdateIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return MMEConfigurationUpdateIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return MMEConfigurationUpdateIEValueProtocolErrorIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c MMEConfigurationUpdateIEValueProtocolErrorIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (MMEConfigurationUpdateIEValueProtocolErrorIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return MMEConfigurationUpdateIEValueProtocolErrorIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return MMEConfigurationUpdateIEValueProtocolErrorIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return MMEConfigurationUpdateIEValueProtocolErrorIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return MMEConfigurationUpdateIEValueProtocolErrorIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c MMEConfigurationUpdateIEValueProtocolErrorIEContainerListValueCodec) EncodeAPER(value MMEConfigurationUpdateIEValueProtocolErrorIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c MMEConfigurationUpdateIEValueProtocolErrorIEContainerListValueCodec) encodeBudgetValue(value MMEConfigurationUpdateIEValueProtocolErrorIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c MMEConfigurationUpdateIEValueProtocolErrorIEContainerListValueCodec) encodeChanged(value MMEConfigurationUpdateIEValueProtocolErrorIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// MMEConfigurationUpdateIEValueProtocolErrorIEContainerList is ProtocolError-IE-ContainerList {{MMEConfigurationUpdateIEs}} of TS 36.413: a list of information element fields.
type MMEConfigurationUpdateIEValueProtocolErrorIEContainerList []MMEConfigurationUpdateIEValueProtocolIESingleContainer

func BridgeMMEConfigurationUpdateIEValueCaptureS1APProtocolErrorIEContainerList(v *MMEConfigurationUpdateIEValueProtocolErrorIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeMMEConfigurationUpdateIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeMMEConfigurationUpdateIEValueCompareS1APProtocolErrorIEContainerList(v *MMEConfigurationUpdateIEValueProtocolErrorIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeMMEConfigurationUpdateIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}

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

// S1SetupRequestIEValueProtocolErrorIEContainerListValueCodec is the concrete ValueCodec[S1SetupRequestIEValueProtocolErrorIEContainerList].
type S1SetupRequestIEValueProtocolErrorIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (S1SetupRequestIEValueProtocolErrorIEContainerList, error)
	encode  func(S1SetupRequestIEValueProtocolErrorIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(S1SetupRequestIEValueProtocolErrorIEContainerList, aper.DecodeState) (S1SetupRequestIEValueProtocolErrorIEContainerList, aper.Snapshot)
	compare func(S1SetupRequestIEValueProtocolErrorIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c S1SetupRequestIEValueProtocolErrorIEContainerListValueCodec) New(value S1SetupRequestIEValueProtocolErrorIEContainerList) (S1SetupRequestIEValueProtocolErrorIEContainerListAPERValue, error) {
	if c.encode == nil {
		return S1SetupRequestIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return S1SetupRequestIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return S1SetupRequestIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return S1SetupRequestIEValueProtocolErrorIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c S1SetupRequestIEValueProtocolErrorIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (S1SetupRequestIEValueProtocolErrorIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return S1SetupRequestIEValueProtocolErrorIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return S1SetupRequestIEValueProtocolErrorIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return S1SetupRequestIEValueProtocolErrorIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return S1SetupRequestIEValueProtocolErrorIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c S1SetupRequestIEValueProtocolErrorIEContainerListValueCodec) EncodeAPER(value S1SetupRequestIEValueProtocolErrorIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c S1SetupRequestIEValueProtocolErrorIEContainerListValueCodec) encodeBudgetValue(value S1SetupRequestIEValueProtocolErrorIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c S1SetupRequestIEValueProtocolErrorIEContainerListValueCodec) encodeChanged(value S1SetupRequestIEValueProtocolErrorIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// S1SetupRequestIEValueProtocolErrorIEContainerList is ProtocolError-IE-ContainerList {{S1SetupRequestIEs}} of TS 36.413: a list of information element fields.
type S1SetupRequestIEValueProtocolErrorIEContainerList []S1SetupRequestIEValueProtocolIESingleContainer

func BridgeS1SetupRequestIEValueCaptureS1APProtocolErrorIEContainerList(v *S1SetupRequestIEValueProtocolErrorIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeS1SetupRequestIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeS1SetupRequestIEValueCompareS1APProtocolErrorIEContainerList(v *S1SetupRequestIEValueProtocolErrorIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
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

// S1SetupResponseIEValueProtocolErrorIEContainerListValueCodec is the concrete ValueCodec[S1SetupResponseIEValueProtocolErrorIEContainerList].
type S1SetupResponseIEValueProtocolErrorIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (S1SetupResponseIEValueProtocolErrorIEContainerList, error)
	encode  func(S1SetupResponseIEValueProtocolErrorIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(S1SetupResponseIEValueProtocolErrorIEContainerList, aper.DecodeState) (S1SetupResponseIEValueProtocolErrorIEContainerList, aper.Snapshot)
	compare func(S1SetupResponseIEValueProtocolErrorIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c S1SetupResponseIEValueProtocolErrorIEContainerListValueCodec) New(value S1SetupResponseIEValueProtocolErrorIEContainerList) (S1SetupResponseIEValueProtocolErrorIEContainerListAPERValue, error) {
	if c.encode == nil {
		return S1SetupResponseIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return S1SetupResponseIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return S1SetupResponseIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return S1SetupResponseIEValueProtocolErrorIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c S1SetupResponseIEValueProtocolErrorIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (S1SetupResponseIEValueProtocolErrorIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return S1SetupResponseIEValueProtocolErrorIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return S1SetupResponseIEValueProtocolErrorIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return S1SetupResponseIEValueProtocolErrorIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return S1SetupResponseIEValueProtocolErrorIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c S1SetupResponseIEValueProtocolErrorIEContainerListValueCodec) EncodeAPER(value S1SetupResponseIEValueProtocolErrorIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c S1SetupResponseIEValueProtocolErrorIEContainerListValueCodec) encodeBudgetValue(value S1SetupResponseIEValueProtocolErrorIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c S1SetupResponseIEValueProtocolErrorIEContainerListValueCodec) encodeChanged(value S1SetupResponseIEValueProtocolErrorIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// S1SetupResponseIEValueProtocolErrorIEContainerList is ProtocolError-IE-ContainerList {{S1SetupResponseIEs}} of TS 36.413: a list of information element fields.
type S1SetupResponseIEValueProtocolErrorIEContainerList []S1SetupResponseIEValueProtocolIESingleContainer

func BridgeS1SetupResponseIEValueCaptureS1APProtocolErrorIEContainerList(v *S1SetupResponseIEValueProtocolErrorIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeS1SetupResponseIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeS1SetupResponseIEValueCompareS1APProtocolErrorIEContainerList(v *S1SetupResponseIEValueProtocolErrorIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeS1SetupResponseIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}

// ENBConfigurationUpdateIEValueProtocolIEContainerListValueCodec is the concrete ValueCodec[ENBConfigurationUpdateIEValueProtocolIEContainerList].
type ENBConfigurationUpdateIEValueProtocolIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ENBConfigurationUpdateIEValueProtocolIEContainerList, error)
	encode  func(ENBConfigurationUpdateIEValueProtocolIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ENBConfigurationUpdateIEValueProtocolIEContainerList, aper.DecodeState) (ENBConfigurationUpdateIEValueProtocolIEContainerList, aper.Snapshot)
	compare func(ENBConfigurationUpdateIEValueProtocolIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ENBConfigurationUpdateIEValueProtocolIEContainerListValueCodec) New(value ENBConfigurationUpdateIEValueProtocolIEContainerList) (ENBConfigurationUpdateIEValueProtocolIEContainerListAPERValue, error) {
	if c.encode == nil {
		return ENBConfigurationUpdateIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ENBConfigurationUpdateIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ENBConfigurationUpdateIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ENBConfigurationUpdateIEValueProtocolIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ENBConfigurationUpdateIEValueProtocolIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ENBConfigurationUpdateIEValueProtocolIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ENBConfigurationUpdateIEValueProtocolIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ENBConfigurationUpdateIEValueProtocolIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ENBConfigurationUpdateIEValueProtocolIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ENBConfigurationUpdateIEValueProtocolIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ENBConfigurationUpdateIEValueProtocolIEContainerListValueCodec) EncodeAPER(value ENBConfigurationUpdateIEValueProtocolIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c ENBConfigurationUpdateIEValueProtocolIEContainerListValueCodec) encodeBudgetValue(value ENBConfigurationUpdateIEValueProtocolIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ENBConfigurationUpdateIEValueProtocolIEContainerListValueCodec) encodeChanged(value ENBConfigurationUpdateIEValueProtocolIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ENBConfigurationUpdateIEValueProtocolIEContainerList is ProtocolIE-ContainerList with IEsSetParam = {ENBConfigurationUpdateIEs} of TS 36.413: a list of information element fields with lowerBound and upperBound supplied by its concrete factory.
type ENBConfigurationUpdateIEValueProtocolIEContainerList []ENBConfigurationUpdateIEValueProtocolIESingleContainer

func BridgeENBConfigurationUpdateIEValueCaptureS1APProtocolIEContainerList(v *ENBConfigurationUpdateIEValueProtocolIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeENBConfigurationUpdateIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeENBConfigurationUpdateIEValueCompareS1APProtocolIEContainerList(v *ENBConfigurationUpdateIEValueProtocolIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeENBConfigurationUpdateIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}

// MMEConfigurationUpdateIEValueProtocolIEContainerListValueCodec is the concrete ValueCodec[MMEConfigurationUpdateIEValueProtocolIEContainerList].
type MMEConfigurationUpdateIEValueProtocolIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (MMEConfigurationUpdateIEValueProtocolIEContainerList, error)
	encode  func(MMEConfigurationUpdateIEValueProtocolIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(MMEConfigurationUpdateIEValueProtocolIEContainerList, aper.DecodeState) (MMEConfigurationUpdateIEValueProtocolIEContainerList, aper.Snapshot)
	compare func(MMEConfigurationUpdateIEValueProtocolIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c MMEConfigurationUpdateIEValueProtocolIEContainerListValueCodec) New(value MMEConfigurationUpdateIEValueProtocolIEContainerList) (MMEConfigurationUpdateIEValueProtocolIEContainerListAPERValue, error) {
	if c.encode == nil {
		return MMEConfigurationUpdateIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return MMEConfigurationUpdateIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return MMEConfigurationUpdateIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return MMEConfigurationUpdateIEValueProtocolIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c MMEConfigurationUpdateIEValueProtocolIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (MMEConfigurationUpdateIEValueProtocolIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return MMEConfigurationUpdateIEValueProtocolIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return MMEConfigurationUpdateIEValueProtocolIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return MMEConfigurationUpdateIEValueProtocolIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return MMEConfigurationUpdateIEValueProtocolIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c MMEConfigurationUpdateIEValueProtocolIEContainerListValueCodec) EncodeAPER(value MMEConfigurationUpdateIEValueProtocolIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c MMEConfigurationUpdateIEValueProtocolIEContainerListValueCodec) encodeBudgetValue(value MMEConfigurationUpdateIEValueProtocolIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c MMEConfigurationUpdateIEValueProtocolIEContainerListValueCodec) encodeChanged(value MMEConfigurationUpdateIEValueProtocolIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// MMEConfigurationUpdateIEValueProtocolIEContainerList is ProtocolIE-ContainerList with IEsSetParam = {MMEConfigurationUpdateIEs} of TS 36.413: a list of information element fields with lowerBound and upperBound supplied by its concrete factory.
type MMEConfigurationUpdateIEValueProtocolIEContainerList []MMEConfigurationUpdateIEValueProtocolIESingleContainer

func BridgeMMEConfigurationUpdateIEValueCaptureS1APProtocolIEContainerList(v *MMEConfigurationUpdateIEValueProtocolIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeMMEConfigurationUpdateIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeMMEConfigurationUpdateIEValueCompareS1APProtocolIEContainerList(v *MMEConfigurationUpdateIEValueProtocolIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeMMEConfigurationUpdateIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}

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

// S1SetupRequestIEValueProtocolIEContainerListValueCodec is the concrete ValueCodec[S1SetupRequestIEValueProtocolIEContainerList].
type S1SetupRequestIEValueProtocolIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (S1SetupRequestIEValueProtocolIEContainerList, error)
	encode  func(S1SetupRequestIEValueProtocolIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(S1SetupRequestIEValueProtocolIEContainerList, aper.DecodeState) (S1SetupRequestIEValueProtocolIEContainerList, aper.Snapshot)
	compare func(S1SetupRequestIEValueProtocolIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c S1SetupRequestIEValueProtocolIEContainerListValueCodec) New(value S1SetupRequestIEValueProtocolIEContainerList) (S1SetupRequestIEValueProtocolIEContainerListAPERValue, error) {
	if c.encode == nil {
		return S1SetupRequestIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return S1SetupRequestIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return S1SetupRequestIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return S1SetupRequestIEValueProtocolIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c S1SetupRequestIEValueProtocolIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (S1SetupRequestIEValueProtocolIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return S1SetupRequestIEValueProtocolIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return S1SetupRequestIEValueProtocolIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return S1SetupRequestIEValueProtocolIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return S1SetupRequestIEValueProtocolIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c S1SetupRequestIEValueProtocolIEContainerListValueCodec) EncodeAPER(value S1SetupRequestIEValueProtocolIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c S1SetupRequestIEValueProtocolIEContainerListValueCodec) encodeBudgetValue(value S1SetupRequestIEValueProtocolIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c S1SetupRequestIEValueProtocolIEContainerListValueCodec) encodeChanged(value S1SetupRequestIEValueProtocolIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// S1SetupRequestIEValueProtocolIEContainerList is ProtocolIE-ContainerList with IEsSetParam = {S1SetupRequestIEs} of TS 36.413: a list of information element fields with lowerBound and upperBound supplied by its concrete factory.
type S1SetupRequestIEValueProtocolIEContainerList []S1SetupRequestIEValueProtocolIESingleContainer

func BridgeS1SetupRequestIEValueCaptureS1APProtocolIEContainerList(v *S1SetupRequestIEValueProtocolIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeS1SetupRequestIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeS1SetupRequestIEValueCompareS1APProtocolIEContainerList(v *S1SetupRequestIEValueProtocolIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
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

// S1SetupResponseIEValueProtocolIEContainerListValueCodec is the concrete ValueCodec[S1SetupResponseIEValueProtocolIEContainerList].
type S1SetupResponseIEValueProtocolIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (S1SetupResponseIEValueProtocolIEContainerList, error)
	encode  func(S1SetupResponseIEValueProtocolIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(S1SetupResponseIEValueProtocolIEContainerList, aper.DecodeState) (S1SetupResponseIEValueProtocolIEContainerList, aper.Snapshot)
	compare func(S1SetupResponseIEValueProtocolIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c S1SetupResponseIEValueProtocolIEContainerListValueCodec) New(value S1SetupResponseIEValueProtocolIEContainerList) (S1SetupResponseIEValueProtocolIEContainerListAPERValue, error) {
	if c.encode == nil {
		return S1SetupResponseIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return S1SetupResponseIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return S1SetupResponseIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return S1SetupResponseIEValueProtocolIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c S1SetupResponseIEValueProtocolIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (S1SetupResponseIEValueProtocolIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return S1SetupResponseIEValueProtocolIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return S1SetupResponseIEValueProtocolIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return S1SetupResponseIEValueProtocolIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return S1SetupResponseIEValueProtocolIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c S1SetupResponseIEValueProtocolIEContainerListValueCodec) EncodeAPER(value S1SetupResponseIEValueProtocolIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c S1SetupResponseIEValueProtocolIEContainerListValueCodec) encodeBudgetValue(value S1SetupResponseIEValueProtocolIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c S1SetupResponseIEValueProtocolIEContainerListValueCodec) encodeChanged(value S1SetupResponseIEValueProtocolIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// S1SetupResponseIEValueProtocolIEContainerList is ProtocolIE-ContainerList with IEsSetParam = {S1SetupResponseIEs} of TS 36.413: a list of information element fields with lowerBound and upperBound supplied by its concrete factory.
type S1SetupResponseIEValueProtocolIEContainerList []S1SetupResponseIEValueProtocolIESingleContainer

func BridgeS1SetupResponseIEValueCaptureS1APProtocolIEContainerList(v *S1SetupResponseIEValueProtocolIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeS1SetupResponseIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeS1SetupResponseIEValueCompareS1APProtocolIEContainerList(v *S1SetupResponseIEValueProtocolIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeS1SetupResponseIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}

// ENBConfigurationUpdateIEValueERABIEContainerListAPERValue is the concrete APERValue[ENBConfigurationUpdateIEValueERABIEContainerList].
type ENBConfigurationUpdateIEValueERABIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         ENBConfigurationUpdateIEValueERABIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ENBConfigurationUpdateIEValueERABIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ENBConfigurationUpdateIEValueERABIEContainerListAPERValue) WithoutReplay() ENBConfigurationUpdateIEValueERABIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ENBConfigurationUpdateIEValueProtocolIESingleContainer is ProtocolIE-SingleContainer {{ENBConfigurationUpdateIEs}} of TS 36.413: a single information element field.
type ENBConfigurationUpdateIEValueProtocolIESingleContainer = ENBConfigurationUpdateIEField

func BridgeENBConfigurationUpdateIEValueCaptureS1APProtocolIESingleContainer(v *ENBConfigurationUpdateIEValueProtocolIESingleContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeENBConfigurationUpdateIEValueCaptureS1APProtocolIEField(v, s)
	s.End(f, nil, false)
}
func BridgeENBConfigurationUpdateIEValueCompareS1APProtocolIESingleContainer(v *ENBConfigurationUpdateIEValueProtocolIESingleContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeENBConfigurationUpdateIEValueCompareS1APProtocolIEField(v, s)
	s.End(f, aper.Snapshot{}, false)
}

// MMEConfigurationUpdateIEValueERABIEContainerListAPERValue is the concrete APERValue[MMEConfigurationUpdateIEValueERABIEContainerList].
type MMEConfigurationUpdateIEValueERABIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         MMEConfigurationUpdateIEValueERABIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v MMEConfigurationUpdateIEValueERABIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v MMEConfigurationUpdateIEValueERABIEContainerListAPERValue) WithoutReplay() MMEConfigurationUpdateIEValueERABIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// MMEConfigurationUpdateIEValueProtocolIESingleContainer is ProtocolIE-SingleContainer {{MMEConfigurationUpdateIEs}} of TS 36.413: a single information element field.
type MMEConfigurationUpdateIEValueProtocolIESingleContainer = s43.MMEConfigurationUpdateIEField

func BridgeMMEConfigurationUpdateIEValueCaptureS1APProtocolIESingleContainer(v *MMEConfigurationUpdateIEValueProtocolIESingleContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeMMEConfigurationUpdateIEValueCaptureS1APProtocolIEField(v, s)
	s.End(f, nil, false)
}
func BridgeMMEConfigurationUpdateIEValueCompareS1APProtocolIESingleContainer(v *MMEConfigurationUpdateIEValueProtocolIESingleContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeMMEConfigurationUpdateIEValueCompareS1APProtocolIEField(v, s)
	s.End(f, aper.Snapshot{}, false)
}

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

// S1SetupRequestIEValueERABIEContainerListAPERValue is the concrete APERValue[S1SetupRequestIEValueERABIEContainerList].
type S1SetupRequestIEValueERABIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         S1SetupRequestIEValueERABIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v S1SetupRequestIEValueERABIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v S1SetupRequestIEValueERABIEContainerListAPERValue) WithoutReplay() S1SetupRequestIEValueERABIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// S1SetupRequestIEValueProtocolIESingleContainer is ProtocolIE-SingleContainer {{S1SetupRequestIEs}} of TS 36.413: a single information element field.
type S1SetupRequestIEValueProtocolIESingleContainer = S1SetupRequestIEField

func BridgeS1SetupRequestIEValueCaptureS1APProtocolIESingleContainer(v *S1SetupRequestIEValueProtocolIESingleContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeS1SetupRequestIEValueCaptureS1APProtocolIEField(v, s)
	s.End(f, nil, false)
}
func BridgeS1SetupRequestIEValueCompareS1APProtocolIESingleContainer(v *S1SetupRequestIEValueProtocolIESingleContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeS1SetupRequestIEValueCompareS1APProtocolIEField(v, s)
	s.End(f, aper.Snapshot{}, false)
}

// S1SetupResponseIEValueERABIEContainerListAPERValue is the concrete APERValue[S1SetupResponseIEValueERABIEContainerList].
type S1SetupResponseIEValueERABIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         S1SetupResponseIEValueERABIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v S1SetupResponseIEValueERABIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v S1SetupResponseIEValueERABIEContainerListAPERValue) WithoutReplay() S1SetupResponseIEValueERABIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// S1SetupResponseIEValueProtocolIESingleContainer is ProtocolIE-SingleContainer {{S1SetupResponseIEs}} of TS 36.413: a single information element field.
type S1SetupResponseIEValueProtocolIESingleContainer = S1SetupResponseIEField

func BridgeS1SetupResponseIEValueCaptureS1APProtocolIESingleContainer(v *S1SetupResponseIEValueProtocolIESingleContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeS1SetupResponseIEValueCaptureS1APProtocolIEField(v, s)
	s.End(f, nil, false)
}
func BridgeS1SetupResponseIEValueCompareS1APProtocolIESingleContainer(v *S1SetupResponseIEValueProtocolIESingleContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeS1SetupResponseIEValueCompareS1APProtocolIEField(v, s)
	s.End(f, aper.Snapshot{}, false)
}

// ENBConfigurationUpdateIEFieldAPERValue is the concrete APERValue[ENBConfigurationUpdateIEField].
type ENBConfigurationUpdateIEFieldAPERValue struct {
	context       s00.BridgeCodecContext
	Value         ENBConfigurationUpdateIEField
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ENBConfigurationUpdateIEFieldAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ENBConfigurationUpdateIEFieldAPERValue) WithoutReplay() ENBConfigurationUpdateIEFieldAPERValue {
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

// S1SetupRequestIEFieldAPERValue is the concrete APERValue[S1SetupRequestIEField].
type S1SetupRequestIEFieldAPERValue struct {
	context       s00.BridgeCodecContext
	Value         S1SetupRequestIEField
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v S1SetupRequestIEFieldAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v S1SetupRequestIEFieldAPERValue) WithoutReplay() S1SetupRequestIEFieldAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// S1SetupResponseIEFieldAPERValue is the concrete APERValue[S1SetupResponseIEField].
type S1SetupResponseIEFieldAPERValue struct {
	context       s00.BridgeCodecContext
	Value         S1SetupResponseIEField
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v S1SetupResponseIEFieldAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v S1SetupResponseIEFieldAPERValue) WithoutReplay() S1SetupResponseIEFieldAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ENBConfigurationUpdateIEContainerAPERValue is the concrete APERValue[ENBConfigurationUpdateIEContainer].
type ENBConfigurationUpdateIEContainerAPERValue struct {
	context       s00.BridgeCodecContext
	Value         ENBConfigurationUpdateIEContainer
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ENBConfigurationUpdateIEContainerAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ENBConfigurationUpdateIEContainerAPERValue) WithoutReplay() ENBConfigurationUpdateIEContainerAPERValue {
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

// S1SetupRequestIEContainerAPERValue is the concrete APERValue[S1SetupRequestIEContainer].
type S1SetupRequestIEContainerAPERValue struct {
	context       s00.BridgeCodecContext
	Value         S1SetupRequestIEContainer
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v S1SetupRequestIEContainerAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v S1SetupRequestIEContainerAPERValue) WithoutReplay() S1SetupRequestIEContainerAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// S1SetupResponseIEContainerAPERValue is the concrete APERValue[S1SetupResponseIEContainer].
type S1SetupResponseIEContainerAPERValue struct {
	context       s00.BridgeCodecContext
	Value         S1SetupResponseIEContainer
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v S1SetupResponseIEContainerAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v S1SetupResponseIEContainerAPERValue) WithoutReplay() S1SetupResponseIEContainerAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ENBConfigurationUpdateIEValueProtocolErrorIEContainerListAPERValue is the concrete APERValue[ENBConfigurationUpdateIEValueProtocolErrorIEContainerList].
type ENBConfigurationUpdateIEValueProtocolErrorIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         ENBConfigurationUpdateIEValueProtocolErrorIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ENBConfigurationUpdateIEValueProtocolErrorIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ENBConfigurationUpdateIEValueProtocolErrorIEContainerListAPERValue) WithoutReplay() ENBConfigurationUpdateIEValueProtocolErrorIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// MMEConfigurationUpdateIEValueProtocolErrorIEContainerListAPERValue is the concrete APERValue[MMEConfigurationUpdateIEValueProtocolErrorIEContainerList].
type MMEConfigurationUpdateIEValueProtocolErrorIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         MMEConfigurationUpdateIEValueProtocolErrorIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v MMEConfigurationUpdateIEValueProtocolErrorIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v MMEConfigurationUpdateIEValueProtocolErrorIEContainerListAPERValue) WithoutReplay() MMEConfigurationUpdateIEValueProtocolErrorIEContainerListAPERValue {
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

// S1SetupRequestIEValueProtocolErrorIEContainerListAPERValue is the concrete APERValue[S1SetupRequestIEValueProtocolErrorIEContainerList].
type S1SetupRequestIEValueProtocolErrorIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         S1SetupRequestIEValueProtocolErrorIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v S1SetupRequestIEValueProtocolErrorIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v S1SetupRequestIEValueProtocolErrorIEContainerListAPERValue) WithoutReplay() S1SetupRequestIEValueProtocolErrorIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// S1SetupResponseIEValueProtocolErrorIEContainerListAPERValue is the concrete APERValue[S1SetupResponseIEValueProtocolErrorIEContainerList].
type S1SetupResponseIEValueProtocolErrorIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         S1SetupResponseIEValueProtocolErrorIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v S1SetupResponseIEValueProtocolErrorIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v S1SetupResponseIEValueProtocolErrorIEContainerListAPERValue) WithoutReplay() S1SetupResponseIEValueProtocolErrorIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ENBConfigurationUpdateIEValueProtocolIEContainerListAPERValue is the concrete APERValue[ENBConfigurationUpdateIEValueProtocolIEContainerList].
type ENBConfigurationUpdateIEValueProtocolIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         ENBConfigurationUpdateIEValueProtocolIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ENBConfigurationUpdateIEValueProtocolIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ENBConfigurationUpdateIEValueProtocolIEContainerListAPERValue) WithoutReplay() ENBConfigurationUpdateIEValueProtocolIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// MMEConfigurationUpdateIEValueProtocolIEContainerListAPERValue is the concrete APERValue[MMEConfigurationUpdateIEValueProtocolIEContainerList].
type MMEConfigurationUpdateIEValueProtocolIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         MMEConfigurationUpdateIEValueProtocolIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v MMEConfigurationUpdateIEValueProtocolIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v MMEConfigurationUpdateIEValueProtocolIEContainerListAPERValue) WithoutReplay() MMEConfigurationUpdateIEValueProtocolIEContainerListAPERValue {
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

// S1SetupRequestIEValueProtocolIEContainerListAPERValue is the concrete APERValue[S1SetupRequestIEValueProtocolIEContainerList].
type S1SetupRequestIEValueProtocolIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         S1SetupRequestIEValueProtocolIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v S1SetupRequestIEValueProtocolIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v S1SetupRequestIEValueProtocolIEContainerListAPERValue) WithoutReplay() S1SetupRequestIEValueProtocolIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// S1SetupResponseIEValueProtocolIEContainerListAPERValue is the concrete APERValue[S1SetupResponseIEValueProtocolIEContainerList].
type S1SetupResponseIEValueProtocolIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         S1SetupResponseIEValueProtocolIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v S1SetupResponseIEValueProtocolIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v S1SetupResponseIEValueProtocolIEContainerListAPERValue) WithoutReplay() S1SetupResponseIEValueProtocolIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}
func BridgeCaptureS1APENBConfigurationUpdate(v *ENBConfigurationUpdate, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeENBConfigurationUpdateIEValueCaptureS1APProtocolIEContainer(&v.ProtocolIEs, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APENBConfigurationUpdate(v *ENBConfigurationUpdate, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeENBConfigurationUpdateIEValueCompareS1APProtocolIEContainer(&v.ProtocolIEs, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APENBConfigurationUpdateIEValue(v *ENBConfigurationUpdateIEValue, s *aper.SemanticCapture) {
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
		case s00.ProtocolIEID(60):
			{
				f := s.Begin()
				s.Bool(v.rowENBname == nil)
				if v.rowENBname != nil {
					s00.BridgeCaptureS1APENBname(v.rowENBname, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(64):
			{
				f := s.Begin()
				s.Bool(v.rowSupportedTAs == nil)
				if v.rowSupportedTAs != nil {
					s31.BridgeCaptureS1APSupportedTAs(v.rowSupportedTAs, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(128):
			{
				f := s.Begin()
				s.Bool(v.rowCSGIdList == nil)
				if v.rowCSGIdList != nil {
					s21.BridgeCaptureS1APCSGIdList(v.rowCSGIdList, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(137):
			{
				f := s.Begin()
				s.Bool(v.rowDefaultPagingDRX == nil)
				if v.rowDefaultPagingDRX != nil {
					s00.BridgeCaptureS1APPagingDRX(v.rowDefaultPagingDRX, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(234):
			{
				f := s.Begin()
				s.Bool(v.rowNBIoTDefaultPagingDRX == nil)
				if v.rowNBIoTDefaultPagingDRX != nil {
					s00.BridgeCaptureS1APNBIoTDefaultPagingDRX(v.rowNBIoTDefaultPagingDRX, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(292):
			{
				f := s.Begin()
				s.Bool(v.rowConnectedengNBToAddList == nil)
				if v.rowConnectedengNBToAddList != nil {
					s31.BridgeCaptureS1APConnectedengNBList(v.rowConnectedengNBToAddList, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(293):
			{
				f := s.Begin()
				s.Bool(v.rowConnectedengNBToRemoveList == nil)
				if v.rowConnectedengNBToRemoveList != nil {
					s31.BridgeCaptureS1APConnectedengNBList(v.rowConnectedengNBToRemoveList, s)
				}
				s.End(f, nil, false)
			}
		}
	}
	s.End(f, &v.replay, false)
	s.CheckReceived(v.replay, v.received)
}
func (v ENBConfigurationUpdateIEValue) captureSemantics(s aper.SemanticCapture) ENBConfigurationUpdateIEValue {
	BridgeCaptureS1APENBConfigurationUpdateIEValue(&v, &s)
	return v
}
func BridgeCompareS1APENBConfigurationUpdateIEValue(v *ENBConfigurationUpdateIEValue, s *aper.SemanticComparison) {
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
		case s00.ProtocolIEID(60):
			{
				f := s.Begin()
				s.Bool(v.rowENBname == nil)
				if v.rowENBname != nil {
					s02.BridgeCompareS1APENBname(v.rowENBname, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(64):
			{
				f := s.Begin()
				s.Bool(v.rowSupportedTAs == nil)
				if v.rowSupportedTAs != nil {
					s31.BridgeCompareS1APSupportedTAs(v.rowSupportedTAs, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(128):
			{
				f := s.Begin()
				s.Bool(v.rowCSGIdList == nil)
				if v.rowCSGIdList != nil {
					s22.BridgeCompareS1APCSGIdList(v.rowCSGIdList, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(137):
			{
				f := s.Begin()
				s.Bool(v.rowDefaultPagingDRX == nil)
				if v.rowDefaultPagingDRX != nil {
					s02.BridgeCompareS1APPagingDRX(v.rowDefaultPagingDRX, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(234):
			{
				f := s.Begin()
				s.Bool(v.rowNBIoTDefaultPagingDRX == nil)
				if v.rowNBIoTDefaultPagingDRX != nil {
					s02.BridgeCompareS1APNBIoTDefaultPagingDRX(v.rowNBIoTDefaultPagingDRX, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(292):
			{
				f := s.Begin()
				s.Bool(v.rowConnectedengNBToAddList == nil)
				if v.rowConnectedengNBToAddList != nil {
					s31.BridgeCompareS1APConnectedengNBList(v.rowConnectedengNBToAddList, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(293):
			{
				f := s.Begin()
				s.Bool(v.rowConnectedengNBToRemoveList == nil)
				if v.rowConnectedengNBToRemoveList != nil {
					s31.BridgeCompareS1APConnectedengNBList(v.rowConnectedengNBToRemoveList, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		}
	}
	s.End(f, v.replay, false)
	s.CheckReceived(v.replay, v.received)
}
func (v ENBConfigurationUpdateIEValue) compareSemantics(s aper.SemanticComparison) aper.SemanticComparison {
	BridgeCompareS1APENBConfigurationUpdateIEValue(&v, &s)
	return s
}
func BridgeCaptureS1APMMEConfigurationUpdate(v *MMEConfigurationUpdate, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeMMEConfigurationUpdateIEValueCaptureS1APProtocolIEContainer(&v.ProtocolIEs, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APMMEConfigurationUpdate(v *MMEConfigurationUpdate, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeMMEConfigurationUpdateIEValueCompareS1APProtocolIEContainer(&v.ProtocolIEs, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, v.replay, v.withoutReplay)
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
					s33.BridgeCompareS1APTAIListForRestart(v.rowTAIListForRestart, s)
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
func BridgeCaptureS1APS1SetupRequest(v *S1SetupRequest, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeS1SetupRequestIEValueCaptureS1APProtocolIEContainer(&v.ProtocolIEs, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APS1SetupRequest(v *S1SetupRequest, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeS1SetupRequestIEValueCompareS1APProtocolIEContainer(&v.ProtocolIEs, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APS1SetupRequestIEValue(v *S1SetupRequestIEValue, s *aper.SemanticCapture) {
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
		case s00.ProtocolIEID(59):
			{
				f := s.Begin()
				s.Bool(v.rowGlobalENBID == nil)
				if v.rowGlobalENBID != nil {
					s18.BridgeCaptureS1APGlobalENBID(v.rowGlobalENBID, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(60):
			{
				f := s.Begin()
				s.Bool(v.rowENBname == nil)
				if v.rowENBname != nil {
					s00.BridgeCaptureS1APENBname(v.rowENBname, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(64):
			{
				f := s.Begin()
				s.Bool(v.rowSupportedTAs == nil)
				if v.rowSupportedTAs != nil {
					s31.BridgeCaptureS1APSupportedTAs(v.rowSupportedTAs, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(137):
			{
				f := s.Begin()
				s.Bool(v.rowDefaultPagingDRX == nil)
				if v.rowDefaultPagingDRX != nil {
					s00.BridgeCaptureS1APPagingDRX(v.rowDefaultPagingDRX, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(128):
			{
				f := s.Begin()
				s.Bool(v.rowCSGIdList == nil)
				if v.rowCSGIdList != nil {
					s21.BridgeCaptureS1APCSGIdList(v.rowCSGIdList, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(228):
			{
				f := s.Begin()
				s.Bool(v.rowUERetentionInformation == nil)
				if v.rowUERetentionInformation != nil {
					s00.BridgeCaptureS1APUERetentionInformation(v.rowUERetentionInformation, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(234):
			{
				f := s.Begin()
				s.Bool(v.rowNBIoTDefaultPagingDRX == nil)
				if v.rowNBIoTDefaultPagingDRX != nil {
					s00.BridgeCaptureS1APNBIoTDefaultPagingDRX(v.rowNBIoTDefaultPagingDRX, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(291):
			{
				f := s.Begin()
				s.Bool(v.rowConnectedengNBList == nil)
				if v.rowConnectedengNBList != nil {
					s31.BridgeCaptureS1APConnectedengNBList(v.rowConnectedengNBList, s)
				}
				s.End(f, nil, false)
			}
		}
	}
	s.End(f, &v.replay, false)
	s.CheckReceived(v.replay, v.received)
}
func (v S1SetupRequestIEValue) captureSemantics(s aper.SemanticCapture) S1SetupRequestIEValue {
	BridgeCaptureS1APS1SetupRequestIEValue(&v, &s)
	return v
}
func BridgeCompareS1APS1SetupRequestIEValue(v *S1SetupRequestIEValue, s *aper.SemanticComparison) {
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
		case s00.ProtocolIEID(59):
			{
				f := s.Begin()
				s.Bool(v.rowGlobalENBID == nil)
				if v.rowGlobalENBID != nil {
					s18.BridgeCompareS1APGlobalENBID(v.rowGlobalENBID, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(60):
			{
				f := s.Begin()
				s.Bool(v.rowENBname == nil)
				if v.rowENBname != nil {
					s02.BridgeCompareS1APENBname(v.rowENBname, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(64):
			{
				f := s.Begin()
				s.Bool(v.rowSupportedTAs == nil)
				if v.rowSupportedTAs != nil {
					s31.BridgeCompareS1APSupportedTAs(v.rowSupportedTAs, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(137):
			{
				f := s.Begin()
				s.Bool(v.rowDefaultPagingDRX == nil)
				if v.rowDefaultPagingDRX != nil {
					s02.BridgeCompareS1APPagingDRX(v.rowDefaultPagingDRX, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(128):
			{
				f := s.Begin()
				s.Bool(v.rowCSGIdList == nil)
				if v.rowCSGIdList != nil {
					s22.BridgeCompareS1APCSGIdList(v.rowCSGIdList, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(228):
			{
				f := s.Begin()
				s.Bool(v.rowUERetentionInformation == nil)
				if v.rowUERetentionInformation != nil {
					s07.BridgeCompareS1APUERetentionInformation(v.rowUERetentionInformation, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(234):
			{
				f := s.Begin()
				s.Bool(v.rowNBIoTDefaultPagingDRX == nil)
				if v.rowNBIoTDefaultPagingDRX != nil {
					s02.BridgeCompareS1APNBIoTDefaultPagingDRX(v.rowNBIoTDefaultPagingDRX, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(291):
			{
				f := s.Begin()
				s.Bool(v.rowConnectedengNBList == nil)
				if v.rowConnectedengNBList != nil {
					s31.BridgeCompareS1APConnectedengNBList(v.rowConnectedengNBList, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		}
	}
	s.End(f, v.replay, false)
	s.CheckReceived(v.replay, v.received)
}
func (v S1SetupRequestIEValue) compareSemantics(s aper.SemanticComparison) aper.SemanticComparison {
	BridgeCompareS1APS1SetupRequestIEValue(&v, &s)
	return s
}
func BridgeCaptureS1APS1SetupResponse(v *S1SetupResponse, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeS1SetupResponseIEValueCaptureS1APProtocolIEContainer(&v.ProtocolIEs, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APS1SetupResponse(v *S1SetupResponse, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeS1SetupResponseIEValueCompareS1APProtocolIEContainer(&v.ProtocolIEs, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APS1SetupResponseIEValue(v *S1SetupResponseIEValue, s *aper.SemanticCapture) {
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
		case s00.ProtocolIEID(61):
			{
				f := s.Begin()
				s.Bool(v.rowMMEname == nil)
				if v.rowMMEname != nil {
					s00.BridgeCaptureS1APMMEname(v.rowMMEname, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(105):
			{
				f := s.Begin()
				s.Bool(v.rowServedGUMMEIs == nil)
				if v.rowServedGUMMEIs != nil {
					s31.BridgeCaptureS1APServedGUMMEIs(v.rowServedGUMMEIs, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(87):
			{
				f := s.Begin()
				s.Bool(v.rowRelativeMMECapacity == nil)
				if v.rowRelativeMMECapacity != nil {
					s00.BridgeCaptureS1APRelativeMMECapacity(v.rowRelativeMMECapacity, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(163):
			{
				f := s.Begin()
				s.Bool(v.rowMMERelaySupportIndicator == nil)
				if v.rowMMERelaySupportIndicator != nil {
					s00.BridgeCaptureS1APMMERelaySupportIndicator(v.rowMMERelaySupportIndicator, s)
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
		case s00.ProtocolIEID(228):
			{
				f := s.Begin()
				s.Bool(v.rowUERetentionInformation == nil)
				if v.rowUERetentionInformation != nil {
					s00.BridgeCaptureS1APUERetentionInformation(v.rowUERetentionInformation, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(247):
			{
				f := s.Begin()
				s.Bool(v.rowServedDCNs == nil)
				if v.rowServedDCNs != nil {
					s31.BridgeCaptureS1APServedDCNs(v.rowServedDCNs, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(303):
			{
				f := s.Begin()
				s.Bool(v.rowIABSupported == nil)
				if v.rowIABSupported != nil {
					s00.BridgeCaptureS1APIABSupported(v.rowIABSupported, s)
				}
				s.End(f, nil, false)
			}
		}
	}
	s.End(f, &v.replay, false)
	s.CheckReceived(v.replay, v.received)
}
func (v S1SetupResponseIEValue) captureSemantics(s aper.SemanticCapture) S1SetupResponseIEValue {
	BridgeCaptureS1APS1SetupResponseIEValue(&v, &s)
	return v
}
func BridgeCompareS1APS1SetupResponseIEValue(v *S1SetupResponseIEValue, s *aper.SemanticComparison) {
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
		case s00.ProtocolIEID(61):
			{
				f := s.Begin()
				s.Bool(v.rowMMEname == nil)
				if v.rowMMEname != nil {
					s02.BridgeCompareS1APMMEname(v.rowMMEname, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(105):
			{
				f := s.Begin()
				s.Bool(v.rowServedGUMMEIs == nil)
				if v.rowServedGUMMEIs != nil {
					s31.BridgeCompareS1APServedGUMMEIs(v.rowServedGUMMEIs, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(87):
			{
				f := s.Begin()
				s.Bool(v.rowRelativeMMECapacity == nil)
				if v.rowRelativeMMECapacity != nil {
					s06.BridgeCompareS1APRelativeMMECapacity(v.rowRelativeMMECapacity, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(163):
			{
				f := s.Begin()
				s.Bool(v.rowMMERelaySupportIndicator == nil)
				if v.rowMMERelaySupportIndicator != nil {
					s02.BridgeCompareS1APMMERelaySupportIndicator(v.rowMMERelaySupportIndicator, s)
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
		case s00.ProtocolIEID(228):
			{
				f := s.Begin()
				s.Bool(v.rowUERetentionInformation == nil)
				if v.rowUERetentionInformation != nil {
					s07.BridgeCompareS1APUERetentionInformation(v.rowUERetentionInformation, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(247):
			{
				f := s.Begin()
				s.Bool(v.rowServedDCNs == nil)
				if v.rowServedDCNs != nil {
					s31.BridgeCompareS1APServedDCNs(v.rowServedDCNs, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(303):
			{
				f := s.Begin()
				s.Bool(v.rowIABSupported == nil)
				if v.rowIABSupported != nil {
					s02.BridgeCompareS1APIABSupported(v.rowIABSupported, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		}
	}
	s.End(f, v.replay, false)
	s.CheckReceived(v.replay, v.received)
}
func (v S1SetupResponseIEValue) compareSemantics(s aper.SemanticComparison) aper.SemanticComparison {
	BridgeCompareS1APS1SetupResponseIEValue(&v, &s)
	return s
}
func BridgeCaptureS1APServedGroupIDsComplete(v *ServedGroupIDsComplete, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APServedGroupIDs(&v.Value, s)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APServedGroupIDsComplete(v *ServedGroupIDsComplete, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s07.BridgeCompareS1APServedGroupIDs(&v.Value, s)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APServedMMECsComplete(v *ServedMMECsComplete, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APServedMMECs(&v.Value, s)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APServedMMECsComplete(v *ServedMMECsComplete, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s07.BridgeCompareS1APServedMMECs(&v.Value, s)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APServedPLMNsComplete(v *ServedPLMNsComplete, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APServedPLMNs(&v.Value, s)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APServedPLMNsComplete(v *ServedPLMNsComplete, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s07.BridgeCompareS1APServedPLMNs(&v.Value, s)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APSupportedTAsComplete(v *SupportedTAsComplete, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s31.BridgeCaptureS1APSupportedTAs(&v.Value, s)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APSupportedTAsComplete(v *SupportedTAsComplete, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s31.BridgeCompareS1APSupportedTAs(&v.Value, s)
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
	s33.BridgeCompareS1APTAICancelled(&v.Value, s)
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
	s33.BridgeCompareS1APTAIListForRestart(&v.Value, s)
	s.End(f, v.replay, v.withoutReplay)
}

// MarshalAPERServedGUMMEIs encodes a ServedGUMMEIs list to APER.
func BridgeMarshalAPERServedGUMMEIs(list s43.ServedGUMMEIsComplete) ([]byte, error) {
	return s43.BridgeServedGUMMEIsCompleteMethodMarshalAPERLegacy(&list)
}

// UnmarshalAPERServedGUMMEIs decodes a ServedGUMMEIs list from APER.
func BridgeUnmarshalAPERServedGUMMEIs(data []byte) (s43.ServedGUMMEIsComplete, error) {
	var value s43.ServedGUMMEIsComplete
	if err := s43.BridgeServedGUMMEIsCompleteMethodUnmarshalAPERLegacy(&value, data); err != nil {
		return value, err
	}
	return value, nil
}

// ServedGroupIDsComplete carries a complete ServedGroupIDs encoding, including observed terminal bits.
// ITU-T X.691 (02/2021) 11.1.3.1 and 11.1.4 require new encodings to pad with zero bits.
type ServedGroupIDsComplete struct {
	replay           aper.Snapshot
	stream           aper.WireSpan
	received         bool
	withoutReplay    bool
	receivedAbsolute bool
	receivedBytes    aper.WireSpan
	receivedLocation aper.Location
	Value            s00.ServedGroupIDs
	perPadding       aper.CompletePadding `json:"-"`
}

func (v *ServedGroupIDsComplete) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := s13.BridgeMarshalAPERServedGroupIDsTo(v.Value, bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.perPadding)
}

// UnmarshalAPER decodes ServedGroupIDs from APER format.
func (v *ServedGroupIDsComplete) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes ServedGroupIDs with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *ServedGroupIDsComplete) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "ServedGroupIDs")
	}
	bb.EnterComponent("ServedGroupIDs")
	value, err := BridgeUnmarshalAPERServedGroupIDsFrom(bb)
	if err != nil {
		return runtime.WrapDecodePath(err, "ServedGroupIDs")
	}
	padding, err := aper.CaptureFinalBits(bb, "ServedGroupIDs")
	if err != nil {
		return runtime.WrapDecodePath(err, "ServedGroupIDs")
	}
	v.Value, v.perPadding = value, padding.Padding()
	return nil
}

// MarshalAPERServedGroupIDs encodes a ServedGroupIDs list to APER.
func BridgeMarshalAPERServedGroupIDs(list ServedGroupIDsComplete) ([]byte, error) {
	return list.marshalAPERLegacy()
}

// UnmarshalAPERServedGroupIDs decodes a ServedGroupIDs list from APER.
func BridgeUnmarshalAPERServedGroupIDs(data []byte) (ServedGroupIDsComplete, error) {
	var value ServedGroupIDsComplete
	if err := value.unmarshalAPERLegacy(data); err != nil {
		return value, err
	}
	return value, nil
}

// UnmarshalAPERServedGroupIDsFrom decodes a ServedGroupIDs list from bb.
func BridgeUnmarshalAPERServedGroupIDsFrom(bb *aper.BitBuffer) (s00.ServedGroupIDs, error) {
	if err := bb.EnterDecodeValue(); err != nil {
		return nil, err
	}
	defer bb.LeaveDecodeValue()
	var v s00.BridgeAsn1cAPERServedGroupIDsListValue
	if err := BridgeUnmarshalAPERServedGroupIDsInto(&v, bb); err != nil {
		return nil, err
	}
	return v.Value, nil
}
func BridgeUnmarshalAPERServedGroupIDsInto(v *s00.BridgeAsn1cAPERServedGroupIDsListValue, bb *aper.BitBuffer) error {
	toleranceMark_value := bb.EnterComponent("Value")
	v.Value = make(s00.ServedGroupIDs, 0)
	_, errCollection_value := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
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

// ServedMMECsComplete carries a complete ServedMMECs encoding, including observed terminal bits.
// ITU-T X.691 (02/2021) 11.1.3.1 and 11.1.4 require new encodings to pad with zero bits.
type ServedMMECsComplete struct {
	replay           aper.Snapshot
	stream           aper.WireSpan
	received         bool
	withoutReplay    bool
	receivedAbsolute bool
	receivedBytes    aper.WireSpan
	receivedLocation aper.Location
	Value            s00.ServedMMECs
	perPadding       aper.CompletePadding `json:"-"`
}

func (v *ServedMMECsComplete) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := s13.BridgeMarshalAPERServedMMECsTo(v.Value, bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.perPadding)
}

// UnmarshalAPER decodes ServedMMECs from APER format.
func (v *ServedMMECsComplete) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes ServedMMECs with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *ServedMMECsComplete) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "ServedMMECs")
	}
	bb.EnterComponent("ServedMMECs")
	value, err := BridgeUnmarshalAPERServedMMECsFrom(bb)
	if err != nil {
		return runtime.WrapDecodePath(err, "ServedMMECs")
	}
	padding, err := aper.CaptureFinalBits(bb, "ServedMMECs")
	if err != nil {
		return runtime.WrapDecodePath(err, "ServedMMECs")
	}
	v.Value, v.perPadding = value, padding.Padding()
	return nil
}

// MarshalAPERServedMMECs encodes a ServedMMECs list to APER.
func BridgeMarshalAPERServedMMECs(list ServedMMECsComplete) ([]byte, error) {
	return list.marshalAPERLegacy()
}

// UnmarshalAPERServedMMECs decodes a ServedMMECs list from APER.
func BridgeUnmarshalAPERServedMMECs(data []byte) (ServedMMECsComplete, error) {
	var value ServedMMECsComplete
	if err := value.unmarshalAPERLegacy(data); err != nil {
		return value, err
	}
	return value, nil
}

// UnmarshalAPERServedMMECsFrom decodes a ServedMMECs list from bb.
func BridgeUnmarshalAPERServedMMECsFrom(bb *aper.BitBuffer) (s00.ServedMMECs, error) {
	if err := bb.EnterDecodeValue(); err != nil {
		return nil, err
	}
	defer bb.LeaveDecodeValue()
	var v s00.BridgeAsn1cAPERServedMMECsListValue
	if err := BridgeUnmarshalAPERServedMMECsInto(&v, bb); err != nil {
		return nil, err
	}
	return v.Value, nil
}
func BridgeUnmarshalAPERServedMMECsInto(v *s00.BridgeAsn1cAPERServedMMECsListValue, bb *aper.BitBuffer) error {
	toleranceMark_value := bb.EnterComponent("Value")
	v.Value = make(s00.ServedMMECs, 0)
	_, errCollection_value := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 256, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_5: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1191
		if fragmentOffset_value < 0 || fragmentLength_value < 0 || fragmentLength_value > int64(^uint(0)>>1) || fragmentOffset_value > int64(^uint(0)>>1)-fragmentLength_value {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_value; i++ {
			val, err := aper.DecodeOctetStringAligned(bb, 1, 1, true)
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

// ServedPLMNsComplete carries a complete ServedPLMNs encoding, including observed terminal bits.
// ITU-T X.691 (02/2021) 11.1.3.1 and 11.1.4 require new encodings to pad with zero bits.
type ServedPLMNsComplete struct {
	replay           aper.Snapshot
	stream           aper.WireSpan
	received         bool
	withoutReplay    bool
	receivedAbsolute bool
	receivedBytes    aper.WireSpan
	receivedLocation aper.Location
	Value            s00.ServedPLMNs
	perPadding       aper.CompletePadding `json:"-"`
}

func (v *ServedPLMNsComplete) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := s13.BridgeMarshalAPERServedPLMNsTo(v.Value, bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.perPadding)
}

// UnmarshalAPER decodes ServedPLMNs from APER format.
func (v *ServedPLMNsComplete) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes ServedPLMNs with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *ServedPLMNsComplete) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "ServedPLMNs")
	}
	bb.EnterComponent("ServedPLMNs")
	value, err := BridgeUnmarshalAPERServedPLMNsFrom(bb)
	if err != nil {
		return runtime.WrapDecodePath(err, "ServedPLMNs")
	}
	padding, err := aper.CaptureFinalBits(bb, "ServedPLMNs")
	if err != nil {
		return runtime.WrapDecodePath(err, "ServedPLMNs")
	}
	v.Value, v.perPadding = value, padding.Padding()
	return nil
}

// MarshalAPERServedPLMNs encodes a ServedPLMNs list to APER.
func BridgeMarshalAPERServedPLMNs(list ServedPLMNsComplete) ([]byte, error) {
	return list.marshalAPERLegacy()
}

// UnmarshalAPERServedPLMNs decodes a ServedPLMNs list from APER.
func BridgeUnmarshalAPERServedPLMNs(data []byte) (ServedPLMNsComplete, error) {
	var value ServedPLMNsComplete
	if err := value.unmarshalAPERLegacy(data); err != nil {
		return value, err
	}
	return value, nil
}

// UnmarshalAPERServedPLMNsFrom decodes a ServedPLMNs list from bb.
func BridgeUnmarshalAPERServedPLMNsFrom(bb *aper.BitBuffer) (s00.ServedPLMNs, error) {
	if err := bb.EnterDecodeValue(); err != nil {
		return nil, err
	}
	defer bb.LeaveDecodeValue()
	var v s00.BridgeAsn1cAPERServedPLMNsListValue
	if err := BridgeUnmarshalAPERServedPLMNsInto(&v, bb); err != nil {
		return nil, err
	}
	return v.Value, nil
}
func BridgeUnmarshalAPERServedPLMNsInto(v *s00.BridgeAsn1cAPERServedPLMNsListValue, bb *aper.BitBuffer) error {
	toleranceMark_value := bb.EnterComponent("Value")
	v.Value = make(s00.ServedPLMNs, 0)
	_, errCollection_value := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 32, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
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

// SupportedTAsComplete carries a complete SupportedTAs encoding, including observed terminal bits.
// ITU-T X.691 (02/2021) 11.1.3.1 and 11.1.4 require new encodings to pad with zero bits.
type SupportedTAsComplete struct {
	replay           aper.Snapshot
	stream           aper.WireSpan
	received         bool
	withoutReplay    bool
	receivedAbsolute bool
	receivedBytes    aper.WireSpan
	receivedLocation aper.Location
	Value            s31.SupportedTAs
	perPadding       aper.CompletePadding `json:"-"`
}

func (v *SupportedTAsComplete) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := s31.BridgeMarshalAPERSupportedTAsTo(v.Value, bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.perPadding)
}

// UnmarshalAPER decodes SupportedTAs from APER format.
func (v *SupportedTAsComplete) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes SupportedTAs with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *SupportedTAsComplete) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "SupportedTAs")
	}
	bb.EnterComponent("SupportedTAs")
	value, err := BridgeUnmarshalAPERSupportedTAsFrom(bb)
	if err != nil {
		return runtime.WrapDecodePath(err, "SupportedTAs")
	}
	padding, err := aper.CaptureFinalBits(bb, "SupportedTAs")
	if err != nil {
		return runtime.WrapDecodePath(err, "SupportedTAs")
	}
	v.Value, v.perPadding = value, padding.Padding()
	return nil
}

// MarshalAPERSupportedTAs encodes a SupportedTAs list to APER.
func BridgeMarshalAPERSupportedTAs(list SupportedTAsComplete) ([]byte, error) {
	return list.marshalAPERLegacy()
}

// UnmarshalAPERSupportedTAs decodes a SupportedTAs list from APER.
func BridgeUnmarshalAPERSupportedTAs(data []byte) (SupportedTAsComplete, error) {
	var value SupportedTAsComplete
	if err := value.unmarshalAPERLegacy(data); err != nil {
		return value, err
	}
	return value, nil
}

// UnmarshalAPERSupportedTAsFrom decodes a SupportedTAs list from bb.
func BridgeUnmarshalAPERSupportedTAsFrom(bb *aper.BitBuffer) (s31.SupportedTAs, error) {
	if err := bb.EnterDecodeValue(); err != nil {
		return nil, err
	}
	defer bb.LeaveDecodeValue()
	var v s31.BridgeAsn1cAPERSupportedTAsListValue
	if err := BridgeUnmarshalAPERSupportedTAsInto(&v, bb); err != nil {
		return nil, err
	}
	return v.Value, nil
}
func BridgeUnmarshalAPERSupportedTAsInto(v *s31.BridgeAsn1cAPERSupportedTAsListValue, bb *aper.BitBuffer) error {
	toleranceMark_value := bb.EnterComponent("Value")
	v.Value = make(s31.SupportedTAs, 0)
	_, errCollection_value := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 256, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1128
		if fragmentOffset_value < 0 || fragmentLength_value < 0 || fragmentLength_value > int64(^uint(0)>>1) || fragmentOffset_value > int64(^uint(0)>>1)-fragmentLength_value {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_value; i++ {
			var elem s31.SupportedTAsItem
			elementMark := bb.EnterIndex(fragmentOffset_value + i)
			if err := s31.BridgeSupportedTAsItemMethodUnmarshalAPERFrom(&elem, bb); err != nil {
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
			var elem s32.TAI
			elementMark := bb.EnterIndex(fragmentOffset_value + i)
			if err := s32.BridgeTAIMethodUnmarshalAPERFrom(&elem, bb); err != nil {
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
func (v *ServedGroupIDsComplete) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s14.BridgeReceivedFormAt(v.received, v.receivedBytes, "ServedGroupIDsComplete", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "ServedGroupIDsComplete", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v ServedGroupIDsComplete) WithoutReplay() ServedGroupIDsComplete {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero ServedGroupIDsComplete
	v.perPadding = zero.perPadding
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *ServedMMECsComplete) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s14.BridgeReceivedFormAt(v.received, v.receivedBytes, "ServedMMECsComplete", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "ServedMMECsComplete", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v ServedMMECsComplete) WithoutReplay() ServedMMECsComplete {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero ServedMMECsComplete
	v.perPadding = zero.perPadding
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *ServedPLMNsComplete) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s14.BridgeReceivedFormAt(v.received, v.receivedBytes, "ServedPLMNsComplete", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "ServedPLMNsComplete", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v ServedPLMNsComplete) WithoutReplay() ServedPLMNsComplete {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero ServedPLMNsComplete
	v.perPadding = zero.perPadding
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *SupportedTAsComplete) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s14.BridgeReceivedFormAt(v.received, v.receivedBytes, "SupportedTAsComplete", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "SupportedTAsComplete", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v SupportedTAsComplete) WithoutReplay() SupportedTAsComplete {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero SupportedTAsComplete
	v.perPadding = zero.perPadding
	return v
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

// MarshalAPER encodes a complete value using one per-call change plan.
func (v *ServedGroupIDsComplete) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "ServedGroupIDsComplete")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *ServedGroupIDsComplete) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "ServedGroupIDsComplete")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APServedGroupIDsComplete(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "ServedGroupIDsComplete")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "ServedGroupIDsComplete")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *ServedGroupIDsComplete) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "ServedGroupIDsComplete")
}
func (v *ServedGroupIDsComplete) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "ServedGroupIDsComplete")
}
func (v *ServedGroupIDsComplete) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APServedGroupIDsComplete(v, &s)
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
func (v *ServedGroupIDsComplete) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *ServedGroupIDsComplete) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
	if err := s13.BridgeMarshalAPERServedGroupIDsTo(v.Value, bb, fresh); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.perPadding)
}

// MarshalAPER encodes a complete value using one per-call change plan.
func (v *ServedMMECsComplete) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "ServedMMECsComplete")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *ServedMMECsComplete) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "ServedMMECsComplete")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APServedMMECsComplete(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "ServedMMECsComplete")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "ServedMMECsComplete")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *ServedMMECsComplete) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "ServedMMECsComplete")
}
func (v *ServedMMECsComplete) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "ServedMMECsComplete")
}
func (v *ServedMMECsComplete) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APServedMMECsComplete(v, &s)
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
func (v *ServedMMECsComplete) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *ServedMMECsComplete) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
	if err := s13.BridgeMarshalAPERServedMMECsTo(v.Value, bb, fresh); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.perPadding)
}

// MarshalAPER encodes a complete value using one per-call change plan.
func (v *ServedPLMNsComplete) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "ServedPLMNsComplete")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *ServedPLMNsComplete) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "ServedPLMNsComplete")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APServedPLMNsComplete(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "ServedPLMNsComplete")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "ServedPLMNsComplete")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *ServedPLMNsComplete) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "ServedPLMNsComplete")
}
func (v *ServedPLMNsComplete) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "ServedPLMNsComplete")
}
func (v *ServedPLMNsComplete) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APServedPLMNsComplete(v, &s)
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
func (v *ServedPLMNsComplete) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *ServedPLMNsComplete) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
	if err := s13.BridgeMarshalAPERServedPLMNsTo(v.Value, bb, fresh); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.perPadding)
}

// MarshalAPER encodes a complete value using one per-call change plan.
func (v *SupportedTAsComplete) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "SupportedTAsComplete")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *SupportedTAsComplete) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "SupportedTAsComplete")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APSupportedTAsComplete(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "SupportedTAsComplete")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "SupportedTAsComplete")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *SupportedTAsComplete) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "SupportedTAsComplete")
}
func (v *SupportedTAsComplete) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "SupportedTAsComplete")
}
func (v *SupportedTAsComplete) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APSupportedTAsComplete(v, &s)
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
func (v *SupportedTAsComplete) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *SupportedTAsComplete) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
	if err := s31.BridgeMarshalAPERSupportedTAsTo(v.Value, bb, fresh); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.perPadding)
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

// UnmarshalAPER decodes one complete value and returns its report.
func (v *ServedGroupIDsComplete) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "ServedGroupIDsComplete")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded ServedGroupIDsComplete
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APServedGroupIDsComplete(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = ServedGroupIDsComplete{}
		return report, aper.OperationError(err, "ServedGroupIDsComplete")
	}
	*v = decoded
	return report, aper.OperationError(nil, "ServedGroupIDsComplete")
}

// UnmarshalAPER decodes one complete value and returns its report.
func (v *ServedMMECsComplete) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "ServedMMECsComplete")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded ServedMMECsComplete
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APServedMMECsComplete(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = ServedMMECsComplete{}
		return report, aper.OperationError(err, "ServedMMECsComplete")
	}
	*v = decoded
	return report, aper.OperationError(nil, "ServedMMECsComplete")
}

// UnmarshalAPER decodes one complete value and returns its report.
func (v *ServedPLMNsComplete) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "ServedPLMNsComplete")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded ServedPLMNsComplete
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APServedPLMNsComplete(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = ServedPLMNsComplete{}
		return report, aper.OperationError(err, "ServedPLMNsComplete")
	}
	*v = decoded
	return report, aper.OperationError(nil, "ServedPLMNsComplete")
}

// UnmarshalAPER decodes one complete value and returns its report.
func (v *SupportedTAsComplete) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "SupportedTAsComplete")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded SupportedTAsComplete
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APSupportedTAsComplete(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = SupportedTAsComplete{}
		return report, aper.OperationError(err, "SupportedTAsComplete")
	}
	*v = decoded
	return report, aper.OperationError(nil, "SupportedTAsComplete")
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

// MarshalAPERServedGUMMEIs encodes a complete named list.
func MarshalAPERServedGUMMEIs(v s43.ServedGUMMEIsComplete, options ...aper.EncodeOption) ([]byte, error) {
	return v.MarshalAPER(options...)
}

// MarshalAPERServedGroupIDs encodes a complete named list.
func MarshalAPERServedGroupIDs(v ServedGroupIDsComplete, options ...aper.EncodeOption) ([]byte, error) {
	return v.MarshalAPER(options...)
}

// MarshalAPERServedMMECs encodes a complete named list.
func MarshalAPERServedMMECs(v ServedMMECsComplete, options ...aper.EncodeOption) ([]byte, error) {
	return v.MarshalAPER(options...)
}

// MarshalAPERServedPLMNs encodes a complete named list.
func MarshalAPERServedPLMNs(v ServedPLMNsComplete, options ...aper.EncodeOption) ([]byte, error) {
	return v.MarshalAPER(options...)
}

// MarshalAPERSupportedTAs encodes a complete named list.
func MarshalAPERSupportedTAs(v SupportedTAsComplete, options ...aper.EncodeOption) ([]byte, error) {
	return v.MarshalAPER(options...)
}

// MarshalAPERTACListInLTENTN encodes a complete named list.
func MarshalAPERTACListInLTENTN(v TACListInLTENTNComplete, options ...aper.EncodeOption) ([]byte, error) {
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

// MarshalAPERTAIListForRestart encodes a complete named list.
func MarshalAPERTAIListForRestart(v TAIListForRestartComplete, options ...aper.EncodeOption) ([]byte, error) {
	return v.MarshalAPER(options...)
}

// UnmarshalAPERServedGUMMEIs decodes a complete named list.
func UnmarshalAPERServedGUMMEIs(data []byte, options ...aper.DecodeOption) (s43.ServedGUMMEIsComplete, aper.DecodeReport, error) {
	var v s43.ServedGUMMEIsComplete
	report, err := v.UnmarshalAPER(data, options...)
	return v, report, err
}

// UnmarshalAPERServedGroupIDs decodes a complete named list.
func UnmarshalAPERServedGroupIDs(data []byte, options ...aper.DecodeOption) (ServedGroupIDsComplete, aper.DecodeReport, error) {
	var v ServedGroupIDsComplete
	report, err := v.UnmarshalAPER(data, options...)
	return v, report, err
}

// UnmarshalAPERServedMMECs decodes a complete named list.
func UnmarshalAPERServedMMECs(data []byte, options ...aper.DecodeOption) (ServedMMECsComplete, aper.DecodeReport, error) {
	var v ServedMMECsComplete
	report, err := v.UnmarshalAPER(data, options...)
	return v, report, err
}

// UnmarshalAPERServedPLMNs decodes a complete named list.
func UnmarshalAPERServedPLMNs(data []byte, options ...aper.DecodeOption) (ServedPLMNsComplete, aper.DecodeReport, error) {
	var v ServedPLMNsComplete
	report, err := v.UnmarshalAPER(data, options...)
	return v, report, err
}

// UnmarshalAPERSupportedTAs decodes a complete named list.
func UnmarshalAPERSupportedTAs(data []byte, options ...aper.DecodeOption) (SupportedTAsComplete, aper.DecodeReport, error) {
	var v SupportedTAsComplete
	report, err := v.UnmarshalAPER(data, options...)
	return v, report, err
}

// UnmarshalAPERTACListInLTENTN decodes a complete named list.
func UnmarshalAPERTACListInLTENTN(data []byte, options ...aper.DecodeOption) (TACListInLTENTNComplete, aper.DecodeReport, error) {
	var v TACListInLTENTNComplete
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

// UnmarshalAPERTAIListForRestart decodes a complete named list.
func UnmarshalAPERTAIListForRestart(data []byte, options ...aper.DecodeOption) (TAIListForRestartComplete, aper.DecodeReport, error) {
	var v TAIListForRestartComplete
	report, err := v.UnmarshalAPER(data, options...)
	return v, report, err
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
	ProtocolIEs      S1SetupRequestIEContainer `asn1:"tag:0,context,implicit"`
	protocolIEsIndef bool                      `asn1:"-" json:"-"`
	extCount         int64                     `asn1:"-" json:"-"`
	extPresent       []bool                    `asn1:"-" json:"-"`
	extData          [][]byte                  `asn1:"-" json:"-"`
	perPadding       aper.FinalPadding         `asn1:"-" json:"-"`
	perExtPadding    []aper.CompletePadding    `asn1:"-" json:"-"`
	extOrigin        []aper.OpaqueOrigin
	extWire          []aper.WireSpan
}

// S1SetupResponse represents the ASN.1 type S1SetupResponse (SEQUENCE).
type S1SetupResponse struct {
	replay           aper.Snapshot
	stream           aper.WireSpan
	received         bool
	withoutReplay    bool
	receivedAbsolute bool
	receivedBytes    aper.WireSpan
	receivedLocation aper.Location
	ProtocolIEs      S1SetupResponseIEContainer `asn1:"tag:0,context,implicit"`
	protocolIEsIndef bool                       `asn1:"-" json:"-"`
	extCount         int64                      `asn1:"-" json:"-"`
	extPresent       []bool                     `asn1:"-" json:"-"`
	extData          [][]byte                   `asn1:"-" json:"-"`
	perPadding       aper.FinalPadding          `asn1:"-" json:"-"`
	perExtPadding    []aper.CompletePadding     `asn1:"-" json:"-"`
	extOrigin        []aper.OpaqueOrigin
	extWire          []aper.WireSpan
}

// ENBConfigurationUpdate represents the ASN.1 type ENBConfigurationUpdate (SEQUENCE).
type ENBConfigurationUpdate struct {
	replay           aper.Snapshot
	stream           aper.WireSpan
	received         bool
	withoutReplay    bool
	receivedAbsolute bool
	receivedBytes    aper.WireSpan
	receivedLocation aper.Location
	ProtocolIEs      ENBConfigurationUpdateIEContainer `asn1:"tag:0,context,implicit"`
	protocolIEsIndef bool                              `asn1:"-" json:"-"`
	extCount         int64                             `asn1:"-" json:"-"`
	extPresent       []bool                            `asn1:"-" json:"-"`
	extData          [][]byte                          `asn1:"-" json:"-"`
	perPadding       aper.FinalPadding                 `asn1:"-" json:"-"`
	perExtPadding    []aper.CompletePadding            `asn1:"-" json:"-"`
	extOrigin        []aper.OpaqueOrigin
	extWire          []aper.WireSpan
}

// MMEConfigurationUpdate represents the ASN.1 type MMEConfigurationUpdate (SEQUENCE).
type MMEConfigurationUpdate struct {
	replay           aper.Snapshot
	stream           aper.WireSpan
	received         bool
	withoutReplay    bool
	receivedAbsolute bool
	receivedBytes    aper.WireSpan
	receivedLocation aper.Location
	ProtocolIEs      s43.MMEConfigurationUpdateIEContainer `asn1:"tag:0,context,implicit"`
	protocolIEsIndef bool                                  `asn1:"-" json:"-"`
	extCount         int64                                 `asn1:"-" json:"-"`
	extPresent       []bool                                `asn1:"-" json:"-"`
	extData          [][]byte                              `asn1:"-" json:"-"`
	perPadding       aper.FinalPadding                     `asn1:"-" json:"-"`
	perExtPadding    []aper.CompletePadding                `asn1:"-" json:"-"`
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
	v.ProtocolIEs = make(S1SetupRequestIEContainer, 0)
	_, errCollection_protocolies := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1128
		if fragmentOffset_protocolies < 0 || fragmentLength_protocolies < 0 || fragmentLength_protocolies > int64(^uint(0)>>1) || fragmentOffset_protocolies > int64(^uint(0)>>1)-fragmentLength_protocolies {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_protocolies; i++ {
			var elem S1SetupRequestIEField
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

// MarshalAPER encodes S1SetupResponse to APER format.
func (v *S1SetupResponse) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *S1SetupResponse) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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

// UnmarshalAPER decodes S1SetupResponse from APER format.
func (v *S1SetupResponse) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes S1SetupResponse with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *S1SetupResponse) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "S1SetupResponse")
	}
	bb.EnterComponent("S1SetupResponse")
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "S1SetupResponse")
	}
	padding, err := aper.CaptureFinalBits(bb, "S1SetupResponse")
	if err != nil {
		return runtime.WrapDecodePath(err, "S1SetupResponse")
	}
	v.perPadding = padding.WithRecords(v.perPadding)
	return nil
}
func (v *S1SetupResponse) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = S1SetupResponse{}
	extAdditions := aper.BeginExtensionAdditions(bb)
	hasExtensions, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	toleranceMark_protocolies := bb.EnterComponent("ProtocolIEs")
	v.ProtocolIEs = make(S1SetupResponseIEContainer, 0)
	_, errCollection_protocolies := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1128
		if fragmentOffset_protocolies < 0 || fragmentLength_protocolies < 0 || fragmentLength_protocolies > int64(^uint(0)>>1) || fragmentOffset_protocolies > int64(^uint(0)>>1)-fragmentLength_protocolies {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_protocolies; i++ {
			var elem S1SetupResponseIEField
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

// MarshalAPER encodes ENBConfigurationUpdate to APER format.
func (v *ENBConfigurationUpdate) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *ENBConfigurationUpdate) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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

// UnmarshalAPER decodes ENBConfigurationUpdate from APER format.
func (v *ENBConfigurationUpdate) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes ENBConfigurationUpdate with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *ENBConfigurationUpdate) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "ENBConfigurationUpdate")
	}
	bb.EnterComponent("ENBConfigurationUpdate")
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "ENBConfigurationUpdate")
	}
	padding, err := aper.CaptureFinalBits(bb, "ENBConfigurationUpdate")
	if err != nil {
		return runtime.WrapDecodePath(err, "ENBConfigurationUpdate")
	}
	v.perPadding = padding.WithRecords(v.perPadding)
	return nil
}
func (v *ENBConfigurationUpdate) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = ENBConfigurationUpdate{}
	extAdditions := aper.BeginExtensionAdditions(bb)
	hasExtensions, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	toleranceMark_protocolies := bb.EnterComponent("ProtocolIEs")
	v.ProtocolIEs = make(ENBConfigurationUpdateIEContainer, 0)
	_, errCollection_protocolies := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1128
		if fragmentOffset_protocolies < 0 || fragmentLength_protocolies < 0 || fragmentLength_protocolies > int64(^uint(0)>>1) || fragmentOffset_protocolies > int64(^uint(0)>>1)-fragmentLength_protocolies {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_protocolies; i++ {
			var elem ENBConfigurationUpdateIEField
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

// MarshalAPER encodes MMEConfigurationUpdate to APER format.
func (v *MMEConfigurationUpdate) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *MMEConfigurationUpdate) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
			if err := s43.BridgeMMEConfigurationUpdateIEFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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

// UnmarshalAPER decodes MMEConfigurationUpdate from APER format.
func (v *MMEConfigurationUpdate) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes MMEConfigurationUpdate with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *MMEConfigurationUpdate) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "MMEConfigurationUpdate")
	}
	bb.EnterComponent("MMEConfigurationUpdate")
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "MMEConfigurationUpdate")
	}
	padding, err := aper.CaptureFinalBits(bb, "MMEConfigurationUpdate")
	if err != nil {
		return runtime.WrapDecodePath(err, "MMEConfigurationUpdate")
	}
	v.perPadding = padding.WithRecords(v.perPadding)
	return nil
}
func (v *MMEConfigurationUpdate) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = MMEConfigurationUpdate{}
	extAdditions := aper.BeginExtensionAdditions(bb)
	hasExtensions, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	toleranceMark_protocolies := bb.EnterComponent("ProtocolIEs")
	v.ProtocolIEs = make(s43.MMEConfigurationUpdateIEContainer, 0)
	_, errCollection_protocolies := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1128
		if fragmentOffset_protocolies < 0 || fragmentLength_protocolies < 0 || fragmentLength_protocolies > int64(^uint(0)>>1) || fragmentOffset_protocolies > int64(^uint(0)>>1)-fragmentLength_protocolies {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_protocolies; i++ {
			var elem s43.MMEConfigurationUpdateIEField
			elementMark := bb.EnterIndex(fragmentOffset_protocolies + i)
			if err := s43.BridgeMMEConfigurationUpdateIEFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
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

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *ENBConfigurationUpdate) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s14.BridgeReceivedFormAt(v.received, v.receivedBytes, "ENBConfigurationUpdate", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "ENBConfigurationUpdate", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v ENBConfigurationUpdate) WithoutReplay() ENBConfigurationUpdate {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero ENBConfigurationUpdate
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *MMEConfigurationUpdate) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s14.BridgeReceivedFormAt(v.received, v.receivedBytes, "MMEConfigurationUpdate", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "MMEConfigurationUpdate", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v MMEConfigurationUpdate) WithoutReplay() MMEConfigurationUpdate {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero MMEConfigurationUpdate
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
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
func (v *S1SetupResponse) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s14.BridgeReceivedFormAt(v.received, v.receivedBytes, "S1SetupResponse", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "S1SetupResponse", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v S1SetupResponse) WithoutReplay() S1SetupResponse {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero S1SetupResponse
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// Extensions returns owned unknown sequence additions.
func (v *ENBConfigurationUpdate) Extensions() []aper.SequenceExtension {
	if v == nil {
		return nil
	}
	views := aper.SequenceExtensionViews(v.extPresent, aper.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *ENBConfigurationUpdate) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("ENBConfigurationUpdate.Extensions[%d]", index))
	}
	if err := aper.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("ENBConfigurationUpdate.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *ENBConfigurationUpdate) RemoveExtension(index uint64) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("ENBConfigurationUpdate.Extensions[%d]", index))
	}
	if err := aper.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("ENBConfigurationUpdate.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// Extensions returns owned unknown sequence additions.
func (v *MMEConfigurationUpdate) Extensions() []aper.SequenceExtension {
	if v == nil {
		return nil
	}
	views := aper.SequenceExtensionViews(v.extPresent, aper.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *MMEConfigurationUpdate) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("MMEConfigurationUpdate.Extensions[%d]", index))
	}
	if err := aper.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("MMEConfigurationUpdate.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *MMEConfigurationUpdate) RemoveExtension(index uint64) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("MMEConfigurationUpdate.Extensions[%d]", index))
	}
	if err := aper.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("MMEConfigurationUpdate.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
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
func (v *S1SetupResponse) Extensions() []aper.SequenceExtension {
	if v == nil {
		return nil
	}
	views := aper.SequenceExtensionViews(v.extPresent, aper.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *S1SetupResponse) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("S1SetupResponse.Extensions[%d]", index))
	}
	if err := aper.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("S1SetupResponse.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *S1SetupResponse) RemoveExtension(index uint64) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("S1SetupResponse.Extensions[%d]", index))
	}
	if err := aper.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("S1SetupResponse.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// MarshalAPER encodes a complete value using one per-call change plan.
func (v *ENBConfigurationUpdate) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "ENBConfigurationUpdate")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *ENBConfigurationUpdate) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "ENBConfigurationUpdate")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APENBConfigurationUpdate(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "ENBConfigurationUpdate")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "ENBConfigurationUpdate")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *ENBConfigurationUpdate) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "ENBConfigurationUpdate")
}
func (v *ENBConfigurationUpdate) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "ENBConfigurationUpdate")
}
func (v *ENBConfigurationUpdate) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APENBConfigurationUpdate(v, &s)
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
func (v *ENBConfigurationUpdate) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *ENBConfigurationUpdate) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
func (v *MMEConfigurationUpdate) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "MMEConfigurationUpdate")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *MMEConfigurationUpdate) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "MMEConfigurationUpdate")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APMMEConfigurationUpdate(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "MMEConfigurationUpdate")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "MMEConfigurationUpdate")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *MMEConfigurationUpdate) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "MMEConfigurationUpdate")
}
func (v *MMEConfigurationUpdate) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "MMEConfigurationUpdate")
}
func (v *MMEConfigurationUpdate) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APMMEConfigurationUpdate(v, &s)
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
func (v *MMEConfigurationUpdate) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *MMEConfigurationUpdate) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
func (v *S1SetupResponse) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "S1SetupResponse")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *S1SetupResponse) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "S1SetupResponse")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APS1SetupResponse(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "S1SetupResponse")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "S1SetupResponse")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *S1SetupResponse) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "S1SetupResponse")
}
func (v *S1SetupResponse) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "S1SetupResponse")
}
func (v *S1SetupResponse) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APS1SetupResponse(v, &s)
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
func (v *S1SetupResponse) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *S1SetupResponse) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
func (v *ENBConfigurationUpdate) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "ENBConfigurationUpdate")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded ENBConfigurationUpdate
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APENBConfigurationUpdate(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = ENBConfigurationUpdate{}
		return report, aper.OperationError(err, "ENBConfigurationUpdate")
	}
	*v = decoded
	return report, aper.OperationError(nil, "ENBConfigurationUpdate")
}

// UnmarshalAPER decodes one complete value and returns its report.
func (v *MMEConfigurationUpdate) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "MMEConfigurationUpdate")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded MMEConfigurationUpdate
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APMMEConfigurationUpdate(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = MMEConfigurationUpdate{}
		return report, aper.OperationError(err, "MMEConfigurationUpdate")
	}
	*v = decoded
	return report, aper.OperationError(nil, "MMEConfigurationUpdate")
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
func (v *S1SetupResponse) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "S1SetupResponse")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded S1SetupResponse
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APS1SetupResponse(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = S1SetupResponse{}
		return report, aper.OperationError(err, "S1SetupResponse")
	}
	*v = decoded
	return report, aper.OperationError(nil, "S1SetupResponse")
}

type ENBConfigurationUpdateIEValue struct {
	id                            s00.ProtocolIEID
	received                      aper.WireSpan
	replay                        aper.Snapshot
	opaque                        aper.OpaqueOpenType
	isOpaque                      bool
	rowENBname                    *s00.ENBname
	rowSupportedTAs               *s31.SupportedTAs
	rowCSGIdList                  *s14.CSGIdList
	rowDefaultPagingDRX           *s00.PagingDRX
	rowNBIoTDefaultPagingDRX      *s00.NBIoTDefaultPagingDRX
	rowConnectedengNBToAddList    *s31.ConnectedengNBList
	rowConnectedengNBToRemoveList *s31.ConnectedengNBList
}

func (v ENBConfigurationUpdateIEValue) matchesID(id s00.ProtocolIEID, _ ...*aper.DecodeBudget) bool {
	if v.id != id {
		return false
	}
	if v.isOpaque {
		return true
	}
	switch id {
	case s00.ProtocolIEID(60):
		return v.rowENBname != nil
	case s00.ProtocolIEID(64):
		return v.rowSupportedTAs != nil
	case s00.ProtocolIEID(128):
		return v.rowCSGIdList != nil
	case s00.ProtocolIEID(137):
		return v.rowDefaultPagingDRX != nil
	case s00.ProtocolIEID(234):
		return v.rowNBIoTDefaultPagingDRX != nil
	case s00.ProtocolIEID(292):
		return v.rowConnectedengNBToAddList != nil
	case s00.ProtocolIEID(293):
		return v.rowConnectedengNBToRemoveList != nil
	}
	return false
}

// Opaque returns the retained opaque open value of ENBConfigurationUpdateIEValue and reports whether the opaque alternative is selected.
func (v *ENBConfigurationUpdateIEValue) Opaque() (aper.OpaqueOpenType, bool) {
	if v == nil || !v.isOpaque {
		return aper.OpaqueOpenType{}, false
	}
	return v.opaque, true
}
func (ENBConfigurationUpdateIEValue) rule() aper.SourceRule {
	return aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "ENBConfigurationUpdateIEs"}}
}
func (ENBConfigurationUpdateIEValue) reason(id s00.ProtocolIEID) aper.OpaqueReason {
	switch id {
	case s00.ProtocolIEID(60):
		return aper.UnknownSelector
	case s00.ProtocolIEID(64):
		return aper.UnknownSelector
	case s00.ProtocolIEID(128):
		return aper.UnknownSelector
	case s00.ProtocolIEID(137):
		return aper.UnknownSelector
	case s00.ProtocolIEID(234):
		return aper.UnknownSelector
	case s00.ProtocolIEID(292):
		return aper.UnknownSelector
	case s00.ProtocolIEID(293):
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
	case s00.ProtocolIEID(61):
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

// AsENBname returns the selected ENBname value of ENBConfigurationUpdateIEValue and reports whether that alternative is active.
func (v *ENBConfigurationUpdateIEValue) AsENBname() (*s00.ENBname, bool) {
	if v == nil || v.id != s00.ProtocolIEID(60) || v.rowENBname == nil {
		return nil, false
	}
	return v.rowENBname, true
}

// AsSupportedTAs returns the selected SupportedTAs value of ENBConfigurationUpdateIEValue and reports whether that alternative is active.
func (v *ENBConfigurationUpdateIEValue) AsSupportedTAs() (*s31.SupportedTAs, bool) {
	if v == nil || v.id != s00.ProtocolIEID(64) || v.rowSupportedTAs == nil {
		return nil, false
	}
	return v.rowSupportedTAs, true
}

// AsCSGIdList returns the selected CSGIdList value of ENBConfigurationUpdateIEValue and reports whether that alternative is active.
func (v *ENBConfigurationUpdateIEValue) AsCSGIdList() (*s14.CSGIdList, bool) {
	if v == nil || v.id != s00.ProtocolIEID(128) || v.rowCSGIdList == nil {
		return nil, false
	}
	return v.rowCSGIdList, true
}

// AsDefaultPagingDRX returns the selected DefaultPagingDRX value of ENBConfigurationUpdateIEValue and reports whether that alternative is active.
func (v *ENBConfigurationUpdateIEValue) AsDefaultPagingDRX() (*s00.PagingDRX, bool) {
	if v == nil || v.id != s00.ProtocolIEID(137) || v.rowDefaultPagingDRX == nil {
		return nil, false
	}
	return v.rowDefaultPagingDRX, true
}

// AsNBIoTDefaultPagingDRX returns the selected NBIoTDefaultPagingDRX value of ENBConfigurationUpdateIEValue and reports whether that alternative is active.
func (v *ENBConfigurationUpdateIEValue) AsNBIoTDefaultPagingDRX() (*s00.NBIoTDefaultPagingDRX, bool) {
	if v == nil || v.id != s00.ProtocolIEID(234) || v.rowNBIoTDefaultPagingDRX == nil {
		return nil, false
	}
	return v.rowNBIoTDefaultPagingDRX, true
}

// AsConnectedengNBToAddList returns the selected ConnectedengNBToAddList value of ENBConfigurationUpdateIEValue and reports whether that alternative is active.
func (v *ENBConfigurationUpdateIEValue) AsConnectedengNBToAddList() (*s31.ConnectedengNBList, bool) {
	if v == nil || v.id != s00.ProtocolIEID(292) || v.rowConnectedengNBToAddList == nil {
		return nil, false
	}
	return v.rowConnectedengNBToAddList, true
}

// AsConnectedengNBToRemoveList returns the selected ConnectedengNBToRemoveList value of ENBConfigurationUpdateIEValue and reports whether that alternative is active.
func (v *ENBConfigurationUpdateIEValue) AsConnectedengNBToRemoveList() (*s31.ConnectedengNBList, bool) {
	if v == nil || v.id != s00.ProtocolIEID(293) || v.rowConnectedengNBToRemoveList == nil {
		return nil, false
	}
	return v.rowConnectedengNBToRemoveList, true
}
func (v ENBConfigurationUpdateIEValue) decode(id s00.ProtocolIEID, raw aper.OpaqueOpenType) (ENBConfigurationUpdateIEValue, error) {
	out := ENBConfigurationUpdateIEValue{id: id}
	switch id {
	case s00.ProtocolIEID(60):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		child := scope
		value, err := (func(bb *aper.BitBuffer) (s00.ENBname, error) {
			var v struct{ Value s00.ENBname }
			err := func() error {
				val_value, err := aper.DecodeAlphabetStringAligned(bb, aper.PermittedAlphabet{' ', ' ', '\'', ')', '+', ':', '=', '=', '?', '?', 'A', 'Z', 'a', 'z'}, 1, 150, true, true)
				if err != nil {
					return runtime.WrapDecodePath(err, "Value")
				}
				v.Value = val_value
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
		out.rowENBname = &value
		raw.RetainContents(&out.received)
	case s00.ProtocolIEID(64):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		child := scope
		list, err := BridgeUnmarshalAPERSupportedTAsFrom(child)
		if err != nil {
			return out, fmt.Errorf("%s %w", "SupportedTAs:", err)
		}
		padding, err := aper.CaptureOpenTypePadding(child)
		if err != nil {
			return out, err
		}
		_ = padding
		value := list
		out.rowSupportedTAs = &value
		raw.RetainContents(&out.received)
	case s00.ProtocolIEID(128):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		child := scope
		list, err := s38.BridgeUnmarshalAPERCSGIdListFrom(child)
		if err != nil {
			return out, fmt.Errorf("%s %w", "CSGIdList:", err)
		}
		padding, err := aper.CaptureOpenTypePadding(child)
		if err != nil {
			return out, err
		}
		_ = padding
		value := list
		out.rowCSGIdList = &value
		raw.RetainContents(&out.received)
	case s00.ProtocolIEID(137):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		bb := scope
		decoded, err := aper.DecodeEnumeratedAligned(bb, 4, true, aper.EnumerationSource{KnownExtensions: 0, Path: "PagingDRX"})
		value := s00.PagingDRX(decoded)
		if err != nil {
			return out, fmt.Errorf("%s %w", "DefaultPagingDRX:", err)
		}
		if _, err := aper.CompleteOpenTypeValue(bb, value); err != nil {
			return out, err
		}
		out.rowDefaultPagingDRX = &value
		raw.RetainContents(&out.received)
	case s00.ProtocolIEID(234):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		bb := scope
		decoded, err := aper.DecodeEnumeratedAligned(bb, 4, true, aper.EnumerationSource{KnownExtensions: 0, Path: "NBIoTDefaultPagingDRX"})
		value := s00.NBIoTDefaultPagingDRX(decoded)
		if err != nil {
			return out, fmt.Errorf("%s %w", "NBIoTDefaultPagingDRX:", err)
		}
		if _, err := aper.CompleteOpenTypeValue(bb, value); err != nil {
			return out, err
		}
		out.rowNBIoTDefaultPagingDRX = &value
		raw.RetainContents(&out.received)
	case s00.ProtocolIEID(292):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		child := scope
		list, err := s39.BridgeUnmarshalAPERConnectedengNBListFrom(child)
		if err != nil {
			return out, fmt.Errorf("%s %w", "ConnectedengNBToAddList:", err)
		}
		padding, err := aper.CaptureOpenTypePadding(child)
		if err != nil {
			return out, err
		}
		_ = padding
		value := list
		out.rowConnectedengNBToAddList = &value
		raw.RetainContents(&out.received)
	case s00.ProtocolIEID(293):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		child := scope
		list, err := s39.BridgeUnmarshalAPERConnectedengNBListFrom(child)
		if err != nil {
			return out, fmt.Errorf("%s %w", "ConnectedengNBToRemoveList:", err)
		}
		padding, err := aper.CaptureOpenTypePadding(child)
		if err != nil {
			return out, err
		}
		_ = padding
		value := list
		out.rowConnectedengNBToRemoveList = &value
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
func (v ENBConfigurationUpdateIEValue) encode() ([]byte, error) { return v.encodeFresh(false, nil) }
func (v ENBConfigurationUpdateIEValue) encodeFresh(fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
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
	case s00.ProtocolIEID(60):
		if v.rowENBname == nil {
			return nil, fmt.Errorf("%s missing value", "ENBConfigurationUpdateIEs.id-eNBname:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		candidate, err := (func(value s00.ENBname, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			v := struct{ Value s00.ENBname }{Value: value}
			_ = v
			err := func() error {
				if err := aper.EncodeAlphabetStringAligned(bb, string(v.Value), aper.PermittedAlphabet{' ', ' ', '\'', ')', '+', ':', '=', '=', '?', '?', 'A', 'Z', 'a', 'z'}, 1, 150, true, true); err != nil {
					return fmt.Errorf("encoding value: %w", err)
				}
				return nil
			}()
			if err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		})(*v.rowENBname, budget)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	case s00.ProtocolIEID(64):
		if v.rowSupportedTAs == nil {
			return nil, fmt.Errorf("%s missing value", "ENBConfigurationUpdateIEs.id-SupportedTAs:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		complete := SupportedTAsComplete{Value: *v.rowSupportedTAs}
		candidate, err := complete.marshalAPERBudget(budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	case s00.ProtocolIEID(128):
		if v.rowCSGIdList == nil {
			return nil, fmt.Errorf("%s missing value", "ENBConfigurationUpdateIEs.id-CSG-IdList:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		complete := s38.CSGIdListComplete{Value: *v.rowCSGIdList}
		candidate, err := s38.BridgeCSGIdListCompleteMethodMarshalAPERBudget(&complete, budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	case s00.ProtocolIEID(137):
		if v.rowDefaultPagingDRX == nil {
			return nil, fmt.Errorf("%s missing value", "ENBConfigurationUpdateIEs.id-DefaultPagingDRX:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		encodeBB := aper.NewBudgetBuffer(budget)
		if err := aper.EncodeEnumeratedAligned(encodeBB, int64(*v.rowDefaultPagingDRX), 4, true); err != nil {
			return nil, err
		}
		candidate := encodeBB.CompleteBytes()
		return candidate, nil
	case s00.ProtocolIEID(234):
		if v.rowNBIoTDefaultPagingDRX == nil {
			return nil, fmt.Errorf("%s missing value", "ENBConfigurationUpdateIEs.id-NB-IoT-DefaultPagingDRX:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		encodeBB := aper.NewBudgetBuffer(budget)
		if err := aper.EncodeEnumeratedAligned(encodeBB, int64(*v.rowNBIoTDefaultPagingDRX), 4, true); err != nil {
			return nil, err
		}
		candidate := encodeBB.CompleteBytes()
		return candidate, nil
	case s00.ProtocolIEID(292):
		if v.rowConnectedengNBToAddList == nil {
			return nil, fmt.Errorf("%s missing value", "ENBConfigurationUpdateIEs.id-ConnectedengNBToAddList:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		complete := s39.ConnectedengNBListComplete{Value: *v.rowConnectedengNBToAddList}
		candidate, err := s39.BridgeConnectedengNBListCompleteMethodMarshalAPERBudget(&complete, budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	case s00.ProtocolIEID(293):
		if v.rowConnectedengNBToRemoveList == nil {
			return nil, fmt.Errorf("%s missing value", "ENBConfigurationUpdateIEs.id-ConnectedengNBToRemoveList:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		complete := s39.ConnectedengNBListComplete{Value: *v.rowConnectedengNBToRemoveList}
		candidate, err := s39.BridgeConnectedengNBListCompleteMethodMarshalAPERBudget(&complete, budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	default:
		return nil, fmt.Errorf("%s id %d has no value", "ENBConfigurationUpdateIEValue:", v.id)
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
		list, err := s39.BridgeUnmarshalAPERECGIListForRestartFrom(child)
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
		list, err := s42.BridgeUnmarshalAPEREmergencyAreaIDListForRestartFrom(child)
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
		complete := s39.ECGIListForRestartComplete{Value: *v.rowECGIListForRestart}
		candidate, err := s39.BridgeECGIListForRestartCompleteMethodMarshalAPERBudget(&complete, budget, fresh)
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
		complete := s42.EmergencyAreaIDListForRestartComplete{Value: *v.rowEmergencyAreaIDListForRestart}
		candidate, err := s42.BridgeEmergencyAreaIDListForRestartCompleteMethodMarshalAPERBudget(&complete, budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	default:
		return nil, fmt.Errorf("%s id %d has no value", "PWSRestartIndicationIEValue:", v.id)
	}
}

type S1SetupRequestIEValue struct {
	id                        s00.ProtocolIEID
	received                  aper.WireSpan
	replay                    aper.Snapshot
	opaque                    aper.OpaqueOpenType
	isOpaque                  bool
	rowGlobalENBID            *s18.GlobalENBID
	rowENBname                *s00.ENBname
	rowSupportedTAs           *s31.SupportedTAs
	rowDefaultPagingDRX       *s00.PagingDRX
	rowCSGIdList              *s14.CSGIdList
	rowUERetentionInformation *s00.UERetentionInformation
	rowNBIoTDefaultPagingDRX  *s00.NBIoTDefaultPagingDRX
	rowConnectedengNBList     *s31.ConnectedengNBList
}

func (v S1SetupRequestIEValue) matchesID(id s00.ProtocolIEID, _ ...*aper.DecodeBudget) bool {
	if v.id != id {
		return false
	}
	if v.isOpaque {
		return true
	}
	switch id {
	case s00.ProtocolIEID(59):
		return v.rowGlobalENBID != nil
	case s00.ProtocolIEID(60):
		return v.rowENBname != nil
	case s00.ProtocolIEID(64):
		return v.rowSupportedTAs != nil
	case s00.ProtocolIEID(137):
		return v.rowDefaultPagingDRX != nil
	case s00.ProtocolIEID(128):
		return v.rowCSGIdList != nil
	case s00.ProtocolIEID(228):
		return v.rowUERetentionInformation != nil
	case s00.ProtocolIEID(234):
		return v.rowNBIoTDefaultPagingDRX != nil
	case s00.ProtocolIEID(291):
		return v.rowConnectedengNBList != nil
	}
	return false
}

// Opaque returns the retained opaque open value of S1SetupRequestIEValue and reports whether the opaque alternative is selected.
func (v *S1SetupRequestIEValue) Opaque() (aper.OpaqueOpenType, bool) {
	if v == nil || !v.isOpaque {
		return aper.OpaqueOpenType{}, false
	}
	return v.opaque, true
}
func (S1SetupRequestIEValue) rule() aper.SourceRule {
	return aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "S1SetupRequestIEs"}}
}
func (S1SetupRequestIEValue) reason(id s00.ProtocolIEID) aper.OpaqueReason {
	switch id {
	case s00.ProtocolIEID(59):
		return aper.UnknownSelector
	case s00.ProtocolIEID(60):
		return aper.UnknownSelector
	case s00.ProtocolIEID(64):
		return aper.UnknownSelector
	case s00.ProtocolIEID(137):
		return aper.UnknownSelector
	case s00.ProtocolIEID(128):
		return aper.UnknownSelector
	case s00.ProtocolIEID(228):
		return aper.UnknownSelector
	case s00.ProtocolIEID(234):
		return aper.UnknownSelector
	case s00.ProtocolIEID(291):
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
	case s00.ProtocolIEID(61):
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
	case s00.ProtocolIEID(230):
		return aper.NotInTable
	case s00.ProtocolIEID(231):
		return aper.NotInTable
	case s00.ProtocolIEID(232):
		return aper.NotInTable
	case s00.ProtocolIEID(233):
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

// AsGlobalENBID returns the selected GlobalENBID value of S1SetupRequestIEValue and reports whether that alternative is active.
func (v *S1SetupRequestIEValue) AsGlobalENBID() (*s18.GlobalENBID, bool) {
	if v == nil || v.id != s00.ProtocolIEID(59) || v.rowGlobalENBID == nil {
		return nil, false
	}
	return v.rowGlobalENBID, true
}

// AsENBname returns the selected ENBname value of S1SetupRequestIEValue and reports whether that alternative is active.
func (v *S1SetupRequestIEValue) AsENBname() (*s00.ENBname, bool) {
	if v == nil || v.id != s00.ProtocolIEID(60) || v.rowENBname == nil {
		return nil, false
	}
	return v.rowENBname, true
}

// AsSupportedTAs returns the selected SupportedTAs value of S1SetupRequestIEValue and reports whether that alternative is active.
func (v *S1SetupRequestIEValue) AsSupportedTAs() (*s31.SupportedTAs, bool) {
	if v == nil || v.id != s00.ProtocolIEID(64) || v.rowSupportedTAs == nil {
		return nil, false
	}
	return v.rowSupportedTAs, true
}

// AsDefaultPagingDRX returns the selected DefaultPagingDRX value of S1SetupRequestIEValue and reports whether that alternative is active.
func (v *S1SetupRequestIEValue) AsDefaultPagingDRX() (*s00.PagingDRX, bool) {
	if v == nil || v.id != s00.ProtocolIEID(137) || v.rowDefaultPagingDRX == nil {
		return nil, false
	}
	return v.rowDefaultPagingDRX, true
}

// AsCSGIdList returns the selected CSGIdList value of S1SetupRequestIEValue and reports whether that alternative is active.
func (v *S1SetupRequestIEValue) AsCSGIdList() (*s14.CSGIdList, bool) {
	if v == nil || v.id != s00.ProtocolIEID(128) || v.rowCSGIdList == nil {
		return nil, false
	}
	return v.rowCSGIdList, true
}

// AsUERetentionInformation returns the selected UERetentionInformation value of S1SetupRequestIEValue and reports whether that alternative is active.
func (v *S1SetupRequestIEValue) AsUERetentionInformation() (*s00.UERetentionInformation, bool) {
	if v == nil || v.id != s00.ProtocolIEID(228) || v.rowUERetentionInformation == nil {
		return nil, false
	}
	return v.rowUERetentionInformation, true
}

// AsNBIoTDefaultPagingDRX returns the selected NBIoTDefaultPagingDRX value of S1SetupRequestIEValue and reports whether that alternative is active.
func (v *S1SetupRequestIEValue) AsNBIoTDefaultPagingDRX() (*s00.NBIoTDefaultPagingDRX, bool) {
	if v == nil || v.id != s00.ProtocolIEID(234) || v.rowNBIoTDefaultPagingDRX == nil {
		return nil, false
	}
	return v.rowNBIoTDefaultPagingDRX, true
}

// AsConnectedengNBList returns the selected ConnectedengNBList value of S1SetupRequestIEValue and reports whether that alternative is active.
func (v *S1SetupRequestIEValue) AsConnectedengNBList() (*s31.ConnectedengNBList, bool) {
	if v == nil || v.id != s00.ProtocolIEID(291) || v.rowConnectedengNBList == nil {
		return nil, false
	}
	return v.rowConnectedengNBList, true
}
func (v S1SetupRequestIEValue) decode(id s00.ProtocolIEID, raw aper.OpaqueOpenType) (S1SetupRequestIEValue, error) {
	out := S1SetupRequestIEValue{id: id}
	switch id {
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
	case s00.ProtocolIEID(60):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		child := scope
		value, err := (func(bb *aper.BitBuffer) (s00.ENBname, error) {
			var v struct{ Value s00.ENBname }
			err := func() error {
				val_value, err := aper.DecodeAlphabetStringAligned(bb, aper.PermittedAlphabet{' ', ' ', '\'', ')', '+', ':', '=', '=', '?', '?', 'A', 'Z', 'a', 'z'}, 1, 150, true, true)
				if err != nil {
					return runtime.WrapDecodePath(err, "Value")
				}
				v.Value = val_value
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
		out.rowENBname = &value
		raw.RetainContents(&out.received)
	case s00.ProtocolIEID(64):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		child := scope
		list, err := BridgeUnmarshalAPERSupportedTAsFrom(child)
		if err != nil {
			return out, fmt.Errorf("%s %w", "SupportedTAs:", err)
		}
		padding, err := aper.CaptureOpenTypePadding(child)
		if err != nil {
			return out, err
		}
		_ = padding
		value := list
		out.rowSupportedTAs = &value
		raw.RetainContents(&out.received)
	case s00.ProtocolIEID(137):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		bb := scope
		decoded, err := aper.DecodeEnumeratedAligned(bb, 4, true, aper.EnumerationSource{KnownExtensions: 0, Path: "PagingDRX"})
		value := s00.PagingDRX(decoded)
		if err != nil {
			return out, fmt.Errorf("%s %w", "DefaultPagingDRX:", err)
		}
		if _, err := aper.CompleteOpenTypeValue(bb, value); err != nil {
			return out, err
		}
		out.rowDefaultPagingDRX = &value
		raw.RetainContents(&out.received)
	case s00.ProtocolIEID(128):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		child := scope
		list, err := s38.BridgeUnmarshalAPERCSGIdListFrom(child)
		if err != nil {
			return out, fmt.Errorf("%s %w", "CSGIdList:", err)
		}
		padding, err := aper.CaptureOpenTypePadding(child)
		if err != nil {
			return out, err
		}
		_ = padding
		value := list
		out.rowCSGIdList = &value
		raw.RetainContents(&out.received)
	case s00.ProtocolIEID(228):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		bb := scope
		decoded, err := aper.DecodeEnumeratedAligned(bb, 1, true, aper.EnumerationSource{KnownExtensions: 0, Path: "UERetentionInformation"})
		value := s00.UERetentionInformation(decoded)
		if err != nil {
			return out, fmt.Errorf("%s %w", "UERetentionInformation:", err)
		}
		if _, err := aper.CompleteOpenTypeValue(bb, value); err != nil {
			return out, err
		}
		out.rowUERetentionInformation = &value
		raw.RetainContents(&out.received)
	case s00.ProtocolIEID(234):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		bb := scope
		decoded, err := aper.DecodeEnumeratedAligned(bb, 4, true, aper.EnumerationSource{KnownExtensions: 0, Path: "NBIoTDefaultPagingDRX"})
		value := s00.NBIoTDefaultPagingDRX(decoded)
		if err != nil {
			return out, fmt.Errorf("%s %w", "NBIoTDefaultPagingDRX:", err)
		}
		if _, err := aper.CompleteOpenTypeValue(bb, value); err != nil {
			return out, err
		}
		out.rowNBIoTDefaultPagingDRX = &value
		raw.RetainContents(&out.received)
	case s00.ProtocolIEID(291):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		child := scope
		list, err := s39.BridgeUnmarshalAPERConnectedengNBListFrom(child)
		if err != nil {
			return out, fmt.Errorf("%s %w", "ConnectedengNBList:", err)
		}
		padding, err := aper.CaptureOpenTypePadding(child)
		if err != nil {
			return out, err
		}
		_ = padding
		value := list
		out.rowConnectedengNBList = &value
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
func (v S1SetupRequestIEValue) encode() ([]byte, error) { return v.encodeFresh(false, nil) }
func (v S1SetupRequestIEValue) encodeFresh(fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
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
	case s00.ProtocolIEID(59):
		if v.rowGlobalENBID == nil {
			return nil, fmt.Errorf("%s missing value", "S1SetupRequestIEs.id-Global-ENB-ID:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		candidate, err := s18.BridgeGlobalENBIDMethodMarshalAPERBudget(v.rowGlobalENBID, budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	case s00.ProtocolIEID(60):
		if v.rowENBname == nil {
			return nil, fmt.Errorf("%s missing value", "S1SetupRequestIEs.id-eNBname:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		candidate, err := (func(value s00.ENBname, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			v := struct{ Value s00.ENBname }{Value: value}
			_ = v
			err := func() error {
				if err := aper.EncodeAlphabetStringAligned(bb, string(v.Value), aper.PermittedAlphabet{' ', ' ', '\'', ')', '+', ':', '=', '=', '?', '?', 'A', 'Z', 'a', 'z'}, 1, 150, true, true); err != nil {
					return fmt.Errorf("encoding value: %w", err)
				}
				return nil
			}()
			if err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		})(*v.rowENBname, budget)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	case s00.ProtocolIEID(64):
		if v.rowSupportedTAs == nil {
			return nil, fmt.Errorf("%s missing value", "S1SetupRequestIEs.id-SupportedTAs:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		complete := SupportedTAsComplete{Value: *v.rowSupportedTAs}
		candidate, err := complete.marshalAPERBudget(budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	case s00.ProtocolIEID(137):
		if v.rowDefaultPagingDRX == nil {
			return nil, fmt.Errorf("%s missing value", "S1SetupRequestIEs.id-DefaultPagingDRX:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		encodeBB := aper.NewBudgetBuffer(budget)
		if err := aper.EncodeEnumeratedAligned(encodeBB, int64(*v.rowDefaultPagingDRX), 4, true); err != nil {
			return nil, err
		}
		candidate := encodeBB.CompleteBytes()
		return candidate, nil
	case s00.ProtocolIEID(128):
		if v.rowCSGIdList == nil {
			return nil, fmt.Errorf("%s missing value", "S1SetupRequestIEs.id-CSG-IdList:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		complete := s38.CSGIdListComplete{Value: *v.rowCSGIdList}
		candidate, err := s38.BridgeCSGIdListCompleteMethodMarshalAPERBudget(&complete, budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	case s00.ProtocolIEID(228):
		if v.rowUERetentionInformation == nil {
			return nil, fmt.Errorf("%s missing value", "S1SetupRequestIEs.id-UE-RetentionInformation:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		encodeBB := aper.NewBudgetBuffer(budget)
		if err := aper.EncodeEnumeratedAligned(encodeBB, int64(*v.rowUERetentionInformation), 1, true); err != nil {
			return nil, err
		}
		candidate := encodeBB.CompleteBytes()
		return candidate, nil
	case s00.ProtocolIEID(234):
		if v.rowNBIoTDefaultPagingDRX == nil {
			return nil, fmt.Errorf("%s missing value", "S1SetupRequestIEs.id-NB-IoT-DefaultPagingDRX:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		encodeBB := aper.NewBudgetBuffer(budget)
		if err := aper.EncodeEnumeratedAligned(encodeBB, int64(*v.rowNBIoTDefaultPagingDRX), 4, true); err != nil {
			return nil, err
		}
		candidate := encodeBB.CompleteBytes()
		return candidate, nil
	case s00.ProtocolIEID(291):
		if v.rowConnectedengNBList == nil {
			return nil, fmt.Errorf("%s missing value", "S1SetupRequestIEs.id-ConnectedengNBList:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		complete := s39.ConnectedengNBListComplete{Value: *v.rowConnectedengNBList}
		candidate, err := s39.BridgeConnectedengNBListCompleteMethodMarshalAPERBudget(&complete, budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	default:
		return nil, fmt.Errorf("%s id %d has no value", "S1SetupRequestIEValue:", v.id)
	}
}

type S1SetupResponseIEValue struct {
	id                          s00.ProtocolIEID
	received                    aper.WireSpan
	replay                      aper.Snapshot
	opaque                      aper.OpaqueOpenType
	isOpaque                    bool
	rowMMEname                  *s00.MMEname
	rowServedGUMMEIs            *s31.ServedGUMMEIs
	rowRelativeMMECapacity      *s00.RelativeMMECapacity
	rowMMERelaySupportIndicator *s00.MMERelaySupportIndicator
	rowCriticalityDiagnostics   *s22.CriticalityDiagnostics
	rowUERetentionInformation   *s00.UERetentionInformation
	rowServedDCNs               *s31.ServedDCNs
	rowIABSupported             *s00.IABSupported
}

func (v S1SetupResponseIEValue) matchesID(id s00.ProtocolIEID, _ ...*aper.DecodeBudget) bool {
	if v.id != id {
		return false
	}
	if v.isOpaque {
		return true
	}
	switch id {
	case s00.ProtocolIEID(61):
		return v.rowMMEname != nil
	case s00.ProtocolIEID(105):
		return v.rowServedGUMMEIs != nil
	case s00.ProtocolIEID(87):
		return v.rowRelativeMMECapacity != nil
	case s00.ProtocolIEID(163):
		return v.rowMMERelaySupportIndicator != nil
	case s00.ProtocolIEID(58):
		return v.rowCriticalityDiagnostics != nil
	case s00.ProtocolIEID(228):
		return v.rowUERetentionInformation != nil
	case s00.ProtocolIEID(247):
		return v.rowServedDCNs != nil
	case s00.ProtocolIEID(303):
		return v.rowIABSupported != nil
	}
	return false
}

// Opaque returns the retained opaque open value of S1SetupResponseIEValue and reports whether the opaque alternative is selected.
func (v *S1SetupResponseIEValue) Opaque() (aper.OpaqueOpenType, bool) {
	if v == nil || !v.isOpaque {
		return aper.OpaqueOpenType{}, false
	}
	return v.opaque, true
}
func (S1SetupResponseIEValue) rule() aper.SourceRule {
	return aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "S1SetupResponseIEs"}}
}
func (S1SetupResponseIEValue) reason(id s00.ProtocolIEID) aper.OpaqueReason {
	switch id {
	case s00.ProtocolIEID(61):
		return aper.UnknownSelector
	case s00.ProtocolIEID(105):
		return aper.UnknownSelector
	case s00.ProtocolIEID(87):
		return aper.UnknownSelector
	case s00.ProtocolIEID(163):
		return aper.UnknownSelector
	case s00.ProtocolIEID(58):
		return aper.UnknownSelector
	case s00.ProtocolIEID(228):
		return aper.UnknownSelector
	case s00.ProtocolIEID(247):
		return aper.UnknownSelector
	case s00.ProtocolIEID(303):
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

// AsMMEname returns the selected MMEname value of S1SetupResponseIEValue and reports whether that alternative is active.
func (v *S1SetupResponseIEValue) AsMMEname() (*s00.MMEname, bool) {
	if v == nil || v.id != s00.ProtocolIEID(61) || v.rowMMEname == nil {
		return nil, false
	}
	return v.rowMMEname, true
}

// AsServedGUMMEIs returns the selected ServedGUMMEIs value of S1SetupResponseIEValue and reports whether that alternative is active.
func (v *S1SetupResponseIEValue) AsServedGUMMEIs() (*s31.ServedGUMMEIs, bool) {
	if v == nil || v.id != s00.ProtocolIEID(105) || v.rowServedGUMMEIs == nil {
		return nil, false
	}
	return v.rowServedGUMMEIs, true
}

// AsRelativeMMECapacity returns the selected RelativeMMECapacity value of S1SetupResponseIEValue and reports whether that alternative is active.
func (v *S1SetupResponseIEValue) AsRelativeMMECapacity() (*s00.RelativeMMECapacity, bool) {
	if v == nil || v.id != s00.ProtocolIEID(87) || v.rowRelativeMMECapacity == nil {
		return nil, false
	}
	return v.rowRelativeMMECapacity, true
}

// AsMMERelaySupportIndicator returns the selected MMERelaySupportIndicator value of S1SetupResponseIEValue and reports whether that alternative is active.
func (v *S1SetupResponseIEValue) AsMMERelaySupportIndicator() (*s00.MMERelaySupportIndicator, bool) {
	if v == nil || v.id != s00.ProtocolIEID(163) || v.rowMMERelaySupportIndicator == nil {
		return nil, false
	}
	return v.rowMMERelaySupportIndicator, true
}

// AsCriticalityDiagnostics returns the selected CriticalityDiagnostics value of S1SetupResponseIEValue and reports whether that alternative is active.
func (v *S1SetupResponseIEValue) AsCriticalityDiagnostics() (*s22.CriticalityDiagnostics, bool) {
	if v == nil || v.id != s00.ProtocolIEID(58) || v.rowCriticalityDiagnostics == nil {
		return nil, false
	}
	return v.rowCriticalityDiagnostics, true
}

// AsUERetentionInformation returns the selected UERetentionInformation value of S1SetupResponseIEValue and reports whether that alternative is active.
func (v *S1SetupResponseIEValue) AsUERetentionInformation() (*s00.UERetentionInformation, bool) {
	if v == nil || v.id != s00.ProtocolIEID(228) || v.rowUERetentionInformation == nil {
		return nil, false
	}
	return v.rowUERetentionInformation, true
}

// AsServedDCNs returns the selected ServedDCNs value of S1SetupResponseIEValue and reports whether that alternative is active.
func (v *S1SetupResponseIEValue) AsServedDCNs() (*s31.ServedDCNs, bool) {
	if v == nil || v.id != s00.ProtocolIEID(247) || v.rowServedDCNs == nil {
		return nil, false
	}
	return v.rowServedDCNs, true
}

// AsIABSupported returns the selected IABSupported value of S1SetupResponseIEValue and reports whether that alternative is active.
func (v *S1SetupResponseIEValue) AsIABSupported() (*s00.IABSupported, bool) {
	if v == nil || v.id != s00.ProtocolIEID(303) || v.rowIABSupported == nil {
		return nil, false
	}
	return v.rowIABSupported, true
}
func (v S1SetupResponseIEValue) decode(id s00.ProtocolIEID, raw aper.OpaqueOpenType) (S1SetupResponseIEValue, error) {
	out := S1SetupResponseIEValue{id: id}
	switch id {
	case s00.ProtocolIEID(61):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		child := scope
		value, err := (func(bb *aper.BitBuffer) (s00.MMEname, error) {
			var v struct{ Value s00.MMEname }
			err := func() error {
				val_value, err := aper.DecodeAlphabetStringAligned(bb, aper.PermittedAlphabet{' ', ' ', '\'', ')', '+', ':', '=', '=', '?', '?', 'A', 'Z', 'a', 'z'}, 1, 150, true, true)
				if err != nil {
					return runtime.WrapDecodePath(err, "Value")
				}
				v.Value = val_value
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
		out.rowMMEname = &value
		raw.RetainContents(&out.received)
	case s00.ProtocolIEID(105):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		child := scope
		list, err := s43.BridgeUnmarshalAPERServedGUMMEIsFrom(child)
		if err != nil {
			return out, fmt.Errorf("%s %w", "ServedGUMMEIs:", err)
		}
		padding, err := aper.CaptureOpenTypePadding(child)
		if err != nil {
			return out, err
		}
		_ = padding
		value := list
		out.rowServedGUMMEIs = &value
		raw.RetainContents(&out.received)
	case s00.ProtocolIEID(87):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		bb := scope
		decoded, err := aper.DecodeIntegerAligned(bb, s07.BridgeInt64Ptr(0), s07.BridgeInt64Ptr(255), false)
		value := s00.RelativeMMECapacity(decoded)
		if err != nil {
			return out, fmt.Errorf("%s %w", "RelativeMMECapacity:", err)
		}
		if _, err := aper.CompleteOpenTypeValue(bb, value); err != nil {
			return out, err
		}
		out.rowRelativeMMECapacity = &value
		raw.RetainContents(&out.received)
	case s00.ProtocolIEID(163):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		bb := scope
		decoded, err := aper.DecodeEnumeratedAligned(bb, 1, true, aper.EnumerationSource{KnownExtensions: 0, Path: "MMERelaySupportIndicator"})
		value := s00.MMERelaySupportIndicator(decoded)
		if err != nil {
			return out, fmt.Errorf("%s %w", "MMERelaySupportIndicator:", err)
		}
		if _, err := aper.CompleteOpenTypeValue(bb, value); err != nil {
			return out, err
		}
		out.rowMMERelaySupportIndicator = &value
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
	case s00.ProtocolIEID(228):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		bb := scope
		decoded, err := aper.DecodeEnumeratedAligned(bb, 1, true, aper.EnumerationSource{KnownExtensions: 0, Path: "UERetentionInformation"})
		value := s00.UERetentionInformation(decoded)
		if err != nil {
			return out, fmt.Errorf("%s %w", "UERetentionInformation:", err)
		}
		if _, err := aper.CompleteOpenTypeValue(bb, value); err != nil {
			return out, err
		}
		out.rowUERetentionInformation = &value
		raw.RetainContents(&out.received)
	case s00.ProtocolIEID(247):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		child := scope
		list, err := s43.BridgeUnmarshalAPERServedDCNsFrom(child)
		if err != nil {
			return out, fmt.Errorf("%s %w", "ServedDCNs:", err)
		}
		padding, err := aper.CaptureOpenTypePadding(child)
		if err != nil {
			return out, err
		}
		_ = padding
		value := list
		out.rowServedDCNs = &value
		raw.RetainContents(&out.received)
	case s00.ProtocolIEID(303):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		bb := scope
		decoded, err := aper.DecodeEnumeratedAligned(bb, 1, true, aper.EnumerationSource{KnownExtensions: 0, Path: "IABSupported"})
		value := s00.IABSupported(decoded)
		if err != nil {
			return out, fmt.Errorf("%s %w", "IABSupported:", err)
		}
		if _, err := aper.CompleteOpenTypeValue(bb, value); err != nil {
			return out, err
		}
		out.rowIABSupported = &value
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
func (v S1SetupResponseIEValue) encode() ([]byte, error) { return v.encodeFresh(false, nil) }
func (v S1SetupResponseIEValue) encodeFresh(fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
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
	case s00.ProtocolIEID(61):
		if v.rowMMEname == nil {
			return nil, fmt.Errorf("%s missing value", "S1SetupResponseIEs.id-MMEname:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		candidate, err := (func(value s00.MMEname, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			v := struct{ Value s00.MMEname }{Value: value}
			_ = v
			err := func() error {
				if err := aper.EncodeAlphabetStringAligned(bb, string(v.Value), aper.PermittedAlphabet{' ', ' ', '\'', ')', '+', ':', '=', '=', '?', '?', 'A', 'Z', 'a', 'z'}, 1, 150, true, true); err != nil {
					return fmt.Errorf("encoding value: %w", err)
				}
				return nil
			}()
			if err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		})(*v.rowMMEname, budget)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	case s00.ProtocolIEID(105):
		if v.rowServedGUMMEIs == nil {
			return nil, fmt.Errorf("%s missing value", "S1SetupResponseIEs.id-ServedGUMMEIs:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		complete := s43.ServedGUMMEIsComplete{Value: *v.rowServedGUMMEIs}
		candidate, err := s43.BridgeServedGUMMEIsCompleteMethodMarshalAPERBudget(&complete, budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	case s00.ProtocolIEID(87):
		if v.rowRelativeMMECapacity == nil {
			return nil, fmt.Errorf("%s missing value", "S1SetupResponseIEs.id-RelativeMMECapacity:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		encodeBB := aper.NewBudgetBuffer(budget)
		if err := aper.EncodeIntegerAligned(encodeBB, int64(*v.rowRelativeMMECapacity), s07.BridgeInt64Ptr(0), s07.BridgeInt64Ptr(255), false); err != nil {
			return nil, err
		}
		candidate := encodeBB.CompleteBytes()
		return candidate, nil
	case s00.ProtocolIEID(163):
		if v.rowMMERelaySupportIndicator == nil {
			return nil, fmt.Errorf("%s missing value", "S1SetupResponseIEs.id-MMERelaySupportIndicator:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		encodeBB := aper.NewBudgetBuffer(budget)
		if err := aper.EncodeEnumeratedAligned(encodeBB, int64(*v.rowMMERelaySupportIndicator), 1, true); err != nil {
			return nil, err
		}
		candidate := encodeBB.CompleteBytes()
		return candidate, nil
	case s00.ProtocolIEID(58):
		if v.rowCriticalityDiagnostics == nil {
			return nil, fmt.Errorf("%s missing value", "S1SetupResponseIEs.id-CriticalityDiagnostics:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		candidate, err := s22.BridgeCriticalityDiagnosticsMethodMarshalAPERBudget(v.rowCriticalityDiagnostics, budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	case s00.ProtocolIEID(228):
		if v.rowUERetentionInformation == nil {
			return nil, fmt.Errorf("%s missing value", "S1SetupResponseIEs.id-UE-RetentionInformation:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		encodeBB := aper.NewBudgetBuffer(budget)
		if err := aper.EncodeEnumeratedAligned(encodeBB, int64(*v.rowUERetentionInformation), 1, true); err != nil {
			return nil, err
		}
		candidate := encodeBB.CompleteBytes()
		return candidate, nil
	case s00.ProtocolIEID(247):
		if v.rowServedDCNs == nil {
			return nil, fmt.Errorf("%s missing value", "S1SetupResponseIEs.id-ServedDCNs:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		complete := s43.ServedDCNsComplete{Value: *v.rowServedDCNs}
		candidate, err := s43.BridgeServedDCNsCompleteMethodMarshalAPERBudget(&complete, budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	case s00.ProtocolIEID(303):
		if v.rowIABSupported == nil {
			return nil, fmt.Errorf("%s missing value", "S1SetupResponseIEs.id-IAB-Supported:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		encodeBB := aper.NewBudgetBuffer(budget)
		if err := aper.EncodeEnumeratedAligned(encodeBB, int64(*v.rowIABSupported), 1, true); err != nil {
			return nil, err
		}
		candidate := encodeBB.CompleteBytes()
		return candidate, nil
	default:
		return nil, fmt.Errorf("%s id %d has no value", "S1SetupResponseIEValue:", v.id)
	}
}

type ENBConfigurationUpdateIETable struct{}

func ENBConfigurationUpdateIEs() ENBConfigurationUpdateIETable {
	return ENBConfigurationUpdateIETable{}
}

// ID returns the ASN.1 object-set identity of ENBConfigurationUpdateIETable.
func (ENBConfigurationUpdateIETable) ID() s00.TableID {
	return func() s00.TableID {
		sealed := s00.TableID{}
		*s00.BridgeTableIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "ENBConfigurationUpdateIEs"}
		return sealed
	}()
}

// Table returns the ASN.1 object-set table described by ENBConfigurationUpdateIETable.
func (ENBConfigurationUpdateIETable) Table() s00.ENBConfigurationUpdateIEValueIETable {
	return func() s00.ENBConfigurationUpdateIEValueIETable {
		sealed := s00.ENBConfigurationUpdateIEValueIETable{}
		*s00.BridgeENBConfigurationUpdateIEValueIETableFieldBound(&sealed) = true
		return sealed
	}()
}
func (ENBConfigurationUpdateIETable) infoENBname() s00.FieldInfo {
	return s00.FieldInfo{Table: ENBConfigurationUpdateIEs().ID(), ID: s00.ProtocolIEID(60), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "ENBname"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "ENBConfigurationUpdateIEs", Row: "id-eNBname"}}}
}

// ENBname returns the typed binding for the ENBname row of ENBConfigurationUpdateIETable.
func (t ENBConfigurationUpdateIETable) ENBname() ENBConfigurationUpdateENBnameIEBinding {
	return ENBConfigurationUpdateENBnameIEBinding{info: t.infoENBname(), codec: func() s00.ENBnameValueCodec {
		sealed := s00.ENBnameValueCodec{}
		*s00.BridgeENBnameValueCodecFieldPath(&sealed) = "ENBname"
		*s00.BridgeENBnameValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.ENBname, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s00.ENBname
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("ENBname")
			var zero ENBConfigurationUpdateIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(60), raw)
			if err != nil {
				var empty s00.ENBname
				return empty, runtime.WrapDecodePath(err, "ENBname")
			}
			value, ok := decoded.AsENBname()
			if !ok {
				var empty s00.ENBname
				return empty, fmt.Errorf("binding ENBConfigurationUpdateIEs.id-eNBname: no selected value")
			}
			return *value, nil
		}
		*s00.BridgeENBnameValueCodecFieldEncode(&sealed) = func(value s00.ENBname, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (ENBConfigurationUpdateIEValue{id: s00.ProtocolIEID(60), rowENBname: &value}).encodeFresh(fresh, budget)
		}
		*s00.BridgeENBnameValueCodecFieldCapture(&sealed) = func(v s00.ENBname, options aper.DecodeState) (s00.ENBname, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f :=
				s.Begin()
			s00.BridgeCaptureS1APENBname(&v, &s)
			var root aper.Snapshot
			s.
				End(f, &root, false)
			return v, root
		}
		*s00.BridgeENBnameValueCodecFieldCompare(&sealed) = func(v s00.ENBname, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s02.BridgeCompareS1APENBname(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s00.BridgeENBnameValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ENBname"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s00.ENBname) ENBConfigurationUpdateIEValue {
			return ENBConfigurationUpdateIEValue{id: s00.ProtocolIEID(60), rowENBname: &value}
		}, get: func(value *ENBConfigurationUpdateIEValue) (*s00.ENBname, bool) { return value.AsENBname() }}
}
func (ENBConfigurationUpdateIETable) infoSupportedTAs() s00.FieldInfo {
	return s00.FieldInfo{Table: ENBConfigurationUpdateIEs().ID(), ID: s00.ProtocolIEID(64), Criticality: s00.CriticalityReject, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "SupportedTAs"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "ENBConfigurationUpdateIEs", Row: "id-SupportedTAs"}}}
}

// SupportedTAs returns the typed binding for the SupportedTAs row of ENBConfigurationUpdateIETable.
func (t ENBConfigurationUpdateIETable) SupportedTAs() ENBConfigurationUpdateSupportedTAsIEBinding {
	return ENBConfigurationUpdateSupportedTAsIEBinding{info: t.infoSupportedTAs(), codec: func() s31.SupportedTAsValueCodec {
		sealed := s31.SupportedTAsValueCodec{}
		*s31.BridgeSupportedTAsValueCodecFieldPath(&sealed) = "SupportedTAs"
		*s31.BridgeSupportedTAsValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s31.SupportedTAs, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s31.SupportedTAs
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("SupportedTAs")
			var zero ENBConfigurationUpdateIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(64), raw)
			if err != nil {
				var empty s31.SupportedTAs
				return empty, runtime.WrapDecodePath(err, "SupportedTAs")
			}
			value, ok := decoded.AsSupportedTAs()
			if !ok {
				var empty s31.SupportedTAs
				return empty, fmt.Errorf("binding ENBConfigurationUpdateIEs.id-SupportedTAs: no selected value")
			}
			return *value, nil
		}
		*s31.BridgeSupportedTAsValueCodecFieldEncode(&sealed) = func(value s31.SupportedTAs, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (ENBConfigurationUpdateIEValue{id: s00.ProtocolIEID(64), rowSupportedTAs: &value}).encodeFresh(fresh, budget)
		}
		*s31.BridgeSupportedTAsValueCodecFieldCapture(&sealed) = func(v s31.SupportedTAs, options aper.DecodeState) (s31.SupportedTAs, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s31.BridgeCaptureS1APSupportedTAs(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s31.BridgeSupportedTAsValueCodecFieldCompare(&sealed) = func(v s31.SupportedTAs, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s31.BridgeCompareS1APSupportedTAs(&v, &s)
			s.End(f, root, false)
			return s.Plan(),
				s.
					BudgetValue()
		}
		*s31.BridgeSupportedTAsValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:SupportedTAs"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s31.SupportedTAs) ENBConfigurationUpdateIEValue {
			return ENBConfigurationUpdateIEValue{id: s00.ProtocolIEID(64), rowSupportedTAs: &value}
		}, get: func(value *ENBConfigurationUpdateIEValue) (*s31.SupportedTAs, bool) { return value.AsSupportedTAs() }}
}
func (ENBConfigurationUpdateIETable) infoCSGIdList() s00.FieldInfo {
	return s00.FieldInfo{Table: ENBConfigurationUpdateIEs().ID(), ID: s00.ProtocolIEID(128), Criticality: s00.CriticalityReject, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "CSG-IdList"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "ENBConfigurationUpdateIEs", Row: "id-CSG-IdList"}}}
}

// CSGIdList returns the typed binding for the CSGIdList row of ENBConfigurationUpdateIETable.
func (t ENBConfigurationUpdateIETable) CSGIdList() ENBConfigurationUpdateCSGIdListIEBinding {
	return ENBConfigurationUpdateCSGIdListIEBinding{info: t.infoCSGIdList(), codec: func() s14.CSGIdListValueCodec {
		sealed := s14.CSGIdListValueCodec{}
		*s14.BridgeCSGIdListValueCodecFieldPath(&sealed) = "CSGIdList"
		*s14.BridgeCSGIdListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s14.CSGIdList, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s14.CSGIdList
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("CSGIdList")
			var zero ENBConfigurationUpdateIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(128), raw)
			if err != nil {
				var empty s14.CSGIdList
				return empty, runtime.WrapDecodePath(err, "CSGIdList")
			}
			value, ok := decoded.AsCSGIdList()
			if !ok {
				var empty s14.CSGIdList
				return empty, fmt.Errorf("binding ENBConfigurationUpdateIEs.id-CSG-IdList: no selected value")
			}
			return *value, nil
		}
		*s14.BridgeCSGIdListValueCodecFieldEncode(&sealed) = func(value s14.CSGIdList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (ENBConfigurationUpdateIEValue{id: s00.ProtocolIEID(128), rowCSGIdList: &value}).encodeFresh(fresh, budget)
		}
		*s14.BridgeCSGIdListValueCodecFieldCapture(&sealed) = func(v s14.CSGIdList, options aper.DecodeState) (s14.CSGIdList, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.
				Begin()
			s21.BridgeCaptureS1APCSGIdList(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s14.BridgeCSGIdListValueCodecFieldCompare(&sealed) = func(v s14.CSGIdList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s22.BridgeCompareS1APCSGIdList(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s14.BridgeCSGIdListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:CSGIdList"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s14.CSGIdList) ENBConfigurationUpdateIEValue {
			return ENBConfigurationUpdateIEValue{id: s00.ProtocolIEID(128), rowCSGIdList: &value}
		}, get: func(value *ENBConfigurationUpdateIEValue) (*s14.CSGIdList, bool) { return value.AsCSGIdList() }}
}
func (ENBConfigurationUpdateIETable) infoDefaultPagingDRX() s00.FieldInfo {
	return s00.FieldInfo{Table: ENBConfigurationUpdateIEs().ID(), ID: s00.ProtocolIEID(137), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "PagingDRX"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "ENBConfigurationUpdateIEs", Row: "id-DefaultPagingDRX"}}}
}

// DefaultPagingDRX returns the typed binding for the DefaultPagingDRX row of ENBConfigurationUpdateIETable.
func (t ENBConfigurationUpdateIETable) DefaultPagingDRX() ENBConfigurationUpdatePagingDRXIEBinding {
	return ENBConfigurationUpdatePagingDRXIEBinding{info: t.infoDefaultPagingDRX(), codec: func() s01.PagingDRXValueCodec {
		sealed := s01.PagingDRXValueCodec{}
		*s01.BridgePagingDRXValueCodecFieldPath(&sealed) = "PagingDRX"
		*s01.BridgePagingDRXValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.PagingDRX, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s00.PagingDRX
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("PagingDRX")
			var zero ENBConfigurationUpdateIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(137), raw)
			if err != nil {
				var empty s00.PagingDRX
				return empty, runtime.WrapDecodePath(err, "PagingDRX")
			}
			value, ok := decoded.AsDefaultPagingDRX()
			if !ok {
				var empty s00.PagingDRX
				return empty, fmt.Errorf("binding ENBConfigurationUpdateIEs.id-DefaultPagingDRX: no selected value")
			}
			return *value, nil
		}
		*s01.BridgePagingDRXValueCodecFieldEncode(&sealed) = func(value s00.PagingDRX, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (ENBConfigurationUpdateIEValue{id: s00.ProtocolIEID(137), rowDefaultPagingDRX: &value}).encodeFresh(fresh, budget)
		}
		*s01.BridgePagingDRXValueCodecFieldCapture(&sealed) = func(v s00.PagingDRX, options aper.DecodeState) (s00.PagingDRX, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.
				Begin()
			s00.BridgeCaptureS1APPagingDRX(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s01.BridgePagingDRXValueCodecFieldCompare(&sealed) = func(v s00.PagingDRX, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s02.BridgeCompareS1APPagingDRX(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s01.BridgePagingDRXValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:PagingDRX"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s00.PagingDRX) ENBConfigurationUpdateIEValue {
			return ENBConfigurationUpdateIEValue{id: s00.ProtocolIEID(137), rowDefaultPagingDRX: &value}
		}, get: func(value *ENBConfigurationUpdateIEValue) (*s00.PagingDRX, bool) { return value.AsDefaultPagingDRX() }}
}
func (ENBConfigurationUpdateIETable) infoNBIoTDefaultPagingDRX() s00.FieldInfo {
	return s00.FieldInfo{Table: ENBConfigurationUpdateIEs().ID(), ID: s00.ProtocolIEID(234), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "NB-IoT-DefaultPagingDRX"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "ENBConfigurationUpdateIEs", Row: "id-NB-IoT-DefaultPagingDRX"}}}
}

// NBIoTDefaultPagingDRX returns the typed binding for the NBIoTDefaultPagingDRX row of ENBConfigurationUpdateIETable.
func (t ENBConfigurationUpdateIETable) NBIoTDefaultPagingDRX() ENBConfigurationUpdateNBIoTDefaultPagingDRXIEBinding {
	return ENBConfigurationUpdateNBIoTDefaultPagingDRXIEBinding{info: t.infoNBIoTDefaultPagingDRX(), codec: func() s01.NBIoTDefaultPagingDRXValueCodec {
		sealed := s01.NBIoTDefaultPagingDRXValueCodec{}
		*s01.BridgeNBIoTDefaultPagingDRXValueCodecFieldPath(&sealed) = "NBIoTDefaultPagingDRX"
		*s01.BridgeNBIoTDefaultPagingDRXValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.NBIoTDefaultPagingDRX, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s00.NBIoTDefaultPagingDRX
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("NBIoTDefaultPagingDRX")
			var zero ENBConfigurationUpdateIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(234), raw)
			if err != nil {
				var empty s00.NBIoTDefaultPagingDRX
				return empty, runtime.WrapDecodePath(err, "NBIoTDefaultPagingDRX")
			}
			value, ok := decoded.AsNBIoTDefaultPagingDRX()
			if !ok {
				var empty s00.NBIoTDefaultPagingDRX
				return empty, fmt.Errorf("binding ENBConfigurationUpdateIEs.id-NB-IoT-DefaultPagingDRX: no selected value")
			}
			return *value, nil
		}
		*s01.BridgeNBIoTDefaultPagingDRXValueCodecFieldEncode(&sealed) = func(value s00.NBIoTDefaultPagingDRX, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (ENBConfigurationUpdateIEValue{id: s00.ProtocolIEID(234), rowNBIoTDefaultPagingDRX: &value}).encodeFresh(fresh, budget)
		}
		*s01.BridgeNBIoTDefaultPagingDRXValueCodecFieldCapture(&sealed) = func(v s00.NBIoTDefaultPagingDRX, options aper.DecodeState) (s00.NBIoTDefaultPagingDRX, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s00.BridgeCaptureS1APNBIoTDefaultPagingDRX(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)

			return v, root
		}
		*s01.BridgeNBIoTDefaultPagingDRXValueCodecFieldCompare(&sealed) = func(v s00.NBIoTDefaultPagingDRX, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s02.BridgeCompareS1APNBIoTDefaultPagingDRX(&v, &s)
			s.End(f, root, false)

			return s.Plan(), s.BudgetValue()
		}
		*s01.BridgeNBIoTDefaultPagingDRXValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:NBIoTDefaultPagingDRX"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s00.NBIoTDefaultPagingDRX) ENBConfigurationUpdateIEValue {
			return ENBConfigurationUpdateIEValue{id: s00.ProtocolIEID(234), rowNBIoTDefaultPagingDRX: &value}
		}, get: func(value *ENBConfigurationUpdateIEValue) (*s00.NBIoTDefaultPagingDRX, bool) {
			return value.AsNBIoTDefaultPagingDRX()
		}}
}
func (ENBConfigurationUpdateIETable) infoConnectedengNBToAddList() s00.FieldInfo {
	return s00.FieldInfo{Table: ENBConfigurationUpdateIEs().ID(), ID: s00.ProtocolIEID(292), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "ConnectedengNBList"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "ENBConfigurationUpdateIEs", Row: "id-ConnectedengNBToAddList"}}}
}

// ConnectedengNBToAddList returns the typed binding for the ConnectedengNBToAddList row of ENBConfigurationUpdateIETable.
func (t ENBConfigurationUpdateIETable) ConnectedengNBToAddList() ENBConfigurationUpdateConnectedengNBListIEBinding {
	return ENBConfigurationUpdateConnectedengNBListIEBinding{info: t.infoConnectedengNBToAddList(), codec: func() s31.ConnectedengNBListValueCodec {
		sealed := s31.ConnectedengNBListValueCodec{}
		*s31.BridgeConnectedengNBListValueCodecFieldPath(&sealed) = "ConnectedengNBList"
		*s31.BridgeConnectedengNBListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s31.ConnectedengNBList, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s31.ConnectedengNBList
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("ConnectedengNBList")
			var zero ENBConfigurationUpdateIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(292), raw)
			if err != nil {
				var empty s31.ConnectedengNBList
				return empty, runtime.WrapDecodePath(err, "ConnectedengNBList")
			}
			value, ok := decoded.AsConnectedengNBToAddList()
			if !ok {
				var empty s31.ConnectedengNBList
				return empty, fmt.Errorf("binding ENBConfigurationUpdateIEs.id-ConnectedengNBToAddList: no selected value")
			}
			return *value, nil
		}
		*s31.BridgeConnectedengNBListValueCodecFieldEncode(&sealed) = func(value s31.ConnectedengNBList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (ENBConfigurationUpdateIEValue{id: s00.ProtocolIEID(292), rowConnectedengNBToAddList: &value}).encodeFresh(fresh, budget)
		}
		*s31.BridgeConnectedengNBListValueCodecFieldCapture(&sealed) = func(v s31.ConnectedengNBList, options aper.DecodeState) (s31.ConnectedengNBList, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s31.BridgeCaptureS1APConnectedengNBList(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v,

				root
		}
		*s31.BridgeConnectedengNBListValueCodecFieldCompare(&sealed) = func(v s31.ConnectedengNBList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s31.BridgeCompareS1APConnectedengNBList(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s31.BridgeConnectedengNBListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ConnectedengNBList"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s31.ConnectedengNBList) ENBConfigurationUpdateIEValue {
			return ENBConfigurationUpdateIEValue{id: s00.ProtocolIEID(292), rowConnectedengNBToAddList: &value}
		}, get: func(value *ENBConfigurationUpdateIEValue) (*s31.ConnectedengNBList, bool) {
			return value.AsConnectedengNBToAddList()
		}}
}
func (ENBConfigurationUpdateIETable) infoConnectedengNBToRemoveList() s00.FieldInfo {
	return s00.FieldInfo{Table: ENBConfigurationUpdateIEs().ID(), ID: s00.ProtocolIEID(293), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "ConnectedengNBList"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "ENBConfigurationUpdateIEs", Row: "id-ConnectedengNBToRemoveList"}}}
}

// ConnectedengNBToRemoveList returns the typed binding for the ConnectedengNBToRemoveList row of ENBConfigurationUpdateIETable.
func (t ENBConfigurationUpdateIETable) ConnectedengNBToRemoveList() ENBConfigurationUpdateConnectedengNBListIEBinding {
	return ENBConfigurationUpdateConnectedengNBListIEBinding{info: t.infoConnectedengNBToRemoveList(), codec: func() s31.ConnectedengNBListValueCodec {
		sealed := s31.ConnectedengNBListValueCodec{}
		*s31.BridgeConnectedengNBListValueCodecFieldPath(&sealed) = "ConnectedengNBList"
		*s31.BridgeConnectedengNBListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s31.ConnectedengNBList, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s31.ConnectedengNBList
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("ConnectedengNBList")
			var zero ENBConfigurationUpdateIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(293), raw)
			if err != nil {
				var empty s31.ConnectedengNBList
				return empty, runtime.WrapDecodePath(err, "ConnectedengNBList")
			}
			value, ok := decoded.AsConnectedengNBToRemoveList()
			if !ok {
				var empty s31.ConnectedengNBList
				return empty, fmt.Errorf("binding ENBConfigurationUpdateIEs.id-ConnectedengNBToRemoveList: no selected value")
			}
			return *value, nil
		}
		*s31.BridgeConnectedengNBListValueCodecFieldEncode(&sealed) = func(value s31.ConnectedengNBList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (ENBConfigurationUpdateIEValue{id: s00.ProtocolIEID(293), rowConnectedengNBToRemoveList: &value}).encodeFresh(fresh, budget)
		}
		*s31.BridgeConnectedengNBListValueCodecFieldCapture(&sealed) = func(v s31.ConnectedengNBList, options aper.DecodeState) (s31.ConnectedengNBList, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s31.BridgeCaptureS1APConnectedengNBList(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v,

				root
		}
		*s31.BridgeConnectedengNBListValueCodecFieldCompare(&sealed) = func(v s31.ConnectedengNBList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s31.BridgeCompareS1APConnectedengNBList(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s31.BridgeConnectedengNBListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ConnectedengNBList"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s31.ConnectedengNBList) ENBConfigurationUpdateIEValue {
			return ENBConfigurationUpdateIEValue{id: s00.ProtocolIEID(293), rowConnectedengNBToRemoveList: &value}
		}, get: func(value *ENBConfigurationUpdateIEValue) (*s31.ConnectedengNBList, bool) {
			return value.AsConnectedengNBToRemoveList()
		}}
}

// NewOpaque constructs an owned opaque field for an identifier without a typed row in ENBConfigurationUpdateIETable.
func (t ENBConfigurationUpdateIETable) NewOpaque(id s00.ProtocolIEID, criticality s00.Criticality, data []byte) (ENBConfigurationUpdateIEField, error) {
	if id < 0 || id > 65535 || criticality < 0 || criticality > 2 {
		return ENBConfigurationUpdateIEField{}, aper.OperationError(fmt.Errorf("invalid opaque IE selector or criticality"), "Opaque")
	}
	switch id {
	case s00.ProtocolIEID(60):
		return ENBConfigurationUpdateIEField{}, aper.OperationError(fmt.Errorf("known IE id-eNBname requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(64):
		return ENBConfigurationUpdateIEField{}, aper.OperationError(fmt.Errorf("known IE id-SupportedTAs requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(128):
		return ENBConfigurationUpdateIEField{}, aper.OperationError(fmt.Errorf("known IE id-CSG-IdList requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(137):
		return ENBConfigurationUpdateIEField{}, aper.OperationError(fmt.Errorf("known IE id-DefaultPagingDRX requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(234):
		return ENBConfigurationUpdateIEField{}, aper.OperationError(fmt.Errorf("known IE id-NB-IoT-DefaultPagingDRX requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(292):
		return ENBConfigurationUpdateIEField{}, aper.OperationError(fmt.Errorf("known IE id-ConnectedengNBToAddList requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(293):
		return ENBConfigurationUpdateIEField{}, aper.OperationError(fmt.Errorf("known IE id-ConnectedengNBToRemoveList requires its typed binding"), "Opaque")
	default:
		budget, err := aper.BuildBudget()
		if err != nil {
			return ENBConfigurationUpdateIEField{}, aper.OperationError(err, "Opaque")
		}
		opaque, err := aper.BuildOpaqueOpenType(data, budget)
		if err != nil {
			return ENBConfigurationUpdateIEField{}, aper.OperationError(err, "Opaque")
		}
		return ENBConfigurationUpdateIEField{Id: id, Criticality: criticality, Value: ENBConfigurationUpdateIEValue{id: id, opaque: opaque, isOpaque: true}}, aper.OperationError(nil, "Opaque")
	}
}

type MMEConfigurationUpdateIETable struct{}

func MMEConfigurationUpdateIEs() MMEConfigurationUpdateIETable {
	return MMEConfigurationUpdateIETable{}
}

// ID returns the ASN.1 object-set identity of MMEConfigurationUpdateIETable.
func (MMEConfigurationUpdateIETable) ID() s00.TableID {
	return func() s00.TableID {
		sealed := s00.TableID{}
		*s00.BridgeTableIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "MMEConfigurationUpdateIEs"}
		return sealed
	}()
}

// Table returns the ASN.1 object-set table described by MMEConfigurationUpdateIETable.
func (MMEConfigurationUpdateIETable) Table() s00.MMEConfigurationUpdateIEValueIETable {
	return func() s00.MMEConfigurationUpdateIEValueIETable {
		sealed := s00.MMEConfigurationUpdateIEValueIETable{}
		*s00.BridgeMMEConfigurationUpdateIEValueIETableFieldBound(&sealed) = true
		return sealed
	}()
}
func (MMEConfigurationUpdateIETable) infoMMEname() s00.FieldInfo {
	return s00.FieldInfo{Table: MMEConfigurationUpdateIEs().ID(), ID: s00.ProtocolIEID(61), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "MMEname"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "MMEConfigurationUpdateIEs", Row: "id-MMEname"}}}
}

// MMEname returns the typed binding for the MMEname row of MMEConfigurationUpdateIETable.
func (t MMEConfigurationUpdateIETable) MMEname() MMEConfigurationUpdateMMEnameIEBinding {
	return MMEConfigurationUpdateMMEnameIEBinding{info: t.infoMMEname(), codec: func() s01.MMEnameValueCodec {
		sealed := s01.MMEnameValueCodec{}
		*s01.BridgeMMEnameValueCodecFieldPath(&sealed) = "MMEname"
		*s01.BridgeMMEnameValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.MMEname, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s00.MMEname
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("MMEname")
			var zero s43.MMEConfigurationUpdateIEValue
			decoded, err := s43.BridgeMMEConfigurationUpdateIEValueMethodDecode(zero, s00.ProtocolIEID(61), raw)
			if err != nil {
				var empty s00.MMEname
				return empty, runtime.WrapDecodePath(err, "MMEname")
			}
			value, ok := decoded.AsMMEname()
			if !ok {
				var empty s00.MMEname
				return empty, fmt.Errorf("binding MMEConfigurationUpdateIEs.id-MMEname: no selected value")
			}
			return *value, nil
		}
		*s01.BridgeMMEnameValueCodecFieldEncode(&sealed) = func(value s00.MMEname, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return s43.BridgeMMEConfigurationUpdateIEValueMethodEncodeFresh((func() s43.MMEConfigurationUpdateIEValue {
				sealed := s43.MMEConfigurationUpdateIEValue{}
				*s43.BridgeMMEConfigurationUpdateIEValueFieldId(&sealed) = s00.ProtocolIEID(61)
				*s43.BridgeMMEConfigurationUpdateIEValueFieldRowMMEname(&sealed) = &value
				return sealed
			}()), fresh, budget)
		}
		*s01.BridgeMMEnameValueCodecFieldCapture(&sealed) = func(v s00.MMEname, options aper.DecodeState) (s00.MMEname, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f :=
				s.Begin()
			s00.BridgeCaptureS1APMMEname(&v, &s)
			var root aper.Snapshot
			s.
				End(f, &root, false)
			return v, root
		}
		*s01.BridgeMMEnameValueCodecFieldCompare(&sealed) = func(v s00.MMEname, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s02.BridgeCompareS1APMMEname(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s01.BridgeMMEnameValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:MMEname"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s00.MMEname) s43.MMEConfigurationUpdateIEValue {
			return func() s43.MMEConfigurationUpdateIEValue {
				sealed := s43.MMEConfigurationUpdateIEValue{}
				*s43.BridgeMMEConfigurationUpdateIEValueFieldId(&sealed) = s00.ProtocolIEID(61)
				*s43.BridgeMMEConfigurationUpdateIEValueFieldRowMMEname(&sealed) = &value
				return sealed
			}()
		}, get: func(value *s43.MMEConfigurationUpdateIEValue) (*s00.MMEname, bool) { return value.AsMMEname() }}
}
func (MMEConfigurationUpdateIETable) infoServedGUMMEIs() s00.FieldInfo {
	return s00.FieldInfo{Table: MMEConfigurationUpdateIEs().ID(), ID: s00.ProtocolIEID(105), Criticality: s00.CriticalityReject, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "ServedGUMMEIs"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "MMEConfigurationUpdateIEs", Row: "id-ServedGUMMEIs"}}}
}

// ServedGUMMEIs returns the typed binding for the ServedGUMMEIs row of MMEConfigurationUpdateIETable.
func (t MMEConfigurationUpdateIETable) ServedGUMMEIs() MMEConfigurationUpdateServedGUMMEIsIEBinding {
	return MMEConfigurationUpdateServedGUMMEIsIEBinding{info: t.infoServedGUMMEIs(), codec: func() s31.ServedGUMMEIsValueCodec {
		sealed := s31.ServedGUMMEIsValueCodec{}
		*s31.BridgeServedGUMMEIsValueCodecFieldPath(&sealed) = "ServedGUMMEIs"
		*s31.BridgeServedGUMMEIsValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s31.ServedGUMMEIs, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s31.ServedGUMMEIs
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("ServedGUMMEIs")
			var zero s43.MMEConfigurationUpdateIEValue
			decoded, err := s43.BridgeMMEConfigurationUpdateIEValueMethodDecode(zero, s00.ProtocolIEID(105), raw)
			if err != nil {
				var empty s31.ServedGUMMEIs
				return empty, runtime.WrapDecodePath(err, "ServedGUMMEIs")
			}
			value, ok := decoded.AsServedGUMMEIs()
			if !ok {
				var empty s31.ServedGUMMEIs
				return empty, fmt.Errorf("binding MMEConfigurationUpdateIEs.id-ServedGUMMEIs: no selected value")
			}
			return *value, nil
		}
		*s31.BridgeServedGUMMEIsValueCodecFieldEncode(&sealed) = func(value s31.ServedGUMMEIs, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return s43.BridgeMMEConfigurationUpdateIEValueMethodEncodeFresh((func() s43.MMEConfigurationUpdateIEValue {
				sealed := s43.MMEConfigurationUpdateIEValue{}
				*s43.BridgeMMEConfigurationUpdateIEValueFieldId(&sealed) = s00.ProtocolIEID(105)
				*s43.BridgeMMEConfigurationUpdateIEValueFieldRowServedGUMMEIs(&sealed) = &value
				return sealed
			}()), fresh, budget)
		}
		*s31.BridgeServedGUMMEIsValueCodecFieldCapture(&sealed) = func(v s31.ServedGUMMEIs, options aper.DecodeState) (s31.ServedGUMMEIs, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s31.BridgeCaptureS1APServedGUMMEIs(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s31.BridgeServedGUMMEIsValueCodecFieldCompare(&sealed) = func(v s31.ServedGUMMEIs, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s31.BridgeCompareS1APServedGUMMEIs(&v, &s)
			s.End(f, root, false)
			return s.Plan(),

				s.BudgetValue()
		}
		*s31.BridgeServedGUMMEIsValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ServedGUMMEIs"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s31.ServedGUMMEIs) s43.MMEConfigurationUpdateIEValue {
			return func() s43.MMEConfigurationUpdateIEValue {
				sealed := s43.MMEConfigurationUpdateIEValue{}
				*s43.BridgeMMEConfigurationUpdateIEValueFieldId(&sealed) = s00.ProtocolIEID(105)
				*s43.BridgeMMEConfigurationUpdateIEValueFieldRowServedGUMMEIs(&sealed) = &value
				return sealed
			}()
		}, get: func(value *s43.MMEConfigurationUpdateIEValue) (*s31.ServedGUMMEIs, bool) {
			return value.AsServedGUMMEIs()
		}}
}
func (MMEConfigurationUpdateIETable) infoRelativeMMECapacity() s00.FieldInfo {
	return s00.FieldInfo{Table: MMEConfigurationUpdateIEs().ID(), ID: s00.ProtocolIEID(87), Criticality: s00.CriticalityReject, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "RelativeMMECapacity"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "MMEConfigurationUpdateIEs", Row: "id-RelativeMMECapacity"}}}
}

// RelativeMMECapacity returns the typed binding for the RelativeMMECapacity row of MMEConfigurationUpdateIETable.
func (t MMEConfigurationUpdateIETable) RelativeMMECapacity() MMEConfigurationUpdateRelativeMMECapacityIEBinding {
	return MMEConfigurationUpdateRelativeMMECapacityIEBinding{info: t.infoRelativeMMECapacity(), codec: func() s01.RelativeMMECapacityValueCodec {
		sealed := s01.RelativeMMECapacityValueCodec{}
		*s01.BridgeRelativeMMECapacityValueCodecFieldPath(&sealed) = "RelativeMMECapacity"
		*s01.BridgeRelativeMMECapacityValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.RelativeMMECapacity, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s00.RelativeMMECapacity
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("RelativeMMECapacity")
			var zero s43.MMEConfigurationUpdateIEValue
			decoded, err := s43.BridgeMMEConfigurationUpdateIEValueMethodDecode(zero, s00.ProtocolIEID(87), raw)
			if err != nil {
				var empty s00.RelativeMMECapacity
				return empty, runtime.WrapDecodePath(err, "RelativeMMECapacity")
			}
			value, ok := decoded.AsRelativeMMECapacity()
			if !ok {
				var empty s00.RelativeMMECapacity
				return empty, fmt.Errorf("binding MMEConfigurationUpdateIEs.id-RelativeMMECapacity: no selected value")
			}
			return *value, nil
		}
		*s01.BridgeRelativeMMECapacityValueCodecFieldEncode(&sealed) = func(value s00.RelativeMMECapacity, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return s43.BridgeMMEConfigurationUpdateIEValueMethodEncodeFresh((func() s43.MMEConfigurationUpdateIEValue {
				sealed := s43.MMEConfigurationUpdateIEValue{}
				*s43.BridgeMMEConfigurationUpdateIEValueFieldId(&sealed) = s00.ProtocolIEID(87)
				*s43.BridgeMMEConfigurationUpdateIEValueFieldRowRelativeMMECapacity(&sealed) = &value
				return sealed
			}()), fresh, budget)
		}
		*s01.BridgeRelativeMMECapacityValueCodecFieldCapture(&sealed) = func(v s00.RelativeMMECapacity, options aper.DecodeState) (s00.RelativeMMECapacity, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s00.BridgeCaptureS1APRelativeMMECapacity(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s01.BridgeRelativeMMECapacityValueCodecFieldCompare(&sealed) = func(v s00.RelativeMMECapacity, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s06.BridgeCompareS1APRelativeMMECapacity(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s01.BridgeRelativeMMECapacityValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:RelativeMMECapacity"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s00.RelativeMMECapacity) s43.MMEConfigurationUpdateIEValue {
			return func() s43.MMEConfigurationUpdateIEValue {
				sealed := s43.MMEConfigurationUpdateIEValue{}
				*s43.BridgeMMEConfigurationUpdateIEValueFieldId(&sealed) = s00.ProtocolIEID(87)
				*s43.BridgeMMEConfigurationUpdateIEValueFieldRowRelativeMMECapacity(&sealed) = &value
				return sealed
			}()
		}, get: func(value *s43.MMEConfigurationUpdateIEValue) (*s00.RelativeMMECapacity, bool) {
			return value.AsRelativeMMECapacity()
		}}
}
func (MMEConfigurationUpdateIETable) infoServedDCNs() s00.FieldInfo {
	return s00.FieldInfo{Table: MMEConfigurationUpdateIEs().ID(), ID: s00.ProtocolIEID(247), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "ServedDCNs"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "MMEConfigurationUpdateIEs", Row: "id-ServedDCNs"}}}
}

// ServedDCNs returns the typed binding for the ServedDCNs row of MMEConfigurationUpdateIETable.
func (t MMEConfigurationUpdateIETable) ServedDCNs() MMEConfigurationUpdateServedDCNsIEBinding {
	return MMEConfigurationUpdateServedDCNsIEBinding{info: t.infoServedDCNs(), codec: func() s31.ServedDCNsValueCodec {
		sealed := s31.ServedDCNsValueCodec{}
		*s31.BridgeServedDCNsValueCodecFieldPath(&sealed) = "ServedDCNs"
		*s31.BridgeServedDCNsValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s31.ServedDCNs, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s31.ServedDCNs
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("ServedDCNs")
			var zero s43.MMEConfigurationUpdateIEValue
			decoded, err := s43.BridgeMMEConfigurationUpdateIEValueMethodDecode(zero, s00.ProtocolIEID(247), raw)
			if err != nil {
				var empty s31.ServedDCNs
				return empty, runtime.WrapDecodePath(err, "ServedDCNs")
			}
			value, ok := decoded.AsServedDCNs()
			if !ok {
				var empty s31.ServedDCNs
				return empty, fmt.Errorf("binding MMEConfigurationUpdateIEs.id-ServedDCNs: no selected value")
			}
			return *value, nil
		}
		*s31.BridgeServedDCNsValueCodecFieldEncode(&sealed) = func(value s31.ServedDCNs, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return s43.BridgeMMEConfigurationUpdateIEValueMethodEncodeFresh((func() s43.MMEConfigurationUpdateIEValue {
				sealed := s43.MMEConfigurationUpdateIEValue{}
				*s43.BridgeMMEConfigurationUpdateIEValueFieldId(&sealed) = s00.ProtocolIEID(247)
				*s43.BridgeMMEConfigurationUpdateIEValueFieldRowServedDCNs(&sealed) = &value
				return sealed
			}()), fresh, budget)
		}
		*s31.BridgeServedDCNsValueCodecFieldCapture(&sealed) = func(v s31.ServedDCNs, options aper.DecodeState) (s31.ServedDCNs, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f :=
				s.Begin()
			s31.BridgeCaptureS1APServedDCNs(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s31.BridgeServedDCNsValueCodecFieldCompare(&sealed) = func(v s31.ServedDCNs, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s31.BridgeCompareS1APServedDCNs(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s31.BridgeServedDCNsValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ServedDCNs"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s31.ServedDCNs) s43.MMEConfigurationUpdateIEValue {
			return func() s43.MMEConfigurationUpdateIEValue {
				sealed := s43.MMEConfigurationUpdateIEValue{}
				*s43.BridgeMMEConfigurationUpdateIEValueFieldId(&sealed) = s00.ProtocolIEID(247)
				*s43.BridgeMMEConfigurationUpdateIEValueFieldRowServedDCNs(&sealed) = &value
				return sealed
			}()
		}, get: func(value *s43.MMEConfigurationUpdateIEValue) (*s31.ServedDCNs, bool) { return value.AsServedDCNs() }}
}

// NewOpaque constructs an owned opaque field for an identifier without a typed row in MMEConfigurationUpdateIETable.
func (t MMEConfigurationUpdateIETable) NewOpaque(id s00.ProtocolIEID, criticality s00.Criticality, data []byte) (s43.MMEConfigurationUpdateIEField, error) {
	if id < 0 || id > 65535 || criticality < 0 || criticality > 2 {
		return s43.MMEConfigurationUpdateIEField{}, aper.OperationError(fmt.Errorf("invalid opaque IE selector or criticality"), "Opaque")
	}
	switch id {
	case s00.ProtocolIEID(61):
		return s43.MMEConfigurationUpdateIEField{}, aper.OperationError(fmt.Errorf("known IE id-MMEname requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(105):
		return s43.MMEConfigurationUpdateIEField{}, aper.OperationError(fmt.Errorf("known IE id-ServedGUMMEIs requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(87):
		return s43.MMEConfigurationUpdateIEField{}, aper.OperationError(fmt.Errorf("known IE id-RelativeMMECapacity requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(247):
		return s43.MMEConfigurationUpdateIEField{}, aper.OperationError(fmt.Errorf("known IE id-ServedDCNs requires its typed binding"), "Opaque")
	default:
		budget, err := aper.BuildBudget()
		if err != nil {
			return s43.MMEConfigurationUpdateIEField{}, aper.OperationError(err, "Opaque")
		}
		opaque, err := aper.BuildOpaqueOpenType(data, budget)
		if err != nil {
			return s43.MMEConfigurationUpdateIEField{}, aper.OperationError(err, "Opaque")
		}
		return s43.MMEConfigurationUpdateIEField{Id: id, Criticality: criticality, Value: func() s43.MMEConfigurationUpdateIEValue {
			sealed := s43.MMEConfigurationUpdateIEValue{}
			*s43.BridgeMMEConfigurationUpdateIEValueFieldId(&sealed) = id
			*s43.BridgeMMEConfigurationUpdateIEValueFieldOpaque(&sealed) = opaque
			*s43.BridgeMMEConfigurationUpdateIEValueFieldIsOpaque(&sealed) = true
			return sealed
		}()}, aper.OperationError(nil, "Opaque")
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
			s33.BridgeCompareS1APTAIListForRestart(&v, &s)
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

type S1SetupRequestIETable struct{}

func S1SetupRequestIEs() S1SetupRequestIETable { return S1SetupRequestIETable{} }

// ID returns the ASN.1 object-set identity of S1SetupRequestIETable.
func (S1SetupRequestIETable) ID() s00.TableID {
	return func() s00.TableID {
		sealed := s00.TableID{}
		*s00.BridgeTableIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "S1SetupRequestIEs"}
		return sealed
	}()
}

// Table returns the ASN.1 object-set table described by S1SetupRequestIETable.
func (S1SetupRequestIETable) Table() s00.S1SetupRequestIEValueIETable {
	return func() s00.S1SetupRequestIEValueIETable {
		sealed := s00.S1SetupRequestIEValueIETable{}
		*s00.BridgeS1SetupRequestIEValueIETableFieldBound(&sealed) = true
		return sealed
	}()
}
func (S1SetupRequestIETable) infoGlobalENBID() s00.FieldInfo {
	return s00.FieldInfo{Table: S1SetupRequestIEs().ID(), ID: s00.ProtocolIEID(59), Criticality: s00.CriticalityReject, Presence: s00.PresenceMandatory, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "Global-ENB-ID"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "S1SetupRequestIEs", Row: "id-Global-ENB-ID"}}}
}

// GlobalENBID returns the typed binding for the GlobalENBID row of S1SetupRequestIETable.
func (t S1SetupRequestIETable) GlobalENBID() S1SetupRequestGlobalENBIDIEBinding {
	return S1SetupRequestGlobalENBIDIEBinding{info: t.infoGlobalENBID(), codec: func() s18.GlobalENBIDValueCodec {
		sealed := s18.GlobalENBIDValueCodec{}
		*s18.BridgeGlobalENBIDValueCodecFieldPath(&sealed) = "GlobalENBID"
		*s18.BridgeGlobalENBIDValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s18.GlobalENBID, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s18.GlobalENBID
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("GlobalENBID")
			var zero S1SetupRequestIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(59), raw)
			if err != nil {
				var empty s18.GlobalENBID
				return empty, runtime.WrapDecodePath(err, "GlobalENBID")
			}
			value, ok := decoded.AsGlobalENBID()
			if !ok {
				var empty s18.GlobalENBID
				return empty, fmt.Errorf("binding S1SetupRequestIEs.id-Global-ENB-ID: no selected value")
			}
			return *value, nil
		}
		*s18.BridgeGlobalENBIDValueCodecFieldEncode(&sealed) = func(value s18.GlobalENBID, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (S1SetupRequestIEValue{id: s00.ProtocolIEID(59), rowGlobalENBID: &value}).encodeFresh(fresh, budget)
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
		inject: func(value s18.GlobalENBID) S1SetupRequestIEValue {
			return S1SetupRequestIEValue{id: s00.ProtocolIEID(59), rowGlobalENBID: &value}
		}, get: func(value *S1SetupRequestIEValue) (*s18.GlobalENBID, bool) { return value.AsGlobalENBID() }}
}
func (S1SetupRequestIETable) infoENBname() s00.FieldInfo {
	return s00.FieldInfo{Table: S1SetupRequestIEs().ID(), ID: s00.ProtocolIEID(60), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "ENBname"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "S1SetupRequestIEs", Row: "id-eNBname"}}}
}

// ENBname returns the typed binding for the ENBname row of S1SetupRequestIETable.
func (t S1SetupRequestIETable) ENBname() S1SetupRequestENBnameIEBinding {
	return S1SetupRequestENBnameIEBinding{info: t.infoENBname(), codec: func() s00.ENBnameValueCodec {
		sealed := s00.ENBnameValueCodec{}
		*s00.BridgeENBnameValueCodecFieldPath(&sealed) = "ENBname"
		*s00.BridgeENBnameValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.ENBname, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s00.ENBname
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("ENBname")
			var zero S1SetupRequestIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(60), raw)
			if err != nil {
				var empty s00.ENBname
				return empty, runtime.WrapDecodePath(err, "ENBname")
			}
			value, ok := decoded.AsENBname()
			if !ok {
				var empty s00.ENBname
				return empty, fmt.Errorf("binding S1SetupRequestIEs.id-eNBname: no selected value")
			}
			return *value, nil
		}
		*s00.BridgeENBnameValueCodecFieldEncode(&sealed) = func(value s00.ENBname, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (S1SetupRequestIEValue{id: s00.ProtocolIEID(60), rowENBname: &value}).encodeFresh(fresh, budget)
		}
		*s00.BridgeENBnameValueCodecFieldCapture(&sealed) = func(v s00.ENBname, options aper.DecodeState) (s00.ENBname, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f :=
				s.Begin()
			s00.BridgeCaptureS1APENBname(&v, &s)
			var root aper.Snapshot
			s.
				End(f, &root, false)
			return v, root
		}
		*s00.BridgeENBnameValueCodecFieldCompare(&sealed) = func(v s00.ENBname, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s02.BridgeCompareS1APENBname(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s00.BridgeENBnameValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ENBname"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s00.ENBname) S1SetupRequestIEValue {
			return S1SetupRequestIEValue{id: s00.ProtocolIEID(60), rowENBname: &value}
		}, get: func(value *S1SetupRequestIEValue) (*s00.ENBname, bool) { return value.AsENBname() }}
}
func (S1SetupRequestIETable) infoSupportedTAs() s00.FieldInfo {
	return s00.FieldInfo{Table: S1SetupRequestIEs().ID(), ID: s00.ProtocolIEID(64), Criticality: s00.CriticalityReject, Presence: s00.PresenceMandatory, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "SupportedTAs"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "S1SetupRequestIEs", Row: "id-SupportedTAs"}}}
}

// SupportedTAs returns the typed binding for the SupportedTAs row of S1SetupRequestIETable.
func (t S1SetupRequestIETable) SupportedTAs() S1SetupRequestSupportedTAsIEBinding {
	return S1SetupRequestSupportedTAsIEBinding{info: t.infoSupportedTAs(), codec: func() s31.SupportedTAsValueCodec {
		sealed := s31.SupportedTAsValueCodec{}
		*s31.BridgeSupportedTAsValueCodecFieldPath(&sealed) = "SupportedTAs"
		*s31.BridgeSupportedTAsValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s31.SupportedTAs, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s31.SupportedTAs
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("SupportedTAs")
			var zero S1SetupRequestIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(64), raw)
			if err != nil {
				var empty s31.SupportedTAs
				return empty, runtime.WrapDecodePath(err, "SupportedTAs")
			}
			value, ok := decoded.AsSupportedTAs()
			if !ok {
				var empty s31.SupportedTAs
				return empty, fmt.Errorf("binding S1SetupRequestIEs.id-SupportedTAs: no selected value")
			}
			return *value, nil
		}
		*s31.BridgeSupportedTAsValueCodecFieldEncode(&sealed) = func(value s31.SupportedTAs, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (S1SetupRequestIEValue{id: s00.ProtocolIEID(64), rowSupportedTAs: &value}).encodeFresh(fresh, budget)
		}
		*s31.BridgeSupportedTAsValueCodecFieldCapture(&sealed) = func(v s31.SupportedTAs, options aper.DecodeState) (s31.SupportedTAs, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s31.BridgeCaptureS1APSupportedTAs(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s31.BridgeSupportedTAsValueCodecFieldCompare(&sealed) = func(v s31.SupportedTAs, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s31.BridgeCompareS1APSupportedTAs(&v, &s)
			s.End(f, root, false)
			return s.Plan(),
				s.
					BudgetValue()
		}
		*s31.BridgeSupportedTAsValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:SupportedTAs"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s31.SupportedTAs) S1SetupRequestIEValue {
			return S1SetupRequestIEValue{id: s00.ProtocolIEID(64), rowSupportedTAs: &value}
		}, get: func(value *S1SetupRequestIEValue) (*s31.SupportedTAs, bool) { return value.AsSupportedTAs() }}
}
func (S1SetupRequestIETable) infoDefaultPagingDRX() s00.FieldInfo {
	return s00.FieldInfo{Table: S1SetupRequestIEs().ID(), ID: s00.ProtocolIEID(137), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceMandatory, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "PagingDRX"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "S1SetupRequestIEs", Row: "id-DefaultPagingDRX"}}}
}

// DefaultPagingDRX returns the typed binding for the DefaultPagingDRX row of S1SetupRequestIETable.
func (t S1SetupRequestIETable) DefaultPagingDRX() S1SetupRequestPagingDRXIEBinding {
	return S1SetupRequestPagingDRXIEBinding{info: t.infoDefaultPagingDRX(), codec: func() s01.PagingDRXValueCodec {
		sealed := s01.PagingDRXValueCodec{}
		*s01.BridgePagingDRXValueCodecFieldPath(&sealed) = "PagingDRX"
		*s01.BridgePagingDRXValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.PagingDRX, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s00.PagingDRX
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("PagingDRX")
			var zero S1SetupRequestIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(137), raw)
			if err != nil {
				var empty s00.PagingDRX
				return empty, runtime.WrapDecodePath(err, "PagingDRX")
			}
			value, ok := decoded.AsDefaultPagingDRX()
			if !ok {
				var empty s00.PagingDRX
				return empty, fmt.Errorf("binding S1SetupRequestIEs.id-DefaultPagingDRX: no selected value")
			}
			return *value, nil
		}
		*s01.BridgePagingDRXValueCodecFieldEncode(&sealed) = func(value s00.PagingDRX, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (S1SetupRequestIEValue{id: s00.ProtocolIEID(137), rowDefaultPagingDRX: &value}).encodeFresh(fresh, budget)
		}
		*s01.BridgePagingDRXValueCodecFieldCapture(&sealed) = func(v s00.PagingDRX, options aper.DecodeState) (s00.PagingDRX, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.
				Begin()
			s00.BridgeCaptureS1APPagingDRX(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s01.BridgePagingDRXValueCodecFieldCompare(&sealed) = func(v s00.PagingDRX, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s02.BridgeCompareS1APPagingDRX(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s01.BridgePagingDRXValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:PagingDRX"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s00.PagingDRX) S1SetupRequestIEValue {
			return S1SetupRequestIEValue{id: s00.ProtocolIEID(137), rowDefaultPagingDRX: &value}
		}, get: func(value *S1SetupRequestIEValue) (*s00.PagingDRX, bool) { return value.AsDefaultPagingDRX() }}
}
func (S1SetupRequestIETable) infoCSGIdList() s00.FieldInfo {
	return s00.FieldInfo{Table: S1SetupRequestIEs().ID(), ID: s00.ProtocolIEID(128), Criticality: s00.CriticalityReject, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "CSG-IdList"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "S1SetupRequestIEs", Row: "id-CSG-IdList"}}}
}

// CSGIdList returns the typed binding for the CSGIdList row of S1SetupRequestIETable.
func (t S1SetupRequestIETable) CSGIdList() S1SetupRequestCSGIdListIEBinding {
	return S1SetupRequestCSGIdListIEBinding{info: t.infoCSGIdList(), codec: func() s14.CSGIdListValueCodec {
		sealed := s14.CSGIdListValueCodec{}
		*s14.BridgeCSGIdListValueCodecFieldPath(&sealed) = "CSGIdList"
		*s14.BridgeCSGIdListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s14.CSGIdList, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s14.CSGIdList
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("CSGIdList")
			var zero S1SetupRequestIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(128), raw)
			if err != nil {
				var empty s14.CSGIdList
				return empty, runtime.WrapDecodePath(err, "CSGIdList")
			}
			value, ok := decoded.AsCSGIdList()
			if !ok {
				var empty s14.CSGIdList
				return empty, fmt.Errorf("binding S1SetupRequestIEs.id-CSG-IdList: no selected value")
			}
			return *value, nil
		}
		*s14.BridgeCSGIdListValueCodecFieldEncode(&sealed) = func(value s14.CSGIdList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (S1SetupRequestIEValue{id: s00.ProtocolIEID(128), rowCSGIdList: &value}).encodeFresh(fresh, budget)
		}
		*s14.BridgeCSGIdListValueCodecFieldCapture(&sealed) = func(v s14.CSGIdList, options aper.DecodeState) (s14.CSGIdList, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.
				Begin()
			s21.BridgeCaptureS1APCSGIdList(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s14.BridgeCSGIdListValueCodecFieldCompare(&sealed) = func(v s14.CSGIdList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s22.BridgeCompareS1APCSGIdList(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s14.BridgeCSGIdListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:CSGIdList"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s14.CSGIdList) S1SetupRequestIEValue {
			return S1SetupRequestIEValue{id: s00.ProtocolIEID(128), rowCSGIdList: &value}
		}, get: func(value *S1SetupRequestIEValue) (*s14.CSGIdList, bool) { return value.AsCSGIdList() }}
}
func (S1SetupRequestIETable) infoUERetentionInformation() s00.FieldInfo {
	return s00.FieldInfo{Table: S1SetupRequestIEs().ID(), ID: s00.ProtocolIEID(228), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "UE-RetentionInformation"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "S1SetupRequestIEs", Row: "id-UE-RetentionInformation"}}}
}

// UERetentionInformation returns the typed binding for the UERetentionInformation row of S1SetupRequestIETable.
func (t S1SetupRequestIETable) UERetentionInformation() S1SetupRequestUERetentionInformationIEBinding {
	return S1SetupRequestUERetentionInformationIEBinding{info: t.infoUERetentionInformation(), codec: func() s02.UERetentionInformationValueCodec {
		sealed := s02.UERetentionInformationValueCodec{}
		*s02.BridgeUERetentionInformationValueCodecFieldPath(&sealed) = "UERetentionInformation"
		*s02.BridgeUERetentionInformationValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.UERetentionInformation, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s00.UERetentionInformation
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("UERetentionInformation")
			var zero S1SetupRequestIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(228), raw)
			if err != nil {
				var empty s00.UERetentionInformation
				return empty, runtime.WrapDecodePath(err, "UERetentionInformation")
			}
			value, ok := decoded.AsUERetentionInformation()
			if !ok {
				var empty s00.UERetentionInformation
				return empty, fmt.Errorf("binding S1SetupRequestIEs.id-UE-RetentionInformation: no selected value")
			}
			return *value, nil
		}
		*s02.BridgeUERetentionInformationValueCodecFieldEncode(&sealed) = func(value s00.UERetentionInformation, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (S1SetupRequestIEValue{id: s00.ProtocolIEID(228), rowUERetentionInformation: &value}).encodeFresh(fresh, budget)
		}
		*s02.BridgeUERetentionInformationValueCodecFieldCapture(&sealed) = func(v s00.UERetentionInformation, options aper.DecodeState) (s00.UERetentionInformation, aper.Snapshot,

		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s00.BridgeCaptureS1APUERetentionInformation(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s02.BridgeUERetentionInformationValueCodecFieldCompare(&sealed) = func(v s00.UERetentionInformation, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s07.BridgeCompareS1APUERetentionInformation(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s02.BridgeUERetentionInformationValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:UERetentionInformation"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s00.UERetentionInformation) S1SetupRequestIEValue {
			return S1SetupRequestIEValue{id: s00.ProtocolIEID(228), rowUERetentionInformation: &value}
		}, get: func(value *S1SetupRequestIEValue) (*s00.UERetentionInformation, bool) {
			return value.AsUERetentionInformation()
		}}
}
func (S1SetupRequestIETable) infoNBIoTDefaultPagingDRX() s00.FieldInfo {
	return s00.FieldInfo{Table: S1SetupRequestIEs().ID(), ID: s00.ProtocolIEID(234), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "NB-IoT-DefaultPagingDRX"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "S1SetupRequestIEs", Row: "id-NB-IoT-DefaultPagingDRX"}}}
}

// NBIoTDefaultPagingDRX returns the typed binding for the NBIoTDefaultPagingDRX row of S1SetupRequestIETable.
func (t S1SetupRequestIETable) NBIoTDefaultPagingDRX() S1SetupRequestNBIoTDefaultPagingDRXIEBinding {
	return S1SetupRequestNBIoTDefaultPagingDRXIEBinding{info: t.infoNBIoTDefaultPagingDRX(), codec: func() s01.NBIoTDefaultPagingDRXValueCodec {
		sealed := s01.NBIoTDefaultPagingDRXValueCodec{}
		*s01.BridgeNBIoTDefaultPagingDRXValueCodecFieldPath(&sealed) = "NBIoTDefaultPagingDRX"
		*s01.BridgeNBIoTDefaultPagingDRXValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.NBIoTDefaultPagingDRX, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s00.NBIoTDefaultPagingDRX
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("NBIoTDefaultPagingDRX")
			var zero S1SetupRequestIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(234), raw)
			if err != nil {
				var empty s00.NBIoTDefaultPagingDRX
				return empty, runtime.WrapDecodePath(err, "NBIoTDefaultPagingDRX")
			}
			value, ok := decoded.AsNBIoTDefaultPagingDRX()
			if !ok {
				var empty s00.NBIoTDefaultPagingDRX
				return empty, fmt.Errorf("binding S1SetupRequestIEs.id-NB-IoT-DefaultPagingDRX: no selected value")
			}
			return *value, nil
		}
		*s01.BridgeNBIoTDefaultPagingDRXValueCodecFieldEncode(&sealed) = func(value s00.NBIoTDefaultPagingDRX, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (S1SetupRequestIEValue{id: s00.ProtocolIEID(234), rowNBIoTDefaultPagingDRX: &value}).encodeFresh(fresh, budget)
		}
		*s01.BridgeNBIoTDefaultPagingDRXValueCodecFieldCapture(&sealed) = func(v s00.NBIoTDefaultPagingDRX, options aper.DecodeState) (s00.NBIoTDefaultPagingDRX, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s00.BridgeCaptureS1APNBIoTDefaultPagingDRX(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)

			return v, root
		}
		*s01.BridgeNBIoTDefaultPagingDRXValueCodecFieldCompare(&sealed) = func(v s00.NBIoTDefaultPagingDRX, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s02.BridgeCompareS1APNBIoTDefaultPagingDRX(&v, &s)
			s.End(f, root, false)

			return s.Plan(), s.BudgetValue()
		}
		*s01.BridgeNBIoTDefaultPagingDRXValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:NBIoTDefaultPagingDRX"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s00.NBIoTDefaultPagingDRX) S1SetupRequestIEValue {
			return S1SetupRequestIEValue{id: s00.ProtocolIEID(234), rowNBIoTDefaultPagingDRX: &value}
		}, get: func(value *S1SetupRequestIEValue) (*s00.NBIoTDefaultPagingDRX, bool) {
			return value.AsNBIoTDefaultPagingDRX()
		}}
}
func (S1SetupRequestIETable) infoConnectedengNBList() s00.FieldInfo {
	return s00.FieldInfo{Table: S1SetupRequestIEs().ID(), ID: s00.ProtocolIEID(291), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "ConnectedengNBList"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "S1SetupRequestIEs", Row: "id-ConnectedengNBList"}}}
}

// ConnectedengNBList returns the typed binding for the ConnectedengNBList row of S1SetupRequestIETable.
func (t S1SetupRequestIETable) ConnectedengNBList() S1SetupRequestConnectedengNBListIEBinding {
	return S1SetupRequestConnectedengNBListIEBinding{info: t.infoConnectedengNBList(), codec: func() s31.ConnectedengNBListValueCodec {
		sealed := s31.ConnectedengNBListValueCodec{}
		*s31.BridgeConnectedengNBListValueCodecFieldPath(&sealed) = "ConnectedengNBList"
		*s31.BridgeConnectedengNBListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s31.ConnectedengNBList, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s31.ConnectedengNBList
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("ConnectedengNBList")
			var zero S1SetupRequestIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(291), raw)
			if err != nil {
				var empty s31.ConnectedengNBList
				return empty, runtime.WrapDecodePath(err, "ConnectedengNBList")
			}
			value, ok := decoded.AsConnectedengNBList()
			if !ok {
				var empty s31.ConnectedengNBList
				return empty, fmt.Errorf("binding S1SetupRequestIEs.id-ConnectedengNBList: no selected value")
			}
			return *value, nil
		}
		*s31.BridgeConnectedengNBListValueCodecFieldEncode(&sealed) = func(value s31.ConnectedengNBList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (S1SetupRequestIEValue{id: s00.ProtocolIEID(291), rowConnectedengNBList: &value}).encodeFresh(fresh, budget)
		}
		*s31.BridgeConnectedengNBListValueCodecFieldCapture(&sealed) = func(v s31.ConnectedengNBList, options aper.DecodeState) (s31.ConnectedengNBList, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s31.BridgeCaptureS1APConnectedengNBList(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v,

				root
		}
		*s31.BridgeConnectedengNBListValueCodecFieldCompare(&sealed) = func(v s31.ConnectedengNBList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s31.BridgeCompareS1APConnectedengNBList(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s31.BridgeConnectedengNBListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ConnectedengNBList"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s31.ConnectedengNBList) S1SetupRequestIEValue {
			return S1SetupRequestIEValue{id: s00.ProtocolIEID(291), rowConnectedengNBList: &value}
		}, get: func(value *S1SetupRequestIEValue) (*s31.ConnectedengNBList, bool) {
			return value.AsConnectedengNBList()
		}}
}

// NewOpaque constructs an owned opaque field for an identifier without a typed row in S1SetupRequestIETable.
func (t S1SetupRequestIETable) NewOpaque(id s00.ProtocolIEID, criticality s00.Criticality, data []byte) (S1SetupRequestIEField, error) {
	if id < 0 || id > 65535 || criticality < 0 || criticality > 2 {
		return S1SetupRequestIEField{}, aper.OperationError(fmt.Errorf("invalid opaque IE selector or criticality"), "Opaque")
	}
	switch id {
	case s00.ProtocolIEID(59):
		return S1SetupRequestIEField{}, aper.OperationError(fmt.Errorf("known IE id-Global-ENB-ID requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(60):
		return S1SetupRequestIEField{}, aper.OperationError(fmt.Errorf("known IE id-eNBname requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(64):
		return S1SetupRequestIEField{}, aper.OperationError(fmt.Errorf("known IE id-SupportedTAs requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(137):
		return S1SetupRequestIEField{}, aper.OperationError(fmt.Errorf("known IE id-DefaultPagingDRX requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(128):
		return S1SetupRequestIEField{}, aper.OperationError(fmt.Errorf("known IE id-CSG-IdList requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(228):
		return S1SetupRequestIEField{}, aper.OperationError(fmt.Errorf("known IE id-UE-RetentionInformation requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(234):
		return S1SetupRequestIEField{}, aper.OperationError(fmt.Errorf("known IE id-NB-IoT-DefaultPagingDRX requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(291):
		return S1SetupRequestIEField{}, aper.OperationError(fmt.Errorf("known IE id-ConnectedengNBList requires its typed binding"), "Opaque")
	default:
		budget, err := aper.BuildBudget()
		if err != nil {
			return S1SetupRequestIEField{}, aper.OperationError(err, "Opaque")
		}
		opaque, err := aper.BuildOpaqueOpenType(data, budget)
		if err != nil {
			return S1SetupRequestIEField{}, aper.OperationError(err, "Opaque")
		}
		return S1SetupRequestIEField{Id: id, Criticality: criticality, Value: S1SetupRequestIEValue{id: id, opaque: opaque, isOpaque: true}}, aper.OperationError(nil, "Opaque")
	}
}

type S1SetupResponseIETable struct{}

func S1SetupResponseIEs() S1SetupResponseIETable { return S1SetupResponseIETable{} }

// ID returns the ASN.1 object-set identity of S1SetupResponseIETable.
func (S1SetupResponseIETable) ID() s00.TableID {
	return func() s00.TableID {
		sealed := s00.TableID{}
		*s00.BridgeTableIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "S1SetupResponseIEs"}
		return sealed
	}()
}

// Table returns the ASN.1 object-set table described by S1SetupResponseIETable.
func (S1SetupResponseIETable) Table() s00.S1SetupResponseIEValueIETable {
	return func() s00.S1SetupResponseIEValueIETable {
		sealed := s00.S1SetupResponseIEValueIETable{}
		*s00.BridgeS1SetupResponseIEValueIETableFieldBound(&sealed) = true
		return sealed
	}()
}
func (S1SetupResponseIETable) infoMMEname() s00.FieldInfo {
	return s00.FieldInfo{Table: S1SetupResponseIEs().ID(), ID: s00.ProtocolIEID(61), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "MMEname"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "S1SetupResponseIEs", Row: "id-MMEname"}}}
}

// MMEname returns the typed binding for the MMEname row of S1SetupResponseIETable.
func (t S1SetupResponseIETable) MMEname() S1SetupResponseMMEnameIEBinding {
	return S1SetupResponseMMEnameIEBinding{info: t.infoMMEname(), codec: func() s01.MMEnameValueCodec {
		sealed := s01.MMEnameValueCodec{}
		*s01.BridgeMMEnameValueCodecFieldPath(&sealed) = "MMEname"
		*s01.BridgeMMEnameValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.MMEname, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s00.MMEname
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("MMEname")
			var zero S1SetupResponseIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(61), raw)
			if err != nil {
				var empty s00.MMEname
				return empty, runtime.WrapDecodePath(err, "MMEname")
			}
			value, ok := decoded.AsMMEname()
			if !ok {
				var empty s00.MMEname
				return empty, fmt.Errorf("binding S1SetupResponseIEs.id-MMEname: no selected value")
			}
			return *value, nil
		}
		*s01.BridgeMMEnameValueCodecFieldEncode(&sealed) = func(value s00.MMEname, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (S1SetupResponseIEValue{id: s00.ProtocolIEID(61), rowMMEname: &value}).encodeFresh(fresh, budget)
		}
		*s01.BridgeMMEnameValueCodecFieldCapture(&sealed) = func(v s00.MMEname, options aper.DecodeState) (s00.MMEname, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f :=
				s.Begin()
			s00.BridgeCaptureS1APMMEname(&v, &s)
			var root aper.Snapshot
			s.
				End(f, &root, false)
			return v, root
		}
		*s01.BridgeMMEnameValueCodecFieldCompare(&sealed) = func(v s00.MMEname, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s02.BridgeCompareS1APMMEname(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s01.BridgeMMEnameValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:MMEname"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s00.MMEname) S1SetupResponseIEValue {
			return S1SetupResponseIEValue{id: s00.ProtocolIEID(61), rowMMEname: &value}
		}, get: func(value *S1SetupResponseIEValue) (*s00.MMEname, bool) { return value.AsMMEname() }}
}
func (S1SetupResponseIETable) infoServedGUMMEIs() s00.FieldInfo {
	return s00.FieldInfo{Table: S1SetupResponseIEs().ID(), ID: s00.ProtocolIEID(105), Criticality: s00.CriticalityReject, Presence: s00.PresenceMandatory, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "ServedGUMMEIs"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "S1SetupResponseIEs", Row: "id-ServedGUMMEIs"}}}
}

// ServedGUMMEIs returns the typed binding for the ServedGUMMEIs row of S1SetupResponseIETable.
func (t S1SetupResponseIETable) ServedGUMMEIs() S1SetupResponseServedGUMMEIsIEBinding {
	return S1SetupResponseServedGUMMEIsIEBinding{info: t.infoServedGUMMEIs(), codec: func() s31.ServedGUMMEIsValueCodec {
		sealed := s31.ServedGUMMEIsValueCodec{}
		*s31.BridgeServedGUMMEIsValueCodecFieldPath(&sealed) = "ServedGUMMEIs"
		*s31.BridgeServedGUMMEIsValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s31.ServedGUMMEIs, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s31.ServedGUMMEIs
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("ServedGUMMEIs")
			var zero S1SetupResponseIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(105), raw)
			if err != nil {
				var empty s31.ServedGUMMEIs
				return empty, runtime.WrapDecodePath(err, "ServedGUMMEIs")
			}
			value, ok := decoded.AsServedGUMMEIs()
			if !ok {
				var empty s31.ServedGUMMEIs
				return empty, fmt.Errorf("binding S1SetupResponseIEs.id-ServedGUMMEIs: no selected value")
			}
			return *value, nil
		}
		*s31.BridgeServedGUMMEIsValueCodecFieldEncode(&sealed) = func(value s31.ServedGUMMEIs, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (S1SetupResponseIEValue{id: s00.ProtocolIEID(105), rowServedGUMMEIs: &value}).encodeFresh(fresh, budget)
		}
		*s31.BridgeServedGUMMEIsValueCodecFieldCapture(&sealed) = func(v s31.ServedGUMMEIs, options aper.DecodeState) (s31.ServedGUMMEIs, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s31.BridgeCaptureS1APServedGUMMEIs(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s31.BridgeServedGUMMEIsValueCodecFieldCompare(&sealed) = func(v s31.ServedGUMMEIs, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s31.BridgeCompareS1APServedGUMMEIs(&v, &s)
			s.End(f, root, false)
			return s.Plan(),

				s.BudgetValue()
		}
		*s31.BridgeServedGUMMEIsValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ServedGUMMEIs"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s31.ServedGUMMEIs) S1SetupResponseIEValue {
			return S1SetupResponseIEValue{id: s00.ProtocolIEID(105), rowServedGUMMEIs: &value}
		}, get: func(value *S1SetupResponseIEValue) (*s31.ServedGUMMEIs, bool) { return value.AsServedGUMMEIs() }}
}
func (S1SetupResponseIETable) infoRelativeMMECapacity() s00.FieldInfo {
	return s00.FieldInfo{Table: S1SetupResponseIEs().ID(), ID: s00.ProtocolIEID(87), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceMandatory, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "RelativeMMECapacity"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "S1SetupResponseIEs", Row: "id-RelativeMMECapacity"}}}
}

// RelativeMMECapacity returns the typed binding for the RelativeMMECapacity row of S1SetupResponseIETable.
func (t S1SetupResponseIETable) RelativeMMECapacity() S1SetupResponseRelativeMMECapacityIEBinding {
	return S1SetupResponseRelativeMMECapacityIEBinding{info: t.infoRelativeMMECapacity(), codec: func() s01.RelativeMMECapacityValueCodec {
		sealed := s01.RelativeMMECapacityValueCodec{}
		*s01.BridgeRelativeMMECapacityValueCodecFieldPath(&sealed) = "RelativeMMECapacity"
		*s01.BridgeRelativeMMECapacityValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.RelativeMMECapacity, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s00.RelativeMMECapacity
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("RelativeMMECapacity")
			var zero S1SetupResponseIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(87), raw)
			if err != nil {
				var empty s00.RelativeMMECapacity
				return empty, runtime.WrapDecodePath(err, "RelativeMMECapacity")
			}
			value, ok := decoded.AsRelativeMMECapacity()
			if !ok {
				var empty s00.RelativeMMECapacity
				return empty, fmt.Errorf("binding S1SetupResponseIEs.id-RelativeMMECapacity: no selected value")
			}
			return *value, nil
		}
		*s01.BridgeRelativeMMECapacityValueCodecFieldEncode(&sealed) = func(value s00.RelativeMMECapacity, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (S1SetupResponseIEValue{id: s00.ProtocolIEID(87), rowRelativeMMECapacity: &value}).encodeFresh(fresh, budget)
		}
		*s01.BridgeRelativeMMECapacityValueCodecFieldCapture(&sealed) = func(v s00.RelativeMMECapacity, options aper.DecodeState) (s00.RelativeMMECapacity, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s00.BridgeCaptureS1APRelativeMMECapacity(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s01.BridgeRelativeMMECapacityValueCodecFieldCompare(&sealed) = func(v s00.RelativeMMECapacity, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s06.BridgeCompareS1APRelativeMMECapacity(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s01.BridgeRelativeMMECapacityValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:RelativeMMECapacity"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s00.RelativeMMECapacity) S1SetupResponseIEValue {
			return S1SetupResponseIEValue{id: s00.ProtocolIEID(87), rowRelativeMMECapacity: &value}
		}, get: func(value *S1SetupResponseIEValue) (*s00.RelativeMMECapacity, bool) {
			return value.AsRelativeMMECapacity()
		}}
}
func (S1SetupResponseIETable) infoMMERelaySupportIndicator() s00.FieldInfo {
	return s00.FieldInfo{Table: S1SetupResponseIEs().ID(), ID: s00.ProtocolIEID(163), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "MMERelaySupportIndicator"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "S1SetupResponseIEs", Row: "id-MMERelaySupportIndicator"}}}
}

// MMERelaySupportIndicator returns the typed binding for the MMERelaySupportIndicator row of S1SetupResponseIETable.
func (t S1SetupResponseIETable) MMERelaySupportIndicator() S1SetupResponseMMERelaySupportIndicatorIEBinding {
	return S1SetupResponseMMERelaySupportIndicatorIEBinding{info: t.infoMMERelaySupportIndicator(), codec: func() s01.MMERelaySupportIndicatorValueCodec {
		sealed := s01.MMERelaySupportIndicatorValueCodec{}
		*s01.BridgeMMERelaySupportIndicatorValueCodecFieldPath(&sealed) = "MMERelaySupportIndicator"
		*s01.BridgeMMERelaySupportIndicatorValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.MMERelaySupportIndicator, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s00.MMERelaySupportIndicator
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("MMERelaySupportIndicator")
			var zero S1SetupResponseIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(163), raw)
			if err != nil {
				var empty s00.MMERelaySupportIndicator
				return empty, runtime.WrapDecodePath(err, "MMERelaySupportIndicator")
			}
			value, ok := decoded.AsMMERelaySupportIndicator()
			if !ok {
				var empty s00.MMERelaySupportIndicator
				return empty, fmt.Errorf("binding S1SetupResponseIEs.id-MMERelaySupportIndicator: no selected value")
			}
			return *value, nil
		}
		*s01.BridgeMMERelaySupportIndicatorValueCodecFieldEncode(&sealed) = func(value s00.MMERelaySupportIndicator, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (S1SetupResponseIEValue{id: s00.ProtocolIEID(163), rowMMERelaySupportIndicator: &value}).encodeFresh(fresh, budget)
		}
		*s01.BridgeMMERelaySupportIndicatorValueCodecFieldCapture(&sealed) = func(v s00.MMERelaySupportIndicator, options aper.DecodeState) (s00.MMERelaySupportIndicator, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s00.BridgeCaptureS1APMMERelaySupportIndicator(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,

				false)
			return v, root
		}
		*s01.BridgeMMERelaySupportIndicatorValueCodecFieldCompare(&sealed) = func(v s00.MMERelaySupportIndicator, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s02.BridgeCompareS1APMMERelaySupportIndicator(&v, &s)
			s.End(f, root,

				false,
			)
			return s.Plan(), s.BudgetValue()
		}
		*s01.BridgeMMERelaySupportIndicatorValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:MMERelaySupportIndicator"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s00.MMERelaySupportIndicator) S1SetupResponseIEValue {
			return S1SetupResponseIEValue{id: s00.ProtocolIEID(163), rowMMERelaySupportIndicator: &value}
		}, get: func(value *S1SetupResponseIEValue) (*s00.MMERelaySupportIndicator, bool) {
			return value.AsMMERelaySupportIndicator()
		}}
}
func (S1SetupResponseIETable) infoCriticalityDiagnostics() s00.FieldInfo {
	return s00.FieldInfo{Table: S1SetupResponseIEs().ID(), ID: s00.ProtocolIEID(58), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "CriticalityDiagnostics"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "S1SetupResponseIEs", Row: "id-CriticalityDiagnostics"}}}
}

// CriticalityDiagnostics returns the typed binding for the CriticalityDiagnostics row of S1SetupResponseIETable.
func (t S1SetupResponseIETable) CriticalityDiagnostics() S1SetupResponseCriticalityDiagnosticsIEBinding {
	return S1SetupResponseCriticalityDiagnosticsIEBinding{info: t.infoCriticalityDiagnostics(), codec: func() s22.CriticalityDiagnosticsValueCodec {
		sealed := s22.CriticalityDiagnosticsValueCodec{}
		*s22.BridgeCriticalityDiagnosticsValueCodecFieldPath(&sealed) = "CriticalityDiagnostics"
		*s22.BridgeCriticalityDiagnosticsValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s22.CriticalityDiagnostics, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s22.CriticalityDiagnostics
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("CriticalityDiagnostics")
			var zero S1SetupResponseIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(58), raw)
			if err != nil {
				var empty s22.CriticalityDiagnostics
				return empty, runtime.WrapDecodePath(err, "CriticalityDiagnostics")
			}
			value, ok := decoded.AsCriticalityDiagnostics()
			if !ok {
				var empty s22.CriticalityDiagnostics
				return empty, fmt.Errorf("binding S1SetupResponseIEs.id-CriticalityDiagnostics: no selected value")
			}
			return *value, nil
		}
		*s22.BridgeCriticalityDiagnosticsValueCodecFieldEncode(&sealed) = func(value s22.CriticalityDiagnostics, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (S1SetupResponseIEValue{id: s00.ProtocolIEID(58), rowCriticalityDiagnostics: &value}).encodeFresh(fresh, budget)
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
		inject: func(value s22.CriticalityDiagnostics) S1SetupResponseIEValue {
			return S1SetupResponseIEValue{id: s00.ProtocolIEID(58), rowCriticalityDiagnostics: &value}
		}, get: func(value *S1SetupResponseIEValue) (*s22.CriticalityDiagnostics, bool) {
			return value.AsCriticalityDiagnostics()
		}}
}
func (S1SetupResponseIETable) infoUERetentionInformation() s00.FieldInfo {
	return s00.FieldInfo{Table: S1SetupResponseIEs().ID(), ID: s00.ProtocolIEID(228), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "UE-RetentionInformation"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "S1SetupResponseIEs", Row: "id-UE-RetentionInformation"}}}
}

// UERetentionInformation returns the typed binding for the UERetentionInformation row of S1SetupResponseIETable.
func (t S1SetupResponseIETable) UERetentionInformation() S1SetupResponseUERetentionInformationIEBinding {
	return S1SetupResponseUERetentionInformationIEBinding{info: t.infoUERetentionInformation(), codec: func() s02.UERetentionInformationValueCodec {
		sealed := s02.UERetentionInformationValueCodec{}
		*s02.BridgeUERetentionInformationValueCodecFieldPath(&sealed) = "UERetentionInformation"
		*s02.BridgeUERetentionInformationValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.UERetentionInformation, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s00.UERetentionInformation
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("UERetentionInformation")
			var zero S1SetupResponseIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(228), raw)
			if err != nil {
				var empty s00.UERetentionInformation
				return empty, runtime.WrapDecodePath(err, "UERetentionInformation")
			}
			value, ok := decoded.AsUERetentionInformation()
			if !ok {
				var empty s00.UERetentionInformation
				return empty, fmt.Errorf("binding S1SetupResponseIEs.id-UE-RetentionInformation: no selected value")
			}
			return *value, nil
		}
		*s02.BridgeUERetentionInformationValueCodecFieldEncode(&sealed) = func(value s00.UERetentionInformation, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (S1SetupResponseIEValue{id: s00.ProtocolIEID(228), rowUERetentionInformation: &value}).encodeFresh(fresh, budget)
		}
		*s02.BridgeUERetentionInformationValueCodecFieldCapture(&sealed) = func(v s00.UERetentionInformation, options aper.DecodeState) (s00.UERetentionInformation, aper.Snapshot,

		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s00.BridgeCaptureS1APUERetentionInformation(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s02.BridgeUERetentionInformationValueCodecFieldCompare(&sealed) = func(v s00.UERetentionInformation, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s07.BridgeCompareS1APUERetentionInformation(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s02.BridgeUERetentionInformationValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:UERetentionInformation"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s00.UERetentionInformation) S1SetupResponseIEValue {
			return S1SetupResponseIEValue{id: s00.ProtocolIEID(228), rowUERetentionInformation: &value}
		}, get: func(value *S1SetupResponseIEValue) (*s00.UERetentionInformation, bool) {
			return value.AsUERetentionInformation()
		}}
}
func (S1SetupResponseIETable) infoServedDCNs() s00.FieldInfo {
	return s00.FieldInfo{Table: S1SetupResponseIEs().ID(), ID: s00.ProtocolIEID(247), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "ServedDCNs"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "S1SetupResponseIEs", Row: "id-ServedDCNs"}}}
}

// ServedDCNs returns the typed binding for the ServedDCNs row of S1SetupResponseIETable.
func (t S1SetupResponseIETable) ServedDCNs() S1SetupResponseServedDCNsIEBinding {
	return S1SetupResponseServedDCNsIEBinding{info: t.infoServedDCNs(), codec: func() s31.ServedDCNsValueCodec {
		sealed := s31.ServedDCNsValueCodec{}
		*s31.BridgeServedDCNsValueCodecFieldPath(&sealed) = "ServedDCNs"
		*s31.BridgeServedDCNsValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s31.ServedDCNs, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s31.ServedDCNs
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("ServedDCNs")
			var zero S1SetupResponseIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(247), raw)
			if err != nil {
				var empty s31.ServedDCNs
				return empty, runtime.WrapDecodePath(err, "ServedDCNs")
			}
			value, ok := decoded.AsServedDCNs()
			if !ok {
				var empty s31.ServedDCNs
				return empty, fmt.Errorf("binding S1SetupResponseIEs.id-ServedDCNs: no selected value")
			}
			return *value, nil
		}
		*s31.BridgeServedDCNsValueCodecFieldEncode(&sealed) = func(value s31.ServedDCNs, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (S1SetupResponseIEValue{id: s00.ProtocolIEID(247), rowServedDCNs: &value}).encodeFresh(fresh, budget)
		}
		*s31.BridgeServedDCNsValueCodecFieldCapture(&sealed) = func(v s31.ServedDCNs, options aper.DecodeState) (s31.ServedDCNs, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f :=
				s.Begin()
			s31.BridgeCaptureS1APServedDCNs(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s31.BridgeServedDCNsValueCodecFieldCompare(&sealed) = func(v s31.ServedDCNs, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s31.BridgeCompareS1APServedDCNs(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s31.BridgeServedDCNsValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ServedDCNs"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s31.ServedDCNs) S1SetupResponseIEValue {
			return S1SetupResponseIEValue{id: s00.ProtocolIEID(247), rowServedDCNs: &value}
		}, get: func(value *S1SetupResponseIEValue) (*s31.ServedDCNs, bool) { return value.AsServedDCNs() }}
}
func (S1SetupResponseIETable) infoIABSupported() s00.FieldInfo {
	return s00.FieldInfo{Table: S1SetupResponseIEs().ID(), ID: s00.ProtocolIEID(303), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "IAB-Supported"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "S1SetupResponseIEs", Row: "id-IAB-Supported"}}}
}

// IABSupported returns the typed binding for the IABSupported row of S1SetupResponseIETable.
func (t S1SetupResponseIETable) IABSupported() S1SetupResponseIABSupportedIEBinding {
	return S1SetupResponseIABSupportedIEBinding{info: t.infoIABSupported(), codec: func() s01.IABSupportedValueCodec {
		sealed := s01.IABSupportedValueCodec{}
		*s01.BridgeIABSupportedValueCodecFieldPath(&sealed) = "IABSupported"
		*s01.BridgeIABSupportedValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.IABSupported, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s00.IABSupported
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("IABSupported")
			var zero S1SetupResponseIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(303), raw)
			if err != nil {
				var empty s00.IABSupported
				return empty, runtime.WrapDecodePath(err, "IABSupported")
			}
			value, ok := decoded.AsIABSupported()
			if !ok {
				var empty s00.IABSupported
				return empty, fmt.Errorf("binding S1SetupResponseIEs.id-IAB-Supported: no selected value")
			}
			return *value, nil
		}
		*s01.BridgeIABSupportedValueCodecFieldEncode(&sealed) = func(value s00.IABSupported, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (S1SetupResponseIEValue{id: s00.ProtocolIEID(303), rowIABSupported: &value}).encodeFresh(fresh, budget)
		}
		*s01.BridgeIABSupportedValueCodecFieldCapture(&sealed) = func(v s00.IABSupported, options aper.DecodeState) (s00.IABSupported, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s00.BridgeCaptureS1APIABSupported(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s01.BridgeIABSupportedValueCodecFieldCompare(&sealed) = func(v s00.IABSupported, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s02.BridgeCompareS1APIABSupported(&v, &s)
			s.End(f, root, false)
			return s.Plan(),
				s.
					BudgetValue()
		}
		*s01.BridgeIABSupportedValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:IABSupported"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s00.IABSupported) S1SetupResponseIEValue {
			return S1SetupResponseIEValue{id: s00.ProtocolIEID(303), rowIABSupported: &value}
		}, get: func(value *S1SetupResponseIEValue) (*s00.IABSupported, bool) { return value.AsIABSupported() }}
}

// NewOpaque constructs an owned opaque field for an identifier without a typed row in S1SetupResponseIETable.
func (t S1SetupResponseIETable) NewOpaque(id s00.ProtocolIEID, criticality s00.Criticality, data []byte) (S1SetupResponseIEField, error) {
	if id < 0 || id > 65535 || criticality < 0 || criticality > 2 {
		return S1SetupResponseIEField{}, aper.OperationError(fmt.Errorf("invalid opaque IE selector or criticality"), "Opaque")
	}
	switch id {
	case s00.ProtocolIEID(61):
		return S1SetupResponseIEField{}, aper.OperationError(fmt.Errorf("known IE id-MMEname requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(105):
		return S1SetupResponseIEField{}, aper.OperationError(fmt.Errorf("known IE id-ServedGUMMEIs requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(87):
		return S1SetupResponseIEField{}, aper.OperationError(fmt.Errorf("known IE id-RelativeMMECapacity requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(163):
		return S1SetupResponseIEField{}, aper.OperationError(fmt.Errorf("known IE id-MMERelaySupportIndicator requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(58):
		return S1SetupResponseIEField{}, aper.OperationError(fmt.Errorf("known IE id-CriticalityDiagnostics requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(228):
		return S1SetupResponseIEField{}, aper.OperationError(fmt.Errorf("known IE id-UE-RetentionInformation requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(247):
		return S1SetupResponseIEField{}, aper.OperationError(fmt.Errorf("known IE id-ServedDCNs requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(303):
		return S1SetupResponseIEField{}, aper.OperationError(fmt.Errorf("known IE id-IAB-Supported requires its typed binding"), "Opaque")
	default:
		budget, err := aper.BuildBudget()
		if err != nil {
			return S1SetupResponseIEField{}, aper.OperationError(err, "Opaque")
		}
		opaque, err := aper.BuildOpaqueOpenType(data, budget)
		if err != nil {
			return S1SetupResponseIEField{}, aper.OperationError(err, "Opaque")
		}
		return S1SetupResponseIEField{Id: id, Criticality: criticality, Value: S1SetupResponseIEValue{id: id, opaque: opaque, isOpaque: true}}, aper.OperationError(nil, "Opaque")
	}
}

// CSGIdListCodec binds the complete APER value type.
func CSGIdListCodec() s14.CSGIdListValueCodec { return ENBConfigurationUpdateIEs().CSGIdList().Codec() }

// ConnectedengNBListCodec binds the complete APER value type.
func ConnectedengNBListCodec() s31.ConnectedengNBListValueCodec {
	return ENBConfigurationUpdateIEs().ConnectedengNBToAddList().Codec()
}

// ECGIListForRestartCodec binds the complete APER value type.
func ECGIListForRestartCodec() s17.ECGIListForRestartValueCodec {
	return PWSRestartIndicationIEs().ECGIListForRestart().Codec()
}

// ENBnameCodec binds the complete APER value type.
func ENBnameCodec() s00.ENBnameValueCodec { return ENBConfigurationUpdateIEs().ENBname().Codec() }

// EmergencyAreaIDListForRestartCodec binds the complete APER value type.
func EmergencyAreaIDListForRestartCodec() s00.EmergencyAreaIDListForRestartValueCodec {
	return PWSRestartIndicationIEs().EmergencyAreaIDListForRestart().Codec()
}

// IABSupportedCodec binds the complete APER value type.
func IABSupportedCodec() s01.IABSupportedValueCodec {
	return S1SetupResponseIEs().IABSupported().Codec()
}

// MMERelaySupportIndicatorCodec binds the complete APER value type.
func MMERelaySupportIndicatorCodec() s01.MMERelaySupportIndicatorValueCodec {
	return S1SetupResponseIEs().MMERelaySupportIndicator().Codec()
}

// MMEnameCodec binds the complete APER value type.
func MMEnameCodec() s01.MMEnameValueCodec { return MMEConfigurationUpdateIEs().MMEname().Codec() }

// NBIoTDefaultPagingDRXCodec binds the complete APER value type.
func NBIoTDefaultPagingDRXCodec() s01.NBIoTDefaultPagingDRXValueCodec {
	return ENBConfigurationUpdateIEs().NBIoTDefaultPagingDRX().Codec()
}

// PagingDRXCodec binds the complete APER value type.
func PagingDRXCodec() s01.PagingDRXValueCodec {
	return ENBConfigurationUpdateIEs().DefaultPagingDRX().Codec()
}

// RelativeMMECapacityCodec binds the complete APER value type.
func RelativeMMECapacityCodec() s01.RelativeMMECapacityValueCodec {
	return MMEConfigurationUpdateIEs().RelativeMMECapacity().Codec()
}

// ServedDCNsCodec binds the complete APER value type.
func ServedDCNsCodec() s31.ServedDCNsValueCodec {
	return MMEConfigurationUpdateIEs().ServedDCNs().Codec()
}

// ServedGUMMEIsCodec binds the complete APER value type.
func ServedGUMMEIsCodec() s31.ServedGUMMEIsValueCodec {
	return MMEConfigurationUpdateIEs().ServedGUMMEIs().Codec()
}

// ServedGroupIDsCodec binds the complete source value type.
func ServedGroupIDsCodec() s01.ServedGroupIDsValueCodec {
	return func() s01.ServedGroupIDsValueCodec {
		sealed := s01.ServedGroupIDsValueCodec{}
		*s01.BridgeServedGroupIDsValueCodecFieldPath(&sealed) = "ServedGroupIDs"
		*s01.BridgeServedGroupIDsValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.ServedGroupIDs, error) {
			var complete ServedGroupIDsComplete
			if err := complete.unmarshalAPERWithOptions(data, options); err != nil {
				var zero s00.ServedGroupIDs
				return zero, err
			}
			return complete.Value, nil
		}
		*s01.BridgeServedGroupIDsValueCodecFieldEncode(&sealed) = func(value s00.ServedGroupIDs, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			complete := ServedGroupIDsComplete{Value: value}
			return complete.marshalAPERBudget(budget, fresh)
		}
		*s01.BridgeServedGroupIDsValueCodecFieldCapture(&sealed) = func(v s00.ServedGroupIDs, options aper.DecodeState) (s00.ServedGroupIDs, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s00.BridgeCaptureS1APServedGroupIDs(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s01.BridgeServedGroupIDsValueCodecFieldCompare(&sealed) = func(v s00.ServedGroupIDs, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s07.BridgeCompareS1APServedGroupIDs(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s01.BridgeServedGroupIDsValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ServedGroupIDs"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// ServedMMECsCodec binds the complete source value type.
func ServedMMECsCodec() s01.ServedMMECsValueCodec {
	return func() s01.ServedMMECsValueCodec {
		sealed := s01.ServedMMECsValueCodec{}
		*s01.BridgeServedMMECsValueCodecFieldPath(&sealed) = "ServedMMECs"
		*s01.BridgeServedMMECsValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.ServedMMECs, error) {
			var complete ServedMMECsComplete
			if err := complete.unmarshalAPERWithOptions(data, options); err != nil {
				var zero s00.ServedMMECs
				return zero, err
			}
			return complete.Value, nil
		}
		*s01.BridgeServedMMECsValueCodecFieldEncode(&sealed) = func(value s00.ServedMMECs, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			complete := ServedMMECsComplete{Value: value}
			return complete.marshalAPERBudget(budget, fresh)
		}
		*s01.BridgeServedMMECsValueCodecFieldCapture(&sealed) = func(v s00.ServedMMECs, options aper.DecodeState) (s00.ServedMMECs, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s00.BridgeCaptureS1APServedMMECs(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s01.BridgeServedMMECsValueCodecFieldCompare(&sealed) = func(v s00.ServedMMECs, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s07.BridgeCompareS1APServedMMECs(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.
				BudgetValue()
		}
		*s01.BridgeServedMMECsValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ServedMMECs"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// ServedPLMNsCodec binds the complete source value type.
func ServedPLMNsCodec() s01.ServedPLMNsValueCodec {
	return func() s01.ServedPLMNsValueCodec {
		sealed := s01.ServedPLMNsValueCodec{}
		*s01.BridgeServedPLMNsValueCodecFieldPath(&sealed) = "ServedPLMNs"
		*s01.BridgeServedPLMNsValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.ServedPLMNs, error) {
			var complete ServedPLMNsComplete
			if err := complete.unmarshalAPERWithOptions(data, options); err != nil {
				var zero s00.ServedPLMNs
				return zero, err
			}
			return complete.Value, nil
		}
		*s01.BridgeServedPLMNsValueCodecFieldEncode(&sealed) = func(value s00.ServedPLMNs, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			complete := ServedPLMNsComplete{Value: value}
			return complete.marshalAPERBudget(budget, fresh)
		}
		*s01.BridgeServedPLMNsValueCodecFieldCapture(&sealed) = func(v s00.ServedPLMNs, options aper.DecodeState) (s00.ServedPLMNs, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s00.BridgeCaptureS1APServedPLMNs(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s01.BridgeServedPLMNsValueCodecFieldCompare(&sealed) = func(v s00.ServedPLMNs, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s07.BridgeCompareS1APServedPLMNs(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.
				BudgetValue()
		}
		*s01.BridgeServedPLMNsValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ServedPLMNs"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// SupportedTAsCodec binds the complete APER value type.
func SupportedTAsCodec() s31.SupportedTAsValueCodec {
	return ENBConfigurationUpdateIEs().SupportedTAs().Codec()
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
			s33.BridgeCompareS1APTAICancelled(&v, &s)
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

// UERetentionInformationCodec binds the complete APER value type.
func UERetentionInformationCodec() s02.UERetentionInformationValueCodec {
	return S1SetupRequestIEs().UERetentionInformation().Codec()
}
func BridgeENBConfigurationUpdateAPERValueFieldContext(v *ENBConfigurationUpdateAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeENBConfigurationUpdateAPERValueFieldReceived(v *ENBConfigurationUpdateAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeENBConfigurationUpdateAPERValueFieldReplay(v *ENBConfigurationUpdateAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeENBConfigurationUpdateAPERValueFieldWithoutReplay(v *ENBConfigurationUpdateAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeENBConfigurationUpdateCSGIdListIEBindingFieldCodec(v *ENBConfigurationUpdateCSGIdListIEBinding) *s14.CSGIdListValueCodec {
	return &v.codec
}
func BridgeENBConfigurationUpdateCSGIdListIEBindingFieldGet(v *ENBConfigurationUpdateCSGIdListIEBinding) *func(*ENBConfigurationUpdateIEValue) (*s14.CSGIdList, bool) {
	return &v.get
}
func BridgeENBConfigurationUpdateCSGIdListIEBindingFieldInfo(v *ENBConfigurationUpdateCSGIdListIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeENBConfigurationUpdateCSGIdListIEBindingFieldInject(v *ENBConfigurationUpdateCSGIdListIEBinding) *func(s14.CSGIdList) ENBConfigurationUpdateIEValue {
	return &v.inject
}
func BridgeENBConfigurationUpdateConnectedengNBListIEBindingFieldCodec(v *ENBConfigurationUpdateConnectedengNBListIEBinding) *s31.ConnectedengNBListValueCodec {
	return &v.codec
}
func BridgeENBConfigurationUpdateConnectedengNBListIEBindingFieldGet(v *ENBConfigurationUpdateConnectedengNBListIEBinding) *func(*ENBConfigurationUpdateIEValue) (*s31.ConnectedengNBList, bool) {
	return &v.get
}
func BridgeENBConfigurationUpdateConnectedengNBListIEBindingFieldInfo(v *ENBConfigurationUpdateConnectedengNBListIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeENBConfigurationUpdateConnectedengNBListIEBindingFieldInject(v *ENBConfigurationUpdateConnectedengNBListIEBinding) *func(s31.ConnectedengNBList) ENBConfigurationUpdateIEValue {
	return &v.inject
}
func BridgeENBConfigurationUpdateENBnameIEBindingFieldCodec(v *ENBConfigurationUpdateENBnameIEBinding) *s00.ENBnameValueCodec {
	return &v.codec
}
func BridgeENBConfigurationUpdateENBnameIEBindingFieldGet(v *ENBConfigurationUpdateENBnameIEBinding) *func(*ENBConfigurationUpdateIEValue) (*s00.ENBname, bool) {
	return &v.get
}
func BridgeENBConfigurationUpdateENBnameIEBindingFieldInfo(v *ENBConfigurationUpdateENBnameIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeENBConfigurationUpdateENBnameIEBindingFieldInject(v *ENBConfigurationUpdateENBnameIEBinding) *func(s00.ENBname) ENBConfigurationUpdateIEValue {
	return &v.inject
}
func BridgeENBConfigurationUpdateFieldExtCount(v *ENBConfigurationUpdate) *int64   { return &v.extCount }
func BridgeENBConfigurationUpdateFieldExtData(v *ENBConfigurationUpdate) *[][]byte { return &v.extData }
func BridgeENBConfigurationUpdateFieldExtOrigin(v *ENBConfigurationUpdate) *[]aper.OpaqueOrigin {
	return &v.extOrigin
}
func BridgeENBConfigurationUpdateFieldExtPresent(v *ENBConfigurationUpdate) *[]bool {
	return &v.extPresent
}
func BridgeENBConfigurationUpdateFieldExtWire(v *ENBConfigurationUpdate) *[]aper.WireSpan {
	return &v.extWire
}
func BridgeENBConfigurationUpdateFieldPerExtPadding(v *ENBConfigurationUpdate) *[]aper.CompletePadding {
	return &v.perExtPadding
}
func BridgeENBConfigurationUpdateFieldPerPadding(v *ENBConfigurationUpdate) *aper.FinalPadding {
	return &v.perPadding
}
func BridgeENBConfigurationUpdateFieldProtocolIEsIndef(v *ENBConfigurationUpdate) *bool {
	return &v.protocolIEsIndef
}
func BridgeENBConfigurationUpdateFieldReceived(v *ENBConfigurationUpdate) *bool { return &v.received }
func BridgeENBConfigurationUpdateFieldReceivedAbsolute(v *ENBConfigurationUpdate) *bool {
	return &v.receivedAbsolute
}
func BridgeENBConfigurationUpdateFieldReceivedBytes(v *ENBConfigurationUpdate) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeENBConfigurationUpdateFieldReceivedLocation(v *ENBConfigurationUpdate) *aper.Location {
	return &v.receivedLocation
}
func BridgeENBConfigurationUpdateFieldReplay(v *ENBConfigurationUpdate) *aper.Snapshot {
	return &v.replay
}
func BridgeENBConfigurationUpdateFieldStream(v *ENBConfigurationUpdate) *aper.WireSpan {
	return &v.stream
}
func BridgeENBConfigurationUpdateFieldWithoutReplay(v *ENBConfigurationUpdate) *bool {
	return &v.withoutReplay
}
func BridgeENBConfigurationUpdateIEContainerAPERValueFieldContext(v *ENBConfigurationUpdateIEContainerAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeENBConfigurationUpdateIEContainerAPERValueFieldReceived(v *ENBConfigurationUpdateIEContainerAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeENBConfigurationUpdateIEContainerAPERValueFieldReplay(v *ENBConfigurationUpdateIEContainerAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeENBConfigurationUpdateIEContainerAPERValueFieldWithoutReplay(v *ENBConfigurationUpdateIEContainerAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeENBConfigurationUpdateIEContainerValueCodecFieldCapture(v *ENBConfigurationUpdateIEContainerValueCodec) *func(ENBConfigurationUpdateIEContainer, aper.DecodeState) (ENBConfigurationUpdateIEContainer, aper.Snapshot) {
	return &v.capture
}
func BridgeENBConfigurationUpdateIEContainerValueCodecFieldCompare(v *ENBConfigurationUpdateIEContainerValueCodec) *func(ENBConfigurationUpdateIEContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeENBConfigurationUpdateIEContainerValueCodecFieldContext(v *ENBConfigurationUpdateIEContainerValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeENBConfigurationUpdateIEContainerValueCodecFieldDecode(v *ENBConfigurationUpdateIEContainerValueCodec) *func([]byte, aper.DecodeState) (ENBConfigurationUpdateIEContainer, error) {
	return &v.decode
}
func BridgeENBConfigurationUpdateIEContainerValueCodecFieldEncode(v *ENBConfigurationUpdateIEContainerValueCodec) *func(ENBConfigurationUpdateIEContainer, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeENBConfigurationUpdateIEContainerValueCodecFieldPath(v *ENBConfigurationUpdateIEContainerValueCodec) *aper.Path {
	return &v.path
}
func BridgeENBConfigurationUpdateIEContainerValueCodecMethodEncodeBudgetValue(v ENBConfigurationUpdateIEContainerValueCodec, a0 ENBConfigurationUpdateIEContainer, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeENBConfigurationUpdateIEContainerValueCodecMethodEncodeChanged(v ENBConfigurationUpdateIEContainerValueCodec, a0 ENBConfigurationUpdateIEContainer, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeENBConfigurationUpdateIEFieldAPERValueFieldContext(v *ENBConfigurationUpdateIEFieldAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeENBConfigurationUpdateIEFieldAPERValueFieldReceived(v *ENBConfigurationUpdateIEFieldAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeENBConfigurationUpdateIEFieldAPERValueFieldReplay(v *ENBConfigurationUpdateIEFieldAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeENBConfigurationUpdateIEFieldAPERValueFieldWithoutReplay(v *ENBConfigurationUpdateIEFieldAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeENBConfigurationUpdateIEFieldFieldReceived(v *ENBConfigurationUpdateIEField) *aper.CompletePadding {
	return &v.received
}
func BridgeENBConfigurationUpdateIEFieldFieldReplay(v *ENBConfigurationUpdateIEField) *aper.Snapshot {
	return &v.replay
}
func BridgeENBConfigurationUpdateIEFieldFieldStream(v *ENBConfigurationUpdateIEField) *aper.WireSpan {
	return &v.stream
}
func BridgeENBConfigurationUpdateIEFieldFieldWithoutReplay(v *ENBConfigurationUpdateIEField) *bool {
	return &v.withoutReplay
}
func BridgeENBConfigurationUpdateIEFieldMethodMarshalAPERTo(v *ENBConfigurationUpdateIEField, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeENBConfigurationUpdateIEFieldMethodUnmarshalAPERFrom(v *ENBConfigurationUpdateIEField, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeENBConfigurationUpdateIEFieldValueCodecFieldCapture(v *ENBConfigurationUpdateIEFieldValueCodec) *func(ENBConfigurationUpdateIEField, aper.DecodeState) (ENBConfigurationUpdateIEField, aper.Snapshot) {
	return &v.capture
}
func BridgeENBConfigurationUpdateIEFieldValueCodecFieldCompare(v *ENBConfigurationUpdateIEFieldValueCodec) *func(ENBConfigurationUpdateIEField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeENBConfigurationUpdateIEFieldValueCodecFieldContext(v *ENBConfigurationUpdateIEFieldValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeENBConfigurationUpdateIEFieldValueCodecFieldDecode(v *ENBConfigurationUpdateIEFieldValueCodec) *func([]byte, aper.DecodeState) (ENBConfigurationUpdateIEField, error) {
	return &v.decode
}
func BridgeENBConfigurationUpdateIEFieldValueCodecFieldEncode(v *ENBConfigurationUpdateIEFieldValueCodec) *func(ENBConfigurationUpdateIEField, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeENBConfigurationUpdateIEFieldValueCodecFieldPath(v *ENBConfigurationUpdateIEFieldValueCodec) *aper.Path {
	return &v.path
}
func BridgeENBConfigurationUpdateIEFieldValueCodecMethodEncodeBudgetValue(v ENBConfigurationUpdateIEFieldValueCodec, a0 ENBConfigurationUpdateIEField, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeENBConfigurationUpdateIEFieldValueCodecMethodEncodeChanged(v ENBConfigurationUpdateIEFieldValueCodec, a0 ENBConfigurationUpdateIEField, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeENBConfigurationUpdateIETableMethodInfoCSGIdList(v ENBConfigurationUpdateIETable) s00.FieldInfo {
	return v.infoCSGIdList()
}
func BridgeENBConfigurationUpdateIETableMethodInfoConnectedengNBToAddList(v ENBConfigurationUpdateIETable) s00.FieldInfo {
	return v.infoConnectedengNBToAddList()
}
func BridgeENBConfigurationUpdateIETableMethodInfoConnectedengNBToRemoveList(v ENBConfigurationUpdateIETable) s00.FieldInfo {
	return v.infoConnectedengNBToRemoveList()
}
func BridgeENBConfigurationUpdateIETableMethodInfoDefaultPagingDRX(v ENBConfigurationUpdateIETable) s00.FieldInfo {
	return v.infoDefaultPagingDRX()
}
func BridgeENBConfigurationUpdateIETableMethodInfoENBname(v ENBConfigurationUpdateIETable) s00.FieldInfo {
	return v.infoENBname()
}
func BridgeENBConfigurationUpdateIETableMethodInfoNBIoTDefaultPagingDRX(v ENBConfigurationUpdateIETable) s00.FieldInfo {
	return v.infoNBIoTDefaultPagingDRX()
}
func BridgeENBConfigurationUpdateIETableMethodInfoSupportedTAs(v ENBConfigurationUpdateIETable) s00.FieldInfo {
	return v.infoSupportedTAs()
}
func BridgeENBConfigurationUpdateIEValueERABIEContainerListAPERValueFieldContext(v *ENBConfigurationUpdateIEValueERABIEContainerListAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeENBConfigurationUpdateIEValueERABIEContainerListAPERValueFieldReceived(v *ENBConfigurationUpdateIEValueERABIEContainerListAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeENBConfigurationUpdateIEValueERABIEContainerListAPERValueFieldReplay(v *ENBConfigurationUpdateIEValueERABIEContainerListAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeENBConfigurationUpdateIEValueERABIEContainerListAPERValueFieldWithoutReplay(v *ENBConfigurationUpdateIEValueERABIEContainerListAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeENBConfigurationUpdateIEValueERABIEContainerListValueCodecFieldCapture(v *ENBConfigurationUpdateIEValueERABIEContainerListValueCodec) *func(ENBConfigurationUpdateIEValueERABIEContainerList, aper.DecodeState) (ENBConfigurationUpdateIEValueERABIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgeENBConfigurationUpdateIEValueERABIEContainerListValueCodecFieldCompare(v *ENBConfigurationUpdateIEValueERABIEContainerListValueCodec) *func(ENBConfigurationUpdateIEValueERABIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeENBConfigurationUpdateIEValueERABIEContainerListValueCodecFieldContext(v *ENBConfigurationUpdateIEValueERABIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeENBConfigurationUpdateIEValueERABIEContainerListValueCodecFieldDecode(v *ENBConfigurationUpdateIEValueERABIEContainerListValueCodec) *func([]byte, aper.DecodeState) (ENBConfigurationUpdateIEValueERABIEContainerList, error) {
	return &v.decode
}
func BridgeENBConfigurationUpdateIEValueERABIEContainerListValueCodecFieldEncode(v *ENBConfigurationUpdateIEValueERABIEContainerListValueCodec) *func(ENBConfigurationUpdateIEValueERABIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeENBConfigurationUpdateIEValueERABIEContainerListValueCodecFieldPath(v *ENBConfigurationUpdateIEValueERABIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgeENBConfigurationUpdateIEValueERABIEContainerListValueCodecMethodEncodeBudgetValue(v ENBConfigurationUpdateIEValueERABIEContainerListValueCodec, a0 ENBConfigurationUpdateIEValueERABIEContainerList, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeENBConfigurationUpdateIEValueERABIEContainerListValueCodecMethodEncodeChanged(v ENBConfigurationUpdateIEValueERABIEContainerListValueCodec, a0 ENBConfigurationUpdateIEValueERABIEContainerList, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeENBConfigurationUpdateIEValueFieldId(v *ENBConfigurationUpdateIEValue) *s00.ProtocolIEID {
	return &v.id
}
func BridgeENBConfigurationUpdateIEValueFieldIsOpaque(v *ENBConfigurationUpdateIEValue) *bool {
	return &v.isOpaque
}
func BridgeENBConfigurationUpdateIEValueFieldOpaque(v *ENBConfigurationUpdateIEValue) *aper.OpaqueOpenType {
	return &v.opaque
}
func BridgeENBConfigurationUpdateIEValueFieldReceived(v *ENBConfigurationUpdateIEValue) *aper.WireSpan {
	return &v.received
}
func BridgeENBConfigurationUpdateIEValueFieldReplay(v *ENBConfigurationUpdateIEValue) *aper.Snapshot {
	return &v.replay
}
func BridgeENBConfigurationUpdateIEValueFieldRowCSGIdList(v *ENBConfigurationUpdateIEValue) **s14.CSGIdList {
	return &v.rowCSGIdList
}
func BridgeENBConfigurationUpdateIEValueFieldRowConnectedengNBToAddList(v *ENBConfigurationUpdateIEValue) **s31.ConnectedengNBList {
	return &v.rowConnectedengNBToAddList
}
func BridgeENBConfigurationUpdateIEValueFieldRowConnectedengNBToRemoveList(v *ENBConfigurationUpdateIEValue) **s31.ConnectedengNBList {
	return &v.rowConnectedengNBToRemoveList
}
func BridgeENBConfigurationUpdateIEValueFieldRowDefaultPagingDRX(v *ENBConfigurationUpdateIEValue) **s00.PagingDRX {
	return &v.rowDefaultPagingDRX
}
func BridgeENBConfigurationUpdateIEValueFieldRowENBname(v *ENBConfigurationUpdateIEValue) **s00.ENBname {
	return &v.rowENBname
}
func BridgeENBConfigurationUpdateIEValueFieldRowNBIoTDefaultPagingDRX(v *ENBConfigurationUpdateIEValue) **s00.NBIoTDefaultPagingDRX {
	return &v.rowNBIoTDefaultPagingDRX
}
func BridgeENBConfigurationUpdateIEValueFieldRowSupportedTAs(v *ENBConfigurationUpdateIEValue) **s31.SupportedTAs {
	return &v.rowSupportedTAs
}
func BridgeENBConfigurationUpdateIEValueMethodCaptureSemantics(v ENBConfigurationUpdateIEValue, a0 aper.SemanticCapture) ENBConfigurationUpdateIEValue {
	return v.captureSemantics(a0)
}
func BridgeENBConfigurationUpdateIEValueMethodCompareSemantics(v ENBConfigurationUpdateIEValue, a0 aper.SemanticComparison) aper.SemanticComparison {
	return v.compareSemantics(a0)
}
func BridgeENBConfigurationUpdateIEValueMethodDecode(v ENBConfigurationUpdateIEValue, a0 s00.ProtocolIEID, a1 aper.OpaqueOpenType) (ENBConfigurationUpdateIEValue, error) {
	return v.decode(a0, a1)
}
func BridgeENBConfigurationUpdateIEValueMethodEncode(v ENBConfigurationUpdateIEValue) ([]byte, error) {
	return v.encode()
}
func BridgeENBConfigurationUpdateIEValueMethodEncodeFresh(v ENBConfigurationUpdateIEValue, a0 bool, a1 *aper.DecodeBudget) ([]byte, error) {
	return v.encodeFresh(a0, a1)
}
func BridgeENBConfigurationUpdateIEValueMethodMatchesID(v ENBConfigurationUpdateIEValue, a0 s00.ProtocolIEID, a1 ...*aper.DecodeBudget) bool {
	return v.matchesID(a0, a1...)
}
func BridgeENBConfigurationUpdateIEValueMethodReason(v ENBConfigurationUpdateIEValue, a0 s00.ProtocolIEID) aper.OpaqueReason {
	return v.reason(a0)
}
func BridgeENBConfigurationUpdateIEValueMethodRule(v ENBConfigurationUpdateIEValue) aper.SourceRule {
	return v.rule()
}
func BridgeENBConfigurationUpdateIEValueProtocolErrorIEContainerListAPERValueFieldContext(v *ENBConfigurationUpdateIEValueProtocolErrorIEContainerListAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeENBConfigurationUpdateIEValueProtocolErrorIEContainerListAPERValueFieldReceived(v *ENBConfigurationUpdateIEValueProtocolErrorIEContainerListAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeENBConfigurationUpdateIEValueProtocolErrorIEContainerListAPERValueFieldReplay(v *ENBConfigurationUpdateIEValueProtocolErrorIEContainerListAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeENBConfigurationUpdateIEValueProtocolErrorIEContainerListAPERValueFieldWithoutReplay(v *ENBConfigurationUpdateIEValueProtocolErrorIEContainerListAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeENBConfigurationUpdateIEValueProtocolErrorIEContainerListValueCodecFieldCapture(v *ENBConfigurationUpdateIEValueProtocolErrorIEContainerListValueCodec) *func(ENBConfigurationUpdateIEValueProtocolErrorIEContainerList, aper.DecodeState) (ENBConfigurationUpdateIEValueProtocolErrorIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgeENBConfigurationUpdateIEValueProtocolErrorIEContainerListValueCodecFieldCompare(v *ENBConfigurationUpdateIEValueProtocolErrorIEContainerListValueCodec) *func(ENBConfigurationUpdateIEValueProtocolErrorIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeENBConfigurationUpdateIEValueProtocolErrorIEContainerListValueCodecFieldContext(v *ENBConfigurationUpdateIEValueProtocolErrorIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeENBConfigurationUpdateIEValueProtocolErrorIEContainerListValueCodecFieldDecode(v *ENBConfigurationUpdateIEValueProtocolErrorIEContainerListValueCodec) *func([]byte, aper.DecodeState) (ENBConfigurationUpdateIEValueProtocolErrorIEContainerList, error) {
	return &v.decode
}
func BridgeENBConfigurationUpdateIEValueProtocolErrorIEContainerListValueCodecFieldEncode(v *ENBConfigurationUpdateIEValueProtocolErrorIEContainerListValueCodec) *func(ENBConfigurationUpdateIEValueProtocolErrorIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeENBConfigurationUpdateIEValueProtocolErrorIEContainerListValueCodecFieldPath(v *ENBConfigurationUpdateIEValueProtocolErrorIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgeENBConfigurationUpdateIEValueProtocolErrorIEContainerListValueCodecMethodEncodeBudgetValue(v ENBConfigurationUpdateIEValueProtocolErrorIEContainerListValueCodec, a0 ENBConfigurationUpdateIEValueProtocolErrorIEContainerList, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeENBConfigurationUpdateIEValueProtocolErrorIEContainerListValueCodecMethodEncodeChanged(v ENBConfigurationUpdateIEValueProtocolErrorIEContainerListValueCodec, a0 ENBConfigurationUpdateIEValueProtocolErrorIEContainerList, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeENBConfigurationUpdateIEValueProtocolIEContainerListAPERValueFieldContext(v *ENBConfigurationUpdateIEValueProtocolIEContainerListAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeENBConfigurationUpdateIEValueProtocolIEContainerListAPERValueFieldReceived(v *ENBConfigurationUpdateIEValueProtocolIEContainerListAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeENBConfigurationUpdateIEValueProtocolIEContainerListAPERValueFieldReplay(v *ENBConfigurationUpdateIEValueProtocolIEContainerListAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeENBConfigurationUpdateIEValueProtocolIEContainerListAPERValueFieldWithoutReplay(v *ENBConfigurationUpdateIEValueProtocolIEContainerListAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeENBConfigurationUpdateIEValueProtocolIEContainerListValueCodecFieldCapture(v *ENBConfigurationUpdateIEValueProtocolIEContainerListValueCodec) *func(ENBConfigurationUpdateIEValueProtocolIEContainerList, aper.DecodeState) (ENBConfigurationUpdateIEValueProtocolIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgeENBConfigurationUpdateIEValueProtocolIEContainerListValueCodecFieldCompare(v *ENBConfigurationUpdateIEValueProtocolIEContainerListValueCodec) *func(ENBConfigurationUpdateIEValueProtocolIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeENBConfigurationUpdateIEValueProtocolIEContainerListValueCodecFieldContext(v *ENBConfigurationUpdateIEValueProtocolIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeENBConfigurationUpdateIEValueProtocolIEContainerListValueCodecFieldDecode(v *ENBConfigurationUpdateIEValueProtocolIEContainerListValueCodec) *func([]byte, aper.DecodeState) (ENBConfigurationUpdateIEValueProtocolIEContainerList, error) {
	return &v.decode
}
func BridgeENBConfigurationUpdateIEValueProtocolIEContainerListValueCodecFieldEncode(v *ENBConfigurationUpdateIEValueProtocolIEContainerListValueCodec) *func(ENBConfigurationUpdateIEValueProtocolIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeENBConfigurationUpdateIEValueProtocolIEContainerListValueCodecFieldPath(v *ENBConfigurationUpdateIEValueProtocolIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgeENBConfigurationUpdateIEValueProtocolIEContainerListValueCodecMethodEncodeBudgetValue(v ENBConfigurationUpdateIEValueProtocolIEContainerListValueCodec, a0 ENBConfigurationUpdateIEValueProtocolIEContainerList, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeENBConfigurationUpdateIEValueProtocolIEContainerListValueCodecMethodEncodeChanged(v ENBConfigurationUpdateIEValueProtocolIEContainerListValueCodec, a0 ENBConfigurationUpdateIEValueProtocolIEContainerList, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeENBConfigurationUpdateMethodMarshalAPERBudget(v *ENBConfigurationUpdate, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeENBConfigurationUpdateMethodMarshalAPERBudgetValue(v *ENBConfigurationUpdate, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudgetValue(a0, a1)
}
func BridgeENBConfigurationUpdateMethodMarshalAPERChanged(v *ENBConfigurationUpdate, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeENBConfigurationUpdateMethodMarshalAPERChangedValue(v *ENBConfigurationUpdate, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeENBConfigurationUpdateMethodMarshalAPERLegacy(v *ENBConfigurationUpdate) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeENBConfigurationUpdateMethodMarshalAPERNewValue(v *ENBConfigurationUpdate, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERNewValue(a0, a1)
}
func BridgeENBConfigurationUpdateMethodMarshalAPERPlanned(v *ENBConfigurationUpdate, a0 *aper.DecodeBudget, a1 bool, a2 *aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1, a2)
}
func BridgeENBConfigurationUpdateMethodMarshalAPERTo(v *ENBConfigurationUpdate, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeENBConfigurationUpdateMethodUnmarshalAPERFrom(v *ENBConfigurationUpdate, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeENBConfigurationUpdateMethodUnmarshalAPERLegacy(v *ENBConfigurationUpdate, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeENBConfigurationUpdateMethodUnmarshalAPERWithOptions(v *ENBConfigurationUpdate, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeENBConfigurationUpdateNBIoTDefaultPagingDRXIEBindingFieldCodec(v *ENBConfigurationUpdateNBIoTDefaultPagingDRXIEBinding) *s01.NBIoTDefaultPagingDRXValueCodec {
	return &v.codec
}
func BridgeENBConfigurationUpdateNBIoTDefaultPagingDRXIEBindingFieldGet(v *ENBConfigurationUpdateNBIoTDefaultPagingDRXIEBinding) *func(*ENBConfigurationUpdateIEValue) (*s00.NBIoTDefaultPagingDRX, bool) {
	return &v.get
}
func BridgeENBConfigurationUpdateNBIoTDefaultPagingDRXIEBindingFieldInfo(v *ENBConfigurationUpdateNBIoTDefaultPagingDRXIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeENBConfigurationUpdateNBIoTDefaultPagingDRXIEBindingFieldInject(v *ENBConfigurationUpdateNBIoTDefaultPagingDRXIEBinding) *func(s00.NBIoTDefaultPagingDRX) ENBConfigurationUpdateIEValue {
	return &v.inject
}
func BridgeENBConfigurationUpdatePagingDRXIEBindingFieldCodec(v *ENBConfigurationUpdatePagingDRXIEBinding) *s01.PagingDRXValueCodec {
	return &v.codec
}
func BridgeENBConfigurationUpdatePagingDRXIEBindingFieldGet(v *ENBConfigurationUpdatePagingDRXIEBinding) *func(*ENBConfigurationUpdateIEValue) (*s00.PagingDRX, bool) {
	return &v.get
}
func BridgeENBConfigurationUpdatePagingDRXIEBindingFieldInfo(v *ENBConfigurationUpdatePagingDRXIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeENBConfigurationUpdatePagingDRXIEBindingFieldInject(v *ENBConfigurationUpdatePagingDRXIEBinding) *func(s00.PagingDRX) ENBConfigurationUpdateIEValue {
	return &v.inject
}
func BridgeENBConfigurationUpdateSupportedTAsIEBindingFieldCodec(v *ENBConfigurationUpdateSupportedTAsIEBinding) *s31.SupportedTAsValueCodec {
	return &v.codec
}
func BridgeENBConfigurationUpdateSupportedTAsIEBindingFieldGet(v *ENBConfigurationUpdateSupportedTAsIEBinding) *func(*ENBConfigurationUpdateIEValue) (*s31.SupportedTAs, bool) {
	return &v.get
}
func BridgeENBConfigurationUpdateSupportedTAsIEBindingFieldInfo(v *ENBConfigurationUpdateSupportedTAsIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeENBConfigurationUpdateSupportedTAsIEBindingFieldInject(v *ENBConfigurationUpdateSupportedTAsIEBinding) *func(s31.SupportedTAs) ENBConfigurationUpdateIEValue {
	return &v.inject
}
func BridgeENBConfigurationUpdateValueCodecFieldCapture(v *ENBConfigurationUpdateValueCodec) *func(ENBConfigurationUpdate, aper.DecodeState) (ENBConfigurationUpdate, aper.Snapshot) {
	return &v.capture
}
func BridgeENBConfigurationUpdateValueCodecFieldCompare(v *ENBConfigurationUpdateValueCodec) *func(ENBConfigurationUpdate, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeENBConfigurationUpdateValueCodecFieldContext(v *ENBConfigurationUpdateValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeENBConfigurationUpdateValueCodecFieldDecode(v *ENBConfigurationUpdateValueCodec) *func([]byte, aper.DecodeState) (ENBConfigurationUpdate, error) {
	return &v.decode
}
func BridgeENBConfigurationUpdateValueCodecFieldEncode(v *ENBConfigurationUpdateValueCodec) *func(ENBConfigurationUpdate, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeENBConfigurationUpdateValueCodecFieldPath(v *ENBConfigurationUpdateValueCodec) *aper.Path {
	return &v.path
}
func BridgeENBConfigurationUpdateValueCodecMethodEncodeBudgetValue(v ENBConfigurationUpdateValueCodec, a0 ENBConfigurationUpdate, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeENBConfigurationUpdateValueCodecMethodEncodeChanged(v ENBConfigurationUpdateValueCodec, a0 ENBConfigurationUpdate, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeMMEConfigurationUpdateAPERValueFieldContext(v *MMEConfigurationUpdateAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeMMEConfigurationUpdateAPERValueFieldReceived(v *MMEConfigurationUpdateAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeMMEConfigurationUpdateAPERValueFieldReplay(v *MMEConfigurationUpdateAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeMMEConfigurationUpdateAPERValueFieldWithoutReplay(v *MMEConfigurationUpdateAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeMMEConfigurationUpdateFieldExtCount(v *MMEConfigurationUpdate) *int64   { return &v.extCount }
func BridgeMMEConfigurationUpdateFieldExtData(v *MMEConfigurationUpdate) *[][]byte { return &v.extData }
func BridgeMMEConfigurationUpdateFieldExtOrigin(v *MMEConfigurationUpdate) *[]aper.OpaqueOrigin {
	return &v.extOrigin
}
func BridgeMMEConfigurationUpdateFieldExtPresent(v *MMEConfigurationUpdate) *[]bool {
	return &v.extPresent
}
func BridgeMMEConfigurationUpdateFieldExtWire(v *MMEConfigurationUpdate) *[]aper.WireSpan {
	return &v.extWire
}
func BridgeMMEConfigurationUpdateFieldPerExtPadding(v *MMEConfigurationUpdate) *[]aper.CompletePadding {
	return &v.perExtPadding
}
func BridgeMMEConfigurationUpdateFieldPerPadding(v *MMEConfigurationUpdate) *aper.FinalPadding {
	return &v.perPadding
}
func BridgeMMEConfigurationUpdateFieldProtocolIEsIndef(v *MMEConfigurationUpdate) *bool {
	return &v.protocolIEsIndef
}
func BridgeMMEConfigurationUpdateFieldReceived(v *MMEConfigurationUpdate) *bool { return &v.received }
func BridgeMMEConfigurationUpdateFieldReceivedAbsolute(v *MMEConfigurationUpdate) *bool {
	return &v.receivedAbsolute
}
func BridgeMMEConfigurationUpdateFieldReceivedBytes(v *MMEConfigurationUpdate) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeMMEConfigurationUpdateFieldReceivedLocation(v *MMEConfigurationUpdate) *aper.Location {
	return &v.receivedLocation
}
func BridgeMMEConfigurationUpdateFieldReplay(v *MMEConfigurationUpdate) *aper.Snapshot {
	return &v.replay
}
func BridgeMMEConfigurationUpdateFieldStream(v *MMEConfigurationUpdate) *aper.WireSpan {
	return &v.stream
}
func BridgeMMEConfigurationUpdateFieldWithoutReplay(v *MMEConfigurationUpdate) *bool {
	return &v.withoutReplay
}
func BridgeMMEConfigurationUpdateIEFieldValueCodecFieldCapture(v *MMEConfigurationUpdateIEFieldValueCodec) *func(s43.MMEConfigurationUpdateIEField, aper.DecodeState) (s43.MMEConfigurationUpdateIEField, aper.Snapshot) {
	return &v.capture
}
func BridgeMMEConfigurationUpdateIEFieldValueCodecFieldCompare(v *MMEConfigurationUpdateIEFieldValueCodec) *func(s43.MMEConfigurationUpdateIEField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeMMEConfigurationUpdateIEFieldValueCodecFieldContext(v *MMEConfigurationUpdateIEFieldValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeMMEConfigurationUpdateIEFieldValueCodecFieldDecode(v *MMEConfigurationUpdateIEFieldValueCodec) *func([]byte, aper.DecodeState) (s43.MMEConfigurationUpdateIEField, error) {
	return &v.decode
}
func BridgeMMEConfigurationUpdateIEFieldValueCodecFieldEncode(v *MMEConfigurationUpdateIEFieldValueCodec) *func(s43.MMEConfigurationUpdateIEField, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeMMEConfigurationUpdateIEFieldValueCodecFieldPath(v *MMEConfigurationUpdateIEFieldValueCodec) *aper.Path {
	return &v.path
}
func BridgeMMEConfigurationUpdateIEFieldValueCodecMethodEncodeBudgetValue(v MMEConfigurationUpdateIEFieldValueCodec, a0 s43.MMEConfigurationUpdateIEField, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeMMEConfigurationUpdateIEFieldValueCodecMethodEncodeChanged(v MMEConfigurationUpdateIEFieldValueCodec, a0 s43.MMEConfigurationUpdateIEField, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeMMEConfigurationUpdateIETableMethodInfoMMEname(v MMEConfigurationUpdateIETable) s00.FieldInfo {
	return v.infoMMEname()
}
func BridgeMMEConfigurationUpdateIETableMethodInfoRelativeMMECapacity(v MMEConfigurationUpdateIETable) s00.FieldInfo {
	return v.infoRelativeMMECapacity()
}
func BridgeMMEConfigurationUpdateIETableMethodInfoServedDCNs(v MMEConfigurationUpdateIETable) s00.FieldInfo {
	return v.infoServedDCNs()
}
func BridgeMMEConfigurationUpdateIETableMethodInfoServedGUMMEIs(v MMEConfigurationUpdateIETable) s00.FieldInfo {
	return v.infoServedGUMMEIs()
}
func BridgeMMEConfigurationUpdateIEValueERABIEContainerListAPERValueFieldContext(v *MMEConfigurationUpdateIEValueERABIEContainerListAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeMMEConfigurationUpdateIEValueERABIEContainerListAPERValueFieldReceived(v *MMEConfigurationUpdateIEValueERABIEContainerListAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeMMEConfigurationUpdateIEValueERABIEContainerListAPERValueFieldReplay(v *MMEConfigurationUpdateIEValueERABIEContainerListAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeMMEConfigurationUpdateIEValueERABIEContainerListAPERValueFieldWithoutReplay(v *MMEConfigurationUpdateIEValueERABIEContainerListAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeMMEConfigurationUpdateIEValueERABIEContainerListValueCodecFieldCapture(v *MMEConfigurationUpdateIEValueERABIEContainerListValueCodec) *func(MMEConfigurationUpdateIEValueERABIEContainerList, aper.DecodeState) (MMEConfigurationUpdateIEValueERABIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgeMMEConfigurationUpdateIEValueERABIEContainerListValueCodecFieldCompare(v *MMEConfigurationUpdateIEValueERABIEContainerListValueCodec) *func(MMEConfigurationUpdateIEValueERABIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeMMEConfigurationUpdateIEValueERABIEContainerListValueCodecFieldContext(v *MMEConfigurationUpdateIEValueERABIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeMMEConfigurationUpdateIEValueERABIEContainerListValueCodecFieldDecode(v *MMEConfigurationUpdateIEValueERABIEContainerListValueCodec) *func([]byte, aper.DecodeState) (MMEConfigurationUpdateIEValueERABIEContainerList, error) {
	return &v.decode
}
func BridgeMMEConfigurationUpdateIEValueERABIEContainerListValueCodecFieldEncode(v *MMEConfigurationUpdateIEValueERABIEContainerListValueCodec) *func(MMEConfigurationUpdateIEValueERABIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeMMEConfigurationUpdateIEValueERABIEContainerListValueCodecFieldPath(v *MMEConfigurationUpdateIEValueERABIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgeMMEConfigurationUpdateIEValueERABIEContainerListValueCodecMethodEncodeBudgetValue(v MMEConfigurationUpdateIEValueERABIEContainerListValueCodec, a0 MMEConfigurationUpdateIEValueERABIEContainerList, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeMMEConfigurationUpdateIEValueERABIEContainerListValueCodecMethodEncodeChanged(v MMEConfigurationUpdateIEValueERABIEContainerListValueCodec, a0 MMEConfigurationUpdateIEValueERABIEContainerList, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeMMEConfigurationUpdateIEValueProtocolErrorIEContainerListAPERValueFieldContext(v *MMEConfigurationUpdateIEValueProtocolErrorIEContainerListAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeMMEConfigurationUpdateIEValueProtocolErrorIEContainerListAPERValueFieldReceived(v *MMEConfigurationUpdateIEValueProtocolErrorIEContainerListAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeMMEConfigurationUpdateIEValueProtocolErrorIEContainerListAPERValueFieldReplay(v *MMEConfigurationUpdateIEValueProtocolErrorIEContainerListAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeMMEConfigurationUpdateIEValueProtocolErrorIEContainerListAPERValueFieldWithoutReplay(v *MMEConfigurationUpdateIEValueProtocolErrorIEContainerListAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeMMEConfigurationUpdateIEValueProtocolErrorIEContainerListValueCodecFieldCapture(v *MMEConfigurationUpdateIEValueProtocolErrorIEContainerListValueCodec) *func(MMEConfigurationUpdateIEValueProtocolErrorIEContainerList, aper.DecodeState) (MMEConfigurationUpdateIEValueProtocolErrorIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgeMMEConfigurationUpdateIEValueProtocolErrorIEContainerListValueCodecFieldCompare(v *MMEConfigurationUpdateIEValueProtocolErrorIEContainerListValueCodec) *func(MMEConfigurationUpdateIEValueProtocolErrorIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeMMEConfigurationUpdateIEValueProtocolErrorIEContainerListValueCodecFieldContext(v *MMEConfigurationUpdateIEValueProtocolErrorIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeMMEConfigurationUpdateIEValueProtocolErrorIEContainerListValueCodecFieldDecode(v *MMEConfigurationUpdateIEValueProtocolErrorIEContainerListValueCodec) *func([]byte, aper.DecodeState) (MMEConfigurationUpdateIEValueProtocolErrorIEContainerList, error) {
	return &v.decode
}
func BridgeMMEConfigurationUpdateIEValueProtocolErrorIEContainerListValueCodecFieldEncode(v *MMEConfigurationUpdateIEValueProtocolErrorIEContainerListValueCodec) *func(MMEConfigurationUpdateIEValueProtocolErrorIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeMMEConfigurationUpdateIEValueProtocolErrorIEContainerListValueCodecFieldPath(v *MMEConfigurationUpdateIEValueProtocolErrorIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgeMMEConfigurationUpdateIEValueProtocolErrorIEContainerListValueCodecMethodEncodeBudgetValue(v MMEConfigurationUpdateIEValueProtocolErrorIEContainerListValueCodec, a0 MMEConfigurationUpdateIEValueProtocolErrorIEContainerList, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeMMEConfigurationUpdateIEValueProtocolErrorIEContainerListValueCodecMethodEncodeChanged(v MMEConfigurationUpdateIEValueProtocolErrorIEContainerListValueCodec, a0 MMEConfigurationUpdateIEValueProtocolErrorIEContainerList, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeMMEConfigurationUpdateIEValueProtocolIEContainerListAPERValueFieldContext(v *MMEConfigurationUpdateIEValueProtocolIEContainerListAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeMMEConfigurationUpdateIEValueProtocolIEContainerListAPERValueFieldReceived(v *MMEConfigurationUpdateIEValueProtocolIEContainerListAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeMMEConfigurationUpdateIEValueProtocolIEContainerListAPERValueFieldReplay(v *MMEConfigurationUpdateIEValueProtocolIEContainerListAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeMMEConfigurationUpdateIEValueProtocolIEContainerListAPERValueFieldWithoutReplay(v *MMEConfigurationUpdateIEValueProtocolIEContainerListAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeMMEConfigurationUpdateIEValueProtocolIEContainerListValueCodecFieldCapture(v *MMEConfigurationUpdateIEValueProtocolIEContainerListValueCodec) *func(MMEConfigurationUpdateIEValueProtocolIEContainerList, aper.DecodeState) (MMEConfigurationUpdateIEValueProtocolIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgeMMEConfigurationUpdateIEValueProtocolIEContainerListValueCodecFieldCompare(v *MMEConfigurationUpdateIEValueProtocolIEContainerListValueCodec) *func(MMEConfigurationUpdateIEValueProtocolIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeMMEConfigurationUpdateIEValueProtocolIEContainerListValueCodecFieldContext(v *MMEConfigurationUpdateIEValueProtocolIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeMMEConfigurationUpdateIEValueProtocolIEContainerListValueCodecFieldDecode(v *MMEConfigurationUpdateIEValueProtocolIEContainerListValueCodec) *func([]byte, aper.DecodeState) (MMEConfigurationUpdateIEValueProtocolIEContainerList, error) {
	return &v.decode
}
func BridgeMMEConfigurationUpdateIEValueProtocolIEContainerListValueCodecFieldEncode(v *MMEConfigurationUpdateIEValueProtocolIEContainerListValueCodec) *func(MMEConfigurationUpdateIEValueProtocolIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeMMEConfigurationUpdateIEValueProtocolIEContainerListValueCodecFieldPath(v *MMEConfigurationUpdateIEValueProtocolIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgeMMEConfigurationUpdateIEValueProtocolIEContainerListValueCodecMethodEncodeBudgetValue(v MMEConfigurationUpdateIEValueProtocolIEContainerListValueCodec, a0 MMEConfigurationUpdateIEValueProtocolIEContainerList, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeMMEConfigurationUpdateIEValueProtocolIEContainerListValueCodecMethodEncodeChanged(v MMEConfigurationUpdateIEValueProtocolIEContainerListValueCodec, a0 MMEConfigurationUpdateIEValueProtocolIEContainerList, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeMMEConfigurationUpdateMMEnameIEBindingFieldCodec(v *MMEConfigurationUpdateMMEnameIEBinding) *s01.MMEnameValueCodec {
	return &v.codec
}
func BridgeMMEConfigurationUpdateMMEnameIEBindingFieldGet(v *MMEConfigurationUpdateMMEnameIEBinding) *func(*s43.MMEConfigurationUpdateIEValue) (*s00.MMEname, bool) {
	return &v.get
}
func BridgeMMEConfigurationUpdateMMEnameIEBindingFieldInfo(v *MMEConfigurationUpdateMMEnameIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeMMEConfigurationUpdateMMEnameIEBindingFieldInject(v *MMEConfigurationUpdateMMEnameIEBinding) *func(s00.MMEname) s43.MMEConfigurationUpdateIEValue {
	return &v.inject
}
func BridgeMMEConfigurationUpdateMethodMarshalAPERBudget(v *MMEConfigurationUpdate, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeMMEConfigurationUpdateMethodMarshalAPERBudgetValue(v *MMEConfigurationUpdate, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudgetValue(a0, a1)
}
func BridgeMMEConfigurationUpdateMethodMarshalAPERChanged(v *MMEConfigurationUpdate, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeMMEConfigurationUpdateMethodMarshalAPERChangedValue(v *MMEConfigurationUpdate, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeMMEConfigurationUpdateMethodMarshalAPERLegacy(v *MMEConfigurationUpdate) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeMMEConfigurationUpdateMethodMarshalAPERNewValue(v *MMEConfigurationUpdate, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERNewValue(a0, a1)
}
func BridgeMMEConfigurationUpdateMethodMarshalAPERPlanned(v *MMEConfigurationUpdate, a0 *aper.DecodeBudget, a1 bool, a2 *aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1, a2)
}
func BridgeMMEConfigurationUpdateMethodMarshalAPERTo(v *MMEConfigurationUpdate, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeMMEConfigurationUpdateMethodUnmarshalAPERFrom(v *MMEConfigurationUpdate, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeMMEConfigurationUpdateMethodUnmarshalAPERLegacy(v *MMEConfigurationUpdate, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeMMEConfigurationUpdateMethodUnmarshalAPERWithOptions(v *MMEConfigurationUpdate, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeMMEConfigurationUpdateRelativeMMECapacityIEBindingFieldCodec(v *MMEConfigurationUpdateRelativeMMECapacityIEBinding) *s01.RelativeMMECapacityValueCodec {
	return &v.codec
}
func BridgeMMEConfigurationUpdateRelativeMMECapacityIEBindingFieldGet(v *MMEConfigurationUpdateRelativeMMECapacityIEBinding) *func(*s43.MMEConfigurationUpdateIEValue) (*s00.RelativeMMECapacity, bool) {
	return &v.get
}
func BridgeMMEConfigurationUpdateRelativeMMECapacityIEBindingFieldInfo(v *MMEConfigurationUpdateRelativeMMECapacityIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeMMEConfigurationUpdateRelativeMMECapacityIEBindingFieldInject(v *MMEConfigurationUpdateRelativeMMECapacityIEBinding) *func(s00.RelativeMMECapacity) s43.MMEConfigurationUpdateIEValue {
	return &v.inject
}
func BridgeMMEConfigurationUpdateServedDCNsIEBindingFieldCodec(v *MMEConfigurationUpdateServedDCNsIEBinding) *s31.ServedDCNsValueCodec {
	return &v.codec
}
func BridgeMMEConfigurationUpdateServedDCNsIEBindingFieldGet(v *MMEConfigurationUpdateServedDCNsIEBinding) *func(*s43.MMEConfigurationUpdateIEValue) (*s31.ServedDCNs, bool) {
	return &v.get
}
func BridgeMMEConfigurationUpdateServedDCNsIEBindingFieldInfo(v *MMEConfigurationUpdateServedDCNsIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeMMEConfigurationUpdateServedDCNsIEBindingFieldInject(v *MMEConfigurationUpdateServedDCNsIEBinding) *func(s31.ServedDCNs) s43.MMEConfigurationUpdateIEValue {
	return &v.inject
}
func BridgeMMEConfigurationUpdateServedGUMMEIsIEBindingFieldCodec(v *MMEConfigurationUpdateServedGUMMEIsIEBinding) *s31.ServedGUMMEIsValueCodec {
	return &v.codec
}
func BridgeMMEConfigurationUpdateServedGUMMEIsIEBindingFieldGet(v *MMEConfigurationUpdateServedGUMMEIsIEBinding) *func(*s43.MMEConfigurationUpdateIEValue) (*s31.ServedGUMMEIs, bool) {
	return &v.get
}
func BridgeMMEConfigurationUpdateServedGUMMEIsIEBindingFieldInfo(v *MMEConfigurationUpdateServedGUMMEIsIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeMMEConfigurationUpdateServedGUMMEIsIEBindingFieldInject(v *MMEConfigurationUpdateServedGUMMEIsIEBinding) *func(s31.ServedGUMMEIs) s43.MMEConfigurationUpdateIEValue {
	return &v.inject
}
func BridgeMMEConfigurationUpdateValueCodecFieldCapture(v *MMEConfigurationUpdateValueCodec) *func(MMEConfigurationUpdate, aper.DecodeState) (MMEConfigurationUpdate, aper.Snapshot) {
	return &v.capture
}
func BridgeMMEConfigurationUpdateValueCodecFieldCompare(v *MMEConfigurationUpdateValueCodec) *func(MMEConfigurationUpdate, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeMMEConfigurationUpdateValueCodecFieldContext(v *MMEConfigurationUpdateValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeMMEConfigurationUpdateValueCodecFieldDecode(v *MMEConfigurationUpdateValueCodec) *func([]byte, aper.DecodeState) (MMEConfigurationUpdate, error) {
	return &v.decode
}
func BridgeMMEConfigurationUpdateValueCodecFieldEncode(v *MMEConfigurationUpdateValueCodec) *func(MMEConfigurationUpdate, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeMMEConfigurationUpdateValueCodecFieldPath(v *MMEConfigurationUpdateValueCodec) *aper.Path {
	return &v.path
}
func BridgeMMEConfigurationUpdateValueCodecMethodEncodeBudgetValue(v MMEConfigurationUpdateValueCodec, a0 MMEConfigurationUpdate, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeMMEConfigurationUpdateValueCodecMethodEncodeChanged(v MMEConfigurationUpdateValueCodec, a0 MMEConfigurationUpdate, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
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
func BridgeS1SetupRequestCSGIdListIEBindingFieldCodec(v *S1SetupRequestCSGIdListIEBinding) *s14.CSGIdListValueCodec {
	return &v.codec
}
func BridgeS1SetupRequestCSGIdListIEBindingFieldGet(v *S1SetupRequestCSGIdListIEBinding) *func(*S1SetupRequestIEValue) (*s14.CSGIdList, bool) {
	return &v.get
}
func BridgeS1SetupRequestCSGIdListIEBindingFieldInfo(v *S1SetupRequestCSGIdListIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeS1SetupRequestCSGIdListIEBindingFieldInject(v *S1SetupRequestCSGIdListIEBinding) *func(s14.CSGIdList) S1SetupRequestIEValue {
	return &v.inject
}
func BridgeS1SetupRequestConnectedengNBListIEBindingFieldCodec(v *S1SetupRequestConnectedengNBListIEBinding) *s31.ConnectedengNBListValueCodec {
	return &v.codec
}
func BridgeS1SetupRequestConnectedengNBListIEBindingFieldGet(v *S1SetupRequestConnectedengNBListIEBinding) *func(*S1SetupRequestIEValue) (*s31.ConnectedengNBList, bool) {
	return &v.get
}
func BridgeS1SetupRequestConnectedengNBListIEBindingFieldInfo(v *S1SetupRequestConnectedengNBListIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeS1SetupRequestConnectedengNBListIEBindingFieldInject(v *S1SetupRequestConnectedengNBListIEBinding) *func(s31.ConnectedengNBList) S1SetupRequestIEValue {
	return &v.inject
}
func BridgeS1SetupRequestENBnameIEBindingFieldCodec(v *S1SetupRequestENBnameIEBinding) *s00.ENBnameValueCodec {
	return &v.codec
}
func BridgeS1SetupRequestENBnameIEBindingFieldGet(v *S1SetupRequestENBnameIEBinding) *func(*S1SetupRequestIEValue) (*s00.ENBname, bool) {
	return &v.get
}
func BridgeS1SetupRequestENBnameIEBindingFieldInfo(v *S1SetupRequestENBnameIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeS1SetupRequestENBnameIEBindingFieldInject(v *S1SetupRequestENBnameIEBinding) *func(s00.ENBname) S1SetupRequestIEValue {
	return &v.inject
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
func BridgeS1SetupRequestGlobalENBIDIEBindingFieldCodec(v *S1SetupRequestGlobalENBIDIEBinding) *s18.GlobalENBIDValueCodec {
	return &v.codec
}
func BridgeS1SetupRequestGlobalENBIDIEBindingFieldGet(v *S1SetupRequestGlobalENBIDIEBinding) *func(*S1SetupRequestIEValue) (*s18.GlobalENBID, bool) {
	return &v.get
}
func BridgeS1SetupRequestGlobalENBIDIEBindingFieldInfo(v *S1SetupRequestGlobalENBIDIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeS1SetupRequestGlobalENBIDIEBindingFieldInject(v *S1SetupRequestGlobalENBIDIEBinding) *func(s18.GlobalENBID) S1SetupRequestIEValue {
	return &v.inject
}
func BridgeS1SetupRequestIEContainerAPERValueFieldContext(v *S1SetupRequestIEContainerAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeS1SetupRequestIEContainerAPERValueFieldReceived(v *S1SetupRequestIEContainerAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeS1SetupRequestIEContainerAPERValueFieldReplay(v *S1SetupRequestIEContainerAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeS1SetupRequestIEContainerAPERValueFieldWithoutReplay(v *S1SetupRequestIEContainerAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeS1SetupRequestIEContainerValueCodecFieldCapture(v *S1SetupRequestIEContainerValueCodec) *func(S1SetupRequestIEContainer, aper.DecodeState) (S1SetupRequestIEContainer, aper.Snapshot) {
	return &v.capture
}
func BridgeS1SetupRequestIEContainerValueCodecFieldCompare(v *S1SetupRequestIEContainerValueCodec) *func(S1SetupRequestIEContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeS1SetupRequestIEContainerValueCodecFieldContext(v *S1SetupRequestIEContainerValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeS1SetupRequestIEContainerValueCodecFieldDecode(v *S1SetupRequestIEContainerValueCodec) *func([]byte, aper.DecodeState) (S1SetupRequestIEContainer, error) {
	return &v.decode
}
func BridgeS1SetupRequestIEContainerValueCodecFieldEncode(v *S1SetupRequestIEContainerValueCodec) *func(S1SetupRequestIEContainer, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeS1SetupRequestIEContainerValueCodecFieldPath(v *S1SetupRequestIEContainerValueCodec) *aper.Path {
	return &v.path
}
func BridgeS1SetupRequestIEContainerValueCodecMethodEncodeBudgetValue(v S1SetupRequestIEContainerValueCodec, a0 S1SetupRequestIEContainer, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeS1SetupRequestIEContainerValueCodecMethodEncodeChanged(v S1SetupRequestIEContainerValueCodec, a0 S1SetupRequestIEContainer, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeS1SetupRequestIEFieldAPERValueFieldContext(v *S1SetupRequestIEFieldAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeS1SetupRequestIEFieldAPERValueFieldReceived(v *S1SetupRequestIEFieldAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeS1SetupRequestIEFieldAPERValueFieldReplay(v *S1SetupRequestIEFieldAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeS1SetupRequestIEFieldAPERValueFieldWithoutReplay(v *S1SetupRequestIEFieldAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeS1SetupRequestIEFieldFieldReceived(v *S1SetupRequestIEField) *aper.CompletePadding {
	return &v.received
}
func BridgeS1SetupRequestIEFieldFieldReplay(v *S1SetupRequestIEField) *aper.Snapshot {
	return &v.replay
}
func BridgeS1SetupRequestIEFieldFieldStream(v *S1SetupRequestIEField) *aper.WireSpan {
	return &v.stream
}
func BridgeS1SetupRequestIEFieldFieldWithoutReplay(v *S1SetupRequestIEField) *bool {
	return &v.withoutReplay
}
func BridgeS1SetupRequestIEFieldMethodMarshalAPERTo(v *S1SetupRequestIEField, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeS1SetupRequestIEFieldMethodUnmarshalAPERFrom(v *S1SetupRequestIEField, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeS1SetupRequestIEFieldValueCodecFieldCapture(v *S1SetupRequestIEFieldValueCodec) *func(S1SetupRequestIEField, aper.DecodeState) (S1SetupRequestIEField, aper.Snapshot) {
	return &v.capture
}
func BridgeS1SetupRequestIEFieldValueCodecFieldCompare(v *S1SetupRequestIEFieldValueCodec) *func(S1SetupRequestIEField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeS1SetupRequestIEFieldValueCodecFieldContext(v *S1SetupRequestIEFieldValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeS1SetupRequestIEFieldValueCodecFieldDecode(v *S1SetupRequestIEFieldValueCodec) *func([]byte, aper.DecodeState) (S1SetupRequestIEField, error) {
	return &v.decode
}
func BridgeS1SetupRequestIEFieldValueCodecFieldEncode(v *S1SetupRequestIEFieldValueCodec) *func(S1SetupRequestIEField, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeS1SetupRequestIEFieldValueCodecFieldPath(v *S1SetupRequestIEFieldValueCodec) *aper.Path {
	return &v.path
}
func BridgeS1SetupRequestIEFieldValueCodecMethodEncodeBudgetValue(v S1SetupRequestIEFieldValueCodec, a0 S1SetupRequestIEField, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeS1SetupRequestIEFieldValueCodecMethodEncodeChanged(v S1SetupRequestIEFieldValueCodec, a0 S1SetupRequestIEField, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeS1SetupRequestIETableMethodInfoCSGIdList(v S1SetupRequestIETable) s00.FieldInfo {
	return v.infoCSGIdList()
}
func BridgeS1SetupRequestIETableMethodInfoConnectedengNBList(v S1SetupRequestIETable) s00.FieldInfo {
	return v.infoConnectedengNBList()
}
func BridgeS1SetupRequestIETableMethodInfoDefaultPagingDRX(v S1SetupRequestIETable) s00.FieldInfo {
	return v.infoDefaultPagingDRX()
}
func BridgeS1SetupRequestIETableMethodInfoENBname(v S1SetupRequestIETable) s00.FieldInfo {
	return v.infoENBname()
}
func BridgeS1SetupRequestIETableMethodInfoGlobalENBID(v S1SetupRequestIETable) s00.FieldInfo {
	return v.infoGlobalENBID()
}
func BridgeS1SetupRequestIETableMethodInfoNBIoTDefaultPagingDRX(v S1SetupRequestIETable) s00.FieldInfo {
	return v.infoNBIoTDefaultPagingDRX()
}
func BridgeS1SetupRequestIETableMethodInfoSupportedTAs(v S1SetupRequestIETable) s00.FieldInfo {
	return v.infoSupportedTAs()
}
func BridgeS1SetupRequestIETableMethodInfoUERetentionInformation(v S1SetupRequestIETable) s00.FieldInfo {
	return v.infoUERetentionInformation()
}
func BridgeS1SetupRequestIEValueERABIEContainerListAPERValueFieldContext(v *S1SetupRequestIEValueERABIEContainerListAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeS1SetupRequestIEValueERABIEContainerListAPERValueFieldReceived(v *S1SetupRequestIEValueERABIEContainerListAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeS1SetupRequestIEValueERABIEContainerListAPERValueFieldReplay(v *S1SetupRequestIEValueERABIEContainerListAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeS1SetupRequestIEValueERABIEContainerListAPERValueFieldWithoutReplay(v *S1SetupRequestIEValueERABIEContainerListAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeS1SetupRequestIEValueERABIEContainerListValueCodecFieldCapture(v *S1SetupRequestIEValueERABIEContainerListValueCodec) *func(S1SetupRequestIEValueERABIEContainerList, aper.DecodeState) (S1SetupRequestIEValueERABIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgeS1SetupRequestIEValueERABIEContainerListValueCodecFieldCompare(v *S1SetupRequestIEValueERABIEContainerListValueCodec) *func(S1SetupRequestIEValueERABIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeS1SetupRequestIEValueERABIEContainerListValueCodecFieldContext(v *S1SetupRequestIEValueERABIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeS1SetupRequestIEValueERABIEContainerListValueCodecFieldDecode(v *S1SetupRequestIEValueERABIEContainerListValueCodec) *func([]byte, aper.DecodeState) (S1SetupRequestIEValueERABIEContainerList, error) {
	return &v.decode
}
func BridgeS1SetupRequestIEValueERABIEContainerListValueCodecFieldEncode(v *S1SetupRequestIEValueERABIEContainerListValueCodec) *func(S1SetupRequestIEValueERABIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeS1SetupRequestIEValueERABIEContainerListValueCodecFieldPath(v *S1SetupRequestIEValueERABIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgeS1SetupRequestIEValueERABIEContainerListValueCodecMethodEncodeBudgetValue(v S1SetupRequestIEValueERABIEContainerListValueCodec, a0 S1SetupRequestIEValueERABIEContainerList, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeS1SetupRequestIEValueERABIEContainerListValueCodecMethodEncodeChanged(v S1SetupRequestIEValueERABIEContainerListValueCodec, a0 S1SetupRequestIEValueERABIEContainerList, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeS1SetupRequestIEValueFieldId(v *S1SetupRequestIEValue) *s00.ProtocolIEID { return &v.id }
func BridgeS1SetupRequestIEValueFieldIsOpaque(v *S1SetupRequestIEValue) *bool       { return &v.isOpaque }
func BridgeS1SetupRequestIEValueFieldOpaque(v *S1SetupRequestIEValue) *aper.OpaqueOpenType {
	return &v.opaque
}
func BridgeS1SetupRequestIEValueFieldReceived(v *S1SetupRequestIEValue) *aper.WireSpan {
	return &v.received
}
func BridgeS1SetupRequestIEValueFieldReplay(v *S1SetupRequestIEValue) *aper.Snapshot {
	return &v.replay
}
func BridgeS1SetupRequestIEValueFieldRowCSGIdList(v *S1SetupRequestIEValue) **s14.CSGIdList {
	return &v.rowCSGIdList
}
func BridgeS1SetupRequestIEValueFieldRowConnectedengNBList(v *S1SetupRequestIEValue) **s31.ConnectedengNBList {
	return &v.rowConnectedengNBList
}
func BridgeS1SetupRequestIEValueFieldRowDefaultPagingDRX(v *S1SetupRequestIEValue) **s00.PagingDRX {
	return &v.rowDefaultPagingDRX
}
func BridgeS1SetupRequestIEValueFieldRowENBname(v *S1SetupRequestIEValue) **s00.ENBname {
	return &v.rowENBname
}
func BridgeS1SetupRequestIEValueFieldRowGlobalENBID(v *S1SetupRequestIEValue) **s18.GlobalENBID {
	return &v.rowGlobalENBID
}
func BridgeS1SetupRequestIEValueFieldRowNBIoTDefaultPagingDRX(v *S1SetupRequestIEValue) **s00.NBIoTDefaultPagingDRX {
	return &v.rowNBIoTDefaultPagingDRX
}
func BridgeS1SetupRequestIEValueFieldRowSupportedTAs(v *S1SetupRequestIEValue) **s31.SupportedTAs {
	return &v.rowSupportedTAs
}
func BridgeS1SetupRequestIEValueFieldRowUERetentionInformation(v *S1SetupRequestIEValue) **s00.UERetentionInformation {
	return &v.rowUERetentionInformation
}
func BridgeS1SetupRequestIEValueMethodCaptureSemantics(v S1SetupRequestIEValue, a0 aper.SemanticCapture) S1SetupRequestIEValue {
	return v.captureSemantics(a0)
}
func BridgeS1SetupRequestIEValueMethodCompareSemantics(v S1SetupRequestIEValue, a0 aper.SemanticComparison) aper.SemanticComparison {
	return v.compareSemantics(a0)
}
func BridgeS1SetupRequestIEValueMethodDecode(v S1SetupRequestIEValue, a0 s00.ProtocolIEID, a1 aper.OpaqueOpenType) (S1SetupRequestIEValue, error) {
	return v.decode(a0, a1)
}
func BridgeS1SetupRequestIEValueMethodEncode(v S1SetupRequestIEValue) ([]byte, error) {
	return v.encode()
}
func BridgeS1SetupRequestIEValueMethodEncodeFresh(v S1SetupRequestIEValue, a0 bool, a1 *aper.DecodeBudget) ([]byte, error) {
	return v.encodeFresh(a0, a1)
}
func BridgeS1SetupRequestIEValueMethodMatchesID(v S1SetupRequestIEValue, a0 s00.ProtocolIEID, a1 ...*aper.DecodeBudget) bool {
	return v.matchesID(a0, a1...)
}
func BridgeS1SetupRequestIEValueMethodReason(v S1SetupRequestIEValue, a0 s00.ProtocolIEID) aper.OpaqueReason {
	return v.reason(a0)
}
func BridgeS1SetupRequestIEValueMethodRule(v S1SetupRequestIEValue) aper.SourceRule { return v.rule() }
func BridgeS1SetupRequestIEValueProtocolErrorIEContainerListAPERValueFieldContext(v *S1SetupRequestIEValueProtocolErrorIEContainerListAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeS1SetupRequestIEValueProtocolErrorIEContainerListAPERValueFieldReceived(v *S1SetupRequestIEValueProtocolErrorIEContainerListAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeS1SetupRequestIEValueProtocolErrorIEContainerListAPERValueFieldReplay(v *S1SetupRequestIEValueProtocolErrorIEContainerListAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeS1SetupRequestIEValueProtocolErrorIEContainerListAPERValueFieldWithoutReplay(v *S1SetupRequestIEValueProtocolErrorIEContainerListAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeS1SetupRequestIEValueProtocolErrorIEContainerListValueCodecFieldCapture(v *S1SetupRequestIEValueProtocolErrorIEContainerListValueCodec) *func(S1SetupRequestIEValueProtocolErrorIEContainerList, aper.DecodeState) (S1SetupRequestIEValueProtocolErrorIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgeS1SetupRequestIEValueProtocolErrorIEContainerListValueCodecFieldCompare(v *S1SetupRequestIEValueProtocolErrorIEContainerListValueCodec) *func(S1SetupRequestIEValueProtocolErrorIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeS1SetupRequestIEValueProtocolErrorIEContainerListValueCodecFieldContext(v *S1SetupRequestIEValueProtocolErrorIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeS1SetupRequestIEValueProtocolErrorIEContainerListValueCodecFieldDecode(v *S1SetupRequestIEValueProtocolErrorIEContainerListValueCodec) *func([]byte, aper.DecodeState) (S1SetupRequestIEValueProtocolErrorIEContainerList, error) {
	return &v.decode
}
func BridgeS1SetupRequestIEValueProtocolErrorIEContainerListValueCodecFieldEncode(v *S1SetupRequestIEValueProtocolErrorIEContainerListValueCodec) *func(S1SetupRequestIEValueProtocolErrorIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeS1SetupRequestIEValueProtocolErrorIEContainerListValueCodecFieldPath(v *S1SetupRequestIEValueProtocolErrorIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgeS1SetupRequestIEValueProtocolErrorIEContainerListValueCodecMethodEncodeBudgetValue(v S1SetupRequestIEValueProtocolErrorIEContainerListValueCodec, a0 S1SetupRequestIEValueProtocolErrorIEContainerList, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeS1SetupRequestIEValueProtocolErrorIEContainerListValueCodecMethodEncodeChanged(v S1SetupRequestIEValueProtocolErrorIEContainerListValueCodec, a0 S1SetupRequestIEValueProtocolErrorIEContainerList, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeS1SetupRequestIEValueProtocolIEContainerListAPERValueFieldContext(v *S1SetupRequestIEValueProtocolIEContainerListAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeS1SetupRequestIEValueProtocolIEContainerListAPERValueFieldReceived(v *S1SetupRequestIEValueProtocolIEContainerListAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeS1SetupRequestIEValueProtocolIEContainerListAPERValueFieldReplay(v *S1SetupRequestIEValueProtocolIEContainerListAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeS1SetupRequestIEValueProtocolIEContainerListAPERValueFieldWithoutReplay(v *S1SetupRequestIEValueProtocolIEContainerListAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeS1SetupRequestIEValueProtocolIEContainerListValueCodecFieldCapture(v *S1SetupRequestIEValueProtocolIEContainerListValueCodec) *func(S1SetupRequestIEValueProtocolIEContainerList, aper.DecodeState) (S1SetupRequestIEValueProtocolIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgeS1SetupRequestIEValueProtocolIEContainerListValueCodecFieldCompare(v *S1SetupRequestIEValueProtocolIEContainerListValueCodec) *func(S1SetupRequestIEValueProtocolIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeS1SetupRequestIEValueProtocolIEContainerListValueCodecFieldContext(v *S1SetupRequestIEValueProtocolIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeS1SetupRequestIEValueProtocolIEContainerListValueCodecFieldDecode(v *S1SetupRequestIEValueProtocolIEContainerListValueCodec) *func([]byte, aper.DecodeState) (S1SetupRequestIEValueProtocolIEContainerList, error) {
	return &v.decode
}
func BridgeS1SetupRequestIEValueProtocolIEContainerListValueCodecFieldEncode(v *S1SetupRequestIEValueProtocolIEContainerListValueCodec) *func(S1SetupRequestIEValueProtocolIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeS1SetupRequestIEValueProtocolIEContainerListValueCodecFieldPath(v *S1SetupRequestIEValueProtocolIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgeS1SetupRequestIEValueProtocolIEContainerListValueCodecMethodEncodeBudgetValue(v S1SetupRequestIEValueProtocolIEContainerListValueCodec, a0 S1SetupRequestIEValueProtocolIEContainerList, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeS1SetupRequestIEValueProtocolIEContainerListValueCodecMethodEncodeChanged(v S1SetupRequestIEValueProtocolIEContainerListValueCodec, a0 S1SetupRequestIEValueProtocolIEContainerList, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
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
func BridgeS1SetupRequestNBIoTDefaultPagingDRXIEBindingFieldCodec(v *S1SetupRequestNBIoTDefaultPagingDRXIEBinding) *s01.NBIoTDefaultPagingDRXValueCodec {
	return &v.codec
}
func BridgeS1SetupRequestNBIoTDefaultPagingDRXIEBindingFieldGet(v *S1SetupRequestNBIoTDefaultPagingDRXIEBinding) *func(*S1SetupRequestIEValue) (*s00.NBIoTDefaultPagingDRX, bool) {
	return &v.get
}
func BridgeS1SetupRequestNBIoTDefaultPagingDRXIEBindingFieldInfo(v *S1SetupRequestNBIoTDefaultPagingDRXIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeS1SetupRequestNBIoTDefaultPagingDRXIEBindingFieldInject(v *S1SetupRequestNBIoTDefaultPagingDRXIEBinding) *func(s00.NBIoTDefaultPagingDRX) S1SetupRequestIEValue {
	return &v.inject
}
func BridgeS1SetupRequestPagingDRXIEBindingFieldCodec(v *S1SetupRequestPagingDRXIEBinding) *s01.PagingDRXValueCodec {
	return &v.codec
}
func BridgeS1SetupRequestPagingDRXIEBindingFieldGet(v *S1SetupRequestPagingDRXIEBinding) *func(*S1SetupRequestIEValue) (*s00.PagingDRX, bool) {
	return &v.get
}
func BridgeS1SetupRequestPagingDRXIEBindingFieldInfo(v *S1SetupRequestPagingDRXIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeS1SetupRequestPagingDRXIEBindingFieldInject(v *S1SetupRequestPagingDRXIEBinding) *func(s00.PagingDRX) S1SetupRequestIEValue {
	return &v.inject
}
func BridgeS1SetupRequestSupportedTAsIEBindingFieldCodec(v *S1SetupRequestSupportedTAsIEBinding) *s31.SupportedTAsValueCodec {
	return &v.codec
}
func BridgeS1SetupRequestSupportedTAsIEBindingFieldGet(v *S1SetupRequestSupportedTAsIEBinding) *func(*S1SetupRequestIEValue) (*s31.SupportedTAs, bool) {
	return &v.get
}
func BridgeS1SetupRequestSupportedTAsIEBindingFieldInfo(v *S1SetupRequestSupportedTAsIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeS1SetupRequestSupportedTAsIEBindingFieldInject(v *S1SetupRequestSupportedTAsIEBinding) *func(s31.SupportedTAs) S1SetupRequestIEValue {
	return &v.inject
}
func BridgeS1SetupRequestUERetentionInformationIEBindingFieldCodec(v *S1SetupRequestUERetentionInformationIEBinding) *s02.UERetentionInformationValueCodec {
	return &v.codec
}
func BridgeS1SetupRequestUERetentionInformationIEBindingFieldGet(v *S1SetupRequestUERetentionInformationIEBinding) *func(*S1SetupRequestIEValue) (*s00.UERetentionInformation, bool) {
	return &v.get
}
func BridgeS1SetupRequestUERetentionInformationIEBindingFieldInfo(v *S1SetupRequestUERetentionInformationIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeS1SetupRequestUERetentionInformationIEBindingFieldInject(v *S1SetupRequestUERetentionInformationIEBinding) *func(s00.UERetentionInformation) S1SetupRequestIEValue {
	return &v.inject
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
func BridgeS1SetupResponseAPERValueFieldContext(v *S1SetupResponseAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeS1SetupResponseAPERValueFieldReceived(v *S1SetupResponseAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeS1SetupResponseAPERValueFieldReplay(v *S1SetupResponseAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeS1SetupResponseAPERValueFieldWithoutReplay(v *S1SetupResponseAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeS1SetupResponseCriticalityDiagnosticsIEBindingFieldCodec(v *S1SetupResponseCriticalityDiagnosticsIEBinding) *s22.CriticalityDiagnosticsValueCodec {
	return &v.codec
}
func BridgeS1SetupResponseCriticalityDiagnosticsIEBindingFieldGet(v *S1SetupResponseCriticalityDiagnosticsIEBinding) *func(*S1SetupResponseIEValue) (*s22.CriticalityDiagnostics, bool) {
	return &v.get
}
func BridgeS1SetupResponseCriticalityDiagnosticsIEBindingFieldInfo(v *S1SetupResponseCriticalityDiagnosticsIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeS1SetupResponseCriticalityDiagnosticsIEBindingFieldInject(v *S1SetupResponseCriticalityDiagnosticsIEBinding) *func(s22.CriticalityDiagnostics) S1SetupResponseIEValue {
	return &v.inject
}
func BridgeS1SetupResponseFieldExtCount(v *S1SetupResponse) *int64   { return &v.extCount }
func BridgeS1SetupResponseFieldExtData(v *S1SetupResponse) *[][]byte { return &v.extData }
func BridgeS1SetupResponseFieldExtOrigin(v *S1SetupResponse) *[]aper.OpaqueOrigin {
	return &v.extOrigin
}
func BridgeS1SetupResponseFieldExtPresent(v *S1SetupResponse) *[]bool       { return &v.extPresent }
func BridgeS1SetupResponseFieldExtWire(v *S1SetupResponse) *[]aper.WireSpan { return &v.extWire }
func BridgeS1SetupResponseFieldPerExtPadding(v *S1SetupResponse) *[]aper.CompletePadding {
	return &v.perExtPadding
}
func BridgeS1SetupResponseFieldPerPadding(v *S1SetupResponse) *aper.FinalPadding {
	return &v.perPadding
}
func BridgeS1SetupResponseFieldProtocolIEsIndef(v *S1SetupResponse) *bool { return &v.protocolIEsIndef }
func BridgeS1SetupResponseFieldReceived(v *S1SetupResponse) *bool         { return &v.received }
func BridgeS1SetupResponseFieldReceivedAbsolute(v *S1SetupResponse) *bool { return &v.receivedAbsolute }
func BridgeS1SetupResponseFieldReceivedBytes(v *S1SetupResponse) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeS1SetupResponseFieldReceivedLocation(v *S1SetupResponse) *aper.Location {
	return &v.receivedLocation
}
func BridgeS1SetupResponseFieldReplay(v *S1SetupResponse) *aper.Snapshot { return &v.replay }
func BridgeS1SetupResponseFieldStream(v *S1SetupResponse) *aper.WireSpan { return &v.stream }
func BridgeS1SetupResponseFieldWithoutReplay(v *S1SetupResponse) *bool   { return &v.withoutReplay }
func BridgeS1SetupResponseIABSupportedIEBindingFieldCodec(v *S1SetupResponseIABSupportedIEBinding) *s01.IABSupportedValueCodec {
	return &v.codec
}
func BridgeS1SetupResponseIABSupportedIEBindingFieldGet(v *S1SetupResponseIABSupportedIEBinding) *func(*S1SetupResponseIEValue) (*s00.IABSupported, bool) {
	return &v.get
}
func BridgeS1SetupResponseIABSupportedIEBindingFieldInfo(v *S1SetupResponseIABSupportedIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeS1SetupResponseIABSupportedIEBindingFieldInject(v *S1SetupResponseIABSupportedIEBinding) *func(s00.IABSupported) S1SetupResponseIEValue {
	return &v.inject
}
func BridgeS1SetupResponseIEContainerAPERValueFieldContext(v *S1SetupResponseIEContainerAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeS1SetupResponseIEContainerAPERValueFieldReceived(v *S1SetupResponseIEContainerAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeS1SetupResponseIEContainerAPERValueFieldReplay(v *S1SetupResponseIEContainerAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeS1SetupResponseIEContainerAPERValueFieldWithoutReplay(v *S1SetupResponseIEContainerAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeS1SetupResponseIEContainerValueCodecFieldCapture(v *S1SetupResponseIEContainerValueCodec) *func(S1SetupResponseIEContainer, aper.DecodeState) (S1SetupResponseIEContainer, aper.Snapshot) {
	return &v.capture
}
func BridgeS1SetupResponseIEContainerValueCodecFieldCompare(v *S1SetupResponseIEContainerValueCodec) *func(S1SetupResponseIEContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeS1SetupResponseIEContainerValueCodecFieldContext(v *S1SetupResponseIEContainerValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeS1SetupResponseIEContainerValueCodecFieldDecode(v *S1SetupResponseIEContainerValueCodec) *func([]byte, aper.DecodeState) (S1SetupResponseIEContainer, error) {
	return &v.decode
}
func BridgeS1SetupResponseIEContainerValueCodecFieldEncode(v *S1SetupResponseIEContainerValueCodec) *func(S1SetupResponseIEContainer, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeS1SetupResponseIEContainerValueCodecFieldPath(v *S1SetupResponseIEContainerValueCodec) *aper.Path {
	return &v.path
}
func BridgeS1SetupResponseIEContainerValueCodecMethodEncodeBudgetValue(v S1SetupResponseIEContainerValueCodec, a0 S1SetupResponseIEContainer, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeS1SetupResponseIEContainerValueCodecMethodEncodeChanged(v S1SetupResponseIEContainerValueCodec, a0 S1SetupResponseIEContainer, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeS1SetupResponseIEFieldAPERValueFieldContext(v *S1SetupResponseIEFieldAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeS1SetupResponseIEFieldAPERValueFieldReceived(v *S1SetupResponseIEFieldAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeS1SetupResponseIEFieldAPERValueFieldReplay(v *S1SetupResponseIEFieldAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeS1SetupResponseIEFieldAPERValueFieldWithoutReplay(v *S1SetupResponseIEFieldAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeS1SetupResponseIEFieldFieldReceived(v *S1SetupResponseIEField) *aper.CompletePadding {
	return &v.received
}
func BridgeS1SetupResponseIEFieldFieldReplay(v *S1SetupResponseIEField) *aper.Snapshot {
	return &v.replay
}
func BridgeS1SetupResponseIEFieldFieldStream(v *S1SetupResponseIEField) *aper.WireSpan {
	return &v.stream
}
func BridgeS1SetupResponseIEFieldFieldWithoutReplay(v *S1SetupResponseIEField) *bool {
	return &v.withoutReplay
}
func BridgeS1SetupResponseIEFieldMethodMarshalAPERTo(v *S1SetupResponseIEField, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeS1SetupResponseIEFieldMethodUnmarshalAPERFrom(v *S1SetupResponseIEField, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeS1SetupResponseIEFieldValueCodecFieldCapture(v *S1SetupResponseIEFieldValueCodec) *func(S1SetupResponseIEField, aper.DecodeState) (S1SetupResponseIEField, aper.Snapshot) {
	return &v.capture
}
func BridgeS1SetupResponseIEFieldValueCodecFieldCompare(v *S1SetupResponseIEFieldValueCodec) *func(S1SetupResponseIEField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeS1SetupResponseIEFieldValueCodecFieldContext(v *S1SetupResponseIEFieldValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeS1SetupResponseIEFieldValueCodecFieldDecode(v *S1SetupResponseIEFieldValueCodec) *func([]byte, aper.DecodeState) (S1SetupResponseIEField, error) {
	return &v.decode
}
func BridgeS1SetupResponseIEFieldValueCodecFieldEncode(v *S1SetupResponseIEFieldValueCodec) *func(S1SetupResponseIEField, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeS1SetupResponseIEFieldValueCodecFieldPath(v *S1SetupResponseIEFieldValueCodec) *aper.Path {
	return &v.path
}
func BridgeS1SetupResponseIEFieldValueCodecMethodEncodeBudgetValue(v S1SetupResponseIEFieldValueCodec, a0 S1SetupResponseIEField, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeS1SetupResponseIEFieldValueCodecMethodEncodeChanged(v S1SetupResponseIEFieldValueCodec, a0 S1SetupResponseIEField, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeS1SetupResponseIETableMethodInfoCriticalityDiagnostics(v S1SetupResponseIETable) s00.FieldInfo {
	return v.infoCriticalityDiagnostics()
}
func BridgeS1SetupResponseIETableMethodInfoIABSupported(v S1SetupResponseIETable) s00.FieldInfo {
	return v.infoIABSupported()
}
func BridgeS1SetupResponseIETableMethodInfoMMERelaySupportIndicator(v S1SetupResponseIETable) s00.FieldInfo {
	return v.infoMMERelaySupportIndicator()
}
func BridgeS1SetupResponseIETableMethodInfoMMEname(v S1SetupResponseIETable) s00.FieldInfo {
	return v.infoMMEname()
}
func BridgeS1SetupResponseIETableMethodInfoRelativeMMECapacity(v S1SetupResponseIETable) s00.FieldInfo {
	return v.infoRelativeMMECapacity()
}
func BridgeS1SetupResponseIETableMethodInfoServedDCNs(v S1SetupResponseIETable) s00.FieldInfo {
	return v.infoServedDCNs()
}
func BridgeS1SetupResponseIETableMethodInfoServedGUMMEIs(v S1SetupResponseIETable) s00.FieldInfo {
	return v.infoServedGUMMEIs()
}
func BridgeS1SetupResponseIETableMethodInfoUERetentionInformation(v S1SetupResponseIETable) s00.FieldInfo {
	return v.infoUERetentionInformation()
}
func BridgeS1SetupResponseIEValueERABIEContainerListAPERValueFieldContext(v *S1SetupResponseIEValueERABIEContainerListAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeS1SetupResponseIEValueERABIEContainerListAPERValueFieldReceived(v *S1SetupResponseIEValueERABIEContainerListAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeS1SetupResponseIEValueERABIEContainerListAPERValueFieldReplay(v *S1SetupResponseIEValueERABIEContainerListAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeS1SetupResponseIEValueERABIEContainerListAPERValueFieldWithoutReplay(v *S1SetupResponseIEValueERABIEContainerListAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeS1SetupResponseIEValueERABIEContainerListValueCodecFieldCapture(v *S1SetupResponseIEValueERABIEContainerListValueCodec) *func(S1SetupResponseIEValueERABIEContainerList, aper.DecodeState) (S1SetupResponseIEValueERABIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgeS1SetupResponseIEValueERABIEContainerListValueCodecFieldCompare(v *S1SetupResponseIEValueERABIEContainerListValueCodec) *func(S1SetupResponseIEValueERABIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeS1SetupResponseIEValueERABIEContainerListValueCodecFieldContext(v *S1SetupResponseIEValueERABIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeS1SetupResponseIEValueERABIEContainerListValueCodecFieldDecode(v *S1SetupResponseIEValueERABIEContainerListValueCodec) *func([]byte, aper.DecodeState) (S1SetupResponseIEValueERABIEContainerList, error) {
	return &v.decode
}
func BridgeS1SetupResponseIEValueERABIEContainerListValueCodecFieldEncode(v *S1SetupResponseIEValueERABIEContainerListValueCodec) *func(S1SetupResponseIEValueERABIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeS1SetupResponseIEValueERABIEContainerListValueCodecFieldPath(v *S1SetupResponseIEValueERABIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgeS1SetupResponseIEValueERABIEContainerListValueCodecMethodEncodeBudgetValue(v S1SetupResponseIEValueERABIEContainerListValueCodec, a0 S1SetupResponseIEValueERABIEContainerList, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeS1SetupResponseIEValueERABIEContainerListValueCodecMethodEncodeChanged(v S1SetupResponseIEValueERABIEContainerListValueCodec, a0 S1SetupResponseIEValueERABIEContainerList, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeS1SetupResponseIEValueFieldId(v *S1SetupResponseIEValue) *s00.ProtocolIEID { return &v.id }
func BridgeS1SetupResponseIEValueFieldIsOpaque(v *S1SetupResponseIEValue) *bool       { return &v.isOpaque }
func BridgeS1SetupResponseIEValueFieldOpaque(v *S1SetupResponseIEValue) *aper.OpaqueOpenType {
	return &v.opaque
}
func BridgeS1SetupResponseIEValueFieldReceived(v *S1SetupResponseIEValue) *aper.WireSpan {
	return &v.received
}
func BridgeS1SetupResponseIEValueFieldReplay(v *S1SetupResponseIEValue) *aper.Snapshot {
	return &v.replay
}
func BridgeS1SetupResponseIEValueFieldRowCriticalityDiagnostics(v *S1SetupResponseIEValue) **s22.CriticalityDiagnostics {
	return &v.rowCriticalityDiagnostics
}
func BridgeS1SetupResponseIEValueFieldRowIABSupported(v *S1SetupResponseIEValue) **s00.IABSupported {
	return &v.rowIABSupported
}
func BridgeS1SetupResponseIEValueFieldRowMMERelaySupportIndicator(v *S1SetupResponseIEValue) **s00.MMERelaySupportIndicator {
	return &v.rowMMERelaySupportIndicator
}
func BridgeS1SetupResponseIEValueFieldRowMMEname(v *S1SetupResponseIEValue) **s00.MMEname {
	return &v.rowMMEname
}
func BridgeS1SetupResponseIEValueFieldRowRelativeMMECapacity(v *S1SetupResponseIEValue) **s00.RelativeMMECapacity {
	return &v.rowRelativeMMECapacity
}
func BridgeS1SetupResponseIEValueFieldRowServedDCNs(v *S1SetupResponseIEValue) **s31.ServedDCNs {
	return &v.rowServedDCNs
}
func BridgeS1SetupResponseIEValueFieldRowServedGUMMEIs(v *S1SetupResponseIEValue) **s31.ServedGUMMEIs {
	return &v.rowServedGUMMEIs
}
func BridgeS1SetupResponseIEValueFieldRowUERetentionInformation(v *S1SetupResponseIEValue) **s00.UERetentionInformation {
	return &v.rowUERetentionInformation
}
func BridgeS1SetupResponseIEValueMethodCaptureSemantics(v S1SetupResponseIEValue, a0 aper.SemanticCapture) S1SetupResponseIEValue {
	return v.captureSemantics(a0)
}
func BridgeS1SetupResponseIEValueMethodCompareSemantics(v S1SetupResponseIEValue, a0 aper.SemanticComparison) aper.SemanticComparison {
	return v.compareSemantics(a0)
}
func BridgeS1SetupResponseIEValueMethodDecode(v S1SetupResponseIEValue, a0 s00.ProtocolIEID, a1 aper.OpaqueOpenType) (S1SetupResponseIEValue, error) {
	return v.decode(a0, a1)
}
func BridgeS1SetupResponseIEValueMethodEncode(v S1SetupResponseIEValue) ([]byte, error) {
	return v.encode()
}
func BridgeS1SetupResponseIEValueMethodEncodeFresh(v S1SetupResponseIEValue, a0 bool, a1 *aper.DecodeBudget) ([]byte, error) {
	return v.encodeFresh(a0, a1)
}
func BridgeS1SetupResponseIEValueMethodMatchesID(v S1SetupResponseIEValue, a0 s00.ProtocolIEID, a1 ...*aper.DecodeBudget) bool {
	return v.matchesID(a0, a1...)
}
func BridgeS1SetupResponseIEValueMethodReason(v S1SetupResponseIEValue, a0 s00.ProtocolIEID) aper.OpaqueReason {
	return v.reason(a0)
}
func BridgeS1SetupResponseIEValueMethodRule(v S1SetupResponseIEValue) aper.SourceRule {
	return v.rule()
}
func BridgeS1SetupResponseIEValueProtocolErrorIEContainerListAPERValueFieldContext(v *S1SetupResponseIEValueProtocolErrorIEContainerListAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeS1SetupResponseIEValueProtocolErrorIEContainerListAPERValueFieldReceived(v *S1SetupResponseIEValueProtocolErrorIEContainerListAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeS1SetupResponseIEValueProtocolErrorIEContainerListAPERValueFieldReplay(v *S1SetupResponseIEValueProtocolErrorIEContainerListAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeS1SetupResponseIEValueProtocolErrorIEContainerListAPERValueFieldWithoutReplay(v *S1SetupResponseIEValueProtocolErrorIEContainerListAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeS1SetupResponseIEValueProtocolErrorIEContainerListValueCodecFieldCapture(v *S1SetupResponseIEValueProtocolErrorIEContainerListValueCodec) *func(S1SetupResponseIEValueProtocolErrorIEContainerList, aper.DecodeState) (S1SetupResponseIEValueProtocolErrorIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgeS1SetupResponseIEValueProtocolErrorIEContainerListValueCodecFieldCompare(v *S1SetupResponseIEValueProtocolErrorIEContainerListValueCodec) *func(S1SetupResponseIEValueProtocolErrorIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeS1SetupResponseIEValueProtocolErrorIEContainerListValueCodecFieldContext(v *S1SetupResponseIEValueProtocolErrorIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeS1SetupResponseIEValueProtocolErrorIEContainerListValueCodecFieldDecode(v *S1SetupResponseIEValueProtocolErrorIEContainerListValueCodec) *func([]byte, aper.DecodeState) (S1SetupResponseIEValueProtocolErrorIEContainerList, error) {
	return &v.decode
}
func BridgeS1SetupResponseIEValueProtocolErrorIEContainerListValueCodecFieldEncode(v *S1SetupResponseIEValueProtocolErrorIEContainerListValueCodec) *func(S1SetupResponseIEValueProtocolErrorIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeS1SetupResponseIEValueProtocolErrorIEContainerListValueCodecFieldPath(v *S1SetupResponseIEValueProtocolErrorIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgeS1SetupResponseIEValueProtocolErrorIEContainerListValueCodecMethodEncodeBudgetValue(v S1SetupResponseIEValueProtocolErrorIEContainerListValueCodec, a0 S1SetupResponseIEValueProtocolErrorIEContainerList, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeS1SetupResponseIEValueProtocolErrorIEContainerListValueCodecMethodEncodeChanged(v S1SetupResponseIEValueProtocolErrorIEContainerListValueCodec, a0 S1SetupResponseIEValueProtocolErrorIEContainerList, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeS1SetupResponseIEValueProtocolIEContainerListAPERValueFieldContext(v *S1SetupResponseIEValueProtocolIEContainerListAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeS1SetupResponseIEValueProtocolIEContainerListAPERValueFieldReceived(v *S1SetupResponseIEValueProtocolIEContainerListAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeS1SetupResponseIEValueProtocolIEContainerListAPERValueFieldReplay(v *S1SetupResponseIEValueProtocolIEContainerListAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeS1SetupResponseIEValueProtocolIEContainerListAPERValueFieldWithoutReplay(v *S1SetupResponseIEValueProtocolIEContainerListAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeS1SetupResponseIEValueProtocolIEContainerListValueCodecFieldCapture(v *S1SetupResponseIEValueProtocolIEContainerListValueCodec) *func(S1SetupResponseIEValueProtocolIEContainerList, aper.DecodeState) (S1SetupResponseIEValueProtocolIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgeS1SetupResponseIEValueProtocolIEContainerListValueCodecFieldCompare(v *S1SetupResponseIEValueProtocolIEContainerListValueCodec) *func(S1SetupResponseIEValueProtocolIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeS1SetupResponseIEValueProtocolIEContainerListValueCodecFieldContext(v *S1SetupResponseIEValueProtocolIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeS1SetupResponseIEValueProtocolIEContainerListValueCodecFieldDecode(v *S1SetupResponseIEValueProtocolIEContainerListValueCodec) *func([]byte, aper.DecodeState) (S1SetupResponseIEValueProtocolIEContainerList, error) {
	return &v.decode
}
func BridgeS1SetupResponseIEValueProtocolIEContainerListValueCodecFieldEncode(v *S1SetupResponseIEValueProtocolIEContainerListValueCodec) *func(S1SetupResponseIEValueProtocolIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeS1SetupResponseIEValueProtocolIEContainerListValueCodecFieldPath(v *S1SetupResponseIEValueProtocolIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgeS1SetupResponseIEValueProtocolIEContainerListValueCodecMethodEncodeBudgetValue(v S1SetupResponseIEValueProtocolIEContainerListValueCodec, a0 S1SetupResponseIEValueProtocolIEContainerList, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeS1SetupResponseIEValueProtocolIEContainerListValueCodecMethodEncodeChanged(v S1SetupResponseIEValueProtocolIEContainerListValueCodec, a0 S1SetupResponseIEValueProtocolIEContainerList, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeS1SetupResponseMMERelaySupportIndicatorIEBindingFieldCodec(v *S1SetupResponseMMERelaySupportIndicatorIEBinding) *s01.MMERelaySupportIndicatorValueCodec {
	return &v.codec
}
func BridgeS1SetupResponseMMERelaySupportIndicatorIEBindingFieldGet(v *S1SetupResponseMMERelaySupportIndicatorIEBinding) *func(*S1SetupResponseIEValue) (*s00.MMERelaySupportIndicator, bool) {
	return &v.get
}
func BridgeS1SetupResponseMMERelaySupportIndicatorIEBindingFieldInfo(v *S1SetupResponseMMERelaySupportIndicatorIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeS1SetupResponseMMERelaySupportIndicatorIEBindingFieldInject(v *S1SetupResponseMMERelaySupportIndicatorIEBinding) *func(s00.MMERelaySupportIndicator) S1SetupResponseIEValue {
	return &v.inject
}
func BridgeS1SetupResponseMMEnameIEBindingFieldCodec(v *S1SetupResponseMMEnameIEBinding) *s01.MMEnameValueCodec {
	return &v.codec
}
func BridgeS1SetupResponseMMEnameIEBindingFieldGet(v *S1SetupResponseMMEnameIEBinding) *func(*S1SetupResponseIEValue) (*s00.MMEname, bool) {
	return &v.get
}
func BridgeS1SetupResponseMMEnameIEBindingFieldInfo(v *S1SetupResponseMMEnameIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeS1SetupResponseMMEnameIEBindingFieldInject(v *S1SetupResponseMMEnameIEBinding) *func(s00.MMEname) S1SetupResponseIEValue {
	return &v.inject
}
func BridgeS1SetupResponseMethodMarshalAPERBudget(v *S1SetupResponse, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeS1SetupResponseMethodMarshalAPERBudgetValue(v *S1SetupResponse, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudgetValue(a0, a1)
}
func BridgeS1SetupResponseMethodMarshalAPERChanged(v *S1SetupResponse, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeS1SetupResponseMethodMarshalAPERChangedValue(v *S1SetupResponse, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeS1SetupResponseMethodMarshalAPERLegacy(v *S1SetupResponse) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeS1SetupResponseMethodMarshalAPERNewValue(v *S1SetupResponse, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERNewValue(a0, a1)
}
func BridgeS1SetupResponseMethodMarshalAPERPlanned(v *S1SetupResponse, a0 *aper.DecodeBudget, a1 bool, a2 *aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1, a2)
}
func BridgeS1SetupResponseMethodMarshalAPERTo(v *S1SetupResponse, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeS1SetupResponseMethodUnmarshalAPERFrom(v *S1SetupResponse, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeS1SetupResponseMethodUnmarshalAPERLegacy(v *S1SetupResponse, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeS1SetupResponseMethodUnmarshalAPERWithOptions(v *S1SetupResponse, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeS1SetupResponseRelativeMMECapacityIEBindingFieldCodec(v *S1SetupResponseRelativeMMECapacityIEBinding) *s01.RelativeMMECapacityValueCodec {
	return &v.codec
}
func BridgeS1SetupResponseRelativeMMECapacityIEBindingFieldGet(v *S1SetupResponseRelativeMMECapacityIEBinding) *func(*S1SetupResponseIEValue) (*s00.RelativeMMECapacity, bool) {
	return &v.get
}
func BridgeS1SetupResponseRelativeMMECapacityIEBindingFieldInfo(v *S1SetupResponseRelativeMMECapacityIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeS1SetupResponseRelativeMMECapacityIEBindingFieldInject(v *S1SetupResponseRelativeMMECapacityIEBinding) *func(s00.RelativeMMECapacity) S1SetupResponseIEValue {
	return &v.inject
}
func BridgeS1SetupResponseServedDCNsIEBindingFieldCodec(v *S1SetupResponseServedDCNsIEBinding) *s31.ServedDCNsValueCodec {
	return &v.codec
}
func BridgeS1SetupResponseServedDCNsIEBindingFieldGet(v *S1SetupResponseServedDCNsIEBinding) *func(*S1SetupResponseIEValue) (*s31.ServedDCNs, bool) {
	return &v.get
}
func BridgeS1SetupResponseServedDCNsIEBindingFieldInfo(v *S1SetupResponseServedDCNsIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeS1SetupResponseServedDCNsIEBindingFieldInject(v *S1SetupResponseServedDCNsIEBinding) *func(s31.ServedDCNs) S1SetupResponseIEValue {
	return &v.inject
}
func BridgeS1SetupResponseServedGUMMEIsIEBindingFieldCodec(v *S1SetupResponseServedGUMMEIsIEBinding) *s31.ServedGUMMEIsValueCodec {
	return &v.codec
}
func BridgeS1SetupResponseServedGUMMEIsIEBindingFieldGet(v *S1SetupResponseServedGUMMEIsIEBinding) *func(*S1SetupResponseIEValue) (*s31.ServedGUMMEIs, bool) {
	return &v.get
}
func BridgeS1SetupResponseServedGUMMEIsIEBindingFieldInfo(v *S1SetupResponseServedGUMMEIsIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeS1SetupResponseServedGUMMEIsIEBindingFieldInject(v *S1SetupResponseServedGUMMEIsIEBinding) *func(s31.ServedGUMMEIs) S1SetupResponseIEValue {
	return &v.inject
}
func BridgeS1SetupResponseUERetentionInformationIEBindingFieldCodec(v *S1SetupResponseUERetentionInformationIEBinding) *s02.UERetentionInformationValueCodec {
	return &v.codec
}
func BridgeS1SetupResponseUERetentionInformationIEBindingFieldGet(v *S1SetupResponseUERetentionInformationIEBinding) *func(*S1SetupResponseIEValue) (*s00.UERetentionInformation, bool) {
	return &v.get
}
func BridgeS1SetupResponseUERetentionInformationIEBindingFieldInfo(v *S1SetupResponseUERetentionInformationIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeS1SetupResponseUERetentionInformationIEBindingFieldInject(v *S1SetupResponseUERetentionInformationIEBinding) *func(s00.UERetentionInformation) S1SetupResponseIEValue {
	return &v.inject
}
func BridgeS1SetupResponseValueCodecFieldCapture(v *S1SetupResponseValueCodec) *func(S1SetupResponse, aper.DecodeState) (S1SetupResponse, aper.Snapshot) {
	return &v.capture
}
func BridgeS1SetupResponseValueCodecFieldCompare(v *S1SetupResponseValueCodec) *func(S1SetupResponse, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeS1SetupResponseValueCodecFieldContext(v *S1SetupResponseValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeS1SetupResponseValueCodecFieldDecode(v *S1SetupResponseValueCodec) *func([]byte, aper.DecodeState) (S1SetupResponse, error) {
	return &v.decode
}
func BridgeS1SetupResponseValueCodecFieldEncode(v *S1SetupResponseValueCodec) *func(S1SetupResponse, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeS1SetupResponseValueCodecFieldPath(v *S1SetupResponseValueCodec) *aper.Path {
	return &v.path
}
func BridgeS1SetupResponseValueCodecMethodEncodeBudgetValue(v S1SetupResponseValueCodec, a0 S1SetupResponse, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeS1SetupResponseValueCodecMethodEncodeChanged(v S1SetupResponseValueCodec, a0 S1SetupResponse, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeServedGroupIDsCompleteFieldPerPadding(v *ServedGroupIDsComplete) *aper.CompletePadding {
	return &v.perPadding
}
func BridgeServedGroupIDsCompleteFieldReceived(v *ServedGroupIDsComplete) *bool { return &v.received }
func BridgeServedGroupIDsCompleteFieldReceivedAbsolute(v *ServedGroupIDsComplete) *bool {
	return &v.receivedAbsolute
}
func BridgeServedGroupIDsCompleteFieldReceivedBytes(v *ServedGroupIDsComplete) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeServedGroupIDsCompleteFieldReceivedLocation(v *ServedGroupIDsComplete) *aper.Location {
	return &v.receivedLocation
}
func BridgeServedGroupIDsCompleteFieldReplay(v *ServedGroupIDsComplete) *aper.Snapshot {
	return &v.replay
}
func BridgeServedGroupIDsCompleteFieldStream(v *ServedGroupIDsComplete) *aper.WireSpan {
	return &v.stream
}
func BridgeServedGroupIDsCompleteFieldWithoutReplay(v *ServedGroupIDsComplete) *bool {
	return &v.withoutReplay
}
func BridgeServedGroupIDsCompleteMethodMarshalAPERBudget(v *ServedGroupIDsComplete, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeServedGroupIDsCompleteMethodMarshalAPERBudgetValue(v *ServedGroupIDsComplete, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudgetValue(a0, a1)
}
func BridgeServedGroupIDsCompleteMethodMarshalAPERChanged(v *ServedGroupIDsComplete, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeServedGroupIDsCompleteMethodMarshalAPERChangedValue(v *ServedGroupIDsComplete, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeServedGroupIDsCompleteMethodMarshalAPERLegacy(v *ServedGroupIDsComplete) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeServedGroupIDsCompleteMethodMarshalAPERNewValue(v *ServedGroupIDsComplete, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERNewValue(a0, a1)
}
func BridgeServedGroupIDsCompleteMethodMarshalAPERPlanned(v *ServedGroupIDsComplete, a0 *aper.DecodeBudget, a1 bool, a2 *aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1, a2)
}
func BridgeServedGroupIDsCompleteMethodUnmarshalAPERLegacy(v *ServedGroupIDsComplete, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeServedGroupIDsCompleteMethodUnmarshalAPERWithOptions(v *ServedGroupIDsComplete, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeServedMMECsCompleteFieldPerPadding(v *ServedMMECsComplete) *aper.CompletePadding {
	return &v.perPadding
}
func BridgeServedMMECsCompleteFieldReceived(v *ServedMMECsComplete) *bool { return &v.received }
func BridgeServedMMECsCompleteFieldReceivedAbsolute(v *ServedMMECsComplete) *bool {
	return &v.receivedAbsolute
}
func BridgeServedMMECsCompleteFieldReceivedBytes(v *ServedMMECsComplete) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeServedMMECsCompleteFieldReceivedLocation(v *ServedMMECsComplete) *aper.Location {
	return &v.receivedLocation
}
func BridgeServedMMECsCompleteFieldReplay(v *ServedMMECsComplete) *aper.Snapshot { return &v.replay }
func BridgeServedMMECsCompleteFieldStream(v *ServedMMECsComplete) *aper.WireSpan { return &v.stream }
func BridgeServedMMECsCompleteFieldWithoutReplay(v *ServedMMECsComplete) *bool {
	return &v.withoutReplay
}
func BridgeServedMMECsCompleteMethodMarshalAPERBudget(v *ServedMMECsComplete, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeServedMMECsCompleteMethodMarshalAPERBudgetValue(v *ServedMMECsComplete, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudgetValue(a0, a1)
}
func BridgeServedMMECsCompleteMethodMarshalAPERChanged(v *ServedMMECsComplete, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeServedMMECsCompleteMethodMarshalAPERChangedValue(v *ServedMMECsComplete, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeServedMMECsCompleteMethodMarshalAPERLegacy(v *ServedMMECsComplete) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeServedMMECsCompleteMethodMarshalAPERNewValue(v *ServedMMECsComplete, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERNewValue(a0, a1)
}
func BridgeServedMMECsCompleteMethodMarshalAPERPlanned(v *ServedMMECsComplete, a0 *aper.DecodeBudget, a1 bool, a2 *aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1, a2)
}
func BridgeServedMMECsCompleteMethodUnmarshalAPERLegacy(v *ServedMMECsComplete, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeServedMMECsCompleteMethodUnmarshalAPERWithOptions(v *ServedMMECsComplete, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeServedPLMNsCompleteFieldPerPadding(v *ServedPLMNsComplete) *aper.CompletePadding {
	return &v.perPadding
}
func BridgeServedPLMNsCompleteFieldReceived(v *ServedPLMNsComplete) *bool { return &v.received }
func BridgeServedPLMNsCompleteFieldReceivedAbsolute(v *ServedPLMNsComplete) *bool {
	return &v.receivedAbsolute
}
func BridgeServedPLMNsCompleteFieldReceivedBytes(v *ServedPLMNsComplete) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeServedPLMNsCompleteFieldReceivedLocation(v *ServedPLMNsComplete) *aper.Location {
	return &v.receivedLocation
}
func BridgeServedPLMNsCompleteFieldReplay(v *ServedPLMNsComplete) *aper.Snapshot { return &v.replay }
func BridgeServedPLMNsCompleteFieldStream(v *ServedPLMNsComplete) *aper.WireSpan { return &v.stream }
func BridgeServedPLMNsCompleteFieldWithoutReplay(v *ServedPLMNsComplete) *bool {
	return &v.withoutReplay
}
func BridgeServedPLMNsCompleteMethodMarshalAPERBudget(v *ServedPLMNsComplete, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeServedPLMNsCompleteMethodMarshalAPERBudgetValue(v *ServedPLMNsComplete, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudgetValue(a0, a1)
}
func BridgeServedPLMNsCompleteMethodMarshalAPERChanged(v *ServedPLMNsComplete, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeServedPLMNsCompleteMethodMarshalAPERChangedValue(v *ServedPLMNsComplete, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeServedPLMNsCompleteMethodMarshalAPERLegacy(v *ServedPLMNsComplete) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeServedPLMNsCompleteMethodMarshalAPERNewValue(v *ServedPLMNsComplete, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERNewValue(a0, a1)
}
func BridgeServedPLMNsCompleteMethodMarshalAPERPlanned(v *ServedPLMNsComplete, a0 *aper.DecodeBudget, a1 bool, a2 *aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1, a2)
}
func BridgeServedPLMNsCompleteMethodUnmarshalAPERLegacy(v *ServedPLMNsComplete, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeServedPLMNsCompleteMethodUnmarshalAPERWithOptions(v *ServedPLMNsComplete, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeSupportedTAsCompleteFieldPerPadding(v *SupportedTAsComplete) *aper.CompletePadding {
	return &v.perPadding
}
func BridgeSupportedTAsCompleteFieldReceived(v *SupportedTAsComplete) *bool { return &v.received }
func BridgeSupportedTAsCompleteFieldReceivedAbsolute(v *SupportedTAsComplete) *bool {
	return &v.receivedAbsolute
}
func BridgeSupportedTAsCompleteFieldReceivedBytes(v *SupportedTAsComplete) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeSupportedTAsCompleteFieldReceivedLocation(v *SupportedTAsComplete) *aper.Location {
	return &v.receivedLocation
}
func BridgeSupportedTAsCompleteFieldReplay(v *SupportedTAsComplete) *aper.Snapshot { return &v.replay }
func BridgeSupportedTAsCompleteFieldStream(v *SupportedTAsComplete) *aper.WireSpan { return &v.stream }
func BridgeSupportedTAsCompleteFieldWithoutReplay(v *SupportedTAsComplete) *bool {
	return &v.withoutReplay
}
func BridgeSupportedTAsCompleteMethodMarshalAPERBudget(v *SupportedTAsComplete, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeSupportedTAsCompleteMethodMarshalAPERBudgetValue(v *SupportedTAsComplete, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudgetValue(a0, a1)
}
func BridgeSupportedTAsCompleteMethodMarshalAPERChanged(v *SupportedTAsComplete, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeSupportedTAsCompleteMethodMarshalAPERChangedValue(v *SupportedTAsComplete, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeSupportedTAsCompleteMethodMarshalAPERLegacy(v *SupportedTAsComplete) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeSupportedTAsCompleteMethodMarshalAPERNewValue(v *SupportedTAsComplete, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERNewValue(a0, a1)
}
func BridgeSupportedTAsCompleteMethodMarshalAPERPlanned(v *SupportedTAsComplete, a0 *aper.DecodeBudget, a1 bool, a2 *aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1, a2)
}
func BridgeSupportedTAsCompleteMethodUnmarshalAPERLegacy(v *SupportedTAsComplete, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeSupportedTAsCompleteMethodUnmarshalAPERWithOptions(v *SupportedTAsComplete, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
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

// Selected returns the decoded value of the active alternative, as the matching As method returns it, or false when the value is opaque or empty.
// The field's Id distinguishes alternatives with the same Go type.
func (v *ENBConfigurationUpdateIEValue) Selected() (any, bool) {
	if v == nil || v.isOpaque {
		return nil, false
	}
	switch v.id {
	case 60:
		if value, ok := v.AsENBname(); ok {
			return value, true
		}
	case 64:
		if value, ok := v.AsSupportedTAs(); ok {
			return value, true
		}
	case 128:
		if value, ok := v.AsCSGIdList(); ok {
			return value, true
		}
	case 137:
		if value, ok := v.AsDefaultPagingDRX(); ok {
			return value, true
		}
	case 234:
		if value, ok := v.AsNBIoTDefaultPagingDRX(); ok {
			return value, true
		}
	case 292:
		if value, ok := v.AsConnectedengNBToAddList(); ok {
			return value, true
		}
	case 293:
		if value, ok := v.AsConnectedengNBToRemoveList(); ok {
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
func (v *S1SetupRequestIEValue) Selected() (any, bool) {
	if v == nil || v.isOpaque {
		return nil, false
	}
	switch v.id {
	case 59:
		if value, ok := v.AsGlobalENBID(); ok {
			return value, true
		}
	case 60:
		if value, ok := v.AsENBname(); ok {
			return value, true
		}
	case 64:
		if value, ok := v.AsSupportedTAs(); ok {
			return value, true
		}
	case 137:
		if value, ok := v.AsDefaultPagingDRX(); ok {
			return value, true
		}
	case 128:
		if value, ok := v.AsCSGIdList(); ok {
			return value, true
		}
	case 228:
		if value, ok := v.AsUERetentionInformation(); ok {
			return value, true
		}
	case 234:
		if value, ok := v.AsNBIoTDefaultPagingDRX(); ok {
			return value, true
		}
	case 291:
		if value, ok := v.AsConnectedengNBList(); ok {
			return value, true
		}
	}
	return nil, false
}

// Selected returns the decoded value of the active alternative, as the matching As method returns it, or false when the value is opaque or empty.
func (v *S1SetupResponseIEValue) Selected() (any, bool) {
	if v == nil || v.isOpaque {
		return nil, false
	}
	switch v.id {
	case 61:
		if value, ok := v.AsMMEname(); ok {
			return value, true
		}
	case 105:
		if value, ok := v.AsServedGUMMEIs(); ok {
			return value, true
		}
	case 87:
		if value, ok := v.AsRelativeMMECapacity(); ok {
			return value, true
		}
	case 163:
		if value, ok := v.AsMMERelaySupportIndicator(); ok {
			return value, true
		}
	case 58:
		if value, ok := v.AsCriticalityDiagnostics(); ok {
			return value, true
		}
	case 228:
		if value, ok := v.AsUERetentionInformation(); ok {
			return value, true
		}
	case 247:
		if value, ok := v.AsServedDCNs(); ok {
			return value, true
		}
	case 303:
		if value, ok := v.AsIABSupported(); ok {
			return value, true
		}
	}
	return nil, false
}
