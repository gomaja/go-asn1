// Code generated from the pinned S1AP source closure. DO NOT EDIT.

// Package s54 implements the github.com/gomaja/go-asn1/telecom/lte/s1ap root package.
package s54

import (
	fmt "fmt"
	s00 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s00"
	s01 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s01"
	s02 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s02"
	s03 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s03"
	s08 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s08"
	s16 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s16"
	s17 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s17"
	s21 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s21"
	s25 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s25"
	s26 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s26"
	s31 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s31"
	s39 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s39"
	s40 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s40"
	s41 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s41"
	s48 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s48"
	s53 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s53"
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
	if err := aper.EncodeIntegerAligned(bb, int64(v.Id), s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(65535), false); err != nil {
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
	id, err := aper.DecodeIntegerAligned(bb, s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(65535), false)
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
	if err := aper.EncodeIntegerAligned(bb, int64(v.Id), s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(65535), false); err != nil {
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
	id, err := aper.DecodeIntegerAligned(bb, s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(65535), false)
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
	if err := aper.EncodeIntegerAligned(bb, int64(v.Id), s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(65535), false); err != nil {
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
	id, err := aper.DecodeIntegerAligned(bb, s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(65535), false)
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

// MMEConfigurationUpdateIEContainer is ProtocolIE-Container {{MMEConfigurationUpdateIEs}} of TS 36.413: a list of MMEConfigurationUpdateIEField values.
type MMEConfigurationUpdateIEContainer []MMEConfigurationUpdateIEField

// MMEConfigurationUpdateIEField is ProtocolIE-Field {{MMEConfigurationUpdateIEs}} of TS 36.413: an information element field.
type MMEConfigurationUpdateIEField struct {
	withoutReplay bool
	replay        aper.Snapshot
	stream        aper.WireSpan
	Id            s00.ProtocolIEID
	Criticality   s00.Criticality
	Value         MMEConfigurationUpdateIEValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v MMEConfigurationUpdateIEField) WithoutReplay() MMEConfigurationUpdateIEField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *MMEConfigurationUpdateIEField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *MMEConfigurationUpdateIEField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
	if err := aper.EncodeIntegerAligned(bb, int64(v.Id), s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(65535), false); err != nil {
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
func (v *MMEConfigurationUpdateIEField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolIEField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = MMEConfigurationUpdateIEField{}
	id, err := aper.DecodeIntegerAligned(bb, s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(65535), false)
	if err != nil {
		return runtime.WrapDecodePath(err, "Id")
	}
	v.Id = s00.ProtocolIEID(id)
	criticality, err := aper.DecodeEnumeratedAligned(bb, 3, false)
	if err != nil {
		return runtime.WrapDecodePath(err, "Criticality")
	}
	v.Criticality = s00.Criticality(criticality)
	var zero MMEConfigurationUpdateIEValue

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
func BridgeMMEConfigurationUpdateIEValueCaptureS1APProtocolIEContainer(v *MMEConfigurationUpdateIEContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
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
func BridgeMMEConfigurationUpdateIEValueCompareS1APProtocolIEContainer(v *MMEConfigurationUpdateIEContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
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
	codec  s40.SupportedTAsValueCodec
	inject func(s40.SupportedTAs,

	) ENBConfigurationUpdateIEValue

	get func(*ENBConfigurationUpdateIEValue,

	) (*s40.SupportedTAs,

		bool)
}

// Info returns the source descriptor for this binding.
func (b ENBConfigurationUpdateSupportedTAsIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b ENBConfigurationUpdateSupportedTAsIEBinding) Codec() s40.SupportedTAsValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b ENBConfigurationUpdateSupportedTAsIEBinding) New(value s40.SupportedTAs,

) (ENBConfigurationUpdateIEField, error) {
	if b.inject == nil {
		return ENBConfigurationUpdateIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ENBConfigurationUpdateIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s40.BridgeSupportedTAsValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return ENBConfigurationUpdateIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return ENBConfigurationUpdateIEField{}, aper.OperationError(err, "Value.New")
	}
	return ENBConfigurationUpdateIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b ENBConfigurationUpdateSupportedTAsIEBinding) Get(field *ENBConfigurationUpdateIEField) (*s40.SupportedTAs,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// ENBConfigurationUpdateCSGIdListIEBinding binds CSGIdList to the ENBConfigurationUpdateIEs object set of TS 36.413.
type ENBConfigurationUpdateCSGIdListIEBinding struct {
	info   s00.FieldInfo
	codec  s17.CSGIdListValueCodec
	inject func(s17.CSGIdList,

	) ENBConfigurationUpdateIEValue

	get func(*ENBConfigurationUpdateIEValue,

	) (*s17.CSGIdList,

		bool)
}

// Info returns the source descriptor for this binding.
func (b ENBConfigurationUpdateCSGIdListIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b ENBConfigurationUpdateCSGIdListIEBinding) Codec() s17.CSGIdListValueCodec { return b.codec }

// New validates a source value and constructs its bound field.
func (b ENBConfigurationUpdateCSGIdListIEBinding) New(value s17.CSGIdList,

) (ENBConfigurationUpdateIEField, error) {
	if b.inject == nil {
		return ENBConfigurationUpdateIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ENBConfigurationUpdateIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s17.BridgeCSGIdListValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return ENBConfigurationUpdateIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return ENBConfigurationUpdateIEField{}, aper.OperationError(err, "Value.New")
	}
	return ENBConfigurationUpdateIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b ENBConfigurationUpdateCSGIdListIEBinding) Get(field *ENBConfigurationUpdateIEField) (*s17.CSGIdList,

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
	codec  s40.ConnectedengNBListValueCodec
	inject func(s40.ConnectedengNBList,

	) ENBConfigurationUpdateIEValue

	get func(*ENBConfigurationUpdateIEValue,

	) (*s40.ConnectedengNBList,

		bool)
}

// Info returns the source descriptor for this binding.
func (b ENBConfigurationUpdateConnectedengNBListIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b ENBConfigurationUpdateConnectedengNBListIEBinding) Codec() s40.ConnectedengNBListValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b ENBConfigurationUpdateConnectedengNBListIEBinding) New(value s40.ConnectedengNBList,

) (ENBConfigurationUpdateIEField, error) {
	if b.inject == nil {
		return ENBConfigurationUpdateIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ENBConfigurationUpdateIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s40.BridgeConnectedengNBListValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return ENBConfigurationUpdateIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return ENBConfigurationUpdateIEField{}, aper.OperationError(err, "Value.New")
	}
	return ENBConfigurationUpdateIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b ENBConfigurationUpdateConnectedengNBListIEBinding) Get(field *ENBConfigurationUpdateIEField) (*s40.ConnectedengNBList,

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

	) MMEConfigurationUpdateIEValue

	get func(*MMEConfigurationUpdateIEValue,

	) (*s00.MMEname,

		bool)
}

// Info returns the source descriptor for this binding.
func (b MMEConfigurationUpdateMMEnameIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b MMEConfigurationUpdateMMEnameIEBinding) Codec() s01.MMEnameValueCodec { return b.codec }

// New validates a source value and constructs its bound field.
func (b MMEConfigurationUpdateMMEnameIEBinding) New(value s00.MMEname,

) (MMEConfigurationUpdateIEField, error) {
	if b.inject == nil {
		return MMEConfigurationUpdateIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return MMEConfigurationUpdateIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s01.BridgeMMEnameValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return MMEConfigurationUpdateIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return MMEConfigurationUpdateIEField{}, aper.OperationError(err, "Value.New")
	}
	return MMEConfigurationUpdateIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b MMEConfigurationUpdateMMEnameIEBinding) Get(field *MMEConfigurationUpdateIEField) (*s00.MMEname,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// MMEConfigurationUpdateServedGUMMEIsIEBinding binds ServedGUMMEIs to the MMEConfigurationUpdateIEs object set of TS 36.413.
type MMEConfigurationUpdateServedGUMMEIsIEBinding struct {
	info   s00.FieldInfo
	codec  s39.ServedGUMMEIsValueCodec
	inject func(s39.ServedGUMMEIs,

	) MMEConfigurationUpdateIEValue

	get func(*MMEConfigurationUpdateIEValue,

	) (*s39.ServedGUMMEIs,

		bool)
}

// Info returns the source descriptor for this binding.
func (b MMEConfigurationUpdateServedGUMMEIsIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b MMEConfigurationUpdateServedGUMMEIsIEBinding) Codec() s39.ServedGUMMEIsValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b MMEConfigurationUpdateServedGUMMEIsIEBinding) New(value s39.ServedGUMMEIs,

) (MMEConfigurationUpdateIEField, error) {
	if b.inject == nil {
		return MMEConfigurationUpdateIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return MMEConfigurationUpdateIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s39.BridgeServedGUMMEIsValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return MMEConfigurationUpdateIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return MMEConfigurationUpdateIEField{}, aper.OperationError(err, "Value.New")
	}
	return MMEConfigurationUpdateIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b MMEConfigurationUpdateServedGUMMEIsIEBinding) Get(field *MMEConfigurationUpdateIEField) (*s39.ServedGUMMEIs,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// MMEConfigurationUpdateRelativeMMECapacityIEBinding binds RelativeMMECapacity to the MMEConfigurationUpdateIEs object set of TS 36.413.
type MMEConfigurationUpdateRelativeMMECapacityIEBinding struct {
	info   s00.FieldInfo
	codec  s02.RelativeMMECapacityValueCodec
	inject func(s00.RelativeMMECapacity,

	) MMEConfigurationUpdateIEValue

	get func(*MMEConfigurationUpdateIEValue,

	) (*s00.RelativeMMECapacity,

		bool)
}

// Info returns the source descriptor for this binding.
func (b MMEConfigurationUpdateRelativeMMECapacityIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b MMEConfigurationUpdateRelativeMMECapacityIEBinding) Codec() s02.RelativeMMECapacityValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b MMEConfigurationUpdateRelativeMMECapacityIEBinding) New(value s00.RelativeMMECapacity,

) (MMEConfigurationUpdateIEField, error) {
	if b.inject == nil {
		return MMEConfigurationUpdateIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return MMEConfigurationUpdateIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s02.BridgeRelativeMMECapacityValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return MMEConfigurationUpdateIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return MMEConfigurationUpdateIEField{}, aper.OperationError(err, "Value.New")
	}
	return MMEConfigurationUpdateIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b MMEConfigurationUpdateRelativeMMECapacityIEBinding) Get(field *MMEConfigurationUpdateIEField) (*s00.RelativeMMECapacity,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// MMEConfigurationUpdateServedDCNsIEBinding binds ServedDCNs to the MMEConfigurationUpdateIEs object set of TS 36.413.
type MMEConfigurationUpdateServedDCNsIEBinding struct {
	info   s00.FieldInfo
	codec  s39.ServedDCNsValueCodec
	inject func(s39.ServedDCNs,

	) MMEConfigurationUpdateIEValue

	get func(*MMEConfigurationUpdateIEValue,

	) (*s39.ServedDCNs,

		bool)
}

// Info returns the source descriptor for this binding.
func (b MMEConfigurationUpdateServedDCNsIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b MMEConfigurationUpdateServedDCNsIEBinding) Codec() s39.ServedDCNsValueCodec { return b.codec }

// New validates a source value and constructs its bound field.
func (b MMEConfigurationUpdateServedDCNsIEBinding) New(value s39.ServedDCNs,

) (MMEConfigurationUpdateIEField, error) {
	if b.inject == nil {
		return MMEConfigurationUpdateIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return MMEConfigurationUpdateIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s39.BridgeServedDCNsValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return MMEConfigurationUpdateIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return MMEConfigurationUpdateIEField{}, aper.OperationError(err, "Value.New")
	}
	return MMEConfigurationUpdateIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b MMEConfigurationUpdateServedDCNsIEBinding) Get(field *MMEConfigurationUpdateIEField) (*s39.ServedDCNs,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// S1SetupRequestGlobalENBIDIEBinding binds GlobalENBID to the S1SetupRequestIEs object set of TS 36.413.
type S1SetupRequestGlobalENBIDIEBinding struct {
	info   s00.FieldInfo
	codec  s21.GlobalENBIDValueCodec
	inject func(s21.GlobalENBID,

	) S1SetupRequestIEValue

	get func(*S1SetupRequestIEValue,

	) (*s21.GlobalENBID,

		bool)
}

// Info returns the source descriptor for this binding.
func (b S1SetupRequestGlobalENBIDIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b S1SetupRequestGlobalENBIDIEBinding) Codec() s21.GlobalENBIDValueCodec { return b.codec }

// New validates a source value and constructs its bound field.
func (b S1SetupRequestGlobalENBIDIEBinding) New(value s21.GlobalENBID,

) (S1SetupRequestIEField, error) {
	if b.inject == nil {
		return S1SetupRequestIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return S1SetupRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s21.BridgeGlobalENBIDValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return S1SetupRequestIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return S1SetupRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	return S1SetupRequestIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b S1SetupRequestGlobalENBIDIEBinding) Get(field *S1SetupRequestIEField) (*s21.GlobalENBID,

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
	codec  s40.SupportedTAsValueCodec
	inject func(s40.SupportedTAs,

	) S1SetupRequestIEValue

	get func(*S1SetupRequestIEValue,

	) (*s40.SupportedTAs,

		bool)
}

// Info returns the source descriptor for this binding.
func (b S1SetupRequestSupportedTAsIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b S1SetupRequestSupportedTAsIEBinding) Codec() s40.SupportedTAsValueCodec { return b.codec }

// New validates a source value and constructs its bound field.
func (b S1SetupRequestSupportedTAsIEBinding) New(value s40.SupportedTAs,

) (S1SetupRequestIEField, error) {
	if b.inject == nil {
		return S1SetupRequestIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return S1SetupRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s40.BridgeSupportedTAsValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return S1SetupRequestIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return S1SetupRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	return S1SetupRequestIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b S1SetupRequestSupportedTAsIEBinding) Get(field *S1SetupRequestIEField) (*s40.SupportedTAs,

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
	codec  s17.CSGIdListValueCodec
	inject func(s17.CSGIdList,

	) S1SetupRequestIEValue

	get func(*S1SetupRequestIEValue,

	) (*s17.CSGIdList,

		bool)
}

// Info returns the source descriptor for this binding.
func (b S1SetupRequestCSGIdListIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b S1SetupRequestCSGIdListIEBinding) Codec() s17.CSGIdListValueCodec { return b.codec }

// New validates a source value and constructs its bound field.
func (b S1SetupRequestCSGIdListIEBinding) New(value s17.CSGIdList,

) (S1SetupRequestIEField, error) {
	if b.inject == nil {
		return S1SetupRequestIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return S1SetupRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s17.BridgeCSGIdListValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return S1SetupRequestIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return S1SetupRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	return S1SetupRequestIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b S1SetupRequestCSGIdListIEBinding) Get(field *S1SetupRequestIEField) (*s17.CSGIdList,

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
	codec  s40.ConnectedengNBListValueCodec
	inject func(s40.ConnectedengNBList,

	) S1SetupRequestIEValue

	get func(*S1SetupRequestIEValue,

	) (*s40.ConnectedengNBList,

		bool)
}

// Info returns the source descriptor for this binding.
func (b S1SetupRequestConnectedengNBListIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b S1SetupRequestConnectedengNBListIEBinding) Codec() s40.ConnectedengNBListValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b S1SetupRequestConnectedengNBListIEBinding) New(value s40.ConnectedengNBList,

) (S1SetupRequestIEField, error) {
	if b.inject == nil {
		return S1SetupRequestIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return S1SetupRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s40.BridgeConnectedengNBListValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return S1SetupRequestIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return S1SetupRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	return S1SetupRequestIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b S1SetupRequestConnectedengNBListIEBinding) Get(field *S1SetupRequestIEField) (*s40.ConnectedengNBList,

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
	codec  s39.ServedGUMMEIsValueCodec
	inject func(s39.ServedGUMMEIs,

	) S1SetupResponseIEValue

	get func(*S1SetupResponseIEValue,

	) (*s39.ServedGUMMEIs,

		bool)
}

// Info returns the source descriptor for this binding.
func (b S1SetupResponseServedGUMMEIsIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b S1SetupResponseServedGUMMEIsIEBinding) Codec() s39.ServedGUMMEIsValueCodec { return b.codec }

// New validates a source value and constructs its bound field.
func (b S1SetupResponseServedGUMMEIsIEBinding) New(value s39.ServedGUMMEIs,

) (S1SetupResponseIEField, error) {
	if b.inject == nil {
		return S1SetupResponseIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return S1SetupResponseIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s39.BridgeServedGUMMEIsValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return S1SetupResponseIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return S1SetupResponseIEField{}, aper.OperationError(err, "Value.New")
	}
	return S1SetupResponseIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b S1SetupResponseServedGUMMEIsIEBinding) Get(field *S1SetupResponseIEField) (*s39.ServedGUMMEIs,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// S1SetupResponseRelativeMMECapacityIEBinding binds RelativeMMECapacity to the S1SetupResponseIEs object set of TS 36.413.
type S1SetupResponseRelativeMMECapacityIEBinding struct {
	info   s00.FieldInfo
	codec  s02.RelativeMMECapacityValueCodec
	inject func(s00.RelativeMMECapacity,

	) S1SetupResponseIEValue

	get func(*S1SetupResponseIEValue,

	) (*s00.RelativeMMECapacity,

		bool)
}

// Info returns the source descriptor for this binding.
func (b S1SetupResponseRelativeMMECapacityIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b S1SetupResponseRelativeMMECapacityIEBinding) Codec() s02.RelativeMMECapacityValueCodec {
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
	if _, err := (*s02.BridgeRelativeMMECapacityValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
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
	codec  s26.CriticalityDiagnosticsValueCodec
	inject func(s26.CriticalityDiagnostics,

	) S1SetupResponseIEValue

	get func(*S1SetupResponseIEValue,

	) (*s26.CriticalityDiagnostics,

		bool)
}

// Info returns the source descriptor for this binding.
func (b S1SetupResponseCriticalityDiagnosticsIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b S1SetupResponseCriticalityDiagnosticsIEBinding) Codec() s26.CriticalityDiagnosticsValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b S1SetupResponseCriticalityDiagnosticsIEBinding) New(value s26.CriticalityDiagnostics,

) (S1SetupResponseIEField, error) {
	if b.inject == nil {
		return S1SetupResponseIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return S1SetupResponseIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s26.BridgeCriticalityDiagnosticsValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return S1SetupResponseIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return S1SetupResponseIEField{}, aper.OperationError(err, "Value.New")
	}
	return S1SetupResponseIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b S1SetupResponseCriticalityDiagnosticsIEBinding) Get(field *S1SetupResponseIEField) (*s26.CriticalityDiagnostics,

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
	codec  s39.ServedDCNsValueCodec
	inject func(s39.ServedDCNs,

	) S1SetupResponseIEValue

	get func(*S1SetupResponseIEValue,

	) (*s39.ServedDCNs,

		bool)
}

// Info returns the source descriptor for this binding.
func (b S1SetupResponseServedDCNsIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b S1SetupResponseServedDCNsIEBinding) Codec() s39.ServedDCNsValueCodec { return b.codec }

// New validates a source value and constructs its bound field.
func (b S1SetupResponseServedDCNsIEBinding) New(value s39.ServedDCNs,

) (S1SetupResponseIEField, error) {
	if b.inject == nil {
		return S1SetupResponseIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return S1SetupResponseIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s39.BridgeServedDCNsValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return S1SetupResponseIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return S1SetupResponseIEField{}, aper.OperationError(err, "Value.New")
	}
	return S1SetupResponseIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b S1SetupResponseServedDCNsIEBinding) Get(field *S1SetupResponseIEField) (*s39.ServedDCNs,

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

) s25.ValidationReport {
	report := func() s25.ValidationReport {
		sealed := s25.ValidationReport{Complete: true}
		*s25.BridgeValidationReportFieldBudget(&sealed) = budget
		return sealed
	}()
	bb := aper.NewBudgetBuffer(budget)
	if err := bb.ChargeAllocation(uint64(len(rows))+uint64(len(fields)), 32); err != nil {
		*s25.BridgeValidationReportFieldErr(&report) = err
		return report
	}
	byID := make(map[s00.ProtocolIEID]int, len(rows))
	counts := make(map[s00.ProtocolIEID]int, len(fields))
	for i, row := range rows {
		byID[row.ID] = i
	}
	lastRank := -1
	for i, field := range fields {
		if *s25.BridgeValidationReportFieldErr(&report) != nil {
			return report
		}
		if err := bb.ChargeWork(1); err != nil {
			*s25.BridgeValidationReportFieldErr(&report) = err
			return report
		}
		location := aper.Location{Path: aper.Path(fmt.Sprintf("%s[%d]{id=%d}", path, i, field.Id))}
		// TS 36.413 V19.2.0 §9.3.7 binds the selected value to @id.
		if !field.Value.matchesID(field.Id, budget) {
			rule := field.Value.rule()
			s25.BridgeValidationReportMethodAddIssue(&report, s25.ValidationIssue{Code: s00.ValueIDMismatch, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: aper.Path(fmt.Sprintf("%s.id", location.Path))}, Table: func() s00.TableID {
				sealed := s00.TableID{}
				*s00.BridgeTableIDFieldSource(&sealed) = rule.Assignment
				return sealed
			}(), IEID: field.Id, HasIEID: true, Rule: s31.BridgeS1apValidationRule(s00.ValueIDMismatch), RelatedRules: []aper.SourceRule{rule}})
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
			s25.BridgeValidationReportMethodAddIssue(&report, s25.ValidationIssue{Code: s00.RepeatedIE, Severity: s00.ValidationSeverityError, Location: location, Table: table, IEID: field.Id, HasIEID: true, Rule: s31.BridgeS1apValidationRule(s00.RepeatedIE), RelatedRules: append([]aper.SourceRule{s31.BridgeS1apAdoptedRule(s00.RepeatedIE)}, sourceRules...)})
		}
		if !allowed {
			severity := s00.ValidationSeverityUnrecognized
			if _, globallyKnown := s16.BridgeKnownS1APIEIDs[field.Id]; globallyKnown {
				severity = s00.ValidationSeverityError
			}
			s25.BridgeValidationReportMethodAddIssue(&report, s25.ValidationIssue{Code: s00.NotAllowed, Severity: severity, Location: location, Table: table, IEID: field.Id, HasIEID: true, Rule: s31.BridgeS1apValidationRule(s00.NotAllowed), RelatedRules: s31.BridgeS1apHandlingRules(s00.NotAllowed)})
			continue
		}
		row := rows[rank]
		if field.Criticality != row.Criticality {
			expected, received := row.Criticality, field.Criticality
			s25.BridgeValidationReportMethodAddIssue(&report, s25.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: aper.Path(fmt.Sprintf("%s.criticality", location.Path))}, Table: row.Table, IEID: field.Id, HasIEID: true, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s31.BridgeS1apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{s31.BridgeS1apAdoptedRule(s00.WrongCriticality), row.Rule}})
		}
		if rank < lastRank {
			s25.BridgeValidationReportMethodAddIssue(&report, s25.ValidationIssue{Code: s00.WrongOrder, Severity: s00.ValidationSeverityError, Location: location, Table: row.Table, IEID: field.Id, HasIEID: true, Rule: s31.BridgeS1apValidationRule(s00.WrongOrder), RelatedRules: []aper.SourceRule{s31.BridgeS1apAdoptedRule(s00.WrongOrder), row.Rule}})
		} else {
			lastRank = rank
		}
	}
	for _, row := range rows {
		if row.Presence == s00.PresenceMandatory && counts[row.ID] == 0 {
			s25.BridgeValidationReportMethodAddIssue(&report, s25.ValidationIssue{Code: s00.MissingMandatory, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: aper.Path(path)}, Table: row.Table, IEID: row.ID, HasIEID: true, Rule: s31.BridgeS1apValidationRule(s00.MissingMandatory), RelatedRules: []aper.SourceRule{s31.BridgeS1apAdoptedRule(s00.MissingMandatory), row.Rule}})
		}
		if row.Presence == s00.PresenceConditional {
			s25.BridgeValidationReportMethodAddDeferred(&report, s00.DeferredCondition{Location: aper.Location{Path: aper.Path(path)}, Table: row.Table, IEID: row.ID, Rule: row.Rule})
			if *s25.BridgeValidationReportFieldErr(&report) != nil {
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

) s25.ValidationReport {
	report := func() s25.ValidationReport {
		sealed := s25.ValidationReport{Complete: true}
		*s25.BridgeValidationReportFieldBudget(&sealed) = budget
		return sealed
	}()
	bb := aper.NewBudgetBuffer(budget)
	if err := bb.ChargeAllocation(uint64(len(rows))+uint64(len(fields)), 32); err != nil {
		*s25.BridgeValidationReportFieldErr(&report) = err
		return report
	}
	byID := make(map[s00.ProtocolIEID]int, len(rows))
	counts := make(map[s00.ProtocolIEID]int, len(fields))
	for i, row := range rows {
		byID[row.ID] = i
	}
	lastRank := -1
	for i, field := range fields {
		if *s25.BridgeValidationReportFieldErr(&report) != nil {
			return report
		}
		if err := bb.ChargeWork(1); err != nil {
			*s25.BridgeValidationReportFieldErr(&report) = err
			return report
		}
		location := aper.Location{Path: aper.Path(fmt.Sprintf("%s[%d]{id=%d}", path, i, field.Id))}
		// TS 36.413 V19.2.0 §9.3.7 binds the selected value to @id.
		if !field.Value.matchesID(field.Id, budget) {
			rule := field.Value.rule()
			s25.BridgeValidationReportMethodAddIssue(&report, s25.ValidationIssue{Code: s00.ValueIDMismatch, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: aper.Path(fmt.Sprintf("%s.id", location.Path))}, Table: func() s00.TableID {
				sealed := s00.TableID{}
				*s00.BridgeTableIDFieldSource(&sealed) = rule.Assignment
				return sealed
			}(), IEID: field.Id, HasIEID: true, Rule: s31.BridgeS1apValidationRule(s00.ValueIDMismatch), RelatedRules: []aper.SourceRule{rule}})
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
			s25.BridgeValidationReportMethodAddIssue(&report, s25.ValidationIssue{Code: s00.RepeatedIE, Severity: s00.ValidationSeverityError, Location: location, Table: table, IEID: field.Id, HasIEID: true, Rule: s31.BridgeS1apValidationRule(s00.RepeatedIE), RelatedRules: append([]aper.SourceRule{s31.BridgeS1apAdoptedRule(s00.RepeatedIE)}, sourceRules...)})
		}
		if !allowed {
			severity := s00.ValidationSeverityUnrecognized
			if _, globallyKnown := s16.BridgeKnownS1APIEIDs[field.Id]; globallyKnown {
				severity = s00.ValidationSeverityError
			}
			s25.BridgeValidationReportMethodAddIssue(&report, s25.ValidationIssue{Code: s00.NotAllowed, Severity: severity, Location: location, Table: table, IEID: field.Id, HasIEID: true, Rule: s31.BridgeS1apValidationRule(s00.NotAllowed), RelatedRules: s31.BridgeS1apHandlingRules(s00.NotAllowed)})
			continue
		}
		row := rows[rank]
		if field.Criticality != row.Criticality {
			expected, received := row.Criticality, field.Criticality
			s25.BridgeValidationReportMethodAddIssue(&report, s25.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: aper.Path(fmt.Sprintf("%s.criticality", location.Path))}, Table: row.Table, IEID: field.Id, HasIEID: true, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s31.BridgeS1apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{s31.BridgeS1apAdoptedRule(s00.WrongCriticality), row.Rule}})
		}
		if rank < lastRank {
			s25.BridgeValidationReportMethodAddIssue(&report, s25.ValidationIssue{Code: s00.WrongOrder, Severity: s00.ValidationSeverityError, Location: location, Table: row.Table, IEID: field.Id, HasIEID: true, Rule: s31.BridgeS1apValidationRule(s00.WrongOrder), RelatedRules: []aper.SourceRule{s31.BridgeS1apAdoptedRule(s00.WrongOrder), row.Rule}})
		} else {
			lastRank = rank
		}
	}
	for _, row := range rows {
		if row.Presence == s00.PresenceMandatory && counts[row.ID] == 0 {
			s25.BridgeValidationReportMethodAddIssue(&report, s25.ValidationIssue{Code: s00.MissingMandatory, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: aper.Path(path)}, Table: row.Table, IEID: row.ID, HasIEID: true, Rule: s31.BridgeS1apValidationRule(s00.MissingMandatory), RelatedRules: []aper.SourceRule{s31.BridgeS1apAdoptedRule(s00.MissingMandatory), row.Rule}})
		}
		if row.Presence == s00.PresenceConditional {
			s25.BridgeValidationReportMethodAddDeferred(&report, s00.DeferredCondition{Location: aper.Location{Path: aper.Path(path)}, Table: row.Table, IEID: row.ID, Rule: row.Rule})
			if *s25.BridgeValidationReportFieldErr(&report) != nil {
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

) s25.ValidationReport {
	report := func() s25.ValidationReport {
		sealed := s25.ValidationReport{Complete: true}
		*s25.BridgeValidationReportFieldBudget(&sealed) = budget
		return sealed
	}()
	bb := aper.NewBudgetBuffer(budget)
	if err := bb.ChargeAllocation(uint64(len(rows))+uint64(len(fields)), 32); err != nil {
		*s25.BridgeValidationReportFieldErr(&report) = err
		return report
	}
	byID := make(map[s00.ProtocolIEID]int, len(rows))
	counts := make(map[s00.ProtocolIEID]int, len(fields))
	for i, row := range rows {
		byID[row.ID] = i
	}
	lastRank := -1
	for i, field := range fields {
		if *s25.BridgeValidationReportFieldErr(&report) != nil {
			return report
		}
		if err := bb.ChargeWork(1); err != nil {
			*s25.BridgeValidationReportFieldErr(&report) = err
			return report
		}
		location := aper.Location{Path: aper.Path(fmt.Sprintf("%s[%d]{id=%d}", path, i, field.Id))}
		// TS 36.413 V19.2.0 §9.3.7 binds the selected value to @id.
		if !field.Value.matchesID(field.Id, budget) {
			rule := field.Value.rule()
			s25.BridgeValidationReportMethodAddIssue(&report, s25.ValidationIssue{Code: s00.ValueIDMismatch, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: aper.Path(fmt.Sprintf("%s.id", location.Path))}, Table: func() s00.TableID {
				sealed := s00.TableID{}
				*s00.BridgeTableIDFieldSource(&sealed) = rule.Assignment
				return sealed
			}(), IEID: field.Id, HasIEID: true, Rule: s31.BridgeS1apValidationRule(s00.ValueIDMismatch), RelatedRules: []aper.SourceRule{rule}})
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
			s25.BridgeValidationReportMethodAddIssue(&report, s25.ValidationIssue{Code: s00.RepeatedIE, Severity: s00.ValidationSeverityError, Location: location, Table: table, IEID: field.Id, HasIEID: true, Rule: s31.BridgeS1apValidationRule(s00.RepeatedIE), RelatedRules: append([]aper.SourceRule{s31.BridgeS1apAdoptedRule(s00.RepeatedIE)}, sourceRules...)})
		}
		if !allowed {
			severity := s00.ValidationSeverityUnrecognized
			if _, globallyKnown := s16.BridgeKnownS1APIEIDs[field.Id]; globallyKnown {
				severity = s00.ValidationSeverityError
			}
			s25.BridgeValidationReportMethodAddIssue(&report, s25.ValidationIssue{Code: s00.NotAllowed, Severity: severity, Location: location, Table: table, IEID: field.Id, HasIEID: true, Rule: s31.BridgeS1apValidationRule(s00.NotAllowed), RelatedRules: s31.BridgeS1apHandlingRules(s00.NotAllowed)})
			continue
		}
		row := rows[rank]
		if field.Criticality != row.Criticality {
			expected, received := row.Criticality, field.Criticality
			s25.BridgeValidationReportMethodAddIssue(&report, s25.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: aper.Path(fmt.Sprintf("%s.criticality", location.Path))}, Table: row.Table, IEID: field.Id, HasIEID: true, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s31.BridgeS1apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{s31.BridgeS1apAdoptedRule(s00.WrongCriticality), row.Rule}})
		}
		if rank < lastRank {
			s25.BridgeValidationReportMethodAddIssue(&report, s25.ValidationIssue{Code: s00.WrongOrder, Severity: s00.ValidationSeverityError, Location: location, Table: row.Table, IEID: field.Id, HasIEID: true, Rule: s31.BridgeS1apValidationRule(s00.WrongOrder), RelatedRules: []aper.SourceRule{s31.BridgeS1apAdoptedRule(s00.WrongOrder), row.Rule}})
		} else {
			lastRank = rank
		}
	}
	for _, row := range rows {
		if row.Presence == s00.PresenceMandatory && counts[row.ID] == 0 {
			s25.BridgeValidationReportMethodAddIssue(&report, s25.ValidationIssue{Code: s00.MissingMandatory, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: aper.Path(path)}, Table: row.Table, IEID: row.ID, HasIEID: true, Rule: s31.BridgeS1apValidationRule(s00.MissingMandatory), RelatedRules: []aper.SourceRule{s31.BridgeS1apAdoptedRule(s00.MissingMandatory), row.Rule}})
		}
		if row.Presence == s00.PresenceConditional {
			s25.BridgeValidationReportMethodAddDeferred(&report, s00.DeferredCondition{Location: aper.Location{Path: aper.Path(path)}, Table: row.Table, IEID: row.ID, Rule: row.Rule})
			if *s25.BridgeValidationReportFieldErr(&report) != nil {
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
func BridgeMMEConfigurationUpdateIEValueValidateS1APIEContainer(fields MMEConfigurationUpdateIEContainer, rows []s00.FieldInfo, path string, budget *aper.DecodeBudget,

) s25.ValidationReport {
	report := func() s25.ValidationReport {
		sealed := s25.ValidationReport{Complete: true}
		*s25.BridgeValidationReportFieldBudget(&sealed) = budget
		return sealed
	}()
	bb := aper.NewBudgetBuffer(budget)
	if err := bb.ChargeAllocation(uint64(len(rows))+uint64(len(fields)), 32); err != nil {
		*s25.BridgeValidationReportFieldErr(&report) = err
		return report
	}
	byID := make(map[s00.ProtocolIEID]int, len(rows))
	counts := make(map[s00.ProtocolIEID]int, len(fields))
	for i, row := range rows {
		byID[row.ID] = i
	}
	lastRank := -1
	for i, field := range fields {
		if *s25.BridgeValidationReportFieldErr(&report) != nil {
			return report
		}
		if err := bb.ChargeWork(1); err != nil {
			*s25.BridgeValidationReportFieldErr(&report) = err
			return report
		}
		location := aper.Location{Path: aper.Path(fmt.Sprintf("%s[%d]{id=%d}", path, i, field.Id))}
		// TS 36.413 V19.2.0 §9.3.7 binds the selected value to @id.
		if !field.Value.matchesID(field.Id, budget) {
			rule := field.Value.rule()
			s25.BridgeValidationReportMethodAddIssue(&report, s25.ValidationIssue{Code: s00.ValueIDMismatch, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: aper.Path(fmt.Sprintf("%s.id", location.Path))}, Table: func() s00.TableID {
				sealed := s00.TableID{}
				*s00.BridgeTableIDFieldSource(&sealed) = rule.Assignment
				return sealed
			}(), IEID: field.Id, HasIEID: true, Rule: s31.BridgeS1apValidationRule(s00.ValueIDMismatch), RelatedRules: []aper.SourceRule{rule}})
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
			s25.BridgeValidationReportMethodAddIssue(&report, s25.ValidationIssue{Code: s00.RepeatedIE, Severity: s00.ValidationSeverityError, Location: location, Table: table, IEID: field.Id, HasIEID: true, Rule: s31.BridgeS1apValidationRule(s00.RepeatedIE), RelatedRules: append([]aper.SourceRule{s31.BridgeS1apAdoptedRule(s00.RepeatedIE)}, sourceRules...)})
		}
		if !allowed {
			severity := s00.ValidationSeverityUnrecognized
			if _, globallyKnown := s16.BridgeKnownS1APIEIDs[field.Id]; globallyKnown {
				severity = s00.ValidationSeverityError
			}
			s25.BridgeValidationReportMethodAddIssue(&report, s25.ValidationIssue{Code: s00.NotAllowed, Severity: severity, Location: location, Table: table, IEID: field.Id, HasIEID: true, Rule: s31.BridgeS1apValidationRule(s00.NotAllowed), RelatedRules: s31.BridgeS1apHandlingRules(s00.NotAllowed)})
			continue
		}
		row := rows[rank]
		if field.Criticality != row.Criticality {
			expected, received := row.Criticality, field.Criticality
			s25.BridgeValidationReportMethodAddIssue(&report, s25.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: aper.Path(fmt.Sprintf("%s.criticality", location.Path))}, Table: row.Table, IEID: field.Id, HasIEID: true, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s31.BridgeS1apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{s31.BridgeS1apAdoptedRule(s00.WrongCriticality), row.Rule}})
		}
		if rank < lastRank {
			s25.BridgeValidationReportMethodAddIssue(&report, s25.ValidationIssue{Code: s00.WrongOrder, Severity: s00.ValidationSeverityError, Location: location, Table: row.Table, IEID: field.Id, HasIEID: true, Rule: s31.BridgeS1apValidationRule(s00.WrongOrder), RelatedRules: []aper.SourceRule{s31.BridgeS1apAdoptedRule(s00.WrongOrder), row.Rule}})
		} else {
			lastRank = rank
		}
	}
	for _, row := range rows {
		if row.Presence == s00.PresenceMandatory && counts[row.ID] == 0 {
			s25.BridgeValidationReportMethodAddIssue(&report, s25.ValidationIssue{Code: s00.MissingMandatory, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: aper.Path(path)}, Table: row.Table, IEID: row.ID, HasIEID: true, Rule: s31.BridgeS1apValidationRule(s00.MissingMandatory), RelatedRules: []aper.SourceRule{s31.BridgeS1apAdoptedRule(s00.MissingMandatory), row.Rule}})
		}
		if row.Presence == s00.PresenceConditional {
			s25.BridgeValidationReportMethodAddDeferred(&report, s00.DeferredCondition{Location: aper.Location{Path: aper.Path(path)}, Table: row.Table, IEID: row.ID, Rule: row.Rule})
			if *s25.BridgeValidationReportFieldErr(&report) != nil {
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
	return ENBConfigurationUpdateIEValueERABIEContainerListValueCodec{path: "ENBConfigurationUpdateIEValueERABIEContainerList", decode: func(data []byte, options aper.DecodeState) (ENBConfigurationUpdateIEValueERABIEContainerList, error) {
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
	if codec.decode == nil {
		return MMEConfigurationUpdateIEValueERABIEContainerListValueCodec{}
	}
	size := aper.SizeConstraint{Lower: (aper.ListBounds{Lower: 1, Upper: 256}).Lower, Upper: (aper.ListBounds{Lower: 1, Upper: 256}).Upper, HasLower: true, HasUpper: true}
	return MMEConfigurationUpdateIEValueERABIEContainerListValueCodec{path: "MMEConfigurationUpdateIEValueERABIEContainerList", decode: func(data []byte, options aper.DecodeState) (MMEConfigurationUpdateIEValueERABIEContainerList, error) {
		bb := aper.NewCompleteDecodeBuffer(data, options)
		if err := bb.SetDecodeOptionsAligned(options); err != nil {
			return nil, err
		}
		var fields MMEConfigurationUpdateIEValueERABIEContainerList
		_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
			for i := int64(0); i < length; i++ {
				var field MMEConfigurationUpdateIEField
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
			return nil, runtime.WrapDecodePath(err, "MMEConfigurationUpdateIEValueERABIEContainerList")
		}
		if _, err := aper.CaptureFinalBits(bb, "MMEConfigurationUpdateIEValueERABIEContainerList"); err != nil {
			return nil, runtime.WrapDecodePath(err, "MMEConfigurationUpdateIEValueERABIEContainerList")
		}
		return fields, nil
	}, encode: func(value MMEConfigurationUpdateIEValueERABIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return codec.encode(MMEConfigurationUpdateIEContainer(value), fresh, budget)
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
	return S1SetupRequestIEValueERABIEContainerListValueCodec{path: "S1SetupRequestIEValueERABIEContainerList", decode: func(data []byte, options aper.DecodeState) (S1SetupRequestIEValueERABIEContainerList, error) {
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
	return S1SetupResponseIEValueERABIEContainerListValueCodec{path: "S1SetupResponseIEValueERABIEContainerList", decode: func(data []byte, options aper.DecodeState) (S1SetupResponseIEValueERABIEContainerList, error) {
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
	return ENBConfigurationUpdateIEFieldValueCodec{path: "ENBConfigurationUpdateIEField", decode: func(data []byte, options aper.DecodeState) (ENBConfigurationUpdateIEField, error) {
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
	return MMEConfigurationUpdateIEFieldValueCodec{path: "MMEConfigurationUpdateIEField", decode: func(data []byte, options aper.DecodeState) (MMEConfigurationUpdateIEField, error) {
		var field MMEConfigurationUpdateIEField
		bb := aper.NewCompleteDecodeBuffer(data, options)
		if err := bb.SetDecodeOptionsAligned(options); err != nil {
			return field, err
		}
		if err := field.unmarshalAPERFrom(bb); err != nil {
			return field, runtime.WrapDecodePath(err, "MMEConfigurationUpdateIEField")
		}
		if _, err := aper.CaptureFinalBits(bb, "MMEConfigurationUpdateIEField"); err != nil {
			return field, runtime.WrapDecodePath(err, "MMEConfigurationUpdateIEField")
		}
		return field, nil
	}, encode: func(field MMEConfigurationUpdateIEField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		bb := aper.NewBudgetBuffer(budget)
		if err := field.marshalAPERTo(bb, fresh); err != nil {
			return nil, err
		}
		return bb.CompleteBytes(), nil
	}, capture: func(v MMEConfigurationUpdateIEField, options aper.DecodeState) (MMEConfigurationUpdateIEField, aper.Snapshot,
	) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeMMEConfigurationUpdateIEValueCaptureS1APProtocolIEField(&v, &s)
		var root aper.Snapshot
		s.End(f, &root, false)
		return v, root
	}, compare: func(v MMEConfigurationUpdateIEField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

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

// S1SetupRequestIEValueIEFieldTableCodec constructs the ProtocolIE-Field {{S1SetupRequestIEs}} codec of TS 36.413.
func S1SetupRequestIEValueIEFieldTableCodec(table s00.S1SetupRequestIEValueIETable) S1SetupRequestIEFieldValueCodec {
	if !*s00.BridgeS1SetupRequestIEValueIETableFieldBound(&table) {
		return S1SetupRequestIEFieldValueCodec{}
	}
	return S1SetupRequestIEFieldValueCodec{path: "S1SetupRequestIEField", decode: func(data []byte, options aper.DecodeState) (S1SetupRequestIEField, error) {
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
	return S1SetupResponseIEFieldValueCodec{path: "S1SetupResponseIEField", decode: func(data []byte, options aper.DecodeState) (S1SetupResponseIEField, error) {
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
	return ENBConfigurationUpdateIEContainerValueCodec{path: "ENBConfigurationUpdateIEContainer", decode: func(data []byte, options aper.DecodeState) (ENBConfigurationUpdateIEContainer, error) {
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
func MMEConfigurationUpdateIEValueIETableCodec(table s00.MMEConfigurationUpdateIEValueIETable, bounds aper.ListBounds) MMEConfigurationUpdateIEContainerValueCodec {
	if !*s00.BridgeMMEConfigurationUpdateIEValueIETableFieldBound(&table) {
		return MMEConfigurationUpdateIEContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return MMEConfigurationUpdateIEContainerValueCodec{path: "MMEConfigurationUpdateIEContainer", decode: func(data []byte, options aper.DecodeState) (MMEConfigurationUpdateIEContainer, error) {
		bb := aper.NewCompleteDecodeBuffer(data, options)
		if err := bb.SetDecodeOptionsAligned(options); err != nil {
			return nil, err
		}
		var fields MMEConfigurationUpdateIEContainer
		_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
			for i := int64(0); i < length; i++ {
				var field MMEConfigurationUpdateIEField
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
			return nil, runtime.WrapDecodePath(err, "MMEConfigurationUpdateIEContainer")
		}
		if _, err := aper.CaptureFinalBits(bb, "MMEConfigurationUpdateIEContainer"); err != nil {
			return nil, runtime.WrapDecodePath(err, "MMEConfigurationUpdateIEContainer")
		}
		return fields, nil
	},
		encode: func(fields MMEConfigurationUpdateIEContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
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
		}, capture: func(v MMEConfigurationUpdateIEContainer, options aper.DecodeState) (MMEConfigurationUpdateIEContainer, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeMMEConfigurationUpdateIEValueCaptureS1APProtocolIEContainer(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,

				false)
			return v, root
		}, compare: func(v MMEConfigurationUpdateIEContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeMMEConfigurationUpdateIEValueCompareS1APProtocolIEContainer(&v, &s)
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
	return S1SetupRequestIEContainerValueCodec{path: "S1SetupRequestIEContainer", decode: func(data []byte, options aper.DecodeState) (S1SetupRequestIEContainer, error) {
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
	return S1SetupResponseIEContainerValueCodec{path: "S1SetupResponseIEContainer", decode: func(data []byte, options aper.DecodeState) (S1SetupResponseIEContainer, error) {
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
	return ENBConfigurationUpdateIEValueProtocolErrorIEContainerListValueCodec{path: "ENBConfigurationUpdateIEValueProtocolErrorIEContainerList", decode: func(data []byte, options aper.DecodeState) (ENBConfigurationUpdateIEValueProtocolErrorIEContainerList, error) {
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
	if codec.decode == nil {
		return MMEConfigurationUpdateIEValueProtocolErrorIEContainerListValueCodec{}
	}
	size := aper.SizeConstraint{Lower: (aper.ListBounds{Lower: 1, Upper: 256}).Lower, Upper: (aper.ListBounds{Lower: 1, Upper: 256}).Upper, HasLower: true, HasUpper: true}
	return MMEConfigurationUpdateIEValueProtocolErrorIEContainerListValueCodec{path: "MMEConfigurationUpdateIEValueProtocolErrorIEContainerList", decode: func(data []byte, options aper.DecodeState) (MMEConfigurationUpdateIEValueProtocolErrorIEContainerList, error) {
		bb := aper.NewCompleteDecodeBuffer(data, options)
		if err := bb.SetDecodeOptionsAligned(options); err != nil {
			return nil, err
		}
		var fields MMEConfigurationUpdateIEValueProtocolErrorIEContainerList
		_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
			for i := int64(0); i < length; i++ {
				var field MMEConfigurationUpdateIEField
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
			return nil, runtime.WrapDecodePath(err, "MMEConfigurationUpdateIEValueProtocolErrorIEContainerList")
		}
		if _, err := aper.CaptureFinalBits(bb, "MMEConfigurationUpdateIEValueProtocolErrorIEContainerList"); err != nil {
			return nil, runtime.WrapDecodePath(err, "MMEConfigurationUpdateIEValueProtocolErrorIEContainerList")
		}
		return fields, nil
	}, encode: func(value MMEConfigurationUpdateIEValueProtocolErrorIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return codec.encode(MMEConfigurationUpdateIEContainer(value), fresh, budget)
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
	return S1SetupRequestIEValueProtocolErrorIEContainerListValueCodec{path: "S1SetupRequestIEValueProtocolErrorIEContainerList", decode: func(data []byte, options aper.DecodeState) (S1SetupRequestIEValueProtocolErrorIEContainerList, error) {
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
	return S1SetupResponseIEValueProtocolErrorIEContainerListValueCodec{path: "S1SetupResponseIEValueProtocolErrorIEContainerList", decode: func(data []byte, options aper.DecodeState) (S1SetupResponseIEValueProtocolErrorIEContainerList, error) {
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
	return ENBConfigurationUpdateIEValueProtocolIEContainerListValueCodec{path: "ENBConfigurationUpdateIEValueProtocolIEContainerList", decode: func(data []byte, options aper.DecodeState) (ENBConfigurationUpdateIEValueProtocolIEContainerList, error) {
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
	if codec.decode == nil {
		return MMEConfigurationUpdateIEValueProtocolIEContainerListValueCodec{}
	}
	size := aper.SizeConstraint{Lower: (bounds).Lower, Upper: (bounds).Upper, HasLower: true, HasUpper: true}
	return MMEConfigurationUpdateIEValueProtocolIEContainerListValueCodec{path: "MMEConfigurationUpdateIEValueProtocolIEContainerList", decode: func(data []byte, options aper.DecodeState) (MMEConfigurationUpdateIEValueProtocolIEContainerList, error) {
		bb := aper.NewCompleteDecodeBuffer(data, options)
		if err := bb.SetDecodeOptionsAligned(options); err != nil {
			return nil, err
		}
		var fields MMEConfigurationUpdateIEValueProtocolIEContainerList
		_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
			for i := int64(0); i < length; i++ {
				var field MMEConfigurationUpdateIEField
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
			return nil, runtime.WrapDecodePath(err, "MMEConfigurationUpdateIEValueProtocolIEContainerList")
		}
		if _, err := aper.CaptureFinalBits(bb, "MMEConfigurationUpdateIEValueProtocolIEContainerList"); err != nil {
			return nil, runtime.WrapDecodePath(err, "MMEConfigurationUpdateIEValueProtocolIEContainerList")
		}
		return fields, nil
	}, encode: func(value MMEConfigurationUpdateIEValueProtocolIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return codec.encode(MMEConfigurationUpdateIEContainer(value), fresh, budget)
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
	return S1SetupRequestIEValueProtocolIEContainerListValueCodec{path: "S1SetupRequestIEValueProtocolIEContainerList", decode: func(data []byte, options aper.DecodeState) (S1SetupRequestIEValueProtocolIEContainerList, error) {
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
	return S1SetupResponseIEValueProtocolIEContainerListValueCodec{path: "S1SetupResponseIEValueProtocolIEContainerList", decode: func(data []byte, options aper.DecodeState) (S1SetupResponseIEValueProtocolIEContainerList, error) {
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
	s03.BridgeCompareS1APProtocolIEID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = v.Value.compareSemantics(*s)
	s.End(f, v.replay, v.withoutReplay)
}

// mMEConfigurationUpdateIEValueProtocolOpenValue is the concrete protocolOpenValue[MMEConfigurationUpdateIEValue].
type MMEConfigurationUpdateIEValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) MMEConfigurationUpdateIEValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (MMEConfigurationUpdateIEValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

func BridgeMMEConfigurationUpdateIEValueCaptureS1APProtocolIEField(v *MMEConfigurationUpdateIEField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolIEID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.Value = v.Value.captureSemantics(*s)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeMMEConfigurationUpdateIEValueCompareS1APProtocolIEField(v *MMEConfigurationUpdateIEField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s03.BridgeCompareS1APProtocolIEID(&v.Id, s)
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
	s03.BridgeCompareS1APProtocolIEID(&v.Id, s)
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
	s03.BridgeCompareS1APProtocolIEID(&v.Id, s)
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
	decode  func([]byte, aper.DecodeState) (MMEConfigurationUpdateIEField, error)
	encode  func(MMEConfigurationUpdateIEField, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(MMEConfigurationUpdateIEField, aper.DecodeState) (MMEConfigurationUpdateIEField, aper.Snapshot)
	compare func(MMEConfigurationUpdateIEField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c MMEConfigurationUpdateIEFieldValueCodec) New(value MMEConfigurationUpdateIEField) (MMEConfigurationUpdateIEFieldAPERValue, error) {
	if c.encode == nil {
		return MMEConfigurationUpdateIEFieldAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return MMEConfigurationUpdateIEFieldAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return MMEConfigurationUpdateIEFieldAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return MMEConfigurationUpdateIEFieldAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c MMEConfigurationUpdateIEFieldValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (MMEConfigurationUpdateIEFieldAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return MMEConfigurationUpdateIEFieldAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return MMEConfigurationUpdateIEFieldAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return MMEConfigurationUpdateIEFieldAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return MMEConfigurationUpdateIEFieldAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c MMEConfigurationUpdateIEFieldValueCodec) EncodeAPER(value MMEConfigurationUpdateIEFieldAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c MMEConfigurationUpdateIEFieldValueCodec) encodeBudgetValue(value MMEConfigurationUpdateIEField, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c MMEConfigurationUpdateIEFieldValueCodec) encodeChanged(value MMEConfigurationUpdateIEField, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
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

// MMEConfigurationUpdateIEContainerValueCodec is the concrete ValueCodec[MMEConfigurationUpdateIEContainer].
type MMEConfigurationUpdateIEContainerValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (MMEConfigurationUpdateIEContainer, error)
	encode  func(MMEConfigurationUpdateIEContainer, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(MMEConfigurationUpdateIEContainer, aper.DecodeState) (MMEConfigurationUpdateIEContainer, aper.Snapshot)
	compare func(MMEConfigurationUpdateIEContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c MMEConfigurationUpdateIEContainerValueCodec) New(value MMEConfigurationUpdateIEContainer) (MMEConfigurationUpdateIEContainerAPERValue, error) {
	if c.encode == nil {
		return MMEConfigurationUpdateIEContainerAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return MMEConfigurationUpdateIEContainerAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return MMEConfigurationUpdateIEContainerAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return MMEConfigurationUpdateIEContainerAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c MMEConfigurationUpdateIEContainerValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (MMEConfigurationUpdateIEContainerAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return MMEConfigurationUpdateIEContainerAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return MMEConfigurationUpdateIEContainerAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return MMEConfigurationUpdateIEContainerAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return MMEConfigurationUpdateIEContainerAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c MMEConfigurationUpdateIEContainerValueCodec) EncodeAPER(value MMEConfigurationUpdateIEContainerAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c MMEConfigurationUpdateIEContainerValueCodec) encodeBudgetValue(value MMEConfigurationUpdateIEContainer, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c MMEConfigurationUpdateIEContainerValueCodec) encodeChanged(value MMEConfigurationUpdateIEContainer, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
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
type MMEConfigurationUpdateIEValueProtocolIESingleContainer = MMEConfigurationUpdateIEField

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

// MMEConfigurationUpdateIEFieldAPERValue is the concrete APERValue[MMEConfigurationUpdateIEField].
type MMEConfigurationUpdateIEFieldAPERValue struct {
	context       s00.BridgeCodecContext
	Value         MMEConfigurationUpdateIEField
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v MMEConfigurationUpdateIEFieldAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v MMEConfigurationUpdateIEFieldAPERValue) WithoutReplay() MMEConfigurationUpdateIEFieldAPERValue {
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

// MMEConfigurationUpdateIEContainerAPERValue is the concrete APERValue[MMEConfigurationUpdateIEContainer].
type MMEConfigurationUpdateIEContainerAPERValue struct {
	context       s00.BridgeCodecContext
	Value         MMEConfigurationUpdateIEContainer
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v MMEConfigurationUpdateIEContainerAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v MMEConfigurationUpdateIEContainerAPERValue) WithoutReplay() MMEConfigurationUpdateIEContainerAPERValue {
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
					s40.BridgeCaptureS1APSupportedTAs(v.rowSupportedTAs, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(128):
			{
				f := s.Begin()
				s.Bool(v.rowCSGIdList == nil)
				if v.rowCSGIdList != nil {
					s25.BridgeCaptureS1APCSGIdList(v.rowCSGIdList, s)
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
					s40.BridgeCaptureS1APConnectedengNBList(v.rowConnectedengNBToAddList, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(293):
			{
				f := s.Begin()
				s.Bool(v.rowConnectedengNBToRemoveList == nil)
				if v.rowConnectedengNBToRemoveList != nil {
					s40.BridgeCaptureS1APConnectedengNBList(v.rowConnectedengNBToRemoveList, s)
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
	s03.BridgeCompareS1APProtocolIEID(&v.id, s)
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
					s40.BridgeCompareS1APSupportedTAs(v.rowSupportedTAs, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(128):
			{
				f := s.Begin()
				s.Bool(v.rowCSGIdList == nil)
				if v.rowCSGIdList != nil {
					s25.BridgeCompareS1APCSGIdList(v.rowCSGIdList, s)
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
					s40.BridgeCompareS1APConnectedengNBList(v.rowConnectedengNBToAddList, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(293):
			{
				f := s.Begin()
				s.Bool(v.rowConnectedengNBToRemoveList == nil)
				if v.rowConnectedengNBToRemoveList != nil {
					s40.BridgeCompareS1APConnectedengNBList(v.rowConnectedengNBToRemoveList, s)
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
func BridgeCaptureS1APMMEConfigurationUpdateIEValue(v *MMEConfigurationUpdateIEValue, s *aper.SemanticCapture) {
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
					s39.BridgeCaptureS1APServedGUMMEIs(v.rowServedGUMMEIs, s)
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
		case s00.ProtocolIEID(247):
			{
				f := s.Begin()
				s.Bool(v.rowServedDCNs == nil)
				if v.rowServedDCNs != nil {
					s39.BridgeCaptureS1APServedDCNs(v.rowServedDCNs, s)
				}
				s.End(f, nil, false)
			}
		}
	}
	s.End(f, &v.replay, false)
	s.CheckReceived(v.replay, v.received)
}
func (v MMEConfigurationUpdateIEValue) captureSemantics(s aper.SemanticCapture) MMEConfigurationUpdateIEValue {
	BridgeCaptureS1APMMEConfigurationUpdateIEValue(&v, &s)
	return v
}
func BridgeCompareS1APMMEConfigurationUpdateIEValue(v *MMEConfigurationUpdateIEValue, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s03.BridgeCompareS1APProtocolIEID(&v.id, s)
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
					s39.BridgeCompareS1APServedGUMMEIs(v.rowServedGUMMEIs, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(87):
			{
				f := s.Begin()
				s.Bool(v.rowRelativeMMECapacity == nil)
				if v.rowRelativeMMECapacity != nil {
					s08.BridgeCompareS1APRelativeMMECapacity(v.rowRelativeMMECapacity, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(247):
			{
				f := s.Begin()
				s.Bool(v.rowServedDCNs == nil)
				if v.rowServedDCNs != nil {
					s39.BridgeCompareS1APServedDCNs(v.rowServedDCNs, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		}
	}
	s.End(f, v.replay, false)
	s.CheckReceived(v.replay, v.received)
}
func (v MMEConfigurationUpdateIEValue) compareSemantics(s aper.SemanticComparison) aper.SemanticComparison {
	BridgeCompareS1APMMEConfigurationUpdateIEValue(&v, &s)
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
					s21.BridgeCaptureS1APGlobalENBID(v.rowGlobalENBID, s)
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
					s40.BridgeCaptureS1APSupportedTAs(v.rowSupportedTAs, s)
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
					s25.BridgeCaptureS1APCSGIdList(v.rowCSGIdList, s)
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
					s40.BridgeCaptureS1APConnectedengNBList(v.rowConnectedengNBList, s)
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
	s03.BridgeCompareS1APProtocolIEID(&v.id, s)
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
					s21.BridgeCompareS1APGlobalENBID(v.rowGlobalENBID, s)
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
					s40.BridgeCompareS1APSupportedTAs(v.rowSupportedTAs, s)
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
					s25.BridgeCompareS1APCSGIdList(v.rowCSGIdList, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(228):
			{
				f := s.Begin()
				s.Bool(v.rowUERetentionInformation == nil)
				if v.rowUERetentionInformation != nil {
					s08.BridgeCompareS1APUERetentionInformation(v.rowUERetentionInformation, s)
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
					s40.BridgeCompareS1APConnectedengNBList(v.rowConnectedengNBList, s)
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
					s39.BridgeCaptureS1APServedGUMMEIs(v.rowServedGUMMEIs, s)
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
					s26.BridgeCaptureS1APCriticalityDiagnostics(v.rowCriticalityDiagnostics, s)
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
					s39.BridgeCaptureS1APServedDCNs(v.rowServedDCNs, s)
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
	s03.BridgeCompareS1APProtocolIEID(&v.id, s)
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
					s39.BridgeCompareS1APServedGUMMEIs(v.rowServedGUMMEIs, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(87):
			{
				f := s.Begin()
				s.Bool(v.rowRelativeMMECapacity == nil)
				if v.rowRelativeMMECapacity != nil {
					s08.BridgeCompareS1APRelativeMMECapacity(v.rowRelativeMMECapacity, s)
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
					s26.BridgeCompareS1APCriticalityDiagnostics(v.rowCriticalityDiagnostics, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(228):
			{
				f := s.Begin()
				s.Bool(v.rowUERetentionInformation == nil)
				if v.rowUERetentionInformation != nil {
					s08.BridgeCompareS1APUERetentionInformation(v.rowUERetentionInformation, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(247):
			{
				f := s.Begin()
				s.Bool(v.rowServedDCNs == nil)
				if v.rowServedDCNs != nil {
					s39.BridgeCompareS1APServedDCNs(v.rowServedDCNs, s)
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
	s08.BridgeCompareS1APServedGroupIDs(&v.Value, s)
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
	s08.BridgeCompareS1APServedMMECs(&v.Value, s)
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
	s08.BridgeCompareS1APServedPLMNs(&v.Value, s)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APSupportedTAsComplete(v *SupportedTAsComplete, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s40.BridgeCaptureS1APSupportedTAs(&v.Value, s)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APSupportedTAsComplete(v *SupportedTAsComplete, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s40.BridgeCompareS1APSupportedTAs(&v.Value, s)
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
	s08.BridgeCompareS1APTACListInLTENTN(&v.Value, s)
	s.End(f, v.replay, v.withoutReplay)
}

// MarshalAPERServedGUMMEIs encodes a ServedGUMMEIs list to APER.
func BridgeMarshalAPERServedGUMMEIs(list s53.ServedGUMMEIsComplete) ([]byte, error) {
	return s53.BridgeServedGUMMEIsCompleteMethodMarshalAPERLegacy(&list)
}

// UnmarshalAPERServedGUMMEIs decodes a ServedGUMMEIs list from APER.
func BridgeUnmarshalAPERServedGUMMEIs(data []byte) (s53.ServedGUMMEIsComplete, error) {
	var value s53.ServedGUMMEIsComplete
	if err := s53.BridgeServedGUMMEIsCompleteMethodUnmarshalAPERLegacy(&value, data); err != nil {
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
	if err := s16.BridgeMarshalAPERServedGroupIDsTo(v.Value, bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.perPadding)
}

// UnmarshalAPER decodes ServedGroupIDs from APER format.
func (v *ServedGroupIDsComplete) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}
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
		// arithmetic pattern APER_FRAGMENT_LOOP_5: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1190
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
	if err := s16.BridgeMarshalAPERServedMMECsTo(v.Value, bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.perPadding)
}

// UnmarshalAPER decodes ServedMMECs from APER format.
func (v *ServedMMECsComplete) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}
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
		// arithmetic pattern APER_FRAGMENT_LOOP_5: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1190
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
	if err := s16.BridgeMarshalAPERServedPLMNsTo(v.Value, bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.perPadding)
}

// UnmarshalAPER decodes ServedPLMNs from APER format.
func (v *ServedPLMNsComplete) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}
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
		// arithmetic pattern APER_FRAGMENT_LOOP_5: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1190
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
	Value            s40.SupportedTAs
	perPadding       aper.CompletePadding `json:"-"`
}

func (v *SupportedTAsComplete) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := s40.BridgeMarshalAPERSupportedTAsTo(v.Value, bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.perPadding)
}

// UnmarshalAPER decodes SupportedTAs from APER format.
func (v *SupportedTAsComplete) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}
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
func BridgeUnmarshalAPERSupportedTAsFrom(bb *aper.BitBuffer) (s40.SupportedTAs, error) {
	if err := bb.EnterDecodeValue(); err != nil {
		return nil, err
	}
	defer bb.LeaveDecodeValue()
	var v s40.BridgeAsn1cAPERSupportedTAsListValue
	if err := BridgeUnmarshalAPERSupportedTAsInto(&v, bb); err != nil {
		return nil, err
	}
	return v.Value, nil
}
func BridgeUnmarshalAPERSupportedTAsInto(v *s40.BridgeAsn1cAPERSupportedTAsListValue, bb *aper.BitBuffer) error {
	toleranceMark_value := bb.EnterComponent("Value")
	v.Value = make(s40.SupportedTAs, 0)
	_, errCollection_value := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 256, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1127
		if fragmentOffset_value < 0 || fragmentLength_value < 0 || fragmentLength_value > int64(^uint(0)>>1) || fragmentOffset_value > int64(^uint(0)>>1)-fragmentLength_value {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_value; i++ {
			var elem s40.SupportedTAsItem
			elementMark := bb.EnterIndex(fragmentOffset_value + i)
			if err := s40.BridgeSupportedTAsItemMethodUnmarshalAPERFrom(&elem, bb); err != nil {
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
	if err := s16.BridgeMarshalAPERTACListInLTENTNTo(v.Value, bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.perPadding)
}

// UnmarshalAPER decodes TACListInLTENTN from APER format.
func (v *TACListInLTENTNComplete) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}
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
		// arithmetic pattern APER_FRAGMENT_LOOP_5: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1190
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

// UnmarshalAPERTAIBroadcastFrom decodes a TAIBroadcast list from bb.
func BridgeUnmarshalAPERTAIBroadcastFrom(bb *aper.BitBuffer) (s41.TAIBroadcast, error) {
	if err := bb.EnterDecodeValue(); err != nil {
		return nil, err
	}
	defer bb.LeaveDecodeValue()
	var v s41.BridgeAsn1cAPERTAIBroadcastListValue
	if err := BridgeUnmarshalAPERTAIBroadcastInto(&v, bb); err != nil {
		return nil, err
	}
	return v.Value, nil
}
func BridgeUnmarshalAPERTAIBroadcastInto(v *s41.BridgeAsn1cAPERTAIBroadcastListValue, bb *aper.BitBuffer) error {
	toleranceMark_value := bb.EnterComponent("Value")
	v.Value = make(s41.TAIBroadcast, 0)
	_, errCollection_value := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1127
		if fragmentOffset_value < 0 || fragmentLength_value < 0 || fragmentLength_value > int64(^uint(0)>>1) || fragmentOffset_value > int64(^uint(0)>>1)-fragmentLength_value {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_value; i++ {
			var elem s41.TAIBroadcastItem
			elementMark := bb.EnterIndex(fragmentOffset_value + i)
			if err := s41.BridgeTAIBroadcastItemMethodUnmarshalAPERFrom(&elem, bb); err != nil {
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
		return s16.BridgeReceivedFormAt(v.received, v.receivedBytes, "ServedGroupIDsComplete", v.receivedLocation, v.perPadding)
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
		return s16.BridgeReceivedFormAt(v.received, v.receivedBytes, "ServedMMECsComplete", v.receivedLocation, v.perPadding)
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
		return s16.BridgeReceivedFormAt(v.received, v.receivedBytes, "ServedPLMNsComplete", v.receivedLocation, v.perPadding)
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
		return s16.BridgeReceivedFormAt(v.received, v.receivedBytes, "SupportedTAsComplete", v.receivedLocation, v.perPadding)
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
		return s16.BridgeReceivedFormAt(v.received, v.receivedBytes, "TACListInLTENTNComplete", v.receivedLocation, v.perPadding)
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
	if err := s16.BridgeMarshalAPERServedGroupIDsTo(v.Value, bb, fresh); err != nil {
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
	if err := s16.BridgeMarshalAPERServedMMECsTo(v.Value, bb, fresh); err != nil {
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
	if err := s16.BridgeMarshalAPERServedPLMNsTo(v.Value, bb, fresh); err != nil {
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
	if err := s40.BridgeMarshalAPERSupportedTAsTo(v.Value, bb, fresh); err != nil {
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
	if err := s16.BridgeMarshalAPERTACListInLTENTNTo(v.Value, bb, fresh); err != nil {
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

// MarshalAPERServedGUMMEIs encodes a complete named list.
func MarshalAPERServedGUMMEIs(v s53.ServedGUMMEIsComplete, options ...aper.EncodeOption) ([]byte, error) {
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

// UnmarshalAPERServedGUMMEIs decodes a complete named list.
func UnmarshalAPERServedGUMMEIs(data []byte, options ...aper.DecodeOption) (s53.ServedGUMMEIsComplete, aper.DecodeReport, error) {
	var v s53.ServedGUMMEIsComplete
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
	ProtocolIEs      MMEConfigurationUpdateIEContainer `asn1:"tag:0,context,implicit"`
	protocolIEsIndef bool                              `asn1:"-" json:"-"`
	extCount         int64                             `asn1:"-" json:"-"`
	extPresent       []bool                            `asn1:"-" json:"-"`
	extData          [][]byte                          `asn1:"-" json:"-"`
	perPadding       aper.FinalPadding                 `asn1:"-" json:"-"`
	perExtPadding    []aper.CompletePadding            `asn1:"-" json:"-"`
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
		extensionCount, _ = s16.BridgePreferredSequenceTail(v.extPresent, extensionEncodingData)
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()

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
		// arithmetic pattern APER_EXT_BITMAP_LENGTH: 0 <= extCount < 16383; gen/codegen_aper.go:436
		if extCount < 0 || extCount >= 16383 {
			return fmt.Errorf("%w: extension bitmap index %d", aper.ErrUnsupportedFragmentedNormallySmallLength, extCount)
		}
		if err := aper.EncodeNormallySmallLengthAligned(bb, extCount+1); err != nil {
			return err
		}
		// arithmetic pattern APER_EXT_VALUE_1: 0 <= extCount < max int; gen/codegen_aper.go:440
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return fmt.Errorf("extension count out of range")
		}
		for i := int64(0); i <= extCount; i++ {
			p := (i < int64(len(v.extPresent)) && v.extPresent[i]) || (i < int64(len(extensionEncodingData)) && extensionEncodingData[i] != nil)
			if err := aper.EncodeBoolean(bb, p); err != nil {
				return err
			}
		}
		// arithmetic pattern APER_EXT_VALUE_2: 0 <= extCount < max int; gen/codegen_aper.go:447
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
	return nil
}

// UnmarshalAPER decodes S1SetupRequest from APER format.
func (v *S1SetupRequest) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}
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
	v.perPadding = padding
	return nil
}
func (v *S1SetupRequest) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = S1SetupRequest{}
	var extAdditions aper.ExtensionAdditions
	hasExtensions, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	toleranceMark_protocolies := bb.EnterComponent("ProtocolIEs")
	v.ProtocolIEs = make(S1SetupRequestIEContainer, 0)
	_, errCollection_protocolies := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1127
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
		// arithmetic pattern APER_EXT_COUNT_ALLOC_3: 0 <= extCount < max int; gen/codegen_aper.go:624
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
		// arithmetic pattern APER_EXT_COUNT_LOOP_2: 0 <= extCount < max int; gen/codegen_aper.go:627
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return fmt.Errorf("extension count out of range")
		}
		for i := int64(0); i <= extCount; i++ {
			if extPresent[i] {
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
		extensionCount, _ = s16.BridgePreferredSequenceTail(v.extPresent, extensionEncodingData)
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()

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
		// arithmetic pattern APER_EXT_BITMAP_LENGTH: 0 <= extCount < 16383; gen/codegen_aper.go:436
		if extCount < 0 || extCount >= 16383 {
			return fmt.Errorf("%w: extension bitmap index %d", aper.ErrUnsupportedFragmentedNormallySmallLength, extCount)
		}
		if err := aper.EncodeNormallySmallLengthAligned(bb, extCount+1); err != nil {
			return err
		}
		// arithmetic pattern APER_EXT_VALUE_1: 0 <= extCount < max int; gen/codegen_aper.go:440
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return fmt.Errorf("extension count out of range")
		}
		for i := int64(0); i <= extCount; i++ {
			p := (i < int64(len(v.extPresent)) && v.extPresent[i]) || (i < int64(len(extensionEncodingData)) && extensionEncodingData[i] != nil)
			if err := aper.EncodeBoolean(bb, p); err != nil {
				return err
			}
		}
		// arithmetic pattern APER_EXT_VALUE_2: 0 <= extCount < max int; gen/codegen_aper.go:447
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
	return nil
}

// UnmarshalAPER decodes S1SetupResponse from APER format.
func (v *S1SetupResponse) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}
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
	v.perPadding = padding
	return nil
}
func (v *S1SetupResponse) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = S1SetupResponse{}
	var extAdditions aper.ExtensionAdditions
	hasExtensions, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	toleranceMark_protocolies := bb.EnterComponent("ProtocolIEs")
	v.ProtocolIEs = make(S1SetupResponseIEContainer, 0)
	_, errCollection_protocolies := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1127
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
		// arithmetic pattern APER_EXT_COUNT_ALLOC_3: 0 <= extCount < max int; gen/codegen_aper.go:624
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
		// arithmetic pattern APER_EXT_COUNT_LOOP_2: 0 <= extCount < max int; gen/codegen_aper.go:627
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return fmt.Errorf("extension count out of range")
		}
		for i := int64(0); i <= extCount; i++ {
			if extPresent[i] {
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
		extensionCount, _ = s16.BridgePreferredSequenceTail(v.extPresent, extensionEncodingData)
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()

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
		// arithmetic pattern APER_EXT_BITMAP_LENGTH: 0 <= extCount < 16383; gen/codegen_aper.go:436
		if extCount < 0 || extCount >= 16383 {
			return fmt.Errorf("%w: extension bitmap index %d", aper.ErrUnsupportedFragmentedNormallySmallLength, extCount)
		}
		if err := aper.EncodeNormallySmallLengthAligned(bb, extCount+1); err != nil {
			return err
		}
		// arithmetic pattern APER_EXT_VALUE_1: 0 <= extCount < max int; gen/codegen_aper.go:440
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return fmt.Errorf("extension count out of range")
		}
		for i := int64(0); i <= extCount; i++ {
			p := (i < int64(len(v.extPresent)) && v.extPresent[i]) || (i < int64(len(extensionEncodingData)) && extensionEncodingData[i] != nil)
			if err := aper.EncodeBoolean(bb, p); err != nil {
				return err
			}
		}
		// arithmetic pattern APER_EXT_VALUE_2: 0 <= extCount < max int; gen/codegen_aper.go:447
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
	return nil
}

// UnmarshalAPER decodes ENBConfigurationUpdate from APER format.
func (v *ENBConfigurationUpdate) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}
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
	v.perPadding = padding
	return nil
}
func (v *ENBConfigurationUpdate) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = ENBConfigurationUpdate{}
	var extAdditions aper.ExtensionAdditions
	hasExtensions, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	toleranceMark_protocolies := bb.EnterComponent("ProtocolIEs")
	v.ProtocolIEs = make(ENBConfigurationUpdateIEContainer, 0)
	_, errCollection_protocolies := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1127
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
		// arithmetic pattern APER_EXT_COUNT_ALLOC_3: 0 <= extCount < max int; gen/codegen_aper.go:624
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
		// arithmetic pattern APER_EXT_COUNT_LOOP_2: 0 <= extCount < max int; gen/codegen_aper.go:627
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return fmt.Errorf("extension count out of range")
		}
		for i := int64(0); i <= extCount; i++ {
			if extPresent[i] {
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
		extensionCount, _ = s16.BridgePreferredSequenceTail(v.extPresent, extensionEncodingData)
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()

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
		// arithmetic pattern APER_EXT_BITMAP_LENGTH: 0 <= extCount < 16383; gen/codegen_aper.go:436
		if extCount < 0 || extCount >= 16383 {
			return fmt.Errorf("%w: extension bitmap index %d", aper.ErrUnsupportedFragmentedNormallySmallLength, extCount)
		}
		if err := aper.EncodeNormallySmallLengthAligned(bb, extCount+1); err != nil {
			return err
		}
		// arithmetic pattern APER_EXT_VALUE_1: 0 <= extCount < max int; gen/codegen_aper.go:440
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return fmt.Errorf("extension count out of range")
		}
		for i := int64(0); i <= extCount; i++ {
			p := (i < int64(len(v.extPresent)) && v.extPresent[i]) || (i < int64(len(extensionEncodingData)) && extensionEncodingData[i] != nil)
			if err := aper.EncodeBoolean(bb, p); err != nil {
				return err
			}
		}
		// arithmetic pattern APER_EXT_VALUE_2: 0 <= extCount < max int; gen/codegen_aper.go:447
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
	return nil
}

// UnmarshalAPER decodes MMEConfigurationUpdate from APER format.
func (v *MMEConfigurationUpdate) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}
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
	v.perPadding = padding
	return nil
}
func (v *MMEConfigurationUpdate) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = MMEConfigurationUpdate{}
	var extAdditions aper.ExtensionAdditions
	hasExtensions, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	toleranceMark_protocolies := bb.EnterComponent("ProtocolIEs")
	v.ProtocolIEs = make(MMEConfigurationUpdateIEContainer, 0)
	_, errCollection_protocolies := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1127
		if fragmentOffset_protocolies < 0 || fragmentLength_protocolies < 0 || fragmentLength_protocolies > int64(^uint(0)>>1) || fragmentOffset_protocolies > int64(^uint(0)>>1)-fragmentLength_protocolies {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_protocolies; i++ {
			var elem MMEConfigurationUpdateIEField
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
		// arithmetic pattern APER_EXT_COUNT_ALLOC_3: 0 <= extCount < max int; gen/codegen_aper.go:624
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
		// arithmetic pattern APER_EXT_COUNT_LOOP_2: 0 <= extCount < max int; gen/codegen_aper.go:627
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return fmt.Errorf("extension count out of range")
		}
		for i := int64(0); i <= extCount; i++ {
			if extPresent[i] {
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
		return s16.BridgeReceivedFormAt(v.received, v.receivedBytes, "ENBConfigurationUpdate", v.receivedLocation, v.perPadding)
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
		return s16.BridgeReceivedFormAt(v.received, v.receivedBytes, "MMEConfigurationUpdate", v.receivedLocation, v.perPadding)
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
func (v *S1SetupRequest) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s16.BridgeReceivedFormAt(v.received, v.receivedBytes, "S1SetupRequest", v.receivedLocation, v.perPadding)
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
		return s16.BridgeReceivedFormAt(v.received, v.receivedBytes, "S1SetupResponse", v.receivedLocation, v.perPadding)
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
	rowSupportedTAs               *s40.SupportedTAs
	rowCSGIdList                  *s17.CSGIdList
	rowDefaultPagingDRX           *s00.PagingDRX
	rowNBIoTDefaultPagingDRX      *s00.NBIoTDefaultPagingDRX
	rowConnectedengNBToAddList    *s40.ConnectedengNBList
	rowConnectedengNBToRemoveList *s40.ConnectedengNBList
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
func (v *ENBConfigurationUpdateIEValue) AsSupportedTAs() (*s40.SupportedTAs, bool) {
	if v == nil || v.id != s00.ProtocolIEID(64) || v.rowSupportedTAs == nil {
		return nil, false
	}
	return v.rowSupportedTAs, true
}

// AsCSGIdList returns the selected CSGIdList value of ENBConfigurationUpdateIEValue and reports whether that alternative is active.
func (v *ENBConfigurationUpdateIEValue) AsCSGIdList() (*s17.CSGIdList, bool) {
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
func (v *ENBConfigurationUpdateIEValue) AsConnectedengNBToAddList() (*s40.ConnectedengNBList, bool) {
	if v == nil || v.id != s00.ProtocolIEID(292) || v.rowConnectedengNBToAddList == nil {
		return nil, false
	}
	return v.rowConnectedengNBToAddList, true
}

// AsConnectedengNBToRemoveList returns the selected ConnectedengNBToRemoveList value of ENBConfigurationUpdateIEValue and reports whether that alternative is active.
func (v *ENBConfigurationUpdateIEValue) AsConnectedengNBToRemoveList() (*s40.ConnectedengNBList, bool) {
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
		list, err := s48.BridgeUnmarshalAPERCSGIdListFrom(child)
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
		list, err := s48.BridgeUnmarshalAPERConnectedengNBListFrom(child)
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
		list, err := s48.BridgeUnmarshalAPERConnectedengNBListFrom(child)
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
		complete := s48.CSGIdListComplete{Value: *v.rowCSGIdList}
		candidate, err := s48.BridgeCSGIdListCompleteMethodMarshalAPERBudget(&complete, budget, fresh)
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
		complete := s48.ConnectedengNBListComplete{Value: *v.rowConnectedengNBToAddList}
		candidate, err := s48.BridgeConnectedengNBListCompleteMethodMarshalAPERBudget(&complete, budget, fresh)
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
		complete := s48.ConnectedengNBListComplete{Value: *v.rowConnectedengNBToRemoveList}
		candidate, err := s48.BridgeConnectedengNBListCompleteMethodMarshalAPERBudget(&complete, budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	default:
		return nil, fmt.Errorf("%s id %d has no value", "ENBConfigurationUpdateIEValue:", v.id)
	}
}

type MMEConfigurationUpdateIEValue struct {
	id                     s00.ProtocolIEID
	received               aper.WireSpan
	replay                 aper.Snapshot
	opaque                 aper.OpaqueOpenType
	isOpaque               bool
	rowMMEname             *s00.MMEname
	rowServedGUMMEIs       *s39.ServedGUMMEIs
	rowRelativeMMECapacity *s00.RelativeMMECapacity
	rowServedDCNs          *s39.ServedDCNs
}

func (v MMEConfigurationUpdateIEValue) matchesID(id s00.ProtocolIEID, _ ...*aper.DecodeBudget) bool {
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
	case s00.ProtocolIEID(247):
		return v.rowServedDCNs != nil
	}
	return false
}

// Opaque returns the retained opaque open value of MMEConfigurationUpdateIEValue and reports whether the opaque alternative is selected.
func (v *MMEConfigurationUpdateIEValue) Opaque() (aper.OpaqueOpenType, bool) {
	if v == nil || !v.isOpaque {
		return aper.OpaqueOpenType{}, false
	}
	return v.opaque, true
}
func (MMEConfigurationUpdateIEValue) rule() aper.SourceRule {
	return aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "MMEConfigurationUpdateIEs"}}
}
func (MMEConfigurationUpdateIEValue) reason(id s00.ProtocolIEID) aper.OpaqueReason {
	switch id {
	case s00.ProtocolIEID(61):
		return aper.UnknownSelector
	case s00.ProtocolIEID(105):
		return aper.UnknownSelector
	case s00.ProtocolIEID(87):
		return aper.UnknownSelector
	case s00.ProtocolIEID(247):
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

// AsMMEname returns the selected MMEname value of MMEConfigurationUpdateIEValue and reports whether that alternative is active.
func (v *MMEConfigurationUpdateIEValue) AsMMEname() (*s00.MMEname, bool) {
	if v == nil || v.id != s00.ProtocolIEID(61) || v.rowMMEname == nil {
		return nil, false
	}
	return v.rowMMEname, true
}

// AsServedGUMMEIs returns the selected ServedGUMMEIs value of MMEConfigurationUpdateIEValue and reports whether that alternative is active.
func (v *MMEConfigurationUpdateIEValue) AsServedGUMMEIs() (*s39.ServedGUMMEIs, bool) {
	if v == nil || v.id != s00.ProtocolIEID(105) || v.rowServedGUMMEIs == nil {
		return nil, false
	}
	return v.rowServedGUMMEIs, true
}

// AsRelativeMMECapacity returns the selected RelativeMMECapacity value of MMEConfigurationUpdateIEValue and reports whether that alternative is active.
func (v *MMEConfigurationUpdateIEValue) AsRelativeMMECapacity() (*s00.RelativeMMECapacity, bool) {
	if v == nil || v.id != s00.ProtocolIEID(87) || v.rowRelativeMMECapacity == nil {
		return nil, false
	}
	return v.rowRelativeMMECapacity, true
}

// AsServedDCNs returns the selected ServedDCNs value of MMEConfigurationUpdateIEValue and reports whether that alternative is active.
func (v *MMEConfigurationUpdateIEValue) AsServedDCNs() (*s39.ServedDCNs, bool) {
	if v == nil || v.id != s00.ProtocolIEID(247) || v.rowServedDCNs == nil {
		return nil, false
	}
	return v.rowServedDCNs, true
}
func (v MMEConfigurationUpdateIEValue) decode(id s00.ProtocolIEID, raw aper.OpaqueOpenType) (MMEConfigurationUpdateIEValue, error) {
	out := MMEConfigurationUpdateIEValue{id: id}
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
		list, err := s53.BridgeUnmarshalAPERServedGUMMEIsFrom(child)
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
		decoded, err := aper.DecodeIntegerAligned(bb, s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(255), false)
		value := s00.RelativeMMECapacity(decoded)
		if err != nil {
			return out, fmt.Errorf("%s %w", "RelativeMMECapacity:", err)
		}
		if _, err := aper.CompleteOpenTypeValue(bb, value); err != nil {
			return out, err
		}
		out.rowRelativeMMECapacity = &value
		raw.RetainContents(&out.received)
	case s00.ProtocolIEID(247):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		child := scope
		list, err := s53.BridgeUnmarshalAPERServedDCNsFrom(child)
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
	default:
		if err := raw.Observe(aper.UnknownIE); err != nil {
			return out, err
		}
		out.opaque = raw.Detached()
		out.isOpaque = true
	}
	return out, nil
}
func (v MMEConfigurationUpdateIEValue) encode() ([]byte, error) { return v.encodeFresh(false, nil) }
func (v MMEConfigurationUpdateIEValue) encodeFresh(fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
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
			return nil, fmt.Errorf("%s missing value", "MMEConfigurationUpdateIEs.id-MMEname:")
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
			return nil, fmt.Errorf("%s missing value", "MMEConfigurationUpdateIEs.id-ServedGUMMEIs:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		complete := s53.ServedGUMMEIsComplete{Value: *v.rowServedGUMMEIs}
		candidate, err := s53.BridgeServedGUMMEIsCompleteMethodMarshalAPERBudget(&complete, budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	case s00.ProtocolIEID(87):
		if v.rowRelativeMMECapacity == nil {
			return nil, fmt.Errorf("%s missing value", "MMEConfigurationUpdateIEs.id-RelativeMMECapacity:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		encodeBB := aper.NewBudgetBuffer(budget)
		if err := aper.EncodeIntegerAligned(encodeBB, int64(*v.rowRelativeMMECapacity), s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(255), false); err != nil {
			return nil, err
		}
		candidate := encodeBB.CompleteBytes()
		return candidate, nil
	case s00.ProtocolIEID(247):
		if v.rowServedDCNs == nil {
			return nil, fmt.Errorf("%s missing value", "MMEConfigurationUpdateIEs.id-ServedDCNs:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		complete := s53.ServedDCNsComplete{Value: *v.rowServedDCNs}
		candidate, err := s53.BridgeServedDCNsCompleteMethodMarshalAPERBudget(&complete, budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	default:
		return nil, fmt.Errorf("%s id %d has no value", "MMEConfigurationUpdateIEValue:", v.id)
	}
}

type S1SetupRequestIEValue struct {
	id                        s00.ProtocolIEID
	received                  aper.WireSpan
	replay                    aper.Snapshot
	opaque                    aper.OpaqueOpenType
	isOpaque                  bool
	rowGlobalENBID            *s21.GlobalENBID
	rowENBname                *s00.ENBname
	rowSupportedTAs           *s40.SupportedTAs
	rowDefaultPagingDRX       *s00.PagingDRX
	rowCSGIdList              *s17.CSGIdList
	rowUERetentionInformation *s00.UERetentionInformation
	rowNBIoTDefaultPagingDRX  *s00.NBIoTDefaultPagingDRX
	rowConnectedengNBList     *s40.ConnectedengNBList
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
func (v *S1SetupRequestIEValue) AsGlobalENBID() (*s21.GlobalENBID, bool) {
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
func (v *S1SetupRequestIEValue) AsSupportedTAs() (*s40.SupportedTAs, bool) {
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
func (v *S1SetupRequestIEValue) AsCSGIdList() (*s17.CSGIdList, bool) {
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
func (v *S1SetupRequestIEValue) AsConnectedengNBList() (*s40.ConnectedengNBList, bool) {
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
		var value s21.GlobalENBID
		child := scope
		if err := s21.BridgeGlobalENBIDMethodUnmarshalAPERFrom(&value, child); err != nil {
			return out, fmt.Errorf("%s %w", "GlobalENBID:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "GlobalENBID")
		if err != nil {
			return out, err
		}
		*s21.BridgeGlobalENBIDFieldPerPadding(&value) = padding
		*s21.BridgeGlobalENBIDFieldReceived(&value) = true
		raw.RetainContents(s21.BridgeGlobalENBIDFieldReceivedBytes(&value))
		*s21.BridgeGlobalENBIDFieldReceivedLocation(&value) = raw.ContentLocation()
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
		list, err := s48.BridgeUnmarshalAPERCSGIdListFrom(child)
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
		list, err := s48.BridgeUnmarshalAPERConnectedengNBListFrom(child)
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
		candidate, err := s21.BridgeGlobalENBIDMethodMarshalAPERBudget(v.rowGlobalENBID, budget, fresh)
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
		complete := s48.CSGIdListComplete{Value: *v.rowCSGIdList}
		candidate, err := s48.BridgeCSGIdListCompleteMethodMarshalAPERBudget(&complete, budget, fresh)
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
		complete := s48.ConnectedengNBListComplete{Value: *v.rowConnectedengNBList}
		candidate, err := s48.BridgeConnectedengNBListCompleteMethodMarshalAPERBudget(&complete, budget, fresh)
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
	rowServedGUMMEIs            *s39.ServedGUMMEIs
	rowRelativeMMECapacity      *s00.RelativeMMECapacity
	rowMMERelaySupportIndicator *s00.MMERelaySupportIndicator
	rowCriticalityDiagnostics   *s26.CriticalityDiagnostics
	rowUERetentionInformation   *s00.UERetentionInformation
	rowServedDCNs               *s39.ServedDCNs
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
func (v *S1SetupResponseIEValue) AsServedGUMMEIs() (*s39.ServedGUMMEIs, bool) {
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
func (v *S1SetupResponseIEValue) AsCriticalityDiagnostics() (*s26.CriticalityDiagnostics, bool) {
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
func (v *S1SetupResponseIEValue) AsServedDCNs() (*s39.ServedDCNs, bool) {
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
		list, err := s53.BridgeUnmarshalAPERServedGUMMEIsFrom(child)
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
		decoded, err := aper.DecodeIntegerAligned(bb, s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(255), false)
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
		var value s26.CriticalityDiagnostics
		child := scope
		if err := s26.BridgeCriticalityDiagnosticsMethodUnmarshalAPERFrom(&value, child); err != nil {
			return out, fmt.Errorf("%s %w", "CriticalityDiagnostics:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "CriticalityDiagnostics")
		if err != nil {
			return out, err
		}
		*s26.BridgeCriticalityDiagnosticsFieldPerPadding(&value) = padding
		*s26.BridgeCriticalityDiagnosticsFieldReceived(&value) = true
		raw.RetainContents(s26.BridgeCriticalityDiagnosticsFieldReceivedBytes(&value))
		*s26.BridgeCriticalityDiagnosticsFieldReceivedLocation(&value) = raw.ContentLocation()
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
		list, err := s53.BridgeUnmarshalAPERServedDCNsFrom(child)
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
		complete := s53.ServedGUMMEIsComplete{Value: *v.rowServedGUMMEIs}
		candidate, err := s53.BridgeServedGUMMEIsCompleteMethodMarshalAPERBudget(&complete, budget, fresh)
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
		if err := aper.EncodeIntegerAligned(encodeBB, int64(*v.rowRelativeMMECapacity), s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(255), false); err != nil {
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
		candidate, err := s26.BridgeCriticalityDiagnosticsMethodMarshalAPERBudget(v.rowCriticalityDiagnostics, budget, fresh)
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
		complete := s53.ServedDCNsComplete{Value: *v.rowServedDCNs}
		candidate, err := s53.BridgeServedDCNsCompleteMethodMarshalAPERBudget(&complete, budget, fresh)
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
	return ENBConfigurationUpdateSupportedTAsIEBinding{info: t.infoSupportedTAs(), codec: func() s40.SupportedTAsValueCodec {
		sealed := s40.SupportedTAsValueCodec{}
		*s40.BridgeSupportedTAsValueCodecFieldPath(&sealed) = "SupportedTAs"
		*s40.BridgeSupportedTAsValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s40.SupportedTAs, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s40.SupportedTAs
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("SupportedTAs")
			var zero ENBConfigurationUpdateIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(64), raw)
			if err != nil {
				var empty s40.SupportedTAs
				return empty, runtime.WrapDecodePath(err, "SupportedTAs")
			}
			value, ok := decoded.AsSupportedTAs()
			if !ok {
				var empty s40.SupportedTAs
				return empty, fmt.Errorf("binding ENBConfigurationUpdateIEs.id-SupportedTAs: no selected value")
			}
			return *value, nil
		}
		*s40.BridgeSupportedTAsValueCodecFieldEncode(&sealed) = func(value s40.SupportedTAs, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (ENBConfigurationUpdateIEValue{id: s00.ProtocolIEID(64), rowSupportedTAs: &value}).encodeFresh(fresh, budget)
		}
		*s40.BridgeSupportedTAsValueCodecFieldCapture(&sealed) = func(v s40.SupportedTAs, options aper.DecodeState) (s40.SupportedTAs, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s40.BridgeCaptureS1APSupportedTAs(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s40.BridgeSupportedTAsValueCodecFieldCompare(&sealed) = func(v s40.SupportedTAs, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s40.BridgeCompareS1APSupportedTAs(&v, &s)
			s.End(f, root, false)
			return s.Plan(),
				s.
					BudgetValue()
		}
		*s40.BridgeSupportedTAsValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:SupportedTAs"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s40.SupportedTAs) ENBConfigurationUpdateIEValue {
			return ENBConfigurationUpdateIEValue{id: s00.ProtocolIEID(64), rowSupportedTAs: &value}
		}, get: func(value *ENBConfigurationUpdateIEValue) (*s40.SupportedTAs, bool) { return value.AsSupportedTAs() }}
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
	return ENBConfigurationUpdateCSGIdListIEBinding{info: t.infoCSGIdList(), codec: func() s17.CSGIdListValueCodec {
		sealed := s17.CSGIdListValueCodec{}
		*s17.BridgeCSGIdListValueCodecFieldPath(&sealed) = "CSGIdList"
		*s17.BridgeCSGIdListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s17.CSGIdList, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s17.CSGIdList
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("CSGIdList")
			var zero ENBConfigurationUpdateIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(128), raw)
			if err != nil {
				var empty s17.CSGIdList
				return empty, runtime.WrapDecodePath(err, "CSGIdList")
			}
			value, ok := decoded.AsCSGIdList()
			if !ok {
				var empty s17.CSGIdList
				return empty, fmt.Errorf("binding ENBConfigurationUpdateIEs.id-CSG-IdList: no selected value")
			}
			return *value, nil
		}
		*s17.BridgeCSGIdListValueCodecFieldEncode(&sealed) = func(value s17.CSGIdList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (ENBConfigurationUpdateIEValue{id: s00.ProtocolIEID(128), rowCSGIdList: &value}).encodeFresh(fresh, budget)
		}
		*s17.BridgeCSGIdListValueCodecFieldCapture(&sealed) = func(v s17.CSGIdList, options aper.DecodeState) (s17.CSGIdList, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.
				Begin()
			s25.BridgeCaptureS1APCSGIdList(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s17.BridgeCSGIdListValueCodecFieldCompare(&sealed) = func(v s17.CSGIdList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s25.BridgeCompareS1APCSGIdList(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s17.BridgeCSGIdListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:CSGIdList"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s17.CSGIdList) ENBConfigurationUpdateIEValue {
			return ENBConfigurationUpdateIEValue{id: s00.ProtocolIEID(128), rowCSGIdList: &value}
		}, get: func(value *ENBConfigurationUpdateIEValue) (*s17.CSGIdList, bool) { return value.AsCSGIdList() }}
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
	return ENBConfigurationUpdateConnectedengNBListIEBinding{info: t.infoConnectedengNBToAddList(), codec: func() s40.ConnectedengNBListValueCodec {
		sealed := s40.ConnectedengNBListValueCodec{}
		*s40.BridgeConnectedengNBListValueCodecFieldPath(&sealed) = "ConnectedengNBList"
		*s40.BridgeConnectedengNBListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s40.ConnectedengNBList, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s40.ConnectedengNBList
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("ConnectedengNBList")
			var zero ENBConfigurationUpdateIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(292), raw)
			if err != nil {
				var empty s40.ConnectedengNBList
				return empty, runtime.WrapDecodePath(err, "ConnectedengNBList")
			}
			value, ok := decoded.AsConnectedengNBToAddList()
			if !ok {
				var empty s40.ConnectedengNBList
				return empty, fmt.Errorf("binding ENBConfigurationUpdateIEs.id-ConnectedengNBToAddList: no selected value")
			}
			return *value, nil
		}
		*s40.BridgeConnectedengNBListValueCodecFieldEncode(&sealed) = func(value s40.ConnectedengNBList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (ENBConfigurationUpdateIEValue{id: s00.ProtocolIEID(292), rowConnectedengNBToAddList: &value}).encodeFresh(fresh, budget)
		}
		*s40.BridgeConnectedengNBListValueCodecFieldCapture(&sealed) = func(v s40.ConnectedengNBList, options aper.DecodeState) (s40.ConnectedengNBList, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s40.BridgeCaptureS1APConnectedengNBList(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v,

				root
		}
		*s40.BridgeConnectedengNBListValueCodecFieldCompare(&sealed) = func(v s40.ConnectedengNBList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s40.BridgeCompareS1APConnectedengNBList(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s40.BridgeConnectedengNBListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ConnectedengNBList"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s40.ConnectedengNBList) ENBConfigurationUpdateIEValue {
			return ENBConfigurationUpdateIEValue{id: s00.ProtocolIEID(292), rowConnectedengNBToAddList: &value}
		}, get: func(value *ENBConfigurationUpdateIEValue) (*s40.ConnectedengNBList, bool) {
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
	return ENBConfigurationUpdateConnectedengNBListIEBinding{info: t.infoConnectedengNBToRemoveList(), codec: func() s40.ConnectedengNBListValueCodec {
		sealed := s40.ConnectedengNBListValueCodec{}
		*s40.BridgeConnectedengNBListValueCodecFieldPath(&sealed) = "ConnectedengNBList"
		*s40.BridgeConnectedengNBListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s40.ConnectedengNBList, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s40.ConnectedengNBList
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("ConnectedengNBList")
			var zero ENBConfigurationUpdateIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(293), raw)
			if err != nil {
				var empty s40.ConnectedengNBList
				return empty, runtime.WrapDecodePath(err, "ConnectedengNBList")
			}
			value, ok := decoded.AsConnectedengNBToRemoveList()
			if !ok {
				var empty s40.ConnectedengNBList
				return empty, fmt.Errorf("binding ENBConfigurationUpdateIEs.id-ConnectedengNBToRemoveList: no selected value")
			}
			return *value, nil
		}
		*s40.BridgeConnectedengNBListValueCodecFieldEncode(&sealed) = func(value s40.ConnectedengNBList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (ENBConfigurationUpdateIEValue{id: s00.ProtocolIEID(293), rowConnectedengNBToRemoveList: &value}).encodeFresh(fresh, budget)
		}
		*s40.BridgeConnectedengNBListValueCodecFieldCapture(&sealed) = func(v s40.ConnectedengNBList, options aper.DecodeState) (s40.ConnectedengNBList, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s40.BridgeCaptureS1APConnectedengNBList(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v,

				root
		}
		*s40.BridgeConnectedengNBListValueCodecFieldCompare(&sealed) = func(v s40.ConnectedengNBList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s40.BridgeCompareS1APConnectedengNBList(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s40.BridgeConnectedengNBListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ConnectedengNBList"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s40.ConnectedengNBList) ENBConfigurationUpdateIEValue {
			return ENBConfigurationUpdateIEValue{id: s00.ProtocolIEID(293), rowConnectedengNBToRemoveList: &value}
		}, get: func(value *ENBConfigurationUpdateIEValue) (*s40.ConnectedengNBList, bool) {
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
			var zero MMEConfigurationUpdateIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(61), raw)
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
			return (MMEConfigurationUpdateIEValue{id: s00.ProtocolIEID(61), rowMMEname: &value}).encodeFresh(fresh, budget)
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
		inject: func(value s00.MMEname) MMEConfigurationUpdateIEValue {
			return MMEConfigurationUpdateIEValue{id: s00.ProtocolIEID(61), rowMMEname: &value}
		}, get: func(value *MMEConfigurationUpdateIEValue) (*s00.MMEname, bool) { return value.AsMMEname() }}
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
	return MMEConfigurationUpdateServedGUMMEIsIEBinding{info: t.infoServedGUMMEIs(), codec: func() s39.ServedGUMMEIsValueCodec {
		sealed := s39.ServedGUMMEIsValueCodec{}
		*s39.BridgeServedGUMMEIsValueCodecFieldPath(&sealed) = "ServedGUMMEIs"
		*s39.BridgeServedGUMMEIsValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s39.ServedGUMMEIs, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s39.ServedGUMMEIs
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("ServedGUMMEIs")
			var zero MMEConfigurationUpdateIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(105), raw)
			if err != nil {
				var empty s39.ServedGUMMEIs
				return empty, runtime.WrapDecodePath(err, "ServedGUMMEIs")
			}
			value, ok := decoded.AsServedGUMMEIs()
			if !ok {
				var empty s39.ServedGUMMEIs
				return empty, fmt.Errorf("binding MMEConfigurationUpdateIEs.id-ServedGUMMEIs: no selected value")
			}
			return *value, nil
		}
		*s39.BridgeServedGUMMEIsValueCodecFieldEncode(&sealed) = func(value s39.ServedGUMMEIs, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (MMEConfigurationUpdateIEValue{id: s00.ProtocolIEID(105), rowServedGUMMEIs: &value}).encodeFresh(fresh, budget)
		}
		*s39.BridgeServedGUMMEIsValueCodecFieldCapture(&sealed) = func(v s39.ServedGUMMEIs, options aper.DecodeState) (s39.ServedGUMMEIs, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s39.BridgeCaptureS1APServedGUMMEIs(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s39.BridgeServedGUMMEIsValueCodecFieldCompare(&sealed) = func(v s39.ServedGUMMEIs, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s39.BridgeCompareS1APServedGUMMEIs(&v, &s)
			s.End(f, root, false)
			return s.Plan(),

				s.BudgetValue()
		}
		*s39.BridgeServedGUMMEIsValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ServedGUMMEIs"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s39.ServedGUMMEIs) MMEConfigurationUpdateIEValue {
			return MMEConfigurationUpdateIEValue{id: s00.ProtocolIEID(105), rowServedGUMMEIs: &value}
		}, get: func(value *MMEConfigurationUpdateIEValue) (*s39.ServedGUMMEIs, bool) { return value.AsServedGUMMEIs() }}
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
	return MMEConfigurationUpdateRelativeMMECapacityIEBinding{info: t.infoRelativeMMECapacity(), codec: func() s02.RelativeMMECapacityValueCodec {
		sealed := s02.RelativeMMECapacityValueCodec{}
		*s02.BridgeRelativeMMECapacityValueCodecFieldPath(&sealed) = "RelativeMMECapacity"
		*s02.BridgeRelativeMMECapacityValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.RelativeMMECapacity, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s00.RelativeMMECapacity
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("RelativeMMECapacity")
			var zero MMEConfigurationUpdateIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(87), raw)
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
		*s02.BridgeRelativeMMECapacityValueCodecFieldEncode(&sealed) = func(value s00.RelativeMMECapacity, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (MMEConfigurationUpdateIEValue{id: s00.ProtocolIEID(87), rowRelativeMMECapacity: &value}).encodeFresh(fresh, budget)
		}
		*s02.BridgeRelativeMMECapacityValueCodecFieldCapture(&sealed) = func(v s00.RelativeMMECapacity, options aper.DecodeState) (s00.RelativeMMECapacity, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s00.BridgeCaptureS1APRelativeMMECapacity(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s02.BridgeRelativeMMECapacityValueCodecFieldCompare(&sealed) = func(v s00.RelativeMMECapacity, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s08.BridgeCompareS1APRelativeMMECapacity(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s02.BridgeRelativeMMECapacityValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:RelativeMMECapacity"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s00.RelativeMMECapacity) MMEConfigurationUpdateIEValue {
			return MMEConfigurationUpdateIEValue{id: s00.ProtocolIEID(87), rowRelativeMMECapacity: &value}
		}, get: func(value *MMEConfigurationUpdateIEValue) (*s00.RelativeMMECapacity, bool) {
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
	return MMEConfigurationUpdateServedDCNsIEBinding{info: t.infoServedDCNs(), codec: func() s39.ServedDCNsValueCodec {
		sealed := s39.ServedDCNsValueCodec{}
		*s39.BridgeServedDCNsValueCodecFieldPath(&sealed) = "ServedDCNs"
		*s39.BridgeServedDCNsValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s39.ServedDCNs, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s39.ServedDCNs
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("ServedDCNs")
			var zero MMEConfigurationUpdateIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(247), raw)
			if err != nil {
				var empty s39.ServedDCNs
				return empty, runtime.WrapDecodePath(err, "ServedDCNs")
			}
			value, ok := decoded.AsServedDCNs()
			if !ok {
				var empty s39.ServedDCNs
				return empty, fmt.Errorf("binding MMEConfigurationUpdateIEs.id-ServedDCNs: no selected value")
			}
			return *value, nil
		}
		*s39.BridgeServedDCNsValueCodecFieldEncode(&sealed) = func(value s39.ServedDCNs, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (MMEConfigurationUpdateIEValue{id: s00.ProtocolIEID(247), rowServedDCNs: &value}).encodeFresh(fresh, budget)
		}
		*s39.BridgeServedDCNsValueCodecFieldCapture(&sealed) = func(v s39.ServedDCNs, options aper.DecodeState) (s39.ServedDCNs, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f :=
				s.Begin()
			s39.BridgeCaptureS1APServedDCNs(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s39.BridgeServedDCNsValueCodecFieldCompare(&sealed) = func(v s39.ServedDCNs, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s39.BridgeCompareS1APServedDCNs(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s39.BridgeServedDCNsValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ServedDCNs"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s39.ServedDCNs) MMEConfigurationUpdateIEValue {
			return MMEConfigurationUpdateIEValue{id: s00.ProtocolIEID(247), rowServedDCNs: &value}
		}, get: func(value *MMEConfigurationUpdateIEValue) (*s39.ServedDCNs, bool) { return value.AsServedDCNs() }}
}

// NewOpaque constructs an owned opaque field for an identifier without a typed row in MMEConfigurationUpdateIETable.
func (t MMEConfigurationUpdateIETable) NewOpaque(id s00.ProtocolIEID, criticality s00.Criticality, data []byte) (MMEConfigurationUpdateIEField, error) {
	if id < 0 || id > 65535 || criticality < 0 || criticality > 2 {
		return MMEConfigurationUpdateIEField{}, aper.OperationError(fmt.Errorf("invalid opaque IE selector or criticality"), "Opaque")
	}
	switch id {
	case s00.ProtocolIEID(61):
		return MMEConfigurationUpdateIEField{}, aper.OperationError(fmt.Errorf("known IE id-MMEname requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(105):
		return MMEConfigurationUpdateIEField{}, aper.OperationError(fmt.Errorf("known IE id-ServedGUMMEIs requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(87):
		return MMEConfigurationUpdateIEField{}, aper.OperationError(fmt.Errorf("known IE id-RelativeMMECapacity requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(247):
		return MMEConfigurationUpdateIEField{}, aper.OperationError(fmt.Errorf("known IE id-ServedDCNs requires its typed binding"), "Opaque")
	default:
		budget, err := aper.BuildBudget()
		if err != nil {
			return MMEConfigurationUpdateIEField{}, aper.OperationError(err, "Opaque")
		}
		opaque, err := aper.BuildOpaqueOpenType(data, budget)
		if err != nil {
			return MMEConfigurationUpdateIEField{}, aper.OperationError(err, "Opaque")
		}
		return MMEConfigurationUpdateIEField{Id: id, Criticality: criticality, Value: MMEConfigurationUpdateIEValue{id: id, opaque: opaque, isOpaque: true}}, aper.OperationError(nil, "Opaque")
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
	return S1SetupRequestGlobalENBIDIEBinding{info: t.infoGlobalENBID(), codec: func() s21.GlobalENBIDValueCodec {
		sealed := s21.GlobalENBIDValueCodec{}
		*s21.BridgeGlobalENBIDValueCodecFieldPath(&sealed) = "GlobalENBID"
		*s21.BridgeGlobalENBIDValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s21.GlobalENBID, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s21.GlobalENBID
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("GlobalENBID")
			var zero S1SetupRequestIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(59), raw)
			if err != nil {
				var empty s21.GlobalENBID
				return empty, runtime.WrapDecodePath(err, "GlobalENBID")
			}
			value, ok := decoded.AsGlobalENBID()
			if !ok {
				var empty s21.GlobalENBID
				return empty, fmt.Errorf("binding S1SetupRequestIEs.id-Global-ENB-ID: no selected value")
			}
			return *value, nil
		}
		*s21.BridgeGlobalENBIDValueCodecFieldEncode(&sealed) = func(value s21.GlobalENBID, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (S1SetupRequestIEValue{id: s00.ProtocolIEID(59), rowGlobalENBID: &value}).encodeFresh(fresh, budget)
		}
		*s21.BridgeGlobalENBIDValueCodecFieldCapture(&sealed) = func(v s21.GlobalENBID, options aper.DecodeState) (s21.GlobalENBID, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s21.BridgeCaptureS1APGlobalENBID(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s21.BridgeGlobalENBIDValueCodecFieldCompare(&sealed) = func(v s21.GlobalENBID, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s21.BridgeCompareS1APGlobalENBID(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.
				BudgetValue()
		}
		*s21.BridgeGlobalENBIDValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:GlobalENBID"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s21.GlobalENBID) S1SetupRequestIEValue {
			return S1SetupRequestIEValue{id: s00.ProtocolIEID(59), rowGlobalENBID: &value}
		}, get: func(value *S1SetupRequestIEValue) (*s21.GlobalENBID, bool) { return value.AsGlobalENBID() }}
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
	return S1SetupRequestSupportedTAsIEBinding{info: t.infoSupportedTAs(), codec: func() s40.SupportedTAsValueCodec {
		sealed := s40.SupportedTAsValueCodec{}
		*s40.BridgeSupportedTAsValueCodecFieldPath(&sealed) = "SupportedTAs"
		*s40.BridgeSupportedTAsValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s40.SupportedTAs, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s40.SupportedTAs
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("SupportedTAs")
			var zero S1SetupRequestIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(64), raw)
			if err != nil {
				var empty s40.SupportedTAs
				return empty, runtime.WrapDecodePath(err, "SupportedTAs")
			}
			value, ok := decoded.AsSupportedTAs()
			if !ok {
				var empty s40.SupportedTAs
				return empty, fmt.Errorf("binding S1SetupRequestIEs.id-SupportedTAs: no selected value")
			}
			return *value, nil
		}
		*s40.BridgeSupportedTAsValueCodecFieldEncode(&sealed) = func(value s40.SupportedTAs, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (S1SetupRequestIEValue{id: s00.ProtocolIEID(64), rowSupportedTAs: &value}).encodeFresh(fresh, budget)
		}
		*s40.BridgeSupportedTAsValueCodecFieldCapture(&sealed) = func(v s40.SupportedTAs, options aper.DecodeState) (s40.SupportedTAs, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s40.BridgeCaptureS1APSupportedTAs(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s40.BridgeSupportedTAsValueCodecFieldCompare(&sealed) = func(v s40.SupportedTAs, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s40.BridgeCompareS1APSupportedTAs(&v, &s)
			s.End(f, root, false)
			return s.Plan(),
				s.
					BudgetValue()
		}
		*s40.BridgeSupportedTAsValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:SupportedTAs"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s40.SupportedTAs) S1SetupRequestIEValue {
			return S1SetupRequestIEValue{id: s00.ProtocolIEID(64), rowSupportedTAs: &value}
		}, get: func(value *S1SetupRequestIEValue) (*s40.SupportedTAs, bool) { return value.AsSupportedTAs() }}
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
	return S1SetupRequestCSGIdListIEBinding{info: t.infoCSGIdList(), codec: func() s17.CSGIdListValueCodec {
		sealed := s17.CSGIdListValueCodec{}
		*s17.BridgeCSGIdListValueCodecFieldPath(&sealed) = "CSGIdList"
		*s17.BridgeCSGIdListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s17.CSGIdList, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s17.CSGIdList
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("CSGIdList")
			var zero S1SetupRequestIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(128), raw)
			if err != nil {
				var empty s17.CSGIdList
				return empty, runtime.WrapDecodePath(err, "CSGIdList")
			}
			value, ok := decoded.AsCSGIdList()
			if !ok {
				var empty s17.CSGIdList
				return empty, fmt.Errorf("binding S1SetupRequestIEs.id-CSG-IdList: no selected value")
			}
			return *value, nil
		}
		*s17.BridgeCSGIdListValueCodecFieldEncode(&sealed) = func(value s17.CSGIdList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (S1SetupRequestIEValue{id: s00.ProtocolIEID(128), rowCSGIdList: &value}).encodeFresh(fresh, budget)
		}
		*s17.BridgeCSGIdListValueCodecFieldCapture(&sealed) = func(v s17.CSGIdList, options aper.DecodeState) (s17.CSGIdList, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.
				Begin()
			s25.BridgeCaptureS1APCSGIdList(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s17.BridgeCSGIdListValueCodecFieldCompare(&sealed) = func(v s17.CSGIdList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s25.BridgeCompareS1APCSGIdList(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s17.BridgeCSGIdListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:CSGIdList"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s17.CSGIdList) S1SetupRequestIEValue {
			return S1SetupRequestIEValue{id: s00.ProtocolIEID(128), rowCSGIdList: &value}
		}, get: func(value *S1SetupRequestIEValue) (*s17.CSGIdList, bool) { return value.AsCSGIdList() }}
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
			s08.BridgeCompareS1APUERetentionInformation(&v, &s)
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
	return S1SetupRequestConnectedengNBListIEBinding{info: t.infoConnectedengNBList(), codec: func() s40.ConnectedengNBListValueCodec {
		sealed := s40.ConnectedengNBListValueCodec{}
		*s40.BridgeConnectedengNBListValueCodecFieldPath(&sealed) = "ConnectedengNBList"
		*s40.BridgeConnectedengNBListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s40.ConnectedengNBList, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s40.ConnectedengNBList
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("ConnectedengNBList")
			var zero S1SetupRequestIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(291), raw)
			if err != nil {
				var empty s40.ConnectedengNBList
				return empty, runtime.WrapDecodePath(err, "ConnectedengNBList")
			}
			value, ok := decoded.AsConnectedengNBList()
			if !ok {
				var empty s40.ConnectedengNBList
				return empty, fmt.Errorf("binding S1SetupRequestIEs.id-ConnectedengNBList: no selected value")
			}
			return *value, nil
		}
		*s40.BridgeConnectedengNBListValueCodecFieldEncode(&sealed) = func(value s40.ConnectedengNBList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (S1SetupRequestIEValue{id: s00.ProtocolIEID(291), rowConnectedengNBList: &value}).encodeFresh(fresh, budget)
		}
		*s40.BridgeConnectedengNBListValueCodecFieldCapture(&sealed) = func(v s40.ConnectedengNBList, options aper.DecodeState) (s40.ConnectedengNBList, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s40.BridgeCaptureS1APConnectedengNBList(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v,

				root
		}
		*s40.BridgeConnectedengNBListValueCodecFieldCompare(&sealed) = func(v s40.ConnectedengNBList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s40.BridgeCompareS1APConnectedengNBList(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s40.BridgeConnectedengNBListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ConnectedengNBList"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s40.ConnectedengNBList) S1SetupRequestIEValue {
			return S1SetupRequestIEValue{id: s00.ProtocolIEID(291), rowConnectedengNBList: &value}
		}, get: func(value *S1SetupRequestIEValue) (*s40.ConnectedengNBList, bool) {
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
	return S1SetupResponseServedGUMMEIsIEBinding{info: t.infoServedGUMMEIs(), codec: func() s39.ServedGUMMEIsValueCodec {
		sealed := s39.ServedGUMMEIsValueCodec{}
		*s39.BridgeServedGUMMEIsValueCodecFieldPath(&sealed) = "ServedGUMMEIs"
		*s39.BridgeServedGUMMEIsValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s39.ServedGUMMEIs, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s39.ServedGUMMEIs
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("ServedGUMMEIs")
			var zero S1SetupResponseIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(105), raw)
			if err != nil {
				var empty s39.ServedGUMMEIs
				return empty, runtime.WrapDecodePath(err, "ServedGUMMEIs")
			}
			value, ok := decoded.AsServedGUMMEIs()
			if !ok {
				var empty s39.ServedGUMMEIs
				return empty, fmt.Errorf("binding S1SetupResponseIEs.id-ServedGUMMEIs: no selected value")
			}
			return *value, nil
		}
		*s39.BridgeServedGUMMEIsValueCodecFieldEncode(&sealed) = func(value s39.ServedGUMMEIs, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (S1SetupResponseIEValue{id: s00.ProtocolIEID(105), rowServedGUMMEIs: &value}).encodeFresh(fresh, budget)
		}
		*s39.BridgeServedGUMMEIsValueCodecFieldCapture(&sealed) = func(v s39.ServedGUMMEIs, options aper.DecodeState) (s39.ServedGUMMEIs, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s39.BridgeCaptureS1APServedGUMMEIs(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s39.BridgeServedGUMMEIsValueCodecFieldCompare(&sealed) = func(v s39.ServedGUMMEIs, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s39.BridgeCompareS1APServedGUMMEIs(&v, &s)
			s.End(f, root, false)
			return s.Plan(),

				s.BudgetValue()
		}
		*s39.BridgeServedGUMMEIsValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ServedGUMMEIs"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s39.ServedGUMMEIs) S1SetupResponseIEValue {
			return S1SetupResponseIEValue{id: s00.ProtocolIEID(105), rowServedGUMMEIs: &value}
		}, get: func(value *S1SetupResponseIEValue) (*s39.ServedGUMMEIs, bool) { return value.AsServedGUMMEIs() }}
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
	return S1SetupResponseRelativeMMECapacityIEBinding{info: t.infoRelativeMMECapacity(), codec: func() s02.RelativeMMECapacityValueCodec {
		sealed := s02.RelativeMMECapacityValueCodec{}
		*s02.BridgeRelativeMMECapacityValueCodecFieldPath(&sealed) = "RelativeMMECapacity"
		*s02.BridgeRelativeMMECapacityValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.RelativeMMECapacity, error) {
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
		*s02.BridgeRelativeMMECapacityValueCodecFieldEncode(&sealed) = func(value s00.RelativeMMECapacity, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (S1SetupResponseIEValue{id: s00.ProtocolIEID(87), rowRelativeMMECapacity: &value}).encodeFresh(fresh, budget)
		}
		*s02.BridgeRelativeMMECapacityValueCodecFieldCapture(&sealed) = func(v s00.RelativeMMECapacity, options aper.DecodeState) (s00.RelativeMMECapacity, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s00.BridgeCaptureS1APRelativeMMECapacity(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s02.BridgeRelativeMMECapacityValueCodecFieldCompare(&sealed) = func(v s00.RelativeMMECapacity, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s08.BridgeCompareS1APRelativeMMECapacity(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s02.BridgeRelativeMMECapacityValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
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
	return S1SetupResponseCriticalityDiagnosticsIEBinding{info: t.infoCriticalityDiagnostics(), codec: func() s26.CriticalityDiagnosticsValueCodec {
		sealed := s26.CriticalityDiagnosticsValueCodec{}
		*s26.BridgeCriticalityDiagnosticsValueCodecFieldPath(&sealed) = "CriticalityDiagnostics"
		*s26.BridgeCriticalityDiagnosticsValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s26.CriticalityDiagnostics, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s26.CriticalityDiagnostics
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("CriticalityDiagnostics")
			var zero S1SetupResponseIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(58), raw)
			if err != nil {
				var empty s26.CriticalityDiagnostics
				return empty, runtime.WrapDecodePath(err, "CriticalityDiagnostics")
			}
			value, ok := decoded.AsCriticalityDiagnostics()
			if !ok {
				var empty s26.CriticalityDiagnostics
				return empty, fmt.Errorf("binding S1SetupResponseIEs.id-CriticalityDiagnostics: no selected value")
			}
			return *value, nil
		}
		*s26.BridgeCriticalityDiagnosticsValueCodecFieldEncode(&sealed) = func(value s26.CriticalityDiagnostics, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (S1SetupResponseIEValue{id: s00.ProtocolIEID(58), rowCriticalityDiagnostics: &value}).encodeFresh(fresh, budget)
		}
		*s26.BridgeCriticalityDiagnosticsValueCodecFieldCapture(&sealed) = func(v s26.CriticalityDiagnostics, options aper.DecodeState) (s26.CriticalityDiagnostics, aper.Snapshot,

		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s26.BridgeCaptureS1APCriticalityDiagnostics(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s26.BridgeCriticalityDiagnosticsValueCodecFieldCompare(&sealed) = func(v s26.CriticalityDiagnostics, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s26.BridgeCompareS1APCriticalityDiagnostics(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s26.BridgeCriticalityDiagnosticsValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:CriticalityDiagnostics"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s26.CriticalityDiagnostics) S1SetupResponseIEValue {
			return S1SetupResponseIEValue{id: s00.ProtocolIEID(58), rowCriticalityDiagnostics: &value}
		}, get: func(value *S1SetupResponseIEValue) (*s26.CriticalityDiagnostics, bool) {
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
			s08.BridgeCompareS1APUERetentionInformation(&v, &s)
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
	return S1SetupResponseServedDCNsIEBinding{info: t.infoServedDCNs(), codec: func() s39.ServedDCNsValueCodec {
		sealed := s39.ServedDCNsValueCodec{}
		*s39.BridgeServedDCNsValueCodecFieldPath(&sealed) = "ServedDCNs"
		*s39.BridgeServedDCNsValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s39.ServedDCNs, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s39.ServedDCNs
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("ServedDCNs")
			var zero S1SetupResponseIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(247), raw)
			if err != nil {
				var empty s39.ServedDCNs
				return empty, runtime.WrapDecodePath(err, "ServedDCNs")
			}
			value, ok := decoded.AsServedDCNs()
			if !ok {
				var empty s39.ServedDCNs
				return empty, fmt.Errorf("binding S1SetupResponseIEs.id-ServedDCNs: no selected value")
			}
			return *value, nil
		}
		*s39.BridgeServedDCNsValueCodecFieldEncode(&sealed) = func(value s39.ServedDCNs, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (S1SetupResponseIEValue{id: s00.ProtocolIEID(247), rowServedDCNs: &value}).encodeFresh(fresh, budget)
		}
		*s39.BridgeServedDCNsValueCodecFieldCapture(&sealed) = func(v s39.ServedDCNs, options aper.DecodeState) (s39.ServedDCNs, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f :=
				s.Begin()
			s39.BridgeCaptureS1APServedDCNs(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s39.BridgeServedDCNsValueCodecFieldCompare(&sealed) = func(v s39.ServedDCNs, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s39.BridgeCompareS1APServedDCNs(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s39.BridgeServedDCNsValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ServedDCNs"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s39.ServedDCNs) S1SetupResponseIEValue {
			return S1SetupResponseIEValue{id: s00.ProtocolIEID(247), rowServedDCNs: &value}
		}, get: func(value *S1SetupResponseIEValue) (*s39.ServedDCNs, bool) { return value.AsServedDCNs() }}
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
func CSGIdListCodec() s17.CSGIdListValueCodec { return ENBConfigurationUpdateIEs().CSGIdList().Codec() }

// ConnectedengNBListCodec binds the complete APER value type.
func ConnectedengNBListCodec() s40.ConnectedengNBListValueCodec {
	return ENBConfigurationUpdateIEs().ConnectedengNBToAddList().Codec()
}

// ENBnameCodec binds the complete APER value type.
func ENBnameCodec() s00.ENBnameValueCodec { return ENBConfigurationUpdateIEs().ENBname().Codec() }

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
func RelativeMMECapacityCodec() s02.RelativeMMECapacityValueCodec {
	return MMEConfigurationUpdateIEs().RelativeMMECapacity().Codec()
}

// ServedDCNsCodec binds the complete APER value type.
func ServedDCNsCodec() s39.ServedDCNsValueCodec {
	return MMEConfigurationUpdateIEs().ServedDCNs().Codec()
}

// ServedGUMMEIsCodec binds the complete APER value type.
func ServedGUMMEIsCodec() s39.ServedGUMMEIsValueCodec {
	return MMEConfigurationUpdateIEs().ServedGUMMEIs().Codec()
}

// ServedGroupIDsCodec binds the complete source value type.
func ServedGroupIDsCodec() s02.ServedGroupIDsValueCodec {
	return func() s02.ServedGroupIDsValueCodec {
		sealed := s02.ServedGroupIDsValueCodec{}
		*s02.BridgeServedGroupIDsValueCodecFieldPath(&sealed) = "ServedGroupIDs"
		*s02.BridgeServedGroupIDsValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.ServedGroupIDs, error) {
			var complete ServedGroupIDsComplete
			if err := complete.unmarshalAPERWithOptions(data, options); err != nil {
				var zero s00.ServedGroupIDs
				return zero, err
			}
			return complete.Value, nil
		}
		*s02.BridgeServedGroupIDsValueCodecFieldEncode(&sealed) = func(value s00.ServedGroupIDs, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			complete := ServedGroupIDsComplete{Value: value}
			return complete.marshalAPERBudget(budget, fresh)
		}
		*s02.BridgeServedGroupIDsValueCodecFieldCapture(&sealed) = func(v s00.ServedGroupIDs, options aper.DecodeState) (s00.ServedGroupIDs, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s00.BridgeCaptureS1APServedGroupIDs(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s02.BridgeServedGroupIDsValueCodecFieldCompare(&sealed) = func(v s00.ServedGroupIDs, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s08.BridgeCompareS1APServedGroupIDs(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s02.BridgeServedGroupIDsValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ServedGroupIDs"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// ServedMMECsCodec binds the complete source value type.
func ServedMMECsCodec() s02.ServedMMECsValueCodec {
	return func() s02.ServedMMECsValueCodec {
		sealed := s02.ServedMMECsValueCodec{}
		*s02.BridgeServedMMECsValueCodecFieldPath(&sealed) = "ServedMMECs"
		*s02.BridgeServedMMECsValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.ServedMMECs, error) {
			var complete ServedMMECsComplete
			if err := complete.unmarshalAPERWithOptions(data, options); err != nil {
				var zero s00.ServedMMECs
				return zero, err
			}
			return complete.Value, nil
		}
		*s02.BridgeServedMMECsValueCodecFieldEncode(&sealed) = func(value s00.ServedMMECs, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			complete := ServedMMECsComplete{Value: value}
			return complete.marshalAPERBudget(budget, fresh)
		}
		*s02.BridgeServedMMECsValueCodecFieldCapture(&sealed) = func(v s00.ServedMMECs, options aper.DecodeState) (s00.ServedMMECs, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s00.BridgeCaptureS1APServedMMECs(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s02.BridgeServedMMECsValueCodecFieldCompare(&sealed) = func(v s00.ServedMMECs, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s08.BridgeCompareS1APServedMMECs(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.
				BudgetValue()
		}
		*s02.BridgeServedMMECsValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ServedMMECs"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// ServedPLMNsCodec binds the complete source value type.
func ServedPLMNsCodec() s02.ServedPLMNsValueCodec {
	return func() s02.ServedPLMNsValueCodec {
		sealed := s02.ServedPLMNsValueCodec{}
		*s02.BridgeServedPLMNsValueCodecFieldPath(&sealed) = "ServedPLMNs"
		*s02.BridgeServedPLMNsValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.ServedPLMNs, error) {
			var complete ServedPLMNsComplete
			if err := complete.unmarshalAPERWithOptions(data, options); err != nil {
				var zero s00.ServedPLMNs
				return zero, err
			}
			return complete.Value, nil
		}
		*s02.BridgeServedPLMNsValueCodecFieldEncode(&sealed) = func(value s00.ServedPLMNs, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			complete := ServedPLMNsComplete{Value: value}
			return complete.marshalAPERBudget(budget, fresh)
		}
		*s02.BridgeServedPLMNsValueCodecFieldCapture(&sealed) = func(v s00.ServedPLMNs, options aper.DecodeState) (s00.ServedPLMNs, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s00.BridgeCaptureS1APServedPLMNs(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s02.BridgeServedPLMNsValueCodecFieldCompare(&sealed) = func(v s00.ServedPLMNs, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s08.BridgeCompareS1APServedPLMNs(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.
				BudgetValue()
		}
		*s02.BridgeServedPLMNsValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ServedPLMNs"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// SupportedTAsCodec binds the complete APER value type.
func SupportedTAsCodec() s40.SupportedTAsValueCodec {
	return ENBConfigurationUpdateIEs().SupportedTAs().Codec()
}

// TACListInLTENTNCodec binds the complete source value type.
func TACListInLTENTNCodec() s02.TACListInLTENTNValueCodec {
	return func() s02.TACListInLTENTNValueCodec {
		sealed := s02.TACListInLTENTNValueCodec{}
		*s02.BridgeTACListInLTENTNValueCodecFieldPath(&sealed) = "TACListInLTENTN"
		*s02.BridgeTACListInLTENTNValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.TACListInLTENTN, error) {
			var complete TACListInLTENTNComplete
			if err := complete.unmarshalAPERWithOptions(data, options); err != nil {
				var zero s00.TACListInLTENTN
				return zero, err
			}
			return complete.Value, nil
		}
		*s02.BridgeTACListInLTENTNValueCodecFieldEncode(&sealed) = func(value s00.TACListInLTENTN, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			complete := TACListInLTENTNComplete{Value: value}
			return complete.marshalAPERBudget(budget, fresh)
		}
		*s02.BridgeTACListInLTENTNValueCodecFieldCapture(&sealed) = func(v s00.TACListInLTENTN, options aper.DecodeState) (s00.TACListInLTENTN, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s00.BridgeCaptureS1APTACListInLTENTN(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s02.BridgeTACListInLTENTNValueCodecFieldCompare(&sealed) = func(v s00.TACListInLTENTN, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s08.BridgeCompareS1APTACListInLTENTN(&v, &s)
			s.End(f, root, false)
			return s.
				Plan(), s.BudgetValue()
		}
		*s02.BridgeTACListInLTENTNValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:TACListInLTENTN"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// UERetentionInformationCodec binds the complete APER value type.
func UERetentionInformationCodec() s02.UERetentionInformationValueCodec {
	return S1SetupRequestIEs().UERetentionInformation().Codec()
}
func BridgeENBConfigurationUpdateFieldPerPadding(v *ENBConfigurationUpdate) *aper.FinalPadding {
	return &v.perPadding
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
func BridgeENBConfigurationUpdateIEValueFieldId(v *ENBConfigurationUpdateIEValue) *s00.ProtocolIEID {
	return &v.id
}
func BridgeENBConfigurationUpdateIEValueFieldIsOpaque(v *ENBConfigurationUpdateIEValue) *bool {
	return &v.isOpaque
}
func BridgeENBConfigurationUpdateIEValueFieldOpaque(v *ENBConfigurationUpdateIEValue) *aper.OpaqueOpenType {
	return &v.opaque
}
func BridgeENBConfigurationUpdateIEValueFieldRowCSGIdList(v *ENBConfigurationUpdateIEValue) **s17.CSGIdList {
	return &v.rowCSGIdList
}
func BridgeENBConfigurationUpdateIEValueFieldRowConnectedengNBToAddList(v *ENBConfigurationUpdateIEValue) **s40.ConnectedengNBList {
	return &v.rowConnectedengNBToAddList
}
func BridgeENBConfigurationUpdateIEValueFieldRowConnectedengNBToRemoveList(v *ENBConfigurationUpdateIEValue) **s40.ConnectedengNBList {
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
func BridgeENBConfigurationUpdateIEValueFieldRowSupportedTAs(v *ENBConfigurationUpdateIEValue) **s40.SupportedTAs {
	return &v.rowSupportedTAs
}
func BridgeENBConfigurationUpdateMethodMarshalAPERBudget(v *ENBConfigurationUpdate, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeENBConfigurationUpdateMethodUnmarshalAPERFrom(v *ENBConfigurationUpdate, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeENBConfigurationUpdateMethodUnmarshalAPERWithOptions(v *ENBConfigurationUpdate, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
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
func BridgeMMEConfigurationUpdateFieldPerPadding(v *MMEConfigurationUpdate) *aper.FinalPadding {
	return &v.perPadding
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
func BridgeMMEConfigurationUpdateIEValueFieldId(v *MMEConfigurationUpdateIEValue) *s00.ProtocolIEID {
	return &v.id
}
func BridgeMMEConfigurationUpdateIEValueFieldIsOpaque(v *MMEConfigurationUpdateIEValue) *bool {
	return &v.isOpaque
}
func BridgeMMEConfigurationUpdateIEValueFieldOpaque(v *MMEConfigurationUpdateIEValue) *aper.OpaqueOpenType {
	return &v.opaque
}
func BridgeMMEConfigurationUpdateIEValueFieldRowMMEname(v *MMEConfigurationUpdateIEValue) **s00.MMEname {
	return &v.rowMMEname
}
func BridgeMMEConfigurationUpdateIEValueFieldRowRelativeMMECapacity(v *MMEConfigurationUpdateIEValue) **s00.RelativeMMECapacity {
	return &v.rowRelativeMMECapacity
}
func BridgeMMEConfigurationUpdateIEValueFieldRowServedDCNs(v *MMEConfigurationUpdateIEValue) **s39.ServedDCNs {
	return &v.rowServedDCNs
}
func BridgeMMEConfigurationUpdateIEValueFieldRowServedGUMMEIs(v *MMEConfigurationUpdateIEValue) **s39.ServedGUMMEIs {
	return &v.rowServedGUMMEIs
}
func BridgeMMEConfigurationUpdateMethodMarshalAPERBudget(v *MMEConfigurationUpdate, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeMMEConfigurationUpdateMethodUnmarshalAPERFrom(v *MMEConfigurationUpdate, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeMMEConfigurationUpdateMethodUnmarshalAPERWithOptions(v *MMEConfigurationUpdate, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
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
func BridgeS1SetupRequestFieldPerPadding(v *S1SetupRequest) *aper.FinalPadding { return &v.perPadding }
func BridgeS1SetupRequestFieldReceived(v *S1SetupRequest) *bool                { return &v.received }
func BridgeS1SetupRequestFieldReceivedAbsolute(v *S1SetupRequest) *bool        { return &v.receivedAbsolute }
func BridgeS1SetupRequestFieldReceivedBytes(v *S1SetupRequest) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeS1SetupRequestFieldReceivedLocation(v *S1SetupRequest) *aper.Location {
	return &v.receivedLocation
}
func BridgeS1SetupRequestIEValueFieldId(v *S1SetupRequestIEValue) *s00.ProtocolIEID { return &v.id }
func BridgeS1SetupRequestIEValueFieldIsOpaque(v *S1SetupRequestIEValue) *bool       { return &v.isOpaque }
func BridgeS1SetupRequestIEValueFieldOpaque(v *S1SetupRequestIEValue) *aper.OpaqueOpenType {
	return &v.opaque
}
func BridgeS1SetupRequestIEValueFieldRowCSGIdList(v *S1SetupRequestIEValue) **s17.CSGIdList {
	return &v.rowCSGIdList
}
func BridgeS1SetupRequestIEValueFieldRowConnectedengNBList(v *S1SetupRequestIEValue) **s40.ConnectedengNBList {
	return &v.rowConnectedengNBList
}
func BridgeS1SetupRequestIEValueFieldRowDefaultPagingDRX(v *S1SetupRequestIEValue) **s00.PagingDRX {
	return &v.rowDefaultPagingDRX
}
func BridgeS1SetupRequestIEValueFieldRowENBname(v *S1SetupRequestIEValue) **s00.ENBname {
	return &v.rowENBname
}
func BridgeS1SetupRequestIEValueFieldRowGlobalENBID(v *S1SetupRequestIEValue) **s21.GlobalENBID {
	return &v.rowGlobalENBID
}
func BridgeS1SetupRequestIEValueFieldRowNBIoTDefaultPagingDRX(v *S1SetupRequestIEValue) **s00.NBIoTDefaultPagingDRX {
	return &v.rowNBIoTDefaultPagingDRX
}
func BridgeS1SetupRequestIEValueFieldRowSupportedTAs(v *S1SetupRequestIEValue) **s40.SupportedTAs {
	return &v.rowSupportedTAs
}
func BridgeS1SetupRequestIEValueFieldRowUERetentionInformation(v *S1SetupRequestIEValue) **s00.UERetentionInformation {
	return &v.rowUERetentionInformation
}
func BridgeS1SetupRequestMethodMarshalAPERBudget(v *S1SetupRequest, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeS1SetupRequestMethodUnmarshalAPERFrom(v *S1SetupRequest, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
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
func BridgeS1SetupResponseFieldPerPadding(v *S1SetupResponse) *aper.FinalPadding {
	return &v.perPadding
}
func BridgeS1SetupResponseFieldReceived(v *S1SetupResponse) *bool         { return &v.received }
func BridgeS1SetupResponseFieldReceivedAbsolute(v *S1SetupResponse) *bool { return &v.receivedAbsolute }
func BridgeS1SetupResponseFieldReceivedBytes(v *S1SetupResponse) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeS1SetupResponseFieldReceivedLocation(v *S1SetupResponse) *aper.Location {
	return &v.receivedLocation
}
func BridgeS1SetupResponseIEValueFieldId(v *S1SetupResponseIEValue) *s00.ProtocolIEID { return &v.id }
func BridgeS1SetupResponseIEValueFieldIsOpaque(v *S1SetupResponseIEValue) *bool       { return &v.isOpaque }
func BridgeS1SetupResponseIEValueFieldOpaque(v *S1SetupResponseIEValue) *aper.OpaqueOpenType {
	return &v.opaque
}
func BridgeS1SetupResponseIEValueFieldRowCriticalityDiagnostics(v *S1SetupResponseIEValue) **s26.CriticalityDiagnostics {
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
func BridgeS1SetupResponseIEValueFieldRowServedDCNs(v *S1SetupResponseIEValue) **s39.ServedDCNs {
	return &v.rowServedDCNs
}
func BridgeS1SetupResponseIEValueFieldRowServedGUMMEIs(v *S1SetupResponseIEValue) **s39.ServedGUMMEIs {
	return &v.rowServedGUMMEIs
}
func BridgeS1SetupResponseIEValueFieldRowUERetentionInformation(v *S1SetupResponseIEValue) **s00.UERetentionInformation {
	return &v.rowUERetentionInformation
}
func BridgeS1SetupResponseMethodMarshalAPERBudget(v *S1SetupResponse, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeS1SetupResponseMethodUnmarshalAPERFrom(v *S1SetupResponse, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeS1SetupResponseMethodUnmarshalAPERWithOptions(v *S1SetupResponse, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
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
func (v *MMEConfigurationUpdateIEValue) Selected() (any, bool) {
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
	case 247:
		if value, ok := v.AsServedDCNs(); ok {
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
