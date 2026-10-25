// Code generated from the pinned S1AP source closure. DO NOT EDIT.

// Package s37 implements the github.com/gomaja/go-asn1/telecom/lte/s1ap root package.
package s37

import (
	fmt "fmt"
	s00 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s00"
	s01 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s01"
	s02 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s02"
	s06 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s06"
	s07 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s07"
	s12 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s12"
	s13 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s13"
	s14 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s14"
	s15 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s15"
	s17 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s17"
	s18 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s18"
	s21 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s21"
	s24 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s24"
	s25 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s25"
	s26 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s26"
	s28 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s28"
	s31 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s31"
	s32 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s32"
	s36 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s36"
	runtime "github.com/gomaja/go-asn1/telecom/lte/s1ap/runtime"
	aper "github.com/gomaja/go-asn1/telecom/lte/s1ap/runtime/aper"
)

// UEContextReleaseCommandIEContainer is ProtocolIE-Container {{UEContextReleaseCommand-IEs}} of TS 36.413: a list of UEContextReleaseCommandIEField values.
type UEContextReleaseCommandIEContainer []UEContextReleaseCommandIEField

// UEContextReleaseCommandIEField is ProtocolIE-Field {{UEContextReleaseCommand-IEs}} of TS 36.413: an information element field.
type UEContextReleaseCommandIEField struct {
	withoutReplay bool
	replay        aper.Snapshot
	stream        aper.WireSpan
	Id            s00.ProtocolIEID
	Criticality   s00.Criticality
	Value         UEContextReleaseCommandIEValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v UEContextReleaseCommandIEField) WithoutReplay() UEContextReleaseCommandIEField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *UEContextReleaseCommandIEField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *UEContextReleaseCommandIEField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
func (v *UEContextReleaseCommandIEField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolIEField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = UEContextReleaseCommandIEField{}
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
	var zero UEContextReleaseCommandIEValue

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

// ENBCPRelocationIndicationIEContainer is ProtocolIE-Container {{ENBCPRelocationIndicationIEs}} of TS 36.413: a list of ENBCPRelocationIndicationIEField values.
type ENBCPRelocationIndicationIEContainer []ENBCPRelocationIndicationIEField

// ENBCPRelocationIndicationIEField is ProtocolIE-Field {{ENBCPRelocationIndicationIEs}} of TS 36.413: an information element field.
type ENBCPRelocationIndicationIEField struct {
	withoutReplay bool
	replay        aper.Snapshot
	stream        aper.WireSpan
	Id            s00.ProtocolIEID
	Criticality   s00.Criticality
	Value         ENBCPRelocationIndicationIEValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ENBCPRelocationIndicationIEField) WithoutReplay() ENBCPRelocationIndicationIEField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *ENBCPRelocationIndicationIEField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *ENBCPRelocationIndicationIEField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
func (v *ENBCPRelocationIndicationIEField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolIEField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = ENBCPRelocationIndicationIEField{}
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
	var zero ENBCPRelocationIndicationIEValue

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

// ENBEarlyStatusTransferIEContainer is ProtocolIE-Container {{ENBEarlyStatusTransferIEs}} of TS 36.413: a list of ENBEarlyStatusTransferIEField values.
type ENBEarlyStatusTransferIEContainer []ENBEarlyStatusTransferIEField

// ENBEarlyStatusTransferIEField is ProtocolIE-Field {{ENBEarlyStatusTransferIEs}} of TS 36.413: an information element field.
type ENBEarlyStatusTransferIEField struct {
	withoutReplay bool
	replay        aper.Snapshot
	stream        aper.WireSpan
	Id            s00.ProtocolIEID
	Criticality   s00.Criticality
	Value         ENBEarlyStatusTransferIEValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ENBEarlyStatusTransferIEField) WithoutReplay() ENBEarlyStatusTransferIEField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *ENBEarlyStatusTransferIEField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *ENBEarlyStatusTransferIEField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
func (v *ENBEarlyStatusTransferIEField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolIEField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = ENBEarlyStatusTransferIEField{}
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
	var zero ENBEarlyStatusTransferIEValue

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

// MMEEarlyStatusTransferIEContainer is ProtocolIE-Container {{MMEEarlyStatusTransferIEs}} of TS 36.413: a list of MMEEarlyStatusTransferIEField values.
type MMEEarlyStatusTransferIEContainer []MMEEarlyStatusTransferIEField

// MMEEarlyStatusTransferIEField is ProtocolIE-Field {{MMEEarlyStatusTransferIEs}} of TS 36.413: an information element field.
type MMEEarlyStatusTransferIEField struct {
	withoutReplay bool
	replay        aper.Snapshot
	stream        aper.WireSpan
	Id            s00.ProtocolIEID
	Criticality   s00.Criticality
	Value         MMEEarlyStatusTransferIEValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v MMEEarlyStatusTransferIEField) WithoutReplay() MMEEarlyStatusTransferIEField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *MMEEarlyStatusTransferIEField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *MMEEarlyStatusTransferIEField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
func (v *MMEEarlyStatusTransferIEField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolIEField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = MMEEarlyStatusTransferIEField{}
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
	var zero MMEEarlyStatusTransferIEValue

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
func BridgeENBCPRelocationIndicationIEValueCaptureS1APProtocolIEContainer(v *ENBCPRelocationIndicationIEContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeENBCPRelocationIndicationIEValueCaptureS1APProtocolIEField(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeENBCPRelocationIndicationIEValueCompareS1APProtocolIEContainer(v *ENBCPRelocationIndicationIEContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeENBCPRelocationIndicationIEValueCompareS1APProtocolIEField(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeENBEarlyStatusTransferIEValueCaptureS1APProtocolIEContainer(v *ENBEarlyStatusTransferIEContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeENBEarlyStatusTransferIEValueCaptureS1APProtocolIEField(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeENBEarlyStatusTransferIEValueCompareS1APProtocolIEContainer(v *ENBEarlyStatusTransferIEContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeENBEarlyStatusTransferIEValueCompareS1APProtocolIEField(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeENBEarlyStatusTransferTransparentContainerExtIEsValueCaptureS1APProtocolExtensionContainer(v *ENBEarlyStatusTransferTransparentContainerExtIEsExtContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeENBEarlyStatusTransferTransparentContainerExtIEsValueCaptureS1APProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeENBEarlyStatusTransferTransparentContainerExtIEsValueCompareS1APProtocolExtensionContainer(v *ENBEarlyStatusTransferTransparentContainerExtIEsExtContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeENBEarlyStatusTransferTransparentContainerExtIEsValueCompareS1APProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeUEContextReleaseCommandIEValueCaptureS1APProtocolIEContainer(v *UEContextReleaseCommandIEContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeUEContextReleaseCommandIEValueCaptureS1APProtocolIEField(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeUEContextReleaseCommandIEValueCompareS1APProtocolIEContainer(v *UEContextReleaseCommandIEContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeUEContextReleaseCommandIEValueCompareS1APProtocolIEField(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeUERadioCapabilityMatchResponseIEValueCompareS1APProtocolIEContainer(v *s24.UERadioCapabilityMatchResponseIEContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			s36.BridgeUERadioCapabilityMatchResponseIEValueCompareS1APProtocolIEField(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeUES1APIDPairExtIEsValueCaptureS1APProtocolExtensionContainer(v *s12.UES1APIDPairExtIEsExtContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeUES1APIDPairExtIEsValueCaptureS1APProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeUES1APIDPairExtIEsValueCompareS1APProtocolExtensionContainer(v *s12.UES1APIDPairExtIEsExtContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeUES1APIDPairExtIEsValueCompareS1APProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeUESecurityCapabilitiesExtIEsValueCaptureS1APProtocolExtensionContainer(v *s12.UESecurityCapabilitiesExtIEsExtContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeUESecurityCapabilitiesExtIEsValueCaptureS1APProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeUESecurityCapabilitiesExtIEsValueCompareS1APProtocolExtensionContainer(v *s12.UESecurityCapabilitiesExtIEsExtContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeUESecurityCapabilitiesExtIEsValueCompareS1APProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeUESidelinkAggregateMaximumBitratesExtIEsValueCaptureS1APProtocolExtensionContainer(v *s12.UESidelinkAggregateMaximumBitratesExtIEsExtContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeUESidelinkAggregateMaximumBitratesExtIEsValueCaptureS1APProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeUESidelinkAggregateMaximumBitratesExtIEsValueCompareS1APProtocolExtensionContainer(v *s12.UESidelinkAggregateMaximumBitratesExtIEsExtContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeUESidelinkAggregateMaximumBitratesExtIEsValueCompareS1APProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeULCPSecurityInformationExtIEsValueCaptureS1APProtocolExtensionContainer(v *s12.ULCPSecurityInformationExtIEsExtContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeULCPSecurityInformationExtIEsValueCaptureS1APProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeULCPSecurityInformationExtIEsValueCompareS1APProtocolExtensionContainer(v *s12.ULCPSecurityInformationExtIEsExtContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeULCPSecurityInformationExtIEsValueCompareS1APProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}

// ENBEarlyStatusTransferTransparentContainerExtIEsExtContainer is ProtocolExtensionContainer {{ENB-EarlyStatusTransfer-TransparentContainer-ExtIEs}} of TS 36.413: a list of ENBEarlyStatusTransferTransparentContainerExtIEsExtField values.
type ENBEarlyStatusTransferTransparentContainerExtIEsExtContainer []ENBEarlyStatusTransferTransparentContainerExtIEsExtField

// ENBEarlyStatusTransferTransparentContainerExtIEsExtField is ProtocolExtensionField {{ENB-EarlyStatusTransfer-TransparentContainer-ExtIEs}} of TS 36.413: an extension field.
type ENBEarlyStatusTransferTransparentContainerExtIEsExtField struct {
	withoutReplay  bool
	replay         aper.Snapshot
	stream         aper.WireSpan
	Id             s00.ProtocolExtensionID
	Criticality    s00.Criticality
	ExtensionValue ENBEarlyStatusTransferTransparentContainerExtIEsValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ENBEarlyStatusTransferTransparentContainerExtIEsExtField) WithoutReplay() ENBEarlyStatusTransferTransparentContainerExtIEsExtField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *ENBEarlyStatusTransferTransparentContainerExtIEsExtField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *ENBEarlyStatusTransferTransparentContainerExtIEsExtField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
func (v *ENBEarlyStatusTransferTransparentContainerExtIEsExtField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolExtensionField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = ENBEarlyStatusTransferTransparentContainerExtIEsExtField{}
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
	var zero ENBEarlyStatusTransferTransparentContainerExtIEsValue

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

// ENBEarlyStatusTransferTransparentContainerExtIEsBearersSubjectToDLDiscardingListExtBinding binds BearersSubjectToDLDiscardingList to the ENB-EarlyStatusTransfer-TransparentContainer-ExtIEs object set of TS 36.413.
type ENBEarlyStatusTransferTransparentContainerExtIEsBearersSubjectToDLDiscardingListExtBinding struct {
	info   s00.ExtensionInfo
	codec  s15.BearersSubjectToDLDiscardingListValueCodec
	inject func(s15.BearersSubjectToDLDiscardingList,

	) ENBEarlyStatusTransferTransparentContainerExtIEsValue

	get func(*ENBEarlyStatusTransferTransparentContainerExtIEsValue,

	) (*s15.BearersSubjectToDLDiscardingList,

		bool)
}

// Info returns the source descriptor for this binding.
func (b ENBEarlyStatusTransferTransparentContainerExtIEsBearersSubjectToDLDiscardingListExtBinding) Info() s00.ExtensionInfo {
	return b.info
}

// Codec returns the complete value codec for this binding.
func (b ENBEarlyStatusTransferTransparentContainerExtIEsBearersSubjectToDLDiscardingListExtBinding) Codec() s15.BearersSubjectToDLDiscardingListValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b ENBEarlyStatusTransferTransparentContainerExtIEsBearersSubjectToDLDiscardingListExtBinding) New(value s15.BearersSubjectToDLDiscardingList,

) (ENBEarlyStatusTransferTransparentContainerExtIEsExtField, error) {
	if b.inject == nil {
		return ENBEarlyStatusTransferTransparentContainerExtIEsExtField{}, aper.OperationError(fmt.Errorf("unbound extension binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ENBEarlyStatusTransferTransparentContainerExtIEsExtField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s15.BridgeBearersSubjectToDLDiscardingListValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return ENBEarlyStatusTransferTransparentContainerExtIEsExtField{}, aper.OperationError(fmt.Errorf("extension %d: %w", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return ENBEarlyStatusTransferTransparentContainerExtIEsExtField{}, aper.OperationError(err, "Value.New")
	}
	return ENBEarlyStatusTransferTransparentContainerExtIEsExtField{Id: b.info.ID, Criticality: b.info.Criticality, ExtensionValue: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b ENBEarlyStatusTransferTransparentContainerExtIEsBearersSubjectToDLDiscardingListExtBinding) Get(field *ENBEarlyStatusTransferTransparentContainerExtIEsExtField) (*s15.BearersSubjectToDLDiscardingList,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.ExtensionValue)
}

// ENBCPRelocationIndicationENBUES1APIDIEBinding binds ENBUES1APID to the ENBCPRelocationIndicationIEs object set of TS 36.413.
type ENBCPRelocationIndicationENBUES1APIDIEBinding struct {
	info   s00.FieldInfo
	codec  s00.ENBUES1APIDValueCodec
	inject func(s00.ENBUES1APID,

	) ENBCPRelocationIndicationIEValue

	get func(*ENBCPRelocationIndicationIEValue,

	) (*s00.ENBUES1APID,

		bool)
}

// Info returns the source descriptor for this binding.
func (b ENBCPRelocationIndicationENBUES1APIDIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b ENBCPRelocationIndicationENBUES1APIDIEBinding) Codec() s00.ENBUES1APIDValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b ENBCPRelocationIndicationENBUES1APIDIEBinding) New(value s00.ENBUES1APID,

) (ENBCPRelocationIndicationIEField, error) {
	if b.inject == nil {
		return ENBCPRelocationIndicationIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ENBCPRelocationIndicationIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s00.BridgeENBUES1APIDValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return ENBCPRelocationIndicationIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return ENBCPRelocationIndicationIEField{}, aper.OperationError(err, "Value.New")
	}
	return ENBCPRelocationIndicationIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b ENBCPRelocationIndicationENBUES1APIDIEBinding) Get(field *ENBCPRelocationIndicationIEField) (*s00.ENBUES1APID,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// ENBCPRelocationIndicationSTMSIIEBinding binds STMSI to the ENBCPRelocationIndicationIEs object set of TS 36.413.
type ENBCPRelocationIndicationSTMSIIEBinding struct {
	info   s00.FieldInfo
	codec  s28.STMSIValueCodec
	inject func(s28.STMSI,

	) ENBCPRelocationIndicationIEValue

	get func(*ENBCPRelocationIndicationIEValue,

	) (*s28.STMSI,

		bool)
}

// Info returns the source descriptor for this binding.
func (b ENBCPRelocationIndicationSTMSIIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b ENBCPRelocationIndicationSTMSIIEBinding) Codec() s28.STMSIValueCodec { return b.codec }

// New validates a source value and constructs its bound field.
func (b ENBCPRelocationIndicationSTMSIIEBinding) New(value s28.STMSI,

) (ENBCPRelocationIndicationIEField, error) {
	if b.inject == nil {
		return ENBCPRelocationIndicationIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ENBCPRelocationIndicationIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s28.BridgeSTMSIValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return ENBCPRelocationIndicationIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return ENBCPRelocationIndicationIEField{}, aper.OperationError(err, "Value.New")
	}
	return ENBCPRelocationIndicationIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b ENBCPRelocationIndicationSTMSIIEBinding) Get(field *ENBCPRelocationIndicationIEField) (*s28.STMSI,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// ENBCPRelocationIndicationEUTRANCGIIEBinding binds EUTRANCGI to the ENBCPRelocationIndicationIEs object set of TS 36.413.
type ENBCPRelocationIndicationEUTRANCGIIEBinding struct {
	info   s00.FieldInfo
	codec  s17.EUTRANCGIValueCodec
	inject func(s17.EUTRANCGI,

	) ENBCPRelocationIndicationIEValue

	get func(*ENBCPRelocationIndicationIEValue,

	) (*s17.EUTRANCGI,

		bool)
}

// Info returns the source descriptor for this binding.
func (b ENBCPRelocationIndicationEUTRANCGIIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b ENBCPRelocationIndicationEUTRANCGIIEBinding) Codec() s17.EUTRANCGIValueCodec { return b.codec }

// New validates a source value and constructs its bound field.
func (b ENBCPRelocationIndicationEUTRANCGIIEBinding) New(value s17.EUTRANCGI,

) (ENBCPRelocationIndicationIEField, error) {
	if b.inject == nil {
		return ENBCPRelocationIndicationIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ENBCPRelocationIndicationIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s17.BridgeEUTRANCGIValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return ENBCPRelocationIndicationIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return ENBCPRelocationIndicationIEField{}, aper.OperationError(err, "Value.New")
	}
	return ENBCPRelocationIndicationIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b ENBCPRelocationIndicationEUTRANCGIIEBinding) Get(field *ENBCPRelocationIndicationIEField) (*s17.EUTRANCGI,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// ENBCPRelocationIndicationTAIIEBinding binds TAI to the ENBCPRelocationIndicationIEs object set of TS 36.413.
type ENBCPRelocationIndicationTAIIEBinding struct {
	info   s00.FieldInfo
	codec  s32.TAIValueCodec
	inject func(s31.TAI,

	) ENBCPRelocationIndicationIEValue

	get func(*ENBCPRelocationIndicationIEValue,

	) (*s31.TAI,

		bool)
}

// Info returns the source descriptor for this binding.
func (b ENBCPRelocationIndicationTAIIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b ENBCPRelocationIndicationTAIIEBinding) Codec() s32.TAIValueCodec { return b.codec }

// New validates a source value and constructs its bound field.
func (b ENBCPRelocationIndicationTAIIEBinding) New(value s31.TAI,

) (ENBCPRelocationIndicationIEField, error) {
	if b.inject == nil {
		return ENBCPRelocationIndicationIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ENBCPRelocationIndicationIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s32.BridgeTAIValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return ENBCPRelocationIndicationIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return ENBCPRelocationIndicationIEField{}, aper.OperationError(err, "Value.New")
	}
	return ENBCPRelocationIndicationIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b ENBCPRelocationIndicationTAIIEBinding) Get(field *ENBCPRelocationIndicationIEField) (*s31.TAI,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// ENBCPRelocationIndicationULCPSecurityInformationIEBinding binds ULCPSecurityInformation to the ENBCPRelocationIndicationIEs object set of TS 36.413.
type ENBCPRelocationIndicationULCPSecurityInformationIEBinding struct {
	info   s00.FieldInfo
	codec  ULCPSecurityInformationValueCodec
	inject func(ULCPSecurityInformation,

	) ENBCPRelocationIndicationIEValue

	get func(*ENBCPRelocationIndicationIEValue,

	) (*ULCPSecurityInformation,

		bool)
}

// Info returns the source descriptor for this binding.
func (b ENBCPRelocationIndicationULCPSecurityInformationIEBinding) Info() s00.FieldInfo {
	return b.info
}

// Codec returns the complete value codec for this binding.
func (b ENBCPRelocationIndicationULCPSecurityInformationIEBinding) Codec() ULCPSecurityInformationValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b ENBCPRelocationIndicationULCPSecurityInformationIEBinding) New(value ULCPSecurityInformation,

) (ENBCPRelocationIndicationIEField, error) {
	if b.inject == nil {
		return ENBCPRelocationIndicationIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ENBCPRelocationIndicationIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := b.codec.encode(value, false, budget); err != nil {
		return ENBCPRelocationIndicationIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return ENBCPRelocationIndicationIEField{}, aper.OperationError(err, "Value.New")
	}
	return ENBCPRelocationIndicationIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b ENBCPRelocationIndicationULCPSecurityInformationIEBinding) Get(field *ENBCPRelocationIndicationIEField) (*ULCPSecurityInformation,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// ULCPSecurityInformationValueCodec is the concrete ValueCodec[ULCPSecurityInformation].
type ULCPSecurityInformationValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ULCPSecurityInformation,

		error)
	encode func(ULCPSecurityInformation,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ULCPSecurityInformation, aper.DecodeState,

	) (ULCPSecurityInformation, aper.Snapshot,

	)
	compare func(ULCPSecurityInformation, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ULCPSecurityInformationValueCodec) New(value ULCPSecurityInformation,

) (ULCPSecurityInformationAPERValue, error) {
	if c.encode == nil {
		return ULCPSecurityInformationAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ULCPSecurityInformationAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ULCPSecurityInformationAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ULCPSecurityInformationAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ULCPSecurityInformationValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ULCPSecurityInformationAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ULCPSecurityInformationAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ULCPSecurityInformationAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ULCPSecurityInformationAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ULCPSecurityInformationAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ULCPSecurityInformationValueCodec) EncodeAPER(value ULCPSecurityInformationAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c ULCPSecurityInformationValueCodec) encodeBudgetValue(value ULCPSecurityInformation,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ULCPSecurityInformationValueCodec) encodeChanged(value ULCPSecurityInformation,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ENBCPRelocationIndicationLTENTNTAIInformationIEBinding binds LTENTNTAIInformation to the ENBCPRelocationIndicationIEs object set of TS 36.413.
type ENBCPRelocationIndicationLTENTNTAIInformationIEBinding struct {
	info   s00.FieldInfo
	codec  s18.LTENTNTAIInformationValueCodec
	inject func(s18.LTENTNTAIInformation,

	) ENBCPRelocationIndicationIEValue

	get func(*ENBCPRelocationIndicationIEValue,

	) (*s18.LTENTNTAIInformation,

		bool)
}

// Info returns the source descriptor for this binding.
func (b ENBCPRelocationIndicationLTENTNTAIInformationIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b ENBCPRelocationIndicationLTENTNTAIInformationIEBinding) Codec() s18.LTENTNTAIInformationValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b ENBCPRelocationIndicationLTENTNTAIInformationIEBinding) New(value s18.LTENTNTAIInformation,

) (ENBCPRelocationIndicationIEField, error) {
	if b.inject == nil {
		return ENBCPRelocationIndicationIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ENBCPRelocationIndicationIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s18.BridgeLTENTNTAIInformationValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return ENBCPRelocationIndicationIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return ENBCPRelocationIndicationIEField{}, aper.OperationError(err, "Value.New")
	}
	return ENBCPRelocationIndicationIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b ENBCPRelocationIndicationLTENTNTAIInformationIEBinding) Get(field *ENBCPRelocationIndicationIEField) (*s18.LTENTNTAIInformation,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// ENBEarlyStatusTransferMMEUES1APIDIEBinding binds MMEUES1APID to the ENBEarlyStatusTransferIEs object set of TS 36.413.
type ENBEarlyStatusTransferMMEUES1APIDIEBinding struct {
	info   s00.FieldInfo
	codec  s01.MMEUES1APIDValueCodec
	inject func(s00.MMEUES1APID,

	) ENBEarlyStatusTransferIEValue

	get func(*ENBEarlyStatusTransferIEValue,

	) (*s00.MMEUES1APID,

		bool)
}

// Info returns the source descriptor for this binding.
func (b ENBEarlyStatusTransferMMEUES1APIDIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b ENBEarlyStatusTransferMMEUES1APIDIEBinding) Codec() s01.MMEUES1APIDValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b ENBEarlyStatusTransferMMEUES1APIDIEBinding) New(value s00.MMEUES1APID,

) (ENBEarlyStatusTransferIEField, error) {
	if b.inject == nil {
		return ENBEarlyStatusTransferIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ENBEarlyStatusTransferIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s01.BridgeMMEUES1APIDValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return ENBEarlyStatusTransferIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return ENBEarlyStatusTransferIEField{}, aper.OperationError(err, "Value.New")
	}
	return ENBEarlyStatusTransferIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b ENBEarlyStatusTransferMMEUES1APIDIEBinding) Get(field *ENBEarlyStatusTransferIEField) (*s00.MMEUES1APID,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// ENBEarlyStatusTransferENBUES1APIDIEBinding binds ENBUES1APID to the ENBEarlyStatusTransferIEs object set of TS 36.413.
type ENBEarlyStatusTransferENBUES1APIDIEBinding struct {
	info   s00.FieldInfo
	codec  s00.ENBUES1APIDValueCodec
	inject func(s00.ENBUES1APID,

	) ENBEarlyStatusTransferIEValue

	get func(*ENBEarlyStatusTransferIEValue,

	) (*s00.ENBUES1APID,

		bool)
}

// Info returns the source descriptor for this binding.
func (b ENBEarlyStatusTransferENBUES1APIDIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b ENBEarlyStatusTransferENBUES1APIDIEBinding) Codec() s00.ENBUES1APIDValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b ENBEarlyStatusTransferENBUES1APIDIEBinding) New(value s00.ENBUES1APID,

) (ENBEarlyStatusTransferIEField, error) {
	if b.inject == nil {
		return ENBEarlyStatusTransferIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ENBEarlyStatusTransferIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s00.BridgeENBUES1APIDValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return ENBEarlyStatusTransferIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return ENBEarlyStatusTransferIEField{}, aper.OperationError(err, "Value.New")
	}
	return ENBEarlyStatusTransferIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b ENBEarlyStatusTransferENBUES1APIDIEBinding) Get(field *ENBEarlyStatusTransferIEField) (*s00.ENBUES1APID,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// ENBEarlyStatusTransferENBEarlyStatusTransferTransparentContainerIEBinding binds ENBEarlyStatusTransferTransparentContainer to the ENBEarlyStatusTransferIEs object set of TS 36.413.
type ENBEarlyStatusTransferENBEarlyStatusTransferTransparentContainerIEBinding struct {
	info   s00.FieldInfo
	codec  ENBEarlyStatusTransferTransparentContainerValueCodec
	inject func(ENBEarlyStatusTransferTransparentContainer,

	) ENBEarlyStatusTransferIEValue

	get func(*ENBEarlyStatusTransferIEValue,

	) (*ENBEarlyStatusTransferTransparentContainer,

		bool)
}

// Info returns the source descriptor for this binding.
func (b ENBEarlyStatusTransferENBEarlyStatusTransferTransparentContainerIEBinding) Info() s00.FieldInfo {
	return b.info
}

// Codec returns the complete value codec for this binding.
func (b ENBEarlyStatusTransferENBEarlyStatusTransferTransparentContainerIEBinding) Codec() ENBEarlyStatusTransferTransparentContainerValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b ENBEarlyStatusTransferENBEarlyStatusTransferTransparentContainerIEBinding) New(value ENBEarlyStatusTransferTransparentContainer,

) (ENBEarlyStatusTransferIEField, error) {
	if b.inject == nil {
		return ENBEarlyStatusTransferIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ENBEarlyStatusTransferIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := b.codec.encode(value, false, budget); err != nil {
		return ENBEarlyStatusTransferIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return ENBEarlyStatusTransferIEField{}, aper.OperationError(err, "Value.New")
	}
	return ENBEarlyStatusTransferIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b ENBEarlyStatusTransferENBEarlyStatusTransferTransparentContainerIEBinding) Get(field *ENBEarlyStatusTransferIEField) (*ENBEarlyStatusTransferTransparentContainer,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// ENBEarlyStatusTransferTransparentContainerValueCodec is the concrete ValueCodec[ENBEarlyStatusTransferTransparentContainer].
type ENBEarlyStatusTransferTransparentContainerValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ENBEarlyStatusTransferTransparentContainer,

		error)
	encode func(ENBEarlyStatusTransferTransparentContainer,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ENBEarlyStatusTransferTransparentContainer, aper.DecodeState,

	) (ENBEarlyStatusTransferTransparentContainer, aper.Snapshot,

	)
	compare func(ENBEarlyStatusTransferTransparentContainer, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ENBEarlyStatusTransferTransparentContainerValueCodec) New(value ENBEarlyStatusTransferTransparentContainer,

) (ENBEarlyStatusTransferTransparentContainerAPERValue, error) {
	if c.encode == nil {
		return ENBEarlyStatusTransferTransparentContainerAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ENBEarlyStatusTransferTransparentContainerAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ENBEarlyStatusTransferTransparentContainerAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ENBEarlyStatusTransferTransparentContainerAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ENBEarlyStatusTransferTransparentContainerValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ENBEarlyStatusTransferTransparentContainerAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ENBEarlyStatusTransferTransparentContainerAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ENBEarlyStatusTransferTransparentContainerAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ENBEarlyStatusTransferTransparentContainerAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ENBEarlyStatusTransferTransparentContainerAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ENBEarlyStatusTransferTransparentContainerValueCodec) EncodeAPER(value ENBEarlyStatusTransferTransparentContainerAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c ENBEarlyStatusTransferTransparentContainerValueCodec) encodeBudgetValue(value ENBEarlyStatusTransferTransparentContainer,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ENBEarlyStatusTransferTransparentContainerValueCodec) encodeChanged(value ENBEarlyStatusTransferTransparentContainer,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// UESecurityCapabilitiesValueCodec is the concrete ValueCodec[UESecurityCapabilities].
type UESecurityCapabilitiesValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (UESecurityCapabilities,

		error)
	encode func(UESecurityCapabilities,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(UESecurityCapabilities, aper.DecodeState,

	) (UESecurityCapabilities, aper.Snapshot,

	)
	compare func(UESecurityCapabilities, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c UESecurityCapabilitiesValueCodec) New(value UESecurityCapabilities,

) (UESecurityCapabilitiesAPERValue, error) {
	if c.encode == nil {
		return UESecurityCapabilitiesAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return UESecurityCapabilitiesAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return UESecurityCapabilitiesAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return UESecurityCapabilitiesAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c UESecurityCapabilitiesValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (UESecurityCapabilitiesAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return UESecurityCapabilitiesAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return UESecurityCapabilitiesAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return UESecurityCapabilitiesAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return UESecurityCapabilitiesAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c UESecurityCapabilitiesValueCodec) EncodeAPER(value UESecurityCapabilitiesAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c UESecurityCapabilitiesValueCodec) encodeBudgetValue(value UESecurityCapabilities,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c UESecurityCapabilitiesValueCodec) encodeChanged(value UESecurityCapabilities,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// UESidelinkAggregateMaximumBitrateValueCodec is the concrete ValueCodec[UESidelinkAggregateMaximumBitrate].
type UESidelinkAggregateMaximumBitrateValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (UESidelinkAggregateMaximumBitrate,

		error)
	encode func(UESidelinkAggregateMaximumBitrate,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(UESidelinkAggregateMaximumBitrate, aper.DecodeState,

	) (UESidelinkAggregateMaximumBitrate, aper.Snapshot,

	)
	compare func(UESidelinkAggregateMaximumBitrate, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c UESidelinkAggregateMaximumBitrateValueCodec) New(value UESidelinkAggregateMaximumBitrate,

) (UESidelinkAggregateMaximumBitrateAPERValue, error) {
	if c.encode == nil {
		return UESidelinkAggregateMaximumBitrateAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return UESidelinkAggregateMaximumBitrateAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return UESidelinkAggregateMaximumBitrateAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return UESidelinkAggregateMaximumBitrateAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c UESidelinkAggregateMaximumBitrateValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (UESidelinkAggregateMaximumBitrateAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return UESidelinkAggregateMaximumBitrateAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return UESidelinkAggregateMaximumBitrateAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return UESidelinkAggregateMaximumBitrateAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return UESidelinkAggregateMaximumBitrateAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c UESidelinkAggregateMaximumBitrateValueCodec) EncodeAPER(value UESidelinkAggregateMaximumBitrateAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c UESidelinkAggregateMaximumBitrateValueCodec) encodeBudgetValue(value UESidelinkAggregateMaximumBitrate,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c UESidelinkAggregateMaximumBitrateValueCodec) encodeChanged(value UESidelinkAggregateMaximumBitrate,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// MMEEarlyStatusTransferMMEUES1APIDIEBinding binds MMEUES1APID to the MMEEarlyStatusTransferIEs object set of TS 36.413.
type MMEEarlyStatusTransferMMEUES1APIDIEBinding struct {
	info   s00.FieldInfo
	codec  s01.MMEUES1APIDValueCodec
	inject func(s00.MMEUES1APID,

	) MMEEarlyStatusTransferIEValue

	get func(*MMEEarlyStatusTransferIEValue,

	) (*s00.MMEUES1APID,

		bool)
}

// Info returns the source descriptor for this binding.
func (b MMEEarlyStatusTransferMMEUES1APIDIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b MMEEarlyStatusTransferMMEUES1APIDIEBinding) Codec() s01.MMEUES1APIDValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b MMEEarlyStatusTransferMMEUES1APIDIEBinding) New(value s00.MMEUES1APID,

) (MMEEarlyStatusTransferIEField, error) {
	if b.inject == nil {
		return MMEEarlyStatusTransferIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return MMEEarlyStatusTransferIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s01.BridgeMMEUES1APIDValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return MMEEarlyStatusTransferIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return MMEEarlyStatusTransferIEField{}, aper.OperationError(err, "Value.New")
	}
	return MMEEarlyStatusTransferIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b MMEEarlyStatusTransferMMEUES1APIDIEBinding) Get(field *MMEEarlyStatusTransferIEField) (*s00.MMEUES1APID,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// MMEEarlyStatusTransferENBUES1APIDIEBinding binds ENBUES1APID to the MMEEarlyStatusTransferIEs object set of TS 36.413.
type MMEEarlyStatusTransferENBUES1APIDIEBinding struct {
	info   s00.FieldInfo
	codec  s00.ENBUES1APIDValueCodec
	inject func(s00.ENBUES1APID,

	) MMEEarlyStatusTransferIEValue

	get func(*MMEEarlyStatusTransferIEValue,

	) (*s00.ENBUES1APID,

		bool)
}

// Info returns the source descriptor for this binding.
func (b MMEEarlyStatusTransferENBUES1APIDIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b MMEEarlyStatusTransferENBUES1APIDIEBinding) Codec() s00.ENBUES1APIDValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b MMEEarlyStatusTransferENBUES1APIDIEBinding) New(value s00.ENBUES1APID,

) (MMEEarlyStatusTransferIEField, error) {
	if b.inject == nil {
		return MMEEarlyStatusTransferIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return MMEEarlyStatusTransferIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s00.BridgeENBUES1APIDValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return MMEEarlyStatusTransferIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return MMEEarlyStatusTransferIEField{}, aper.OperationError(err, "Value.New")
	}
	return MMEEarlyStatusTransferIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b MMEEarlyStatusTransferENBUES1APIDIEBinding) Get(field *MMEEarlyStatusTransferIEField) (*s00.ENBUES1APID,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// MMEEarlyStatusTransferENBEarlyStatusTransferTransparentContainerIEBinding binds ENBEarlyStatusTransferTransparentContainer to the MMEEarlyStatusTransferIEs object set of TS 36.413.
type MMEEarlyStatusTransferENBEarlyStatusTransferTransparentContainerIEBinding struct {
	info   s00.FieldInfo
	codec  ENBEarlyStatusTransferTransparentContainerValueCodec
	inject func(ENBEarlyStatusTransferTransparentContainer,

	) MMEEarlyStatusTransferIEValue

	get func(*MMEEarlyStatusTransferIEValue,

	) (*ENBEarlyStatusTransferTransparentContainer,

		bool)
}

// Info returns the source descriptor for this binding.
func (b MMEEarlyStatusTransferENBEarlyStatusTransferTransparentContainerIEBinding) Info() s00.FieldInfo {
	return b.info
}

// Codec returns the complete value codec for this binding.
func (b MMEEarlyStatusTransferENBEarlyStatusTransferTransparentContainerIEBinding) Codec() ENBEarlyStatusTransferTransparentContainerValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b MMEEarlyStatusTransferENBEarlyStatusTransferTransparentContainerIEBinding) New(value ENBEarlyStatusTransferTransparentContainer,

) (MMEEarlyStatusTransferIEField, error) {
	if b.inject == nil {
		return MMEEarlyStatusTransferIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return MMEEarlyStatusTransferIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := b.codec.encode(value, false, budget); err != nil {
		return MMEEarlyStatusTransferIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return MMEEarlyStatusTransferIEField{}, aper.OperationError(err, "Value.New")
	}
	return MMEEarlyStatusTransferIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b MMEEarlyStatusTransferENBEarlyStatusTransferTransparentContainerIEBinding) Get(field *MMEEarlyStatusTransferIEField) (*ENBEarlyStatusTransferTransparentContainer,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// UEContextReleaseCommandUES1APIDsIEBinding binds UES1APIDs to the UEContextReleaseCommand-IEs object set of TS 36.413.
type UEContextReleaseCommandUES1APIDsIEBinding struct {
	info   s00.FieldInfo
	codec  UES1APIDsValueCodec
	inject func(UES1APIDs,

	) UEContextReleaseCommandIEValue

	get func(*UEContextReleaseCommandIEValue,

	) (*UES1APIDs,

		bool)
}

// Info returns the source descriptor for this binding.
func (b UEContextReleaseCommandUES1APIDsIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b UEContextReleaseCommandUES1APIDsIEBinding) Codec() UES1APIDsValueCodec { return b.codec }

// New validates a source value and constructs its bound field.
func (b UEContextReleaseCommandUES1APIDsIEBinding) New(value UES1APIDs,

) (UEContextReleaseCommandIEField, error) {
	if b.inject == nil {
		return UEContextReleaseCommandIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return UEContextReleaseCommandIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := b.codec.encode(value, false, budget); err != nil {
		return UEContextReleaseCommandIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return UEContextReleaseCommandIEField{}, aper.OperationError(err, "Value.New")
	}
	return UEContextReleaseCommandIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b UEContextReleaseCommandUES1APIDsIEBinding) Get(field *UEContextReleaseCommandIEField) (*UES1APIDs,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// UES1APIDsValueCodec is the concrete ValueCodec[UES1APIDs].
type UES1APIDsValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (UES1APIDs,

		error)
	encode func(UES1APIDs,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(UES1APIDs, aper.DecodeState,

	) (UES1APIDs, aper.Snapshot,

	)
	compare func(UES1APIDs, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c UES1APIDsValueCodec) New(value UES1APIDs,

) (UES1APIDsAPERValue, error) {
	if c.encode == nil {
		return UES1APIDsAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return UES1APIDsAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return UES1APIDsAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return UES1APIDsAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c UES1APIDsValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (UES1APIDsAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return UES1APIDsAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return UES1APIDsAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return UES1APIDsAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return UES1APIDsAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c UES1APIDsValueCodec) EncodeAPER(value UES1APIDsAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c UES1APIDsValueCodec) encodeBudgetValue(value UES1APIDs,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c UES1APIDsValueCodec) encodeChanged(value UES1APIDs,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// UEContextReleaseCommandCauseIEBinding binds Cause to the UEContextReleaseCommand-IEs object set of TS 36.413.
type UEContextReleaseCommandCauseIEBinding struct {
	info   s00.FieldInfo
	codec  s14.CauseValueCodec
	inject func(s14.Cause,

	) UEContextReleaseCommandIEValue

	get func(*UEContextReleaseCommandIEValue,

	) (*s14.Cause,

		bool)
}

// Info returns the source descriptor for this binding.
func (b UEContextReleaseCommandCauseIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b UEContextReleaseCommandCauseIEBinding) Codec() s14.CauseValueCodec { return b.codec }

// New validates a source value and constructs its bound field.
func (b UEContextReleaseCommandCauseIEBinding) New(value s14.Cause,

) (UEContextReleaseCommandIEField, error) {
	if b.inject == nil {
		return UEContextReleaseCommandIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return UEContextReleaseCommandIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s14.BridgeCauseValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return UEContextReleaseCommandIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return UEContextReleaseCommandIEField{}, aper.OperationError(err, "Value.New")
	}
	return UEContextReleaseCommandIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b UEContextReleaseCommandCauseIEBinding) Get(field *UEContextReleaseCommandIEField) (*s14.Cause,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// ENBCPRelocationIndicationValueCodec is the concrete ValueCodec[ENBCPRelocationIndication].
type ENBCPRelocationIndicationValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ENBCPRelocationIndication,

		error)
	encode func(ENBCPRelocationIndication,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ENBCPRelocationIndication, aper.DecodeState,

	) (ENBCPRelocationIndication, aper.Snapshot,

	)
	compare func(ENBCPRelocationIndication, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ENBCPRelocationIndicationValueCodec) New(value ENBCPRelocationIndication,

) (ENBCPRelocationIndicationAPERValue, error) {
	if c.encode == nil {
		return ENBCPRelocationIndicationAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ENBCPRelocationIndicationAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ENBCPRelocationIndicationAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ENBCPRelocationIndicationAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ENBCPRelocationIndicationValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ENBCPRelocationIndicationAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ENBCPRelocationIndicationAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ENBCPRelocationIndicationAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ENBCPRelocationIndicationAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ENBCPRelocationIndicationAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ENBCPRelocationIndicationValueCodec) EncodeAPER(value ENBCPRelocationIndicationAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c ENBCPRelocationIndicationValueCodec) encodeBudgetValue(value ENBCPRelocationIndication,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ENBCPRelocationIndicationValueCodec) encodeChanged(value ENBCPRelocationIndication,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// UEContextReleaseCommandValueCodec is the concrete ValueCodec[UEContextReleaseCommand].
type UEContextReleaseCommandValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (UEContextReleaseCommand,

		error)
	encode func(UEContextReleaseCommand,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(UEContextReleaseCommand, aper.DecodeState,

	) (UEContextReleaseCommand, aper.Snapshot,

	)
	compare func(UEContextReleaseCommand, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c UEContextReleaseCommandValueCodec) New(value UEContextReleaseCommand,

) (UEContextReleaseCommandAPERValue, error) {
	if c.encode == nil {
		return UEContextReleaseCommandAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return UEContextReleaseCommandAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return UEContextReleaseCommandAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return UEContextReleaseCommandAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c UEContextReleaseCommandValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (UEContextReleaseCommandAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return UEContextReleaseCommandAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return UEContextReleaseCommandAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return UEContextReleaseCommandAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return UEContextReleaseCommandAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c UEContextReleaseCommandValueCodec) EncodeAPER(value UEContextReleaseCommandAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c UEContextReleaseCommandValueCodec) encodeBudgetValue(value UEContextReleaseCommand,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c UEContextReleaseCommandValueCodec) encodeChanged(value UEContextReleaseCommand,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// UERadioCapabilityMatchResponseValueCodec is the concrete ValueCodec[UERadioCapabilityMatchResponse].
type UERadioCapabilityMatchResponseValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (UERadioCapabilityMatchResponse,

		error)
	encode func(UERadioCapabilityMatchResponse,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(UERadioCapabilityMatchResponse, aper.DecodeState,

	) (UERadioCapabilityMatchResponse, aper.Snapshot,

	)
	compare func(UERadioCapabilityMatchResponse, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c UERadioCapabilityMatchResponseValueCodec) New(value UERadioCapabilityMatchResponse,

) (UERadioCapabilityMatchResponseAPERValue, error) {
	if c.encode == nil {
		return UERadioCapabilityMatchResponseAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return UERadioCapabilityMatchResponseAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return UERadioCapabilityMatchResponseAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return UERadioCapabilityMatchResponseAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c UERadioCapabilityMatchResponseValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (UERadioCapabilityMatchResponseAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return UERadioCapabilityMatchResponseAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return UERadioCapabilityMatchResponseAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return UERadioCapabilityMatchResponseAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return UERadioCapabilityMatchResponseAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c UERadioCapabilityMatchResponseValueCodec) EncodeAPER(value UERadioCapabilityMatchResponseAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c UERadioCapabilityMatchResponseValueCodec) encodeBudgetValue(value UERadioCapabilityMatchResponse,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c UERadioCapabilityMatchResponseValueCodec) encodeChanged(value UERadioCapabilityMatchResponse,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// UES1APIDPairValueCodec is the concrete ValueCodec[UES1APIDPair].
type UES1APIDPairValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (UES1APIDPair,

		error)
	encode func(UES1APIDPair,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(UES1APIDPair, aper.DecodeState,

	) (UES1APIDPair, aper.Snapshot,

	)
	compare func(UES1APIDPair, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c UES1APIDPairValueCodec) New(value UES1APIDPair,

) (UES1APIDPairAPERValue, error) {
	if c.encode == nil {
		return UES1APIDPairAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return UES1APIDPairAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return UES1APIDPairAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return UES1APIDPairAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c UES1APIDPairValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (UES1APIDPairAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return UES1APIDPairAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return UES1APIDPairAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return UES1APIDPairAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return UES1APIDPairAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c UES1APIDPairValueCodec) EncodeAPER(value UES1APIDPairAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c UES1APIDPairValueCodec) encodeBudgetValue(value UES1APIDPair,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c UES1APIDPairValueCodec) encodeChanged(value UES1APIDPair,

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
func BridgeUEContextReleaseCommandIEValueValidateS1APIEContainer(fields UEContextReleaseCommandIEContainer, rows []s00.FieldInfo, path string, budget *aper.DecodeBudget,

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
func BridgeUERadioCapabilityMatchResponseIEValueValidateS1APIEContainer(fields s24.UERadioCapabilityMatchResponseIEContainer, rows []s00.FieldInfo, path string, budget *aper.DecodeBudget,

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
		if !s24.BridgeUERadioCapabilityMatchResponseIEValueMethodMatchesID(field.Value, field.Id, budget) {
			rule := s24.BridgeUERadioCapabilityMatchResponseIEValueMethodRule(field.Value)
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.ValueIDMismatch, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: aper.Path(fmt.Sprintf("%s.id", location.Path))}, Table: func() s00.TableID {
				sealed := s00.TableID{}
				*s00.BridgeTableIDFieldSource(&sealed) = rule.Assignment
				return sealed
			}(), IEID: field.Id, HasIEID: true, Rule: s26.BridgeS1apValidationRule(s00.ValueIDMismatch), RelatedRules: []aper.SourceRule{rule}})
		}
		rank, allowed := byID[field.Id]
		table := func() s00.TableID {
			sealed := s00.TableID{}
			*s00.BridgeTableIDFieldSource(&sealed) = s24.BridgeUERadioCapabilityMatchResponseIEValueMethodRule(field.Value).Assignment
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
func BridgeENBCPRelocationIndicationIEValueValidateS1APIEContainer(fields ENBCPRelocationIndicationIEContainer, rows []s00.FieldInfo, path string, budget *aper.DecodeBudget,

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
func BridgeUES1APIDPairExtIEsValueValidateS1APExtensionContainer(fields s12.UES1APIDPairExtIEsExtContainer, rows []s00.FieldInfo, path string, budget *aper.DecodeBudget) s21.ValidationReport {
	bb := aper.NewBudgetBuffer(budget)
	if err := aper.ChargeSlice[s12.UES1APIDPairExtIEsIEField](bb, uint64(len(fields))); err != nil {
		return func() s21.ValidationReport {
			sealed := s21.ValidationReport{}
			*s21.BridgeValidationReportFieldErr(&sealed) = err
			*s21.BridgeValidationReportFieldBudget(&sealed) = budget
			return sealed
		}()
	}
	asIE := make(s12.UES1APIDPairExtIEsIEContainer, len(fields))
	for i := range fields {
		asIE[i].Id = fields[i].Id
		asIE[i].Criticality = fields[i].Criticality
		asIE[i].Value = fields[i].ExtensionValue
	}
	return BridgeUES1APIDPairExtIEsValueValidateS1APIEContainer(asIE, rows, path, budget)
}
func BridgeUESecurityCapabilitiesExtIEsValueValidateS1APExtensionContainer(fields s12.UESecurityCapabilitiesExtIEsExtContainer, rows []s00.FieldInfo, path string, budget *aper.DecodeBudget) s21.ValidationReport {
	bb := aper.NewBudgetBuffer(budget)
	if err := aper.ChargeSlice[s12.UESecurityCapabilitiesExtIEsIEField](bb, uint64(len(fields))); err != nil {
		return func() s21.ValidationReport {
			sealed := s21.ValidationReport{}
			*s21.BridgeValidationReportFieldErr(&sealed) = err
			*s21.BridgeValidationReportFieldBudget(&sealed) = budget
			return sealed
		}()
	}
	asIE := make(s12.UESecurityCapabilitiesExtIEsIEContainer, len(fields))
	for i := range fields {
		asIE[i].Id = fields[i].Id
		asIE[i].Criticality = fields[i].Criticality
		asIE[i].Value = fields[i].ExtensionValue
	}
	return BridgeUESecurityCapabilitiesExtIEsValueValidateS1APIEContainer(asIE, rows, path, budget)
}
func BridgeUESidelinkAggregateMaximumBitratesExtIEsValueValidateS1APExtensionContainer(fields s12.UESidelinkAggregateMaximumBitratesExtIEsExtContainer, rows []s00.FieldInfo, path string, budget *aper.DecodeBudget) s21.ValidationReport {
	bb := aper.NewBudgetBuffer(budget)
	if err := aper.ChargeSlice[s12.UESidelinkAggregateMaximumBitratesExtIEsIEField](bb, uint64(len(fields))); err != nil {
		return func() s21.ValidationReport {
			sealed := s21.ValidationReport{}
			*s21.BridgeValidationReportFieldErr(&sealed) = err
			*s21.BridgeValidationReportFieldBudget(&sealed) = budget
			return sealed
		}()
	}
	asIE := make(s12.UESidelinkAggregateMaximumBitratesExtIEsIEContainer, len(fields))
	for i := range fields {
		asIE[i].Id = fields[i].Id
		asIE[i].Criticality = fields[i].Criticality
		asIE[i].Value = fields[i].ExtensionValue
	}
	return BridgeUESidelinkAggregateMaximumBitratesExtIEsValueValidateS1APIEContainer(asIE, rows, path, budget)
}
func BridgeULCPSecurityInformationExtIEsValueValidateS1APExtensionContainer(fields s12.ULCPSecurityInformationExtIEsExtContainer, rows []s00.FieldInfo, path string, budget *aper.DecodeBudget) s21.ValidationReport {
	bb := aper.NewBudgetBuffer(budget)
	if err := aper.ChargeSlice[s12.ULCPSecurityInformationExtIEsIEField](bb, uint64(len(fields))); err != nil {
		return func() s21.ValidationReport {
			sealed := s21.ValidationReport{}
			*s21.BridgeValidationReportFieldErr(&sealed) = err
			*s21.BridgeValidationReportFieldBudget(&sealed) = budget
			return sealed
		}()
	}
	asIE := make(s12.ULCPSecurityInformationExtIEsIEContainer, len(fields))
	for i := range fields {
		asIE[i].Id = fields[i].Id
		asIE[i].Criticality = fields[i].Criticality
		asIE[i].Value = fields[i].ExtensionValue
	}
	return BridgeULCPSecurityInformationExtIEsValueValidateS1APIEContainer(asIE, rows, path, budget)
}

// ENBCPRelocationIndicationIEValueERABIEContainerListCodec constructs the E-RAB-IE-ContainerList {{ENBCPRelocationIndicationIEs}} codec of TS 36.413.
func ENBCPRelocationIndicationIEValueERABIEContainerListCodec(table s00.ENBCPRelocationIndicationIEValueIETable) ENBCPRelocationIndicationIEValueERABIEContainerListValueCodec {
	codec := ENBCPRelocationIndicationIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if codec.decode == nil {
		return ENBCPRelocationIndicationIEValueERABIEContainerListValueCodec{}
	}
	return ENBCPRelocationIndicationIEValueERABIEContainerListValueCodec{decode: func(data []byte, options aper.DecodeState) (ENBCPRelocationIndicationIEValueERABIEContainerList, error) {
		value, err := codec.decode(data, options)
		return ENBCPRelocationIndicationIEValueERABIEContainerList(value), err
	}, encode: func(value ENBCPRelocationIndicationIEValueERABIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return codec.encode(ENBCPRelocationIndicationIEContainer(value), fresh, budget)
	}, capture: func(v ENBCPRelocationIndicationIEValueERABIEContainerList, options aper.DecodeState) (ENBCPRelocationIndicationIEValueERABIEContainerList, aper.Snapshot) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeENBCPRelocationIndicationIEValueCaptureS1APERABIEContainerList(&v, &s)
		var root aper.Snapshot
		s.End(f, &root, false)
		return v, root
	}, compare: func(v ENBCPRelocationIndicationIEValueERABIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
	) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		BridgeENBCPRelocationIndicationIEValueCompareS1APERABIEContainerList(&v, &s)
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

// UEContextReleaseCommandIEValueERABIEContainerListCodec constructs the E-RAB-IE-ContainerList {{UEContextReleaseCommand-IEs}} codec of TS 36.413.
func UEContextReleaseCommandIEValueERABIEContainerListCodec(table s00.UEContextReleaseCommandIEValueIETable) UEContextReleaseCommandIEValueERABIEContainerListValueCodec {
	codec := UEContextReleaseCommandIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if codec.decode == nil {
		return UEContextReleaseCommandIEValueERABIEContainerListValueCodec{}
	}
	return UEContextReleaseCommandIEValueERABIEContainerListValueCodec{decode: func(data []byte, options aper.DecodeState) (UEContextReleaseCommandIEValueERABIEContainerList, error) {
		value, err := codec.decode(data, options)
		return UEContextReleaseCommandIEValueERABIEContainerList(value), err
	}, encode: func(value UEContextReleaseCommandIEValueERABIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return codec.encode(UEContextReleaseCommandIEContainer(value), fresh, budget)
	}, capture: func(v UEContextReleaseCommandIEValueERABIEContainerList, options aper.DecodeState) (UEContextReleaseCommandIEValueERABIEContainerList, aper.Snapshot) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeUEContextReleaseCommandIEValueCaptureS1APERABIEContainerList(&v, &s)
		var root aper.Snapshot
		s.End(f, &root, false)
		return v, root
	}, compare: func(v UEContextReleaseCommandIEValueERABIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
	) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		BridgeUEContextReleaseCommandIEValueCompareS1APERABIEContainerList(&v, &s)
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

// UERadioCapabilityMatchResponseIEValueERABIEContainerListCodec constructs the E-RAB-IE-ContainerList {{UERadioCapabilityMatchResponseIEs}} codec of TS 36.413.
func UERadioCapabilityMatchResponseIEValueERABIEContainerListCodec(table s00.UERadioCapabilityMatchResponseIEValueIETable) s24.UERadioCapabilityMatchResponseIEValueERABIEContainerListValueCodec {
	codec := UERadioCapabilityMatchResponseIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if *s24.BridgeUERadioCapabilityMatchResponseIEContainerValueCodecFieldDecode(&codec) == nil {
		return s24.UERadioCapabilityMatchResponseIEValueERABIEContainerListValueCodec{}
	}
	return func() s24.UERadioCapabilityMatchResponseIEValueERABIEContainerListValueCodec {
		sealed := s24.UERadioCapabilityMatchResponseIEValueERABIEContainerListValueCodec{}
		*s24.BridgeUERadioCapabilityMatchResponseIEValueERABIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s24.UERadioCapabilityMatchResponseIEValueERABIEContainerList, error) {
			value, err := (*s24.BridgeUERadioCapabilityMatchResponseIEContainerValueCodecFieldDecode(&codec))(data, options)
			return s24.UERadioCapabilityMatchResponseIEValueERABIEContainerList(value), err
		}
		*s24.BridgeUERadioCapabilityMatchResponseIEValueERABIEContainerListValueCodecFieldEncode(&sealed) = func(value s24.UERadioCapabilityMatchResponseIEValueERABIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s24.BridgeUERadioCapabilityMatchResponseIEContainerValueCodecFieldEncode(&codec))(s24.UERadioCapabilityMatchResponseIEContainer(value), fresh, budget)
		}
		*s24.BridgeUERadioCapabilityMatchResponseIEValueERABIEContainerListValueCodecFieldCapture(&sealed) = func(v s24.UERadioCapabilityMatchResponseIEValueERABIEContainerList, options aper.DecodeState) (s24.UERadioCapabilityMatchResponseIEValueERABIEContainerList, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s36.BridgeUERadioCapabilityMatchResponseIEValueCaptureS1APERABIEContainerList(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s24.BridgeUERadioCapabilityMatchResponseIEValueERABIEContainerListValueCodecFieldCompare(&sealed) = func(v s24.UERadioCapabilityMatchResponseIEValueERABIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeUERadioCapabilityMatchResponseIEValueCompareS1APERABIEContainerList(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s24.BridgeUERadioCapabilityMatchResponseIEValueERABIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ERABIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// ENBEarlyStatusTransferTransparentContainerExtIEsValueExtensionFieldTableCodec constructs the ProtocolExtensionField {{ENB-EarlyStatusTransfer-TransparentContainer-ExtIEs}} codec of TS 36.413.
func ENBEarlyStatusTransferTransparentContainerExtIEsValueExtensionFieldTableCodec(table s00.ENBEarlyStatusTransferTransparentContainerExtIEsValueExtensionTable) ENBEarlyStatusTransferTransparentContainerExtIEsExtFieldValueCodec {
	if !*s00.BridgeENBEarlyStatusTransferTransparentContainerExtIEsValueExtensionTableFieldBound(&table) {
		return ENBEarlyStatusTransferTransparentContainerExtIEsExtFieldValueCodec{}
	}
	return ENBEarlyStatusTransferTransparentContainerExtIEsExtFieldValueCodec{decode: func(data []byte, options aper.DecodeState) (ENBEarlyStatusTransferTransparentContainerExtIEsExtField, error) {
		var field ENBEarlyStatusTransferTransparentContainerExtIEsExtField
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
	}, encode: func(field ENBEarlyStatusTransferTransparentContainerExtIEsExtField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		bb := aper.NewBudgetBuffer(budget)
		if err := field.marshalAPERTo(bb, fresh); err != nil {
			return nil, err
		}
		return bb.CompleteBytes(), nil
	}, capture: func(v ENBEarlyStatusTransferTransparentContainerExtIEsExtField, options aper.DecodeState) (ENBEarlyStatusTransferTransparentContainerExtIEsExtField, aper.Snapshot,
	) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeENBEarlyStatusTransferTransparentContainerExtIEsValueCaptureS1APProtocolExtensionField(&v, &s)
		var root aper.Snapshot
		s.End(f, &root,
			false)
		return v, root
	}, compare: func(v ENBEarlyStatusTransferTransparentContainerExtIEsExtField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
	) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		BridgeENBEarlyStatusTransferTransparentContainerExtIEsValueCompareS1APProtocolExtensionField(&v, &s)
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

// UES1APIDPairExtIEsValueExtensionFieldTableCodec constructs the ProtocolExtensionField {{UE-S1AP-ID-pair-ExtIEs}} codec of TS 36.413.
func UES1APIDPairExtIEsValueExtensionFieldTableCodec(table s00.UES1APIDPairExtIEsValueExtensionTable) s12.UES1APIDPairExtIEsExtFieldValueCodec {
	if !*s00.BridgeUES1APIDPairExtIEsValueExtensionTableFieldBound(&table) {
		return s12.UES1APIDPairExtIEsExtFieldValueCodec{}
	}
	return func() s12.UES1APIDPairExtIEsExtFieldValueCodec {
		sealed := s12.UES1APIDPairExtIEsExtFieldValueCodec{}
		*s12.BridgeUES1APIDPairExtIEsExtFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s12.UES1APIDPairExtIEsExtField, error) {
			var field s12.UES1APIDPairExtIEsExtField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s12.BridgeUES1APIDPairExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, err
			}
			if _, err := aper.CaptureFinalBits(bb, "ProtocolExtensionField"); err != nil {
				return field, err
			}
			return field, nil
		}
		*s12.BridgeUES1APIDPairExtIEsExtFieldValueCodecFieldEncode(&sealed) = func(field s12.UES1APIDPairExtIEsExtField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s12.BridgeUES1APIDPairExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s12.BridgeUES1APIDPairExtIEsExtFieldValueCodecFieldCapture(&sealed) = func(v s12.UES1APIDPairExtIEsExtField, options aper.DecodeState) (s12.UES1APIDPairExtIEsExtField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeUES1APIDPairExtIEsValueCaptureS1APProtocolExtensionField(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,
				false)
			return v, root
		}
		*s12.BridgeUES1APIDPairExtIEsExtFieldValueCodecFieldCompare(&sealed) = func(v s12.UES1APIDPairExtIEsExtField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeUES1APIDPairExtIEsValueCompareS1APProtocolExtensionField(&v, &s)
			s.End(f, root,

				false)
			return s.Plan(), s.BudgetValue()
		}
		*s12.BridgeUES1APIDPairExtIEsExtFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// UESecurityCapabilitiesExtIEsValueExtensionFieldTableCodec constructs the ProtocolExtensionField {{UESecurityCapabilities-ExtIEs}} codec of TS 36.413.
func UESecurityCapabilitiesExtIEsValueExtensionFieldTableCodec(table s00.UESecurityCapabilitiesExtIEsValueExtensionTable) s12.UESecurityCapabilitiesExtIEsExtFieldValueCodec {
	if !*s00.BridgeUESecurityCapabilitiesExtIEsValueExtensionTableFieldBound(&table) {
		return s12.UESecurityCapabilitiesExtIEsExtFieldValueCodec{}
	}
	return func() s12.UESecurityCapabilitiesExtIEsExtFieldValueCodec {
		sealed := s12.UESecurityCapabilitiesExtIEsExtFieldValueCodec{}
		*s12.BridgeUESecurityCapabilitiesExtIEsExtFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s12.UESecurityCapabilitiesExtIEsExtField, error) {
			var field s12.UESecurityCapabilitiesExtIEsExtField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s12.BridgeUESecurityCapabilitiesExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, err
			}
			if _, err := aper.CaptureFinalBits(bb, "ProtocolExtensionField"); err != nil {
				return field, err
			}
			return field, nil
		}
		*s12.BridgeUESecurityCapabilitiesExtIEsExtFieldValueCodecFieldEncode(&sealed) = func(field s12.UESecurityCapabilitiesExtIEsExtField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s12.BridgeUESecurityCapabilitiesExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s12.BridgeUESecurityCapabilitiesExtIEsExtFieldValueCodecFieldCapture(&sealed) = func(v s12.UESecurityCapabilitiesExtIEsExtField, options aper.DecodeState) (s12.UESecurityCapabilitiesExtIEsExtField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeUESecurityCapabilitiesExtIEsValueCaptureS1APProtocolExtensionField(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,
				false)
			return v, root
		}
		*s12.BridgeUESecurityCapabilitiesExtIEsExtFieldValueCodecFieldCompare(&sealed) = func(v s12.UESecurityCapabilitiesExtIEsExtField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeUESecurityCapabilitiesExtIEsValueCompareS1APProtocolExtensionField(&v, &s)
			s.End(f, root,

				false)
			return s.Plan(), s.BudgetValue()
		}
		*s12.BridgeUESecurityCapabilitiesExtIEsExtFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// UESidelinkAggregateMaximumBitratesExtIEsValueExtensionFieldTableCodec constructs the ProtocolExtensionField {{UE-Sidelink-Aggregate-MaximumBitrates-ExtIEs}} codec of TS 36.413.
func UESidelinkAggregateMaximumBitratesExtIEsValueExtensionFieldTableCodec(table s00.UESidelinkAggregateMaximumBitratesExtIEsValueExtensionTable) s12.UESidelinkAggregateMaximumBitratesExtIEsExtFieldValueCodec {
	if !*s00.BridgeUESidelinkAggregateMaximumBitratesExtIEsValueExtensionTableFieldBound(&table) {
		return s12.UESidelinkAggregateMaximumBitratesExtIEsExtFieldValueCodec{}
	}
	return func() s12.UESidelinkAggregateMaximumBitratesExtIEsExtFieldValueCodec {
		sealed := s12.UESidelinkAggregateMaximumBitratesExtIEsExtFieldValueCodec{}
		*s12.BridgeUESidelinkAggregateMaximumBitratesExtIEsExtFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s12.UESidelinkAggregateMaximumBitratesExtIEsExtField, error) {
			var field s12.UESidelinkAggregateMaximumBitratesExtIEsExtField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s12.BridgeUESidelinkAggregateMaximumBitratesExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, err
			}
			if _, err := aper.CaptureFinalBits(bb, "ProtocolExtensionField"); err != nil {
				return field, err
			}
			return field, nil
		}
		*s12.BridgeUESidelinkAggregateMaximumBitratesExtIEsExtFieldValueCodecFieldEncode(&sealed) = func(field s12.UESidelinkAggregateMaximumBitratesExtIEsExtField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s12.BridgeUESidelinkAggregateMaximumBitratesExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s12.BridgeUESidelinkAggregateMaximumBitratesExtIEsExtFieldValueCodecFieldCapture(&sealed) = func(v s12.UESidelinkAggregateMaximumBitratesExtIEsExtField, options aper.DecodeState) (s12.UESidelinkAggregateMaximumBitratesExtIEsExtField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeUESidelinkAggregateMaximumBitratesExtIEsValueCaptureS1APProtocolExtensionField(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,
				false)
			return v, root
		}
		*s12.BridgeUESidelinkAggregateMaximumBitratesExtIEsExtFieldValueCodecFieldCompare(&sealed) = func(v s12.UESidelinkAggregateMaximumBitratesExtIEsExtField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeUESidelinkAggregateMaximumBitratesExtIEsValueCompareS1APProtocolExtensionField(&v, &s)
			s.End(f, root,

				false)
			return s.Plan(), s.BudgetValue()
		}
		*s12.BridgeUESidelinkAggregateMaximumBitratesExtIEsExtFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// ULCPSecurityInformationExtIEsValueExtensionFieldTableCodec constructs the ProtocolExtensionField {{UL-CP-SecurityInformation-ExtIEs}} codec of TS 36.413.
func ULCPSecurityInformationExtIEsValueExtensionFieldTableCodec(table s00.ULCPSecurityInformationExtIEsValueExtensionTable) s12.ULCPSecurityInformationExtIEsExtFieldValueCodec {
	if !*s00.BridgeULCPSecurityInformationExtIEsValueExtensionTableFieldBound(&table) {
		return s12.ULCPSecurityInformationExtIEsExtFieldValueCodec{}
	}
	return func() s12.ULCPSecurityInformationExtIEsExtFieldValueCodec {
		sealed := s12.ULCPSecurityInformationExtIEsExtFieldValueCodec{}
		*s12.BridgeULCPSecurityInformationExtIEsExtFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s12.ULCPSecurityInformationExtIEsExtField, error) {
			var field s12.ULCPSecurityInformationExtIEsExtField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s12.BridgeULCPSecurityInformationExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, err
			}
			if _, err := aper.CaptureFinalBits(bb, "ProtocolExtensionField"); err != nil {
				return field, err
			}
			return field, nil
		}
		*s12.BridgeULCPSecurityInformationExtIEsExtFieldValueCodecFieldEncode(&sealed) = func(field s12.ULCPSecurityInformationExtIEsExtField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s12.BridgeULCPSecurityInformationExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s12.BridgeULCPSecurityInformationExtIEsExtFieldValueCodecFieldCapture(&sealed) = func(v s12.ULCPSecurityInformationExtIEsExtField, options aper.DecodeState) (s12.ULCPSecurityInformationExtIEsExtField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeULCPSecurityInformationExtIEsValueCaptureS1APProtocolExtensionField(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,
				false)
			return v, root
		}
		*s12.BridgeULCPSecurityInformationExtIEsExtFieldValueCodecFieldCompare(&sealed) = func(v s12.ULCPSecurityInformationExtIEsExtField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeULCPSecurityInformationExtIEsValueCompareS1APProtocolExtensionField(&v, &s)
			s.End(f, root,

				false)
			return s.Plan(), s.BudgetValue()
		}
		*s12.BridgeULCPSecurityInformationExtIEsExtFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// ENBEarlyStatusTransferTransparentContainerExtIEsValueExtensionTableCodec constructs the ProtocolExtensionContainer {{ENB-EarlyStatusTransfer-TransparentContainer-ExtIEs}} codec of TS 36.413.
func ENBEarlyStatusTransferTransparentContainerExtIEsValueExtensionTableCodec(table s00.ENBEarlyStatusTransferTransparentContainerExtIEsValueExtensionTable, bounds aper.ListBounds) ENBEarlyStatusTransferTransparentContainerExtIEsExtContainerValueCodec {
	if !*s00.BridgeENBEarlyStatusTransferTransparentContainerExtIEsValueExtensionTableFieldBound(&table) {
		return ENBEarlyStatusTransferTransparentContainerExtIEsExtContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return ENBEarlyStatusTransferTransparentContainerExtIEsExtContainerValueCodec{decode: func(data []byte, options aper.DecodeState) (ENBEarlyStatusTransferTransparentContainerExtIEsExtContainer, error) {
		bb := aper.NewCompleteDecodeBuffer(data, options)
		if err := bb.SetDecodeOptionsAligned(options); err != nil {
			return nil, err
		}
		var fields ENBEarlyStatusTransferTransparentContainerExtIEsExtContainer
		_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
			for i := int64(0); i < length; i++ {
				var field ENBEarlyStatusTransferTransparentContainerExtIEsExtField
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
		encode: func(fields ENBEarlyStatusTransferTransparentContainerExtIEsExtContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
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
		}, capture: func(v ENBEarlyStatusTransferTransparentContainerExtIEsExtContainer, options aper.DecodeState) (ENBEarlyStatusTransferTransparentContainerExtIEsExtContainer, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeENBEarlyStatusTransferTransparentContainerExtIEsValueCaptureS1APProtocolExtensionContainer(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}, compare: func(v ENBEarlyStatusTransferTransparentContainerExtIEsExtContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.
				Begin()
			BridgeENBEarlyStatusTransferTransparentContainerExtIEsValueCompareS1APProtocolExtensionContainer(&v, &s)
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

// UES1APIDPairExtIEsValueExtensionTableCodec constructs the ProtocolExtensionContainer {{UE-S1AP-ID-pair-ExtIEs}} codec of TS 36.413.
func UES1APIDPairExtIEsValueExtensionTableCodec(table s00.UES1APIDPairExtIEsValueExtensionTable, bounds aper.ListBounds) s12.UES1APIDPairExtIEsExtContainerValueCodec {
	if !*s00.BridgeUES1APIDPairExtIEsValueExtensionTableFieldBound(&table) {
		return s12.UES1APIDPairExtIEsExtContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s12.UES1APIDPairExtIEsExtContainerValueCodec {
		sealed := s12.UES1APIDPairExtIEsExtContainerValueCodec{}
		*s12.BridgeUES1APIDPairExtIEsExtContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s12.UES1APIDPairExtIEsExtContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s12.UES1APIDPairExtIEsExtContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s12.UES1APIDPairExtIEsExtField
					if err := s12.BridgeUES1APIDPairExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
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
		*s12.BridgeUES1APIDPairExtIEsExtContainerValueCodecFieldEncode(&sealed) = func(fields s12.UES1APIDPairExtIEsExtContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s12.BridgeUES1APIDPairExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
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
		*s12.BridgeUES1APIDPairExtIEsExtContainerValueCodecFieldCapture(&sealed) = func(v s12.UES1APIDPairExtIEsExtContainer, options aper.DecodeState) (s12.UES1APIDPairExtIEsExtContainer, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeUES1APIDPairExtIEsValueCaptureS1APProtocolExtensionContainer(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s12.BridgeUES1APIDPairExtIEsExtContainerValueCodecFieldCompare(&sealed) = func(v s12.UES1APIDPairExtIEsExtContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.
				Begin()
			BridgeUES1APIDPairExtIEsValueCompareS1APProtocolExtensionContainer(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s12.BridgeUES1APIDPairExtIEsExtContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}

// UESecurityCapabilitiesExtIEsValueExtensionTableCodec constructs the ProtocolExtensionContainer {{UESecurityCapabilities-ExtIEs}} codec of TS 36.413.
func UESecurityCapabilitiesExtIEsValueExtensionTableCodec(table s00.UESecurityCapabilitiesExtIEsValueExtensionTable, bounds aper.ListBounds) s12.UESecurityCapabilitiesExtIEsExtContainerValueCodec {
	if !*s00.BridgeUESecurityCapabilitiesExtIEsValueExtensionTableFieldBound(&table) {
		return s12.UESecurityCapabilitiesExtIEsExtContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s12.UESecurityCapabilitiesExtIEsExtContainerValueCodec {
		sealed := s12.UESecurityCapabilitiesExtIEsExtContainerValueCodec{}
		*s12.BridgeUESecurityCapabilitiesExtIEsExtContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s12.UESecurityCapabilitiesExtIEsExtContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s12.UESecurityCapabilitiesExtIEsExtContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s12.UESecurityCapabilitiesExtIEsExtField
					if err := s12.BridgeUESecurityCapabilitiesExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
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
		*s12.BridgeUESecurityCapabilitiesExtIEsExtContainerValueCodecFieldEncode(&sealed) = func(fields s12.UESecurityCapabilitiesExtIEsExtContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s12.BridgeUESecurityCapabilitiesExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
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
		*s12.BridgeUESecurityCapabilitiesExtIEsExtContainerValueCodecFieldCapture(&sealed) = func(v s12.UESecurityCapabilitiesExtIEsExtContainer, options aper.DecodeState) (s12.UESecurityCapabilitiesExtIEsExtContainer, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeUESecurityCapabilitiesExtIEsValueCaptureS1APProtocolExtensionContainer(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s12.BridgeUESecurityCapabilitiesExtIEsExtContainerValueCodecFieldCompare(&sealed) = func(v s12.UESecurityCapabilitiesExtIEsExtContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.
				Begin()
			BridgeUESecurityCapabilitiesExtIEsValueCompareS1APProtocolExtensionContainer(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s12.BridgeUESecurityCapabilitiesExtIEsExtContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}

// UESidelinkAggregateMaximumBitratesExtIEsValueExtensionTableCodec constructs the ProtocolExtensionContainer {{UE-Sidelink-Aggregate-MaximumBitrates-ExtIEs}} codec of TS 36.413.
func UESidelinkAggregateMaximumBitratesExtIEsValueExtensionTableCodec(table s00.UESidelinkAggregateMaximumBitratesExtIEsValueExtensionTable, bounds aper.ListBounds) s12.UESidelinkAggregateMaximumBitratesExtIEsExtContainerValueCodec {
	if !*s00.BridgeUESidelinkAggregateMaximumBitratesExtIEsValueExtensionTableFieldBound(&table) {
		return s12.UESidelinkAggregateMaximumBitratesExtIEsExtContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s12.UESidelinkAggregateMaximumBitratesExtIEsExtContainerValueCodec {
		sealed := s12.UESidelinkAggregateMaximumBitratesExtIEsExtContainerValueCodec{}
		*s12.BridgeUESidelinkAggregateMaximumBitratesExtIEsExtContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s12.UESidelinkAggregateMaximumBitratesExtIEsExtContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s12.UESidelinkAggregateMaximumBitratesExtIEsExtContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s12.UESidelinkAggregateMaximumBitratesExtIEsExtField
					if err := s12.BridgeUESidelinkAggregateMaximumBitratesExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
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
		*s12.BridgeUESidelinkAggregateMaximumBitratesExtIEsExtContainerValueCodecFieldEncode(&sealed) = func(fields s12.UESidelinkAggregateMaximumBitratesExtIEsExtContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s12.BridgeUESidelinkAggregateMaximumBitratesExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
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
		*s12.BridgeUESidelinkAggregateMaximumBitratesExtIEsExtContainerValueCodecFieldCapture(&sealed) = func(v s12.UESidelinkAggregateMaximumBitratesExtIEsExtContainer, options aper.DecodeState) (s12.UESidelinkAggregateMaximumBitratesExtIEsExtContainer, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeUESidelinkAggregateMaximumBitratesExtIEsValueCaptureS1APProtocolExtensionContainer(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s12.BridgeUESidelinkAggregateMaximumBitratesExtIEsExtContainerValueCodecFieldCompare(&sealed) = func(v s12.UESidelinkAggregateMaximumBitratesExtIEsExtContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.
				Begin()
			BridgeUESidelinkAggregateMaximumBitratesExtIEsValueCompareS1APProtocolExtensionContainer(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s12.BridgeUESidelinkAggregateMaximumBitratesExtIEsExtContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}

// ULCPSecurityInformationExtIEsValueExtensionTableCodec constructs the ProtocolExtensionContainer {{UL-CP-SecurityInformation-ExtIEs}} codec of TS 36.413.
func ULCPSecurityInformationExtIEsValueExtensionTableCodec(table s00.ULCPSecurityInformationExtIEsValueExtensionTable, bounds aper.ListBounds) s12.ULCPSecurityInformationExtIEsExtContainerValueCodec {
	if !*s00.BridgeULCPSecurityInformationExtIEsValueExtensionTableFieldBound(&table) {
		return s12.ULCPSecurityInformationExtIEsExtContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s12.ULCPSecurityInformationExtIEsExtContainerValueCodec {
		sealed := s12.ULCPSecurityInformationExtIEsExtContainerValueCodec{}
		*s12.BridgeULCPSecurityInformationExtIEsExtContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s12.ULCPSecurityInformationExtIEsExtContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s12.ULCPSecurityInformationExtIEsExtContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s12.ULCPSecurityInformationExtIEsExtField
					if err := s12.BridgeULCPSecurityInformationExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
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
		*s12.BridgeULCPSecurityInformationExtIEsExtContainerValueCodecFieldEncode(&sealed) = func(fields s12.ULCPSecurityInformationExtIEsExtContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s12.BridgeULCPSecurityInformationExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
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
		*s12.BridgeULCPSecurityInformationExtIEsExtContainerValueCodecFieldCapture(&sealed) = func(v s12.ULCPSecurityInformationExtIEsExtContainer, options aper.DecodeState) (s12.ULCPSecurityInformationExtIEsExtContainer, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeULCPSecurityInformationExtIEsValueCaptureS1APProtocolExtensionContainer(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s12.BridgeULCPSecurityInformationExtIEsExtContainerValueCodecFieldCompare(&sealed) = func(v s12.ULCPSecurityInformationExtIEsExtContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.
				Begin()
			BridgeULCPSecurityInformationExtIEsValueCompareS1APProtocolExtensionContainer(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s12.BridgeULCPSecurityInformationExtIEsExtContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}

// ENBCPRelocationIndicationIEValueIEFieldTableCodec constructs the ProtocolIE-Field {{ENBCPRelocationIndicationIEs}} codec of TS 36.413.
func ENBCPRelocationIndicationIEValueIEFieldTableCodec(table s00.ENBCPRelocationIndicationIEValueIETable) ENBCPRelocationIndicationIEFieldValueCodec {
	if !*s00.BridgeENBCPRelocationIndicationIEValueIETableFieldBound(&table) {
		return ENBCPRelocationIndicationIEFieldValueCodec{}
	}
	return ENBCPRelocationIndicationIEFieldValueCodec{decode: func(data []byte, options aper.DecodeState) (ENBCPRelocationIndicationIEField, error) {
		var field ENBCPRelocationIndicationIEField
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
	}, encode: func(field ENBCPRelocationIndicationIEField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		bb := aper.NewBudgetBuffer(budget)
		if err := field.marshalAPERTo(bb, fresh); err != nil {
			return nil, err
		}
		return bb.CompleteBytes(), nil
	}, capture: func(v ENBCPRelocationIndicationIEField, options aper.DecodeState) (ENBCPRelocationIndicationIEField, aper.Snapshot,
	) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeENBCPRelocationIndicationIEValueCaptureS1APProtocolIEField(&v,
			&s)
		var root aper.Snapshot
		s.End(f, &root, false)
		return v,
			root
	}, compare: func(v ENBCPRelocationIndicationIEField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

	) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		BridgeENBCPRelocationIndicationIEValueCompareS1APProtocolIEField(&v, &s)
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

// ENBEarlyStatusTransferIEValueIEFieldTableCodec constructs the ProtocolIE-Field {{ENBEarlyStatusTransferIEs}} codec of TS 36.413.
func ENBEarlyStatusTransferIEValueIEFieldTableCodec(table s00.ENBEarlyStatusTransferIEValueIETable) ENBEarlyStatusTransferIEFieldValueCodec {
	if !*s00.BridgeENBEarlyStatusTransferIEValueIETableFieldBound(&table) {
		return ENBEarlyStatusTransferIEFieldValueCodec{}
	}
	return ENBEarlyStatusTransferIEFieldValueCodec{decode: func(data []byte, options aper.DecodeState) (ENBEarlyStatusTransferIEField, error) {
		var field ENBEarlyStatusTransferIEField
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
	}, encode: func(field ENBEarlyStatusTransferIEField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		bb := aper.NewBudgetBuffer(budget)
		if err := field.marshalAPERTo(bb, fresh); err != nil {
			return nil, err
		}
		return bb.CompleteBytes(), nil
	}, capture: func(v ENBEarlyStatusTransferIEField, options aper.DecodeState) (ENBEarlyStatusTransferIEField, aper.Snapshot,
	) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeENBEarlyStatusTransferIEValueCaptureS1APProtocolIEField(&v,
			&s)
		var root aper.Snapshot
		s.End(f, &root, false)
		return v,
			root
	}, compare: func(v ENBEarlyStatusTransferIEField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

	) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		BridgeENBEarlyStatusTransferIEValueCompareS1APProtocolIEField(&v, &s)
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

// UEContextReleaseCommandIEValueIEFieldTableCodec constructs the ProtocolIE-Field {{UEContextReleaseCommand-IEs}} codec of TS 36.413.
func UEContextReleaseCommandIEValueIEFieldTableCodec(table s00.UEContextReleaseCommandIEValueIETable) UEContextReleaseCommandIEFieldValueCodec {
	if !*s00.BridgeUEContextReleaseCommandIEValueIETableFieldBound(&table) {
		return UEContextReleaseCommandIEFieldValueCodec{}
	}
	return UEContextReleaseCommandIEFieldValueCodec{decode: func(data []byte, options aper.DecodeState) (UEContextReleaseCommandIEField, error) {
		var field UEContextReleaseCommandIEField
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
	}, encode: func(field UEContextReleaseCommandIEField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		bb := aper.NewBudgetBuffer(budget)
		if err := field.marshalAPERTo(bb, fresh); err != nil {
			return nil, err
		}
		return bb.CompleteBytes(), nil
	}, capture: func(v UEContextReleaseCommandIEField, options aper.DecodeState) (UEContextReleaseCommandIEField, aper.Snapshot,
	) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeUEContextReleaseCommandIEValueCaptureS1APProtocolIEField(&v,
			&s)
		var root aper.Snapshot
		s.End(f, &root, false)
		return v,
			root
	}, compare: func(v UEContextReleaseCommandIEField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

	) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		BridgeUEContextReleaseCommandIEValueCompareS1APProtocolIEField(&v, &s)
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

// UERadioCapabilityMatchResponseIEValueIEFieldTableCodec constructs the ProtocolIE-Field {{UERadioCapabilityMatchResponseIEs}} codec of TS 36.413.
func UERadioCapabilityMatchResponseIEValueIEFieldTableCodec(table s00.UERadioCapabilityMatchResponseIEValueIETable) s24.UERadioCapabilityMatchResponseIEFieldValueCodec {
	if !*s00.BridgeUERadioCapabilityMatchResponseIEValueIETableFieldBound(&table) {
		return s24.UERadioCapabilityMatchResponseIEFieldValueCodec{}
	}
	return func() s24.UERadioCapabilityMatchResponseIEFieldValueCodec {
		sealed := s24.UERadioCapabilityMatchResponseIEFieldValueCodec{}
		*s24.BridgeUERadioCapabilityMatchResponseIEFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s24.UERadioCapabilityMatchResponseIEField, error) {
			var field s24.UERadioCapabilityMatchResponseIEField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s24.BridgeUERadioCapabilityMatchResponseIEFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, err
			}
			if _, err := aper.CaptureFinalBits(bb, "ProtocolIEField"); err != nil {
				return field, err
			}
			return field, nil
		}
		*s24.BridgeUERadioCapabilityMatchResponseIEFieldValueCodecFieldEncode(&sealed) = func(field s24.UERadioCapabilityMatchResponseIEField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s24.BridgeUERadioCapabilityMatchResponseIEFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s24.BridgeUERadioCapabilityMatchResponseIEFieldValueCodecFieldCapture(&sealed) = func(v s24.UERadioCapabilityMatchResponseIEField, options aper.DecodeState) (s24.UERadioCapabilityMatchResponseIEField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s36.BridgeUERadioCapabilityMatchResponseIEValueCaptureS1APProtocolIEField(&v,
				&s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v,
				root
		}
		*s24.BridgeUERadioCapabilityMatchResponseIEFieldValueCodecFieldCompare(&sealed) = func(v s24.UERadioCapabilityMatchResponseIEField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s36.BridgeUERadioCapabilityMatchResponseIEValueCompareS1APProtocolIEField(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s24.BridgeUERadioCapabilityMatchResponseIEFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// ENBCPRelocationIndicationIEValueIETableCodec constructs the ProtocolIE-Container {{ENBCPRelocationIndicationIEs}} codec of TS 36.413.
func ENBCPRelocationIndicationIEValueIETableCodec(table s00.ENBCPRelocationIndicationIEValueIETable, bounds aper.ListBounds) ENBCPRelocationIndicationIEContainerValueCodec {
	if !*s00.BridgeENBCPRelocationIndicationIEValueIETableFieldBound(&table) {
		return ENBCPRelocationIndicationIEContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return ENBCPRelocationIndicationIEContainerValueCodec{decode: func(data []byte, options aper.DecodeState) (ENBCPRelocationIndicationIEContainer, error) {
		bb := aper.NewCompleteDecodeBuffer(data, options)
		if err := bb.SetDecodeOptionsAligned(options); err != nil {
			return nil, err
		}
		var fields ENBCPRelocationIndicationIEContainer
		_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
			for i := int64(0); i < length; i++ {
				var field ENBCPRelocationIndicationIEField
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
		encode: func(fields ENBCPRelocationIndicationIEContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
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
		}, capture: func(v ENBCPRelocationIndicationIEContainer, options aper.DecodeState) (ENBCPRelocationIndicationIEContainer, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeENBCPRelocationIndicationIEValueCaptureS1APProtocolIEContainer(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}, compare: func(v ENBCPRelocationIndicationIEContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeENBCPRelocationIndicationIEValueCompareS1APProtocolIEContainer(&v, &s)
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

// UEContextReleaseCommandIEValueIETableCodec constructs the ProtocolIE-Container {{UEContextReleaseCommand-IEs}} codec of TS 36.413.
func UEContextReleaseCommandIEValueIETableCodec(table s00.UEContextReleaseCommandIEValueIETable, bounds aper.ListBounds) UEContextReleaseCommandIEContainerValueCodec {
	if !*s00.BridgeUEContextReleaseCommandIEValueIETableFieldBound(&table) {
		return UEContextReleaseCommandIEContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return UEContextReleaseCommandIEContainerValueCodec{decode: func(data []byte, options aper.DecodeState) (UEContextReleaseCommandIEContainer, error) {
		bb := aper.NewCompleteDecodeBuffer(data, options)
		if err := bb.SetDecodeOptionsAligned(options); err != nil {
			return nil, err
		}
		var fields UEContextReleaseCommandIEContainer
		_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
			for i := int64(0); i < length; i++ {
				var field UEContextReleaseCommandIEField
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
		encode: func(fields UEContextReleaseCommandIEContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
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
		}, capture: func(v UEContextReleaseCommandIEContainer, options aper.DecodeState) (UEContextReleaseCommandIEContainer, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeUEContextReleaseCommandIEValueCaptureS1APProtocolIEContainer(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}, compare: func(v UEContextReleaseCommandIEContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeUEContextReleaseCommandIEValueCompareS1APProtocolIEContainer(&v, &s)
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

// UERadioCapabilityMatchResponseIEValueIETableCodec constructs the ProtocolIE-Container {{UERadioCapabilityMatchResponseIEs}} codec of TS 36.413.
func UERadioCapabilityMatchResponseIEValueIETableCodec(table s00.UERadioCapabilityMatchResponseIEValueIETable, bounds aper.ListBounds) s24.UERadioCapabilityMatchResponseIEContainerValueCodec {
	if !*s00.BridgeUERadioCapabilityMatchResponseIEValueIETableFieldBound(&table) {
		return s24.UERadioCapabilityMatchResponseIEContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s24.UERadioCapabilityMatchResponseIEContainerValueCodec {
		sealed := s24.UERadioCapabilityMatchResponseIEContainerValueCodec{}
		*s24.BridgeUERadioCapabilityMatchResponseIEContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s24.UERadioCapabilityMatchResponseIEContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s24.UERadioCapabilityMatchResponseIEContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s24.UERadioCapabilityMatchResponseIEField
					if err := s24.BridgeUERadioCapabilityMatchResponseIEFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
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
		*s24.BridgeUERadioCapabilityMatchResponseIEContainerValueCodecFieldEncode(&sealed) = func(fields s24.UERadioCapabilityMatchResponseIEContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s24.BridgeUERadioCapabilityMatchResponseIEFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
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
		*s24.BridgeUERadioCapabilityMatchResponseIEContainerValueCodecFieldCapture(&sealed) = func(v s24.UERadioCapabilityMatchResponseIEContainer, options aper.DecodeState) (s24.UERadioCapabilityMatchResponseIEContainer, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s36.BridgeUERadioCapabilityMatchResponseIEValueCaptureS1APProtocolIEContainer(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s24.BridgeUERadioCapabilityMatchResponseIEContainerValueCodecFieldCompare(&sealed) = func(v s24.UERadioCapabilityMatchResponseIEContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeUERadioCapabilityMatchResponseIEValueCompareS1APProtocolIEContainer(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s24.BridgeUERadioCapabilityMatchResponseIEContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}

// ENBCPRelocationIndicationIEValueProtocolErrorIEContainerListCodec constructs the ProtocolError-IE-ContainerList {{ENBCPRelocationIndicationIEs}} codec of TS 36.413.
func ENBCPRelocationIndicationIEValueProtocolErrorIEContainerListCodec(table s00.ENBCPRelocationIndicationIEValueIETable) ENBCPRelocationIndicationIEValueProtocolErrorIEContainerListValueCodec {
	codec := ENBCPRelocationIndicationIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if codec.decode == nil {
		return ENBCPRelocationIndicationIEValueProtocolErrorIEContainerListValueCodec{}
	}
	return ENBCPRelocationIndicationIEValueProtocolErrorIEContainerListValueCodec{decode: func(data []byte, options aper.DecodeState) (ENBCPRelocationIndicationIEValueProtocolErrorIEContainerList, error) {
		value, err := codec.decode(data, options)
		return ENBCPRelocationIndicationIEValueProtocolErrorIEContainerList(value), err
	}, encode: func(value ENBCPRelocationIndicationIEValueProtocolErrorIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return codec.encode(ENBCPRelocationIndicationIEContainer(value), fresh, budget)
	}, capture: func(v ENBCPRelocationIndicationIEValueProtocolErrorIEContainerList, options aper.DecodeState) (ENBCPRelocationIndicationIEValueProtocolErrorIEContainerList, aper.Snapshot,
	) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeENBCPRelocationIndicationIEValueCaptureS1APProtocolErrorIEContainerList(&v, &s)
		var root aper.Snapshot

		s.End(f, &root, false)
		return v, root
	}, compare: func(v ENBCPRelocationIndicationIEValueProtocolErrorIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

	) {
		s := aper.NewSemanticComparison(root, budget)
		f :=
			s.
				Begin()
		BridgeENBCPRelocationIndicationIEValueCompareS1APProtocolErrorIEContainerList(&v, &s)
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

// UEContextReleaseCommandIEValueProtocolErrorIEContainerListCodec constructs the ProtocolError-IE-ContainerList {{UEContextReleaseCommand-IEs}} codec of TS 36.413.
func UEContextReleaseCommandIEValueProtocolErrorIEContainerListCodec(table s00.UEContextReleaseCommandIEValueIETable) UEContextReleaseCommandIEValueProtocolErrorIEContainerListValueCodec {
	codec := UEContextReleaseCommandIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if codec.decode == nil {
		return UEContextReleaseCommandIEValueProtocolErrorIEContainerListValueCodec{}
	}
	return UEContextReleaseCommandIEValueProtocolErrorIEContainerListValueCodec{decode: func(data []byte, options aper.DecodeState) (UEContextReleaseCommandIEValueProtocolErrorIEContainerList, error) {
		value, err := codec.decode(data, options)
		return UEContextReleaseCommandIEValueProtocolErrorIEContainerList(value), err
	}, encode: func(value UEContextReleaseCommandIEValueProtocolErrorIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return codec.encode(UEContextReleaseCommandIEContainer(value), fresh, budget)
	}, capture: func(v UEContextReleaseCommandIEValueProtocolErrorIEContainerList, options aper.DecodeState) (UEContextReleaseCommandIEValueProtocolErrorIEContainerList, aper.Snapshot,
	) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeUEContextReleaseCommandIEValueCaptureS1APProtocolErrorIEContainerList(&v, &s)
		var root aper.Snapshot

		s.End(f, &root, false)
		return v, root
	}, compare: func(v UEContextReleaseCommandIEValueProtocolErrorIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

	) {
		s := aper.NewSemanticComparison(root, budget)
		f :=
			s.
				Begin()
		BridgeUEContextReleaseCommandIEValueCompareS1APProtocolErrorIEContainerList(&v, &s)
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

// UERadioCapabilityMatchResponseIEValueProtocolErrorIEContainerListCodec constructs the ProtocolError-IE-ContainerList {{UERadioCapabilityMatchResponseIEs}} codec of TS 36.413.
func UERadioCapabilityMatchResponseIEValueProtocolErrorIEContainerListCodec(table s00.UERadioCapabilityMatchResponseIEValueIETable) s24.UERadioCapabilityMatchResponseIEValueProtocolErrorIEContainerListValueCodec {
	codec := UERadioCapabilityMatchResponseIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if *s24.BridgeUERadioCapabilityMatchResponseIEContainerValueCodecFieldDecode(&codec) == nil {
		return s24.UERadioCapabilityMatchResponseIEValueProtocolErrorIEContainerListValueCodec{}
	}
	return func() s24.UERadioCapabilityMatchResponseIEValueProtocolErrorIEContainerListValueCodec {
		sealed := s24.UERadioCapabilityMatchResponseIEValueProtocolErrorIEContainerListValueCodec{}
		*s24.BridgeUERadioCapabilityMatchResponseIEValueProtocolErrorIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s24.UERadioCapabilityMatchResponseIEValueProtocolErrorIEContainerList, error) {
			value, err := (*s24.BridgeUERadioCapabilityMatchResponseIEContainerValueCodecFieldDecode(&codec))(data, options)
			return s24.UERadioCapabilityMatchResponseIEValueProtocolErrorIEContainerList(value), err
		}
		*s24.BridgeUERadioCapabilityMatchResponseIEValueProtocolErrorIEContainerListValueCodecFieldEncode(&sealed) = func(value s24.UERadioCapabilityMatchResponseIEValueProtocolErrorIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s24.BridgeUERadioCapabilityMatchResponseIEContainerValueCodecFieldEncode(&codec))(s24.UERadioCapabilityMatchResponseIEContainer(value), fresh, budget)
		}
		*s24.BridgeUERadioCapabilityMatchResponseIEValueProtocolErrorIEContainerListValueCodecFieldCapture(&sealed) = func(v s24.UERadioCapabilityMatchResponseIEValueProtocolErrorIEContainerList, options aper.DecodeState) (s24.UERadioCapabilityMatchResponseIEValueProtocolErrorIEContainerList, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s36.BridgeUERadioCapabilityMatchResponseIEValueCaptureS1APProtocolErrorIEContainerList(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s24.BridgeUERadioCapabilityMatchResponseIEValueProtocolErrorIEContainerListValueCodecFieldCompare(&sealed) = func(v s24.UERadioCapabilityMatchResponseIEValueProtocolErrorIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f :=
				s.
					Begin()
			BridgeUERadioCapabilityMatchResponseIEValueCompareS1APProtocolErrorIEContainerList(&v, &s)
			s.
				End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s24.BridgeUERadioCapabilityMatchResponseIEValueProtocolErrorIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolErrorIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// ENBCPRelocationIndicationIEValueProtocolIEContainerListCodec constructs a codec for ProtocolIE-ContainerList with IEsSetParam = {ENBCPRelocationIndicationIEs} of TS 36.413, with lowerBound and upperBound supplied by its arguments.
func ENBCPRelocationIndicationIEValueProtocolIEContainerListCodec(table s00.ENBCPRelocationIndicationIEValueIETable, bounds aper.ListBounds) ENBCPRelocationIndicationIEValueProtocolIEContainerListValueCodec {
	codec := ENBCPRelocationIndicationIEValueIETableCodec(table, bounds)
	if codec.decode == nil {
		return ENBCPRelocationIndicationIEValueProtocolIEContainerListValueCodec{}
	}
	return ENBCPRelocationIndicationIEValueProtocolIEContainerListValueCodec{decode: func(data []byte, options aper.DecodeState) (ENBCPRelocationIndicationIEValueProtocolIEContainerList, error) {
		value, err := codec.decode(data, options)
		return ENBCPRelocationIndicationIEValueProtocolIEContainerList(value), err
	}, encode: func(value ENBCPRelocationIndicationIEValueProtocolIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return codec.encode(ENBCPRelocationIndicationIEContainer(value), fresh, budget)
	}, capture: func(v ENBCPRelocationIndicationIEValueProtocolIEContainerList, options aper.DecodeState) (ENBCPRelocationIndicationIEValueProtocolIEContainerList, aper.Snapshot,
	) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeENBCPRelocationIndicationIEValueCaptureS1APProtocolIEContainerList(&v, &s)
		var root aper.Snapshot
		s.End(
			f,
			&root, false)
		return v, root
	}, compare: func(v ENBCPRelocationIndicationIEValueProtocolIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
	) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		BridgeENBCPRelocationIndicationIEValueCompareS1APProtocolIEContainerList(&v, &s)
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

// UEContextReleaseCommandIEValueProtocolIEContainerListCodec constructs a codec for ProtocolIE-ContainerList with IEsSetParam = {UEContextReleaseCommand-IEs} of TS 36.413, with lowerBound and upperBound supplied by its arguments.
func UEContextReleaseCommandIEValueProtocolIEContainerListCodec(table s00.UEContextReleaseCommandIEValueIETable, bounds aper.ListBounds) UEContextReleaseCommandIEValueProtocolIEContainerListValueCodec {
	codec := UEContextReleaseCommandIEValueIETableCodec(table, bounds)
	if codec.decode == nil {
		return UEContextReleaseCommandIEValueProtocolIEContainerListValueCodec{}
	}
	return UEContextReleaseCommandIEValueProtocolIEContainerListValueCodec{decode: func(data []byte, options aper.DecodeState) (UEContextReleaseCommandIEValueProtocolIEContainerList, error) {
		value, err := codec.decode(data, options)
		return UEContextReleaseCommandIEValueProtocolIEContainerList(value), err
	}, encode: func(value UEContextReleaseCommandIEValueProtocolIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return codec.encode(UEContextReleaseCommandIEContainer(value), fresh, budget)
	}, capture: func(v UEContextReleaseCommandIEValueProtocolIEContainerList, options aper.DecodeState) (UEContextReleaseCommandIEValueProtocolIEContainerList, aper.Snapshot,
	) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeUEContextReleaseCommandIEValueCaptureS1APProtocolIEContainerList(&v, &s)
		var root aper.Snapshot
		s.End(
			f,
			&root, false)
		return v, root
	}, compare: func(v UEContextReleaseCommandIEValueProtocolIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
	) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		BridgeUEContextReleaseCommandIEValueCompareS1APProtocolIEContainerList(&v, &s)
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

// UERadioCapabilityMatchResponseIEValueProtocolIEContainerListCodec constructs a codec for ProtocolIE-ContainerList with IEsSetParam = {UERadioCapabilityMatchResponseIEs} of TS 36.413, with lowerBound and upperBound supplied by its arguments.
func UERadioCapabilityMatchResponseIEValueProtocolIEContainerListCodec(table s00.UERadioCapabilityMatchResponseIEValueIETable, bounds aper.ListBounds) s24.UERadioCapabilityMatchResponseIEValueProtocolIEContainerListValueCodec {
	codec := UERadioCapabilityMatchResponseIEValueIETableCodec(table, bounds)
	if *s24.BridgeUERadioCapabilityMatchResponseIEContainerValueCodecFieldDecode(&codec) == nil {
		return s24.UERadioCapabilityMatchResponseIEValueProtocolIEContainerListValueCodec{}
	}
	return func() s24.UERadioCapabilityMatchResponseIEValueProtocolIEContainerListValueCodec {
		sealed := s24.UERadioCapabilityMatchResponseIEValueProtocolIEContainerListValueCodec{}
		*s24.BridgeUERadioCapabilityMatchResponseIEValueProtocolIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s24.UERadioCapabilityMatchResponseIEValueProtocolIEContainerList, error) {
			value, err := (*s24.BridgeUERadioCapabilityMatchResponseIEContainerValueCodecFieldDecode(&codec))(data, options)
			return s24.UERadioCapabilityMatchResponseIEValueProtocolIEContainerList(value), err
		}
		*s24.BridgeUERadioCapabilityMatchResponseIEValueProtocolIEContainerListValueCodecFieldEncode(&sealed) = func(value s24.UERadioCapabilityMatchResponseIEValueProtocolIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s24.BridgeUERadioCapabilityMatchResponseIEContainerValueCodecFieldEncode(&codec))(s24.UERadioCapabilityMatchResponseIEContainer(value), fresh, budget)
		}
		*s24.BridgeUERadioCapabilityMatchResponseIEValueProtocolIEContainerListValueCodecFieldCapture(&sealed) = func(v s24.UERadioCapabilityMatchResponseIEValueProtocolIEContainerList, options aper.DecodeState) (s24.UERadioCapabilityMatchResponseIEValueProtocolIEContainerList, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s36.BridgeUERadioCapabilityMatchResponseIEValueCaptureS1APProtocolIEContainerList(&v, &s)
			var root aper.Snapshot
			s.End(
				f,
				&root, false)
			return v, root
		}
		*s24.BridgeUERadioCapabilityMatchResponseIEValueProtocolIEContainerListValueCodecFieldCompare(&sealed) = func(v s24.UERadioCapabilityMatchResponseIEValueProtocolIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeUERadioCapabilityMatchResponseIEValueCompareS1APProtocolIEContainerList(&v, &s)
			s.End(f, root,

				false)
			return s.Plan(), s.BudgetValue()
		}
		*s24.BridgeUERadioCapabilityMatchResponseIEValueProtocolIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}

// eNBCPRelocationIndicationIEValueProtocolOpenValue is the concrete protocolOpenValue[ENBCPRelocationIndicationIEValue].
type ENBCPRelocationIndicationIEValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) ENBCPRelocationIndicationIEValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (ENBCPRelocationIndicationIEValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

func BridgeENBCPRelocationIndicationIEValueCaptureS1APProtocolIEField(v *ENBCPRelocationIndicationIEField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolIEID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.Value = v.Value.captureSemantics(*s)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeENBCPRelocationIndicationIEValueCompareS1APProtocolIEField(v *ENBCPRelocationIndicationIEField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s02.BridgeCompareS1APProtocolIEID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = v.Value.compareSemantics(*s)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeENBEarlyStatusTransferIEValueCaptureS1APProtocolIEField(v *ENBEarlyStatusTransferIEField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolIEID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.Value = v.Value.captureSemantics(*s)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeENBEarlyStatusTransferIEValueCompareS1APProtocolIEField(v *ENBEarlyStatusTransferIEField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s02.BridgeCompareS1APProtocolIEID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = v.Value.compareSemantics(*s)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeENBEarlyStatusTransferTransparentContainerExtIEsValueCaptureS1APProtocolExtensionField(v *ENBEarlyStatusTransferTransparentContainerExtIEsExtField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolExtensionID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.ExtensionValue = v.ExtensionValue.captureSemantics(*s)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeENBEarlyStatusTransferTransparentContainerExtIEsValueCompareS1APProtocolExtensionField(v *ENBEarlyStatusTransferTransparentContainerExtIEsExtField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s02.BridgeCompareS1APProtocolExtensionID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = v.ExtensionValue.compareSemantics(*s)
	s.End(f, v.replay, v.withoutReplay)
}

// uEContextReleaseCommandIEValueProtocolOpenValue is the concrete protocolOpenValue[UEContextReleaseCommandIEValue].
type UEContextReleaseCommandIEValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) UEContextReleaseCommandIEValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (UEContextReleaseCommandIEValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

func BridgeUEContextReleaseCommandIEValueCaptureS1APProtocolIEField(v *UEContextReleaseCommandIEField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolIEID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.Value = v.Value.captureSemantics(*s)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeUEContextReleaseCommandIEValueCompareS1APProtocolIEField(v *UEContextReleaseCommandIEField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s02.BridgeCompareS1APProtocolIEID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = v.Value.compareSemantics(*s)
	s.End(f, v.replay, v.withoutReplay)
}

// uERadioCapabilityMatchResponseIEValueProtocolOpenValue is the concrete protocolOpenValue[UERadioCapabilityMatchResponseIEValue].
type UERadioCapabilityMatchResponseIEValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) s24.UERadioCapabilityMatchResponseIEValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (s24.UERadioCapabilityMatchResponseIEValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

// uES1APIDPairExtIEsValueProtocolOpenValue is the concrete protocolOpenValue[UES1APIDPairExtIEsValue].
type UES1APIDPairExtIEsValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) s06.UES1APIDPairExtIEsValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (s06.UES1APIDPairExtIEsValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

func BridgeUES1APIDPairExtIEsValueCaptureS1APProtocolExtensionField(v *s12.UES1APIDPairExtIEsExtField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolExtensionID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.ExtensionValue = s06.BridgeUES1APIDPairExtIEsValueMethodCaptureSemantics(v.ExtensionValue, *s)
	s.End(f, s12.BridgeUES1APIDPairExtIEsExtFieldFieldReplay(v), *s12.BridgeUES1APIDPairExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeUES1APIDPairExtIEsValueCompareS1APProtocolExtensionField(v *s12.UES1APIDPairExtIEsExtField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s02.BridgeCompareS1APProtocolExtensionID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s06.BridgeUES1APIDPairExtIEsValueMethodCompareSemantics(v.ExtensionValue, *s)
	s.End(f, *s12.BridgeUES1APIDPairExtIEsExtFieldFieldReplay(v), *s12.BridgeUES1APIDPairExtIEsExtFieldFieldWithoutReplay(v))
}

// uESecurityCapabilitiesExtIEsValueProtocolOpenValue is the concrete protocolOpenValue[UESecurityCapabilitiesExtIEsValue].
type UESecurityCapabilitiesExtIEsValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) s06.UESecurityCapabilitiesExtIEsValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (s06.UESecurityCapabilitiesExtIEsValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

func BridgeUESecurityCapabilitiesExtIEsValueCaptureS1APProtocolExtensionField(v *s12.UESecurityCapabilitiesExtIEsExtField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolExtensionID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.ExtensionValue = s06.BridgeUESecurityCapabilitiesExtIEsValueMethodCaptureSemantics(v.ExtensionValue, *s)
	s.End(f, s12.BridgeUESecurityCapabilitiesExtIEsExtFieldFieldReplay(v), *s12.BridgeUESecurityCapabilitiesExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeUESecurityCapabilitiesExtIEsValueCompareS1APProtocolExtensionField(v *s12.UESecurityCapabilitiesExtIEsExtField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s02.BridgeCompareS1APProtocolExtensionID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s06.BridgeUESecurityCapabilitiesExtIEsValueMethodCompareSemantics(v.ExtensionValue, *s)
	s.End(f, *s12.BridgeUESecurityCapabilitiesExtIEsExtFieldFieldReplay(v), *s12.BridgeUESecurityCapabilitiesExtIEsExtFieldFieldWithoutReplay(v))
}

// uESidelinkAggregateMaximumBitratesExtIEsValueProtocolOpenValue is the concrete protocolOpenValue[UESidelinkAggregateMaximumBitratesExtIEsValue].
type UESidelinkAggregateMaximumBitratesExtIEsValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) s06.UESidelinkAggregateMaximumBitratesExtIEsValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (s06.UESidelinkAggregateMaximumBitratesExtIEsValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

func BridgeUESidelinkAggregateMaximumBitratesExtIEsValueCaptureS1APProtocolExtensionField(v *s12.UESidelinkAggregateMaximumBitratesExtIEsExtField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolExtensionID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.ExtensionValue = s06.BridgeUESidelinkAggregateMaximumBitratesExtIEsValueMethodCaptureSemantics(v.ExtensionValue, *s)
	s.End(f, s12.BridgeUESidelinkAggregateMaximumBitratesExtIEsExtFieldFieldReplay(v), *s12.BridgeUESidelinkAggregateMaximumBitratesExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeUESidelinkAggregateMaximumBitratesExtIEsValueCompareS1APProtocolExtensionField(v *s12.UESidelinkAggregateMaximumBitratesExtIEsExtField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s02.BridgeCompareS1APProtocolExtensionID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s06.BridgeUESidelinkAggregateMaximumBitratesExtIEsValueMethodCompareSemantics(v.ExtensionValue, *s)
	s.End(f, *s12.BridgeUESidelinkAggregateMaximumBitratesExtIEsExtFieldFieldReplay(v), *s12.BridgeUESidelinkAggregateMaximumBitratesExtIEsExtFieldFieldWithoutReplay(v))
}

// uLCPSecurityInformationExtIEsValueProtocolOpenValue is the concrete protocolOpenValue[ULCPSecurityInformationExtIEsValue].
type ULCPSecurityInformationExtIEsValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) s06.ULCPSecurityInformationExtIEsValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (s06.ULCPSecurityInformationExtIEsValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

func BridgeULCPSecurityInformationExtIEsValueCaptureS1APProtocolExtensionField(v *s12.ULCPSecurityInformationExtIEsExtField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolExtensionID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.ExtensionValue = s06.BridgeULCPSecurityInformationExtIEsValueMethodCaptureSemantics(v.ExtensionValue, *s)
	s.End(f, s12.BridgeULCPSecurityInformationExtIEsExtFieldFieldReplay(v), *s12.BridgeULCPSecurityInformationExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeULCPSecurityInformationExtIEsValueCompareS1APProtocolExtensionField(v *s12.ULCPSecurityInformationExtIEsExtField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s02.BridgeCompareS1APProtocolExtensionID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s06.BridgeULCPSecurityInformationExtIEsValueMethodCompareSemantics(v.ExtensionValue, *s)
	s.End(f, *s12.BridgeULCPSecurityInformationExtIEsExtFieldFieldReplay(v), *s12.BridgeULCPSecurityInformationExtIEsExtFieldFieldWithoutReplay(v))
}

// ULCPSecurityInformationAPERValue is the concrete APERValue[ULCPSecurityInformation].
type ULCPSecurityInformationAPERValue struct {
	context s00.BridgeCodecContext
	Value   ULCPSecurityInformation

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ULCPSecurityInformationAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ULCPSecurityInformationAPERValue) WithoutReplay() ULCPSecurityInformationAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ENBEarlyStatusTransferTransparentContainerAPERValue is the concrete APERValue[ENBEarlyStatusTransferTransparentContainer].
type ENBEarlyStatusTransferTransparentContainerAPERValue struct {
	context s00.BridgeCodecContext
	Value   ENBEarlyStatusTransferTransparentContainer

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ENBEarlyStatusTransferTransparentContainerAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ENBEarlyStatusTransferTransparentContainerAPERValue) WithoutReplay() ENBEarlyStatusTransferTransparentContainerAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// UESecurityCapabilitiesAPERValue is the concrete APERValue[UESecurityCapabilities].
type UESecurityCapabilitiesAPERValue struct {
	context s00.BridgeCodecContext
	Value   UESecurityCapabilities

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v UESecurityCapabilitiesAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v UESecurityCapabilitiesAPERValue) WithoutReplay() UESecurityCapabilitiesAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// UESidelinkAggregateMaximumBitrateAPERValue is the concrete APERValue[UESidelinkAggregateMaximumBitrate].
type UESidelinkAggregateMaximumBitrateAPERValue struct {
	context s00.BridgeCodecContext
	Value   UESidelinkAggregateMaximumBitrate

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v UESidelinkAggregateMaximumBitrateAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v UESidelinkAggregateMaximumBitrateAPERValue) WithoutReplay() UESidelinkAggregateMaximumBitrateAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// UES1APIDsAPERValue is the concrete APERValue[UES1APIDs].
type UES1APIDsAPERValue struct {
	context s00.BridgeCodecContext
	Value   UES1APIDs

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v UES1APIDsAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v UES1APIDsAPERValue) WithoutReplay() UES1APIDsAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ENBCPRelocationIndicationAPERValue is the concrete APERValue[ENBCPRelocationIndication].
type ENBCPRelocationIndicationAPERValue struct {
	context s00.BridgeCodecContext
	Value   ENBCPRelocationIndication

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ENBCPRelocationIndicationAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ENBCPRelocationIndicationAPERValue) WithoutReplay() ENBCPRelocationIndicationAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// UEContextReleaseCommandAPERValue is the concrete APERValue[UEContextReleaseCommand].
type UEContextReleaseCommandAPERValue struct {
	context s00.BridgeCodecContext
	Value   UEContextReleaseCommand

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v UEContextReleaseCommandAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v UEContextReleaseCommandAPERValue) WithoutReplay() UEContextReleaseCommandAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// UERadioCapabilityMatchResponseAPERValue is the concrete APERValue[UERadioCapabilityMatchResponse].
type UERadioCapabilityMatchResponseAPERValue struct {
	context s00.BridgeCodecContext
	Value   UERadioCapabilityMatchResponse

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v UERadioCapabilityMatchResponseAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v UERadioCapabilityMatchResponseAPERValue) WithoutReplay() UERadioCapabilityMatchResponseAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// UES1APIDPairAPERValue is the concrete APERValue[UES1APIDPair].
type UES1APIDPairAPERValue struct {
	context s00.BridgeCodecContext
	Value   UES1APIDPair

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v UES1APIDPairAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v UES1APIDPairAPERValue) WithoutReplay() UES1APIDPairAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ENBEarlyStatusTransferTransparentContainerExtIEsIEField uses the ProtocolIE-Field shape for object set ENB-EarlyStatusTransfer-TransparentContainer-ExtIEs of TS 36.413.
type ENBEarlyStatusTransferTransparentContainerExtIEsIEField struct {
	withoutReplay bool
	replay        aper.Snapshot
	stream        aper.WireSpan
	Id            s00.ProtocolIEID
	Criticality   s00.Criticality
	Value         ENBEarlyStatusTransferTransparentContainerExtIEsValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ENBEarlyStatusTransferTransparentContainerExtIEsIEField) WithoutReplay() ENBEarlyStatusTransferTransparentContainerExtIEsIEField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *ENBEarlyStatusTransferTransparentContainerExtIEsIEField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *ENBEarlyStatusTransferTransparentContainerExtIEsIEField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
func (v *ENBEarlyStatusTransferTransparentContainerExtIEsIEField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolIEField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = ENBEarlyStatusTransferTransparentContainerExtIEsIEField{}
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
	var zero ENBEarlyStatusTransferTransparentContainerExtIEsValue

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

// ENBEarlyStatusTransferTransparentContainerExtIEsIEContainer uses the ProtocolIE-Container shape for object set ENB-EarlyStatusTransfer-TransparentContainer-ExtIEs of TS 36.413: a list of ENBEarlyStatusTransferTransparentContainerExtIEsIEField values.
type ENBEarlyStatusTransferTransparentContainerExtIEsIEContainer []ENBEarlyStatusTransferTransparentContainerExtIEsIEField

// TS 36.413 V19.2.0 §§9.3.3–9.3.4 supply the selected object-set order and
// presence. §§10.3.1–10.3.6 define abstract-syntax diagnostics. Unknown IEs do
// not determine the order of known rows.
func BridgeUES1APIDPairExtIEsValueValidateS1APIEContainer(fields s12.UES1APIDPairExtIEsIEContainer, rows []s00.FieldInfo, path string, budget *aper.DecodeBudget,

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
		if !s06.BridgeUES1APIDPairExtIEsValueMethodMatchesID(field.Value, field.Id, budget) {
			rule := s06.BridgeUES1APIDPairExtIEsValueMethodRule(field.Value)
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.ValueIDMismatch, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: aper.Path(fmt.Sprintf("%s.id", location.Path))}, Table: func() s00.TableID {
				sealed := s00.TableID{}
				*s00.BridgeTableIDFieldSource(&sealed) = rule.Assignment
				return sealed
			}(), IEID: field.Id, HasIEID: true, Rule: s26.BridgeS1apValidationRule(s00.ValueIDMismatch), RelatedRules: []aper.SourceRule{rule}})
		}
		rank, allowed := byID[field.Id]
		table := func() s00.TableID {
			sealed := s00.TableID{}
			*s00.BridgeTableIDFieldSource(&sealed) = s06.BridgeUES1APIDPairExtIEsValueMethodRule(field.Value).Assignment
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
func BridgeUESecurityCapabilitiesExtIEsValueValidateS1APIEContainer(fields s12.UESecurityCapabilitiesExtIEsIEContainer, rows []s00.FieldInfo, path string, budget *aper.DecodeBudget,

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
		if !s06.BridgeUESecurityCapabilitiesExtIEsValueMethodMatchesID(field.Value, field.Id, budget) {
			rule := s06.BridgeUESecurityCapabilitiesExtIEsValueMethodRule(field.Value)
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.ValueIDMismatch, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: aper.Path(fmt.Sprintf("%s.id", location.Path))}, Table: func() s00.TableID {
				sealed := s00.TableID{}
				*s00.BridgeTableIDFieldSource(&sealed) = rule.Assignment
				return sealed
			}(), IEID: field.Id, HasIEID: true, Rule: s26.BridgeS1apValidationRule(s00.ValueIDMismatch), RelatedRules: []aper.SourceRule{rule}})
		}
		rank, allowed := byID[field.Id]
		table := func() s00.TableID {
			sealed := s00.TableID{}
			*s00.BridgeTableIDFieldSource(&sealed) = s06.BridgeUESecurityCapabilitiesExtIEsValueMethodRule(field.Value).Assignment
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
func BridgeUESidelinkAggregateMaximumBitratesExtIEsValueValidateS1APIEContainer(fields s12.UESidelinkAggregateMaximumBitratesExtIEsIEContainer, rows []s00.FieldInfo, path string, budget *aper.DecodeBudget,

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
		if !s06.BridgeUESidelinkAggregateMaximumBitratesExtIEsValueMethodMatchesID(field.Value, field.Id, budget) {
			rule := s06.BridgeUESidelinkAggregateMaximumBitratesExtIEsValueMethodRule(field.Value)
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.ValueIDMismatch, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: aper.Path(fmt.Sprintf("%s.id", location.Path))}, Table: func() s00.TableID {
				sealed := s00.TableID{}
				*s00.BridgeTableIDFieldSource(&sealed) = rule.Assignment
				return sealed
			}(), IEID: field.Id, HasIEID: true, Rule: s26.BridgeS1apValidationRule(s00.ValueIDMismatch), RelatedRules: []aper.SourceRule{rule}})
		}
		rank, allowed := byID[field.Id]
		table := func() s00.TableID {
			sealed := s00.TableID{}
			*s00.BridgeTableIDFieldSource(&sealed) = s06.BridgeUESidelinkAggregateMaximumBitratesExtIEsValueMethodRule(field.Value).Assignment
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
func BridgeULCPSecurityInformationExtIEsValueValidateS1APIEContainer(fields s12.ULCPSecurityInformationExtIEsIEContainer, rows []s00.FieldInfo, path string, budget *aper.DecodeBudget,

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
		if !s06.BridgeULCPSecurityInformationExtIEsValueMethodMatchesID(field.Value, field.Id, budget) {
			rule := s06.BridgeULCPSecurityInformationExtIEsValueMethodRule(field.Value)
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.ValueIDMismatch, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: aper.Path(fmt.Sprintf("%s.id", location.Path))}, Table: func() s00.TableID {
				sealed := s00.TableID{}
				*s00.BridgeTableIDFieldSource(&sealed) = rule.Assignment
				return sealed
			}(), IEID: field.Id, HasIEID: true, Rule: s26.BridgeS1apValidationRule(s00.ValueIDMismatch), RelatedRules: []aper.SourceRule{rule}})
		}
		rank, allowed := byID[field.Id]
		table := func() s00.TableID {
			sealed := s00.TableID{}
			*s00.BridgeTableIDFieldSource(&sealed) = s06.BridgeULCPSecurityInformationExtIEsValueMethodRule(field.Value).Assignment
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

// ENBCPRelocationIndicationIEValueERABIEContainerListValueCodec is the concrete ValueCodec[ENBCPRelocationIndicationIEValueERABIEContainerList].
type ENBCPRelocationIndicationIEValueERABIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ENBCPRelocationIndicationIEValueERABIEContainerList, error)
	encode  func(ENBCPRelocationIndicationIEValueERABIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ENBCPRelocationIndicationIEValueERABIEContainerList, aper.DecodeState) (ENBCPRelocationIndicationIEValueERABIEContainerList, aper.Snapshot)
	compare func(ENBCPRelocationIndicationIEValueERABIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ENBCPRelocationIndicationIEValueERABIEContainerListValueCodec) New(value ENBCPRelocationIndicationIEValueERABIEContainerList) (ENBCPRelocationIndicationIEValueERABIEContainerListAPERValue, error) {
	if c.encode == nil {
		return ENBCPRelocationIndicationIEValueERABIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ENBCPRelocationIndicationIEValueERABIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ENBCPRelocationIndicationIEValueERABIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ENBCPRelocationIndicationIEValueERABIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ENBCPRelocationIndicationIEValueERABIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ENBCPRelocationIndicationIEValueERABIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ENBCPRelocationIndicationIEValueERABIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ENBCPRelocationIndicationIEValueERABIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ENBCPRelocationIndicationIEValueERABIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ENBCPRelocationIndicationIEValueERABIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ENBCPRelocationIndicationIEValueERABIEContainerListValueCodec) EncodeAPER(value ENBCPRelocationIndicationIEValueERABIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c ENBCPRelocationIndicationIEValueERABIEContainerListValueCodec) encodeBudgetValue(value ENBCPRelocationIndicationIEValueERABIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ENBCPRelocationIndicationIEValueERABIEContainerListValueCodec) encodeChanged(value ENBCPRelocationIndicationIEValueERABIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ENBCPRelocationIndicationIEValueERABIEContainerList is E-RAB-IE-ContainerList {{ENBCPRelocationIndicationIEs}} of TS 36.413: a list of information element fields.
type ENBCPRelocationIndicationIEValueERABIEContainerList []ENBCPRelocationIndicationIEValueProtocolIESingleContainer

func BridgeENBCPRelocationIndicationIEValueCaptureS1APERABIEContainerList(v *ENBCPRelocationIndicationIEValueERABIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeENBCPRelocationIndicationIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeENBCPRelocationIndicationIEValueCompareS1APERABIEContainerList(v *ENBCPRelocationIndicationIEValueERABIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeENBCPRelocationIndicationIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}

// ENBEarlyStatusTransferIEValueERABIEContainerListValueCodec is the concrete ValueCodec[ENBEarlyStatusTransferIEValueERABIEContainerList].
type ENBEarlyStatusTransferIEValueERABIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ENBEarlyStatusTransferIEValueERABIEContainerList, error)
	encode  func(ENBEarlyStatusTransferIEValueERABIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ENBEarlyStatusTransferIEValueERABIEContainerList, aper.DecodeState) (ENBEarlyStatusTransferIEValueERABIEContainerList, aper.Snapshot)
	compare func(ENBEarlyStatusTransferIEValueERABIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ENBEarlyStatusTransferIEValueERABIEContainerListValueCodec) New(value ENBEarlyStatusTransferIEValueERABIEContainerList) (ENBEarlyStatusTransferIEValueERABIEContainerListAPERValue, error) {
	if c.encode == nil {
		return ENBEarlyStatusTransferIEValueERABIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ENBEarlyStatusTransferIEValueERABIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ENBEarlyStatusTransferIEValueERABIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ENBEarlyStatusTransferIEValueERABIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ENBEarlyStatusTransferIEValueERABIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ENBEarlyStatusTransferIEValueERABIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ENBEarlyStatusTransferIEValueERABIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ENBEarlyStatusTransferIEValueERABIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ENBEarlyStatusTransferIEValueERABIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ENBEarlyStatusTransferIEValueERABIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ENBEarlyStatusTransferIEValueERABIEContainerListValueCodec) EncodeAPER(value ENBEarlyStatusTransferIEValueERABIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c ENBEarlyStatusTransferIEValueERABIEContainerListValueCodec) encodeBudgetValue(value ENBEarlyStatusTransferIEValueERABIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ENBEarlyStatusTransferIEValueERABIEContainerListValueCodec) encodeChanged(value ENBEarlyStatusTransferIEValueERABIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ENBEarlyStatusTransferIEValueERABIEContainerList is E-RAB-IE-ContainerList {{ENBEarlyStatusTransferIEs}} of TS 36.413: a list of information element fields.
type ENBEarlyStatusTransferIEValueERABIEContainerList []ENBEarlyStatusTransferIEValueProtocolIESingleContainer

func BridgeENBEarlyStatusTransferIEValueCaptureS1APERABIEContainerList(v *ENBEarlyStatusTransferIEValueERABIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeENBEarlyStatusTransferIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}

// MMEEarlyStatusTransferIEValueERABIEContainerListValueCodec is the concrete ValueCodec[MMEEarlyStatusTransferIEValueERABIEContainerList].
type MMEEarlyStatusTransferIEValueERABIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (MMEEarlyStatusTransferIEValueERABIEContainerList, error)
	encode  func(MMEEarlyStatusTransferIEValueERABIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(MMEEarlyStatusTransferIEValueERABIEContainerList, aper.DecodeState) (MMEEarlyStatusTransferIEValueERABIEContainerList, aper.Snapshot)
	compare func(MMEEarlyStatusTransferIEValueERABIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c MMEEarlyStatusTransferIEValueERABIEContainerListValueCodec) New(value MMEEarlyStatusTransferIEValueERABIEContainerList) (MMEEarlyStatusTransferIEValueERABIEContainerListAPERValue, error) {
	if c.encode == nil {
		return MMEEarlyStatusTransferIEValueERABIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return MMEEarlyStatusTransferIEValueERABIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return MMEEarlyStatusTransferIEValueERABIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return MMEEarlyStatusTransferIEValueERABIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c MMEEarlyStatusTransferIEValueERABIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (MMEEarlyStatusTransferIEValueERABIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return MMEEarlyStatusTransferIEValueERABIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return MMEEarlyStatusTransferIEValueERABIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return MMEEarlyStatusTransferIEValueERABIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return MMEEarlyStatusTransferIEValueERABIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c MMEEarlyStatusTransferIEValueERABIEContainerListValueCodec) EncodeAPER(value MMEEarlyStatusTransferIEValueERABIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c MMEEarlyStatusTransferIEValueERABIEContainerListValueCodec) encodeBudgetValue(value MMEEarlyStatusTransferIEValueERABIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c MMEEarlyStatusTransferIEValueERABIEContainerListValueCodec) encodeChanged(value MMEEarlyStatusTransferIEValueERABIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// MMEEarlyStatusTransferIEValueERABIEContainerList is E-RAB-IE-ContainerList {{MMEEarlyStatusTransferIEs}} of TS 36.413: a list of information element fields.
type MMEEarlyStatusTransferIEValueERABIEContainerList []MMEEarlyStatusTransferIEValueProtocolIESingleContainer

// UEContextReleaseCommandIEValueERABIEContainerListValueCodec is the concrete ValueCodec[UEContextReleaseCommandIEValueERABIEContainerList].
type UEContextReleaseCommandIEValueERABIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (UEContextReleaseCommandIEValueERABIEContainerList, error)
	encode  func(UEContextReleaseCommandIEValueERABIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(UEContextReleaseCommandIEValueERABIEContainerList, aper.DecodeState) (UEContextReleaseCommandIEValueERABIEContainerList, aper.Snapshot)
	compare func(UEContextReleaseCommandIEValueERABIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c UEContextReleaseCommandIEValueERABIEContainerListValueCodec) New(value UEContextReleaseCommandIEValueERABIEContainerList) (UEContextReleaseCommandIEValueERABIEContainerListAPERValue, error) {
	if c.encode == nil {
		return UEContextReleaseCommandIEValueERABIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return UEContextReleaseCommandIEValueERABIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return UEContextReleaseCommandIEValueERABIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return UEContextReleaseCommandIEValueERABIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c UEContextReleaseCommandIEValueERABIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (UEContextReleaseCommandIEValueERABIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return UEContextReleaseCommandIEValueERABIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return UEContextReleaseCommandIEValueERABIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return UEContextReleaseCommandIEValueERABIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return UEContextReleaseCommandIEValueERABIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c UEContextReleaseCommandIEValueERABIEContainerListValueCodec) EncodeAPER(value UEContextReleaseCommandIEValueERABIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c UEContextReleaseCommandIEValueERABIEContainerListValueCodec) encodeBudgetValue(value UEContextReleaseCommandIEValueERABIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c UEContextReleaseCommandIEValueERABIEContainerListValueCodec) encodeChanged(value UEContextReleaseCommandIEValueERABIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// UEContextReleaseCommandIEValueERABIEContainerList is E-RAB-IE-ContainerList {{UEContextReleaseCommand-IEs}} of TS 36.413: a list of information element fields.
type UEContextReleaseCommandIEValueERABIEContainerList []UEContextReleaseCommandIEValueProtocolIESingleContainer

func BridgeUEContextReleaseCommandIEValueCaptureS1APERABIEContainerList(v *UEContextReleaseCommandIEValueERABIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeUEContextReleaseCommandIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeUEContextReleaseCommandIEValueCompareS1APERABIEContainerList(v *UEContextReleaseCommandIEValueERABIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeUEContextReleaseCommandIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeUERadioCapabilityMatchResponseIEValueCompareS1APERABIEContainerList(v *s24.UERadioCapabilityMatchResponseIEValueERABIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeUERadioCapabilityMatchResponseIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}

// ENBEarlyStatusTransferTransparentContainerExtIEsExtFieldValueCodec is the concrete ValueCodec[ENBEarlyStatusTransferTransparentContainerExtIEsExtField].
type ENBEarlyStatusTransferTransparentContainerExtIEsExtFieldValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ENBEarlyStatusTransferTransparentContainerExtIEsExtField, error)
	encode  func(ENBEarlyStatusTransferTransparentContainerExtIEsExtField, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ENBEarlyStatusTransferTransparentContainerExtIEsExtField, aper.DecodeState) (ENBEarlyStatusTransferTransparentContainerExtIEsExtField, aper.Snapshot)
	compare func(ENBEarlyStatusTransferTransparentContainerExtIEsExtField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ENBEarlyStatusTransferTransparentContainerExtIEsExtFieldValueCodec) New(value ENBEarlyStatusTransferTransparentContainerExtIEsExtField) (ENBEarlyStatusTransferTransparentContainerExtIEsExtFieldAPERValue, error) {
	if c.encode == nil {
		return ENBEarlyStatusTransferTransparentContainerExtIEsExtFieldAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ENBEarlyStatusTransferTransparentContainerExtIEsExtFieldAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ENBEarlyStatusTransferTransparentContainerExtIEsExtFieldAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ENBEarlyStatusTransferTransparentContainerExtIEsExtFieldAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ENBEarlyStatusTransferTransparentContainerExtIEsExtFieldValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ENBEarlyStatusTransferTransparentContainerExtIEsExtFieldAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ENBEarlyStatusTransferTransparentContainerExtIEsExtFieldAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ENBEarlyStatusTransferTransparentContainerExtIEsExtFieldAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ENBEarlyStatusTransferTransparentContainerExtIEsExtFieldAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ENBEarlyStatusTransferTransparentContainerExtIEsExtFieldAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ENBEarlyStatusTransferTransparentContainerExtIEsExtFieldValueCodec) EncodeAPER(value ENBEarlyStatusTransferTransparentContainerExtIEsExtFieldAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c ENBEarlyStatusTransferTransparentContainerExtIEsExtFieldValueCodec) encodeBudgetValue(value ENBEarlyStatusTransferTransparentContainerExtIEsExtField, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ENBEarlyStatusTransferTransparentContainerExtIEsExtFieldValueCodec) encodeChanged(value ENBEarlyStatusTransferTransparentContainerExtIEsExtField, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ENBEarlyStatusTransferTransparentContainerExtIEsExtContainerValueCodec is the concrete ValueCodec[ENBEarlyStatusTransferTransparentContainerExtIEsExtContainer].
type ENBEarlyStatusTransferTransparentContainerExtIEsExtContainerValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ENBEarlyStatusTransferTransparentContainerExtIEsExtContainer, error)
	encode  func(ENBEarlyStatusTransferTransparentContainerExtIEsExtContainer, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ENBEarlyStatusTransferTransparentContainerExtIEsExtContainer, aper.DecodeState) (ENBEarlyStatusTransferTransparentContainerExtIEsExtContainer, aper.Snapshot)
	compare func(ENBEarlyStatusTransferTransparentContainerExtIEsExtContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ENBEarlyStatusTransferTransparentContainerExtIEsExtContainerValueCodec) New(value ENBEarlyStatusTransferTransparentContainerExtIEsExtContainer) (ENBEarlyStatusTransferTransparentContainerExtIEsExtContainerAPERValue, error) {
	if c.encode == nil {
		return ENBEarlyStatusTransferTransparentContainerExtIEsExtContainerAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ENBEarlyStatusTransferTransparentContainerExtIEsExtContainerAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ENBEarlyStatusTransferTransparentContainerExtIEsExtContainerAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ENBEarlyStatusTransferTransparentContainerExtIEsExtContainerAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ENBEarlyStatusTransferTransparentContainerExtIEsExtContainerValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ENBEarlyStatusTransferTransparentContainerExtIEsExtContainerAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ENBEarlyStatusTransferTransparentContainerExtIEsExtContainerAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ENBEarlyStatusTransferTransparentContainerExtIEsExtContainerAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ENBEarlyStatusTransferTransparentContainerExtIEsExtContainerAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ENBEarlyStatusTransferTransparentContainerExtIEsExtContainerAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ENBEarlyStatusTransferTransparentContainerExtIEsExtContainerValueCodec) EncodeAPER(value ENBEarlyStatusTransferTransparentContainerExtIEsExtContainerAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c ENBEarlyStatusTransferTransparentContainerExtIEsExtContainerValueCodec) encodeBudgetValue(value ENBEarlyStatusTransferTransparentContainerExtIEsExtContainer, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ENBEarlyStatusTransferTransparentContainerExtIEsExtContainerValueCodec) encodeChanged(value ENBEarlyStatusTransferTransparentContainerExtIEsExtContainer, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ENBCPRelocationIndicationIEFieldValueCodec is the concrete ValueCodec[ENBCPRelocationIndicationIEField].
type ENBCPRelocationIndicationIEFieldValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ENBCPRelocationIndicationIEField, error)
	encode  func(ENBCPRelocationIndicationIEField, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ENBCPRelocationIndicationIEField, aper.DecodeState) (ENBCPRelocationIndicationIEField, aper.Snapshot)
	compare func(ENBCPRelocationIndicationIEField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ENBCPRelocationIndicationIEFieldValueCodec) New(value ENBCPRelocationIndicationIEField) (ENBCPRelocationIndicationIEFieldAPERValue, error) {
	if c.encode == nil {
		return ENBCPRelocationIndicationIEFieldAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ENBCPRelocationIndicationIEFieldAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ENBCPRelocationIndicationIEFieldAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ENBCPRelocationIndicationIEFieldAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ENBCPRelocationIndicationIEFieldValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ENBCPRelocationIndicationIEFieldAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ENBCPRelocationIndicationIEFieldAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ENBCPRelocationIndicationIEFieldAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ENBCPRelocationIndicationIEFieldAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ENBCPRelocationIndicationIEFieldAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ENBCPRelocationIndicationIEFieldValueCodec) EncodeAPER(value ENBCPRelocationIndicationIEFieldAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c ENBCPRelocationIndicationIEFieldValueCodec) encodeBudgetValue(value ENBCPRelocationIndicationIEField, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ENBCPRelocationIndicationIEFieldValueCodec) encodeChanged(value ENBCPRelocationIndicationIEField, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ENBEarlyStatusTransferIEFieldValueCodec is the concrete ValueCodec[ENBEarlyStatusTransferIEField].
type ENBEarlyStatusTransferIEFieldValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ENBEarlyStatusTransferIEField, error)
	encode  func(ENBEarlyStatusTransferIEField, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ENBEarlyStatusTransferIEField, aper.DecodeState) (ENBEarlyStatusTransferIEField, aper.Snapshot)
	compare func(ENBEarlyStatusTransferIEField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ENBEarlyStatusTransferIEFieldValueCodec) New(value ENBEarlyStatusTransferIEField) (ENBEarlyStatusTransferIEFieldAPERValue, error) {
	if c.encode == nil {
		return ENBEarlyStatusTransferIEFieldAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ENBEarlyStatusTransferIEFieldAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ENBEarlyStatusTransferIEFieldAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ENBEarlyStatusTransferIEFieldAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ENBEarlyStatusTransferIEFieldValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ENBEarlyStatusTransferIEFieldAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ENBEarlyStatusTransferIEFieldAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ENBEarlyStatusTransferIEFieldAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ENBEarlyStatusTransferIEFieldAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ENBEarlyStatusTransferIEFieldAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ENBEarlyStatusTransferIEFieldValueCodec) EncodeAPER(value ENBEarlyStatusTransferIEFieldAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c ENBEarlyStatusTransferIEFieldValueCodec) encodeBudgetValue(value ENBEarlyStatusTransferIEField, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ENBEarlyStatusTransferIEFieldValueCodec) encodeChanged(value ENBEarlyStatusTransferIEField, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// MMEEarlyStatusTransferIEFieldValueCodec is the concrete ValueCodec[MMEEarlyStatusTransferIEField].
type MMEEarlyStatusTransferIEFieldValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (MMEEarlyStatusTransferIEField, error)
	encode  func(MMEEarlyStatusTransferIEField, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(MMEEarlyStatusTransferIEField, aper.DecodeState) (MMEEarlyStatusTransferIEField, aper.Snapshot)
	compare func(MMEEarlyStatusTransferIEField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c MMEEarlyStatusTransferIEFieldValueCodec) New(value MMEEarlyStatusTransferIEField) (MMEEarlyStatusTransferIEFieldAPERValue, error) {
	if c.encode == nil {
		return MMEEarlyStatusTransferIEFieldAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return MMEEarlyStatusTransferIEFieldAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return MMEEarlyStatusTransferIEFieldAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return MMEEarlyStatusTransferIEFieldAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c MMEEarlyStatusTransferIEFieldValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (MMEEarlyStatusTransferIEFieldAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return MMEEarlyStatusTransferIEFieldAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return MMEEarlyStatusTransferIEFieldAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return MMEEarlyStatusTransferIEFieldAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return MMEEarlyStatusTransferIEFieldAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c MMEEarlyStatusTransferIEFieldValueCodec) EncodeAPER(value MMEEarlyStatusTransferIEFieldAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c MMEEarlyStatusTransferIEFieldValueCodec) encodeBudgetValue(value MMEEarlyStatusTransferIEField, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c MMEEarlyStatusTransferIEFieldValueCodec) encodeChanged(value MMEEarlyStatusTransferIEField, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// UEContextReleaseCommandIEFieldValueCodec is the concrete ValueCodec[UEContextReleaseCommandIEField].
type UEContextReleaseCommandIEFieldValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (UEContextReleaseCommandIEField, error)
	encode  func(UEContextReleaseCommandIEField, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(UEContextReleaseCommandIEField, aper.DecodeState) (UEContextReleaseCommandIEField, aper.Snapshot)
	compare func(UEContextReleaseCommandIEField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c UEContextReleaseCommandIEFieldValueCodec) New(value UEContextReleaseCommandIEField) (UEContextReleaseCommandIEFieldAPERValue, error) {
	if c.encode == nil {
		return UEContextReleaseCommandIEFieldAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return UEContextReleaseCommandIEFieldAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return UEContextReleaseCommandIEFieldAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return UEContextReleaseCommandIEFieldAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c UEContextReleaseCommandIEFieldValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (UEContextReleaseCommandIEFieldAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return UEContextReleaseCommandIEFieldAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return UEContextReleaseCommandIEFieldAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return UEContextReleaseCommandIEFieldAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return UEContextReleaseCommandIEFieldAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c UEContextReleaseCommandIEFieldValueCodec) EncodeAPER(value UEContextReleaseCommandIEFieldAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c UEContextReleaseCommandIEFieldValueCodec) encodeBudgetValue(value UEContextReleaseCommandIEField, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c UEContextReleaseCommandIEFieldValueCodec) encodeChanged(value UEContextReleaseCommandIEField, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ENBCPRelocationIndicationIEContainerValueCodec is the concrete ValueCodec[ENBCPRelocationIndicationIEContainer].
type ENBCPRelocationIndicationIEContainerValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ENBCPRelocationIndicationIEContainer, error)
	encode  func(ENBCPRelocationIndicationIEContainer, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ENBCPRelocationIndicationIEContainer, aper.DecodeState) (ENBCPRelocationIndicationIEContainer, aper.Snapshot)
	compare func(ENBCPRelocationIndicationIEContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ENBCPRelocationIndicationIEContainerValueCodec) New(value ENBCPRelocationIndicationIEContainer) (ENBCPRelocationIndicationIEContainerAPERValue, error) {
	if c.encode == nil {
		return ENBCPRelocationIndicationIEContainerAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ENBCPRelocationIndicationIEContainerAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ENBCPRelocationIndicationIEContainerAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ENBCPRelocationIndicationIEContainerAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ENBCPRelocationIndicationIEContainerValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ENBCPRelocationIndicationIEContainerAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ENBCPRelocationIndicationIEContainerAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ENBCPRelocationIndicationIEContainerAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ENBCPRelocationIndicationIEContainerAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ENBCPRelocationIndicationIEContainerAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ENBCPRelocationIndicationIEContainerValueCodec) EncodeAPER(value ENBCPRelocationIndicationIEContainerAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c ENBCPRelocationIndicationIEContainerValueCodec) encodeBudgetValue(value ENBCPRelocationIndicationIEContainer, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ENBCPRelocationIndicationIEContainerValueCodec) encodeChanged(value ENBCPRelocationIndicationIEContainer, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ENBEarlyStatusTransferIEContainerValueCodec is the concrete ValueCodec[ENBEarlyStatusTransferIEContainer].
type ENBEarlyStatusTransferIEContainerValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ENBEarlyStatusTransferIEContainer, error)
	encode  func(ENBEarlyStatusTransferIEContainer, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ENBEarlyStatusTransferIEContainer, aper.DecodeState) (ENBEarlyStatusTransferIEContainer, aper.Snapshot)
	compare func(ENBEarlyStatusTransferIEContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ENBEarlyStatusTransferIEContainerValueCodec) New(value ENBEarlyStatusTransferIEContainer) (ENBEarlyStatusTransferIEContainerAPERValue, error) {
	if c.encode == nil {
		return ENBEarlyStatusTransferIEContainerAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ENBEarlyStatusTransferIEContainerAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ENBEarlyStatusTransferIEContainerAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ENBEarlyStatusTransferIEContainerAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ENBEarlyStatusTransferIEContainerValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ENBEarlyStatusTransferIEContainerAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ENBEarlyStatusTransferIEContainerAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ENBEarlyStatusTransferIEContainerAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ENBEarlyStatusTransferIEContainerAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ENBEarlyStatusTransferIEContainerAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ENBEarlyStatusTransferIEContainerValueCodec) EncodeAPER(value ENBEarlyStatusTransferIEContainerAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c ENBEarlyStatusTransferIEContainerValueCodec) encodeBudgetValue(value ENBEarlyStatusTransferIEContainer, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ENBEarlyStatusTransferIEContainerValueCodec) encodeChanged(value ENBEarlyStatusTransferIEContainer, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// MMEEarlyStatusTransferIEContainerValueCodec is the concrete ValueCodec[MMEEarlyStatusTransferIEContainer].
type MMEEarlyStatusTransferIEContainerValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (MMEEarlyStatusTransferIEContainer, error)
	encode  func(MMEEarlyStatusTransferIEContainer, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(MMEEarlyStatusTransferIEContainer, aper.DecodeState) (MMEEarlyStatusTransferIEContainer, aper.Snapshot)
	compare func(MMEEarlyStatusTransferIEContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c MMEEarlyStatusTransferIEContainerValueCodec) New(value MMEEarlyStatusTransferIEContainer) (MMEEarlyStatusTransferIEContainerAPERValue, error) {
	if c.encode == nil {
		return MMEEarlyStatusTransferIEContainerAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return MMEEarlyStatusTransferIEContainerAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return MMEEarlyStatusTransferIEContainerAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return MMEEarlyStatusTransferIEContainerAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c MMEEarlyStatusTransferIEContainerValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (MMEEarlyStatusTransferIEContainerAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return MMEEarlyStatusTransferIEContainerAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return MMEEarlyStatusTransferIEContainerAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return MMEEarlyStatusTransferIEContainerAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return MMEEarlyStatusTransferIEContainerAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c MMEEarlyStatusTransferIEContainerValueCodec) EncodeAPER(value MMEEarlyStatusTransferIEContainerAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c MMEEarlyStatusTransferIEContainerValueCodec) encodeBudgetValue(value MMEEarlyStatusTransferIEContainer, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c MMEEarlyStatusTransferIEContainerValueCodec) encodeChanged(value MMEEarlyStatusTransferIEContainer, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// UEContextReleaseCommandIEContainerValueCodec is the concrete ValueCodec[UEContextReleaseCommandIEContainer].
type UEContextReleaseCommandIEContainerValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (UEContextReleaseCommandIEContainer, error)
	encode  func(UEContextReleaseCommandIEContainer, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(UEContextReleaseCommandIEContainer, aper.DecodeState) (UEContextReleaseCommandIEContainer, aper.Snapshot)
	compare func(UEContextReleaseCommandIEContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c UEContextReleaseCommandIEContainerValueCodec) New(value UEContextReleaseCommandIEContainer) (UEContextReleaseCommandIEContainerAPERValue, error) {
	if c.encode == nil {
		return UEContextReleaseCommandIEContainerAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return UEContextReleaseCommandIEContainerAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return UEContextReleaseCommandIEContainerAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return UEContextReleaseCommandIEContainerAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c UEContextReleaseCommandIEContainerValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (UEContextReleaseCommandIEContainerAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return UEContextReleaseCommandIEContainerAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return UEContextReleaseCommandIEContainerAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return UEContextReleaseCommandIEContainerAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return UEContextReleaseCommandIEContainerAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c UEContextReleaseCommandIEContainerValueCodec) EncodeAPER(value UEContextReleaseCommandIEContainerAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c UEContextReleaseCommandIEContainerValueCodec) encodeBudgetValue(value UEContextReleaseCommandIEContainer, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c UEContextReleaseCommandIEContainerValueCodec) encodeChanged(value UEContextReleaseCommandIEContainer, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ENBCPRelocationIndicationIEValueProtocolErrorIEContainerListValueCodec is the concrete ValueCodec[ENBCPRelocationIndicationIEValueProtocolErrorIEContainerList].
type ENBCPRelocationIndicationIEValueProtocolErrorIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ENBCPRelocationIndicationIEValueProtocolErrorIEContainerList, error)
	encode  func(ENBCPRelocationIndicationIEValueProtocolErrorIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ENBCPRelocationIndicationIEValueProtocolErrorIEContainerList, aper.DecodeState) (ENBCPRelocationIndicationIEValueProtocolErrorIEContainerList, aper.Snapshot)
	compare func(ENBCPRelocationIndicationIEValueProtocolErrorIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ENBCPRelocationIndicationIEValueProtocolErrorIEContainerListValueCodec) New(value ENBCPRelocationIndicationIEValueProtocolErrorIEContainerList) (ENBCPRelocationIndicationIEValueProtocolErrorIEContainerListAPERValue, error) {
	if c.encode == nil {
		return ENBCPRelocationIndicationIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ENBCPRelocationIndicationIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ENBCPRelocationIndicationIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ENBCPRelocationIndicationIEValueProtocolErrorIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ENBCPRelocationIndicationIEValueProtocolErrorIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ENBCPRelocationIndicationIEValueProtocolErrorIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ENBCPRelocationIndicationIEValueProtocolErrorIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ENBCPRelocationIndicationIEValueProtocolErrorIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ENBCPRelocationIndicationIEValueProtocolErrorIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ENBCPRelocationIndicationIEValueProtocolErrorIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ENBCPRelocationIndicationIEValueProtocolErrorIEContainerListValueCodec) EncodeAPER(value ENBCPRelocationIndicationIEValueProtocolErrorIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c ENBCPRelocationIndicationIEValueProtocolErrorIEContainerListValueCodec) encodeBudgetValue(value ENBCPRelocationIndicationIEValueProtocolErrorIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ENBCPRelocationIndicationIEValueProtocolErrorIEContainerListValueCodec) encodeChanged(value ENBCPRelocationIndicationIEValueProtocolErrorIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ENBCPRelocationIndicationIEValueProtocolErrorIEContainerList is ProtocolError-IE-ContainerList {{ENBCPRelocationIndicationIEs}} of TS 36.413: a list of information element fields.
type ENBCPRelocationIndicationIEValueProtocolErrorIEContainerList []ENBCPRelocationIndicationIEValueProtocolIESingleContainer

func BridgeENBCPRelocationIndicationIEValueCaptureS1APProtocolErrorIEContainerList(v *ENBCPRelocationIndicationIEValueProtocolErrorIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeENBCPRelocationIndicationIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeENBCPRelocationIndicationIEValueCompareS1APProtocolErrorIEContainerList(v *ENBCPRelocationIndicationIEValueProtocolErrorIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeENBCPRelocationIndicationIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}

// ENBEarlyStatusTransferIEValueProtocolErrorIEContainerListValueCodec is the concrete ValueCodec[ENBEarlyStatusTransferIEValueProtocolErrorIEContainerList].
type ENBEarlyStatusTransferIEValueProtocolErrorIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ENBEarlyStatusTransferIEValueProtocolErrorIEContainerList, error)
	encode  func(ENBEarlyStatusTransferIEValueProtocolErrorIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ENBEarlyStatusTransferIEValueProtocolErrorIEContainerList, aper.DecodeState) (ENBEarlyStatusTransferIEValueProtocolErrorIEContainerList, aper.Snapshot)
	compare func(ENBEarlyStatusTransferIEValueProtocolErrorIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ENBEarlyStatusTransferIEValueProtocolErrorIEContainerListValueCodec) New(value ENBEarlyStatusTransferIEValueProtocolErrorIEContainerList) (ENBEarlyStatusTransferIEValueProtocolErrorIEContainerListAPERValue, error) {
	if c.encode == nil {
		return ENBEarlyStatusTransferIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ENBEarlyStatusTransferIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ENBEarlyStatusTransferIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ENBEarlyStatusTransferIEValueProtocolErrorIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ENBEarlyStatusTransferIEValueProtocolErrorIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ENBEarlyStatusTransferIEValueProtocolErrorIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ENBEarlyStatusTransferIEValueProtocolErrorIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ENBEarlyStatusTransferIEValueProtocolErrorIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ENBEarlyStatusTransferIEValueProtocolErrorIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ENBEarlyStatusTransferIEValueProtocolErrorIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ENBEarlyStatusTransferIEValueProtocolErrorIEContainerListValueCodec) EncodeAPER(value ENBEarlyStatusTransferIEValueProtocolErrorIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c ENBEarlyStatusTransferIEValueProtocolErrorIEContainerListValueCodec) encodeBudgetValue(value ENBEarlyStatusTransferIEValueProtocolErrorIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ENBEarlyStatusTransferIEValueProtocolErrorIEContainerListValueCodec) encodeChanged(value ENBEarlyStatusTransferIEValueProtocolErrorIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ENBEarlyStatusTransferIEValueProtocolErrorIEContainerList is ProtocolError-IE-ContainerList {{ENBEarlyStatusTransferIEs}} of TS 36.413: a list of information element fields.
type ENBEarlyStatusTransferIEValueProtocolErrorIEContainerList []ENBEarlyStatusTransferIEValueProtocolIESingleContainer

func BridgeENBEarlyStatusTransferIEValueCaptureS1APProtocolErrorIEContainerList(v *ENBEarlyStatusTransferIEValueProtocolErrorIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeENBEarlyStatusTransferIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}

// MMEEarlyStatusTransferIEValueProtocolErrorIEContainerListValueCodec is the concrete ValueCodec[MMEEarlyStatusTransferIEValueProtocolErrorIEContainerList].
type MMEEarlyStatusTransferIEValueProtocolErrorIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (MMEEarlyStatusTransferIEValueProtocolErrorIEContainerList, error)
	encode  func(MMEEarlyStatusTransferIEValueProtocolErrorIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(MMEEarlyStatusTransferIEValueProtocolErrorIEContainerList, aper.DecodeState) (MMEEarlyStatusTransferIEValueProtocolErrorIEContainerList, aper.Snapshot)
	compare func(MMEEarlyStatusTransferIEValueProtocolErrorIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c MMEEarlyStatusTransferIEValueProtocolErrorIEContainerListValueCodec) New(value MMEEarlyStatusTransferIEValueProtocolErrorIEContainerList) (MMEEarlyStatusTransferIEValueProtocolErrorIEContainerListAPERValue, error) {
	if c.encode == nil {
		return MMEEarlyStatusTransferIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return MMEEarlyStatusTransferIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return MMEEarlyStatusTransferIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return MMEEarlyStatusTransferIEValueProtocolErrorIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c MMEEarlyStatusTransferIEValueProtocolErrorIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (MMEEarlyStatusTransferIEValueProtocolErrorIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return MMEEarlyStatusTransferIEValueProtocolErrorIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return MMEEarlyStatusTransferIEValueProtocolErrorIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return MMEEarlyStatusTransferIEValueProtocolErrorIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return MMEEarlyStatusTransferIEValueProtocolErrorIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c MMEEarlyStatusTransferIEValueProtocolErrorIEContainerListValueCodec) EncodeAPER(value MMEEarlyStatusTransferIEValueProtocolErrorIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c MMEEarlyStatusTransferIEValueProtocolErrorIEContainerListValueCodec) encodeBudgetValue(value MMEEarlyStatusTransferIEValueProtocolErrorIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c MMEEarlyStatusTransferIEValueProtocolErrorIEContainerListValueCodec) encodeChanged(value MMEEarlyStatusTransferIEValueProtocolErrorIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// MMEEarlyStatusTransferIEValueProtocolErrorIEContainerList is ProtocolError-IE-ContainerList {{MMEEarlyStatusTransferIEs}} of TS 36.413: a list of information element fields.
type MMEEarlyStatusTransferIEValueProtocolErrorIEContainerList []MMEEarlyStatusTransferIEValueProtocolIESingleContainer

// UEContextReleaseCommandIEValueProtocolErrorIEContainerListValueCodec is the concrete ValueCodec[UEContextReleaseCommandIEValueProtocolErrorIEContainerList].
type UEContextReleaseCommandIEValueProtocolErrorIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (UEContextReleaseCommandIEValueProtocolErrorIEContainerList, error)
	encode  func(UEContextReleaseCommandIEValueProtocolErrorIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(UEContextReleaseCommandIEValueProtocolErrorIEContainerList, aper.DecodeState) (UEContextReleaseCommandIEValueProtocolErrorIEContainerList, aper.Snapshot)
	compare func(UEContextReleaseCommandIEValueProtocolErrorIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c UEContextReleaseCommandIEValueProtocolErrorIEContainerListValueCodec) New(value UEContextReleaseCommandIEValueProtocolErrorIEContainerList) (UEContextReleaseCommandIEValueProtocolErrorIEContainerListAPERValue, error) {
	if c.encode == nil {
		return UEContextReleaseCommandIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return UEContextReleaseCommandIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return UEContextReleaseCommandIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return UEContextReleaseCommandIEValueProtocolErrorIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c UEContextReleaseCommandIEValueProtocolErrorIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (UEContextReleaseCommandIEValueProtocolErrorIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return UEContextReleaseCommandIEValueProtocolErrorIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return UEContextReleaseCommandIEValueProtocolErrorIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return UEContextReleaseCommandIEValueProtocolErrorIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return UEContextReleaseCommandIEValueProtocolErrorIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c UEContextReleaseCommandIEValueProtocolErrorIEContainerListValueCodec) EncodeAPER(value UEContextReleaseCommandIEValueProtocolErrorIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c UEContextReleaseCommandIEValueProtocolErrorIEContainerListValueCodec) encodeBudgetValue(value UEContextReleaseCommandIEValueProtocolErrorIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c UEContextReleaseCommandIEValueProtocolErrorIEContainerListValueCodec) encodeChanged(value UEContextReleaseCommandIEValueProtocolErrorIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// UEContextReleaseCommandIEValueProtocolErrorIEContainerList is ProtocolError-IE-ContainerList {{UEContextReleaseCommand-IEs}} of TS 36.413: a list of information element fields.
type UEContextReleaseCommandIEValueProtocolErrorIEContainerList []UEContextReleaseCommandIEValueProtocolIESingleContainer

func BridgeUEContextReleaseCommandIEValueCaptureS1APProtocolErrorIEContainerList(v *UEContextReleaseCommandIEValueProtocolErrorIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeUEContextReleaseCommandIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeUEContextReleaseCommandIEValueCompareS1APProtocolErrorIEContainerList(v *UEContextReleaseCommandIEValueProtocolErrorIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeUEContextReleaseCommandIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeUERadioCapabilityMatchResponseIEValueCompareS1APProtocolErrorIEContainerList(v *s24.UERadioCapabilityMatchResponseIEValueProtocolErrorIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeUERadioCapabilityMatchResponseIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}

// ENBCPRelocationIndicationIEValueProtocolIEContainerListValueCodec is the concrete ValueCodec[ENBCPRelocationIndicationIEValueProtocolIEContainerList].
type ENBCPRelocationIndicationIEValueProtocolIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ENBCPRelocationIndicationIEValueProtocolIEContainerList, error)
	encode  func(ENBCPRelocationIndicationIEValueProtocolIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ENBCPRelocationIndicationIEValueProtocolIEContainerList, aper.DecodeState) (ENBCPRelocationIndicationIEValueProtocolIEContainerList, aper.Snapshot)
	compare func(ENBCPRelocationIndicationIEValueProtocolIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ENBCPRelocationIndicationIEValueProtocolIEContainerListValueCodec) New(value ENBCPRelocationIndicationIEValueProtocolIEContainerList) (ENBCPRelocationIndicationIEValueProtocolIEContainerListAPERValue, error) {
	if c.encode == nil {
		return ENBCPRelocationIndicationIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ENBCPRelocationIndicationIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ENBCPRelocationIndicationIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ENBCPRelocationIndicationIEValueProtocolIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ENBCPRelocationIndicationIEValueProtocolIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ENBCPRelocationIndicationIEValueProtocolIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ENBCPRelocationIndicationIEValueProtocolIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ENBCPRelocationIndicationIEValueProtocolIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ENBCPRelocationIndicationIEValueProtocolIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ENBCPRelocationIndicationIEValueProtocolIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ENBCPRelocationIndicationIEValueProtocolIEContainerListValueCodec) EncodeAPER(value ENBCPRelocationIndicationIEValueProtocolIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c ENBCPRelocationIndicationIEValueProtocolIEContainerListValueCodec) encodeBudgetValue(value ENBCPRelocationIndicationIEValueProtocolIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ENBCPRelocationIndicationIEValueProtocolIEContainerListValueCodec) encodeChanged(value ENBCPRelocationIndicationIEValueProtocolIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ENBCPRelocationIndicationIEValueProtocolIEContainerList is ProtocolIE-ContainerList with IEsSetParam = {ENBCPRelocationIndicationIEs} of TS 36.413: a list of information element fields with lowerBound and upperBound supplied by its concrete factory.
type ENBCPRelocationIndicationIEValueProtocolIEContainerList []ENBCPRelocationIndicationIEValueProtocolIESingleContainer

func BridgeENBCPRelocationIndicationIEValueCaptureS1APProtocolIEContainerList(v *ENBCPRelocationIndicationIEValueProtocolIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeENBCPRelocationIndicationIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeENBCPRelocationIndicationIEValueCompareS1APProtocolIEContainerList(v *ENBCPRelocationIndicationIEValueProtocolIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeENBCPRelocationIndicationIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}

// ENBEarlyStatusTransferIEValueProtocolIEContainerListValueCodec is the concrete ValueCodec[ENBEarlyStatusTransferIEValueProtocolIEContainerList].
type ENBEarlyStatusTransferIEValueProtocolIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ENBEarlyStatusTransferIEValueProtocolIEContainerList, error)
	encode  func(ENBEarlyStatusTransferIEValueProtocolIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ENBEarlyStatusTransferIEValueProtocolIEContainerList, aper.DecodeState) (ENBEarlyStatusTransferIEValueProtocolIEContainerList, aper.Snapshot)
	compare func(ENBEarlyStatusTransferIEValueProtocolIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ENBEarlyStatusTransferIEValueProtocolIEContainerListValueCodec) New(value ENBEarlyStatusTransferIEValueProtocolIEContainerList) (ENBEarlyStatusTransferIEValueProtocolIEContainerListAPERValue, error) {
	if c.encode == nil {
		return ENBEarlyStatusTransferIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ENBEarlyStatusTransferIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ENBEarlyStatusTransferIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ENBEarlyStatusTransferIEValueProtocolIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ENBEarlyStatusTransferIEValueProtocolIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ENBEarlyStatusTransferIEValueProtocolIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ENBEarlyStatusTransferIEValueProtocolIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ENBEarlyStatusTransferIEValueProtocolIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ENBEarlyStatusTransferIEValueProtocolIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ENBEarlyStatusTransferIEValueProtocolIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ENBEarlyStatusTransferIEValueProtocolIEContainerListValueCodec) EncodeAPER(value ENBEarlyStatusTransferIEValueProtocolIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c ENBEarlyStatusTransferIEValueProtocolIEContainerListValueCodec) encodeBudgetValue(value ENBEarlyStatusTransferIEValueProtocolIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ENBEarlyStatusTransferIEValueProtocolIEContainerListValueCodec) encodeChanged(value ENBEarlyStatusTransferIEValueProtocolIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ENBEarlyStatusTransferIEValueProtocolIEContainerList is ProtocolIE-ContainerList with IEsSetParam = {ENBEarlyStatusTransferIEs} of TS 36.413: a list of information element fields with lowerBound and upperBound supplied by its concrete factory.
type ENBEarlyStatusTransferIEValueProtocolIEContainerList []ENBEarlyStatusTransferIEValueProtocolIESingleContainer

func BridgeENBEarlyStatusTransferIEValueCaptureS1APProtocolIEContainerList(v *ENBEarlyStatusTransferIEValueProtocolIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeENBEarlyStatusTransferIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}

// MMEEarlyStatusTransferIEValueProtocolIEContainerListValueCodec is the concrete ValueCodec[MMEEarlyStatusTransferIEValueProtocolIEContainerList].
type MMEEarlyStatusTransferIEValueProtocolIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (MMEEarlyStatusTransferIEValueProtocolIEContainerList, error)
	encode  func(MMEEarlyStatusTransferIEValueProtocolIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(MMEEarlyStatusTransferIEValueProtocolIEContainerList, aper.DecodeState) (MMEEarlyStatusTransferIEValueProtocolIEContainerList, aper.Snapshot)
	compare func(MMEEarlyStatusTransferIEValueProtocolIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c MMEEarlyStatusTransferIEValueProtocolIEContainerListValueCodec) New(value MMEEarlyStatusTransferIEValueProtocolIEContainerList) (MMEEarlyStatusTransferIEValueProtocolIEContainerListAPERValue, error) {
	if c.encode == nil {
		return MMEEarlyStatusTransferIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return MMEEarlyStatusTransferIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return MMEEarlyStatusTransferIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return MMEEarlyStatusTransferIEValueProtocolIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c MMEEarlyStatusTransferIEValueProtocolIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (MMEEarlyStatusTransferIEValueProtocolIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return MMEEarlyStatusTransferIEValueProtocolIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return MMEEarlyStatusTransferIEValueProtocolIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return MMEEarlyStatusTransferIEValueProtocolIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return MMEEarlyStatusTransferIEValueProtocolIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c MMEEarlyStatusTransferIEValueProtocolIEContainerListValueCodec) EncodeAPER(value MMEEarlyStatusTransferIEValueProtocolIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c MMEEarlyStatusTransferIEValueProtocolIEContainerListValueCodec) encodeBudgetValue(value MMEEarlyStatusTransferIEValueProtocolIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c MMEEarlyStatusTransferIEValueProtocolIEContainerListValueCodec) encodeChanged(value MMEEarlyStatusTransferIEValueProtocolIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// MMEEarlyStatusTransferIEValueProtocolIEContainerList is ProtocolIE-ContainerList with IEsSetParam = {MMEEarlyStatusTransferIEs} of TS 36.413: a list of information element fields with lowerBound and upperBound supplied by its concrete factory.
type MMEEarlyStatusTransferIEValueProtocolIEContainerList []MMEEarlyStatusTransferIEValueProtocolIESingleContainer

// UEContextReleaseCommandIEValueProtocolIEContainerListValueCodec is the concrete ValueCodec[UEContextReleaseCommandIEValueProtocolIEContainerList].
type UEContextReleaseCommandIEValueProtocolIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (UEContextReleaseCommandIEValueProtocolIEContainerList, error)
	encode  func(UEContextReleaseCommandIEValueProtocolIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(UEContextReleaseCommandIEValueProtocolIEContainerList, aper.DecodeState) (UEContextReleaseCommandIEValueProtocolIEContainerList, aper.Snapshot)
	compare func(UEContextReleaseCommandIEValueProtocolIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c UEContextReleaseCommandIEValueProtocolIEContainerListValueCodec) New(value UEContextReleaseCommandIEValueProtocolIEContainerList) (UEContextReleaseCommandIEValueProtocolIEContainerListAPERValue, error) {
	if c.encode == nil {
		return UEContextReleaseCommandIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return UEContextReleaseCommandIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return UEContextReleaseCommandIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return UEContextReleaseCommandIEValueProtocolIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c UEContextReleaseCommandIEValueProtocolIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (UEContextReleaseCommandIEValueProtocolIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return UEContextReleaseCommandIEValueProtocolIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return UEContextReleaseCommandIEValueProtocolIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return UEContextReleaseCommandIEValueProtocolIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return UEContextReleaseCommandIEValueProtocolIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c UEContextReleaseCommandIEValueProtocolIEContainerListValueCodec) EncodeAPER(value UEContextReleaseCommandIEValueProtocolIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c UEContextReleaseCommandIEValueProtocolIEContainerListValueCodec) encodeBudgetValue(value UEContextReleaseCommandIEValueProtocolIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c UEContextReleaseCommandIEValueProtocolIEContainerListValueCodec) encodeChanged(value UEContextReleaseCommandIEValueProtocolIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// UEContextReleaseCommandIEValueProtocolIEContainerList is ProtocolIE-ContainerList with IEsSetParam = {UEContextReleaseCommand-IEs} of TS 36.413: a list of information element fields with lowerBound and upperBound supplied by its concrete factory.
type UEContextReleaseCommandIEValueProtocolIEContainerList []UEContextReleaseCommandIEValueProtocolIESingleContainer

func BridgeUEContextReleaseCommandIEValueCaptureS1APProtocolIEContainerList(v *UEContextReleaseCommandIEValueProtocolIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeUEContextReleaseCommandIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeUEContextReleaseCommandIEValueCompareS1APProtocolIEContainerList(v *UEContextReleaseCommandIEValueProtocolIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeUEContextReleaseCommandIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeUERadioCapabilityMatchResponseIEValueCompareS1APProtocolIEContainerList(v *s24.UERadioCapabilityMatchResponseIEValueProtocolIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeUERadioCapabilityMatchResponseIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}

// ENBCPRelocationIndicationIEValueERABIEContainerListAPERValue is the concrete APERValue[ENBCPRelocationIndicationIEValueERABIEContainerList].
type ENBCPRelocationIndicationIEValueERABIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         ENBCPRelocationIndicationIEValueERABIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ENBCPRelocationIndicationIEValueERABIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ENBCPRelocationIndicationIEValueERABIEContainerListAPERValue) WithoutReplay() ENBCPRelocationIndicationIEValueERABIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ENBCPRelocationIndicationIEValueProtocolIESingleContainer is ProtocolIE-SingleContainer {{ENBCPRelocationIndicationIEs}} of TS 36.413: a single information element field.
type ENBCPRelocationIndicationIEValueProtocolIESingleContainer = ENBCPRelocationIndicationIEField

func BridgeENBCPRelocationIndicationIEValueCaptureS1APProtocolIESingleContainer(v *ENBCPRelocationIndicationIEValueProtocolIESingleContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeENBCPRelocationIndicationIEValueCaptureS1APProtocolIEField(v, s)
	s.End(f, nil, false)
}
func BridgeENBCPRelocationIndicationIEValueCompareS1APProtocolIESingleContainer(v *ENBCPRelocationIndicationIEValueProtocolIESingleContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeENBCPRelocationIndicationIEValueCompareS1APProtocolIEField(v, s)
	s.End(f, aper.Snapshot{}, false)
}

// ENBEarlyStatusTransferIEValueERABIEContainerListAPERValue is the concrete APERValue[ENBEarlyStatusTransferIEValueERABIEContainerList].
type ENBEarlyStatusTransferIEValueERABIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         ENBEarlyStatusTransferIEValueERABIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ENBEarlyStatusTransferIEValueERABIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ENBEarlyStatusTransferIEValueERABIEContainerListAPERValue) WithoutReplay() ENBEarlyStatusTransferIEValueERABIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ENBEarlyStatusTransferIEValueProtocolIESingleContainer is ProtocolIE-SingleContainer {{ENBEarlyStatusTransferIEs}} of TS 36.413: a single information element field.
type ENBEarlyStatusTransferIEValueProtocolIESingleContainer = ENBEarlyStatusTransferIEField

func BridgeENBEarlyStatusTransferIEValueCaptureS1APProtocolIESingleContainer(v *ENBEarlyStatusTransferIEValueProtocolIESingleContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeENBEarlyStatusTransferIEValueCaptureS1APProtocolIEField(v, s)
	s.End(f, nil, false)
}

// MMEEarlyStatusTransferIEValueERABIEContainerListAPERValue is the concrete APERValue[MMEEarlyStatusTransferIEValueERABIEContainerList].
type MMEEarlyStatusTransferIEValueERABIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         MMEEarlyStatusTransferIEValueERABIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v MMEEarlyStatusTransferIEValueERABIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v MMEEarlyStatusTransferIEValueERABIEContainerListAPERValue) WithoutReplay() MMEEarlyStatusTransferIEValueERABIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// MMEEarlyStatusTransferIEValueProtocolIESingleContainer is ProtocolIE-SingleContainer {{MMEEarlyStatusTransferIEs}} of TS 36.413: a single information element field.
type MMEEarlyStatusTransferIEValueProtocolIESingleContainer = MMEEarlyStatusTransferIEField

// UEContextReleaseCommandIEValueERABIEContainerListAPERValue is the concrete APERValue[UEContextReleaseCommandIEValueERABIEContainerList].
type UEContextReleaseCommandIEValueERABIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         UEContextReleaseCommandIEValueERABIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v UEContextReleaseCommandIEValueERABIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v UEContextReleaseCommandIEValueERABIEContainerListAPERValue) WithoutReplay() UEContextReleaseCommandIEValueERABIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// UEContextReleaseCommandIEValueProtocolIESingleContainer is ProtocolIE-SingleContainer {{UEContextReleaseCommand-IEs}} of TS 36.413: a single information element field.
type UEContextReleaseCommandIEValueProtocolIESingleContainer = UEContextReleaseCommandIEField

func BridgeUEContextReleaseCommandIEValueCaptureS1APProtocolIESingleContainer(v *UEContextReleaseCommandIEValueProtocolIESingleContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeUEContextReleaseCommandIEValueCaptureS1APProtocolIEField(v, s)
	s.End(f, nil, false)
}
func BridgeUEContextReleaseCommandIEValueCompareS1APProtocolIESingleContainer(v *UEContextReleaseCommandIEValueProtocolIESingleContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeUEContextReleaseCommandIEValueCompareS1APProtocolIEField(v, s)
	s.End(f, aper.Snapshot{}, false)
}
func BridgeUERadioCapabilityMatchResponseIEValueCompareS1APProtocolIESingleContainer(v *s24.UERadioCapabilityMatchResponseIEValueProtocolIESingleContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s36.BridgeUERadioCapabilityMatchResponseIEValueCompareS1APProtocolIEField(v, s)
	s.End(f, aper.Snapshot{}, false)
}

// ENBEarlyStatusTransferTransparentContainerExtIEsExtFieldAPERValue is the concrete APERValue[ENBEarlyStatusTransferTransparentContainerExtIEsExtField].
type ENBEarlyStatusTransferTransparentContainerExtIEsExtFieldAPERValue struct {
	context       s00.BridgeCodecContext
	Value         ENBEarlyStatusTransferTransparentContainerExtIEsExtField
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ENBEarlyStatusTransferTransparentContainerExtIEsExtFieldAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ENBEarlyStatusTransferTransparentContainerExtIEsExtFieldAPERValue) WithoutReplay() ENBEarlyStatusTransferTransparentContainerExtIEsExtFieldAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ENBEarlyStatusTransferTransparentContainerExtIEsExtContainerAPERValue is the concrete APERValue[ENBEarlyStatusTransferTransparentContainerExtIEsExtContainer].
type ENBEarlyStatusTransferTransparentContainerExtIEsExtContainerAPERValue struct {
	context       s00.BridgeCodecContext
	Value         ENBEarlyStatusTransferTransparentContainerExtIEsExtContainer
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ENBEarlyStatusTransferTransparentContainerExtIEsExtContainerAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ENBEarlyStatusTransferTransparentContainerExtIEsExtContainerAPERValue) WithoutReplay() ENBEarlyStatusTransferTransparentContainerExtIEsExtContainerAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ENBCPRelocationIndicationIEFieldAPERValue is the concrete APERValue[ENBCPRelocationIndicationIEField].
type ENBCPRelocationIndicationIEFieldAPERValue struct {
	context       s00.BridgeCodecContext
	Value         ENBCPRelocationIndicationIEField
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ENBCPRelocationIndicationIEFieldAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ENBCPRelocationIndicationIEFieldAPERValue) WithoutReplay() ENBCPRelocationIndicationIEFieldAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ENBEarlyStatusTransferIEFieldAPERValue is the concrete APERValue[ENBEarlyStatusTransferIEField].
type ENBEarlyStatusTransferIEFieldAPERValue struct {
	context       s00.BridgeCodecContext
	Value         ENBEarlyStatusTransferIEField
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ENBEarlyStatusTransferIEFieldAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ENBEarlyStatusTransferIEFieldAPERValue) WithoutReplay() ENBEarlyStatusTransferIEFieldAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// MMEEarlyStatusTransferIEFieldAPERValue is the concrete APERValue[MMEEarlyStatusTransferIEField].
type MMEEarlyStatusTransferIEFieldAPERValue struct {
	context       s00.BridgeCodecContext
	Value         MMEEarlyStatusTransferIEField
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v MMEEarlyStatusTransferIEFieldAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v MMEEarlyStatusTransferIEFieldAPERValue) WithoutReplay() MMEEarlyStatusTransferIEFieldAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// UEContextReleaseCommandIEFieldAPERValue is the concrete APERValue[UEContextReleaseCommandIEField].
type UEContextReleaseCommandIEFieldAPERValue struct {
	context       s00.BridgeCodecContext
	Value         UEContextReleaseCommandIEField
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v UEContextReleaseCommandIEFieldAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v UEContextReleaseCommandIEFieldAPERValue) WithoutReplay() UEContextReleaseCommandIEFieldAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ENBCPRelocationIndicationIEContainerAPERValue is the concrete APERValue[ENBCPRelocationIndicationIEContainer].
type ENBCPRelocationIndicationIEContainerAPERValue struct {
	context       s00.BridgeCodecContext
	Value         ENBCPRelocationIndicationIEContainer
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ENBCPRelocationIndicationIEContainerAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ENBCPRelocationIndicationIEContainerAPERValue) WithoutReplay() ENBCPRelocationIndicationIEContainerAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ENBEarlyStatusTransferIEContainerAPERValue is the concrete APERValue[ENBEarlyStatusTransferIEContainer].
type ENBEarlyStatusTransferIEContainerAPERValue struct {
	context       s00.BridgeCodecContext
	Value         ENBEarlyStatusTransferIEContainer
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ENBEarlyStatusTransferIEContainerAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ENBEarlyStatusTransferIEContainerAPERValue) WithoutReplay() ENBEarlyStatusTransferIEContainerAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// MMEEarlyStatusTransferIEContainerAPERValue is the concrete APERValue[MMEEarlyStatusTransferIEContainer].
type MMEEarlyStatusTransferIEContainerAPERValue struct {
	context       s00.BridgeCodecContext
	Value         MMEEarlyStatusTransferIEContainer
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v MMEEarlyStatusTransferIEContainerAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v MMEEarlyStatusTransferIEContainerAPERValue) WithoutReplay() MMEEarlyStatusTransferIEContainerAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// UEContextReleaseCommandIEContainerAPERValue is the concrete APERValue[UEContextReleaseCommandIEContainer].
type UEContextReleaseCommandIEContainerAPERValue struct {
	context       s00.BridgeCodecContext
	Value         UEContextReleaseCommandIEContainer
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v UEContextReleaseCommandIEContainerAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v UEContextReleaseCommandIEContainerAPERValue) WithoutReplay() UEContextReleaseCommandIEContainerAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ENBCPRelocationIndicationIEValueProtocolErrorIEContainerListAPERValue is the concrete APERValue[ENBCPRelocationIndicationIEValueProtocolErrorIEContainerList].
type ENBCPRelocationIndicationIEValueProtocolErrorIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         ENBCPRelocationIndicationIEValueProtocolErrorIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ENBCPRelocationIndicationIEValueProtocolErrorIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ENBCPRelocationIndicationIEValueProtocolErrorIEContainerListAPERValue) WithoutReplay() ENBCPRelocationIndicationIEValueProtocolErrorIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ENBEarlyStatusTransferIEValueProtocolErrorIEContainerListAPERValue is the concrete APERValue[ENBEarlyStatusTransferIEValueProtocolErrorIEContainerList].
type ENBEarlyStatusTransferIEValueProtocolErrorIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         ENBEarlyStatusTransferIEValueProtocolErrorIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ENBEarlyStatusTransferIEValueProtocolErrorIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ENBEarlyStatusTransferIEValueProtocolErrorIEContainerListAPERValue) WithoutReplay() ENBEarlyStatusTransferIEValueProtocolErrorIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// MMEEarlyStatusTransferIEValueProtocolErrorIEContainerListAPERValue is the concrete APERValue[MMEEarlyStatusTransferIEValueProtocolErrorIEContainerList].
type MMEEarlyStatusTransferIEValueProtocolErrorIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         MMEEarlyStatusTransferIEValueProtocolErrorIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v MMEEarlyStatusTransferIEValueProtocolErrorIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v MMEEarlyStatusTransferIEValueProtocolErrorIEContainerListAPERValue) WithoutReplay() MMEEarlyStatusTransferIEValueProtocolErrorIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// UEContextReleaseCommandIEValueProtocolErrorIEContainerListAPERValue is the concrete APERValue[UEContextReleaseCommandIEValueProtocolErrorIEContainerList].
type UEContextReleaseCommandIEValueProtocolErrorIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         UEContextReleaseCommandIEValueProtocolErrorIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v UEContextReleaseCommandIEValueProtocolErrorIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v UEContextReleaseCommandIEValueProtocolErrorIEContainerListAPERValue) WithoutReplay() UEContextReleaseCommandIEValueProtocolErrorIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ENBCPRelocationIndicationIEValueProtocolIEContainerListAPERValue is the concrete APERValue[ENBCPRelocationIndicationIEValueProtocolIEContainerList].
type ENBCPRelocationIndicationIEValueProtocolIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         ENBCPRelocationIndicationIEValueProtocolIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ENBCPRelocationIndicationIEValueProtocolIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ENBCPRelocationIndicationIEValueProtocolIEContainerListAPERValue) WithoutReplay() ENBCPRelocationIndicationIEValueProtocolIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ENBEarlyStatusTransferIEValueProtocolIEContainerListAPERValue is the concrete APERValue[ENBEarlyStatusTransferIEValueProtocolIEContainerList].
type ENBEarlyStatusTransferIEValueProtocolIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         ENBEarlyStatusTransferIEValueProtocolIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ENBEarlyStatusTransferIEValueProtocolIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ENBEarlyStatusTransferIEValueProtocolIEContainerListAPERValue) WithoutReplay() ENBEarlyStatusTransferIEValueProtocolIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// MMEEarlyStatusTransferIEValueProtocolIEContainerListAPERValue is the concrete APERValue[MMEEarlyStatusTransferIEValueProtocolIEContainerList].
type MMEEarlyStatusTransferIEValueProtocolIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         MMEEarlyStatusTransferIEValueProtocolIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v MMEEarlyStatusTransferIEValueProtocolIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v MMEEarlyStatusTransferIEValueProtocolIEContainerListAPERValue) WithoutReplay() MMEEarlyStatusTransferIEValueProtocolIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// UEContextReleaseCommandIEValueProtocolIEContainerListAPERValue is the concrete APERValue[UEContextReleaseCommandIEValueProtocolIEContainerList].
type UEContextReleaseCommandIEValueProtocolIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         UEContextReleaseCommandIEValueProtocolIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v UEContextReleaseCommandIEValueProtocolIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v UEContextReleaseCommandIEValueProtocolIEContainerListAPERValue) WithoutReplay() UEContextReleaseCommandIEValueProtocolIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}
func BridgeCaptureS1APActivatedCellsListComplete(v *ActivatedCellsListComplete, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s21.BridgeCaptureS1APActivatedCellsList(&v.Value, s)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APActivatedCellsListComplete(v *ActivatedCellsListComplete, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s21.BridgeCompareS1APActivatedCellsList(&v.Value, s)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APBPLMNsComplete(v *BPLMNsComplete, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APBPLMNs(&v.Value, s)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APBPLMNsComplete(v *BPLMNsComplete, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s07.BridgeCompareS1APBPLMNs(&v.Value, s)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APBearersSubjectToDLDiscardingListComplete(v *BearersSubjectToDLDiscardingListComplete, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s21.BridgeCaptureS1APBearersSubjectToDLDiscardingList(&v.Value, s)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APBearersSubjectToDLDiscardingListComplete(v *BearersSubjectToDLDiscardingListComplete, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s21.BridgeCompareS1APBearersSubjectToDLDiscardingList(&v.Value, s)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APENBCPRelocationIndication(v *ENBCPRelocationIndication, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeENBCPRelocationIndicationIEValueCaptureS1APProtocolIEContainer(&v.ProtocolIEs, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APENBCPRelocationIndication(v *ENBCPRelocationIndication, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeENBCPRelocationIndicationIEValueCompareS1APProtocolIEContainer(&v.ProtocolIEs, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APENBCPRelocationIndicationIEValue(v *ENBCPRelocationIndicationIEValue, s *aper.SemanticCapture) {
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
		case s00.ProtocolIEID(96):
			{
				f := s.Begin()
				s.Bool(v.rowSTMSI == nil)
				if v.rowSTMSI != nil {
					s28.BridgeCaptureS1APSTMSI(v.rowSTMSI, s)
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
		case s00.ProtocolIEID(254):
			{
				f := s.Begin()
				s.Bool(v.rowULCPSecurityInformation == nil)
				if v.rowULCPSecurityInformation != nil {
					BridgeCaptureS1APULCPSecurityInformation(v.rowULCPSecurityInformation, s)
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
func (v ENBCPRelocationIndicationIEValue) captureSemantics(s aper.SemanticCapture) ENBCPRelocationIndicationIEValue {
	BridgeCaptureS1APENBCPRelocationIndicationIEValue(&v, &s)
	return v
}
func BridgeCompareS1APENBCPRelocationIndicationIEValue(v *ENBCPRelocationIndicationIEValue, s *aper.SemanticComparison) {
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
		case s00.ProtocolIEID(96):
			{
				f := s.Begin()
				s.Bool(v.rowSTMSI == nil)
				if v.rowSTMSI != nil {
					s28.BridgeCompareS1APSTMSI(v.rowSTMSI, s)
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
		case s00.ProtocolIEID(254):
			{
				f := s.Begin()
				s.Bool(v.rowULCPSecurityInformation == nil)
				if v.rowULCPSecurityInformation != nil {
					BridgeCompareS1APULCPSecurityInformation(v.rowULCPSecurityInformation, s)
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
func (v ENBCPRelocationIndicationIEValue) compareSemantics(s aper.SemanticComparison) aper.SemanticComparison {
	BridgeCompareS1APENBCPRelocationIndicationIEValue(&v, &s)
	return s
}
func BridgeCaptureS1APENBEarlyStatusTransferIEValue(v *ENBEarlyStatusTransferIEValue, s *aper.SemanticCapture) {
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
		case s00.ProtocolIEID(321):
			{
				f := s.Begin()
				s.Bool(v.rowENBEarlyStatusTransferTransparentContainer == nil)
				if v.rowENBEarlyStatusTransferTransparentContainer != nil {
					BridgeCaptureS1APENBEarlyStatusTransferTransparentContainer(v.rowENBEarlyStatusTransferTransparentContainer, s)
				}
				s.End(f, nil, false)
			}
		}
	}
	s.End(f, &v.replay, false)
	s.CheckReceived(v.replay, v.received)
}
func (v ENBEarlyStatusTransferIEValue) captureSemantics(s aper.SemanticCapture) ENBEarlyStatusTransferIEValue {
	BridgeCaptureS1APENBEarlyStatusTransferIEValue(&v, &s)
	return v
}
func BridgeCompareS1APENBEarlyStatusTransferIEValue(v *ENBEarlyStatusTransferIEValue, s *aper.SemanticComparison) {
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
		case s00.ProtocolIEID(321):
			{
				f := s.Begin()
				s.Bool(v.rowENBEarlyStatusTransferTransparentContainer == nil)
				if v.rowENBEarlyStatusTransferTransparentContainer != nil {
					BridgeCompareS1APENBEarlyStatusTransferTransparentContainer(v.rowENBEarlyStatusTransferTransparentContainer, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		}
	}
	s.End(f, v.replay, false)
	s.CheckReceived(v.replay, v.received)
}
func (v ENBEarlyStatusTransferIEValue) compareSemantics(s aper.SemanticComparison) aper.SemanticComparison {
	BridgeCompareS1APENBEarlyStatusTransferIEValue(&v, &s)
	return s
}
func BridgeCaptureS1APENBEarlyStatusTransferTransparentContainer(v *ENBEarlyStatusTransferTransparentContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s21.BridgeCaptureS1APBearersSubjectToEarlyStatusTransferList(&v.BearersSubjectToEarlyStatusTransferList, s)
	s.Bool(v.IEExtensions == nil)
	BridgeENBEarlyStatusTransferTransparentContainerExtIEsValueCaptureS1APProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APENBEarlyStatusTransferTransparentContainer(v *ENBEarlyStatusTransferTransparentContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s21.BridgeCompareS1APBearersSubjectToEarlyStatusTransferList(&v.BearersSubjectToEarlyStatusTransferList, s)
	s.Bool(v.IEExtensions == nil)
	BridgeENBEarlyStatusTransferTransparentContainerExtIEsValueCompareS1APProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APENBEarlyStatusTransferTransparentContainerExtIEsValue(v *ENBEarlyStatusTransferTransparentContainerExtIEsValue, s *aper.SemanticCapture) {
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
		case s00.ProtocolIEID(352):
			{
				f := s.Begin()
				s.Bool(v.rowBearersSubjectToDLDiscardingList == nil)
				if v.rowBearersSubjectToDLDiscardingList != nil {
					s21.BridgeCaptureS1APBearersSubjectToDLDiscardingList(v.rowBearersSubjectToDLDiscardingList, s)
				}
				s.End(f, nil, false)
			}
		}
	}
	s.End(f, &v.replay, false)
	s.CheckReceived(v.replay, v.received)
}
func (v ENBEarlyStatusTransferTransparentContainerExtIEsValue) captureSemantics(s aper.SemanticCapture) ENBEarlyStatusTransferTransparentContainerExtIEsValue {
	BridgeCaptureS1APENBEarlyStatusTransferTransparentContainerExtIEsValue(&v, &s)
	return v
}
func BridgeCompareS1APENBEarlyStatusTransferTransparentContainerExtIEsValue(v *ENBEarlyStatusTransferTransparentContainerExtIEsValue, s *aper.SemanticComparison) {
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
		case s00.ProtocolIEID(352):
			{
				f := s.Begin()
				s.Bool(v.rowBearersSubjectToDLDiscardingList == nil)
				if v.rowBearersSubjectToDLDiscardingList != nil {
					s21.BridgeCompareS1APBearersSubjectToDLDiscardingList(v.rowBearersSubjectToDLDiscardingList, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		}
	}
	s.End(f, v.replay, false)
	s.CheckReceived(v.replay, v.received)
}
func (v ENBEarlyStatusTransferTransparentContainerExtIEsValue) compareSemantics(s aper.SemanticComparison) aper.SemanticComparison {
	BridgeCompareS1APENBEarlyStatusTransferTransparentContainerExtIEsValue(&v, &s)
	return s
}
func BridgeCaptureS1APMMEEarlyStatusTransferIEValue(v *MMEEarlyStatusTransferIEValue, s *aper.SemanticCapture) {
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
		case s00.ProtocolIEID(321):
			{
				f := s.Begin()
				s.Bool(v.rowENBEarlyStatusTransferTransparentContainer == nil)
				if v.rowENBEarlyStatusTransferTransparentContainer != nil {
					BridgeCaptureS1APENBEarlyStatusTransferTransparentContainer(v.rowENBEarlyStatusTransferTransparentContainer, s)
				}
				s.End(f, nil, false)
			}
		}
	}
	s.End(f, &v.replay, false)
	s.CheckReceived(v.replay, v.received)
}
func (v MMEEarlyStatusTransferIEValue) captureSemantics(s aper.SemanticCapture) MMEEarlyStatusTransferIEValue {
	BridgeCaptureS1APMMEEarlyStatusTransferIEValue(&v, &s)
	return v
}
func BridgeCompareS1APMMEEarlyStatusTransferIEValue(v *MMEEarlyStatusTransferIEValue, s *aper.SemanticComparison) {
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
		case s00.ProtocolIEID(321):
			{
				f := s.Begin()
				s.Bool(v.rowENBEarlyStatusTransferTransparentContainer == nil)
				if v.rowENBEarlyStatusTransferTransparentContainer != nil {
					BridgeCompareS1APENBEarlyStatusTransferTransparentContainer(v.rowENBEarlyStatusTransferTransparentContainer, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		}
	}
	s.End(f, v.replay, false)
	s.CheckReceived(v.replay, v.received)
}
func (v MMEEarlyStatusTransferIEValue) compareSemantics(s aper.SemanticComparison) aper.SemanticComparison {
	BridgeCompareS1APMMEEarlyStatusTransferIEValue(&v, &s)
	return s
}
func BridgeCaptureS1APUEContextReleaseCommand(v *UEContextReleaseCommand, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeUEContextReleaseCommandIEValueCaptureS1APProtocolIEContainer(&v.ProtocolIEs, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APUEContextReleaseCommand(v *UEContextReleaseCommand, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeUEContextReleaseCommandIEValueCompareS1APProtocolIEContainer(&v.ProtocolIEs, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APUEContextReleaseCommandIEValue(v *UEContextReleaseCommandIEValue, s *aper.SemanticCapture) {
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
		case s00.ProtocolIEID(99):
			{
				f := s.Begin()
				s.Bool(v.rowUES1APIDs == nil)
				if v.rowUES1APIDs != nil {
					BridgeCaptureS1APUES1APIDs(v.rowUES1APIDs, s)
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
		}
	}
	s.End(f, &v.replay, false)
	s.CheckReceived(v.replay, v.received)
}
func (v UEContextReleaseCommandIEValue) captureSemantics(s aper.SemanticCapture) UEContextReleaseCommandIEValue {
	BridgeCaptureS1APUEContextReleaseCommandIEValue(&v, &s)
	return v
}
func BridgeCompareS1APUEContextReleaseCommandIEValue(v *UEContextReleaseCommandIEValue, s *aper.SemanticComparison) {
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
		case s00.ProtocolIEID(99):
			{
				f := s.Begin()
				s.Bool(v.rowUES1APIDs == nil)
				if v.rowUES1APIDs != nil {
					BridgeCompareS1APUES1APIDs(v.rowUES1APIDs, s)
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
		}
	}
	s.End(f, v.replay, false)
	s.CheckReceived(v.replay, v.received)
}
func (v UEContextReleaseCommandIEValue) compareSemantics(s aper.SemanticComparison) aper.SemanticComparison {
	BridgeCompareS1APUEContextReleaseCommandIEValue(&v, &s)
	return s
}
func BridgeCaptureS1APUERadioCapabilityMatchResponse(v *UERadioCapabilityMatchResponse, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s36.BridgeUERadioCapabilityMatchResponseIEValueCaptureS1APProtocolIEContainer(&v.ProtocolIEs, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APUERadioCapabilityMatchResponse(v *UERadioCapabilityMatchResponse, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeUERadioCapabilityMatchResponseIEValueCompareS1APProtocolIEContainer(&v.ProtocolIEs, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APUES1APIDPair(v *UES1APIDPair, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APMMEUES1APID(&v.MMEUES1APID, s)
	s00.BridgeCaptureS1APENBUES1APID(&v.ENBUES1APID, s)
	s.Bool(v.IEExtensions == nil)
	BridgeUES1APIDPairExtIEsValueCaptureS1APProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APUES1APIDPair(v *UES1APIDPair, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s02.BridgeCompareS1APMMEUES1APID(&v.MMEUES1APID, s)
	s02.BridgeCompareS1APENBUES1APID(&v.ENBUES1APID, s)
	s.Bool(v.IEExtensions == nil)
	BridgeUES1APIDPairExtIEsValueCompareS1APProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APUES1APIDs(v *UES1APIDs, s *aper.SemanticCapture) {
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
	case s00.UES1APIDsChoiceUES1APIDPair:
		{
			f := s.Begin()
			s.Bool(v.UES1APIDPair == nil)
			if v.UES1APIDPair != nil {
				BridgeCaptureS1APUES1APIDPair(v.UES1APIDPair, s)
			}
			s.End(f, nil, false)
		}
	case s00.UES1APIDsChoiceMMEUES1APID:
		{
			f := s.Begin()
			s.Bool(v.MMEUES1APID == nil)
			if v.MMEUES1APID != nil {
				s00.BridgeCaptureS1APMMEUES1APID(v.MMEUES1APID, s)
			}
			s.End(f, nil, false)
		}
	}
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APUES1APIDs(v *UES1APIDs, s *aper.SemanticComparison) {
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
	case s00.UES1APIDsChoiceUES1APIDPair:
		{
			f := s.Begin()
			s.Bool(v.UES1APIDPair == nil)
			if v.UES1APIDPair != nil {
				BridgeCompareS1APUES1APIDPair(v.UES1APIDPair, s)
			}
			s.End(f, aper.Snapshot{}, false)
		}
	case s00.UES1APIDsChoiceMMEUES1APID:
		{
			f := s.Begin()
			s.Bool(v.MMEUES1APID == nil)
			if v.MMEUES1APID != nil {
				s02.BridgeCompareS1APMMEUES1APID(v.MMEUES1APID, s)
			}
			s.End(f, aper.Snapshot{}, false)
		}
	}
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APUESecurityCapabilities(v *UESecurityCapabilities, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APEncryptionAlgorithms(&v.EncryptionAlgorithms, s)
	s00.BridgeCaptureS1APIntegrityProtectionAlgorithms(&v.IntegrityProtectionAlgorithms, s)
	s.Bool(v.IEExtensions == nil)
	BridgeUESecurityCapabilitiesExtIEsValueCaptureS1APProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APUESecurityCapabilities(v *UESecurityCapabilities, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s02.BridgeCompareS1APEncryptionAlgorithms(&v.EncryptionAlgorithms, s)
	s02.BridgeCompareS1APIntegrityProtectionAlgorithms(&v.IntegrityProtectionAlgorithms, s)
	s.Bool(v.IEExtensions == nil)
	BridgeUESecurityCapabilitiesExtIEsValueCompareS1APProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APUESidelinkAggregateMaximumBitrate(v *UESidelinkAggregateMaximumBitrate, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APBitRate(&v.UESidelinkAggregateMaximumBitRate, s)
	s.Bool(v.IEExtensions == nil)
	BridgeUESidelinkAggregateMaximumBitratesExtIEsValueCaptureS1APProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APUESidelinkAggregateMaximumBitrate(v *UESidelinkAggregateMaximumBitrate, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s02.BridgeCompareS1APBitRate(&v.UESidelinkAggregateMaximumBitRate, s)
	s.Bool(v.IEExtensions == nil)
	BridgeUESidelinkAggregateMaximumBitratesExtIEsValueCompareS1APProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APULCPSecurityInformation(v *ULCPSecurityInformation, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APULNASMAC(&v.UlNASMAC, s)
	s00.BridgeCaptureS1APULNASCount(&v.UlNASCount, s)
	s.Bool(v.IEExtensions == nil)
	BridgeULCPSecurityInformationExtIEsValueCaptureS1APProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APULCPSecurityInformation(v *ULCPSecurityInformation, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s07.BridgeCompareS1APULNASMAC(&v.UlNASMAC, s)
	s07.BridgeCompareS1APULNASCount(&v.UlNASCount, s)
	s.Bool(v.IEExtensions == nil)
	BridgeULCPSecurityInformationExtIEsValueCompareS1APProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, v.replay, v.withoutReplay)
}

// ENBEarlyStatusTransferTransparentContainer represents the ASN.1 type ENB-EarlyStatusTransfer-TransparentContainer (SEQUENCE).
type ENBEarlyStatusTransferTransparentContainer struct {
	replay                                       aper.Snapshot
	stream                                       aper.WireSpan
	received                                     bool
	withoutReplay                                bool
	receivedAbsolute                             bool
	receivedBytes                                aper.WireSpan
	receivedLocation                             aper.Location
	BearersSubjectToEarlyStatusTransferList      s15.BearersSubjectToEarlyStatusTransferList                  `asn1:"tag:0,context,implicit"`
	bearersSubjectToEarlyStatusTransferListIndef bool                                                         `asn1:"-" json:"-"`
	IEExtensions                                 ENBEarlyStatusTransferTransparentContainerExtIEsExtContainer `asn1:"tag:1,context,implicit,optional" json:"IEExtensions,omitzero"`
	iEExtensionsIndef                            bool                                                         `asn1:"-" json:"-"`
	extCount                                     int64                                                        `asn1:"-" json:"-"`
	extPresent                                   []bool                                                       `asn1:"-" json:"-"`
	extData                                      [][]byte                                                     `asn1:"-" json:"-"`
	perPadding                                   aper.FinalPadding                                            `asn1:"-" json:"-"`
	perExtPadding                                []aper.CompletePadding                                       `asn1:"-" json:"-"`
	extOrigin                                    []aper.OpaqueOrigin
	extWire                                      []aper.WireSpan
}

// UES1APIDs represents the ASN.1 CHOICE type UE-S1AP-IDs.
type UES1APIDs struct {
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
	UES1APIDPair       *UES1APIDPair         `json:"UES1APIDPair,omitempty"`
	MMEUES1APID        *s00.MMEUES1APID      `json:"MMEUES1APID,omitempty"`
}

// NewUES1APIDsUES1APIDPair creates a UES1APIDs with the uE-S1AP-ID-pair alternative.
func BridgeNewUES1APIDsUES1APIDPairLegacy(v UES1APIDPair) UES1APIDs {
	return UES1APIDs{
		Choice:       s00.UES1APIDsChoiceUES1APIDPair,
		UES1APIDPair: &v,
	}
}

// NewUES1APIDsMMEUES1APID creates a UES1APIDs with the mME-UE-S1AP-ID alternative.
func BridgeNewUES1APIDsMMEUES1APIDLegacy(v s00.MMEUES1APID) UES1APIDs {
	return UES1APIDs{
		Choice:      s00.UES1APIDsChoiceMMEUES1APID,
		MMEUES1APID: &v,
	}
}

// UES1APIDPair represents the ASN.1 type UE-S1AP-ID-pair (SEQUENCE).
type UES1APIDPair struct {
	replay            aper.Snapshot
	stream            aper.WireSpan
	received          bool
	withoutReplay     bool
	receivedAbsolute  bool
	receivedBytes     aper.WireSpan
	receivedLocation  aper.Location
	MMEUES1APID       s00.MMEUES1APID                    `asn1:"tag:0,context,implicit"`
	ENBUES1APID       s00.ENBUES1APID                    `asn1:"tag:1,context,implicit"`
	IEExtensions      s12.UES1APIDPairExtIEsExtContainer `asn1:"tag:2,context,implicit,optional" json:"IEExtensions,omitzero"`
	iEExtensionsIndef bool                               `asn1:"-" json:"-"`
	extCount          int64                              `asn1:"-" json:"-"`
	extPresent        []bool                             `asn1:"-" json:"-"`
	extData           [][]byte                           `asn1:"-" json:"-"`
	perPadding        aper.FinalPadding                  `asn1:"-" json:"-"`
	perExtPadding     []aper.CompletePadding             `asn1:"-" json:"-"`
	extOrigin         []aper.OpaqueOrigin
	extWire           []aper.WireSpan
}

// UESecurityCapabilities represents the ASN.1 type UESecurityCapabilities (SEQUENCE).
type UESecurityCapabilities struct {
	replay                        aper.Snapshot
	stream                        aper.WireSpan
	received                      bool
	withoutReplay                 bool
	receivedAbsolute              bool
	receivedBytes                 aper.WireSpan
	receivedLocation              aper.Location
	EncryptionAlgorithms          s00.EncryptionAlgorithms                     `asn1:"tag:0,context,implicit"`
	IntegrityProtectionAlgorithms s00.IntegrityProtectionAlgorithms            `asn1:"tag:1,context,implicit"`
	IEExtensions                  s12.UESecurityCapabilitiesExtIEsExtContainer `asn1:"tag:2,context,implicit,optional" json:"IEExtensions,omitzero"`
	iEExtensionsIndef             bool                                         `asn1:"-" json:"-"`
	extCount                      int64                                        `asn1:"-" json:"-"`
	extPresent                    []bool                                       `asn1:"-" json:"-"`
	extData                       [][]byte                                     `asn1:"-" json:"-"`
	perPadding                    aper.FinalPadding                            `asn1:"-" json:"-"`
	perExtPadding                 []aper.CompletePadding                       `asn1:"-" json:"-"`
	extOrigin                     []aper.OpaqueOrigin
	extWire                       []aper.WireSpan
}

// UESidelinkAggregateMaximumBitrate represents the ASN.1 type UESidelinkAggregateMaximumBitrate (SEQUENCE).
type UESidelinkAggregateMaximumBitrate struct {
	replay                            aper.Snapshot
	stream                            aper.WireSpan
	received                          bool
	withoutReplay                     bool
	receivedAbsolute                  bool
	receivedBytes                     aper.WireSpan
	receivedLocation                  aper.Location
	UESidelinkAggregateMaximumBitRate s00.BitRate                                              `asn1:"tag:0,context,implicit"`
	IEExtensions                      s12.UESidelinkAggregateMaximumBitratesExtIEsExtContainer `asn1:"tag:1,context,implicit,optional" json:"IEExtensions,omitzero"`
	iEExtensionsIndef                 bool                                                     `asn1:"-" json:"-"`
	extCount                          int64                                                    `asn1:"-" json:"-"`
	extPresent                        []bool                                                   `asn1:"-" json:"-"`
	extData                           [][]byte                                                 `asn1:"-" json:"-"`
	perPadding                        aper.FinalPadding                                        `asn1:"-" json:"-"`
	perExtPadding                     []aper.CompletePadding                                   `asn1:"-" json:"-"`
	extOrigin                         []aper.OpaqueOrigin
	extWire                           []aper.WireSpan
}

// ULCPSecurityInformation represents the ASN.1 type UL-CP-SecurityInformation (SEQUENCE).
type ULCPSecurityInformation struct {
	replay            aper.Snapshot
	stream            aper.WireSpan
	received          bool
	withoutReplay     bool
	receivedAbsolute  bool
	receivedBytes     aper.WireSpan
	receivedLocation  aper.Location
	UlNASMAC          s00.ULNASMAC                                  `asn1:"tag:0,context,implicit"`
	UlNASCount        s00.ULNASCount                                `asn1:"tag:1,context,implicit"`
	IEExtensions      s12.ULCPSecurityInformationExtIEsExtContainer `asn1:"tag:2,context,implicit,optional" json:"IEExtensions,omitzero"`
	iEExtensionsIndef bool                                          `asn1:"-" json:"-"`
	extCount          int64                                         `asn1:"-" json:"-"`
	extPresent        []bool                                        `asn1:"-" json:"-"`
	extData           [][]byte                                      `asn1:"-" json:"-"`
	perPadding        aper.FinalPadding                             `asn1:"-" json:"-"`
	perExtPadding     []aper.CompletePadding                        `asn1:"-" json:"-"`
	extOrigin         []aper.OpaqueOrigin
	extWire           []aper.WireSpan
}

// BearersSubjectToDLDiscardingListComplete carries a complete BearersSubjectToDLDiscardingList encoding, including observed terminal bits.
// ITU-T X.691 (02/2021) 11.1.3.1 and 11.1.4 require new encodings to pad with zero bits.
type BearersSubjectToDLDiscardingListComplete struct {
	replay           aper.Snapshot
	stream           aper.WireSpan
	received         bool
	withoutReplay    bool
	receivedAbsolute bool
	receivedBytes    aper.WireSpan
	receivedLocation aper.Location
	Value            s15.BearersSubjectToDLDiscardingList
	perPadding       aper.CompletePadding `json:"-"`
}

func (v *BearersSubjectToDLDiscardingListComplete) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := s25.BridgeMarshalAPERBearersSubjectToDLDiscardingListTo(v.Value, bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.perPadding)
}

// UnmarshalAPER decodes BearersSubjectToDLDiscardingList from APER format.
func (v *BearersSubjectToDLDiscardingListComplete) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes BearersSubjectToDLDiscardingList with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *BearersSubjectToDLDiscardingListComplete) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "BearersSubjectToDLDiscardingList")
	}
	bb.EnterComponent("BearersSubjectToDLDiscardingList")
	value, err := BridgeUnmarshalAPERBearersSubjectToDLDiscardingListFrom(bb)
	if err != nil {
		return runtime.WrapDecodePath(err, "BearersSubjectToDLDiscardingList")
	}
	padding, err := aper.CaptureFinalBits(bb, "BearersSubjectToDLDiscardingList")
	if err != nil {
		return runtime.WrapDecodePath(err, "BearersSubjectToDLDiscardingList")
	}
	v.Value, v.perPadding = value, padding.Padding()
	return nil
}

// UnmarshalAPERBearersSubjectToDLDiscardingListFrom decodes a BearersSubjectToDLDiscardingList list from bb.
func BridgeUnmarshalAPERBearersSubjectToDLDiscardingListFrom(bb *aper.BitBuffer) (s15.BearersSubjectToDLDiscardingList, error) {
	if err := bb.EnterDecodeValue(); err != nil {
		return nil, err
	}
	defer bb.LeaveDecodeValue()
	var v s21.BridgeAsn1cAPERBearersSubjectToDLDiscardingListListValue
	if err := BridgeUnmarshalAPERBearersSubjectToDLDiscardingListInto(&v, bb); err != nil {
		return nil, err
	}
	return v.Value, nil
}
func BridgeUnmarshalAPERBearersSubjectToDLDiscardingListInto(v *s21.BridgeAsn1cAPERBearersSubjectToDLDiscardingListListValue, bb *aper.BitBuffer) error {
	toleranceMark_value := bb.EnterComponent("Value")
	v.Value = make(s15.BearersSubjectToDLDiscardingList, 0)
	_, errCollection_value := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 256, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1128
		if fragmentOffset_value < 0 || fragmentLength_value < 0 || fragmentLength_value > int64(^uint(0)>>1) || fragmentOffset_value > int64(^uint(0)>>1)-fragmentLength_value {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_value; i++ {
			var elem s15.BearersSubjectToDLDiscardingItemIEValueProtocolIESingleContainer
			elementMark := bb.EnterIndex(fragmentOffset_value + i)
			if err := s15.BridgeBearersSubjectToDLDiscardingItemIEFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
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

// BPLMNsComplete carries a complete BPLMNs encoding, including observed terminal bits.
// ITU-T X.691 (02/2021) 11.1.3.1 and 11.1.4 require new encodings to pad with zero bits.
type BPLMNsComplete struct {
	replay           aper.Snapshot
	stream           aper.WireSpan
	received         bool
	withoutReplay    bool
	receivedAbsolute bool
	receivedBytes    aper.WireSpan
	receivedLocation aper.Location
	Value            s00.BPLMNs
	perPadding       aper.CompletePadding `json:"-"`
}

func (v *BPLMNsComplete) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := s13.BridgeMarshalAPERBPLMNsTo(v.Value, bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.perPadding)
}

// UnmarshalAPER decodes BPLMNs from APER format.
func (v *BPLMNsComplete) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes BPLMNs with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *BPLMNsComplete) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "BPLMNs")
	}
	bb.EnterComponent("BPLMNs")
	value, err := BridgeUnmarshalAPERBPLMNsFrom(bb)
	if err != nil {
		return runtime.WrapDecodePath(err, "BPLMNs")
	}
	padding, err := aper.CaptureFinalBits(bb, "BPLMNs")
	if err != nil {
		return runtime.WrapDecodePath(err, "BPLMNs")
	}
	v.Value, v.perPadding = value, padding.Padding()
	return nil
}

// MarshalAPERBPLMNs encodes a BPLMNs list to APER.
func BridgeMarshalAPERBPLMNs(list BPLMNsComplete) ([]byte, error) { return list.marshalAPERLegacy() }

// UnmarshalAPERBPLMNs decodes a BPLMNs list from APER.
func BridgeUnmarshalAPERBPLMNs(data []byte) (BPLMNsComplete, error) {
	var value BPLMNsComplete
	if err := value.unmarshalAPERLegacy(data); err != nil {
		return value, err
	}
	return value, nil
}

// UnmarshalAPERBPLMNsFrom decodes a BPLMNs list from bb.
func BridgeUnmarshalAPERBPLMNsFrom(bb *aper.BitBuffer) (s00.BPLMNs, error) {
	if err := bb.EnterDecodeValue(); err != nil {
		return nil, err
	}
	defer bb.LeaveDecodeValue()
	var v s00.BridgeAsn1cAPERBPLMNsListValue
	if err := BridgeUnmarshalAPERBPLMNsInto(&v, bb); err != nil {
		return nil, err
	}
	return v.Value, nil
}
func BridgeUnmarshalAPERBPLMNsInto(v *s00.BridgeAsn1cAPERBPLMNsListValue, bb *aper.BitBuffer) error {
	toleranceMark_value := bb.EnterComponent("Value")
	v.Value = make(s00.BPLMNs, 0)
	_, errCollection_value := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 6, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
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

// MarshalAPER encodes ENBEarlyStatusTransferTransparentContainer to APER format.
func (v *ENBEarlyStatusTransferTransparentContainer) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *ENBEarlyStatusTransferTransparentContainer) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
	if err := aper.EncodeCollection(bb, int64(len(v.BearersSubjectToEarlyStatusTransferList)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 256, HasUpper: true}, true, func(fragmentOffset_bearerssubjecttoearlystatustransferlist, fragmentLength_bearerssubjecttoearlystatustransferlist int64) error {
		// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
		if fragmentOffset_bearerssubjecttoearlystatustransferlist < 0 || fragmentOffset_bearerssubjecttoearlystatustransferlist > int64(len(v.BearersSubjectToEarlyStatusTransferList)) || fragmentLength_bearerssubjecttoearlystatustransferlist < 0 || fragmentLength_bearerssubjecttoearlystatustransferlist > int64(len(v.BearersSubjectToEarlyStatusTransferList[fragmentOffset_bearerssubjecttoearlystatustransferlist:])) {
			return fmt.Errorf("collection fragment outside value")
		}
		for _, elem := range v.BearersSubjectToEarlyStatusTransferList[fragmentOffset_bearerssubjecttoearlystatustransferlist : fragmentOffset_bearerssubjecttoearlystatustransferlist+fragmentLength_bearerssubjecttoearlystatustransferlist] {
			if err := s15.BridgeBearersSubjectToEarlyStatusTransferItemIEFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
				return fmt.Errorf("encoding bearers-SubjectToEarlyStatusTransferList element: %w", err)
			}
		}
		return nil
	}); err != nil {
		return fmt.Errorf("encoding bearers-SubjectToEarlyStatusTransferList: %w", err)
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

// UnmarshalAPER decodes ENBEarlyStatusTransferTransparentContainer from APER format.
func (v *ENBEarlyStatusTransferTransparentContainer) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes ENBEarlyStatusTransferTransparentContainer with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *ENBEarlyStatusTransferTransparentContainer) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "ENBEarlyStatusTransferTransparentContainer")
	}
	bb.EnterComponent("ENBEarlyStatusTransferTransparentContainer")
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "ENBEarlyStatusTransferTransparentContainer")
	}
	padding, err := aper.CaptureFinalBits(bb, "ENBEarlyStatusTransferTransparentContainer")
	if err != nil {
		return runtime.WrapDecodePath(err, "ENBEarlyStatusTransferTransparentContainer")
	}
	v.perPadding = padding.WithRecords(v.perPadding)
	return nil
}
func (v *ENBEarlyStatusTransferTransparentContainer) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = ENBEarlyStatusTransferTransparentContainer{}
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
	toleranceMark_bearerssubjecttoearlystatustransferlist := bb.EnterComponent("BearersSubjectToEarlyStatusTransferList")
	v.BearersSubjectToEarlyStatusTransferList = make(s15.BearersSubjectToEarlyStatusTransferList, 0)
	_, errCollection_bearerssubjecttoearlystatustransferlist := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 256, HasUpper: true}, true, func(fragmentOffset_bearerssubjecttoearlystatustransferlist, fragmentLength_bearerssubjecttoearlystatustransferlist int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1128
		if fragmentOffset_bearerssubjecttoearlystatustransferlist < 0 || fragmentLength_bearerssubjecttoearlystatustransferlist < 0 || fragmentLength_bearerssubjecttoearlystatustransferlist > int64(^uint(0)>>1) || fragmentOffset_bearerssubjecttoearlystatustransferlist > int64(^uint(0)>>1)-fragmentLength_bearerssubjecttoearlystatustransferlist {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_bearerssubjecttoearlystatustransferlist; i++ {
			var elem s15.BearersSubjectToEarlyStatusTransferItemIEValueProtocolIESingleContainer
			elementMark := bb.EnterIndex(fragmentOffset_bearerssubjecttoearlystatustransferlist + i)
			if err := s15.BridgeBearersSubjectToEarlyStatusTransferItemIEFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
				return runtime.WrapDecodePath(err, fmt.Sprintf("BearersSubjectToEarlyStatusTransferList[%d]", fragmentOffset_bearerssubjecttoearlystatustransferlist+i))
			}
			bb.LeaveComponent(elementMark)
			if next, err := aper.AppendValues(bb, v.BearersSubjectToEarlyStatusTransferList, elem); err != nil {
				return err
			} else {
				v.BearersSubjectToEarlyStatusTransferList = next
			}
		}
		return nil
	})
	if errCollection_bearerssubjecttoearlystatustransferlist != nil {
		return runtime.WrapDecodePath(errCollection_bearerssubjecttoearlystatustransferlist, "BearersSubjectToEarlyStatusTransferList")
	}
	bb.LeaveComponent(toleranceMark_bearerssubjecttoearlystatustransferlist)
	if opt_ieextensions {
		toleranceMark_ieextensions := bb.EnterComponent("IEExtensions")
		tmp_ieextensions := make(ENBEarlyStatusTransferTransparentContainerExtIEsExtContainer, 0)
		_, errCollection_ieextensions := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1128
			if fragmentOffset_ieextensions < 0 || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(^uint(0)>>1) || fragmentOffset_ieextensions > int64(^uint(0)>>1)-fragmentLength_ieextensions {
				return fmt.Errorf("collection fragment count out of range")
			}
			for i := int64(0); i < fragmentLength_ieextensions; i++ {
				var elem ENBEarlyStatusTransferTransparentContainerExtIEsExtField
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

// MarshalAPER encodes UES1APIDs to APER format.
func (v *UES1APIDs) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.perPadding)
}
func (v *UES1APIDs) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
			return fmt.Errorf("%s known choice %d and unknown extension are both selected", "UES1APIDs:", v.Choice)
		}
		if v.UnknownExtension.Index() < 0 {
			return fmt.Errorf("%s extension index %d must be non-negative", "UES1APIDs:", v.UnknownExtension.Index())
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
		return fmt.Errorf("%s choice %d must be positive", "UES1APIDs:", v.Choice)
	}
	isExtension := v.Choice > 2
	if err := aper.EncodeBoolean(bb, isExtension); err != nil {
		return err
	}
	if isExtension {
		return fmt.Errorf("%s extension choice %d not supported", "UES1APIDs:", v.Choice)
	}
	// arithmetic pattern APER_CHOICE_ROOT_ENCODE: choice index fits the emitted representation; gen/codegen_aper.go:149
	if v.Choice < 1 {
		return fmt.Errorf("choice index outside root")
	}
	if err := aper.EncodeConstrainedWholeNumberAligned(bb, int64(v.Choice-1), 0, 1); err != nil {
		return err
	}
	switch v.Choice {
	case s00.UES1APIDsChoiceUES1APIDPair:
		if v.UES1APIDPair == nil {
			return fmt.Errorf("choice alternative uE-S1AP-ID-pair is nil")
		}
		if err := v.UES1APIDPair.marshalAPERTo(bb, len(fresh) != 0 && fresh[0]); err != nil {
			return fmt.Errorf("encoding uE-S1AP-ID-pair: %w", err)
		}
	case s00.UES1APIDsChoiceMMEUES1APID:
		if v.MMEUES1APID == nil {
			return fmt.Errorf("choice alternative mME-UE-S1AP-ID is nil")
		}
		if err := aper.EncodeIntegerAligned(bb, int64(*v.MMEUES1APID), s07.BridgeInt64Ptr(0), s07.BridgeInt64Ptr(4294967295), false); err != nil {
			return fmt.Errorf("encoding mME-UE-S1AP-ID: %w", err)
		}
	default:
		return fmt.Errorf("unknown UES1APIDs choice %d", v.Choice)
	}
	return nil
}

// UnmarshalAPER decodes UES1APIDs from APER format.
func (v *UES1APIDs) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes UES1APIDs with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *UES1APIDs) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "UES1APIDs")
	}
	bb.EnterComponent("UES1APIDs")
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "UES1APIDs")
	}
	padding, err := aper.CaptureFinalBits(bb, "UES1APIDs")
	if err != nil {
		return runtime.WrapDecodePath(err, "UES1APIDs")
	}
	v.perPadding = padding.Padding()
	return nil
}
func (v *UES1APIDs) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = UES1APIDs{}
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
	case s00.UES1APIDsChoiceUES1APIDPair:
		toleranceMark_ues1apidpair := bb.EnterComponent("UES1APIDPair")
		var dec_ues1apidpair UES1APIDPair
		if err := dec_ues1apidpair.unmarshalAPERFrom(bb); err != nil {
			return runtime.WrapDecodePath(err, "UES1APIDPair")
		}
		if err := aper.ChargeValue(bb, dec_ues1apidpair); err != nil {
			return err
		}
		v.UES1APIDPair = &dec_ues1apidpair
		bb.LeaveComponent(toleranceMark_ues1apidpair)
	case s00.UES1APIDsChoiceMMEUES1APID:
		val_mmeues1apid, err := aper.DecodeIntegerAligned(bb, s07.BridgeInt64Ptr(0), s07.BridgeInt64Ptr(4294967295), false)
		if err != nil {
			return runtime.WrapDecodePath(err, "MMEUES1APID")
		}
		tmp_mmeues1apid := s00.MMEUES1APID(val_mmeues1apid)
		if err := aper.ChargeValue(bb, tmp_mmeues1apid); err != nil {
			return err
		}
		v.MMEUES1APID = (*s00.MMEUES1APID)(bb.OwnInt64(int64(tmp_mmeues1apid)))

	}
	v.stream = bb.CaptureWireSpan(replayStart)

	return nil
}

// MarshalAPER encodes UES1APIDPair to APER format.
func (v *UES1APIDPair) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *UES1APIDPair) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
	if err := aper.EncodeIntegerAligned(bb, int64(v.MMEUES1APID), s07.BridgeInt64Ptr(0), s07.BridgeInt64Ptr(4294967295), false); err != nil {
		return fmt.Errorf("encoding mME-UE-S1AP-ID: %w", err)
	}
	if err := aper.EncodeIntegerAligned(bb, int64(v.ENBUES1APID), s07.BridgeInt64Ptr(0), s07.BridgeInt64Ptr(16777215), false); err != nil {
		return fmt.Errorf("encoding eNB-UE-S1AP-ID: %w", err)
	}
	if v.IEExtensions != nil {
		if err := aper.EncodeCollection(bb, int64(len(v.IEExtensions)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
			if fragmentOffset_ieextensions < 0 || fragmentOffset_ieextensions > int64(len(v.IEExtensions)) || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(len(v.IEExtensions[fragmentOffset_ieextensions:])) {
				return fmt.Errorf("collection fragment outside value")
			}
			for _, elem := range v.IEExtensions[fragmentOffset_ieextensions : fragmentOffset_ieextensions+fragmentLength_ieextensions] {
				if err := s12.BridgeUES1APIDPairExtIEsExtFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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

// UnmarshalAPER decodes UES1APIDPair from APER format.
func (v *UES1APIDPair) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes UES1APIDPair with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *UES1APIDPair) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "UES1APIDPair")
	}
	bb.EnterComponent("UES1APIDPair")
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "UES1APIDPair")
	}
	padding, err := aper.CaptureFinalBits(bb, "UES1APIDPair")
	if err != nil {
		return runtime.WrapDecodePath(err, "UES1APIDPair")
	}
	v.perPadding = padding.WithRecords(v.perPadding)
	return nil
}
func (v *UES1APIDPair) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = UES1APIDPair{}
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
	val_mmeues1apid, err := aper.DecodeIntegerAligned(bb, s07.BridgeInt64Ptr(0), s07.BridgeInt64Ptr(4294967295), false)
	if err != nil {
		return runtime.WrapDecodePath(err, "MMEUES1APID")
	}
	v.MMEUES1APID = s00.MMEUES1APID(val_mmeues1apid)
	val_enbues1apid, err := aper.DecodeIntegerAligned(bb, s07.BridgeInt64Ptr(0), s07.BridgeInt64Ptr(16777215), false)
	if err != nil {
		return runtime.WrapDecodePath(err, "ENBUES1APID")
	}
	v.ENBUES1APID = s00.ENBUES1APID(val_enbues1apid)
	if opt_ieextensions {
		toleranceMark_ieextensions := bb.EnterComponent("IEExtensions")
		tmp_ieextensions := make(s12.UES1APIDPairExtIEsExtContainer, 0)
		_, errCollection_ieextensions := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1128
			if fragmentOffset_ieextensions < 0 || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(^uint(0)>>1) || fragmentOffset_ieextensions > int64(^uint(0)>>1)-fragmentLength_ieextensions {
				return fmt.Errorf("collection fragment count out of range")
			}
			for i := int64(0); i < fragmentLength_ieextensions; i++ {
				var elem s12.UES1APIDPairExtIEsExtField
				elementMark := bb.EnterIndex(fragmentOffset_ieextensions + i)
				if err := s12.BridgeUES1APIDPairExtIEsExtFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
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

// MarshalAPER encodes UESecurityCapabilities to APER format.
func (v *UESecurityCapabilities) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *UESecurityCapabilities) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
	if err := aper.EncodeBitStringAlignedExt(bb, v.EncryptionAlgorithms.Bytes, v.EncryptionAlgorithms.BitLength, 16, 16, true, true); err != nil {
		return fmt.Errorf("encoding encryptionAlgorithms: %w", err)
	}
	if err := aper.EncodeBitStringAlignedExt(bb, v.IntegrityProtectionAlgorithms.Bytes, v.IntegrityProtectionAlgorithms.BitLength, 16, 16, true, true); err != nil {
		return fmt.Errorf("encoding integrityProtectionAlgorithms: %w", err)
	}
	if v.IEExtensions != nil {
		if err := aper.EncodeCollection(bb, int64(len(v.IEExtensions)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
			if fragmentOffset_ieextensions < 0 || fragmentOffset_ieextensions > int64(len(v.IEExtensions)) || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(len(v.IEExtensions[fragmentOffset_ieextensions:])) {
				return fmt.Errorf("collection fragment outside value")
			}
			for _, elem := range v.IEExtensions[fragmentOffset_ieextensions : fragmentOffset_ieextensions+fragmentLength_ieextensions] {
				if err := s12.BridgeUESecurityCapabilitiesExtIEsExtFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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

// UnmarshalAPER decodes UESecurityCapabilities from APER format.
func (v *UESecurityCapabilities) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes UESecurityCapabilities with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *UESecurityCapabilities) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "UESecurityCapabilities")
	}
	bb.EnterComponent("UESecurityCapabilities")
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "UESecurityCapabilities")
	}
	padding, err := aper.CaptureFinalBits(bb, "UESecurityCapabilities")
	if err != nil {
		return runtime.WrapDecodePath(err, "UESecurityCapabilities")
	}
	v.perPadding = padding.WithRecords(v.perPadding)
	return nil
}
func (v *UESecurityCapabilities) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = UESecurityCapabilities{}
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
	bsBytes_encryptionalgorithms, bsBitLen_encryptionalgorithms, err := aper.DecodeBitStringAlignedExt(bb, 16, 16, true, true)
	if err != nil {
		return runtime.WrapDecodePath(err, "EncryptionAlgorithms")
	}
	v.EncryptionAlgorithms = runtime.BitString{Bytes: bsBytes_encryptionalgorithms, BitLength: bsBitLen_encryptionalgorithms}
	bsBytes_integrityprotectionalgorithms, bsBitLen_integrityprotectionalgorithms, err := aper.DecodeBitStringAlignedExt(bb, 16, 16, true, true)
	if err != nil {
		return runtime.WrapDecodePath(err, "IntegrityProtectionAlgorithms")
	}
	v.IntegrityProtectionAlgorithms = runtime.BitString{Bytes: bsBytes_integrityprotectionalgorithms, BitLength: bsBitLen_integrityprotectionalgorithms}
	if opt_ieextensions {
		toleranceMark_ieextensions := bb.EnterComponent("IEExtensions")
		tmp_ieextensions := make(s12.UESecurityCapabilitiesExtIEsExtContainer, 0)
		_, errCollection_ieextensions := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1128
			if fragmentOffset_ieextensions < 0 || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(^uint(0)>>1) || fragmentOffset_ieextensions > int64(^uint(0)>>1)-fragmentLength_ieextensions {
				return fmt.Errorf("collection fragment count out of range")
			}
			for i := int64(0); i < fragmentLength_ieextensions; i++ {
				var elem s12.UESecurityCapabilitiesExtIEsExtField
				elementMark := bb.EnterIndex(fragmentOffset_ieextensions + i)
				if err := s12.BridgeUESecurityCapabilitiesExtIEsExtFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
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

// MarshalAPER encodes UESidelinkAggregateMaximumBitrate to APER format.
func (v *UESidelinkAggregateMaximumBitrate) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *UESidelinkAggregateMaximumBitrate) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
	if err := aper.EncodeIntegerAligned(bb, int64(v.UESidelinkAggregateMaximumBitRate), s07.BridgeInt64Ptr(0), s07.BridgeInt64Ptr(10000000000), false); err != nil {
		return fmt.Errorf("encoding uESidelinkAggregateMaximumBitRate: %w", err)
	}
	if v.IEExtensions != nil {
		if err := aper.EncodeCollection(bb, int64(len(v.IEExtensions)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
			if fragmentOffset_ieextensions < 0 || fragmentOffset_ieextensions > int64(len(v.IEExtensions)) || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(len(v.IEExtensions[fragmentOffset_ieextensions:])) {
				return fmt.Errorf("collection fragment outside value")
			}
			for _, elem := range v.IEExtensions[fragmentOffset_ieextensions : fragmentOffset_ieextensions+fragmentLength_ieextensions] {
				if err := s12.BridgeUESidelinkAggregateMaximumBitratesExtIEsExtFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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

// UnmarshalAPER decodes UESidelinkAggregateMaximumBitrate from APER format.
func (v *UESidelinkAggregateMaximumBitrate) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes UESidelinkAggregateMaximumBitrate with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *UESidelinkAggregateMaximumBitrate) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "UESidelinkAggregateMaximumBitrate")
	}
	bb.EnterComponent("UESidelinkAggregateMaximumBitrate")
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "UESidelinkAggregateMaximumBitrate")
	}
	padding, err := aper.CaptureFinalBits(bb, "UESidelinkAggregateMaximumBitrate")
	if err != nil {
		return runtime.WrapDecodePath(err, "UESidelinkAggregateMaximumBitrate")
	}
	v.perPadding = padding.WithRecords(v.perPadding)
	return nil
}
func (v *UESidelinkAggregateMaximumBitrate) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = UESidelinkAggregateMaximumBitrate{}
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
	val_uesidelinkaggregatemaximumbitrate, err := aper.DecodeIntegerAligned(bb, s07.BridgeInt64Ptr(0), s07.BridgeInt64Ptr(10000000000), false)
	if err != nil {
		return runtime.WrapDecodePath(err, "UESidelinkAggregateMaximumBitRate")
	}
	v.UESidelinkAggregateMaximumBitRate = s00.BitRate(val_uesidelinkaggregatemaximumbitrate)
	if opt_ieextensions {
		toleranceMark_ieextensions := bb.EnterComponent("IEExtensions")
		tmp_ieextensions := make(s12.UESidelinkAggregateMaximumBitratesExtIEsExtContainer, 0)
		_, errCollection_ieextensions := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1128
			if fragmentOffset_ieextensions < 0 || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(^uint(0)>>1) || fragmentOffset_ieextensions > int64(^uint(0)>>1)-fragmentLength_ieextensions {
				return fmt.Errorf("collection fragment count out of range")
			}
			for i := int64(0); i < fragmentLength_ieextensions; i++ {
				var elem s12.UESidelinkAggregateMaximumBitratesExtIEsExtField
				elementMark := bb.EnterIndex(fragmentOffset_ieextensions + i)
				if err := s12.BridgeUESidelinkAggregateMaximumBitratesExtIEsExtFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
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

// MarshalAPER encodes ULCPSecurityInformation to APER format.
func (v *ULCPSecurityInformation) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *ULCPSecurityInformation) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
	if err := aper.EncodeBitStringAligned(bb, v.UlNASMAC.Bytes, v.UlNASMAC.BitLength, 16, 16, true); err != nil {
		return fmt.Errorf("encoding ul-NAS-MAC: %w", err)
	}
	if err := aper.EncodeBitStringAligned(bb, v.UlNASCount.Bytes, v.UlNASCount.BitLength, 5, 5, true); err != nil {
		return fmt.Errorf("encoding ul-NAS-Count: %w", err)
	}
	if v.IEExtensions != nil {
		if err := aper.EncodeCollection(bb, int64(len(v.IEExtensions)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
			if fragmentOffset_ieextensions < 0 || fragmentOffset_ieextensions > int64(len(v.IEExtensions)) || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(len(v.IEExtensions[fragmentOffset_ieextensions:])) {
				return fmt.Errorf("collection fragment outside value")
			}
			for _, elem := range v.IEExtensions[fragmentOffset_ieextensions : fragmentOffset_ieextensions+fragmentLength_ieextensions] {
				if err := s12.BridgeULCPSecurityInformationExtIEsExtFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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

// UnmarshalAPER decodes ULCPSecurityInformation from APER format.
func (v *ULCPSecurityInformation) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes ULCPSecurityInformation with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *ULCPSecurityInformation) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "ULCPSecurityInformation")
	}
	bb.EnterComponent("ULCPSecurityInformation")
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "ULCPSecurityInformation")
	}
	padding, err := aper.CaptureFinalBits(bb, "ULCPSecurityInformation")
	if err != nil {
		return runtime.WrapDecodePath(err, "ULCPSecurityInformation")
	}
	v.perPadding = padding.WithRecords(v.perPadding)
	return nil
}
func (v *ULCPSecurityInformation) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = ULCPSecurityInformation{}
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
	bsBytes_ulnasmac, bsBitLen_ulnasmac, err := aper.DecodeBitStringAligned(bb, 16, 16, true)
	if err != nil {
		return runtime.WrapDecodePath(err, "UlNASMAC")
	}
	v.UlNASMAC = runtime.BitString{Bytes: bsBytes_ulnasmac, BitLength: bsBitLen_ulnasmac}
	bsBytes_ulnascount, bsBitLen_ulnascount, err := aper.DecodeBitStringAligned(bb, 5, 5, true)
	if err != nil {
		return runtime.WrapDecodePath(err, "UlNASCount")
	}
	v.UlNASCount = runtime.BitString{Bytes: bsBytes_ulnascount, BitLength: bsBitLen_ulnascount}
	if opt_ieextensions {
		toleranceMark_ieextensions := bb.EnterComponent("IEExtensions")
		tmp_ieextensions := make(s12.ULCPSecurityInformationExtIEsExtContainer, 0)
		_, errCollection_ieextensions := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1128
			if fragmentOffset_ieextensions < 0 || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(^uint(0)>>1) || fragmentOffset_ieextensions > int64(^uint(0)>>1)-fragmentLength_ieextensions {
				return fmt.Errorf("collection fragment count out of range")
			}
			for i := int64(0); i < fragmentLength_ieextensions; i++ {
				var elem s12.ULCPSecurityInformationExtIEsExtField
				elementMark := bb.EnterIndex(fragmentOffset_ieextensions + i)
				if err := s12.BridgeULCPSecurityInformationExtIEsExtFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
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
func (v *BPLMNsComplete) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s14.BridgeReceivedFormAt(v.received, v.receivedBytes, "BPLMNsComplete", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "BPLMNsComplete", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v BPLMNsComplete) WithoutReplay() BPLMNsComplete {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero BPLMNsComplete
	v.perPadding = zero.perPadding
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *BearersSubjectToDLDiscardingListComplete) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s14.BridgeReceivedFormAt(v.received, v.receivedBytes, "BearersSubjectToDLDiscardingListComplete", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "BearersSubjectToDLDiscardingListComplete", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v BearersSubjectToDLDiscardingListComplete) WithoutReplay() BearersSubjectToDLDiscardingListComplete {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero BearersSubjectToDLDiscardingListComplete
	v.perPadding = zero.perPadding
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *ENBEarlyStatusTransferTransparentContainer) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s14.BridgeReceivedFormAt(v.received, v.receivedBytes, "ENBEarlyStatusTransferTransparentContainer", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "ENBEarlyStatusTransferTransparentContainer", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v ENBEarlyStatusTransferTransparentContainer) WithoutReplay() ENBEarlyStatusTransferTransparentContainer {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero ENBEarlyStatusTransferTransparentContainer
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *UES1APIDPair) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s14.BridgeReceivedFormAt(v.received, v.receivedBytes, "UES1APIDPair", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "UES1APIDPair", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v UES1APIDPair) WithoutReplay() UES1APIDPair {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero UES1APIDPair
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *UES1APIDs) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s14.BridgeReceivedFormAt(v.received, v.receivedBytes, "UES1APIDs", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "UES1APIDs", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v UES1APIDs) WithoutReplay() UES1APIDs {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero UES1APIDs
	v.perPadding = zero.perPadding
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *UESecurityCapabilities) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s14.BridgeReceivedFormAt(v.received, v.receivedBytes, "UESecurityCapabilities", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "UESecurityCapabilities", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v UESecurityCapabilities) WithoutReplay() UESecurityCapabilities {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero UESecurityCapabilities
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *UESidelinkAggregateMaximumBitrate) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s14.BridgeReceivedFormAt(v.received, v.receivedBytes, "UESidelinkAggregateMaximumBitrate", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "UESidelinkAggregateMaximumBitrate", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v UESidelinkAggregateMaximumBitrate) WithoutReplay() UESidelinkAggregateMaximumBitrate {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero UESidelinkAggregateMaximumBitrate
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *ULCPSecurityInformation) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s14.BridgeReceivedFormAt(v.received, v.receivedBytes, "ULCPSecurityInformation", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "ULCPSecurityInformation", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v ULCPSecurityInformation) WithoutReplay() ULCPSecurityInformation {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero ULCPSecurityInformation
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// Extensions returns owned unknown sequence additions.
func (v *ENBEarlyStatusTransferTransparentContainer) Extensions() []aper.SequenceExtension {
	if v == nil {
		return nil
	}
	views := aper.SequenceExtensionViews(v.extPresent, aper.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *ENBEarlyStatusTransferTransparentContainer) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("ENBEarlyStatusTransferTransparentContainer.Extensions[%d]", index))
	}
	if err := aper.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("ENBEarlyStatusTransferTransparentContainer.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *ENBEarlyStatusTransferTransparentContainer) RemoveExtension(index uint64) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("ENBEarlyStatusTransferTransparentContainer.Extensions[%d]", index))
	}
	if err := aper.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("ENBEarlyStatusTransferTransparentContainer.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// Extensions returns owned unknown sequence additions.
func (v *UES1APIDPair) Extensions() []aper.SequenceExtension {
	if v == nil {
		return nil
	}
	views := aper.SequenceExtensionViews(v.extPresent, aper.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *UES1APIDPair) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("UES1APIDPair.Extensions[%d]", index))
	}
	if err := aper.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("UES1APIDPair.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *UES1APIDPair) RemoveExtension(index uint64) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("UES1APIDPair.Extensions[%d]", index))
	}
	if err := aper.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("UES1APIDPair.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// Extensions returns owned unknown sequence additions.
func (v *UESecurityCapabilities) Extensions() []aper.SequenceExtension {
	if v == nil {
		return nil
	}
	views := aper.SequenceExtensionViews(v.extPresent, aper.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *UESecurityCapabilities) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("UESecurityCapabilities.Extensions[%d]", index))
	}
	if err := aper.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("UESecurityCapabilities.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *UESecurityCapabilities) RemoveExtension(index uint64) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("UESecurityCapabilities.Extensions[%d]", index))
	}
	if err := aper.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("UESecurityCapabilities.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// Extensions returns owned unknown sequence additions.
func (v *UESidelinkAggregateMaximumBitrate) Extensions() []aper.SequenceExtension {
	if v == nil {
		return nil
	}
	views := aper.SequenceExtensionViews(v.extPresent, aper.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *UESidelinkAggregateMaximumBitrate) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("UESidelinkAggregateMaximumBitrate.Extensions[%d]", index))
	}
	if err := aper.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("UESidelinkAggregateMaximumBitrate.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *UESidelinkAggregateMaximumBitrate) RemoveExtension(index uint64) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("UESidelinkAggregateMaximumBitrate.Extensions[%d]", index))
	}
	if err := aper.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("UESidelinkAggregateMaximumBitrate.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// Extensions returns owned unknown sequence additions.
func (v *ULCPSecurityInformation) Extensions() []aper.SequenceExtension {
	if v == nil {
		return nil
	}
	views := aper.SequenceExtensionViews(v.extPresent, aper.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *ULCPSecurityInformation) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("ULCPSecurityInformation.Extensions[%d]", index))
	}
	if err := aper.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("ULCPSecurityInformation.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *ULCPSecurityInformation) RemoveExtension(index uint64) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("ULCPSecurityInformation.Extensions[%d]", index))
	}
	if err := aper.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("ULCPSecurityInformation.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// MarshalAPER encodes a complete value using one per-call change plan.
func (v *BPLMNsComplete) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "BPLMNsComplete")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *BPLMNsComplete) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "BPLMNsComplete")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APBPLMNsComplete(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "BPLMNsComplete")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "BPLMNsComplete")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *BPLMNsComplete) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "BPLMNsComplete")
}
func (v *BPLMNsComplete) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "BPLMNsComplete")
}
func (v *BPLMNsComplete) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APBPLMNsComplete(v, &s)
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
func (v *BPLMNsComplete) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *BPLMNsComplete) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
	if err := s13.BridgeMarshalAPERBPLMNsTo(v.Value, bb, fresh); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.perPadding)
}

// MarshalAPER encodes a complete value using one per-call change plan.
func (v *BearersSubjectToDLDiscardingListComplete) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "BearersSubjectToDLDiscardingListComplete")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *BearersSubjectToDLDiscardingListComplete) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "BearersSubjectToDLDiscardingListComplete")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APBearersSubjectToDLDiscardingListComplete(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "BearersSubjectToDLDiscardingListComplete")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "BearersSubjectToDLDiscardingListComplete")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *BearersSubjectToDLDiscardingListComplete) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "BearersSubjectToDLDiscardingListComplete")
}
func (v *BearersSubjectToDLDiscardingListComplete) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "BearersSubjectToDLDiscardingListComplete")
}
func (v *BearersSubjectToDLDiscardingListComplete) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APBearersSubjectToDLDiscardingListComplete(v, &s)
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
func (v *BearersSubjectToDLDiscardingListComplete) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *BearersSubjectToDLDiscardingListComplete) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
	if err := s25.BridgeMarshalAPERBearersSubjectToDLDiscardingListTo(v.Value, bb, fresh); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.perPadding)
}

// MarshalAPER encodes a complete value using one per-call change plan.
func (v *ENBEarlyStatusTransferTransparentContainer) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "ENBEarlyStatusTransferTransparentContainer")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *ENBEarlyStatusTransferTransparentContainer) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "ENBEarlyStatusTransferTransparentContainer")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APENBEarlyStatusTransferTransparentContainer(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "ENBEarlyStatusTransferTransparentContainer")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "ENBEarlyStatusTransferTransparentContainer")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *ENBEarlyStatusTransferTransparentContainer) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "ENBEarlyStatusTransferTransparentContainer")
}
func (v *ENBEarlyStatusTransferTransparentContainer) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "ENBEarlyStatusTransferTransparentContainer")
}
func (v *ENBEarlyStatusTransferTransparentContainer) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APENBEarlyStatusTransferTransparentContainer(v, &s)
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
func (v *ENBEarlyStatusTransferTransparentContainer) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *ENBEarlyStatusTransferTransparentContainer) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
func (v *UES1APIDPair) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "UES1APIDPair")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *UES1APIDPair) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "UES1APIDPair")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APUES1APIDPair(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "UES1APIDPair")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "UES1APIDPair")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *UES1APIDPair) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "UES1APIDPair")
}
func (v *UES1APIDPair) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "UES1APIDPair")
}
func (v *UES1APIDPair) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APUES1APIDPair(v, &s)
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
func (v *UES1APIDPair) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *UES1APIDPair) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
func (v *UES1APIDs) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "UES1APIDs")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *UES1APIDs) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "UES1APIDs")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APUES1APIDs(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "UES1APIDs")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "UES1APIDs")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *UES1APIDs) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "UES1APIDs")
}
func (v *UES1APIDs) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "UES1APIDs")
}
func (v *UES1APIDs) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APUES1APIDs(v, &s)
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
func (v *UES1APIDs) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *UES1APIDs) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
func (v *UESecurityCapabilities) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "UESecurityCapabilities")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *UESecurityCapabilities) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "UESecurityCapabilities")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APUESecurityCapabilities(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "UESecurityCapabilities")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "UESecurityCapabilities")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *UESecurityCapabilities) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "UESecurityCapabilities")
}
func (v *UESecurityCapabilities) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "UESecurityCapabilities")
}
func (v *UESecurityCapabilities) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APUESecurityCapabilities(v, &s)
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
func (v *UESecurityCapabilities) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *UESecurityCapabilities) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
func (v *UESidelinkAggregateMaximumBitrate) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "UESidelinkAggregateMaximumBitrate")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *UESidelinkAggregateMaximumBitrate) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "UESidelinkAggregateMaximumBitrate")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APUESidelinkAggregateMaximumBitrate(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "UESidelinkAggregateMaximumBitrate")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "UESidelinkAggregateMaximumBitrate")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *UESidelinkAggregateMaximumBitrate) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "UESidelinkAggregateMaximumBitrate")
}
func (v *UESidelinkAggregateMaximumBitrate) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "UESidelinkAggregateMaximumBitrate")
}
func (v *UESidelinkAggregateMaximumBitrate) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APUESidelinkAggregateMaximumBitrate(v, &s)
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
func (v *UESidelinkAggregateMaximumBitrate) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *UESidelinkAggregateMaximumBitrate) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
func (v *ULCPSecurityInformation) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "ULCPSecurityInformation")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *ULCPSecurityInformation) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "ULCPSecurityInformation")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APULCPSecurityInformation(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "ULCPSecurityInformation")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "ULCPSecurityInformation")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *ULCPSecurityInformation) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "ULCPSecurityInformation")
}
func (v *ULCPSecurityInformation) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "ULCPSecurityInformation")
}
func (v *ULCPSecurityInformation) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APULCPSecurityInformation(v, &s)
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
func (v *ULCPSecurityInformation) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *ULCPSecurityInformation) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
func (v *BPLMNsComplete) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "BPLMNsComplete")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded BPLMNsComplete
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APBPLMNsComplete(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = BPLMNsComplete{}
		return report, aper.OperationError(err, "BPLMNsComplete")
	}
	*v = decoded
	return report, aper.OperationError(nil, "BPLMNsComplete")
}

// UnmarshalAPER decodes one complete value and returns its report.
func (v *BearersSubjectToDLDiscardingListComplete) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "BearersSubjectToDLDiscardingListComplete")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded BearersSubjectToDLDiscardingListComplete
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APBearersSubjectToDLDiscardingListComplete(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = BearersSubjectToDLDiscardingListComplete{}
		return report, aper.OperationError(err, "BearersSubjectToDLDiscardingListComplete")
	}
	*v = decoded
	return report, aper.OperationError(nil, "BearersSubjectToDLDiscardingListComplete")
}

// UnmarshalAPER decodes one complete value and returns its report.
func (v *ENBEarlyStatusTransferTransparentContainer) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "ENBEarlyStatusTransferTransparentContainer")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded ENBEarlyStatusTransferTransparentContainer
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APENBEarlyStatusTransferTransparentContainer(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = ENBEarlyStatusTransferTransparentContainer{}
		return report, aper.OperationError(err, "ENBEarlyStatusTransferTransparentContainer")
	}
	*v = decoded
	return report, aper.OperationError(nil, "ENBEarlyStatusTransferTransparentContainer")
}

// UnmarshalAPER decodes one complete value and returns its report.
func (v *UES1APIDPair) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "UES1APIDPair")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded UES1APIDPair
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APUES1APIDPair(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = UES1APIDPair{}
		return report, aper.OperationError(err, "UES1APIDPair")
	}
	*v = decoded
	return report, aper.OperationError(nil, "UES1APIDPair")
}

// UnmarshalAPER decodes one complete value and returns its report.
func (v *UES1APIDs) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "UES1APIDs")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded UES1APIDs
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APUES1APIDs(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = UES1APIDs{}
		return report, aper.OperationError(err, "UES1APIDs")
	}
	*v = decoded
	return report, aper.OperationError(nil, "UES1APIDs")
}

// UnmarshalAPER decodes one complete value and returns its report.
func (v *UESecurityCapabilities) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "UESecurityCapabilities")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded UESecurityCapabilities
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APUESecurityCapabilities(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = UESecurityCapabilities{}
		return report, aper.OperationError(err, "UESecurityCapabilities")
	}
	*v = decoded
	return report, aper.OperationError(nil, "UESecurityCapabilities")
}

// UnmarshalAPER decodes one complete value and returns its report.
func (v *UESidelinkAggregateMaximumBitrate) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "UESidelinkAggregateMaximumBitrate")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded UESidelinkAggregateMaximumBitrate
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APUESidelinkAggregateMaximumBitrate(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = UESidelinkAggregateMaximumBitrate{}
		return report, aper.OperationError(err, "UESidelinkAggregateMaximumBitrate")
	}
	*v = decoded
	return report, aper.OperationError(nil, "UESidelinkAggregateMaximumBitrate")
}

// UnmarshalAPER decodes one complete value and returns its report.
func (v *ULCPSecurityInformation) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "ULCPSecurityInformation")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded ULCPSecurityInformation
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APULCPSecurityInformation(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = ULCPSecurityInformation{}
		return report, aper.OperationError(err, "ULCPSecurityInformation")
	}
	*v = decoded
	return report, aper.OperationError(nil, "ULCPSecurityInformation")
}

// NewUES1APIDsUES1APIDPair constructs a checked complete value.
func NewUES1APIDsUES1APIDPair(v UES1APIDPair, options ...aper.BuildOption) (UES1APIDs, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return UES1APIDs{}, aper.OperationError(err, "UES1APIDsUES1APIDPair")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), v); err != nil {
		return UES1APIDs{}, aper.OperationError(err, "UES1APIDsUES1APIDPair")
	}
	value := BridgeNewUES1APIDsUES1APIDPairLegacy(v)
	if _, err := (&value).marshalAPERBudget(budget, false); err != nil {
		return UES1APIDs{}, aper.OperationError(err, "UES1APIDsUES1APIDPair")
	}
	return value, aper.OperationError(nil, "UES1APIDsUES1APIDPair")
}

// NewUES1APIDsMMEUES1APID constructs a checked complete value.
func NewUES1APIDsMMEUES1APID(v s00.MMEUES1APID, options ...aper.BuildOption) (UES1APIDs, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return UES1APIDs{}, aper.OperationError(err, "UES1APIDsMMEUES1APID")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), v); err != nil {
		return UES1APIDs{}, aper.OperationError(err, "UES1APIDsMMEUES1APID")
	}
	value := BridgeNewUES1APIDsMMEUES1APIDLegacy(v)
	if _, err := (&value).marshalAPERBudget(budget, false); err != nil {
		return UES1APIDs{}, aper.OperationError(err, "UES1APIDsMMEUES1APID")
	}
	return value, aper.OperationError(nil, "UES1APIDsMMEUES1APID")
}

// NewUES1APIDsUnknownExtension builds a checked, owned unknown CHOICE alternative.
func NewUES1APIDsUnknownExtension(index uint64, contents []byte, options ...aper.BuildOption) (UES1APIDs, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return UES1APIDs{}, aper.OperationError(err, "UES1APIDsUnknownExtension")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), aper.ChoiceExtension{}); err != nil {
		return UES1APIDs{}, aper.OperationError(err, "UES1APIDsUnknownExtension")
	}
	extension, err := aper.BuildChoiceExtension(index, contents, budget)
	if err != nil {
		return UES1APIDs{}, aper.OperationError(err, "UES1APIDsUnknownExtension")
	}
	value := UES1APIDs{UnknownExtension: &extension}
	if _, err := value.marshalAPERBudget(budget, false); err != nil {
		return UES1APIDs{}, aper.OperationError(err, "UES1APIDsUnknownExtension")
	}
	return value, aper.OperationError(nil, "UES1APIDsUnknownExtension")
}

// MarshalAPERBearersSubjectToDLDiscardingList encodes a complete named list.
func MarshalAPERBearersSubjectToDLDiscardingList(v BearersSubjectToDLDiscardingListComplete, options ...aper.EncodeOption) ([]byte, error) {
	return v.MarshalAPER(options...)
}

// MarshalAPERBPLMNs encodes a complete named list.
func MarshalAPERBPLMNs(v BPLMNsComplete, options ...aper.EncodeOption) ([]byte, error) {
	return v.MarshalAPER(options...)
}

// UnmarshalAPERBearersSubjectToDLDiscardingList decodes a complete named list.
func UnmarshalAPERBearersSubjectToDLDiscardingList(data []byte, options ...aper.DecodeOption) (BearersSubjectToDLDiscardingListComplete, aper.DecodeReport, error) {
	var v BearersSubjectToDLDiscardingListComplete
	report, err := v.UnmarshalAPER(data, options...)
	return v, report, err
}

// UnmarshalAPERBPLMNs decodes a complete named list.
func UnmarshalAPERBPLMNs(data []byte, options ...aper.DecodeOption) (BPLMNsComplete, aper.DecodeReport, error) {
	var v BPLMNsComplete
	report, err := v.UnmarshalAPER(data, options...)
	return v, report, err
}

// UEContextReleaseCommand represents the ASN.1 type UEContextReleaseCommand (SEQUENCE).
type UEContextReleaseCommand struct {
	replay           aper.Snapshot
	stream           aper.WireSpan
	received         bool
	withoutReplay    bool
	receivedAbsolute bool
	receivedBytes    aper.WireSpan
	receivedLocation aper.Location
	ProtocolIEs      UEContextReleaseCommandIEContainer `asn1:"tag:0,context,implicit"`
	protocolIEsIndef bool                               `asn1:"-" json:"-"`
	extCount         int64                              `asn1:"-" json:"-"`
	extPresent       []bool                             `asn1:"-" json:"-"`
	extData          [][]byte                           `asn1:"-" json:"-"`
	perPadding       aper.FinalPadding                  `asn1:"-" json:"-"`
	perExtPadding    []aper.CompletePadding             `asn1:"-" json:"-"`
	extOrigin        []aper.OpaqueOrigin
	extWire          []aper.WireSpan
}

// UERadioCapabilityMatchResponse represents the ASN.1 type UERadioCapabilityMatchResponse (SEQUENCE).
type UERadioCapabilityMatchResponse struct {
	replay           aper.Snapshot
	stream           aper.WireSpan
	received         bool
	withoutReplay    bool
	receivedAbsolute bool
	receivedBytes    aper.WireSpan
	receivedLocation aper.Location
	ProtocolIEs      s24.UERadioCapabilityMatchResponseIEContainer `asn1:"tag:0,context,implicit"`
	protocolIEsIndef bool                                          `asn1:"-" json:"-"`
	extCount         int64                                         `asn1:"-" json:"-"`
	extPresent       []bool                                        `asn1:"-" json:"-"`
	extData          [][]byte                                      `asn1:"-" json:"-"`
	perPadding       aper.FinalPadding                             `asn1:"-" json:"-"`
	perExtPadding    []aper.CompletePadding                        `asn1:"-" json:"-"`
	extOrigin        []aper.OpaqueOrigin
	extWire          []aper.WireSpan
}

// ENBCPRelocationIndication represents the ASN.1 type ENBCPRelocationIndication (SEQUENCE).
type ENBCPRelocationIndication struct {
	replay           aper.Snapshot
	stream           aper.WireSpan
	received         bool
	withoutReplay    bool
	receivedAbsolute bool
	receivedBytes    aper.WireSpan
	receivedLocation aper.Location
	ProtocolIEs      ENBCPRelocationIndicationIEContainer `asn1:"tag:0,context,implicit"`
	protocolIEsIndef bool                                 `asn1:"-" json:"-"`
	extCount         int64                                `asn1:"-" json:"-"`
	extPresent       []bool                               `asn1:"-" json:"-"`
	extData          [][]byte                             `asn1:"-" json:"-"`
	perPadding       aper.FinalPadding                    `asn1:"-" json:"-"`
	perExtPadding    []aper.CompletePadding               `asn1:"-" json:"-"`
	extOrigin        []aper.OpaqueOrigin
	extWire          []aper.WireSpan
}

// MarshalAPER encodes UEContextReleaseCommand to APER format.
func (v *UEContextReleaseCommand) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *UEContextReleaseCommand) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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

// UnmarshalAPER decodes UEContextReleaseCommand from APER format.
func (v *UEContextReleaseCommand) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes UEContextReleaseCommand with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *UEContextReleaseCommand) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "UEContextReleaseCommand")
	}
	bb.EnterComponent("UEContextReleaseCommand")
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "UEContextReleaseCommand")
	}
	padding, err := aper.CaptureFinalBits(bb, "UEContextReleaseCommand")
	if err != nil {
		return runtime.WrapDecodePath(err, "UEContextReleaseCommand")
	}
	v.perPadding = padding.WithRecords(v.perPadding)
	return nil
}
func (v *UEContextReleaseCommand) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = UEContextReleaseCommand{}
	extAdditions := aper.BeginExtensionAdditions(bb)
	hasExtensions, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	toleranceMark_protocolies := bb.EnterComponent("ProtocolIEs")
	v.ProtocolIEs = make(UEContextReleaseCommandIEContainer, 0)
	_, errCollection_protocolies := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1128
		if fragmentOffset_protocolies < 0 || fragmentLength_protocolies < 0 || fragmentLength_protocolies > int64(^uint(0)>>1) || fragmentOffset_protocolies > int64(^uint(0)>>1)-fragmentLength_protocolies {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_protocolies; i++ {
			var elem UEContextReleaseCommandIEField
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

// MarshalAPER encodes UERadioCapabilityMatchResponse to APER format.
func (v *UERadioCapabilityMatchResponse) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *UERadioCapabilityMatchResponse) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
			if err := s24.BridgeUERadioCapabilityMatchResponseIEFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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

// UnmarshalAPER decodes UERadioCapabilityMatchResponse from APER format.
func (v *UERadioCapabilityMatchResponse) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes UERadioCapabilityMatchResponse with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *UERadioCapabilityMatchResponse) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "UERadioCapabilityMatchResponse")
	}
	bb.EnterComponent("UERadioCapabilityMatchResponse")
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "UERadioCapabilityMatchResponse")
	}
	padding, err := aper.CaptureFinalBits(bb, "UERadioCapabilityMatchResponse")
	if err != nil {
		return runtime.WrapDecodePath(err, "UERadioCapabilityMatchResponse")
	}
	v.perPadding = padding.WithRecords(v.perPadding)
	return nil
}
func (v *UERadioCapabilityMatchResponse) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = UERadioCapabilityMatchResponse{}
	extAdditions := aper.BeginExtensionAdditions(bb)
	hasExtensions, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	toleranceMark_protocolies := bb.EnterComponent("ProtocolIEs")
	v.ProtocolIEs = make(s24.UERadioCapabilityMatchResponseIEContainer, 0)
	_, errCollection_protocolies := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1128
		if fragmentOffset_protocolies < 0 || fragmentLength_protocolies < 0 || fragmentLength_protocolies > int64(^uint(0)>>1) || fragmentOffset_protocolies > int64(^uint(0)>>1)-fragmentLength_protocolies {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_protocolies; i++ {
			var elem s24.UERadioCapabilityMatchResponseIEField
			elementMark := bb.EnterIndex(fragmentOffset_protocolies + i)
			if err := s24.BridgeUERadioCapabilityMatchResponseIEFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
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

// MarshalAPER encodes ENBCPRelocationIndication to APER format.
func (v *ENBCPRelocationIndication) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *ENBCPRelocationIndication) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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

// UnmarshalAPER decodes ENBCPRelocationIndication from APER format.
func (v *ENBCPRelocationIndication) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes ENBCPRelocationIndication with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *ENBCPRelocationIndication) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "ENBCPRelocationIndication")
	}
	bb.EnterComponent("ENBCPRelocationIndication")
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "ENBCPRelocationIndication")
	}
	padding, err := aper.CaptureFinalBits(bb, "ENBCPRelocationIndication")
	if err != nil {
		return runtime.WrapDecodePath(err, "ENBCPRelocationIndication")
	}
	v.perPadding = padding.WithRecords(v.perPadding)
	return nil
}
func (v *ENBCPRelocationIndication) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = ENBCPRelocationIndication{}
	extAdditions := aper.BeginExtensionAdditions(bb)
	hasExtensions, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	toleranceMark_protocolies := bb.EnterComponent("ProtocolIEs")
	v.ProtocolIEs = make(ENBCPRelocationIndicationIEContainer, 0)
	_, errCollection_protocolies := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1128
		if fragmentOffset_protocolies < 0 || fragmentLength_protocolies < 0 || fragmentLength_protocolies > int64(^uint(0)>>1) || fragmentOffset_protocolies > int64(^uint(0)>>1)-fragmentLength_protocolies {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_protocolies; i++ {
			var elem ENBCPRelocationIndicationIEField
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
func (v *ENBCPRelocationIndication) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s14.BridgeReceivedFormAt(v.received, v.receivedBytes, "ENBCPRelocationIndication", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "ENBCPRelocationIndication", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v ENBCPRelocationIndication) WithoutReplay() ENBCPRelocationIndication {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero ENBCPRelocationIndication
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *UEContextReleaseCommand) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s14.BridgeReceivedFormAt(v.received, v.receivedBytes, "UEContextReleaseCommand", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "UEContextReleaseCommand", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v UEContextReleaseCommand) WithoutReplay() UEContextReleaseCommand {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero UEContextReleaseCommand
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *UERadioCapabilityMatchResponse) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s14.BridgeReceivedFormAt(v.received, v.receivedBytes, "UERadioCapabilityMatchResponse", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "UERadioCapabilityMatchResponse", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v UERadioCapabilityMatchResponse) WithoutReplay() UERadioCapabilityMatchResponse {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero UERadioCapabilityMatchResponse
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// Extensions returns owned unknown sequence additions.
func (v *ENBCPRelocationIndication) Extensions() []aper.SequenceExtension {
	if v == nil {
		return nil
	}
	views := aper.SequenceExtensionViews(v.extPresent, aper.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *ENBCPRelocationIndication) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("ENBCPRelocationIndication.Extensions[%d]", index))
	}
	if err := aper.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("ENBCPRelocationIndication.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *ENBCPRelocationIndication) RemoveExtension(index uint64) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("ENBCPRelocationIndication.Extensions[%d]", index))
	}
	if err := aper.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("ENBCPRelocationIndication.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// Extensions returns owned unknown sequence additions.
func (v *UEContextReleaseCommand) Extensions() []aper.SequenceExtension {
	if v == nil {
		return nil
	}
	views := aper.SequenceExtensionViews(v.extPresent, aper.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *UEContextReleaseCommand) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("UEContextReleaseCommand.Extensions[%d]", index))
	}
	if err := aper.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("UEContextReleaseCommand.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *UEContextReleaseCommand) RemoveExtension(index uint64) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("UEContextReleaseCommand.Extensions[%d]", index))
	}
	if err := aper.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("UEContextReleaseCommand.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// Extensions returns owned unknown sequence additions.
func (v *UERadioCapabilityMatchResponse) Extensions() []aper.SequenceExtension {
	if v == nil {
		return nil
	}
	views := aper.SequenceExtensionViews(v.extPresent, aper.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *UERadioCapabilityMatchResponse) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("UERadioCapabilityMatchResponse.Extensions[%d]", index))
	}
	if err := aper.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("UERadioCapabilityMatchResponse.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *UERadioCapabilityMatchResponse) RemoveExtension(index uint64) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("UERadioCapabilityMatchResponse.Extensions[%d]", index))
	}
	if err := aper.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("UERadioCapabilityMatchResponse.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// MarshalAPER encodes a complete value using one per-call change plan.
func (v *ENBCPRelocationIndication) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "ENBCPRelocationIndication")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *ENBCPRelocationIndication) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "ENBCPRelocationIndication")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APENBCPRelocationIndication(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "ENBCPRelocationIndication")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "ENBCPRelocationIndication")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *ENBCPRelocationIndication) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "ENBCPRelocationIndication")
}
func (v *ENBCPRelocationIndication) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "ENBCPRelocationIndication")
}
func (v *ENBCPRelocationIndication) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APENBCPRelocationIndication(v, &s)
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
func (v *ENBCPRelocationIndication) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *ENBCPRelocationIndication) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
func (v *UEContextReleaseCommand) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "UEContextReleaseCommand")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *UEContextReleaseCommand) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "UEContextReleaseCommand")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APUEContextReleaseCommand(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "UEContextReleaseCommand")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "UEContextReleaseCommand")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *UEContextReleaseCommand) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "UEContextReleaseCommand")
}
func (v *UEContextReleaseCommand) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "UEContextReleaseCommand")
}
func (v *UEContextReleaseCommand) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APUEContextReleaseCommand(v, &s)
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
func (v *UEContextReleaseCommand) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *UEContextReleaseCommand) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
func (v *UERadioCapabilityMatchResponse) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "UERadioCapabilityMatchResponse")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *UERadioCapabilityMatchResponse) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "UERadioCapabilityMatchResponse")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APUERadioCapabilityMatchResponse(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "UERadioCapabilityMatchResponse")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "UERadioCapabilityMatchResponse")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *UERadioCapabilityMatchResponse) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "UERadioCapabilityMatchResponse")
}
func (v *UERadioCapabilityMatchResponse) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "UERadioCapabilityMatchResponse")
}
func (v *UERadioCapabilityMatchResponse) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APUERadioCapabilityMatchResponse(v, &s)
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
func (v *UERadioCapabilityMatchResponse) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *UERadioCapabilityMatchResponse) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
func (v *ENBCPRelocationIndication) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "ENBCPRelocationIndication")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded ENBCPRelocationIndication
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APENBCPRelocationIndication(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = ENBCPRelocationIndication{}
		return report, aper.OperationError(err, "ENBCPRelocationIndication")
	}
	*v = decoded
	return report, aper.OperationError(nil, "ENBCPRelocationIndication")
}

// UnmarshalAPER decodes one complete value and returns its report.
func (v *UEContextReleaseCommand) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "UEContextReleaseCommand")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded UEContextReleaseCommand
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APUEContextReleaseCommand(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = UEContextReleaseCommand{}
		return report, aper.OperationError(err, "UEContextReleaseCommand")
	}
	*v = decoded
	return report, aper.OperationError(nil, "UEContextReleaseCommand")
}

// UnmarshalAPER decodes one complete value and returns its report.
func (v *UERadioCapabilityMatchResponse) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "UERadioCapabilityMatchResponse")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded UERadioCapabilityMatchResponse
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APUERadioCapabilityMatchResponse(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = UERadioCapabilityMatchResponse{}
		return report, aper.OperationError(err, "UERadioCapabilityMatchResponse")
	}
	*v = decoded
	return report, aper.OperationError(nil, "UERadioCapabilityMatchResponse")
}

// ActivatedCellsListComplete carries a complete ActivatedCellsList encoding, including observed terminal bits.
// ITU-T X.691 (02/2021) 11.1.3.1 and 11.1.4 require new encodings to pad with zero bits.
type ActivatedCellsListComplete struct {
	replay           aper.Snapshot
	stream           aper.WireSpan
	received         bool
	withoutReplay    bool
	receivedAbsolute bool
	receivedBytes    aper.WireSpan
	receivedLocation aper.Location
	Value            s14.ActivatedCellsList
	perPadding       aper.CompletePadding `json:"-"`
}

func (v *ActivatedCellsListComplete) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := s25.BridgeMarshalAPERActivatedCellsListTo(v.Value, bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.perPadding)
}

// UnmarshalAPER decodes ActivatedCellsList from APER format.
func (v *ActivatedCellsListComplete) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes ActivatedCellsList with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *ActivatedCellsListComplete) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "ActivatedCellsList")
	}
	bb.EnterComponent("ActivatedCellsList")
	value, err := BridgeUnmarshalAPERActivatedCellsListFrom(bb)
	if err != nil {
		return runtime.WrapDecodePath(err, "ActivatedCellsList")
	}
	padding, err := aper.CaptureFinalBits(bb, "ActivatedCellsList")
	if err != nil {
		return runtime.WrapDecodePath(err, "ActivatedCellsList")
	}
	v.Value, v.perPadding = value, padding.Padding()
	return nil
}

// MarshalAPERActivatedCellsList encodes a ActivatedCellsList list to APER.
func BridgeMarshalAPERActivatedCellsList(list ActivatedCellsListComplete) ([]byte, error) {
	return list.marshalAPERLegacy()
}

// UnmarshalAPERActivatedCellsList decodes a ActivatedCellsList list from APER.
func BridgeUnmarshalAPERActivatedCellsList(data []byte) (ActivatedCellsListComplete, error) {
	var value ActivatedCellsListComplete
	if err := value.unmarshalAPERLegacy(data); err != nil {
		return value, err
	}
	return value, nil
}

// UnmarshalAPERActivatedCellsListFrom decodes a ActivatedCellsList list from bb.
func BridgeUnmarshalAPERActivatedCellsListFrom(bb *aper.BitBuffer) (s14.ActivatedCellsList, error) {
	if err := bb.EnterDecodeValue(); err != nil {
		return nil, err
	}
	defer bb.LeaveDecodeValue()
	var v s21.BridgeAsn1cAPERActivatedCellsListListValue
	if err := BridgeUnmarshalAPERActivatedCellsListInto(&v, bb); err != nil {
		return nil, err
	}
	return v.Value, nil
}
func BridgeUnmarshalAPERActivatedCellsListInto(v *s21.BridgeAsn1cAPERActivatedCellsListListValue, bb *aper.BitBuffer) error {
	toleranceMark_value := bb.EnterComponent("Value")
	v.Value = make(s14.ActivatedCellsList, 0)
	_, errCollection_value := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 0, HasLower: true, Upper: 256, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1128
		if fragmentOffset_value < 0 || fragmentLength_value < 0 || fragmentLength_value > int64(^uint(0)>>1) || fragmentOffset_value > int64(^uint(0)>>1)-fragmentLength_value {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_value; i++ {
			var elem s14.ActivatedCellsListItem
			elementMark := bb.EnterIndex(fragmentOffset_value + i)
			if err := s14.BridgeActivatedCellsListItemMethodUnmarshalAPERFrom(&elem, bb); err != nil {
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
func (v *ActivatedCellsListComplete) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s14.BridgeReceivedFormAt(v.received, v.receivedBytes, "ActivatedCellsListComplete", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "ActivatedCellsListComplete", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v ActivatedCellsListComplete) WithoutReplay() ActivatedCellsListComplete {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero ActivatedCellsListComplete
	v.perPadding = zero.perPadding
	return v
}

// MarshalAPER encodes a complete value using one per-call change plan.
func (v *ActivatedCellsListComplete) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "ActivatedCellsListComplete")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *ActivatedCellsListComplete) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "ActivatedCellsListComplete")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APActivatedCellsListComplete(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "ActivatedCellsListComplete")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "ActivatedCellsListComplete")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *ActivatedCellsListComplete) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "ActivatedCellsListComplete")
}
func (v *ActivatedCellsListComplete) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "ActivatedCellsListComplete")
}
func (v *ActivatedCellsListComplete) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APActivatedCellsListComplete(v, &s)
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
func (v *ActivatedCellsListComplete) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *ActivatedCellsListComplete) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
	if err := s25.BridgeMarshalAPERActivatedCellsListTo(v.Value, bb, fresh); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.perPadding)
}

// UnmarshalAPER decodes one complete value and returns its report.
func (v *ActivatedCellsListComplete) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "ActivatedCellsListComplete")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded ActivatedCellsListComplete
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APActivatedCellsListComplete(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = ActivatedCellsListComplete{}
		return report, aper.OperationError(err, "ActivatedCellsListComplete")
	}
	*v = decoded
	return report, aper.OperationError(nil, "ActivatedCellsListComplete")
}

// MarshalAPERActivatedCellsList encodes a complete named list.
func MarshalAPERActivatedCellsList(v ActivatedCellsListComplete, options ...aper.EncodeOption) ([]byte, error) {
	return v.MarshalAPER(options...)
}

// UnmarshalAPERActivatedCellsList decodes a complete named list.
func UnmarshalAPERActivatedCellsList(data []byte, options ...aper.DecodeOption) (ActivatedCellsListComplete, aper.DecodeReport, error) {
	var v ActivatedCellsListComplete
	report, err := v.UnmarshalAPER(data, options...)
	return v, report, err
}

type ENBEarlyStatusTransferTransparentContainerExtIEsValue struct {
	id                                  s00.ProtocolIEID
	received                            aper.WireSpan
	replay                              aper.Snapshot
	opaque                              aper.OpaqueOpenType
	isOpaque                            bool
	rowBearersSubjectToDLDiscardingList *s15.BearersSubjectToDLDiscardingList
}

func (v ENBEarlyStatusTransferTransparentContainerExtIEsValue) matchesID(id s00.ProtocolIEID, _ ...*aper.DecodeBudget) bool {
	if v.id != id {
		return false
	}
	if v.isOpaque {
		return true
	}
	switch id {
	case s00.ProtocolIEID(352):
		return v.rowBearersSubjectToDLDiscardingList != nil
	}
	return false
}

// Opaque returns the retained opaque open value of ENBEarlyStatusTransferTransparentContainerExtIEsValue and reports whether the opaque alternative is selected.
func (v *ENBEarlyStatusTransferTransparentContainerExtIEsValue) Opaque() (aper.OpaqueOpenType, bool) {
	if v == nil || !v.isOpaque {
		return aper.OpaqueOpenType{}, false
	}
	return v.opaque, true
}
func (ENBEarlyStatusTransferTransparentContainerExtIEsValue) rule() aper.SourceRule {
	return aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.4", Assignment: aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "ENB-EarlyStatusTransfer-TransparentContainer-ExtIEs"}}
}
func (ENBEarlyStatusTransferTransparentContainerExtIEsValue) reason(id s00.ProtocolIEID) aper.OpaqueReason {
	switch id {
	case s00.ProtocolIEID(352):
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

// AsBearersSubjectToDLDiscardingList returns the selected BearersSubjectToDLDiscardingList value of ENBEarlyStatusTransferTransparentContainerExtIEsValue and reports whether that alternative is active.
func (v *ENBEarlyStatusTransferTransparentContainerExtIEsValue) AsBearersSubjectToDLDiscardingList() (*s15.BearersSubjectToDLDiscardingList, bool) {
	if v == nil || v.id != s00.ProtocolIEID(352) || v.rowBearersSubjectToDLDiscardingList == nil {
		return nil, false
	}
	return v.rowBearersSubjectToDLDiscardingList, true
}
func (v ENBEarlyStatusTransferTransparentContainerExtIEsValue) decode(id s00.ProtocolIEID, raw aper.OpaqueOpenType) (ENBEarlyStatusTransferTransparentContainerExtIEsValue, error) {
	out := ENBEarlyStatusTransferTransparentContainerExtIEsValue{id: id}
	switch id {
	case s00.ProtocolIEID(352):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		child := scope
		list, err := BridgeUnmarshalAPERBearersSubjectToDLDiscardingListFrom(child)
		if err != nil {
			return out, fmt.Errorf("%s %w", "BearersSubjectToDLDiscardingList:", err)
		}
		padding, err := aper.CaptureOpenTypePadding(child)
		if err != nil {
			return out, err
		}
		_ = padding
		value := list
		out.rowBearersSubjectToDLDiscardingList = &value
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
func (v ENBEarlyStatusTransferTransparentContainerExtIEsValue) encode() ([]byte, error) {
	return v.encodeFresh(false, nil)
}
func (v ENBEarlyStatusTransferTransparentContainerExtIEsValue) encodeFresh(fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
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
	case s00.ProtocolIEID(352):
		if v.rowBearersSubjectToDLDiscardingList == nil {
			return nil, fmt.Errorf("%s missing value", "ENB-EarlyStatusTransfer-TransparentContainer-ExtIEs.id-Bearers-SubjectToDLDiscardingList:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		complete := BearersSubjectToDLDiscardingListComplete{Value: *v.rowBearersSubjectToDLDiscardingList}
		candidate, err := complete.marshalAPERBudget(budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	default:
		return nil, fmt.Errorf("%s id %d has no value", "ENBEarlyStatusTransferTransparentContainerExtIEsValue:", v.id)
	}
}

type ENBCPRelocationIndicationIEValue struct {
	id                         s00.ProtocolIEID
	received                   aper.WireSpan
	replay                     aper.Snapshot
	opaque                     aper.OpaqueOpenType
	isOpaque                   bool
	rowENBUES1APID             *s00.ENBUES1APID
	rowSTMSI                   *s28.STMSI
	rowEUTRANCGI               *s17.EUTRANCGI
	rowTAI                     *s31.TAI
	rowULCPSecurityInformation *ULCPSecurityInformation
	rowLTENTNTAIInformation    *s18.LTENTNTAIInformation
}

func (v ENBCPRelocationIndicationIEValue) matchesID(id s00.ProtocolIEID, _ ...*aper.DecodeBudget) bool {
	if v.id != id {
		return false
	}
	if v.isOpaque {
		return true
	}
	switch id {
	case s00.ProtocolIEID(8):
		return v.rowENBUES1APID != nil
	case s00.ProtocolIEID(96):
		return v.rowSTMSI != nil
	case s00.ProtocolIEID(100):
		return v.rowEUTRANCGI != nil
	case s00.ProtocolIEID(67):
		return v.rowTAI != nil
	case s00.ProtocolIEID(254):
		return v.rowULCPSecurityInformation != nil
	case s00.ProtocolIEID(339):
		return v.rowLTENTNTAIInformation != nil
	}
	return false
}

// Opaque returns the retained opaque open value of ENBCPRelocationIndicationIEValue and reports whether the opaque alternative is selected.
func (v *ENBCPRelocationIndicationIEValue) Opaque() (aper.OpaqueOpenType, bool) {
	if v == nil || !v.isOpaque {
		return aper.OpaqueOpenType{}, false
	}
	return v.opaque, true
}
func (ENBCPRelocationIndicationIEValue) rule() aper.SourceRule {
	return aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "ENBCPRelocationIndicationIEs"}}
}
func (ENBCPRelocationIndicationIEValue) reason(id s00.ProtocolIEID) aper.OpaqueReason {
	switch id {
	case s00.ProtocolIEID(8):
		return aper.UnknownSelector
	case s00.ProtocolIEID(96):
		return aper.UnknownSelector
	case s00.ProtocolIEID(100):
		return aper.UnknownSelector
	case s00.ProtocolIEID(67):
		return aper.UnknownSelector
	case s00.ProtocolIEID(254):
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

// AsENBUES1APID returns the selected ENBUES1APID value of ENBCPRelocationIndicationIEValue and reports whether that alternative is active.
func (v *ENBCPRelocationIndicationIEValue) AsENBUES1APID() (*s00.ENBUES1APID, bool) {
	if v == nil || v.id != s00.ProtocolIEID(8) || v.rowENBUES1APID == nil {
		return nil, false
	}
	return v.rowENBUES1APID, true
}

// AsSTMSI returns the selected STMSI value of ENBCPRelocationIndicationIEValue and reports whether that alternative is active.
func (v *ENBCPRelocationIndicationIEValue) AsSTMSI() (*s28.STMSI, bool) {
	if v == nil || v.id != s00.ProtocolIEID(96) || v.rowSTMSI == nil {
		return nil, false
	}
	return v.rowSTMSI, true
}

// AsEUTRANCGI returns the selected EUTRANCGI value of ENBCPRelocationIndicationIEValue and reports whether that alternative is active.
func (v *ENBCPRelocationIndicationIEValue) AsEUTRANCGI() (*s17.EUTRANCGI, bool) {
	if v == nil || v.id != s00.ProtocolIEID(100) || v.rowEUTRANCGI == nil {
		return nil, false
	}
	return v.rowEUTRANCGI, true
}

// AsTAI returns the selected TAI value of ENBCPRelocationIndicationIEValue and reports whether that alternative is active.
func (v *ENBCPRelocationIndicationIEValue) AsTAI() (*s31.TAI, bool) {
	if v == nil || v.id != s00.ProtocolIEID(67) || v.rowTAI == nil {
		return nil, false
	}
	return v.rowTAI, true
}

// AsULCPSecurityInformation returns the selected ULCPSecurityInformation value of ENBCPRelocationIndicationIEValue and reports whether that alternative is active.
func (v *ENBCPRelocationIndicationIEValue) AsULCPSecurityInformation() (*ULCPSecurityInformation, bool) {
	if v == nil || v.id != s00.ProtocolIEID(254) || v.rowULCPSecurityInformation == nil {
		return nil, false
	}
	return v.rowULCPSecurityInformation, true
}

// AsLTENTNTAIInformation returns the selected LTENTNTAIInformation value of ENBCPRelocationIndicationIEValue and reports whether that alternative is active.
func (v *ENBCPRelocationIndicationIEValue) AsLTENTNTAIInformation() (*s18.LTENTNTAIInformation, bool) {
	if v == nil || v.id != s00.ProtocolIEID(339) || v.rowLTENTNTAIInformation == nil {
		return nil, false
	}
	return v.rowLTENTNTAIInformation, true
}
func (v ENBCPRelocationIndicationIEValue) decode(id s00.ProtocolIEID, raw aper.OpaqueOpenType) (ENBCPRelocationIndicationIEValue, error) {
	out := ENBCPRelocationIndicationIEValue{id: id}
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
	case s00.ProtocolIEID(254):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		var value ULCPSecurityInformation
		child := scope
		if err := value.unmarshalAPERFrom(child); err != nil {
			return out, fmt.Errorf("%s %w", "ULCPSecurityInformation:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "ULCPSecurityInformation")
		if err != nil {
			return out, err
		}
		value.perPadding = padding
		value.received = true
		raw.RetainContents(&value.receivedBytes)
		value.receivedLocation = raw.ContentLocation()
		out.rowULCPSecurityInformation = &value
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
func (v ENBCPRelocationIndicationIEValue) encode() ([]byte, error) { return v.encodeFresh(false, nil) }
func (v ENBCPRelocationIndicationIEValue) encodeFresh(fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
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
			return nil, fmt.Errorf("%s missing value", "ENBCPRelocationIndicationIEs.id-eNB-UE-S1AP-ID:")
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
	case s00.ProtocolIEID(96):
		if v.rowSTMSI == nil {
			return nil, fmt.Errorf("%s missing value", "ENBCPRelocationIndicationIEs.id-S-TMSI:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		candidate, err := s28.BridgeSTMSIMethodMarshalAPERBudget(v.rowSTMSI, budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	case s00.ProtocolIEID(100):
		if v.rowEUTRANCGI == nil {
			return nil, fmt.Errorf("%s missing value", "ENBCPRelocationIndicationIEs.id-EUTRAN-CGI:")
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
			return nil, fmt.Errorf("%s missing value", "ENBCPRelocationIndicationIEs.id-TAI:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		candidate, err := s31.BridgeTAIMethodMarshalAPERBudget(v.rowTAI, budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	case s00.ProtocolIEID(254):
		if v.rowULCPSecurityInformation == nil {
			return nil, fmt.Errorf("%s missing value", "ENBCPRelocationIndicationIEs.id-UL-CP-SecurityInformation:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		candidate, err := v.rowULCPSecurityInformation.marshalAPERBudget(budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	case s00.ProtocolIEID(339):
		if v.rowLTENTNTAIInformation == nil {
			return nil, fmt.Errorf("%s missing value", "ENBCPRelocationIndicationIEs.id-LTE-NTN-TAI-Information:")
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
		return nil, fmt.Errorf("%s id %d has no value", "ENBCPRelocationIndicationIEValue:", v.id)
	}
}

type ENBEarlyStatusTransferIEValue struct {
	id                                            s00.ProtocolIEID
	received                                      aper.WireSpan
	replay                                        aper.Snapshot
	opaque                                        aper.OpaqueOpenType
	isOpaque                                      bool
	rowMMEUES1APID                                *s00.MMEUES1APID
	rowENBUES1APID                                *s00.ENBUES1APID
	rowENBEarlyStatusTransferTransparentContainer *ENBEarlyStatusTransferTransparentContainer
}

func (v ENBEarlyStatusTransferIEValue) matchesID(id s00.ProtocolIEID, _ ...*aper.DecodeBudget) bool {
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
	case s00.ProtocolIEID(321):
		return v.rowENBEarlyStatusTransferTransparentContainer != nil
	}
	return false
}

// Opaque returns the retained opaque open value of ENBEarlyStatusTransferIEValue and reports whether the opaque alternative is selected.
func (v *ENBEarlyStatusTransferIEValue) Opaque() (aper.OpaqueOpenType, bool) {
	if v == nil || !v.isOpaque {
		return aper.OpaqueOpenType{}, false
	}
	return v.opaque, true
}
func (ENBEarlyStatusTransferIEValue) rule() aper.SourceRule {
	return aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "ENBEarlyStatusTransferIEs"}}
}
func (ENBEarlyStatusTransferIEValue) reason(id s00.ProtocolIEID) aper.OpaqueReason {
	switch id {
	case s00.ProtocolIEID(0):
		return aper.UnknownSelector
	case s00.ProtocolIEID(8):
		return aper.UnknownSelector
	case s00.ProtocolIEID(321):
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

// AsMMEUES1APID returns the selected MMEUES1APID value of ENBEarlyStatusTransferIEValue and reports whether that alternative is active.
func (v *ENBEarlyStatusTransferIEValue) AsMMEUES1APID() (*s00.MMEUES1APID, bool) {
	if v == nil || v.id != s00.ProtocolIEID(0) || v.rowMMEUES1APID == nil {
		return nil, false
	}
	return v.rowMMEUES1APID, true
}

// AsENBUES1APID returns the selected ENBUES1APID value of ENBEarlyStatusTransferIEValue and reports whether that alternative is active.
func (v *ENBEarlyStatusTransferIEValue) AsENBUES1APID() (*s00.ENBUES1APID, bool) {
	if v == nil || v.id != s00.ProtocolIEID(8) || v.rowENBUES1APID == nil {
		return nil, false
	}
	return v.rowENBUES1APID, true
}

// AsENBEarlyStatusTransferTransparentContainer returns the selected ENBEarlyStatusTransferTransparentContainer value of ENBEarlyStatusTransferIEValue and reports whether that alternative is active.
func (v *ENBEarlyStatusTransferIEValue) AsENBEarlyStatusTransferTransparentContainer() (*ENBEarlyStatusTransferTransparentContainer, bool) {
	if v == nil || v.id != s00.ProtocolIEID(321) || v.rowENBEarlyStatusTransferTransparentContainer == nil {
		return nil, false
	}
	return v.rowENBEarlyStatusTransferTransparentContainer, true
}
func (v ENBEarlyStatusTransferIEValue) decode(id s00.ProtocolIEID, raw aper.OpaqueOpenType) (ENBEarlyStatusTransferIEValue, error) {
	out := ENBEarlyStatusTransferIEValue{id: id}
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
	case s00.ProtocolIEID(321):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		var value ENBEarlyStatusTransferTransparentContainer
		child := scope
		if err := value.unmarshalAPERFrom(child); err != nil {
			return out, fmt.Errorf("%s %w", "ENBEarlyStatusTransferTransparentContainer:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "ENBEarlyStatusTransferTransparentContainer")
		if err != nil {
			return out, err
		}
		value.perPadding = padding
		value.received = true
		raw.RetainContents(&value.receivedBytes)
		value.receivedLocation = raw.ContentLocation()
		out.rowENBEarlyStatusTransferTransparentContainer = &value
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
func (v ENBEarlyStatusTransferIEValue) encode() ([]byte, error) { return v.encodeFresh(false, nil) }
func (v ENBEarlyStatusTransferIEValue) encodeFresh(fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
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
			return nil, fmt.Errorf("%s missing value", "ENBEarlyStatusTransferIEs.id-MME-UE-S1AP-ID:")
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
			return nil, fmt.Errorf("%s missing value", "ENBEarlyStatusTransferIEs.id-eNB-UE-S1AP-ID:")
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
	case s00.ProtocolIEID(321):
		if v.rowENBEarlyStatusTransferTransparentContainer == nil {
			return nil, fmt.Errorf("%s missing value", "ENBEarlyStatusTransferIEs.id-eNB-EarlyStatusTransfer-TransparentContainer:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		candidate, err := v.rowENBEarlyStatusTransferTransparentContainer.marshalAPERBudget(budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	default:
		return nil, fmt.Errorf("%s id %d has no value", "ENBEarlyStatusTransferIEValue:", v.id)
	}
}

type MMEEarlyStatusTransferIEValue struct {
	id                                            s00.ProtocolIEID
	received                                      aper.WireSpan
	replay                                        aper.Snapshot
	opaque                                        aper.OpaqueOpenType
	isOpaque                                      bool
	rowMMEUES1APID                                *s00.MMEUES1APID
	rowENBUES1APID                                *s00.ENBUES1APID
	rowENBEarlyStatusTransferTransparentContainer *ENBEarlyStatusTransferTransparentContainer
}

func (v MMEEarlyStatusTransferIEValue) matchesID(id s00.ProtocolIEID, _ ...*aper.DecodeBudget) bool {
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
	case s00.ProtocolIEID(321):
		return v.rowENBEarlyStatusTransferTransparentContainer != nil
	}
	return false
}

// Opaque returns the retained opaque open value of MMEEarlyStatusTransferIEValue and reports whether the opaque alternative is selected.
func (v *MMEEarlyStatusTransferIEValue) Opaque() (aper.OpaqueOpenType, bool) {
	if v == nil || !v.isOpaque {
		return aper.OpaqueOpenType{}, false
	}
	return v.opaque, true
}
func (MMEEarlyStatusTransferIEValue) rule() aper.SourceRule {
	return aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "MMEEarlyStatusTransferIEs"}}
}
func (MMEEarlyStatusTransferIEValue) reason(id s00.ProtocolIEID) aper.OpaqueReason {
	switch id {
	case s00.ProtocolIEID(0):
		return aper.UnknownSelector
	case s00.ProtocolIEID(8):
		return aper.UnknownSelector
	case s00.ProtocolIEID(321):
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

// AsMMEUES1APID returns the selected MMEUES1APID value of MMEEarlyStatusTransferIEValue and reports whether that alternative is active.
func (v *MMEEarlyStatusTransferIEValue) AsMMEUES1APID() (*s00.MMEUES1APID, bool) {
	if v == nil || v.id != s00.ProtocolIEID(0) || v.rowMMEUES1APID == nil {
		return nil, false
	}
	return v.rowMMEUES1APID, true
}

// AsENBUES1APID returns the selected ENBUES1APID value of MMEEarlyStatusTransferIEValue and reports whether that alternative is active.
func (v *MMEEarlyStatusTransferIEValue) AsENBUES1APID() (*s00.ENBUES1APID, bool) {
	if v == nil || v.id != s00.ProtocolIEID(8) || v.rowENBUES1APID == nil {
		return nil, false
	}
	return v.rowENBUES1APID, true
}

// AsENBEarlyStatusTransferTransparentContainer returns the selected ENBEarlyStatusTransferTransparentContainer value of MMEEarlyStatusTransferIEValue and reports whether that alternative is active.
func (v *MMEEarlyStatusTransferIEValue) AsENBEarlyStatusTransferTransparentContainer() (*ENBEarlyStatusTransferTransparentContainer, bool) {
	if v == nil || v.id != s00.ProtocolIEID(321) || v.rowENBEarlyStatusTransferTransparentContainer == nil {
		return nil, false
	}
	return v.rowENBEarlyStatusTransferTransparentContainer, true
}
func (v MMEEarlyStatusTransferIEValue) decode(id s00.ProtocolIEID, raw aper.OpaqueOpenType) (MMEEarlyStatusTransferIEValue, error) {
	out := MMEEarlyStatusTransferIEValue{id: id}
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
	case s00.ProtocolIEID(321):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		var value ENBEarlyStatusTransferTransparentContainer
		child := scope
		if err := value.unmarshalAPERFrom(child); err != nil {
			return out, fmt.Errorf("%s %w", "ENBEarlyStatusTransferTransparentContainer:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "ENBEarlyStatusTransferTransparentContainer")
		if err != nil {
			return out, err
		}
		value.perPadding = padding
		value.received = true
		raw.RetainContents(&value.receivedBytes)
		value.receivedLocation = raw.ContentLocation()
		out.rowENBEarlyStatusTransferTransparentContainer = &value
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
func (v MMEEarlyStatusTransferIEValue) encode() ([]byte, error) { return v.encodeFresh(false, nil) }
func (v MMEEarlyStatusTransferIEValue) encodeFresh(fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
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
			return nil, fmt.Errorf("%s missing value", "MMEEarlyStatusTransferIEs.id-MME-UE-S1AP-ID:")
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
			return nil, fmt.Errorf("%s missing value", "MMEEarlyStatusTransferIEs.id-eNB-UE-S1AP-ID:")
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
	case s00.ProtocolIEID(321):
		if v.rowENBEarlyStatusTransferTransparentContainer == nil {
			return nil, fmt.Errorf("%s missing value", "MMEEarlyStatusTransferIEs.id-eNB-EarlyStatusTransfer-TransparentContainer:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		candidate, err := v.rowENBEarlyStatusTransferTransparentContainer.marshalAPERBudget(budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	default:
		return nil, fmt.Errorf("%s id %d has no value", "MMEEarlyStatusTransferIEValue:", v.id)
	}
}

type UEContextReleaseCommandIEValue struct {
	id           s00.ProtocolIEID
	received     aper.WireSpan
	replay       aper.Snapshot
	opaque       aper.OpaqueOpenType
	isOpaque     bool
	rowUES1APIDs *UES1APIDs
	rowCause     *s14.Cause
}

func (v UEContextReleaseCommandIEValue) matchesID(id s00.ProtocolIEID, _ ...*aper.DecodeBudget) bool {
	if v.id != id {
		return false
	}
	if v.isOpaque {
		return true
	}
	switch id {
	case s00.ProtocolIEID(99):
		return v.rowUES1APIDs != nil
	case s00.ProtocolIEID(2):
		return v.rowCause != nil
	}
	return false
}

// Opaque returns the retained opaque open value of UEContextReleaseCommandIEValue and reports whether the opaque alternative is selected.
func (v *UEContextReleaseCommandIEValue) Opaque() (aper.OpaqueOpenType, bool) {
	if v == nil || !v.isOpaque {
		return aper.OpaqueOpenType{}, false
	}
	return v.opaque, true
}
func (UEContextReleaseCommandIEValue) rule() aper.SourceRule {
	return aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "UEContextReleaseCommand-IEs"}}
}
func (UEContextReleaseCommandIEValue) reason(id s00.ProtocolIEID) aper.OpaqueReason {
	switch id {
	case s00.ProtocolIEID(99):
		return aper.UnknownSelector
	case s00.ProtocolIEID(2):
		return aper.UnknownSelector
	case s00.ProtocolIEID(0):
		return aper.NotInTable
	case s00.ProtocolIEID(1):
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

// AsUES1APIDs returns the selected UES1APIDs value of UEContextReleaseCommandIEValue and reports whether that alternative is active.
func (v *UEContextReleaseCommandIEValue) AsUES1APIDs() (*UES1APIDs, bool) {
	if v == nil || v.id != s00.ProtocolIEID(99) || v.rowUES1APIDs == nil {
		return nil, false
	}
	return v.rowUES1APIDs, true
}

// AsCause returns the selected Cause value of UEContextReleaseCommandIEValue and reports whether that alternative is active.
func (v *UEContextReleaseCommandIEValue) AsCause() (*s14.Cause, bool) {
	if v == nil || v.id != s00.ProtocolIEID(2) || v.rowCause == nil {
		return nil, false
	}
	return v.rowCause, true
}
func (v UEContextReleaseCommandIEValue) decode(id s00.ProtocolIEID, raw aper.OpaqueOpenType) (UEContextReleaseCommandIEValue, error) {
	out := UEContextReleaseCommandIEValue{id: id}
	switch id {
	case s00.ProtocolIEID(99):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		var value UES1APIDs
		child := scope
		if err := value.unmarshalAPERFrom(child); err != nil {
			return out, fmt.Errorf("%s %w", "UES1APIDs:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "UES1APIDs")
		if err != nil {
			return out, err
		}
		value.perPadding = padding.Padding()
		value.received = true
		raw.RetainContents(&value.receivedBytes)
		value.receivedLocation = raw.ContentLocation()
		out.rowUES1APIDs = &value
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
	default:
		if err := raw.Observe(aper.UnknownIE); err != nil {
			return out, err
		}
		out.opaque = raw.Detached()
		out.isOpaque = true
	}
	return out, nil
}
func (v UEContextReleaseCommandIEValue) encode() ([]byte, error) { return v.encodeFresh(false, nil) }
func (v UEContextReleaseCommandIEValue) encodeFresh(fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
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
	case s00.ProtocolIEID(99):
		if v.rowUES1APIDs == nil {
			return nil, fmt.Errorf("%s missing value", "UEContextReleaseCommand-IEs.id-UE-S1AP-IDs:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		candidate, err := v.rowUES1APIDs.marshalAPERBudget(budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	case s00.ProtocolIEID(2):
		if v.rowCause == nil {
			return nil, fmt.Errorf("%s missing value", "UEContextReleaseCommand-IEs.id-Cause:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		candidate, err := s14.BridgeCauseMethodMarshalAPERBudget(v.rowCause, budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	default:
		return nil, fmt.Errorf("%s id %d has no value", "UEContextReleaseCommandIEValue:", v.id)
	}
}

type ENBEarlyStatusTransferTransparentContainerExtIETable struct{}

func ENBEarlyStatusTransferTransparentContainerExtIEs() ENBEarlyStatusTransferTransparentContainerExtIETable {
	return ENBEarlyStatusTransferTransparentContainerExtIETable{}
}

// ID returns the ASN.1 object-set identity of ENBEarlyStatusTransferTransparentContainerExtIETable.
func (ENBEarlyStatusTransferTransparentContainerExtIETable) ID() s00.TableID {
	return func() s00.TableID {
		sealed := s00.TableID{}
		*s00.BridgeTableIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "ENB-EarlyStatusTransfer-TransparentContainer-ExtIEs"}
		return sealed
	}()
}

// Table returns the ASN.1 object-set table described by ENBEarlyStatusTransferTransparentContainerExtIETable.
func (ENBEarlyStatusTransferTransparentContainerExtIETable) Table() s00.ENBEarlyStatusTransferTransparentContainerExtIEsValueExtensionTable {
	return func() s00.ENBEarlyStatusTransferTransparentContainerExtIEsValueExtensionTable {
		sealed := s00.ENBEarlyStatusTransferTransparentContainerExtIEsValueExtensionTable{}
		*s00.BridgeENBEarlyStatusTransferTransparentContainerExtIEsValueExtensionTableFieldBound(&sealed) = true
		return sealed
	}()
}
func (ENBEarlyStatusTransferTransparentContainerExtIETable) infoBearersSubjectToDLDiscardingList() s00.ExtensionInfo {
	return s00.ExtensionInfo{Table: ENBEarlyStatusTransferTransparentContainerExtIEs().ID(), ID: s00.ProtocolExtensionID(352), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "Bearers-SubjectToDLDiscardingList"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.4", Assignment: aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "ENB-EarlyStatusTransfer-TransparentContainer-ExtIEs", Row: "id-Bearers-SubjectToDLDiscardingList"}}}
}

// BearersSubjectToDLDiscardingList returns the typed binding for the BearersSubjectToDLDiscardingList row of ENBEarlyStatusTransferTransparentContainerExtIETable.
func (t ENBEarlyStatusTransferTransparentContainerExtIETable) BearersSubjectToDLDiscardingList() ENBEarlyStatusTransferTransparentContainerExtIEsBearersSubjectToDLDiscardingListExtBinding {
	return ENBEarlyStatusTransferTransparentContainerExtIEsBearersSubjectToDLDiscardingListExtBinding{info: t.infoBearersSubjectToDLDiscardingList(), codec: func() s15.BearersSubjectToDLDiscardingListValueCodec {
		sealed := s15.BearersSubjectToDLDiscardingListValueCodec{}
		*s15.BridgeBearersSubjectToDLDiscardingListValueCodecFieldPath(&sealed) = "BearersSubjectToDLDiscardingList"
		*s15.BridgeBearersSubjectToDLDiscardingListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s15.BearersSubjectToDLDiscardingList, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s15.BearersSubjectToDLDiscardingList
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("BearersSubjectToDLDiscardingList")
			var zero ENBEarlyStatusTransferTransparentContainerExtIEsValue
			decoded, err := zero.decode(s00.ProtocolIEID(352), raw)
			if err != nil {
				var empty s15.BearersSubjectToDLDiscardingList
				return empty, runtime.WrapDecodePath(err, "BearersSubjectToDLDiscardingList")
			}
			value, ok := decoded.AsBearersSubjectToDLDiscardingList()
			if !ok {
				var empty s15.BearersSubjectToDLDiscardingList
				return empty, fmt.Errorf("binding ENB-EarlyStatusTransfer-TransparentContainer-ExtIEs.id-Bearers-SubjectToDLDiscardingList: no selected value")
			}
			return *value, nil
		}
		*s15.BridgeBearersSubjectToDLDiscardingListValueCodecFieldEncode(&sealed) = func(value s15.BearersSubjectToDLDiscardingList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (ENBEarlyStatusTransferTransparentContainerExtIEsValue{id: s00.ProtocolIEID(352), rowBearersSubjectToDLDiscardingList: &value}).encodeFresh(fresh, budget)
		}
		*s15.BridgeBearersSubjectToDLDiscardingListValueCodecFieldCapture(&sealed) = func(v s15.BearersSubjectToDLDiscardingList, options aper.DecodeState) (s15.BearersSubjectToDLDiscardingList, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s21.BridgeCaptureS1APBearersSubjectToDLDiscardingList(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s15.BridgeBearersSubjectToDLDiscardingListValueCodecFieldCompare(&sealed) = func(v s15.BearersSubjectToDLDiscardingList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s21.BridgeCompareS1APBearersSubjectToDLDiscardingList(&v,
				&s,
			)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s15.BridgeBearersSubjectToDLDiscardingListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:BearersSubjectToDLDiscardingList"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s15.BearersSubjectToDLDiscardingList) ENBEarlyStatusTransferTransparentContainerExtIEsValue {
			return ENBEarlyStatusTransferTransparentContainerExtIEsValue{id: s00.ProtocolIEID(352), rowBearersSubjectToDLDiscardingList: &value}
		}, get: func(value *ENBEarlyStatusTransferTransparentContainerExtIEsValue) (*s15.BearersSubjectToDLDiscardingList, bool) {
			return value.AsBearersSubjectToDLDiscardingList()
		}}
}

// NewOpaque constructs an owned opaque field for an identifier without a typed row in ENBEarlyStatusTransferTransparentContainerExtIETable.
func (t ENBEarlyStatusTransferTransparentContainerExtIETable) NewOpaque(id s00.ProtocolExtensionID, criticality s00.Criticality, data []byte) (ENBEarlyStatusTransferTransparentContainerExtIEsExtField, error) {
	if id < 0 || id > 65535 || criticality < 0 || criticality > 2 {
		return ENBEarlyStatusTransferTransparentContainerExtIEsExtField{}, aper.OperationError(fmt.Errorf("invalid opaque extension selector or criticality"), "Opaque")
	}
	switch id {
	case s00.ProtocolIEID(352):
		return ENBEarlyStatusTransferTransparentContainerExtIEsExtField{}, aper.OperationError(fmt.Errorf("known extension id-Bearers-SubjectToDLDiscardingList requires its typed binding"), "Opaque")
	default:
		budget, err := aper.BuildBudget()
		if err != nil {
			return ENBEarlyStatusTransferTransparentContainerExtIEsExtField{}, aper.OperationError(err, "Opaque")
		}
		opaque, err := aper.BuildOpaqueOpenType(data, budget)
		if err != nil {
			return ENBEarlyStatusTransferTransparentContainerExtIEsExtField{}, aper.OperationError(err, "Opaque")
		}
		return ENBEarlyStatusTransferTransparentContainerExtIEsExtField{Id: id, Criticality: criticality, ExtensionValue: ENBEarlyStatusTransferTransparentContainerExtIEsValue{id: id, opaque: opaque, isOpaque: true}}, aper.OperationError(nil, "Opaque")
	}
}

type ENBCPRelocationIndicationIETable struct{}

func ENBCPRelocationIndicationIEs() ENBCPRelocationIndicationIETable {
	return ENBCPRelocationIndicationIETable{}
}

// ID returns the ASN.1 object-set identity of ENBCPRelocationIndicationIETable.
func (ENBCPRelocationIndicationIETable) ID() s00.TableID {
	return func() s00.TableID {
		sealed := s00.TableID{}
		*s00.BridgeTableIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "ENBCPRelocationIndicationIEs"}
		return sealed
	}()
}

// Table returns the ASN.1 object-set table described by ENBCPRelocationIndicationIETable.
func (ENBCPRelocationIndicationIETable) Table() s00.ENBCPRelocationIndicationIEValueIETable {
	return func() s00.ENBCPRelocationIndicationIEValueIETable {
		sealed := s00.ENBCPRelocationIndicationIEValueIETable{}
		*s00.BridgeENBCPRelocationIndicationIEValueIETableFieldBound(&sealed) = true
		return sealed
	}()
}
func (ENBCPRelocationIndicationIETable) infoENBUES1APID() s00.FieldInfo {
	return s00.FieldInfo{Table: ENBCPRelocationIndicationIEs().ID(), ID: s00.ProtocolIEID(8), Criticality: s00.CriticalityReject, Presence: s00.PresenceMandatory, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "ENB-UE-S1AP-ID"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "ENBCPRelocationIndicationIEs", Row: "id-eNB-UE-S1AP-ID"}}}
}

// ENBUES1APID returns the typed binding for the ENBUES1APID row of ENBCPRelocationIndicationIETable.
func (t ENBCPRelocationIndicationIETable) ENBUES1APID() ENBCPRelocationIndicationENBUES1APIDIEBinding {
	return ENBCPRelocationIndicationENBUES1APIDIEBinding{info: t.infoENBUES1APID(), codec: func() s00.ENBUES1APIDValueCodec {
		sealed := s00.ENBUES1APIDValueCodec{}
		*s00.BridgeENBUES1APIDValueCodecFieldPath(&sealed) = "ENBUES1APID"
		*s00.BridgeENBUES1APIDValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.ENBUES1APID, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s00.ENBUES1APID
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("ENBUES1APID")
			var zero ENBCPRelocationIndicationIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(8), raw)
			if err != nil {
				var empty s00.ENBUES1APID
				return empty, runtime.WrapDecodePath(err, "ENBUES1APID")
			}
			value, ok := decoded.AsENBUES1APID()
			if !ok {
				var empty s00.ENBUES1APID
				return empty, fmt.Errorf("binding ENBCPRelocationIndicationIEs.id-eNB-UE-S1AP-ID: no selected value")
			}
			return *value, nil
		}
		*s00.BridgeENBUES1APIDValueCodecFieldEncode(&sealed) = func(value s00.ENBUES1APID, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (ENBCPRelocationIndicationIEValue{id: s00.ProtocolIEID(8), rowENBUES1APID: &value}).encodeFresh(fresh, budget)
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
		inject: func(value s00.ENBUES1APID) ENBCPRelocationIndicationIEValue {
			return ENBCPRelocationIndicationIEValue{id: s00.ProtocolIEID(8), rowENBUES1APID: &value}
		}, get: func(value *ENBCPRelocationIndicationIEValue) (*s00.ENBUES1APID, bool) { return value.AsENBUES1APID() }}
}
func (ENBCPRelocationIndicationIETable) infoSTMSI() s00.FieldInfo {
	return s00.FieldInfo{Table: ENBCPRelocationIndicationIEs().ID(), ID: s00.ProtocolIEID(96), Criticality: s00.CriticalityReject, Presence: s00.PresenceMandatory, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "S-TMSI"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "ENBCPRelocationIndicationIEs", Row: "id-S-TMSI"}}}
}

// STMSI returns the typed binding for the STMSI row of ENBCPRelocationIndicationIETable.
func (t ENBCPRelocationIndicationIETable) STMSI() ENBCPRelocationIndicationSTMSIIEBinding {
	return ENBCPRelocationIndicationSTMSIIEBinding{info: t.infoSTMSI(), codec: func() s28.STMSIValueCodec {
		sealed := s28.STMSIValueCodec{}
		*s28.BridgeSTMSIValueCodecFieldPath(&sealed) = "STMSI"
		*s28.BridgeSTMSIValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s28.STMSI, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s28.STMSI
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("STMSI")
			var zero ENBCPRelocationIndicationIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(96), raw)
			if err != nil {
				var empty s28.STMSI
				return empty, runtime.WrapDecodePath(err, "STMSI")
			}
			value, ok := decoded.AsSTMSI()
			if !ok {
				var empty s28.STMSI
				return empty, fmt.Errorf("binding ENBCPRelocationIndicationIEs.id-S-TMSI: no selected value")
			}
			return *value, nil
		}
		*s28.BridgeSTMSIValueCodecFieldEncode(&sealed) = func(value s28.STMSI, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (ENBCPRelocationIndicationIEValue{id: s00.ProtocolIEID(96), rowSTMSI: &value}).encodeFresh(fresh, budget)
		}
		*s28.BridgeSTMSIValueCodecFieldCapture(&sealed) = func(v s28.STMSI, options aper.DecodeState) (s28.STMSI, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s28.BridgeCaptureS1APSTMSI(&v, &s)
			var root aper.Snapshot
			s.End(f,
				&root, false)
			return v, root
		}
		*s28.BridgeSTMSIValueCodecFieldCompare(&sealed) = func(v s28.STMSI, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s28.BridgeCompareS1APSTMSI(&v, &s)
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
		inject: func(value s28.STMSI) ENBCPRelocationIndicationIEValue {
			return ENBCPRelocationIndicationIEValue{id: s00.ProtocolIEID(96), rowSTMSI: &value}
		}, get: func(value *ENBCPRelocationIndicationIEValue) (*s28.STMSI, bool) { return value.AsSTMSI() }}
}
func (ENBCPRelocationIndicationIETable) infoEUTRANCGI() s00.FieldInfo {
	return s00.FieldInfo{Table: ENBCPRelocationIndicationIEs().ID(), ID: s00.ProtocolIEID(100), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceMandatory, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "EUTRAN-CGI"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "ENBCPRelocationIndicationIEs", Row: "id-EUTRAN-CGI"}}}
}

// EUTRANCGI returns the typed binding for the EUTRANCGI row of ENBCPRelocationIndicationIETable.
func (t ENBCPRelocationIndicationIETable) EUTRANCGI() ENBCPRelocationIndicationEUTRANCGIIEBinding {
	return ENBCPRelocationIndicationEUTRANCGIIEBinding{info: t.infoEUTRANCGI(), codec: func() s17.EUTRANCGIValueCodec {
		sealed := s17.EUTRANCGIValueCodec{}
		*s17.BridgeEUTRANCGIValueCodecFieldPath(&sealed) = "EUTRANCGI"
		*s17.BridgeEUTRANCGIValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s17.EUTRANCGI, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s17.EUTRANCGI
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("EUTRANCGI")
			var zero ENBCPRelocationIndicationIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(100), raw)
			if err != nil {
				var empty s17.EUTRANCGI
				return empty, runtime.WrapDecodePath(err, "EUTRANCGI")
			}
			value, ok := decoded.AsEUTRANCGI()
			if !ok {
				var empty s17.EUTRANCGI
				return empty, fmt.Errorf("binding ENBCPRelocationIndicationIEs.id-EUTRAN-CGI: no selected value")
			}
			return *value, nil
		}
		*s17.BridgeEUTRANCGIValueCodecFieldEncode(&sealed) = func(value s17.EUTRANCGI, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (ENBCPRelocationIndicationIEValue{id: s00.ProtocolIEID(100), rowEUTRANCGI: &value}).encodeFresh(fresh, budget)
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
		inject: func(value s17.EUTRANCGI) ENBCPRelocationIndicationIEValue {
			return ENBCPRelocationIndicationIEValue{id: s00.ProtocolIEID(100), rowEUTRANCGI: &value}
		}, get: func(value *ENBCPRelocationIndicationIEValue) (*s17.EUTRANCGI, bool) { return value.AsEUTRANCGI() }}
}
func (ENBCPRelocationIndicationIETable) infoTAI() s00.FieldInfo {
	return s00.FieldInfo{Table: ENBCPRelocationIndicationIEs().ID(), ID: s00.ProtocolIEID(67), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceMandatory, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "TAI"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "ENBCPRelocationIndicationIEs", Row: "id-TAI"}}}
}

// TAI returns the typed binding for the TAI row of ENBCPRelocationIndicationIETable.
func (t ENBCPRelocationIndicationIETable) TAI() ENBCPRelocationIndicationTAIIEBinding {
	return ENBCPRelocationIndicationTAIIEBinding{info: t.infoTAI(), codec: func() s32.TAIValueCodec {
		sealed := s32.TAIValueCodec{}
		*s32.BridgeTAIValueCodecFieldPath(&sealed) = "TAI"
		*s32.BridgeTAIValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s31.TAI, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s31.TAI
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("TAI")
			var zero ENBCPRelocationIndicationIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(67), raw)
			if err != nil {
				var empty s31.TAI
				return empty, runtime.WrapDecodePath(err, "TAI")
			}
			value, ok := decoded.AsTAI()
			if !ok {
				var empty s31.TAI
				return empty, fmt.Errorf("binding ENBCPRelocationIndicationIEs.id-TAI: no selected value")
			}
			return *value, nil
		}
		*s32.BridgeTAIValueCodecFieldEncode(&sealed) = func(value s31.TAI, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (ENBCPRelocationIndicationIEValue{id: s00.ProtocolIEID(67), rowTAI: &value}).encodeFresh(fresh, budget)
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
		inject: func(value s31.TAI) ENBCPRelocationIndicationIEValue {
			return ENBCPRelocationIndicationIEValue{id: s00.ProtocolIEID(67), rowTAI: &value}
		}, get: func(value *ENBCPRelocationIndicationIEValue) (*s31.TAI, bool) { return value.AsTAI() }}
}
func (ENBCPRelocationIndicationIETable) infoULCPSecurityInformation() s00.FieldInfo {
	return s00.FieldInfo{Table: ENBCPRelocationIndicationIEs().ID(), ID: s00.ProtocolIEID(254), Criticality: s00.CriticalityReject, Presence: s00.PresenceMandatory, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "UL-CP-SecurityInformation"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "ENBCPRelocationIndicationIEs", Row: "id-UL-CP-SecurityInformation"}}}
}

// ULCPSecurityInformation returns the typed binding for the ULCPSecurityInformation row of ENBCPRelocationIndicationIETable.
func (t ENBCPRelocationIndicationIETable) ULCPSecurityInformation() ENBCPRelocationIndicationULCPSecurityInformationIEBinding {
	return ENBCPRelocationIndicationULCPSecurityInformationIEBinding{info: t.infoULCPSecurityInformation(), codec: ULCPSecurityInformationValueCodec{path: "ULCPSecurityInformation",
		decode: func(data []byte, options aper.DecodeState) (ULCPSecurityInformation, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty ULCPSecurityInformation
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("ULCPSecurityInformation")
			var zero ENBCPRelocationIndicationIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(254), raw)
			if err != nil {
				var empty ULCPSecurityInformation
				return empty, runtime.WrapDecodePath(err, "ULCPSecurityInformation")
			}
			value, ok := decoded.AsULCPSecurityInformation()
			if !ok {
				var empty ULCPSecurityInformation
				return empty, fmt.Errorf("binding ENBCPRelocationIndicationIEs.id-UL-CP-SecurityInformation: no selected value")
			}
			return *value, nil
		},
		encode: func(value ULCPSecurityInformation, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (ENBCPRelocationIndicationIEValue{id: s00.ProtocolIEID(254), rowULCPSecurityInformation: &value}).encodeFresh(fresh, budget)
		}, capture: func(v ULCPSecurityInformation, options aper.DecodeState) (ULCPSecurityInformation, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeCaptureS1APULCPSecurityInformation(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,

				false,
			)
			return v, root
		}, compare: func(v ULCPSecurityInformation, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeCompareS1APULCPSecurityInformation(&v, &s)
			s.End(f, root,
				false,
			)
			return s.Plan(), s.BudgetValue()
		}, context: func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ULCPSecurityInformation"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}(),
	}, inject: func(value ULCPSecurityInformation) ENBCPRelocationIndicationIEValue {
		return ENBCPRelocationIndicationIEValue{id: s00.ProtocolIEID(254), rowULCPSecurityInformation: &value}
	}, get: func(value *ENBCPRelocationIndicationIEValue) (*ULCPSecurityInformation, bool) {
		return value.AsULCPSecurityInformation()
	}}
}
func (ENBCPRelocationIndicationIETable) infoLTENTNTAIInformation() s00.FieldInfo {
	return s00.FieldInfo{Table: ENBCPRelocationIndicationIEs().ID(), ID: s00.ProtocolIEID(339), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "LTE-NTN-TAI-Information"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "ENBCPRelocationIndicationIEs", Row: "id-LTE-NTN-TAI-Information"}}}
}

// LTENTNTAIInformation returns the typed binding for the LTENTNTAIInformation row of ENBCPRelocationIndicationIETable.
func (t ENBCPRelocationIndicationIETable) LTENTNTAIInformation() ENBCPRelocationIndicationLTENTNTAIInformationIEBinding {
	return ENBCPRelocationIndicationLTENTNTAIInformationIEBinding{info: t.infoLTENTNTAIInformation(), codec: func() s18.LTENTNTAIInformationValueCodec {
		sealed := s18.LTENTNTAIInformationValueCodec{}
		*s18.BridgeLTENTNTAIInformationValueCodecFieldPath(&sealed) = "LTENTNTAIInformation"
		*s18.BridgeLTENTNTAIInformationValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s18.LTENTNTAIInformation, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s18.LTENTNTAIInformation
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("LTENTNTAIInformation")
			var zero ENBCPRelocationIndicationIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(339), raw)
			if err != nil {
				var empty s18.LTENTNTAIInformation
				return empty, runtime.WrapDecodePath(err, "LTENTNTAIInformation")
			}
			value, ok := decoded.AsLTENTNTAIInformation()
			if !ok {
				var empty s18.LTENTNTAIInformation
				return empty, fmt.Errorf("binding ENBCPRelocationIndicationIEs.id-LTE-NTN-TAI-Information: no selected value")
			}
			return *value, nil
		}
		*s18.BridgeLTENTNTAIInformationValueCodecFieldEncode(&sealed) = func(value s18.LTENTNTAIInformation, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (ENBCPRelocationIndicationIEValue{id: s00.ProtocolIEID(339), rowLTENTNTAIInformation: &value}).encodeFresh(fresh, budget)
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
		inject: func(value s18.LTENTNTAIInformation) ENBCPRelocationIndicationIEValue {
			return ENBCPRelocationIndicationIEValue{id: s00.ProtocolIEID(339), rowLTENTNTAIInformation: &value}
		}, get: func(value *ENBCPRelocationIndicationIEValue) (*s18.LTENTNTAIInformation, bool) {
			return value.AsLTENTNTAIInformation()
		}}
}

// NewOpaque constructs an owned opaque field for an identifier without a typed row in ENBCPRelocationIndicationIETable.
func (t ENBCPRelocationIndicationIETable) NewOpaque(id s00.ProtocolIEID, criticality s00.Criticality, data []byte) (ENBCPRelocationIndicationIEField, error) {
	if id < 0 || id > 65535 || criticality < 0 || criticality > 2 {
		return ENBCPRelocationIndicationIEField{}, aper.OperationError(fmt.Errorf("invalid opaque IE selector or criticality"), "Opaque")
	}
	switch id {
	case s00.ProtocolIEID(8):
		return ENBCPRelocationIndicationIEField{}, aper.OperationError(fmt.Errorf("known IE id-eNB-UE-S1AP-ID requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(96):
		return ENBCPRelocationIndicationIEField{}, aper.OperationError(fmt.Errorf("known IE id-S-TMSI requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(100):
		return ENBCPRelocationIndicationIEField{}, aper.OperationError(fmt.Errorf("known IE id-EUTRAN-CGI requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(67):
		return ENBCPRelocationIndicationIEField{}, aper.OperationError(fmt.Errorf("known IE id-TAI requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(254):
		return ENBCPRelocationIndicationIEField{}, aper.OperationError(fmt.Errorf("known IE id-UL-CP-SecurityInformation requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(339):
		return ENBCPRelocationIndicationIEField{}, aper.OperationError(fmt.Errorf("known IE id-LTE-NTN-TAI-Information requires its typed binding"), "Opaque")
	default:
		budget, err := aper.BuildBudget()
		if err != nil {
			return ENBCPRelocationIndicationIEField{}, aper.OperationError(err, "Opaque")
		}
		opaque, err := aper.BuildOpaqueOpenType(data, budget)
		if err != nil {
			return ENBCPRelocationIndicationIEField{}, aper.OperationError(err, "Opaque")
		}
		return ENBCPRelocationIndicationIEField{Id: id, Criticality: criticality, Value: ENBCPRelocationIndicationIEValue{id: id, opaque: opaque, isOpaque: true}}, aper.OperationError(nil, "Opaque")
	}
}

type ENBEarlyStatusTransferIETable struct{}

func ENBEarlyStatusTransferIEs() ENBEarlyStatusTransferIETable {
	return ENBEarlyStatusTransferIETable{}
}

// ID returns the ASN.1 object-set identity of ENBEarlyStatusTransferIETable.
func (ENBEarlyStatusTransferIETable) ID() s00.TableID {
	return func() s00.TableID {
		sealed := s00.TableID{}
		*s00.BridgeTableIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "ENBEarlyStatusTransferIEs"}
		return sealed
	}()
}

// Table returns the ASN.1 object-set table described by ENBEarlyStatusTransferIETable.
func (ENBEarlyStatusTransferIETable) Table() s00.ENBEarlyStatusTransferIEValueIETable {
	return func() s00.ENBEarlyStatusTransferIEValueIETable {
		sealed := s00.ENBEarlyStatusTransferIEValueIETable{}
		*s00.BridgeENBEarlyStatusTransferIEValueIETableFieldBound(&sealed) = true
		return sealed
	}()
}
func (ENBEarlyStatusTransferIETable) infoMMEUES1APID() s00.FieldInfo {
	return s00.FieldInfo{Table: ENBEarlyStatusTransferIEs().ID(), ID: s00.ProtocolIEID(0), Criticality: s00.CriticalityReject, Presence: s00.PresenceMandatory, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "MME-UE-S1AP-ID"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "ENBEarlyStatusTransferIEs", Row: "id-MME-UE-S1AP-ID"}}}
}

// MMEUES1APID returns the typed binding for the MMEUES1APID row of ENBEarlyStatusTransferIETable.
func (t ENBEarlyStatusTransferIETable) MMEUES1APID() ENBEarlyStatusTransferMMEUES1APIDIEBinding {
	return ENBEarlyStatusTransferMMEUES1APIDIEBinding{info: t.infoMMEUES1APID(), codec: func() s01.MMEUES1APIDValueCodec {
		sealed := s01.MMEUES1APIDValueCodec{}
		*s01.BridgeMMEUES1APIDValueCodecFieldPath(&sealed) = "MMEUES1APID"
		*s01.BridgeMMEUES1APIDValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.MMEUES1APID, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s00.MMEUES1APID
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("MMEUES1APID")
			var zero ENBEarlyStatusTransferIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(0), raw)
			if err != nil {
				var empty s00.MMEUES1APID
				return empty, runtime.WrapDecodePath(err, "MMEUES1APID")
			}
			value, ok := decoded.AsMMEUES1APID()
			if !ok {
				var empty s00.MMEUES1APID
				return empty, fmt.Errorf("binding ENBEarlyStatusTransferIEs.id-MME-UE-S1AP-ID: no selected value")
			}
			return *value, nil
		}
		*s01.BridgeMMEUES1APIDValueCodecFieldEncode(&sealed) = func(value s00.MMEUES1APID, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (ENBEarlyStatusTransferIEValue{id: s00.ProtocolIEID(0), rowMMEUES1APID: &value}).encodeFresh(fresh, budget)
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
		inject: func(value s00.MMEUES1APID) ENBEarlyStatusTransferIEValue {
			return ENBEarlyStatusTransferIEValue{id: s00.ProtocolIEID(0), rowMMEUES1APID: &value}
		}, get: func(value *ENBEarlyStatusTransferIEValue) (*s00.MMEUES1APID, bool) { return value.AsMMEUES1APID() }}
}
func (ENBEarlyStatusTransferIETable) infoENBUES1APID() s00.FieldInfo {
	return s00.FieldInfo{Table: ENBEarlyStatusTransferIEs().ID(), ID: s00.ProtocolIEID(8), Criticality: s00.CriticalityReject, Presence: s00.PresenceMandatory, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "ENB-UE-S1AP-ID"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "ENBEarlyStatusTransferIEs", Row: "id-eNB-UE-S1AP-ID"}}}
}

// ENBUES1APID returns the typed binding for the ENBUES1APID row of ENBEarlyStatusTransferIETable.
func (t ENBEarlyStatusTransferIETable) ENBUES1APID() ENBEarlyStatusTransferENBUES1APIDIEBinding {
	return ENBEarlyStatusTransferENBUES1APIDIEBinding{info: t.infoENBUES1APID(), codec: func() s00.ENBUES1APIDValueCodec {
		sealed := s00.ENBUES1APIDValueCodec{}
		*s00.BridgeENBUES1APIDValueCodecFieldPath(&sealed) = "ENBUES1APID"
		*s00.BridgeENBUES1APIDValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.ENBUES1APID, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s00.ENBUES1APID
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("ENBUES1APID")
			var zero ENBEarlyStatusTransferIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(8), raw)
			if err != nil {
				var empty s00.ENBUES1APID
				return empty, runtime.WrapDecodePath(err, "ENBUES1APID")
			}
			value, ok := decoded.AsENBUES1APID()
			if !ok {
				var empty s00.ENBUES1APID
				return empty, fmt.Errorf("binding ENBEarlyStatusTransferIEs.id-eNB-UE-S1AP-ID: no selected value")
			}
			return *value, nil
		}
		*s00.BridgeENBUES1APIDValueCodecFieldEncode(&sealed) = func(value s00.ENBUES1APID, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (ENBEarlyStatusTransferIEValue{id: s00.ProtocolIEID(8), rowENBUES1APID: &value}).encodeFresh(fresh, budget)
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
		inject: func(value s00.ENBUES1APID) ENBEarlyStatusTransferIEValue {
			return ENBEarlyStatusTransferIEValue{id: s00.ProtocolIEID(8), rowENBUES1APID: &value}
		}, get: func(value *ENBEarlyStatusTransferIEValue) (*s00.ENBUES1APID, bool) { return value.AsENBUES1APID() }}
}
func (ENBEarlyStatusTransferIETable) infoENBEarlyStatusTransferTransparentContainer() s00.FieldInfo {
	return s00.FieldInfo{Table: ENBEarlyStatusTransferIEs().ID(), ID: s00.ProtocolIEID(321), Criticality: s00.CriticalityReject, Presence: s00.PresenceMandatory, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "ENB-EarlyStatusTransfer-TransparentContainer"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "ENBEarlyStatusTransferIEs", Row: "id-eNB-EarlyStatusTransfer-TransparentContainer"}}}
}

// ENBEarlyStatusTransferTransparentContainer returns the typed binding for the ENBEarlyStatusTransferTransparentContainer row of ENBEarlyStatusTransferIETable.
func (t ENBEarlyStatusTransferIETable) ENBEarlyStatusTransferTransparentContainer() ENBEarlyStatusTransferENBEarlyStatusTransferTransparentContainerIEBinding {
	return ENBEarlyStatusTransferENBEarlyStatusTransferTransparentContainerIEBinding{info: t.infoENBEarlyStatusTransferTransparentContainer(), codec: ENBEarlyStatusTransferTransparentContainerValueCodec{path: "ENBEarlyStatusTransferTransparentContainer",
		decode: func(data []byte, options aper.DecodeState) (ENBEarlyStatusTransferTransparentContainer, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty ENBEarlyStatusTransferTransparentContainer
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("ENBEarlyStatusTransferTransparentContainer")
			var zero ENBEarlyStatusTransferIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(321), raw)
			if err != nil {
				var empty ENBEarlyStatusTransferTransparentContainer
				return empty, runtime.WrapDecodePath(err, "ENBEarlyStatusTransferTransparentContainer")
			}
			value, ok := decoded.AsENBEarlyStatusTransferTransparentContainer()
			if !ok {
				var empty ENBEarlyStatusTransferTransparentContainer
				return empty, fmt.Errorf("binding ENBEarlyStatusTransferIEs.id-eNB-EarlyStatusTransfer-TransparentContainer: no selected value")
			}
			return *value, nil
		},
		encode: func(value ENBEarlyStatusTransferTransparentContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (ENBEarlyStatusTransferIEValue{id: s00.ProtocolIEID(321), rowENBEarlyStatusTransferTransparentContainer: &value}).encodeFresh(fresh, budget)
		}, capture: func(v ENBEarlyStatusTransferTransparentContainer, options aper.DecodeState) (ENBEarlyStatusTransferTransparentContainer, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeCaptureS1APENBEarlyStatusTransferTransparentContainer(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,

				false)
			return v, root
		}, compare: func(v ENBEarlyStatusTransferTransparentContainer, root aper.Snapshot, budget aper.DecodeBudget,
		) (aper.ReplayPlan, aper.DecodeBudget) {
			s := aper.NewSemanticComparison(root,
				budget)
			f := s.Begin()
			BridgeCompareS1APENBEarlyStatusTransferTransparentContainer(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}, context: func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ENBEarlyStatusTransferTransparentContainer"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}(),
	}, inject: func(value ENBEarlyStatusTransferTransparentContainer) ENBEarlyStatusTransferIEValue {
		return ENBEarlyStatusTransferIEValue{id: s00.ProtocolIEID(321), rowENBEarlyStatusTransferTransparentContainer: &value}
	}, get: func(value *ENBEarlyStatusTransferIEValue) (*ENBEarlyStatusTransferTransparentContainer, bool) {
		return value.AsENBEarlyStatusTransferTransparentContainer()
	}}
}

// NewOpaque constructs an owned opaque field for an identifier without a typed row in ENBEarlyStatusTransferIETable.
func (t ENBEarlyStatusTransferIETable) NewOpaque(id s00.ProtocolIEID, criticality s00.Criticality, data []byte) (ENBEarlyStatusTransferIEField, error) {
	if id < 0 || id > 65535 || criticality < 0 || criticality > 2 {
		return ENBEarlyStatusTransferIEField{}, aper.OperationError(fmt.Errorf("invalid opaque IE selector or criticality"), "Opaque")
	}
	switch id {
	case s00.ProtocolIEID(0):
		return ENBEarlyStatusTransferIEField{}, aper.OperationError(fmt.Errorf("known IE id-MME-UE-S1AP-ID requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(8):
		return ENBEarlyStatusTransferIEField{}, aper.OperationError(fmt.Errorf("known IE id-eNB-UE-S1AP-ID requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(321):
		return ENBEarlyStatusTransferIEField{}, aper.OperationError(fmt.Errorf("known IE id-eNB-EarlyStatusTransfer-TransparentContainer requires its typed binding"), "Opaque")
	default:
		budget, err := aper.BuildBudget()
		if err != nil {
			return ENBEarlyStatusTransferIEField{}, aper.OperationError(err, "Opaque")
		}
		opaque, err := aper.BuildOpaqueOpenType(data, budget)
		if err != nil {
			return ENBEarlyStatusTransferIEField{}, aper.OperationError(err, "Opaque")
		}
		return ENBEarlyStatusTransferIEField{Id: id, Criticality: criticality, Value: ENBEarlyStatusTransferIEValue{id: id, opaque: opaque, isOpaque: true}}, aper.OperationError(nil, "Opaque")
	}
}

type MMEEarlyStatusTransferIETable struct{}

func MMEEarlyStatusTransferIEs() MMEEarlyStatusTransferIETable {
	return MMEEarlyStatusTransferIETable{}
}

// ID returns the ASN.1 object-set identity of MMEEarlyStatusTransferIETable.
func (MMEEarlyStatusTransferIETable) ID() s00.TableID {
	return func() s00.TableID {
		sealed := s00.TableID{}
		*s00.BridgeTableIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "MMEEarlyStatusTransferIEs"}
		return sealed
	}()
}

// Table returns the ASN.1 object-set table described by MMEEarlyStatusTransferIETable.
func (MMEEarlyStatusTransferIETable) Table() s00.MMEEarlyStatusTransferIEValueIETable {
	return func() s00.MMEEarlyStatusTransferIEValueIETable {
		sealed := s00.MMEEarlyStatusTransferIEValueIETable{}
		*s00.BridgeMMEEarlyStatusTransferIEValueIETableFieldBound(&sealed) = true
		return sealed
	}()
}
func (MMEEarlyStatusTransferIETable) infoMMEUES1APID() s00.FieldInfo {
	return s00.FieldInfo{Table: MMEEarlyStatusTransferIEs().ID(), ID: s00.ProtocolIEID(0), Criticality: s00.CriticalityReject, Presence: s00.PresenceMandatory, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "MME-UE-S1AP-ID"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "MMEEarlyStatusTransferIEs", Row: "id-MME-UE-S1AP-ID"}}}
}

// MMEUES1APID returns the typed binding for the MMEUES1APID row of MMEEarlyStatusTransferIETable.
func (t MMEEarlyStatusTransferIETable) MMEUES1APID() MMEEarlyStatusTransferMMEUES1APIDIEBinding {
	return MMEEarlyStatusTransferMMEUES1APIDIEBinding{info: t.infoMMEUES1APID(), codec: func() s01.MMEUES1APIDValueCodec {
		sealed := s01.MMEUES1APIDValueCodec{}
		*s01.BridgeMMEUES1APIDValueCodecFieldPath(&sealed) = "MMEUES1APID"
		*s01.BridgeMMEUES1APIDValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.MMEUES1APID, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s00.MMEUES1APID
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("MMEUES1APID")
			var zero MMEEarlyStatusTransferIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(0), raw)
			if err != nil {
				var empty s00.MMEUES1APID
				return empty, runtime.WrapDecodePath(err, "MMEUES1APID")
			}
			value, ok := decoded.AsMMEUES1APID()
			if !ok {
				var empty s00.MMEUES1APID
				return empty, fmt.Errorf("binding MMEEarlyStatusTransferIEs.id-MME-UE-S1AP-ID: no selected value")
			}
			return *value, nil
		}
		*s01.BridgeMMEUES1APIDValueCodecFieldEncode(&sealed) = func(value s00.MMEUES1APID, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (MMEEarlyStatusTransferIEValue{id: s00.ProtocolIEID(0), rowMMEUES1APID: &value}).encodeFresh(fresh, budget)
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
		inject: func(value s00.MMEUES1APID) MMEEarlyStatusTransferIEValue {
			return MMEEarlyStatusTransferIEValue{id: s00.ProtocolIEID(0), rowMMEUES1APID: &value}
		}, get: func(value *MMEEarlyStatusTransferIEValue) (*s00.MMEUES1APID, bool) { return value.AsMMEUES1APID() }}
}
func (MMEEarlyStatusTransferIETable) infoENBUES1APID() s00.FieldInfo {
	return s00.FieldInfo{Table: MMEEarlyStatusTransferIEs().ID(), ID: s00.ProtocolIEID(8), Criticality: s00.CriticalityReject, Presence: s00.PresenceMandatory, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "ENB-UE-S1AP-ID"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "MMEEarlyStatusTransferIEs", Row: "id-eNB-UE-S1AP-ID"}}}
}

// ENBUES1APID returns the typed binding for the ENBUES1APID row of MMEEarlyStatusTransferIETable.
func (t MMEEarlyStatusTransferIETable) ENBUES1APID() MMEEarlyStatusTransferENBUES1APIDIEBinding {
	return MMEEarlyStatusTransferENBUES1APIDIEBinding{info: t.infoENBUES1APID(), codec: func() s00.ENBUES1APIDValueCodec {
		sealed := s00.ENBUES1APIDValueCodec{}
		*s00.BridgeENBUES1APIDValueCodecFieldPath(&sealed) = "ENBUES1APID"
		*s00.BridgeENBUES1APIDValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.ENBUES1APID, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s00.ENBUES1APID
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("ENBUES1APID")
			var zero MMEEarlyStatusTransferIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(8), raw)
			if err != nil {
				var empty s00.ENBUES1APID
				return empty, runtime.WrapDecodePath(err, "ENBUES1APID")
			}
			value, ok := decoded.AsENBUES1APID()
			if !ok {
				var empty s00.ENBUES1APID
				return empty, fmt.Errorf("binding MMEEarlyStatusTransferIEs.id-eNB-UE-S1AP-ID: no selected value")
			}
			return *value, nil
		}
		*s00.BridgeENBUES1APIDValueCodecFieldEncode(&sealed) = func(value s00.ENBUES1APID, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (MMEEarlyStatusTransferIEValue{id: s00.ProtocolIEID(8), rowENBUES1APID: &value}).encodeFresh(fresh, budget)
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
		inject: func(value s00.ENBUES1APID) MMEEarlyStatusTransferIEValue {
			return MMEEarlyStatusTransferIEValue{id: s00.ProtocolIEID(8), rowENBUES1APID: &value}
		}, get: func(value *MMEEarlyStatusTransferIEValue) (*s00.ENBUES1APID, bool) { return value.AsENBUES1APID() }}
}
func (MMEEarlyStatusTransferIETable) infoENBEarlyStatusTransferTransparentContainer() s00.FieldInfo {
	return s00.FieldInfo{Table: MMEEarlyStatusTransferIEs().ID(), ID: s00.ProtocolIEID(321), Criticality: s00.CriticalityReject, Presence: s00.PresenceMandatory, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "ENB-EarlyStatusTransfer-TransparentContainer"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "MMEEarlyStatusTransferIEs", Row: "id-eNB-EarlyStatusTransfer-TransparentContainer"}}}
}

// ENBEarlyStatusTransferTransparentContainer returns the typed binding for the ENBEarlyStatusTransferTransparentContainer row of MMEEarlyStatusTransferIETable.
func (t MMEEarlyStatusTransferIETable) ENBEarlyStatusTransferTransparentContainer() MMEEarlyStatusTransferENBEarlyStatusTransferTransparentContainerIEBinding {
	return MMEEarlyStatusTransferENBEarlyStatusTransferTransparentContainerIEBinding{info: t.infoENBEarlyStatusTransferTransparentContainer(), codec: ENBEarlyStatusTransferTransparentContainerValueCodec{path: "ENBEarlyStatusTransferTransparentContainer",
		decode: func(data []byte, options aper.DecodeState) (ENBEarlyStatusTransferTransparentContainer, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty ENBEarlyStatusTransferTransparentContainer
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("ENBEarlyStatusTransferTransparentContainer")
			var zero MMEEarlyStatusTransferIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(321), raw)
			if err != nil {
				var empty ENBEarlyStatusTransferTransparentContainer
				return empty, runtime.WrapDecodePath(err, "ENBEarlyStatusTransferTransparentContainer")
			}
			value, ok := decoded.AsENBEarlyStatusTransferTransparentContainer()
			if !ok {
				var empty ENBEarlyStatusTransferTransparentContainer
				return empty, fmt.Errorf("binding MMEEarlyStatusTransferIEs.id-eNB-EarlyStatusTransfer-TransparentContainer: no selected value")
			}
			return *value, nil
		},
		encode: func(value ENBEarlyStatusTransferTransparentContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (MMEEarlyStatusTransferIEValue{id: s00.ProtocolIEID(321), rowENBEarlyStatusTransferTransparentContainer: &value}).encodeFresh(fresh, budget)
		}, capture: func(v ENBEarlyStatusTransferTransparentContainer, options aper.DecodeState) (ENBEarlyStatusTransferTransparentContainer, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeCaptureS1APENBEarlyStatusTransferTransparentContainer(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,

				false)
			return v, root
		}, compare: func(v ENBEarlyStatusTransferTransparentContainer, root aper.Snapshot, budget aper.DecodeBudget,
		) (aper.ReplayPlan, aper.DecodeBudget) {
			s := aper.NewSemanticComparison(root,
				budget)
			f := s.Begin()
			BridgeCompareS1APENBEarlyStatusTransferTransparentContainer(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}, context: func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ENBEarlyStatusTransferTransparentContainer"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}(),
	}, inject: func(value ENBEarlyStatusTransferTransparentContainer) MMEEarlyStatusTransferIEValue {
		return MMEEarlyStatusTransferIEValue{id: s00.ProtocolIEID(321), rowENBEarlyStatusTransferTransparentContainer: &value}
	}, get: func(value *MMEEarlyStatusTransferIEValue) (*ENBEarlyStatusTransferTransparentContainer, bool) {
		return value.AsENBEarlyStatusTransferTransparentContainer()
	}}
}

// NewOpaque constructs an owned opaque field for an identifier without a typed row in MMEEarlyStatusTransferIETable.
func (t MMEEarlyStatusTransferIETable) NewOpaque(id s00.ProtocolIEID, criticality s00.Criticality, data []byte) (MMEEarlyStatusTransferIEField, error) {
	if id < 0 || id > 65535 || criticality < 0 || criticality > 2 {
		return MMEEarlyStatusTransferIEField{}, aper.OperationError(fmt.Errorf("invalid opaque IE selector or criticality"), "Opaque")
	}
	switch id {
	case s00.ProtocolIEID(0):
		return MMEEarlyStatusTransferIEField{}, aper.OperationError(fmt.Errorf("known IE id-MME-UE-S1AP-ID requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(8):
		return MMEEarlyStatusTransferIEField{}, aper.OperationError(fmt.Errorf("known IE id-eNB-UE-S1AP-ID requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(321):
		return MMEEarlyStatusTransferIEField{}, aper.OperationError(fmt.Errorf("known IE id-eNB-EarlyStatusTransfer-TransparentContainer requires its typed binding"), "Opaque")
	default:
		budget, err := aper.BuildBudget()
		if err != nil {
			return MMEEarlyStatusTransferIEField{}, aper.OperationError(err, "Opaque")
		}
		opaque, err := aper.BuildOpaqueOpenType(data, budget)
		if err != nil {
			return MMEEarlyStatusTransferIEField{}, aper.OperationError(err, "Opaque")
		}
		return MMEEarlyStatusTransferIEField{Id: id, Criticality: criticality, Value: MMEEarlyStatusTransferIEValue{id: id, opaque: opaque, isOpaque: true}}, aper.OperationError(nil, "Opaque")
	}
}

type UEContextReleaseCommandIETable struct{}

func UEContextReleaseCommandIEs() UEContextReleaseCommandIETable {
	return UEContextReleaseCommandIETable{}
}

// ID returns the ASN.1 object-set identity of UEContextReleaseCommandIETable.
func (UEContextReleaseCommandIETable) ID() s00.TableID {
	return func() s00.TableID {
		sealed := s00.TableID{}
		*s00.BridgeTableIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "UEContextReleaseCommand-IEs"}
		return sealed
	}()
}

// Table returns the ASN.1 object-set table described by UEContextReleaseCommandIETable.
func (UEContextReleaseCommandIETable) Table() s00.UEContextReleaseCommandIEValueIETable {
	return func() s00.UEContextReleaseCommandIEValueIETable {
		sealed := s00.UEContextReleaseCommandIEValueIETable{}
		*s00.BridgeUEContextReleaseCommandIEValueIETableFieldBound(&sealed) = true
		return sealed
	}()
}
func (UEContextReleaseCommandIETable) infoUES1APIDs() s00.FieldInfo {
	return s00.FieldInfo{Table: UEContextReleaseCommandIEs().ID(), ID: s00.ProtocolIEID(99), Criticality: s00.CriticalityReject, Presence: s00.PresenceMandatory, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "UE-S1AP-IDs"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "UEContextReleaseCommand-IEs", Row: "id-UE-S1AP-IDs"}}}
}

// UES1APIDs returns the typed binding for the UES1APIDs row of UEContextReleaseCommandIETable.
func (t UEContextReleaseCommandIETable) UES1APIDs() UEContextReleaseCommandUES1APIDsIEBinding {
	return UEContextReleaseCommandUES1APIDsIEBinding{info: t.infoUES1APIDs(), codec: UES1APIDsValueCodec{path: "UES1APIDs",
		decode: func(data []byte, options aper.DecodeState) (UES1APIDs, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty UES1APIDs
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("UES1APIDs")
			var zero UEContextReleaseCommandIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(99), raw)
			if err != nil {
				var empty UES1APIDs
				return empty, runtime.WrapDecodePath(err, "UES1APIDs")
			}
			value, ok := decoded.AsUES1APIDs()
			if !ok {
				var empty UES1APIDs
				return empty, fmt.Errorf("binding UEContextReleaseCommand-IEs.id-UE-S1AP-IDs: no selected value")
			}
			return *value, nil
		},
		encode: func(value UES1APIDs, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (UEContextReleaseCommandIEValue{id: s00.ProtocolIEID(99), rowUES1APIDs: &value}).encodeFresh(fresh, budget)
		}, capture: func(v UES1APIDs, options aper.DecodeState) (UES1APIDs, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.
				Begin()
			BridgeCaptureS1APUES1APIDs(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}, compare: func(v UES1APIDs, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeCompareS1APUES1APIDs(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}, context: func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:UES1APIDs"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}(),
	}, inject: func(value UES1APIDs) UEContextReleaseCommandIEValue {
		return UEContextReleaseCommandIEValue{id: s00.ProtocolIEID(99), rowUES1APIDs: &value}
	}, get: func(value *UEContextReleaseCommandIEValue) (*UES1APIDs, bool) { return value.AsUES1APIDs() }}
}
func (UEContextReleaseCommandIETable) infoCause() s00.FieldInfo {
	return s00.FieldInfo{Table: UEContextReleaseCommandIEs().ID(), ID: s00.ProtocolIEID(2), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceMandatory, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "Cause"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "UEContextReleaseCommand-IEs", Row: "id-Cause"}}}
}

// Cause returns the typed binding for the Cause row of UEContextReleaseCommandIETable.
func (t UEContextReleaseCommandIETable) Cause() UEContextReleaseCommandCauseIEBinding {
	return UEContextReleaseCommandCauseIEBinding{info: t.infoCause(), codec: func() s14.CauseValueCodec {
		sealed := s14.CauseValueCodec{}
		*s14.BridgeCauseValueCodecFieldPath(&sealed) = "Cause"
		*s14.BridgeCauseValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s14.Cause, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s14.Cause
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("Cause")
			var zero UEContextReleaseCommandIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(2), raw)
			if err != nil {
				var empty s14.Cause
				return empty, runtime.WrapDecodePath(err, "Cause")
			}
			value, ok := decoded.AsCause()
			if !ok {
				var empty s14.Cause
				return empty, fmt.Errorf("binding UEContextReleaseCommand-IEs.id-Cause: no selected value")
			}
			return *value, nil
		}
		*s14.BridgeCauseValueCodecFieldEncode(&sealed) = func(value s14.Cause, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (UEContextReleaseCommandIEValue{id: s00.ProtocolIEID(2), rowCause: &value}).encodeFresh(fresh, budget)
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
		inject: func(value s14.Cause) UEContextReleaseCommandIEValue {
			return UEContextReleaseCommandIEValue{id: s00.ProtocolIEID(2), rowCause: &value}
		}, get: func(value *UEContextReleaseCommandIEValue) (*s14.Cause, bool) { return value.AsCause() }}
}

// NewOpaque constructs an owned opaque field for an identifier without a typed row in UEContextReleaseCommandIETable.
func (t UEContextReleaseCommandIETable) NewOpaque(id s00.ProtocolIEID, criticality s00.Criticality, data []byte) (UEContextReleaseCommandIEField, error) {
	if id < 0 || id > 65535 || criticality < 0 || criticality > 2 {
		return UEContextReleaseCommandIEField{}, aper.OperationError(fmt.Errorf("invalid opaque IE selector or criticality"), "Opaque")
	}
	switch id {
	case s00.ProtocolIEID(99):
		return UEContextReleaseCommandIEField{}, aper.OperationError(fmt.Errorf("known IE id-UE-S1AP-IDs requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(2):
		return UEContextReleaseCommandIEField{}, aper.OperationError(fmt.Errorf("known IE id-Cause requires its typed binding"), "Opaque")
	default:
		budget, err := aper.BuildBudget()
		if err != nil {
			return UEContextReleaseCommandIEField{}, aper.OperationError(err, "Opaque")
		}
		opaque, err := aper.BuildOpaqueOpenType(data, budget)
		if err != nil {
			return UEContextReleaseCommandIEField{}, aper.OperationError(err, "Opaque")
		}
		return UEContextReleaseCommandIEField{Id: id, Criticality: criticality, Value: UEContextReleaseCommandIEValue{id: id, opaque: opaque, isOpaque: true}}, aper.OperationError(nil, "Opaque")
	}
}

// ActivatedCellsListCodec binds the complete source value type.
func ActivatedCellsListCodec() s14.ActivatedCellsListValueCodec {
	return func() s14.ActivatedCellsListValueCodec {
		sealed := s14.ActivatedCellsListValueCodec{}
		*s14.BridgeActivatedCellsListValueCodecFieldPath(&sealed) = "ActivatedCellsList"
		*s14.BridgeActivatedCellsListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s14.ActivatedCellsList, error) {
			var complete ActivatedCellsListComplete
			if err := complete.unmarshalAPERWithOptions(data, options); err != nil {
				var zero s14.ActivatedCellsList
				return zero, err
			}
			return complete.Value, nil
		}
		*s14.BridgeActivatedCellsListValueCodecFieldEncode(&sealed) = func(value s14.ActivatedCellsList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			complete := ActivatedCellsListComplete{Value: value}
			return complete.marshalAPERBudget(budget, fresh)
		}
		*s14.BridgeActivatedCellsListValueCodecFieldCapture(&sealed) = func(v s14.ActivatedCellsList, options aper.DecodeState) (s14.ActivatedCellsList, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s21.BridgeCaptureS1APActivatedCellsList(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v,

				root
		}
		*s14.BridgeActivatedCellsListValueCodecFieldCompare(&sealed) = func(v s14.ActivatedCellsList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s21.BridgeCompareS1APActivatedCellsList(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s14.BridgeActivatedCellsListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ActivatedCellsList"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// BPLMNsCodec binds the complete source value type.
func BPLMNsCodec() s00.BPLMNsValueCodec {
	return func() s00.BPLMNsValueCodec {
		sealed := s00.BPLMNsValueCodec{}
		*s00.BridgeBPLMNsValueCodecFieldPath(&sealed) = "BPLMNs"
		*s00.BridgeBPLMNsValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.BPLMNs, error) {
			var complete BPLMNsComplete
			if err := complete.unmarshalAPERWithOptions(data, options); err != nil {
				var zero s00.BPLMNs
				return zero, err
			}
			return complete.Value, nil
		}
		*s00.BridgeBPLMNsValueCodecFieldEncode(&sealed) = func(value s00.BPLMNs, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			complete := BPLMNsComplete{Value: value}
			return complete.marshalAPERBudget(budget, fresh)
		}
		*s00.BridgeBPLMNsValueCodecFieldCapture(&sealed) = func(v s00.BPLMNs, options aper.DecodeState) (s00.BPLMNs, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.
				Begin()
			s00.BridgeCaptureS1APBPLMNs(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s00.BridgeBPLMNsValueCodecFieldCompare(&sealed) = func(v s00.BPLMNs, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s07.BridgeCompareS1APBPLMNs(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s00.BridgeBPLMNsValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:BPLMNs"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// BearersSubjectToDLDiscardingListCodec binds the complete APER value type.
func BearersSubjectToDLDiscardingListCodec() s15.BearersSubjectToDLDiscardingListValueCodec {
	return ENBEarlyStatusTransferTransparentContainerExtIEs().BearersSubjectToDLDiscardingList().Codec()
}

// ENBEarlyStatusTransferTransparentContainerCodec binds the complete APER value type.
func ENBEarlyStatusTransferTransparentContainerCodec() ENBEarlyStatusTransferTransparentContainerValueCodec {
	return ENBEarlyStatusTransferIEs().ENBEarlyStatusTransferTransparentContainer().Codec()
}

// STMSICodec binds the complete APER value type.
func STMSICodec() s28.STMSIValueCodec { return ENBCPRelocationIndicationIEs().STMSI().Codec() }

// TAICodec binds the complete APER value type.
func TAICodec() s32.TAIValueCodec { return ENBCPRelocationIndicationIEs().TAI().Codec() }

// UES1APIDPairCodec binds the complete source value type.
func UES1APIDPairCodec() UES1APIDPairValueCodec {
	return UES1APIDPairValueCodec{path: "UES1APIDPair", decode: func(data []byte, options aper.DecodeState) (UES1APIDPair, error) {
		var value UES1APIDPair
		if err := value.unmarshalAPERWithOptions(data, options); err != nil {
			return UES1APIDPair{}, err
		}
		value.received = true
		value.receivedAbsolute = true
		value.receivedBytes = aper.OriginalWire(data)
		return value, nil
	}, encode: func(value UES1APIDPair, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return (&value).marshalAPERBudget(budget, fresh)
	}, capture: func(v UES1APIDPair, options aper.DecodeState) (UES1APIDPair, aper.Snapshot) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeCaptureS1APUES1APIDPair(&v, &s)
		var root aper.Snapshot
		s.End(f, &root, false)
		return v, root
	}, compare: func(v UES1APIDPair, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		BridgeCompareS1APUES1APIDPair(&v, &s)
		s.End(f, root, false)
		return s.Plan(),
			s.
				BudgetValue()
	}, context: func() s00.BridgeCodecContext {
		sealed := s00.BridgeCodecContext{}
		*s00.BridgecodecContextFieldSource(&sealed) = "source-value:UES1APIDPair"
		*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
		return sealed
	}(),
	}
}

// UES1APIDsCodec binds the complete APER value type.
func UES1APIDsCodec() UES1APIDsValueCodec { return UEContextReleaseCommandIEs().UES1APIDs().Codec() }

// ULCPSecurityInformationCodec binds the complete APER value type.
func ULCPSecurityInformationCodec() ULCPSecurityInformationValueCodec {
	return ENBCPRelocationIndicationIEs().ULCPSecurityInformation().Codec()
}
func BridgeActivatedCellsListCompleteFieldPerPadding(v *ActivatedCellsListComplete) *aper.CompletePadding {
	return &v.perPadding
}
func BridgeActivatedCellsListCompleteFieldReceived(v *ActivatedCellsListComplete) *bool {
	return &v.received
}
func BridgeActivatedCellsListCompleteFieldReceivedAbsolute(v *ActivatedCellsListComplete) *bool {
	return &v.receivedAbsolute
}
func BridgeActivatedCellsListCompleteFieldReceivedBytes(v *ActivatedCellsListComplete) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeActivatedCellsListCompleteFieldReceivedLocation(v *ActivatedCellsListComplete) *aper.Location {
	return &v.receivedLocation
}
func BridgeActivatedCellsListCompleteFieldReplay(v *ActivatedCellsListComplete) *aper.Snapshot {
	return &v.replay
}
func BridgeActivatedCellsListCompleteFieldStream(v *ActivatedCellsListComplete) *aper.WireSpan {
	return &v.stream
}
func BridgeActivatedCellsListCompleteFieldWithoutReplay(v *ActivatedCellsListComplete) *bool {
	return &v.withoutReplay
}
func BridgeActivatedCellsListCompleteMethodMarshalAPERBudget(v *ActivatedCellsListComplete, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeActivatedCellsListCompleteMethodMarshalAPERBudgetValue(v *ActivatedCellsListComplete, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudgetValue(a0, a1)
}
func BridgeActivatedCellsListCompleteMethodMarshalAPERChanged(v *ActivatedCellsListComplete, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeActivatedCellsListCompleteMethodMarshalAPERChangedValue(v *ActivatedCellsListComplete, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeActivatedCellsListCompleteMethodMarshalAPERLegacy(v *ActivatedCellsListComplete) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeActivatedCellsListCompleteMethodMarshalAPERNewValue(v *ActivatedCellsListComplete, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERNewValue(a0, a1)
}
func BridgeActivatedCellsListCompleteMethodMarshalAPERPlanned(v *ActivatedCellsListComplete, a0 *aper.DecodeBudget, a1 bool, a2 *aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1, a2)
}
func BridgeActivatedCellsListCompleteMethodUnmarshalAPERLegacy(v *ActivatedCellsListComplete, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeActivatedCellsListCompleteMethodUnmarshalAPERWithOptions(v *ActivatedCellsListComplete, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeBPLMNsCompleteFieldPerPadding(v *BPLMNsComplete) *aper.CompletePadding {
	return &v.perPadding
}
func BridgeBPLMNsCompleteFieldReceived(v *BPLMNsComplete) *bool         { return &v.received }
func BridgeBPLMNsCompleteFieldReceivedAbsolute(v *BPLMNsComplete) *bool { return &v.receivedAbsolute }
func BridgeBPLMNsCompleteFieldReceivedBytes(v *BPLMNsComplete) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeBPLMNsCompleteFieldReceivedLocation(v *BPLMNsComplete) *aper.Location {
	return &v.receivedLocation
}
func BridgeBPLMNsCompleteFieldReplay(v *BPLMNsComplete) *aper.Snapshot { return &v.replay }
func BridgeBPLMNsCompleteFieldStream(v *BPLMNsComplete) *aper.WireSpan { return &v.stream }
func BridgeBPLMNsCompleteFieldWithoutReplay(v *BPLMNsComplete) *bool   { return &v.withoutReplay }
func BridgeBPLMNsCompleteMethodMarshalAPERBudget(v *BPLMNsComplete, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeBPLMNsCompleteMethodMarshalAPERBudgetValue(v *BPLMNsComplete, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudgetValue(a0, a1)
}
func BridgeBPLMNsCompleteMethodMarshalAPERChanged(v *BPLMNsComplete, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeBPLMNsCompleteMethodMarshalAPERChangedValue(v *BPLMNsComplete, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeBPLMNsCompleteMethodMarshalAPERLegacy(v *BPLMNsComplete) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeBPLMNsCompleteMethodMarshalAPERNewValue(v *BPLMNsComplete, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERNewValue(a0, a1)
}
func BridgeBPLMNsCompleteMethodMarshalAPERPlanned(v *BPLMNsComplete, a0 *aper.DecodeBudget, a1 bool, a2 *aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1, a2)
}
func BridgeBPLMNsCompleteMethodUnmarshalAPERLegacy(v *BPLMNsComplete, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeBPLMNsCompleteMethodUnmarshalAPERWithOptions(v *BPLMNsComplete, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeBearersSubjectToDLDiscardingListCompleteFieldPerPadding(v *BearersSubjectToDLDiscardingListComplete) *aper.CompletePadding {
	return &v.perPadding
}
func BridgeBearersSubjectToDLDiscardingListCompleteFieldReceived(v *BearersSubjectToDLDiscardingListComplete) *bool {
	return &v.received
}
func BridgeBearersSubjectToDLDiscardingListCompleteFieldReceivedAbsolute(v *BearersSubjectToDLDiscardingListComplete) *bool {
	return &v.receivedAbsolute
}
func BridgeBearersSubjectToDLDiscardingListCompleteFieldReceivedBytes(v *BearersSubjectToDLDiscardingListComplete) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeBearersSubjectToDLDiscardingListCompleteFieldReceivedLocation(v *BearersSubjectToDLDiscardingListComplete) *aper.Location {
	return &v.receivedLocation
}
func BridgeBearersSubjectToDLDiscardingListCompleteFieldReplay(v *BearersSubjectToDLDiscardingListComplete) *aper.Snapshot {
	return &v.replay
}
func BridgeBearersSubjectToDLDiscardingListCompleteFieldStream(v *BearersSubjectToDLDiscardingListComplete) *aper.WireSpan {
	return &v.stream
}
func BridgeBearersSubjectToDLDiscardingListCompleteFieldWithoutReplay(v *BearersSubjectToDLDiscardingListComplete) *bool {
	return &v.withoutReplay
}
func BridgeBearersSubjectToDLDiscardingListCompleteMethodMarshalAPERBudget(v *BearersSubjectToDLDiscardingListComplete, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeBearersSubjectToDLDiscardingListCompleteMethodMarshalAPERBudgetValue(v *BearersSubjectToDLDiscardingListComplete, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudgetValue(a0, a1)
}
func BridgeBearersSubjectToDLDiscardingListCompleteMethodMarshalAPERChanged(v *BearersSubjectToDLDiscardingListComplete, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeBearersSubjectToDLDiscardingListCompleteMethodMarshalAPERChangedValue(v *BearersSubjectToDLDiscardingListComplete, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeBearersSubjectToDLDiscardingListCompleteMethodMarshalAPERLegacy(v *BearersSubjectToDLDiscardingListComplete) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeBearersSubjectToDLDiscardingListCompleteMethodMarshalAPERNewValue(v *BearersSubjectToDLDiscardingListComplete, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERNewValue(a0, a1)
}
func BridgeBearersSubjectToDLDiscardingListCompleteMethodMarshalAPERPlanned(v *BearersSubjectToDLDiscardingListComplete, a0 *aper.DecodeBudget, a1 bool, a2 *aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1, a2)
}
func BridgeBearersSubjectToDLDiscardingListCompleteMethodUnmarshalAPERLegacy(v *BearersSubjectToDLDiscardingListComplete, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeBearersSubjectToDLDiscardingListCompleteMethodUnmarshalAPERWithOptions(v *BearersSubjectToDLDiscardingListComplete, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeENBCPRelocationIndicationAPERValueFieldContext(v *ENBCPRelocationIndicationAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeENBCPRelocationIndicationAPERValueFieldReceived(v *ENBCPRelocationIndicationAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeENBCPRelocationIndicationAPERValueFieldReplay(v *ENBCPRelocationIndicationAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeENBCPRelocationIndicationAPERValueFieldWithoutReplay(v *ENBCPRelocationIndicationAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeENBCPRelocationIndicationENBUES1APIDIEBindingFieldCodec(v *ENBCPRelocationIndicationENBUES1APIDIEBinding) *s00.ENBUES1APIDValueCodec {
	return &v.codec
}
func BridgeENBCPRelocationIndicationENBUES1APIDIEBindingFieldGet(v *ENBCPRelocationIndicationENBUES1APIDIEBinding) *func(*ENBCPRelocationIndicationIEValue) (*s00.ENBUES1APID, bool) {
	return &v.get
}
func BridgeENBCPRelocationIndicationENBUES1APIDIEBindingFieldInfo(v *ENBCPRelocationIndicationENBUES1APIDIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeENBCPRelocationIndicationENBUES1APIDIEBindingFieldInject(v *ENBCPRelocationIndicationENBUES1APIDIEBinding) *func(s00.ENBUES1APID) ENBCPRelocationIndicationIEValue {
	return &v.inject
}
func BridgeENBCPRelocationIndicationEUTRANCGIIEBindingFieldCodec(v *ENBCPRelocationIndicationEUTRANCGIIEBinding) *s17.EUTRANCGIValueCodec {
	return &v.codec
}
func BridgeENBCPRelocationIndicationEUTRANCGIIEBindingFieldGet(v *ENBCPRelocationIndicationEUTRANCGIIEBinding) *func(*ENBCPRelocationIndicationIEValue) (*s17.EUTRANCGI, bool) {
	return &v.get
}
func BridgeENBCPRelocationIndicationEUTRANCGIIEBindingFieldInfo(v *ENBCPRelocationIndicationEUTRANCGIIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeENBCPRelocationIndicationEUTRANCGIIEBindingFieldInject(v *ENBCPRelocationIndicationEUTRANCGIIEBinding) *func(s17.EUTRANCGI) ENBCPRelocationIndicationIEValue {
	return &v.inject
}
func BridgeENBCPRelocationIndicationFieldExtCount(v *ENBCPRelocationIndication) *int64 {
	return &v.extCount
}
func BridgeENBCPRelocationIndicationFieldExtData(v *ENBCPRelocationIndication) *[][]byte {
	return &v.extData
}
func BridgeENBCPRelocationIndicationFieldExtOrigin(v *ENBCPRelocationIndication) *[]aper.OpaqueOrigin {
	return &v.extOrigin
}
func BridgeENBCPRelocationIndicationFieldExtPresent(v *ENBCPRelocationIndication) *[]bool {
	return &v.extPresent
}
func BridgeENBCPRelocationIndicationFieldExtWire(v *ENBCPRelocationIndication) *[]aper.WireSpan {
	return &v.extWire
}
func BridgeENBCPRelocationIndicationFieldPerExtPadding(v *ENBCPRelocationIndication) *[]aper.CompletePadding {
	return &v.perExtPadding
}
func BridgeENBCPRelocationIndicationFieldPerPadding(v *ENBCPRelocationIndication) *aper.FinalPadding {
	return &v.perPadding
}
func BridgeENBCPRelocationIndicationFieldProtocolIEsIndef(v *ENBCPRelocationIndication) *bool {
	return &v.protocolIEsIndef
}
func BridgeENBCPRelocationIndicationFieldReceived(v *ENBCPRelocationIndication) *bool {
	return &v.received
}
func BridgeENBCPRelocationIndicationFieldReceivedAbsolute(v *ENBCPRelocationIndication) *bool {
	return &v.receivedAbsolute
}
func BridgeENBCPRelocationIndicationFieldReceivedBytes(v *ENBCPRelocationIndication) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeENBCPRelocationIndicationFieldReceivedLocation(v *ENBCPRelocationIndication) *aper.Location {
	return &v.receivedLocation
}
func BridgeENBCPRelocationIndicationFieldReplay(v *ENBCPRelocationIndication) *aper.Snapshot {
	return &v.replay
}
func BridgeENBCPRelocationIndicationFieldStream(v *ENBCPRelocationIndication) *aper.WireSpan {
	return &v.stream
}
func BridgeENBCPRelocationIndicationFieldWithoutReplay(v *ENBCPRelocationIndication) *bool {
	return &v.withoutReplay
}
func BridgeENBCPRelocationIndicationIEContainerAPERValueFieldContext(v *ENBCPRelocationIndicationIEContainerAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeENBCPRelocationIndicationIEContainerAPERValueFieldReceived(v *ENBCPRelocationIndicationIEContainerAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeENBCPRelocationIndicationIEContainerAPERValueFieldReplay(v *ENBCPRelocationIndicationIEContainerAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeENBCPRelocationIndicationIEContainerAPERValueFieldWithoutReplay(v *ENBCPRelocationIndicationIEContainerAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeENBCPRelocationIndicationIEContainerValueCodecFieldCapture(v *ENBCPRelocationIndicationIEContainerValueCodec) *func(ENBCPRelocationIndicationIEContainer, aper.DecodeState) (ENBCPRelocationIndicationIEContainer, aper.Snapshot) {
	return &v.capture
}
func BridgeENBCPRelocationIndicationIEContainerValueCodecFieldCompare(v *ENBCPRelocationIndicationIEContainerValueCodec) *func(ENBCPRelocationIndicationIEContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeENBCPRelocationIndicationIEContainerValueCodecFieldContext(v *ENBCPRelocationIndicationIEContainerValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeENBCPRelocationIndicationIEContainerValueCodecFieldDecode(v *ENBCPRelocationIndicationIEContainerValueCodec) *func([]byte, aper.DecodeState) (ENBCPRelocationIndicationIEContainer, error) {
	return &v.decode
}
func BridgeENBCPRelocationIndicationIEContainerValueCodecFieldEncode(v *ENBCPRelocationIndicationIEContainerValueCodec) *func(ENBCPRelocationIndicationIEContainer, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeENBCPRelocationIndicationIEContainerValueCodecFieldPath(v *ENBCPRelocationIndicationIEContainerValueCodec) *aper.Path {
	return &v.path
}
func BridgeENBCPRelocationIndicationIEContainerValueCodecMethodEncodeBudgetValue(v ENBCPRelocationIndicationIEContainerValueCodec, a0 ENBCPRelocationIndicationIEContainer, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeENBCPRelocationIndicationIEContainerValueCodecMethodEncodeChanged(v ENBCPRelocationIndicationIEContainerValueCodec, a0 ENBCPRelocationIndicationIEContainer, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeENBCPRelocationIndicationIEFieldAPERValueFieldContext(v *ENBCPRelocationIndicationIEFieldAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeENBCPRelocationIndicationIEFieldAPERValueFieldReceived(v *ENBCPRelocationIndicationIEFieldAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeENBCPRelocationIndicationIEFieldAPERValueFieldReplay(v *ENBCPRelocationIndicationIEFieldAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeENBCPRelocationIndicationIEFieldAPERValueFieldWithoutReplay(v *ENBCPRelocationIndicationIEFieldAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeENBCPRelocationIndicationIEFieldFieldReceived(v *ENBCPRelocationIndicationIEField) *aper.CompletePadding {
	return &v.received
}
func BridgeENBCPRelocationIndicationIEFieldFieldReplay(v *ENBCPRelocationIndicationIEField) *aper.Snapshot {
	return &v.replay
}
func BridgeENBCPRelocationIndicationIEFieldFieldStream(v *ENBCPRelocationIndicationIEField) *aper.WireSpan {
	return &v.stream
}
func BridgeENBCPRelocationIndicationIEFieldFieldWithoutReplay(v *ENBCPRelocationIndicationIEField) *bool {
	return &v.withoutReplay
}
func BridgeENBCPRelocationIndicationIEFieldMethodMarshalAPERTo(v *ENBCPRelocationIndicationIEField, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeENBCPRelocationIndicationIEFieldMethodUnmarshalAPERFrom(v *ENBCPRelocationIndicationIEField, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeENBCPRelocationIndicationIEFieldValueCodecFieldCapture(v *ENBCPRelocationIndicationIEFieldValueCodec) *func(ENBCPRelocationIndicationIEField, aper.DecodeState) (ENBCPRelocationIndicationIEField, aper.Snapshot) {
	return &v.capture
}
func BridgeENBCPRelocationIndicationIEFieldValueCodecFieldCompare(v *ENBCPRelocationIndicationIEFieldValueCodec) *func(ENBCPRelocationIndicationIEField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeENBCPRelocationIndicationIEFieldValueCodecFieldContext(v *ENBCPRelocationIndicationIEFieldValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeENBCPRelocationIndicationIEFieldValueCodecFieldDecode(v *ENBCPRelocationIndicationIEFieldValueCodec) *func([]byte, aper.DecodeState) (ENBCPRelocationIndicationIEField, error) {
	return &v.decode
}
func BridgeENBCPRelocationIndicationIEFieldValueCodecFieldEncode(v *ENBCPRelocationIndicationIEFieldValueCodec) *func(ENBCPRelocationIndicationIEField, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeENBCPRelocationIndicationIEFieldValueCodecFieldPath(v *ENBCPRelocationIndicationIEFieldValueCodec) *aper.Path {
	return &v.path
}
func BridgeENBCPRelocationIndicationIEFieldValueCodecMethodEncodeBudgetValue(v ENBCPRelocationIndicationIEFieldValueCodec, a0 ENBCPRelocationIndicationIEField, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeENBCPRelocationIndicationIEFieldValueCodecMethodEncodeChanged(v ENBCPRelocationIndicationIEFieldValueCodec, a0 ENBCPRelocationIndicationIEField, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeENBCPRelocationIndicationIETableMethodInfoENBUES1APID(v ENBCPRelocationIndicationIETable) s00.FieldInfo {
	return v.infoENBUES1APID()
}
func BridgeENBCPRelocationIndicationIETableMethodInfoEUTRANCGI(v ENBCPRelocationIndicationIETable) s00.FieldInfo {
	return v.infoEUTRANCGI()
}
func BridgeENBCPRelocationIndicationIETableMethodInfoLTENTNTAIInformation(v ENBCPRelocationIndicationIETable) s00.FieldInfo {
	return v.infoLTENTNTAIInformation()
}
func BridgeENBCPRelocationIndicationIETableMethodInfoSTMSI(v ENBCPRelocationIndicationIETable) s00.FieldInfo {
	return v.infoSTMSI()
}
func BridgeENBCPRelocationIndicationIETableMethodInfoTAI(v ENBCPRelocationIndicationIETable) s00.FieldInfo {
	return v.infoTAI()
}
func BridgeENBCPRelocationIndicationIETableMethodInfoULCPSecurityInformation(v ENBCPRelocationIndicationIETable) s00.FieldInfo {
	return v.infoULCPSecurityInformation()
}
func BridgeENBCPRelocationIndicationIEValueERABIEContainerListAPERValueFieldContext(v *ENBCPRelocationIndicationIEValueERABIEContainerListAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeENBCPRelocationIndicationIEValueERABIEContainerListAPERValueFieldReceived(v *ENBCPRelocationIndicationIEValueERABIEContainerListAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeENBCPRelocationIndicationIEValueERABIEContainerListAPERValueFieldReplay(v *ENBCPRelocationIndicationIEValueERABIEContainerListAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeENBCPRelocationIndicationIEValueERABIEContainerListAPERValueFieldWithoutReplay(v *ENBCPRelocationIndicationIEValueERABIEContainerListAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeENBCPRelocationIndicationIEValueERABIEContainerListValueCodecFieldCapture(v *ENBCPRelocationIndicationIEValueERABIEContainerListValueCodec) *func(ENBCPRelocationIndicationIEValueERABIEContainerList, aper.DecodeState) (ENBCPRelocationIndicationIEValueERABIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgeENBCPRelocationIndicationIEValueERABIEContainerListValueCodecFieldCompare(v *ENBCPRelocationIndicationIEValueERABIEContainerListValueCodec) *func(ENBCPRelocationIndicationIEValueERABIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeENBCPRelocationIndicationIEValueERABIEContainerListValueCodecFieldContext(v *ENBCPRelocationIndicationIEValueERABIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeENBCPRelocationIndicationIEValueERABIEContainerListValueCodecFieldDecode(v *ENBCPRelocationIndicationIEValueERABIEContainerListValueCodec) *func([]byte, aper.DecodeState) (ENBCPRelocationIndicationIEValueERABIEContainerList, error) {
	return &v.decode
}
func BridgeENBCPRelocationIndicationIEValueERABIEContainerListValueCodecFieldEncode(v *ENBCPRelocationIndicationIEValueERABIEContainerListValueCodec) *func(ENBCPRelocationIndicationIEValueERABIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeENBCPRelocationIndicationIEValueERABIEContainerListValueCodecFieldPath(v *ENBCPRelocationIndicationIEValueERABIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgeENBCPRelocationIndicationIEValueERABIEContainerListValueCodecMethodEncodeBudgetValue(v ENBCPRelocationIndicationIEValueERABIEContainerListValueCodec, a0 ENBCPRelocationIndicationIEValueERABIEContainerList, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeENBCPRelocationIndicationIEValueERABIEContainerListValueCodecMethodEncodeChanged(v ENBCPRelocationIndicationIEValueERABIEContainerListValueCodec, a0 ENBCPRelocationIndicationIEValueERABIEContainerList, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeENBCPRelocationIndicationIEValueFieldId(v *ENBCPRelocationIndicationIEValue) *s00.ProtocolIEID {
	return &v.id
}
func BridgeENBCPRelocationIndicationIEValueFieldIsOpaque(v *ENBCPRelocationIndicationIEValue) *bool {
	return &v.isOpaque
}
func BridgeENBCPRelocationIndicationIEValueFieldOpaque(v *ENBCPRelocationIndicationIEValue) *aper.OpaqueOpenType {
	return &v.opaque
}
func BridgeENBCPRelocationIndicationIEValueFieldReceived(v *ENBCPRelocationIndicationIEValue) *aper.WireSpan {
	return &v.received
}
func BridgeENBCPRelocationIndicationIEValueFieldReplay(v *ENBCPRelocationIndicationIEValue) *aper.Snapshot {
	return &v.replay
}
func BridgeENBCPRelocationIndicationIEValueFieldRowENBUES1APID(v *ENBCPRelocationIndicationIEValue) **s00.ENBUES1APID {
	return &v.rowENBUES1APID
}
func BridgeENBCPRelocationIndicationIEValueFieldRowEUTRANCGI(v *ENBCPRelocationIndicationIEValue) **s17.EUTRANCGI {
	return &v.rowEUTRANCGI
}
func BridgeENBCPRelocationIndicationIEValueFieldRowLTENTNTAIInformation(v *ENBCPRelocationIndicationIEValue) **s18.LTENTNTAIInformation {
	return &v.rowLTENTNTAIInformation
}
func BridgeENBCPRelocationIndicationIEValueFieldRowSTMSI(v *ENBCPRelocationIndicationIEValue) **s28.STMSI {
	return &v.rowSTMSI
}
func BridgeENBCPRelocationIndicationIEValueFieldRowTAI(v *ENBCPRelocationIndicationIEValue) **s31.TAI {
	return &v.rowTAI
}
func BridgeENBCPRelocationIndicationIEValueFieldRowULCPSecurityInformation(v *ENBCPRelocationIndicationIEValue) **ULCPSecurityInformation {
	return &v.rowULCPSecurityInformation
}
func BridgeENBCPRelocationIndicationIEValueMethodCaptureSemantics(v ENBCPRelocationIndicationIEValue, a0 aper.SemanticCapture) ENBCPRelocationIndicationIEValue {
	return v.captureSemantics(a0)
}
func BridgeENBCPRelocationIndicationIEValueMethodCompareSemantics(v ENBCPRelocationIndicationIEValue, a0 aper.SemanticComparison) aper.SemanticComparison {
	return v.compareSemantics(a0)
}
func BridgeENBCPRelocationIndicationIEValueMethodDecode(v ENBCPRelocationIndicationIEValue, a0 s00.ProtocolIEID, a1 aper.OpaqueOpenType) (ENBCPRelocationIndicationIEValue, error) {
	return v.decode(a0, a1)
}
func BridgeENBCPRelocationIndicationIEValueMethodEncode(v ENBCPRelocationIndicationIEValue) ([]byte, error) {
	return v.encode()
}
func BridgeENBCPRelocationIndicationIEValueMethodEncodeFresh(v ENBCPRelocationIndicationIEValue, a0 bool, a1 *aper.DecodeBudget) ([]byte, error) {
	return v.encodeFresh(a0, a1)
}
func BridgeENBCPRelocationIndicationIEValueMethodMatchesID(v ENBCPRelocationIndicationIEValue, a0 s00.ProtocolIEID, a1 ...*aper.DecodeBudget) bool {
	return v.matchesID(a0, a1...)
}
func BridgeENBCPRelocationIndicationIEValueMethodReason(v ENBCPRelocationIndicationIEValue, a0 s00.ProtocolIEID) aper.OpaqueReason {
	return v.reason(a0)
}
func BridgeENBCPRelocationIndicationIEValueMethodRule(v ENBCPRelocationIndicationIEValue) aper.SourceRule {
	return v.rule()
}
func BridgeENBCPRelocationIndicationIEValueProtocolErrorIEContainerListAPERValueFieldContext(v *ENBCPRelocationIndicationIEValueProtocolErrorIEContainerListAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeENBCPRelocationIndicationIEValueProtocolErrorIEContainerListAPERValueFieldReceived(v *ENBCPRelocationIndicationIEValueProtocolErrorIEContainerListAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeENBCPRelocationIndicationIEValueProtocolErrorIEContainerListAPERValueFieldReplay(v *ENBCPRelocationIndicationIEValueProtocolErrorIEContainerListAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeENBCPRelocationIndicationIEValueProtocolErrorIEContainerListAPERValueFieldWithoutReplay(v *ENBCPRelocationIndicationIEValueProtocolErrorIEContainerListAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeENBCPRelocationIndicationIEValueProtocolErrorIEContainerListValueCodecFieldCapture(v *ENBCPRelocationIndicationIEValueProtocolErrorIEContainerListValueCodec) *func(ENBCPRelocationIndicationIEValueProtocolErrorIEContainerList, aper.DecodeState) (ENBCPRelocationIndicationIEValueProtocolErrorIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgeENBCPRelocationIndicationIEValueProtocolErrorIEContainerListValueCodecFieldCompare(v *ENBCPRelocationIndicationIEValueProtocolErrorIEContainerListValueCodec) *func(ENBCPRelocationIndicationIEValueProtocolErrorIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeENBCPRelocationIndicationIEValueProtocolErrorIEContainerListValueCodecFieldContext(v *ENBCPRelocationIndicationIEValueProtocolErrorIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeENBCPRelocationIndicationIEValueProtocolErrorIEContainerListValueCodecFieldDecode(v *ENBCPRelocationIndicationIEValueProtocolErrorIEContainerListValueCodec) *func([]byte, aper.DecodeState) (ENBCPRelocationIndicationIEValueProtocolErrorIEContainerList, error) {
	return &v.decode
}
func BridgeENBCPRelocationIndicationIEValueProtocolErrorIEContainerListValueCodecFieldEncode(v *ENBCPRelocationIndicationIEValueProtocolErrorIEContainerListValueCodec) *func(ENBCPRelocationIndicationIEValueProtocolErrorIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeENBCPRelocationIndicationIEValueProtocolErrorIEContainerListValueCodecFieldPath(v *ENBCPRelocationIndicationIEValueProtocolErrorIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgeENBCPRelocationIndicationIEValueProtocolErrorIEContainerListValueCodecMethodEncodeBudgetValue(v ENBCPRelocationIndicationIEValueProtocolErrorIEContainerListValueCodec, a0 ENBCPRelocationIndicationIEValueProtocolErrorIEContainerList, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeENBCPRelocationIndicationIEValueProtocolErrorIEContainerListValueCodecMethodEncodeChanged(v ENBCPRelocationIndicationIEValueProtocolErrorIEContainerListValueCodec, a0 ENBCPRelocationIndicationIEValueProtocolErrorIEContainerList, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeENBCPRelocationIndicationIEValueProtocolIEContainerListAPERValueFieldContext(v *ENBCPRelocationIndicationIEValueProtocolIEContainerListAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeENBCPRelocationIndicationIEValueProtocolIEContainerListAPERValueFieldReceived(v *ENBCPRelocationIndicationIEValueProtocolIEContainerListAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeENBCPRelocationIndicationIEValueProtocolIEContainerListAPERValueFieldReplay(v *ENBCPRelocationIndicationIEValueProtocolIEContainerListAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeENBCPRelocationIndicationIEValueProtocolIEContainerListAPERValueFieldWithoutReplay(v *ENBCPRelocationIndicationIEValueProtocolIEContainerListAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeENBCPRelocationIndicationIEValueProtocolIEContainerListValueCodecFieldCapture(v *ENBCPRelocationIndicationIEValueProtocolIEContainerListValueCodec) *func(ENBCPRelocationIndicationIEValueProtocolIEContainerList, aper.DecodeState) (ENBCPRelocationIndicationIEValueProtocolIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgeENBCPRelocationIndicationIEValueProtocolIEContainerListValueCodecFieldCompare(v *ENBCPRelocationIndicationIEValueProtocolIEContainerListValueCodec) *func(ENBCPRelocationIndicationIEValueProtocolIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeENBCPRelocationIndicationIEValueProtocolIEContainerListValueCodecFieldContext(v *ENBCPRelocationIndicationIEValueProtocolIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeENBCPRelocationIndicationIEValueProtocolIEContainerListValueCodecFieldDecode(v *ENBCPRelocationIndicationIEValueProtocolIEContainerListValueCodec) *func([]byte, aper.DecodeState) (ENBCPRelocationIndicationIEValueProtocolIEContainerList, error) {
	return &v.decode
}
func BridgeENBCPRelocationIndicationIEValueProtocolIEContainerListValueCodecFieldEncode(v *ENBCPRelocationIndicationIEValueProtocolIEContainerListValueCodec) *func(ENBCPRelocationIndicationIEValueProtocolIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeENBCPRelocationIndicationIEValueProtocolIEContainerListValueCodecFieldPath(v *ENBCPRelocationIndicationIEValueProtocolIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgeENBCPRelocationIndicationIEValueProtocolIEContainerListValueCodecMethodEncodeBudgetValue(v ENBCPRelocationIndicationIEValueProtocolIEContainerListValueCodec, a0 ENBCPRelocationIndicationIEValueProtocolIEContainerList, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeENBCPRelocationIndicationIEValueProtocolIEContainerListValueCodecMethodEncodeChanged(v ENBCPRelocationIndicationIEValueProtocolIEContainerListValueCodec, a0 ENBCPRelocationIndicationIEValueProtocolIEContainerList, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeENBCPRelocationIndicationLTENTNTAIInformationIEBindingFieldCodec(v *ENBCPRelocationIndicationLTENTNTAIInformationIEBinding) *s18.LTENTNTAIInformationValueCodec {
	return &v.codec
}
func BridgeENBCPRelocationIndicationLTENTNTAIInformationIEBindingFieldGet(v *ENBCPRelocationIndicationLTENTNTAIInformationIEBinding) *func(*ENBCPRelocationIndicationIEValue) (*s18.LTENTNTAIInformation, bool) {
	return &v.get
}
func BridgeENBCPRelocationIndicationLTENTNTAIInformationIEBindingFieldInfo(v *ENBCPRelocationIndicationLTENTNTAIInformationIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeENBCPRelocationIndicationLTENTNTAIInformationIEBindingFieldInject(v *ENBCPRelocationIndicationLTENTNTAIInformationIEBinding) *func(s18.LTENTNTAIInformation) ENBCPRelocationIndicationIEValue {
	return &v.inject
}
func BridgeENBCPRelocationIndicationMethodMarshalAPERBudget(v *ENBCPRelocationIndication, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeENBCPRelocationIndicationMethodMarshalAPERBudgetValue(v *ENBCPRelocationIndication, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudgetValue(a0, a1)
}
func BridgeENBCPRelocationIndicationMethodMarshalAPERChanged(v *ENBCPRelocationIndication, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeENBCPRelocationIndicationMethodMarshalAPERChangedValue(v *ENBCPRelocationIndication, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeENBCPRelocationIndicationMethodMarshalAPERLegacy(v *ENBCPRelocationIndication) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeENBCPRelocationIndicationMethodMarshalAPERNewValue(v *ENBCPRelocationIndication, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERNewValue(a0, a1)
}
func BridgeENBCPRelocationIndicationMethodMarshalAPERPlanned(v *ENBCPRelocationIndication, a0 *aper.DecodeBudget, a1 bool, a2 *aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1, a2)
}
func BridgeENBCPRelocationIndicationMethodMarshalAPERTo(v *ENBCPRelocationIndication, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeENBCPRelocationIndicationMethodUnmarshalAPERFrom(v *ENBCPRelocationIndication, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeENBCPRelocationIndicationMethodUnmarshalAPERLegacy(v *ENBCPRelocationIndication, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeENBCPRelocationIndicationMethodUnmarshalAPERWithOptions(v *ENBCPRelocationIndication, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeENBCPRelocationIndicationSTMSIIEBindingFieldCodec(v *ENBCPRelocationIndicationSTMSIIEBinding) *s28.STMSIValueCodec {
	return &v.codec
}
func BridgeENBCPRelocationIndicationSTMSIIEBindingFieldGet(v *ENBCPRelocationIndicationSTMSIIEBinding) *func(*ENBCPRelocationIndicationIEValue) (*s28.STMSI, bool) {
	return &v.get
}
func BridgeENBCPRelocationIndicationSTMSIIEBindingFieldInfo(v *ENBCPRelocationIndicationSTMSIIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeENBCPRelocationIndicationSTMSIIEBindingFieldInject(v *ENBCPRelocationIndicationSTMSIIEBinding) *func(s28.STMSI) ENBCPRelocationIndicationIEValue {
	return &v.inject
}
func BridgeENBCPRelocationIndicationTAIIEBindingFieldCodec(v *ENBCPRelocationIndicationTAIIEBinding) *s32.TAIValueCodec {
	return &v.codec
}
func BridgeENBCPRelocationIndicationTAIIEBindingFieldGet(v *ENBCPRelocationIndicationTAIIEBinding) *func(*ENBCPRelocationIndicationIEValue) (*s31.TAI, bool) {
	return &v.get
}
func BridgeENBCPRelocationIndicationTAIIEBindingFieldInfo(v *ENBCPRelocationIndicationTAIIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeENBCPRelocationIndicationTAIIEBindingFieldInject(v *ENBCPRelocationIndicationTAIIEBinding) *func(s31.TAI) ENBCPRelocationIndicationIEValue {
	return &v.inject
}
func BridgeENBCPRelocationIndicationULCPSecurityInformationIEBindingFieldCodec(v *ENBCPRelocationIndicationULCPSecurityInformationIEBinding) *ULCPSecurityInformationValueCodec {
	return &v.codec
}
func BridgeENBCPRelocationIndicationULCPSecurityInformationIEBindingFieldGet(v *ENBCPRelocationIndicationULCPSecurityInformationIEBinding) *func(*ENBCPRelocationIndicationIEValue) (*ULCPSecurityInformation, bool) {
	return &v.get
}
func BridgeENBCPRelocationIndicationULCPSecurityInformationIEBindingFieldInfo(v *ENBCPRelocationIndicationULCPSecurityInformationIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeENBCPRelocationIndicationULCPSecurityInformationIEBindingFieldInject(v *ENBCPRelocationIndicationULCPSecurityInformationIEBinding) *func(ULCPSecurityInformation) ENBCPRelocationIndicationIEValue {
	return &v.inject
}
func BridgeENBCPRelocationIndicationValueCodecFieldCapture(v *ENBCPRelocationIndicationValueCodec) *func(ENBCPRelocationIndication, aper.DecodeState) (ENBCPRelocationIndication, aper.Snapshot) {
	return &v.capture
}
func BridgeENBCPRelocationIndicationValueCodecFieldCompare(v *ENBCPRelocationIndicationValueCodec) *func(ENBCPRelocationIndication, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeENBCPRelocationIndicationValueCodecFieldContext(v *ENBCPRelocationIndicationValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeENBCPRelocationIndicationValueCodecFieldDecode(v *ENBCPRelocationIndicationValueCodec) *func([]byte, aper.DecodeState) (ENBCPRelocationIndication, error) {
	return &v.decode
}
func BridgeENBCPRelocationIndicationValueCodecFieldEncode(v *ENBCPRelocationIndicationValueCodec) *func(ENBCPRelocationIndication, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeENBCPRelocationIndicationValueCodecFieldPath(v *ENBCPRelocationIndicationValueCodec) *aper.Path {
	return &v.path
}
func BridgeENBCPRelocationIndicationValueCodecMethodEncodeBudgetValue(v ENBCPRelocationIndicationValueCodec, a0 ENBCPRelocationIndication, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeENBCPRelocationIndicationValueCodecMethodEncodeChanged(v ENBCPRelocationIndicationValueCodec, a0 ENBCPRelocationIndication, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeENBEarlyStatusTransferENBEarlyStatusTransferTransparentContainerIEBindingFieldCodec(v *ENBEarlyStatusTransferENBEarlyStatusTransferTransparentContainerIEBinding) *ENBEarlyStatusTransferTransparentContainerValueCodec {
	return &v.codec
}
func BridgeENBEarlyStatusTransferENBEarlyStatusTransferTransparentContainerIEBindingFieldGet(v *ENBEarlyStatusTransferENBEarlyStatusTransferTransparentContainerIEBinding) *func(*ENBEarlyStatusTransferIEValue) (*ENBEarlyStatusTransferTransparentContainer, bool) {
	return &v.get
}
func BridgeENBEarlyStatusTransferENBEarlyStatusTransferTransparentContainerIEBindingFieldInfo(v *ENBEarlyStatusTransferENBEarlyStatusTransferTransparentContainerIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeENBEarlyStatusTransferENBEarlyStatusTransferTransparentContainerIEBindingFieldInject(v *ENBEarlyStatusTransferENBEarlyStatusTransferTransparentContainerIEBinding) *func(ENBEarlyStatusTransferTransparentContainer) ENBEarlyStatusTransferIEValue {
	return &v.inject
}
func BridgeENBEarlyStatusTransferENBUES1APIDIEBindingFieldCodec(v *ENBEarlyStatusTransferENBUES1APIDIEBinding) *s00.ENBUES1APIDValueCodec {
	return &v.codec
}
func BridgeENBEarlyStatusTransferENBUES1APIDIEBindingFieldGet(v *ENBEarlyStatusTransferENBUES1APIDIEBinding) *func(*ENBEarlyStatusTransferIEValue) (*s00.ENBUES1APID, bool) {
	return &v.get
}
func BridgeENBEarlyStatusTransferENBUES1APIDIEBindingFieldInfo(v *ENBEarlyStatusTransferENBUES1APIDIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeENBEarlyStatusTransferENBUES1APIDIEBindingFieldInject(v *ENBEarlyStatusTransferENBUES1APIDIEBinding) *func(s00.ENBUES1APID) ENBEarlyStatusTransferIEValue {
	return &v.inject
}
func BridgeENBEarlyStatusTransferIEContainerAPERValueFieldContext(v *ENBEarlyStatusTransferIEContainerAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeENBEarlyStatusTransferIEContainerAPERValueFieldReceived(v *ENBEarlyStatusTransferIEContainerAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeENBEarlyStatusTransferIEContainerAPERValueFieldReplay(v *ENBEarlyStatusTransferIEContainerAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeENBEarlyStatusTransferIEContainerAPERValueFieldWithoutReplay(v *ENBEarlyStatusTransferIEContainerAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeENBEarlyStatusTransferIEContainerValueCodecFieldCapture(v *ENBEarlyStatusTransferIEContainerValueCodec) *func(ENBEarlyStatusTransferIEContainer, aper.DecodeState) (ENBEarlyStatusTransferIEContainer, aper.Snapshot) {
	return &v.capture
}
func BridgeENBEarlyStatusTransferIEContainerValueCodecFieldCompare(v *ENBEarlyStatusTransferIEContainerValueCodec) *func(ENBEarlyStatusTransferIEContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeENBEarlyStatusTransferIEContainerValueCodecFieldContext(v *ENBEarlyStatusTransferIEContainerValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeENBEarlyStatusTransferIEContainerValueCodecFieldDecode(v *ENBEarlyStatusTransferIEContainerValueCodec) *func([]byte, aper.DecodeState) (ENBEarlyStatusTransferIEContainer, error) {
	return &v.decode
}
func BridgeENBEarlyStatusTransferIEContainerValueCodecFieldEncode(v *ENBEarlyStatusTransferIEContainerValueCodec) *func(ENBEarlyStatusTransferIEContainer, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeENBEarlyStatusTransferIEContainerValueCodecFieldPath(v *ENBEarlyStatusTransferIEContainerValueCodec) *aper.Path {
	return &v.path
}
func BridgeENBEarlyStatusTransferIEContainerValueCodecMethodEncodeBudgetValue(v ENBEarlyStatusTransferIEContainerValueCodec, a0 ENBEarlyStatusTransferIEContainer, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeENBEarlyStatusTransferIEContainerValueCodecMethodEncodeChanged(v ENBEarlyStatusTransferIEContainerValueCodec, a0 ENBEarlyStatusTransferIEContainer, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeENBEarlyStatusTransferIEFieldAPERValueFieldContext(v *ENBEarlyStatusTransferIEFieldAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeENBEarlyStatusTransferIEFieldAPERValueFieldReceived(v *ENBEarlyStatusTransferIEFieldAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeENBEarlyStatusTransferIEFieldAPERValueFieldReplay(v *ENBEarlyStatusTransferIEFieldAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeENBEarlyStatusTransferIEFieldAPERValueFieldWithoutReplay(v *ENBEarlyStatusTransferIEFieldAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeENBEarlyStatusTransferIEFieldFieldReceived(v *ENBEarlyStatusTransferIEField) *aper.CompletePadding {
	return &v.received
}
func BridgeENBEarlyStatusTransferIEFieldFieldReplay(v *ENBEarlyStatusTransferIEField) *aper.Snapshot {
	return &v.replay
}
func BridgeENBEarlyStatusTransferIEFieldFieldStream(v *ENBEarlyStatusTransferIEField) *aper.WireSpan {
	return &v.stream
}
func BridgeENBEarlyStatusTransferIEFieldFieldWithoutReplay(v *ENBEarlyStatusTransferIEField) *bool {
	return &v.withoutReplay
}
func BridgeENBEarlyStatusTransferIEFieldMethodMarshalAPERTo(v *ENBEarlyStatusTransferIEField, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeENBEarlyStatusTransferIEFieldMethodUnmarshalAPERFrom(v *ENBEarlyStatusTransferIEField, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeENBEarlyStatusTransferIEFieldValueCodecFieldCapture(v *ENBEarlyStatusTransferIEFieldValueCodec) *func(ENBEarlyStatusTransferIEField, aper.DecodeState) (ENBEarlyStatusTransferIEField, aper.Snapshot) {
	return &v.capture
}
func BridgeENBEarlyStatusTransferIEFieldValueCodecFieldCompare(v *ENBEarlyStatusTransferIEFieldValueCodec) *func(ENBEarlyStatusTransferIEField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeENBEarlyStatusTransferIEFieldValueCodecFieldContext(v *ENBEarlyStatusTransferIEFieldValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeENBEarlyStatusTransferIEFieldValueCodecFieldDecode(v *ENBEarlyStatusTransferIEFieldValueCodec) *func([]byte, aper.DecodeState) (ENBEarlyStatusTransferIEField, error) {
	return &v.decode
}
func BridgeENBEarlyStatusTransferIEFieldValueCodecFieldEncode(v *ENBEarlyStatusTransferIEFieldValueCodec) *func(ENBEarlyStatusTransferIEField, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeENBEarlyStatusTransferIEFieldValueCodecFieldPath(v *ENBEarlyStatusTransferIEFieldValueCodec) *aper.Path {
	return &v.path
}
func BridgeENBEarlyStatusTransferIEFieldValueCodecMethodEncodeBudgetValue(v ENBEarlyStatusTransferIEFieldValueCodec, a0 ENBEarlyStatusTransferIEField, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeENBEarlyStatusTransferIEFieldValueCodecMethodEncodeChanged(v ENBEarlyStatusTransferIEFieldValueCodec, a0 ENBEarlyStatusTransferIEField, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeENBEarlyStatusTransferIETableMethodInfoENBEarlyStatusTransferTransparentContainer(v ENBEarlyStatusTransferIETable) s00.FieldInfo {
	return v.infoENBEarlyStatusTransferTransparentContainer()
}
func BridgeENBEarlyStatusTransferIETableMethodInfoENBUES1APID(v ENBEarlyStatusTransferIETable) s00.FieldInfo {
	return v.infoENBUES1APID()
}
func BridgeENBEarlyStatusTransferIETableMethodInfoMMEUES1APID(v ENBEarlyStatusTransferIETable) s00.FieldInfo {
	return v.infoMMEUES1APID()
}
func BridgeENBEarlyStatusTransferIEValueERABIEContainerListAPERValueFieldContext(v *ENBEarlyStatusTransferIEValueERABIEContainerListAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeENBEarlyStatusTransferIEValueERABIEContainerListAPERValueFieldReceived(v *ENBEarlyStatusTransferIEValueERABIEContainerListAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeENBEarlyStatusTransferIEValueERABIEContainerListAPERValueFieldReplay(v *ENBEarlyStatusTransferIEValueERABIEContainerListAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeENBEarlyStatusTransferIEValueERABIEContainerListAPERValueFieldWithoutReplay(v *ENBEarlyStatusTransferIEValueERABIEContainerListAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeENBEarlyStatusTransferIEValueERABIEContainerListValueCodecFieldCapture(v *ENBEarlyStatusTransferIEValueERABIEContainerListValueCodec) *func(ENBEarlyStatusTransferIEValueERABIEContainerList, aper.DecodeState) (ENBEarlyStatusTransferIEValueERABIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgeENBEarlyStatusTransferIEValueERABIEContainerListValueCodecFieldCompare(v *ENBEarlyStatusTransferIEValueERABIEContainerListValueCodec) *func(ENBEarlyStatusTransferIEValueERABIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeENBEarlyStatusTransferIEValueERABIEContainerListValueCodecFieldContext(v *ENBEarlyStatusTransferIEValueERABIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeENBEarlyStatusTransferIEValueERABIEContainerListValueCodecFieldDecode(v *ENBEarlyStatusTransferIEValueERABIEContainerListValueCodec) *func([]byte, aper.DecodeState) (ENBEarlyStatusTransferIEValueERABIEContainerList, error) {
	return &v.decode
}
func BridgeENBEarlyStatusTransferIEValueERABIEContainerListValueCodecFieldEncode(v *ENBEarlyStatusTransferIEValueERABIEContainerListValueCodec) *func(ENBEarlyStatusTransferIEValueERABIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeENBEarlyStatusTransferIEValueERABIEContainerListValueCodecFieldPath(v *ENBEarlyStatusTransferIEValueERABIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgeENBEarlyStatusTransferIEValueERABIEContainerListValueCodecMethodEncodeBudgetValue(v ENBEarlyStatusTransferIEValueERABIEContainerListValueCodec, a0 ENBEarlyStatusTransferIEValueERABIEContainerList, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeENBEarlyStatusTransferIEValueERABIEContainerListValueCodecMethodEncodeChanged(v ENBEarlyStatusTransferIEValueERABIEContainerListValueCodec, a0 ENBEarlyStatusTransferIEValueERABIEContainerList, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeENBEarlyStatusTransferIEValueFieldId(v *ENBEarlyStatusTransferIEValue) *s00.ProtocolIEID {
	return &v.id
}
func BridgeENBEarlyStatusTransferIEValueFieldIsOpaque(v *ENBEarlyStatusTransferIEValue) *bool {
	return &v.isOpaque
}
func BridgeENBEarlyStatusTransferIEValueFieldOpaque(v *ENBEarlyStatusTransferIEValue) *aper.OpaqueOpenType {
	return &v.opaque
}
func BridgeENBEarlyStatusTransferIEValueFieldReceived(v *ENBEarlyStatusTransferIEValue) *aper.WireSpan {
	return &v.received
}
func BridgeENBEarlyStatusTransferIEValueFieldReplay(v *ENBEarlyStatusTransferIEValue) *aper.Snapshot {
	return &v.replay
}
func BridgeENBEarlyStatusTransferIEValueFieldRowENBEarlyStatusTransferTransparentContainer(v *ENBEarlyStatusTransferIEValue) **ENBEarlyStatusTransferTransparentContainer {
	return &v.rowENBEarlyStatusTransferTransparentContainer
}
func BridgeENBEarlyStatusTransferIEValueFieldRowENBUES1APID(v *ENBEarlyStatusTransferIEValue) **s00.ENBUES1APID {
	return &v.rowENBUES1APID
}
func BridgeENBEarlyStatusTransferIEValueFieldRowMMEUES1APID(v *ENBEarlyStatusTransferIEValue) **s00.MMEUES1APID {
	return &v.rowMMEUES1APID
}
func BridgeENBEarlyStatusTransferIEValueMethodCaptureSemantics(v ENBEarlyStatusTransferIEValue, a0 aper.SemanticCapture) ENBEarlyStatusTransferIEValue {
	return v.captureSemantics(a0)
}
func BridgeENBEarlyStatusTransferIEValueMethodCompareSemantics(v ENBEarlyStatusTransferIEValue, a0 aper.SemanticComparison) aper.SemanticComparison {
	return v.compareSemantics(a0)
}
func BridgeENBEarlyStatusTransferIEValueMethodDecode(v ENBEarlyStatusTransferIEValue, a0 s00.ProtocolIEID, a1 aper.OpaqueOpenType) (ENBEarlyStatusTransferIEValue, error) {
	return v.decode(a0, a1)
}
func BridgeENBEarlyStatusTransferIEValueMethodEncode(v ENBEarlyStatusTransferIEValue) ([]byte, error) {
	return v.encode()
}
func BridgeENBEarlyStatusTransferIEValueMethodEncodeFresh(v ENBEarlyStatusTransferIEValue, a0 bool, a1 *aper.DecodeBudget) ([]byte, error) {
	return v.encodeFresh(a0, a1)
}
func BridgeENBEarlyStatusTransferIEValueMethodMatchesID(v ENBEarlyStatusTransferIEValue, a0 s00.ProtocolIEID, a1 ...*aper.DecodeBudget) bool {
	return v.matchesID(a0, a1...)
}
func BridgeENBEarlyStatusTransferIEValueMethodReason(v ENBEarlyStatusTransferIEValue, a0 s00.ProtocolIEID) aper.OpaqueReason {
	return v.reason(a0)
}
func BridgeENBEarlyStatusTransferIEValueMethodRule(v ENBEarlyStatusTransferIEValue) aper.SourceRule {
	return v.rule()
}
func BridgeENBEarlyStatusTransferIEValueProtocolErrorIEContainerListAPERValueFieldContext(v *ENBEarlyStatusTransferIEValueProtocolErrorIEContainerListAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeENBEarlyStatusTransferIEValueProtocolErrorIEContainerListAPERValueFieldReceived(v *ENBEarlyStatusTransferIEValueProtocolErrorIEContainerListAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeENBEarlyStatusTransferIEValueProtocolErrorIEContainerListAPERValueFieldReplay(v *ENBEarlyStatusTransferIEValueProtocolErrorIEContainerListAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeENBEarlyStatusTransferIEValueProtocolErrorIEContainerListAPERValueFieldWithoutReplay(v *ENBEarlyStatusTransferIEValueProtocolErrorIEContainerListAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeENBEarlyStatusTransferIEValueProtocolErrorIEContainerListValueCodecFieldCapture(v *ENBEarlyStatusTransferIEValueProtocolErrorIEContainerListValueCodec) *func(ENBEarlyStatusTransferIEValueProtocolErrorIEContainerList, aper.DecodeState) (ENBEarlyStatusTransferIEValueProtocolErrorIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgeENBEarlyStatusTransferIEValueProtocolErrorIEContainerListValueCodecFieldCompare(v *ENBEarlyStatusTransferIEValueProtocolErrorIEContainerListValueCodec) *func(ENBEarlyStatusTransferIEValueProtocolErrorIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeENBEarlyStatusTransferIEValueProtocolErrorIEContainerListValueCodecFieldContext(v *ENBEarlyStatusTransferIEValueProtocolErrorIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeENBEarlyStatusTransferIEValueProtocolErrorIEContainerListValueCodecFieldDecode(v *ENBEarlyStatusTransferIEValueProtocolErrorIEContainerListValueCodec) *func([]byte, aper.DecodeState) (ENBEarlyStatusTransferIEValueProtocolErrorIEContainerList, error) {
	return &v.decode
}
func BridgeENBEarlyStatusTransferIEValueProtocolErrorIEContainerListValueCodecFieldEncode(v *ENBEarlyStatusTransferIEValueProtocolErrorIEContainerListValueCodec) *func(ENBEarlyStatusTransferIEValueProtocolErrorIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeENBEarlyStatusTransferIEValueProtocolErrorIEContainerListValueCodecFieldPath(v *ENBEarlyStatusTransferIEValueProtocolErrorIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgeENBEarlyStatusTransferIEValueProtocolErrorIEContainerListValueCodecMethodEncodeBudgetValue(v ENBEarlyStatusTransferIEValueProtocolErrorIEContainerListValueCodec, a0 ENBEarlyStatusTransferIEValueProtocolErrorIEContainerList, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeENBEarlyStatusTransferIEValueProtocolErrorIEContainerListValueCodecMethodEncodeChanged(v ENBEarlyStatusTransferIEValueProtocolErrorIEContainerListValueCodec, a0 ENBEarlyStatusTransferIEValueProtocolErrorIEContainerList, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeENBEarlyStatusTransferIEValueProtocolIEContainerListAPERValueFieldContext(v *ENBEarlyStatusTransferIEValueProtocolIEContainerListAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeENBEarlyStatusTransferIEValueProtocolIEContainerListAPERValueFieldReceived(v *ENBEarlyStatusTransferIEValueProtocolIEContainerListAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeENBEarlyStatusTransferIEValueProtocolIEContainerListAPERValueFieldReplay(v *ENBEarlyStatusTransferIEValueProtocolIEContainerListAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeENBEarlyStatusTransferIEValueProtocolIEContainerListAPERValueFieldWithoutReplay(v *ENBEarlyStatusTransferIEValueProtocolIEContainerListAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeENBEarlyStatusTransferIEValueProtocolIEContainerListValueCodecFieldCapture(v *ENBEarlyStatusTransferIEValueProtocolIEContainerListValueCodec) *func(ENBEarlyStatusTransferIEValueProtocolIEContainerList, aper.DecodeState) (ENBEarlyStatusTransferIEValueProtocolIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgeENBEarlyStatusTransferIEValueProtocolIEContainerListValueCodecFieldCompare(v *ENBEarlyStatusTransferIEValueProtocolIEContainerListValueCodec) *func(ENBEarlyStatusTransferIEValueProtocolIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeENBEarlyStatusTransferIEValueProtocolIEContainerListValueCodecFieldContext(v *ENBEarlyStatusTransferIEValueProtocolIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeENBEarlyStatusTransferIEValueProtocolIEContainerListValueCodecFieldDecode(v *ENBEarlyStatusTransferIEValueProtocolIEContainerListValueCodec) *func([]byte, aper.DecodeState) (ENBEarlyStatusTransferIEValueProtocolIEContainerList, error) {
	return &v.decode
}
func BridgeENBEarlyStatusTransferIEValueProtocolIEContainerListValueCodecFieldEncode(v *ENBEarlyStatusTransferIEValueProtocolIEContainerListValueCodec) *func(ENBEarlyStatusTransferIEValueProtocolIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeENBEarlyStatusTransferIEValueProtocolIEContainerListValueCodecFieldPath(v *ENBEarlyStatusTransferIEValueProtocolIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgeENBEarlyStatusTransferIEValueProtocolIEContainerListValueCodecMethodEncodeBudgetValue(v ENBEarlyStatusTransferIEValueProtocolIEContainerListValueCodec, a0 ENBEarlyStatusTransferIEValueProtocolIEContainerList, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeENBEarlyStatusTransferIEValueProtocolIEContainerListValueCodecMethodEncodeChanged(v ENBEarlyStatusTransferIEValueProtocolIEContainerListValueCodec, a0 ENBEarlyStatusTransferIEValueProtocolIEContainerList, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeENBEarlyStatusTransferMMEUES1APIDIEBindingFieldCodec(v *ENBEarlyStatusTransferMMEUES1APIDIEBinding) *s01.MMEUES1APIDValueCodec {
	return &v.codec
}
func BridgeENBEarlyStatusTransferMMEUES1APIDIEBindingFieldGet(v *ENBEarlyStatusTransferMMEUES1APIDIEBinding) *func(*ENBEarlyStatusTransferIEValue) (*s00.MMEUES1APID, bool) {
	return &v.get
}
func BridgeENBEarlyStatusTransferMMEUES1APIDIEBindingFieldInfo(v *ENBEarlyStatusTransferMMEUES1APIDIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeENBEarlyStatusTransferMMEUES1APIDIEBindingFieldInject(v *ENBEarlyStatusTransferMMEUES1APIDIEBinding) *func(s00.MMEUES1APID) ENBEarlyStatusTransferIEValue {
	return &v.inject
}
func BridgeENBEarlyStatusTransferTransparentContainerAPERValueFieldContext(v *ENBEarlyStatusTransferTransparentContainerAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeENBEarlyStatusTransferTransparentContainerAPERValueFieldReceived(v *ENBEarlyStatusTransferTransparentContainerAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeENBEarlyStatusTransferTransparentContainerAPERValueFieldReplay(v *ENBEarlyStatusTransferTransparentContainerAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeENBEarlyStatusTransferTransparentContainerAPERValueFieldWithoutReplay(v *ENBEarlyStatusTransferTransparentContainerAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeENBEarlyStatusTransferTransparentContainerExtIETableMethodInfoBearersSubjectToDLDiscardingList(v ENBEarlyStatusTransferTransparentContainerExtIETable) s00.ExtensionInfo {
	return v.infoBearersSubjectToDLDiscardingList()
}
func BridgeENBEarlyStatusTransferTransparentContainerExtIEsBearersSubjectToDLDiscardingListExtBindingFieldCodec(v *ENBEarlyStatusTransferTransparentContainerExtIEsBearersSubjectToDLDiscardingListExtBinding) *s15.BearersSubjectToDLDiscardingListValueCodec {
	return &v.codec
}
func BridgeENBEarlyStatusTransferTransparentContainerExtIEsBearersSubjectToDLDiscardingListExtBindingFieldGet(v *ENBEarlyStatusTransferTransparentContainerExtIEsBearersSubjectToDLDiscardingListExtBinding) *func(*ENBEarlyStatusTransferTransparentContainerExtIEsValue) (*s15.BearersSubjectToDLDiscardingList, bool) {
	return &v.get
}
func BridgeENBEarlyStatusTransferTransparentContainerExtIEsBearersSubjectToDLDiscardingListExtBindingFieldInfo(v *ENBEarlyStatusTransferTransparentContainerExtIEsBearersSubjectToDLDiscardingListExtBinding) *s00.ExtensionInfo {
	return &v.info
}
func BridgeENBEarlyStatusTransferTransparentContainerExtIEsBearersSubjectToDLDiscardingListExtBindingFieldInject(v *ENBEarlyStatusTransferTransparentContainerExtIEsBearersSubjectToDLDiscardingListExtBinding) *func(s15.BearersSubjectToDLDiscardingList) ENBEarlyStatusTransferTransparentContainerExtIEsValue {
	return &v.inject
}
func BridgeENBEarlyStatusTransferTransparentContainerExtIEsExtContainerAPERValueFieldContext(v *ENBEarlyStatusTransferTransparentContainerExtIEsExtContainerAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeENBEarlyStatusTransferTransparentContainerExtIEsExtContainerAPERValueFieldReceived(v *ENBEarlyStatusTransferTransparentContainerExtIEsExtContainerAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeENBEarlyStatusTransferTransparentContainerExtIEsExtContainerAPERValueFieldReplay(v *ENBEarlyStatusTransferTransparentContainerExtIEsExtContainerAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeENBEarlyStatusTransferTransparentContainerExtIEsExtContainerAPERValueFieldWithoutReplay(v *ENBEarlyStatusTransferTransparentContainerExtIEsExtContainerAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeENBEarlyStatusTransferTransparentContainerExtIEsExtContainerValueCodecFieldCapture(v *ENBEarlyStatusTransferTransparentContainerExtIEsExtContainerValueCodec) *func(ENBEarlyStatusTransferTransparentContainerExtIEsExtContainer, aper.DecodeState) (ENBEarlyStatusTransferTransparentContainerExtIEsExtContainer, aper.Snapshot) {
	return &v.capture
}
func BridgeENBEarlyStatusTransferTransparentContainerExtIEsExtContainerValueCodecFieldCompare(v *ENBEarlyStatusTransferTransparentContainerExtIEsExtContainerValueCodec) *func(ENBEarlyStatusTransferTransparentContainerExtIEsExtContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeENBEarlyStatusTransferTransparentContainerExtIEsExtContainerValueCodecFieldContext(v *ENBEarlyStatusTransferTransparentContainerExtIEsExtContainerValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeENBEarlyStatusTransferTransparentContainerExtIEsExtContainerValueCodecFieldDecode(v *ENBEarlyStatusTransferTransparentContainerExtIEsExtContainerValueCodec) *func([]byte, aper.DecodeState) (ENBEarlyStatusTransferTransparentContainerExtIEsExtContainer, error) {
	return &v.decode
}
func BridgeENBEarlyStatusTransferTransparentContainerExtIEsExtContainerValueCodecFieldEncode(v *ENBEarlyStatusTransferTransparentContainerExtIEsExtContainerValueCodec) *func(ENBEarlyStatusTransferTransparentContainerExtIEsExtContainer, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeENBEarlyStatusTransferTransparentContainerExtIEsExtContainerValueCodecFieldPath(v *ENBEarlyStatusTransferTransparentContainerExtIEsExtContainerValueCodec) *aper.Path {
	return &v.path
}
func BridgeENBEarlyStatusTransferTransparentContainerExtIEsExtContainerValueCodecMethodEncodeBudgetValue(v ENBEarlyStatusTransferTransparentContainerExtIEsExtContainerValueCodec, a0 ENBEarlyStatusTransferTransparentContainerExtIEsExtContainer, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeENBEarlyStatusTransferTransparentContainerExtIEsExtContainerValueCodecMethodEncodeChanged(v ENBEarlyStatusTransferTransparentContainerExtIEsExtContainerValueCodec, a0 ENBEarlyStatusTransferTransparentContainerExtIEsExtContainer, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeENBEarlyStatusTransferTransparentContainerExtIEsExtFieldAPERValueFieldContext(v *ENBEarlyStatusTransferTransparentContainerExtIEsExtFieldAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeENBEarlyStatusTransferTransparentContainerExtIEsExtFieldAPERValueFieldReceived(v *ENBEarlyStatusTransferTransparentContainerExtIEsExtFieldAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeENBEarlyStatusTransferTransparentContainerExtIEsExtFieldAPERValueFieldReplay(v *ENBEarlyStatusTransferTransparentContainerExtIEsExtFieldAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeENBEarlyStatusTransferTransparentContainerExtIEsExtFieldAPERValueFieldWithoutReplay(v *ENBEarlyStatusTransferTransparentContainerExtIEsExtFieldAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeENBEarlyStatusTransferTransparentContainerExtIEsExtFieldFieldReceived(v *ENBEarlyStatusTransferTransparentContainerExtIEsExtField) *aper.CompletePadding {
	return &v.received
}
func BridgeENBEarlyStatusTransferTransparentContainerExtIEsExtFieldFieldReplay(v *ENBEarlyStatusTransferTransparentContainerExtIEsExtField) *aper.Snapshot {
	return &v.replay
}
func BridgeENBEarlyStatusTransferTransparentContainerExtIEsExtFieldFieldStream(v *ENBEarlyStatusTransferTransparentContainerExtIEsExtField) *aper.WireSpan {
	return &v.stream
}
func BridgeENBEarlyStatusTransferTransparentContainerExtIEsExtFieldFieldWithoutReplay(v *ENBEarlyStatusTransferTransparentContainerExtIEsExtField) *bool {
	return &v.withoutReplay
}
func BridgeENBEarlyStatusTransferTransparentContainerExtIEsExtFieldMethodMarshalAPERTo(v *ENBEarlyStatusTransferTransparentContainerExtIEsExtField, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeENBEarlyStatusTransferTransparentContainerExtIEsExtFieldMethodUnmarshalAPERFrom(v *ENBEarlyStatusTransferTransparentContainerExtIEsExtField, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeENBEarlyStatusTransferTransparentContainerExtIEsExtFieldValueCodecFieldCapture(v *ENBEarlyStatusTransferTransparentContainerExtIEsExtFieldValueCodec) *func(ENBEarlyStatusTransferTransparentContainerExtIEsExtField, aper.DecodeState) (ENBEarlyStatusTransferTransparentContainerExtIEsExtField, aper.Snapshot) {
	return &v.capture
}
func BridgeENBEarlyStatusTransferTransparentContainerExtIEsExtFieldValueCodecFieldCompare(v *ENBEarlyStatusTransferTransparentContainerExtIEsExtFieldValueCodec) *func(ENBEarlyStatusTransferTransparentContainerExtIEsExtField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeENBEarlyStatusTransferTransparentContainerExtIEsExtFieldValueCodecFieldContext(v *ENBEarlyStatusTransferTransparentContainerExtIEsExtFieldValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeENBEarlyStatusTransferTransparentContainerExtIEsExtFieldValueCodecFieldDecode(v *ENBEarlyStatusTransferTransparentContainerExtIEsExtFieldValueCodec) *func([]byte, aper.DecodeState) (ENBEarlyStatusTransferTransparentContainerExtIEsExtField, error) {
	return &v.decode
}
func BridgeENBEarlyStatusTransferTransparentContainerExtIEsExtFieldValueCodecFieldEncode(v *ENBEarlyStatusTransferTransparentContainerExtIEsExtFieldValueCodec) *func(ENBEarlyStatusTransferTransparentContainerExtIEsExtField, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeENBEarlyStatusTransferTransparentContainerExtIEsExtFieldValueCodecFieldPath(v *ENBEarlyStatusTransferTransparentContainerExtIEsExtFieldValueCodec) *aper.Path {
	return &v.path
}
func BridgeENBEarlyStatusTransferTransparentContainerExtIEsExtFieldValueCodecMethodEncodeBudgetValue(v ENBEarlyStatusTransferTransparentContainerExtIEsExtFieldValueCodec, a0 ENBEarlyStatusTransferTransparentContainerExtIEsExtField, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeENBEarlyStatusTransferTransparentContainerExtIEsExtFieldValueCodecMethodEncodeChanged(v ENBEarlyStatusTransferTransparentContainerExtIEsExtFieldValueCodec, a0 ENBEarlyStatusTransferTransparentContainerExtIEsExtField, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeENBEarlyStatusTransferTransparentContainerExtIEsIEFieldFieldReceived(v *ENBEarlyStatusTransferTransparentContainerExtIEsIEField) *aper.CompletePadding {
	return &v.received
}
func BridgeENBEarlyStatusTransferTransparentContainerExtIEsIEFieldFieldReplay(v *ENBEarlyStatusTransferTransparentContainerExtIEsIEField) *aper.Snapshot {
	return &v.replay
}
func BridgeENBEarlyStatusTransferTransparentContainerExtIEsIEFieldFieldStream(v *ENBEarlyStatusTransferTransparentContainerExtIEsIEField) *aper.WireSpan {
	return &v.stream
}
func BridgeENBEarlyStatusTransferTransparentContainerExtIEsIEFieldFieldWithoutReplay(v *ENBEarlyStatusTransferTransparentContainerExtIEsIEField) *bool {
	return &v.withoutReplay
}
func BridgeENBEarlyStatusTransferTransparentContainerExtIEsIEFieldMethodMarshalAPERTo(v *ENBEarlyStatusTransferTransparentContainerExtIEsIEField, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeENBEarlyStatusTransferTransparentContainerExtIEsIEFieldMethodUnmarshalAPERFrom(v *ENBEarlyStatusTransferTransparentContainerExtIEsIEField, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeENBEarlyStatusTransferTransparentContainerExtIEsValueFieldId(v *ENBEarlyStatusTransferTransparentContainerExtIEsValue) *s00.ProtocolIEID {
	return &v.id
}
func BridgeENBEarlyStatusTransferTransparentContainerExtIEsValueFieldIsOpaque(v *ENBEarlyStatusTransferTransparentContainerExtIEsValue) *bool {
	return &v.isOpaque
}
func BridgeENBEarlyStatusTransferTransparentContainerExtIEsValueFieldOpaque(v *ENBEarlyStatusTransferTransparentContainerExtIEsValue) *aper.OpaqueOpenType {
	return &v.opaque
}
func BridgeENBEarlyStatusTransferTransparentContainerExtIEsValueFieldReceived(v *ENBEarlyStatusTransferTransparentContainerExtIEsValue) *aper.WireSpan {
	return &v.received
}
func BridgeENBEarlyStatusTransferTransparentContainerExtIEsValueFieldReplay(v *ENBEarlyStatusTransferTransparentContainerExtIEsValue) *aper.Snapshot {
	return &v.replay
}
func BridgeENBEarlyStatusTransferTransparentContainerExtIEsValueFieldRowBearersSubjectToDLDiscardingList(v *ENBEarlyStatusTransferTransparentContainerExtIEsValue) **s15.BearersSubjectToDLDiscardingList {
	return &v.rowBearersSubjectToDLDiscardingList
}
func BridgeENBEarlyStatusTransferTransparentContainerExtIEsValueMethodCaptureSemantics(v ENBEarlyStatusTransferTransparentContainerExtIEsValue, a0 aper.SemanticCapture) ENBEarlyStatusTransferTransparentContainerExtIEsValue {
	return v.captureSemantics(a0)
}
func BridgeENBEarlyStatusTransferTransparentContainerExtIEsValueMethodCompareSemantics(v ENBEarlyStatusTransferTransparentContainerExtIEsValue, a0 aper.SemanticComparison) aper.SemanticComparison {
	return v.compareSemantics(a0)
}
func BridgeENBEarlyStatusTransferTransparentContainerExtIEsValueMethodDecode(v ENBEarlyStatusTransferTransparentContainerExtIEsValue, a0 s00.ProtocolIEID, a1 aper.OpaqueOpenType) (ENBEarlyStatusTransferTransparentContainerExtIEsValue, error) {
	return v.decode(a0, a1)
}
func BridgeENBEarlyStatusTransferTransparentContainerExtIEsValueMethodEncode(v ENBEarlyStatusTransferTransparentContainerExtIEsValue) ([]byte, error) {
	return v.encode()
}
func BridgeENBEarlyStatusTransferTransparentContainerExtIEsValueMethodEncodeFresh(v ENBEarlyStatusTransferTransparentContainerExtIEsValue, a0 bool, a1 *aper.DecodeBudget) ([]byte, error) {
	return v.encodeFresh(a0, a1)
}
func BridgeENBEarlyStatusTransferTransparentContainerExtIEsValueMethodMatchesID(v ENBEarlyStatusTransferTransparentContainerExtIEsValue, a0 s00.ProtocolIEID, a1 ...*aper.DecodeBudget) bool {
	return v.matchesID(a0, a1...)
}
func BridgeENBEarlyStatusTransferTransparentContainerExtIEsValueMethodReason(v ENBEarlyStatusTransferTransparentContainerExtIEsValue, a0 s00.ProtocolIEID) aper.OpaqueReason {
	return v.reason(a0)
}
func BridgeENBEarlyStatusTransferTransparentContainerExtIEsValueMethodRule(v ENBEarlyStatusTransferTransparentContainerExtIEsValue) aper.SourceRule {
	return v.rule()
}
func BridgeENBEarlyStatusTransferTransparentContainerFieldBearersSubjectToEarlyStatusTransferListIndef(v *ENBEarlyStatusTransferTransparentContainer) *bool {
	return &v.bearersSubjectToEarlyStatusTransferListIndef
}
func BridgeENBEarlyStatusTransferTransparentContainerFieldExtCount(v *ENBEarlyStatusTransferTransparentContainer) *int64 {
	return &v.extCount
}
func BridgeENBEarlyStatusTransferTransparentContainerFieldExtData(v *ENBEarlyStatusTransferTransparentContainer) *[][]byte {
	return &v.extData
}
func BridgeENBEarlyStatusTransferTransparentContainerFieldExtOrigin(v *ENBEarlyStatusTransferTransparentContainer) *[]aper.OpaqueOrigin {
	return &v.extOrigin
}
func BridgeENBEarlyStatusTransferTransparentContainerFieldExtPresent(v *ENBEarlyStatusTransferTransparentContainer) *[]bool {
	return &v.extPresent
}
func BridgeENBEarlyStatusTransferTransparentContainerFieldExtWire(v *ENBEarlyStatusTransferTransparentContainer) *[]aper.WireSpan {
	return &v.extWire
}
func BridgeENBEarlyStatusTransferTransparentContainerFieldIEExtensionsIndef(v *ENBEarlyStatusTransferTransparentContainer) *bool {
	return &v.iEExtensionsIndef
}
func BridgeENBEarlyStatusTransferTransparentContainerFieldPerExtPadding(v *ENBEarlyStatusTransferTransparentContainer) *[]aper.CompletePadding {
	return &v.perExtPadding
}
func BridgeENBEarlyStatusTransferTransparentContainerFieldPerPadding(v *ENBEarlyStatusTransferTransparentContainer) *aper.FinalPadding {
	return &v.perPadding
}
func BridgeENBEarlyStatusTransferTransparentContainerFieldReceived(v *ENBEarlyStatusTransferTransparentContainer) *bool {
	return &v.received
}
func BridgeENBEarlyStatusTransferTransparentContainerFieldReceivedAbsolute(v *ENBEarlyStatusTransferTransparentContainer) *bool {
	return &v.receivedAbsolute
}
func BridgeENBEarlyStatusTransferTransparentContainerFieldReceivedBytes(v *ENBEarlyStatusTransferTransparentContainer) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeENBEarlyStatusTransferTransparentContainerFieldReceivedLocation(v *ENBEarlyStatusTransferTransparentContainer) *aper.Location {
	return &v.receivedLocation
}
func BridgeENBEarlyStatusTransferTransparentContainerFieldReplay(v *ENBEarlyStatusTransferTransparentContainer) *aper.Snapshot {
	return &v.replay
}
func BridgeENBEarlyStatusTransferTransparentContainerFieldStream(v *ENBEarlyStatusTransferTransparentContainer) *aper.WireSpan {
	return &v.stream
}
func BridgeENBEarlyStatusTransferTransparentContainerFieldWithoutReplay(v *ENBEarlyStatusTransferTransparentContainer) *bool {
	return &v.withoutReplay
}
func BridgeENBEarlyStatusTransferTransparentContainerMethodMarshalAPERBudget(v *ENBEarlyStatusTransferTransparentContainer, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeENBEarlyStatusTransferTransparentContainerMethodMarshalAPERBudgetValue(v *ENBEarlyStatusTransferTransparentContainer, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudgetValue(a0, a1)
}
func BridgeENBEarlyStatusTransferTransparentContainerMethodMarshalAPERChanged(v *ENBEarlyStatusTransferTransparentContainer, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeENBEarlyStatusTransferTransparentContainerMethodMarshalAPERChangedValue(v *ENBEarlyStatusTransferTransparentContainer, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeENBEarlyStatusTransferTransparentContainerMethodMarshalAPERLegacy(v *ENBEarlyStatusTransferTransparentContainer) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeENBEarlyStatusTransferTransparentContainerMethodMarshalAPERNewValue(v *ENBEarlyStatusTransferTransparentContainer, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERNewValue(a0, a1)
}
func BridgeENBEarlyStatusTransferTransparentContainerMethodMarshalAPERPlanned(v *ENBEarlyStatusTransferTransparentContainer, a0 *aper.DecodeBudget, a1 bool, a2 *aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1, a2)
}
func BridgeENBEarlyStatusTransferTransparentContainerMethodMarshalAPERTo(v *ENBEarlyStatusTransferTransparentContainer, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeENBEarlyStatusTransferTransparentContainerMethodUnmarshalAPERFrom(v *ENBEarlyStatusTransferTransparentContainer, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeENBEarlyStatusTransferTransparentContainerMethodUnmarshalAPERLegacy(v *ENBEarlyStatusTransferTransparentContainer, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeENBEarlyStatusTransferTransparentContainerMethodUnmarshalAPERWithOptions(v *ENBEarlyStatusTransferTransparentContainer, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeENBEarlyStatusTransferTransparentContainerValueCodecFieldCapture(v *ENBEarlyStatusTransferTransparentContainerValueCodec) *func(ENBEarlyStatusTransferTransparentContainer, aper.DecodeState) (ENBEarlyStatusTransferTransparentContainer, aper.Snapshot) {
	return &v.capture
}
func BridgeENBEarlyStatusTransferTransparentContainerValueCodecFieldCompare(v *ENBEarlyStatusTransferTransparentContainerValueCodec) *func(ENBEarlyStatusTransferTransparentContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeENBEarlyStatusTransferTransparentContainerValueCodecFieldContext(v *ENBEarlyStatusTransferTransparentContainerValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeENBEarlyStatusTransferTransparentContainerValueCodecFieldDecode(v *ENBEarlyStatusTransferTransparentContainerValueCodec) *func([]byte, aper.DecodeState) (ENBEarlyStatusTransferTransparentContainer, error) {
	return &v.decode
}
func BridgeENBEarlyStatusTransferTransparentContainerValueCodecFieldEncode(v *ENBEarlyStatusTransferTransparentContainerValueCodec) *func(ENBEarlyStatusTransferTransparentContainer, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeENBEarlyStatusTransferTransparentContainerValueCodecFieldPath(v *ENBEarlyStatusTransferTransparentContainerValueCodec) *aper.Path {
	return &v.path
}
func BridgeENBEarlyStatusTransferTransparentContainerValueCodecMethodEncodeBudgetValue(v ENBEarlyStatusTransferTransparentContainerValueCodec, a0 ENBEarlyStatusTransferTransparentContainer, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeENBEarlyStatusTransferTransparentContainerValueCodecMethodEncodeChanged(v ENBEarlyStatusTransferTransparentContainerValueCodec, a0 ENBEarlyStatusTransferTransparentContainer, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeMMEEarlyStatusTransferENBEarlyStatusTransferTransparentContainerIEBindingFieldCodec(v *MMEEarlyStatusTransferENBEarlyStatusTransferTransparentContainerIEBinding) *ENBEarlyStatusTransferTransparentContainerValueCodec {
	return &v.codec
}
func BridgeMMEEarlyStatusTransferENBEarlyStatusTransferTransparentContainerIEBindingFieldGet(v *MMEEarlyStatusTransferENBEarlyStatusTransferTransparentContainerIEBinding) *func(*MMEEarlyStatusTransferIEValue) (*ENBEarlyStatusTransferTransparentContainer, bool) {
	return &v.get
}
func BridgeMMEEarlyStatusTransferENBEarlyStatusTransferTransparentContainerIEBindingFieldInfo(v *MMEEarlyStatusTransferENBEarlyStatusTransferTransparentContainerIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeMMEEarlyStatusTransferENBEarlyStatusTransferTransparentContainerIEBindingFieldInject(v *MMEEarlyStatusTransferENBEarlyStatusTransferTransparentContainerIEBinding) *func(ENBEarlyStatusTransferTransparentContainer) MMEEarlyStatusTransferIEValue {
	return &v.inject
}
func BridgeMMEEarlyStatusTransferENBUES1APIDIEBindingFieldCodec(v *MMEEarlyStatusTransferENBUES1APIDIEBinding) *s00.ENBUES1APIDValueCodec {
	return &v.codec
}
func BridgeMMEEarlyStatusTransferENBUES1APIDIEBindingFieldGet(v *MMEEarlyStatusTransferENBUES1APIDIEBinding) *func(*MMEEarlyStatusTransferIEValue) (*s00.ENBUES1APID, bool) {
	return &v.get
}
func BridgeMMEEarlyStatusTransferENBUES1APIDIEBindingFieldInfo(v *MMEEarlyStatusTransferENBUES1APIDIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeMMEEarlyStatusTransferENBUES1APIDIEBindingFieldInject(v *MMEEarlyStatusTransferENBUES1APIDIEBinding) *func(s00.ENBUES1APID) MMEEarlyStatusTransferIEValue {
	return &v.inject
}
func BridgeMMEEarlyStatusTransferIEContainerAPERValueFieldContext(v *MMEEarlyStatusTransferIEContainerAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeMMEEarlyStatusTransferIEContainerAPERValueFieldReceived(v *MMEEarlyStatusTransferIEContainerAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeMMEEarlyStatusTransferIEContainerAPERValueFieldReplay(v *MMEEarlyStatusTransferIEContainerAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeMMEEarlyStatusTransferIEContainerAPERValueFieldWithoutReplay(v *MMEEarlyStatusTransferIEContainerAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeMMEEarlyStatusTransferIEContainerValueCodecFieldCapture(v *MMEEarlyStatusTransferIEContainerValueCodec) *func(MMEEarlyStatusTransferIEContainer, aper.DecodeState) (MMEEarlyStatusTransferIEContainer, aper.Snapshot) {
	return &v.capture
}
func BridgeMMEEarlyStatusTransferIEContainerValueCodecFieldCompare(v *MMEEarlyStatusTransferIEContainerValueCodec) *func(MMEEarlyStatusTransferIEContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeMMEEarlyStatusTransferIEContainerValueCodecFieldContext(v *MMEEarlyStatusTransferIEContainerValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeMMEEarlyStatusTransferIEContainerValueCodecFieldDecode(v *MMEEarlyStatusTransferIEContainerValueCodec) *func([]byte, aper.DecodeState) (MMEEarlyStatusTransferIEContainer, error) {
	return &v.decode
}
func BridgeMMEEarlyStatusTransferIEContainerValueCodecFieldEncode(v *MMEEarlyStatusTransferIEContainerValueCodec) *func(MMEEarlyStatusTransferIEContainer, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeMMEEarlyStatusTransferIEContainerValueCodecFieldPath(v *MMEEarlyStatusTransferIEContainerValueCodec) *aper.Path {
	return &v.path
}
func BridgeMMEEarlyStatusTransferIEContainerValueCodecMethodEncodeBudgetValue(v MMEEarlyStatusTransferIEContainerValueCodec, a0 MMEEarlyStatusTransferIEContainer, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeMMEEarlyStatusTransferIEContainerValueCodecMethodEncodeChanged(v MMEEarlyStatusTransferIEContainerValueCodec, a0 MMEEarlyStatusTransferIEContainer, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeMMEEarlyStatusTransferIEFieldAPERValueFieldContext(v *MMEEarlyStatusTransferIEFieldAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeMMEEarlyStatusTransferIEFieldAPERValueFieldReceived(v *MMEEarlyStatusTransferIEFieldAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeMMEEarlyStatusTransferIEFieldAPERValueFieldReplay(v *MMEEarlyStatusTransferIEFieldAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeMMEEarlyStatusTransferIEFieldAPERValueFieldWithoutReplay(v *MMEEarlyStatusTransferIEFieldAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeMMEEarlyStatusTransferIEFieldFieldReceived(v *MMEEarlyStatusTransferIEField) *aper.CompletePadding {
	return &v.received
}
func BridgeMMEEarlyStatusTransferIEFieldFieldReplay(v *MMEEarlyStatusTransferIEField) *aper.Snapshot {
	return &v.replay
}
func BridgeMMEEarlyStatusTransferIEFieldFieldStream(v *MMEEarlyStatusTransferIEField) *aper.WireSpan {
	return &v.stream
}
func BridgeMMEEarlyStatusTransferIEFieldFieldWithoutReplay(v *MMEEarlyStatusTransferIEField) *bool {
	return &v.withoutReplay
}
func BridgeMMEEarlyStatusTransferIEFieldMethodMarshalAPERTo(v *MMEEarlyStatusTransferIEField, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeMMEEarlyStatusTransferIEFieldMethodUnmarshalAPERFrom(v *MMEEarlyStatusTransferIEField, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeMMEEarlyStatusTransferIEFieldValueCodecFieldCapture(v *MMEEarlyStatusTransferIEFieldValueCodec) *func(MMEEarlyStatusTransferIEField, aper.DecodeState) (MMEEarlyStatusTransferIEField, aper.Snapshot) {
	return &v.capture
}
func BridgeMMEEarlyStatusTransferIEFieldValueCodecFieldCompare(v *MMEEarlyStatusTransferIEFieldValueCodec) *func(MMEEarlyStatusTransferIEField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeMMEEarlyStatusTransferIEFieldValueCodecFieldContext(v *MMEEarlyStatusTransferIEFieldValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeMMEEarlyStatusTransferIEFieldValueCodecFieldDecode(v *MMEEarlyStatusTransferIEFieldValueCodec) *func([]byte, aper.DecodeState) (MMEEarlyStatusTransferIEField, error) {
	return &v.decode
}
func BridgeMMEEarlyStatusTransferIEFieldValueCodecFieldEncode(v *MMEEarlyStatusTransferIEFieldValueCodec) *func(MMEEarlyStatusTransferIEField, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeMMEEarlyStatusTransferIEFieldValueCodecFieldPath(v *MMEEarlyStatusTransferIEFieldValueCodec) *aper.Path {
	return &v.path
}
func BridgeMMEEarlyStatusTransferIEFieldValueCodecMethodEncodeBudgetValue(v MMEEarlyStatusTransferIEFieldValueCodec, a0 MMEEarlyStatusTransferIEField, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeMMEEarlyStatusTransferIEFieldValueCodecMethodEncodeChanged(v MMEEarlyStatusTransferIEFieldValueCodec, a0 MMEEarlyStatusTransferIEField, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeMMEEarlyStatusTransferIETableMethodInfoENBEarlyStatusTransferTransparentContainer(v MMEEarlyStatusTransferIETable) s00.FieldInfo {
	return v.infoENBEarlyStatusTransferTransparentContainer()
}
func BridgeMMEEarlyStatusTransferIETableMethodInfoENBUES1APID(v MMEEarlyStatusTransferIETable) s00.FieldInfo {
	return v.infoENBUES1APID()
}
func BridgeMMEEarlyStatusTransferIETableMethodInfoMMEUES1APID(v MMEEarlyStatusTransferIETable) s00.FieldInfo {
	return v.infoMMEUES1APID()
}
func BridgeMMEEarlyStatusTransferIEValueERABIEContainerListAPERValueFieldContext(v *MMEEarlyStatusTransferIEValueERABIEContainerListAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeMMEEarlyStatusTransferIEValueERABIEContainerListAPERValueFieldReceived(v *MMEEarlyStatusTransferIEValueERABIEContainerListAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeMMEEarlyStatusTransferIEValueERABIEContainerListAPERValueFieldReplay(v *MMEEarlyStatusTransferIEValueERABIEContainerListAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeMMEEarlyStatusTransferIEValueERABIEContainerListAPERValueFieldWithoutReplay(v *MMEEarlyStatusTransferIEValueERABIEContainerListAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeMMEEarlyStatusTransferIEValueERABIEContainerListValueCodecFieldCapture(v *MMEEarlyStatusTransferIEValueERABIEContainerListValueCodec) *func(MMEEarlyStatusTransferIEValueERABIEContainerList, aper.DecodeState) (MMEEarlyStatusTransferIEValueERABIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgeMMEEarlyStatusTransferIEValueERABIEContainerListValueCodecFieldCompare(v *MMEEarlyStatusTransferIEValueERABIEContainerListValueCodec) *func(MMEEarlyStatusTransferIEValueERABIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeMMEEarlyStatusTransferIEValueERABIEContainerListValueCodecFieldContext(v *MMEEarlyStatusTransferIEValueERABIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeMMEEarlyStatusTransferIEValueERABIEContainerListValueCodecFieldDecode(v *MMEEarlyStatusTransferIEValueERABIEContainerListValueCodec) *func([]byte, aper.DecodeState) (MMEEarlyStatusTransferIEValueERABIEContainerList, error) {
	return &v.decode
}
func BridgeMMEEarlyStatusTransferIEValueERABIEContainerListValueCodecFieldEncode(v *MMEEarlyStatusTransferIEValueERABIEContainerListValueCodec) *func(MMEEarlyStatusTransferIEValueERABIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeMMEEarlyStatusTransferIEValueERABIEContainerListValueCodecFieldPath(v *MMEEarlyStatusTransferIEValueERABIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgeMMEEarlyStatusTransferIEValueERABIEContainerListValueCodecMethodEncodeBudgetValue(v MMEEarlyStatusTransferIEValueERABIEContainerListValueCodec, a0 MMEEarlyStatusTransferIEValueERABIEContainerList, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeMMEEarlyStatusTransferIEValueERABIEContainerListValueCodecMethodEncodeChanged(v MMEEarlyStatusTransferIEValueERABIEContainerListValueCodec, a0 MMEEarlyStatusTransferIEValueERABIEContainerList, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeMMEEarlyStatusTransferIEValueFieldId(v *MMEEarlyStatusTransferIEValue) *s00.ProtocolIEID {
	return &v.id
}
func BridgeMMEEarlyStatusTransferIEValueFieldIsOpaque(v *MMEEarlyStatusTransferIEValue) *bool {
	return &v.isOpaque
}
func BridgeMMEEarlyStatusTransferIEValueFieldOpaque(v *MMEEarlyStatusTransferIEValue) *aper.OpaqueOpenType {
	return &v.opaque
}
func BridgeMMEEarlyStatusTransferIEValueFieldReceived(v *MMEEarlyStatusTransferIEValue) *aper.WireSpan {
	return &v.received
}
func BridgeMMEEarlyStatusTransferIEValueFieldReplay(v *MMEEarlyStatusTransferIEValue) *aper.Snapshot {
	return &v.replay
}
func BridgeMMEEarlyStatusTransferIEValueFieldRowENBEarlyStatusTransferTransparentContainer(v *MMEEarlyStatusTransferIEValue) **ENBEarlyStatusTransferTransparentContainer {
	return &v.rowENBEarlyStatusTransferTransparentContainer
}
func BridgeMMEEarlyStatusTransferIEValueFieldRowENBUES1APID(v *MMEEarlyStatusTransferIEValue) **s00.ENBUES1APID {
	return &v.rowENBUES1APID
}
func BridgeMMEEarlyStatusTransferIEValueFieldRowMMEUES1APID(v *MMEEarlyStatusTransferIEValue) **s00.MMEUES1APID {
	return &v.rowMMEUES1APID
}
func BridgeMMEEarlyStatusTransferIEValueMethodCaptureSemantics(v MMEEarlyStatusTransferIEValue, a0 aper.SemanticCapture) MMEEarlyStatusTransferIEValue {
	return v.captureSemantics(a0)
}
func BridgeMMEEarlyStatusTransferIEValueMethodCompareSemantics(v MMEEarlyStatusTransferIEValue, a0 aper.SemanticComparison) aper.SemanticComparison {
	return v.compareSemantics(a0)
}
func BridgeMMEEarlyStatusTransferIEValueMethodDecode(v MMEEarlyStatusTransferIEValue, a0 s00.ProtocolIEID, a1 aper.OpaqueOpenType) (MMEEarlyStatusTransferIEValue, error) {
	return v.decode(a0, a1)
}
func BridgeMMEEarlyStatusTransferIEValueMethodEncode(v MMEEarlyStatusTransferIEValue) ([]byte, error) {
	return v.encode()
}
func BridgeMMEEarlyStatusTransferIEValueMethodEncodeFresh(v MMEEarlyStatusTransferIEValue, a0 bool, a1 *aper.DecodeBudget) ([]byte, error) {
	return v.encodeFresh(a0, a1)
}
func BridgeMMEEarlyStatusTransferIEValueMethodMatchesID(v MMEEarlyStatusTransferIEValue, a0 s00.ProtocolIEID, a1 ...*aper.DecodeBudget) bool {
	return v.matchesID(a0, a1...)
}
func BridgeMMEEarlyStatusTransferIEValueMethodReason(v MMEEarlyStatusTransferIEValue, a0 s00.ProtocolIEID) aper.OpaqueReason {
	return v.reason(a0)
}
func BridgeMMEEarlyStatusTransferIEValueMethodRule(v MMEEarlyStatusTransferIEValue) aper.SourceRule {
	return v.rule()
}
func BridgeMMEEarlyStatusTransferIEValueProtocolErrorIEContainerListAPERValueFieldContext(v *MMEEarlyStatusTransferIEValueProtocolErrorIEContainerListAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeMMEEarlyStatusTransferIEValueProtocolErrorIEContainerListAPERValueFieldReceived(v *MMEEarlyStatusTransferIEValueProtocolErrorIEContainerListAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeMMEEarlyStatusTransferIEValueProtocolErrorIEContainerListAPERValueFieldReplay(v *MMEEarlyStatusTransferIEValueProtocolErrorIEContainerListAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeMMEEarlyStatusTransferIEValueProtocolErrorIEContainerListAPERValueFieldWithoutReplay(v *MMEEarlyStatusTransferIEValueProtocolErrorIEContainerListAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeMMEEarlyStatusTransferIEValueProtocolErrorIEContainerListValueCodecFieldCapture(v *MMEEarlyStatusTransferIEValueProtocolErrorIEContainerListValueCodec) *func(MMEEarlyStatusTransferIEValueProtocolErrorIEContainerList, aper.DecodeState) (MMEEarlyStatusTransferIEValueProtocolErrorIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgeMMEEarlyStatusTransferIEValueProtocolErrorIEContainerListValueCodecFieldCompare(v *MMEEarlyStatusTransferIEValueProtocolErrorIEContainerListValueCodec) *func(MMEEarlyStatusTransferIEValueProtocolErrorIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeMMEEarlyStatusTransferIEValueProtocolErrorIEContainerListValueCodecFieldContext(v *MMEEarlyStatusTransferIEValueProtocolErrorIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeMMEEarlyStatusTransferIEValueProtocolErrorIEContainerListValueCodecFieldDecode(v *MMEEarlyStatusTransferIEValueProtocolErrorIEContainerListValueCodec) *func([]byte, aper.DecodeState) (MMEEarlyStatusTransferIEValueProtocolErrorIEContainerList, error) {
	return &v.decode
}
func BridgeMMEEarlyStatusTransferIEValueProtocolErrorIEContainerListValueCodecFieldEncode(v *MMEEarlyStatusTransferIEValueProtocolErrorIEContainerListValueCodec) *func(MMEEarlyStatusTransferIEValueProtocolErrorIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeMMEEarlyStatusTransferIEValueProtocolErrorIEContainerListValueCodecFieldPath(v *MMEEarlyStatusTransferIEValueProtocolErrorIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgeMMEEarlyStatusTransferIEValueProtocolErrorIEContainerListValueCodecMethodEncodeBudgetValue(v MMEEarlyStatusTransferIEValueProtocolErrorIEContainerListValueCodec, a0 MMEEarlyStatusTransferIEValueProtocolErrorIEContainerList, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeMMEEarlyStatusTransferIEValueProtocolErrorIEContainerListValueCodecMethodEncodeChanged(v MMEEarlyStatusTransferIEValueProtocolErrorIEContainerListValueCodec, a0 MMEEarlyStatusTransferIEValueProtocolErrorIEContainerList, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeMMEEarlyStatusTransferIEValueProtocolIEContainerListAPERValueFieldContext(v *MMEEarlyStatusTransferIEValueProtocolIEContainerListAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeMMEEarlyStatusTransferIEValueProtocolIEContainerListAPERValueFieldReceived(v *MMEEarlyStatusTransferIEValueProtocolIEContainerListAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeMMEEarlyStatusTransferIEValueProtocolIEContainerListAPERValueFieldReplay(v *MMEEarlyStatusTransferIEValueProtocolIEContainerListAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeMMEEarlyStatusTransferIEValueProtocolIEContainerListAPERValueFieldWithoutReplay(v *MMEEarlyStatusTransferIEValueProtocolIEContainerListAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeMMEEarlyStatusTransferIEValueProtocolIEContainerListValueCodecFieldCapture(v *MMEEarlyStatusTransferIEValueProtocolIEContainerListValueCodec) *func(MMEEarlyStatusTransferIEValueProtocolIEContainerList, aper.DecodeState) (MMEEarlyStatusTransferIEValueProtocolIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgeMMEEarlyStatusTransferIEValueProtocolIEContainerListValueCodecFieldCompare(v *MMEEarlyStatusTransferIEValueProtocolIEContainerListValueCodec) *func(MMEEarlyStatusTransferIEValueProtocolIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeMMEEarlyStatusTransferIEValueProtocolIEContainerListValueCodecFieldContext(v *MMEEarlyStatusTransferIEValueProtocolIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeMMEEarlyStatusTransferIEValueProtocolIEContainerListValueCodecFieldDecode(v *MMEEarlyStatusTransferIEValueProtocolIEContainerListValueCodec) *func([]byte, aper.DecodeState) (MMEEarlyStatusTransferIEValueProtocolIEContainerList, error) {
	return &v.decode
}
func BridgeMMEEarlyStatusTransferIEValueProtocolIEContainerListValueCodecFieldEncode(v *MMEEarlyStatusTransferIEValueProtocolIEContainerListValueCodec) *func(MMEEarlyStatusTransferIEValueProtocolIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeMMEEarlyStatusTransferIEValueProtocolIEContainerListValueCodecFieldPath(v *MMEEarlyStatusTransferIEValueProtocolIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgeMMEEarlyStatusTransferIEValueProtocolIEContainerListValueCodecMethodEncodeBudgetValue(v MMEEarlyStatusTransferIEValueProtocolIEContainerListValueCodec, a0 MMEEarlyStatusTransferIEValueProtocolIEContainerList, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeMMEEarlyStatusTransferIEValueProtocolIEContainerListValueCodecMethodEncodeChanged(v MMEEarlyStatusTransferIEValueProtocolIEContainerListValueCodec, a0 MMEEarlyStatusTransferIEValueProtocolIEContainerList, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeMMEEarlyStatusTransferMMEUES1APIDIEBindingFieldCodec(v *MMEEarlyStatusTransferMMEUES1APIDIEBinding) *s01.MMEUES1APIDValueCodec {
	return &v.codec
}
func BridgeMMEEarlyStatusTransferMMEUES1APIDIEBindingFieldGet(v *MMEEarlyStatusTransferMMEUES1APIDIEBinding) *func(*MMEEarlyStatusTransferIEValue) (*s00.MMEUES1APID, bool) {
	return &v.get
}
func BridgeMMEEarlyStatusTransferMMEUES1APIDIEBindingFieldInfo(v *MMEEarlyStatusTransferMMEUES1APIDIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeMMEEarlyStatusTransferMMEUES1APIDIEBindingFieldInject(v *MMEEarlyStatusTransferMMEUES1APIDIEBinding) *func(s00.MMEUES1APID) MMEEarlyStatusTransferIEValue {
	return &v.inject
}
func BridgeUEContextReleaseCommandAPERValueFieldContext(v *UEContextReleaseCommandAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeUEContextReleaseCommandAPERValueFieldReceived(v *UEContextReleaseCommandAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeUEContextReleaseCommandAPERValueFieldReplay(v *UEContextReleaseCommandAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeUEContextReleaseCommandAPERValueFieldWithoutReplay(v *UEContextReleaseCommandAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeUEContextReleaseCommandCauseIEBindingFieldCodec(v *UEContextReleaseCommandCauseIEBinding) *s14.CauseValueCodec {
	return &v.codec
}
func BridgeUEContextReleaseCommandCauseIEBindingFieldGet(v *UEContextReleaseCommandCauseIEBinding) *func(*UEContextReleaseCommandIEValue) (*s14.Cause, bool) {
	return &v.get
}
func BridgeUEContextReleaseCommandCauseIEBindingFieldInfo(v *UEContextReleaseCommandCauseIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeUEContextReleaseCommandCauseIEBindingFieldInject(v *UEContextReleaseCommandCauseIEBinding) *func(s14.Cause) UEContextReleaseCommandIEValue {
	return &v.inject
}
func BridgeUEContextReleaseCommandFieldExtCount(v *UEContextReleaseCommand) *int64 {
	return &v.extCount
}
func BridgeUEContextReleaseCommandFieldExtData(v *UEContextReleaseCommand) *[][]byte {
	return &v.extData
}
func BridgeUEContextReleaseCommandFieldExtOrigin(v *UEContextReleaseCommand) *[]aper.OpaqueOrigin {
	return &v.extOrigin
}
func BridgeUEContextReleaseCommandFieldExtPresent(v *UEContextReleaseCommand) *[]bool {
	return &v.extPresent
}
func BridgeUEContextReleaseCommandFieldExtWire(v *UEContextReleaseCommand) *[]aper.WireSpan {
	return &v.extWire
}
func BridgeUEContextReleaseCommandFieldPerExtPadding(v *UEContextReleaseCommand) *[]aper.CompletePadding {
	return &v.perExtPadding
}
func BridgeUEContextReleaseCommandFieldPerPadding(v *UEContextReleaseCommand) *aper.FinalPadding {
	return &v.perPadding
}
func BridgeUEContextReleaseCommandFieldProtocolIEsIndef(v *UEContextReleaseCommand) *bool {
	return &v.protocolIEsIndef
}
func BridgeUEContextReleaseCommandFieldReceived(v *UEContextReleaseCommand) *bool { return &v.received }
func BridgeUEContextReleaseCommandFieldReceivedAbsolute(v *UEContextReleaseCommand) *bool {
	return &v.receivedAbsolute
}
func BridgeUEContextReleaseCommandFieldReceivedBytes(v *UEContextReleaseCommand) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeUEContextReleaseCommandFieldReceivedLocation(v *UEContextReleaseCommand) *aper.Location {
	return &v.receivedLocation
}
func BridgeUEContextReleaseCommandFieldReplay(v *UEContextReleaseCommand) *aper.Snapshot {
	return &v.replay
}
func BridgeUEContextReleaseCommandFieldStream(v *UEContextReleaseCommand) *aper.WireSpan {
	return &v.stream
}
func BridgeUEContextReleaseCommandFieldWithoutReplay(v *UEContextReleaseCommand) *bool {
	return &v.withoutReplay
}
func BridgeUEContextReleaseCommandIEContainerAPERValueFieldContext(v *UEContextReleaseCommandIEContainerAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeUEContextReleaseCommandIEContainerAPERValueFieldReceived(v *UEContextReleaseCommandIEContainerAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeUEContextReleaseCommandIEContainerAPERValueFieldReplay(v *UEContextReleaseCommandIEContainerAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeUEContextReleaseCommandIEContainerAPERValueFieldWithoutReplay(v *UEContextReleaseCommandIEContainerAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeUEContextReleaseCommandIEContainerValueCodecFieldCapture(v *UEContextReleaseCommandIEContainerValueCodec) *func(UEContextReleaseCommandIEContainer, aper.DecodeState) (UEContextReleaseCommandIEContainer, aper.Snapshot) {
	return &v.capture
}
func BridgeUEContextReleaseCommandIEContainerValueCodecFieldCompare(v *UEContextReleaseCommandIEContainerValueCodec) *func(UEContextReleaseCommandIEContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeUEContextReleaseCommandIEContainerValueCodecFieldContext(v *UEContextReleaseCommandIEContainerValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeUEContextReleaseCommandIEContainerValueCodecFieldDecode(v *UEContextReleaseCommandIEContainerValueCodec) *func([]byte, aper.DecodeState) (UEContextReleaseCommandIEContainer, error) {
	return &v.decode
}
func BridgeUEContextReleaseCommandIEContainerValueCodecFieldEncode(v *UEContextReleaseCommandIEContainerValueCodec) *func(UEContextReleaseCommandIEContainer, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeUEContextReleaseCommandIEContainerValueCodecFieldPath(v *UEContextReleaseCommandIEContainerValueCodec) *aper.Path {
	return &v.path
}
func BridgeUEContextReleaseCommandIEContainerValueCodecMethodEncodeBudgetValue(v UEContextReleaseCommandIEContainerValueCodec, a0 UEContextReleaseCommandIEContainer, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeUEContextReleaseCommandIEContainerValueCodecMethodEncodeChanged(v UEContextReleaseCommandIEContainerValueCodec, a0 UEContextReleaseCommandIEContainer, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeUEContextReleaseCommandIEFieldAPERValueFieldContext(v *UEContextReleaseCommandIEFieldAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeUEContextReleaseCommandIEFieldAPERValueFieldReceived(v *UEContextReleaseCommandIEFieldAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeUEContextReleaseCommandIEFieldAPERValueFieldReplay(v *UEContextReleaseCommandIEFieldAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeUEContextReleaseCommandIEFieldAPERValueFieldWithoutReplay(v *UEContextReleaseCommandIEFieldAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeUEContextReleaseCommandIEFieldFieldReceived(v *UEContextReleaseCommandIEField) *aper.CompletePadding {
	return &v.received
}
func BridgeUEContextReleaseCommandIEFieldFieldReplay(v *UEContextReleaseCommandIEField) *aper.Snapshot {
	return &v.replay
}
func BridgeUEContextReleaseCommandIEFieldFieldStream(v *UEContextReleaseCommandIEField) *aper.WireSpan {
	return &v.stream
}
func BridgeUEContextReleaseCommandIEFieldFieldWithoutReplay(v *UEContextReleaseCommandIEField) *bool {
	return &v.withoutReplay
}
func BridgeUEContextReleaseCommandIEFieldMethodMarshalAPERTo(v *UEContextReleaseCommandIEField, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeUEContextReleaseCommandIEFieldMethodUnmarshalAPERFrom(v *UEContextReleaseCommandIEField, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeUEContextReleaseCommandIEFieldValueCodecFieldCapture(v *UEContextReleaseCommandIEFieldValueCodec) *func(UEContextReleaseCommandIEField, aper.DecodeState) (UEContextReleaseCommandIEField, aper.Snapshot) {
	return &v.capture
}
func BridgeUEContextReleaseCommandIEFieldValueCodecFieldCompare(v *UEContextReleaseCommandIEFieldValueCodec) *func(UEContextReleaseCommandIEField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeUEContextReleaseCommandIEFieldValueCodecFieldContext(v *UEContextReleaseCommandIEFieldValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeUEContextReleaseCommandIEFieldValueCodecFieldDecode(v *UEContextReleaseCommandIEFieldValueCodec) *func([]byte, aper.DecodeState) (UEContextReleaseCommandIEField, error) {
	return &v.decode
}
func BridgeUEContextReleaseCommandIEFieldValueCodecFieldEncode(v *UEContextReleaseCommandIEFieldValueCodec) *func(UEContextReleaseCommandIEField, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeUEContextReleaseCommandIEFieldValueCodecFieldPath(v *UEContextReleaseCommandIEFieldValueCodec) *aper.Path {
	return &v.path
}
func BridgeUEContextReleaseCommandIEFieldValueCodecMethodEncodeBudgetValue(v UEContextReleaseCommandIEFieldValueCodec, a0 UEContextReleaseCommandIEField, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeUEContextReleaseCommandIEFieldValueCodecMethodEncodeChanged(v UEContextReleaseCommandIEFieldValueCodec, a0 UEContextReleaseCommandIEField, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeUEContextReleaseCommandIETableMethodInfoCause(v UEContextReleaseCommandIETable) s00.FieldInfo {
	return v.infoCause()
}
func BridgeUEContextReleaseCommandIETableMethodInfoUES1APIDs(v UEContextReleaseCommandIETable) s00.FieldInfo {
	return v.infoUES1APIDs()
}
func BridgeUEContextReleaseCommandIEValueERABIEContainerListAPERValueFieldContext(v *UEContextReleaseCommandIEValueERABIEContainerListAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeUEContextReleaseCommandIEValueERABIEContainerListAPERValueFieldReceived(v *UEContextReleaseCommandIEValueERABIEContainerListAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeUEContextReleaseCommandIEValueERABIEContainerListAPERValueFieldReplay(v *UEContextReleaseCommandIEValueERABIEContainerListAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeUEContextReleaseCommandIEValueERABIEContainerListAPERValueFieldWithoutReplay(v *UEContextReleaseCommandIEValueERABIEContainerListAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeUEContextReleaseCommandIEValueERABIEContainerListValueCodecFieldCapture(v *UEContextReleaseCommandIEValueERABIEContainerListValueCodec) *func(UEContextReleaseCommandIEValueERABIEContainerList, aper.DecodeState) (UEContextReleaseCommandIEValueERABIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgeUEContextReleaseCommandIEValueERABIEContainerListValueCodecFieldCompare(v *UEContextReleaseCommandIEValueERABIEContainerListValueCodec) *func(UEContextReleaseCommandIEValueERABIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeUEContextReleaseCommandIEValueERABIEContainerListValueCodecFieldContext(v *UEContextReleaseCommandIEValueERABIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeUEContextReleaseCommandIEValueERABIEContainerListValueCodecFieldDecode(v *UEContextReleaseCommandIEValueERABIEContainerListValueCodec) *func([]byte, aper.DecodeState) (UEContextReleaseCommandIEValueERABIEContainerList, error) {
	return &v.decode
}
func BridgeUEContextReleaseCommandIEValueERABIEContainerListValueCodecFieldEncode(v *UEContextReleaseCommandIEValueERABIEContainerListValueCodec) *func(UEContextReleaseCommandIEValueERABIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeUEContextReleaseCommandIEValueERABIEContainerListValueCodecFieldPath(v *UEContextReleaseCommandIEValueERABIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgeUEContextReleaseCommandIEValueERABIEContainerListValueCodecMethodEncodeBudgetValue(v UEContextReleaseCommandIEValueERABIEContainerListValueCodec, a0 UEContextReleaseCommandIEValueERABIEContainerList, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeUEContextReleaseCommandIEValueERABIEContainerListValueCodecMethodEncodeChanged(v UEContextReleaseCommandIEValueERABIEContainerListValueCodec, a0 UEContextReleaseCommandIEValueERABIEContainerList, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeUEContextReleaseCommandIEValueFieldId(v *UEContextReleaseCommandIEValue) *s00.ProtocolIEID {
	return &v.id
}
func BridgeUEContextReleaseCommandIEValueFieldIsOpaque(v *UEContextReleaseCommandIEValue) *bool {
	return &v.isOpaque
}
func BridgeUEContextReleaseCommandIEValueFieldOpaque(v *UEContextReleaseCommandIEValue) *aper.OpaqueOpenType {
	return &v.opaque
}
func BridgeUEContextReleaseCommandIEValueFieldReceived(v *UEContextReleaseCommandIEValue) *aper.WireSpan {
	return &v.received
}
func BridgeUEContextReleaseCommandIEValueFieldReplay(v *UEContextReleaseCommandIEValue) *aper.Snapshot {
	return &v.replay
}
func BridgeUEContextReleaseCommandIEValueFieldRowCause(v *UEContextReleaseCommandIEValue) **s14.Cause {
	return &v.rowCause
}
func BridgeUEContextReleaseCommandIEValueFieldRowUES1APIDs(v *UEContextReleaseCommandIEValue) **UES1APIDs {
	return &v.rowUES1APIDs
}
func BridgeUEContextReleaseCommandIEValueMethodCaptureSemantics(v UEContextReleaseCommandIEValue, a0 aper.SemanticCapture) UEContextReleaseCommandIEValue {
	return v.captureSemantics(a0)
}
func BridgeUEContextReleaseCommandIEValueMethodCompareSemantics(v UEContextReleaseCommandIEValue, a0 aper.SemanticComparison) aper.SemanticComparison {
	return v.compareSemantics(a0)
}
func BridgeUEContextReleaseCommandIEValueMethodDecode(v UEContextReleaseCommandIEValue, a0 s00.ProtocolIEID, a1 aper.OpaqueOpenType) (UEContextReleaseCommandIEValue, error) {
	return v.decode(a0, a1)
}
func BridgeUEContextReleaseCommandIEValueMethodEncode(v UEContextReleaseCommandIEValue) ([]byte, error) {
	return v.encode()
}
func BridgeUEContextReleaseCommandIEValueMethodEncodeFresh(v UEContextReleaseCommandIEValue, a0 bool, a1 *aper.DecodeBudget) ([]byte, error) {
	return v.encodeFresh(a0, a1)
}
func BridgeUEContextReleaseCommandIEValueMethodMatchesID(v UEContextReleaseCommandIEValue, a0 s00.ProtocolIEID, a1 ...*aper.DecodeBudget) bool {
	return v.matchesID(a0, a1...)
}
func BridgeUEContextReleaseCommandIEValueMethodReason(v UEContextReleaseCommandIEValue, a0 s00.ProtocolIEID) aper.OpaqueReason {
	return v.reason(a0)
}
func BridgeUEContextReleaseCommandIEValueMethodRule(v UEContextReleaseCommandIEValue) aper.SourceRule {
	return v.rule()
}
func BridgeUEContextReleaseCommandIEValueProtocolErrorIEContainerListAPERValueFieldContext(v *UEContextReleaseCommandIEValueProtocolErrorIEContainerListAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeUEContextReleaseCommandIEValueProtocolErrorIEContainerListAPERValueFieldReceived(v *UEContextReleaseCommandIEValueProtocolErrorIEContainerListAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeUEContextReleaseCommandIEValueProtocolErrorIEContainerListAPERValueFieldReplay(v *UEContextReleaseCommandIEValueProtocolErrorIEContainerListAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeUEContextReleaseCommandIEValueProtocolErrorIEContainerListAPERValueFieldWithoutReplay(v *UEContextReleaseCommandIEValueProtocolErrorIEContainerListAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeUEContextReleaseCommandIEValueProtocolErrorIEContainerListValueCodecFieldCapture(v *UEContextReleaseCommandIEValueProtocolErrorIEContainerListValueCodec) *func(UEContextReleaseCommandIEValueProtocolErrorIEContainerList, aper.DecodeState) (UEContextReleaseCommandIEValueProtocolErrorIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgeUEContextReleaseCommandIEValueProtocolErrorIEContainerListValueCodecFieldCompare(v *UEContextReleaseCommandIEValueProtocolErrorIEContainerListValueCodec) *func(UEContextReleaseCommandIEValueProtocolErrorIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeUEContextReleaseCommandIEValueProtocolErrorIEContainerListValueCodecFieldContext(v *UEContextReleaseCommandIEValueProtocolErrorIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeUEContextReleaseCommandIEValueProtocolErrorIEContainerListValueCodecFieldDecode(v *UEContextReleaseCommandIEValueProtocolErrorIEContainerListValueCodec) *func([]byte, aper.DecodeState) (UEContextReleaseCommandIEValueProtocolErrorIEContainerList, error) {
	return &v.decode
}
func BridgeUEContextReleaseCommandIEValueProtocolErrorIEContainerListValueCodecFieldEncode(v *UEContextReleaseCommandIEValueProtocolErrorIEContainerListValueCodec) *func(UEContextReleaseCommandIEValueProtocolErrorIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeUEContextReleaseCommandIEValueProtocolErrorIEContainerListValueCodecFieldPath(v *UEContextReleaseCommandIEValueProtocolErrorIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgeUEContextReleaseCommandIEValueProtocolErrorIEContainerListValueCodecMethodEncodeBudgetValue(v UEContextReleaseCommandIEValueProtocolErrorIEContainerListValueCodec, a0 UEContextReleaseCommandIEValueProtocolErrorIEContainerList, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeUEContextReleaseCommandIEValueProtocolErrorIEContainerListValueCodecMethodEncodeChanged(v UEContextReleaseCommandIEValueProtocolErrorIEContainerListValueCodec, a0 UEContextReleaseCommandIEValueProtocolErrorIEContainerList, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeUEContextReleaseCommandIEValueProtocolIEContainerListAPERValueFieldContext(v *UEContextReleaseCommandIEValueProtocolIEContainerListAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeUEContextReleaseCommandIEValueProtocolIEContainerListAPERValueFieldReceived(v *UEContextReleaseCommandIEValueProtocolIEContainerListAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeUEContextReleaseCommandIEValueProtocolIEContainerListAPERValueFieldReplay(v *UEContextReleaseCommandIEValueProtocolIEContainerListAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeUEContextReleaseCommandIEValueProtocolIEContainerListAPERValueFieldWithoutReplay(v *UEContextReleaseCommandIEValueProtocolIEContainerListAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeUEContextReleaseCommandIEValueProtocolIEContainerListValueCodecFieldCapture(v *UEContextReleaseCommandIEValueProtocolIEContainerListValueCodec) *func(UEContextReleaseCommandIEValueProtocolIEContainerList, aper.DecodeState) (UEContextReleaseCommandIEValueProtocolIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgeUEContextReleaseCommandIEValueProtocolIEContainerListValueCodecFieldCompare(v *UEContextReleaseCommandIEValueProtocolIEContainerListValueCodec) *func(UEContextReleaseCommandIEValueProtocolIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeUEContextReleaseCommandIEValueProtocolIEContainerListValueCodecFieldContext(v *UEContextReleaseCommandIEValueProtocolIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeUEContextReleaseCommandIEValueProtocolIEContainerListValueCodecFieldDecode(v *UEContextReleaseCommandIEValueProtocolIEContainerListValueCodec) *func([]byte, aper.DecodeState) (UEContextReleaseCommandIEValueProtocolIEContainerList, error) {
	return &v.decode
}
func BridgeUEContextReleaseCommandIEValueProtocolIEContainerListValueCodecFieldEncode(v *UEContextReleaseCommandIEValueProtocolIEContainerListValueCodec) *func(UEContextReleaseCommandIEValueProtocolIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeUEContextReleaseCommandIEValueProtocolIEContainerListValueCodecFieldPath(v *UEContextReleaseCommandIEValueProtocolIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgeUEContextReleaseCommandIEValueProtocolIEContainerListValueCodecMethodEncodeBudgetValue(v UEContextReleaseCommandIEValueProtocolIEContainerListValueCodec, a0 UEContextReleaseCommandIEValueProtocolIEContainerList, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeUEContextReleaseCommandIEValueProtocolIEContainerListValueCodecMethodEncodeChanged(v UEContextReleaseCommandIEValueProtocolIEContainerListValueCodec, a0 UEContextReleaseCommandIEValueProtocolIEContainerList, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeUEContextReleaseCommandMethodMarshalAPERBudget(v *UEContextReleaseCommand, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeUEContextReleaseCommandMethodMarshalAPERBudgetValue(v *UEContextReleaseCommand, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudgetValue(a0, a1)
}
func BridgeUEContextReleaseCommandMethodMarshalAPERChanged(v *UEContextReleaseCommand, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeUEContextReleaseCommandMethodMarshalAPERChangedValue(v *UEContextReleaseCommand, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeUEContextReleaseCommandMethodMarshalAPERLegacy(v *UEContextReleaseCommand) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeUEContextReleaseCommandMethodMarshalAPERNewValue(v *UEContextReleaseCommand, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERNewValue(a0, a1)
}
func BridgeUEContextReleaseCommandMethodMarshalAPERPlanned(v *UEContextReleaseCommand, a0 *aper.DecodeBudget, a1 bool, a2 *aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1, a2)
}
func BridgeUEContextReleaseCommandMethodMarshalAPERTo(v *UEContextReleaseCommand, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeUEContextReleaseCommandMethodUnmarshalAPERFrom(v *UEContextReleaseCommand, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeUEContextReleaseCommandMethodUnmarshalAPERLegacy(v *UEContextReleaseCommand, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeUEContextReleaseCommandMethodUnmarshalAPERWithOptions(v *UEContextReleaseCommand, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeUEContextReleaseCommandUES1APIDsIEBindingFieldCodec(v *UEContextReleaseCommandUES1APIDsIEBinding) *UES1APIDsValueCodec {
	return &v.codec
}
func BridgeUEContextReleaseCommandUES1APIDsIEBindingFieldGet(v *UEContextReleaseCommandUES1APIDsIEBinding) *func(*UEContextReleaseCommandIEValue) (*UES1APIDs, bool) {
	return &v.get
}
func BridgeUEContextReleaseCommandUES1APIDsIEBindingFieldInfo(v *UEContextReleaseCommandUES1APIDsIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeUEContextReleaseCommandUES1APIDsIEBindingFieldInject(v *UEContextReleaseCommandUES1APIDsIEBinding) *func(UES1APIDs) UEContextReleaseCommandIEValue {
	return &v.inject
}
func BridgeUEContextReleaseCommandValueCodecFieldCapture(v *UEContextReleaseCommandValueCodec) *func(UEContextReleaseCommand, aper.DecodeState) (UEContextReleaseCommand, aper.Snapshot) {
	return &v.capture
}
func BridgeUEContextReleaseCommandValueCodecFieldCompare(v *UEContextReleaseCommandValueCodec) *func(UEContextReleaseCommand, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeUEContextReleaseCommandValueCodecFieldContext(v *UEContextReleaseCommandValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeUEContextReleaseCommandValueCodecFieldDecode(v *UEContextReleaseCommandValueCodec) *func([]byte, aper.DecodeState) (UEContextReleaseCommand, error) {
	return &v.decode
}
func BridgeUEContextReleaseCommandValueCodecFieldEncode(v *UEContextReleaseCommandValueCodec) *func(UEContextReleaseCommand, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeUEContextReleaseCommandValueCodecFieldPath(v *UEContextReleaseCommandValueCodec) *aper.Path {
	return &v.path
}
func BridgeUEContextReleaseCommandValueCodecMethodEncodeBudgetValue(v UEContextReleaseCommandValueCodec, a0 UEContextReleaseCommand, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeUEContextReleaseCommandValueCodecMethodEncodeChanged(v UEContextReleaseCommandValueCodec, a0 UEContextReleaseCommand, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeUERadioCapabilityMatchResponseAPERValueFieldContext(v *UERadioCapabilityMatchResponseAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeUERadioCapabilityMatchResponseAPERValueFieldReceived(v *UERadioCapabilityMatchResponseAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeUERadioCapabilityMatchResponseAPERValueFieldReplay(v *UERadioCapabilityMatchResponseAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeUERadioCapabilityMatchResponseAPERValueFieldWithoutReplay(v *UERadioCapabilityMatchResponseAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeUERadioCapabilityMatchResponseFieldExtCount(v *UERadioCapabilityMatchResponse) *int64 {
	return &v.extCount
}
func BridgeUERadioCapabilityMatchResponseFieldExtData(v *UERadioCapabilityMatchResponse) *[][]byte {
	return &v.extData
}
func BridgeUERadioCapabilityMatchResponseFieldExtOrigin(v *UERadioCapabilityMatchResponse) *[]aper.OpaqueOrigin {
	return &v.extOrigin
}
func BridgeUERadioCapabilityMatchResponseFieldExtPresent(v *UERadioCapabilityMatchResponse) *[]bool {
	return &v.extPresent
}
func BridgeUERadioCapabilityMatchResponseFieldExtWire(v *UERadioCapabilityMatchResponse) *[]aper.WireSpan {
	return &v.extWire
}
func BridgeUERadioCapabilityMatchResponseFieldPerExtPadding(v *UERadioCapabilityMatchResponse) *[]aper.CompletePadding {
	return &v.perExtPadding
}
func BridgeUERadioCapabilityMatchResponseFieldPerPadding(v *UERadioCapabilityMatchResponse) *aper.FinalPadding {
	return &v.perPadding
}
func BridgeUERadioCapabilityMatchResponseFieldProtocolIEsIndef(v *UERadioCapabilityMatchResponse) *bool {
	return &v.protocolIEsIndef
}
func BridgeUERadioCapabilityMatchResponseFieldReceived(v *UERadioCapabilityMatchResponse) *bool {
	return &v.received
}
func BridgeUERadioCapabilityMatchResponseFieldReceivedAbsolute(v *UERadioCapabilityMatchResponse) *bool {
	return &v.receivedAbsolute
}
func BridgeUERadioCapabilityMatchResponseFieldReceivedBytes(v *UERadioCapabilityMatchResponse) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeUERadioCapabilityMatchResponseFieldReceivedLocation(v *UERadioCapabilityMatchResponse) *aper.Location {
	return &v.receivedLocation
}
func BridgeUERadioCapabilityMatchResponseFieldReplay(v *UERadioCapabilityMatchResponse) *aper.Snapshot {
	return &v.replay
}
func BridgeUERadioCapabilityMatchResponseFieldStream(v *UERadioCapabilityMatchResponse) *aper.WireSpan {
	return &v.stream
}
func BridgeUERadioCapabilityMatchResponseFieldWithoutReplay(v *UERadioCapabilityMatchResponse) *bool {
	return &v.withoutReplay
}
func BridgeUERadioCapabilityMatchResponseMethodMarshalAPERBudget(v *UERadioCapabilityMatchResponse, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeUERadioCapabilityMatchResponseMethodMarshalAPERBudgetValue(v *UERadioCapabilityMatchResponse, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudgetValue(a0, a1)
}
func BridgeUERadioCapabilityMatchResponseMethodMarshalAPERChanged(v *UERadioCapabilityMatchResponse, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeUERadioCapabilityMatchResponseMethodMarshalAPERChangedValue(v *UERadioCapabilityMatchResponse, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeUERadioCapabilityMatchResponseMethodMarshalAPERLegacy(v *UERadioCapabilityMatchResponse) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeUERadioCapabilityMatchResponseMethodMarshalAPERNewValue(v *UERadioCapabilityMatchResponse, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERNewValue(a0, a1)
}
func BridgeUERadioCapabilityMatchResponseMethodMarshalAPERPlanned(v *UERadioCapabilityMatchResponse, a0 *aper.DecodeBudget, a1 bool, a2 *aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1, a2)
}
func BridgeUERadioCapabilityMatchResponseMethodMarshalAPERTo(v *UERadioCapabilityMatchResponse, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeUERadioCapabilityMatchResponseMethodUnmarshalAPERFrom(v *UERadioCapabilityMatchResponse, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeUERadioCapabilityMatchResponseMethodUnmarshalAPERLegacy(v *UERadioCapabilityMatchResponse, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeUERadioCapabilityMatchResponseMethodUnmarshalAPERWithOptions(v *UERadioCapabilityMatchResponse, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeUERadioCapabilityMatchResponseValueCodecFieldCapture(v *UERadioCapabilityMatchResponseValueCodec) *func(UERadioCapabilityMatchResponse, aper.DecodeState) (UERadioCapabilityMatchResponse, aper.Snapshot) {
	return &v.capture
}
func BridgeUERadioCapabilityMatchResponseValueCodecFieldCompare(v *UERadioCapabilityMatchResponseValueCodec) *func(UERadioCapabilityMatchResponse, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeUERadioCapabilityMatchResponseValueCodecFieldContext(v *UERadioCapabilityMatchResponseValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeUERadioCapabilityMatchResponseValueCodecFieldDecode(v *UERadioCapabilityMatchResponseValueCodec) *func([]byte, aper.DecodeState) (UERadioCapabilityMatchResponse, error) {
	return &v.decode
}
func BridgeUERadioCapabilityMatchResponseValueCodecFieldEncode(v *UERadioCapabilityMatchResponseValueCodec) *func(UERadioCapabilityMatchResponse, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeUERadioCapabilityMatchResponseValueCodecFieldPath(v *UERadioCapabilityMatchResponseValueCodec) *aper.Path {
	return &v.path
}
func BridgeUERadioCapabilityMatchResponseValueCodecMethodEncodeBudgetValue(v UERadioCapabilityMatchResponseValueCodec, a0 UERadioCapabilityMatchResponse, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeUERadioCapabilityMatchResponseValueCodecMethodEncodeChanged(v UERadioCapabilityMatchResponseValueCodec, a0 UERadioCapabilityMatchResponse, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeUES1APIDPairAPERValueFieldContext(v *UES1APIDPairAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeUES1APIDPairAPERValueFieldReceived(v *UES1APIDPairAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeUES1APIDPairAPERValueFieldReplay(v *UES1APIDPairAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeUES1APIDPairAPERValueFieldWithoutReplay(v *UES1APIDPairAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeUES1APIDPairFieldExtCount(v *UES1APIDPair) *int64                { return &v.extCount }
func BridgeUES1APIDPairFieldExtData(v *UES1APIDPair) *[][]byte              { return &v.extData }
func BridgeUES1APIDPairFieldExtOrigin(v *UES1APIDPair) *[]aper.OpaqueOrigin { return &v.extOrigin }
func BridgeUES1APIDPairFieldExtPresent(v *UES1APIDPair) *[]bool             { return &v.extPresent }
func BridgeUES1APIDPairFieldExtWire(v *UES1APIDPair) *[]aper.WireSpan       { return &v.extWire }
func BridgeUES1APIDPairFieldIEExtensionsIndef(v *UES1APIDPair) *bool        { return &v.iEExtensionsIndef }
func BridgeUES1APIDPairFieldPerExtPadding(v *UES1APIDPair) *[]aper.CompletePadding {
	return &v.perExtPadding
}
func BridgeUES1APIDPairFieldPerPadding(v *UES1APIDPair) *aper.FinalPadding { return &v.perPadding }
func BridgeUES1APIDPairFieldReceived(v *UES1APIDPair) *bool                { return &v.received }
func BridgeUES1APIDPairFieldReceivedAbsolute(v *UES1APIDPair) *bool        { return &v.receivedAbsolute }
func BridgeUES1APIDPairFieldReceivedBytes(v *UES1APIDPair) *aper.WireSpan  { return &v.receivedBytes }
func BridgeUES1APIDPairFieldReceivedLocation(v *UES1APIDPair) *aper.Location {
	return &v.receivedLocation
}
func BridgeUES1APIDPairFieldReplay(v *UES1APIDPair) *aper.Snapshot { return &v.replay }
func BridgeUES1APIDPairFieldStream(v *UES1APIDPair) *aper.WireSpan { return &v.stream }
func BridgeUES1APIDPairFieldWithoutReplay(v *UES1APIDPair) *bool   { return &v.withoutReplay }
func BridgeUES1APIDPairMethodMarshalAPERBudget(v *UES1APIDPair, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeUES1APIDPairMethodMarshalAPERBudgetValue(v *UES1APIDPair, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudgetValue(a0, a1)
}
func BridgeUES1APIDPairMethodMarshalAPERChanged(v *UES1APIDPair, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeUES1APIDPairMethodMarshalAPERChangedValue(v *UES1APIDPair, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeUES1APIDPairMethodMarshalAPERLegacy(v *UES1APIDPair) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeUES1APIDPairMethodMarshalAPERNewValue(v *UES1APIDPair, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERNewValue(a0, a1)
}
func BridgeUES1APIDPairMethodMarshalAPERPlanned(v *UES1APIDPair, a0 *aper.DecodeBudget, a1 bool, a2 *aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1, a2)
}
func BridgeUES1APIDPairMethodMarshalAPERTo(v *UES1APIDPair, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeUES1APIDPairMethodUnmarshalAPERFrom(v *UES1APIDPair, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeUES1APIDPairMethodUnmarshalAPERLegacy(v *UES1APIDPair, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeUES1APIDPairMethodUnmarshalAPERWithOptions(v *UES1APIDPair, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeUES1APIDPairValueCodecFieldCapture(v *UES1APIDPairValueCodec) *func(UES1APIDPair, aper.DecodeState) (UES1APIDPair, aper.Snapshot) {
	return &v.capture
}
func BridgeUES1APIDPairValueCodecFieldCompare(v *UES1APIDPairValueCodec) *func(UES1APIDPair, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeUES1APIDPairValueCodecFieldContext(v *UES1APIDPairValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeUES1APIDPairValueCodecFieldDecode(v *UES1APIDPairValueCodec) *func([]byte, aper.DecodeState) (UES1APIDPair, error) {
	return &v.decode
}
func BridgeUES1APIDPairValueCodecFieldEncode(v *UES1APIDPairValueCodec) *func(UES1APIDPair, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeUES1APIDPairValueCodecFieldPath(v *UES1APIDPairValueCodec) *aper.Path { return &v.path }
func BridgeUES1APIDPairValueCodecMethodEncodeBudgetValue(v UES1APIDPairValueCodec, a0 UES1APIDPair, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeUES1APIDPairValueCodecMethodEncodeChanged(v UES1APIDPairValueCodec, a0 UES1APIDPair, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeUES1APIDsAPERValueFieldContext(v *UES1APIDsAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeUES1APIDsAPERValueFieldReceived(v *UES1APIDsAPERValue) *aper.WireSpan { return &v.received }
func BridgeUES1APIDsAPERValueFieldReplay(v *UES1APIDsAPERValue) *aper.Snapshot   { return &v.replay }
func BridgeUES1APIDsAPERValueFieldWithoutReplay(v *UES1APIDsAPERValue) *bool     { return &v.withoutReplay }
func BridgeUES1APIDsFieldPerOpenTypePadding(v *UES1APIDs) *aper.CompletePadding {
	return &v.perOpenTypePadding
}
func BridgeUES1APIDsFieldPerPadding(v *UES1APIDs) *aper.CompletePadding { return &v.perPadding }
func BridgeUES1APIDsFieldReceived(v *UES1APIDs) *bool                   { return &v.received }
func BridgeUES1APIDsFieldReceivedAbsolute(v *UES1APIDs) *bool           { return &v.receivedAbsolute }
func BridgeUES1APIDsFieldReceivedBytes(v *UES1APIDs) *aper.WireSpan     { return &v.receivedBytes }
func BridgeUES1APIDsFieldReceivedLocation(v *UES1APIDs) *aper.Location  { return &v.receivedLocation }
func BridgeUES1APIDsFieldReplay(v *UES1APIDs) *aper.Snapshot            { return &v.replay }
func BridgeUES1APIDsFieldStream(v *UES1APIDs) *aper.WireSpan            { return &v.stream }
func BridgeUES1APIDsFieldWithoutReplay(v *UES1APIDs) *bool              { return &v.withoutReplay }
func BridgeUES1APIDsMethodMarshalAPERBudget(v *UES1APIDs, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeUES1APIDsMethodMarshalAPERBudgetValue(v *UES1APIDs, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudgetValue(a0, a1)
}
func BridgeUES1APIDsMethodMarshalAPERChanged(v *UES1APIDs, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeUES1APIDsMethodMarshalAPERChangedValue(v *UES1APIDs, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeUES1APIDsMethodMarshalAPERLegacy(v *UES1APIDs) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeUES1APIDsMethodMarshalAPERNewValue(v *UES1APIDs, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERNewValue(a0, a1)
}
func BridgeUES1APIDsMethodMarshalAPERPlanned(v *UES1APIDs, a0 *aper.DecodeBudget, a1 bool, a2 *aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1, a2)
}
func BridgeUES1APIDsMethodMarshalAPERTo(v *UES1APIDs, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeUES1APIDsMethodUnmarshalAPERFrom(v *UES1APIDs, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeUES1APIDsMethodUnmarshalAPERLegacy(v *UES1APIDs, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeUES1APIDsMethodUnmarshalAPERWithOptions(v *UES1APIDs, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeUES1APIDsValueCodecFieldCapture(v *UES1APIDsValueCodec) *func(UES1APIDs, aper.DecodeState) (UES1APIDs, aper.Snapshot) {
	return &v.capture
}
func BridgeUES1APIDsValueCodecFieldCompare(v *UES1APIDsValueCodec) *func(UES1APIDs, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeUES1APIDsValueCodecFieldContext(v *UES1APIDsValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeUES1APIDsValueCodecFieldDecode(v *UES1APIDsValueCodec) *func([]byte, aper.DecodeState) (UES1APIDs, error) {
	return &v.decode
}
func BridgeUES1APIDsValueCodecFieldEncode(v *UES1APIDsValueCodec) *func(UES1APIDs, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeUES1APIDsValueCodecFieldPath(v *UES1APIDsValueCodec) *aper.Path { return &v.path }
func BridgeUES1APIDsValueCodecMethodEncodeBudgetValue(v UES1APIDsValueCodec, a0 UES1APIDs, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeUES1APIDsValueCodecMethodEncodeChanged(v UES1APIDsValueCodec, a0 UES1APIDs, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeUESecurityCapabilitiesAPERValueFieldContext(v *UESecurityCapabilitiesAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeUESecurityCapabilitiesAPERValueFieldReceived(v *UESecurityCapabilitiesAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeUESecurityCapabilitiesAPERValueFieldReplay(v *UESecurityCapabilitiesAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeUESecurityCapabilitiesAPERValueFieldWithoutReplay(v *UESecurityCapabilitiesAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeUESecurityCapabilitiesFieldExtCount(v *UESecurityCapabilities) *int64   { return &v.extCount }
func BridgeUESecurityCapabilitiesFieldExtData(v *UESecurityCapabilities) *[][]byte { return &v.extData }
func BridgeUESecurityCapabilitiesFieldExtOrigin(v *UESecurityCapabilities) *[]aper.OpaqueOrigin {
	return &v.extOrigin
}
func BridgeUESecurityCapabilitiesFieldExtPresent(v *UESecurityCapabilities) *[]bool {
	return &v.extPresent
}
func BridgeUESecurityCapabilitiesFieldExtWire(v *UESecurityCapabilities) *[]aper.WireSpan {
	return &v.extWire
}
func BridgeUESecurityCapabilitiesFieldIEExtensionsIndef(v *UESecurityCapabilities) *bool {
	return &v.iEExtensionsIndef
}
func BridgeUESecurityCapabilitiesFieldPerExtPadding(v *UESecurityCapabilities) *[]aper.CompletePadding {
	return &v.perExtPadding
}
func BridgeUESecurityCapabilitiesFieldPerPadding(v *UESecurityCapabilities) *aper.FinalPadding {
	return &v.perPadding
}
func BridgeUESecurityCapabilitiesFieldReceived(v *UESecurityCapabilities) *bool { return &v.received }
func BridgeUESecurityCapabilitiesFieldReceivedAbsolute(v *UESecurityCapabilities) *bool {
	return &v.receivedAbsolute
}
func BridgeUESecurityCapabilitiesFieldReceivedBytes(v *UESecurityCapabilities) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeUESecurityCapabilitiesFieldReceivedLocation(v *UESecurityCapabilities) *aper.Location {
	return &v.receivedLocation
}
func BridgeUESecurityCapabilitiesFieldReplay(v *UESecurityCapabilities) *aper.Snapshot {
	return &v.replay
}
func BridgeUESecurityCapabilitiesFieldStream(v *UESecurityCapabilities) *aper.WireSpan {
	return &v.stream
}
func BridgeUESecurityCapabilitiesFieldWithoutReplay(v *UESecurityCapabilities) *bool {
	return &v.withoutReplay
}
func BridgeUESecurityCapabilitiesMethodMarshalAPERBudget(v *UESecurityCapabilities, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeUESecurityCapabilitiesMethodMarshalAPERBudgetValue(v *UESecurityCapabilities, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudgetValue(a0, a1)
}
func BridgeUESecurityCapabilitiesMethodMarshalAPERChanged(v *UESecurityCapabilities, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeUESecurityCapabilitiesMethodMarshalAPERChangedValue(v *UESecurityCapabilities, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeUESecurityCapabilitiesMethodMarshalAPERLegacy(v *UESecurityCapabilities) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeUESecurityCapabilitiesMethodMarshalAPERNewValue(v *UESecurityCapabilities, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERNewValue(a0, a1)
}
func BridgeUESecurityCapabilitiesMethodMarshalAPERPlanned(v *UESecurityCapabilities, a0 *aper.DecodeBudget, a1 bool, a2 *aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1, a2)
}
func BridgeUESecurityCapabilitiesMethodMarshalAPERTo(v *UESecurityCapabilities, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeUESecurityCapabilitiesMethodUnmarshalAPERFrom(v *UESecurityCapabilities, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeUESecurityCapabilitiesMethodUnmarshalAPERLegacy(v *UESecurityCapabilities, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeUESecurityCapabilitiesMethodUnmarshalAPERWithOptions(v *UESecurityCapabilities, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeUESecurityCapabilitiesValueCodecFieldCapture(v *UESecurityCapabilitiesValueCodec) *func(UESecurityCapabilities, aper.DecodeState) (UESecurityCapabilities, aper.Snapshot) {
	return &v.capture
}
func BridgeUESecurityCapabilitiesValueCodecFieldCompare(v *UESecurityCapabilitiesValueCodec) *func(UESecurityCapabilities, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeUESecurityCapabilitiesValueCodecFieldContext(v *UESecurityCapabilitiesValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeUESecurityCapabilitiesValueCodecFieldDecode(v *UESecurityCapabilitiesValueCodec) *func([]byte, aper.DecodeState) (UESecurityCapabilities, error) {
	return &v.decode
}
func BridgeUESecurityCapabilitiesValueCodecFieldEncode(v *UESecurityCapabilitiesValueCodec) *func(UESecurityCapabilities, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeUESecurityCapabilitiesValueCodecFieldPath(v *UESecurityCapabilitiesValueCodec) *aper.Path {
	return &v.path
}
func BridgeUESecurityCapabilitiesValueCodecMethodEncodeBudgetValue(v UESecurityCapabilitiesValueCodec, a0 UESecurityCapabilities, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeUESecurityCapabilitiesValueCodecMethodEncodeChanged(v UESecurityCapabilitiesValueCodec, a0 UESecurityCapabilities, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeUESidelinkAggregateMaximumBitrateAPERValueFieldContext(v *UESidelinkAggregateMaximumBitrateAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeUESidelinkAggregateMaximumBitrateAPERValueFieldReceived(v *UESidelinkAggregateMaximumBitrateAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeUESidelinkAggregateMaximumBitrateAPERValueFieldReplay(v *UESidelinkAggregateMaximumBitrateAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeUESidelinkAggregateMaximumBitrateAPERValueFieldWithoutReplay(v *UESidelinkAggregateMaximumBitrateAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeUESidelinkAggregateMaximumBitrateFieldExtCount(v *UESidelinkAggregateMaximumBitrate) *int64 {
	return &v.extCount
}
func BridgeUESidelinkAggregateMaximumBitrateFieldExtData(v *UESidelinkAggregateMaximumBitrate) *[][]byte {
	return &v.extData
}
func BridgeUESidelinkAggregateMaximumBitrateFieldExtOrigin(v *UESidelinkAggregateMaximumBitrate) *[]aper.OpaqueOrigin {
	return &v.extOrigin
}
func BridgeUESidelinkAggregateMaximumBitrateFieldExtPresent(v *UESidelinkAggregateMaximumBitrate) *[]bool {
	return &v.extPresent
}
func BridgeUESidelinkAggregateMaximumBitrateFieldExtWire(v *UESidelinkAggregateMaximumBitrate) *[]aper.WireSpan {
	return &v.extWire
}
func BridgeUESidelinkAggregateMaximumBitrateFieldIEExtensionsIndef(v *UESidelinkAggregateMaximumBitrate) *bool {
	return &v.iEExtensionsIndef
}
func BridgeUESidelinkAggregateMaximumBitrateFieldPerExtPadding(v *UESidelinkAggregateMaximumBitrate) *[]aper.CompletePadding {
	return &v.perExtPadding
}
func BridgeUESidelinkAggregateMaximumBitrateFieldPerPadding(v *UESidelinkAggregateMaximumBitrate) *aper.FinalPadding {
	return &v.perPadding
}
func BridgeUESidelinkAggregateMaximumBitrateFieldReceived(v *UESidelinkAggregateMaximumBitrate) *bool {
	return &v.received
}
func BridgeUESidelinkAggregateMaximumBitrateFieldReceivedAbsolute(v *UESidelinkAggregateMaximumBitrate) *bool {
	return &v.receivedAbsolute
}
func BridgeUESidelinkAggregateMaximumBitrateFieldReceivedBytes(v *UESidelinkAggregateMaximumBitrate) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeUESidelinkAggregateMaximumBitrateFieldReceivedLocation(v *UESidelinkAggregateMaximumBitrate) *aper.Location {
	return &v.receivedLocation
}
func BridgeUESidelinkAggregateMaximumBitrateFieldReplay(v *UESidelinkAggregateMaximumBitrate) *aper.Snapshot {
	return &v.replay
}
func BridgeUESidelinkAggregateMaximumBitrateFieldStream(v *UESidelinkAggregateMaximumBitrate) *aper.WireSpan {
	return &v.stream
}
func BridgeUESidelinkAggregateMaximumBitrateFieldWithoutReplay(v *UESidelinkAggregateMaximumBitrate) *bool {
	return &v.withoutReplay
}
func BridgeUESidelinkAggregateMaximumBitrateMethodMarshalAPERBudget(v *UESidelinkAggregateMaximumBitrate, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeUESidelinkAggregateMaximumBitrateMethodMarshalAPERBudgetValue(v *UESidelinkAggregateMaximumBitrate, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudgetValue(a0, a1)
}
func BridgeUESidelinkAggregateMaximumBitrateMethodMarshalAPERChanged(v *UESidelinkAggregateMaximumBitrate, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeUESidelinkAggregateMaximumBitrateMethodMarshalAPERChangedValue(v *UESidelinkAggregateMaximumBitrate, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeUESidelinkAggregateMaximumBitrateMethodMarshalAPERLegacy(v *UESidelinkAggregateMaximumBitrate) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeUESidelinkAggregateMaximumBitrateMethodMarshalAPERNewValue(v *UESidelinkAggregateMaximumBitrate, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERNewValue(a0, a1)
}
func BridgeUESidelinkAggregateMaximumBitrateMethodMarshalAPERPlanned(v *UESidelinkAggregateMaximumBitrate, a0 *aper.DecodeBudget, a1 bool, a2 *aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1, a2)
}
func BridgeUESidelinkAggregateMaximumBitrateMethodMarshalAPERTo(v *UESidelinkAggregateMaximumBitrate, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeUESidelinkAggregateMaximumBitrateMethodUnmarshalAPERFrom(v *UESidelinkAggregateMaximumBitrate, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeUESidelinkAggregateMaximumBitrateMethodUnmarshalAPERLegacy(v *UESidelinkAggregateMaximumBitrate, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeUESidelinkAggregateMaximumBitrateMethodUnmarshalAPERWithOptions(v *UESidelinkAggregateMaximumBitrate, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeUESidelinkAggregateMaximumBitrateValueCodecFieldCapture(v *UESidelinkAggregateMaximumBitrateValueCodec) *func(UESidelinkAggregateMaximumBitrate, aper.DecodeState) (UESidelinkAggregateMaximumBitrate, aper.Snapshot) {
	return &v.capture
}
func BridgeUESidelinkAggregateMaximumBitrateValueCodecFieldCompare(v *UESidelinkAggregateMaximumBitrateValueCodec) *func(UESidelinkAggregateMaximumBitrate, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeUESidelinkAggregateMaximumBitrateValueCodecFieldContext(v *UESidelinkAggregateMaximumBitrateValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeUESidelinkAggregateMaximumBitrateValueCodecFieldDecode(v *UESidelinkAggregateMaximumBitrateValueCodec) *func([]byte, aper.DecodeState) (UESidelinkAggregateMaximumBitrate, error) {
	return &v.decode
}
func BridgeUESidelinkAggregateMaximumBitrateValueCodecFieldEncode(v *UESidelinkAggregateMaximumBitrateValueCodec) *func(UESidelinkAggregateMaximumBitrate, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeUESidelinkAggregateMaximumBitrateValueCodecFieldPath(v *UESidelinkAggregateMaximumBitrateValueCodec) *aper.Path {
	return &v.path
}
func BridgeUESidelinkAggregateMaximumBitrateValueCodecMethodEncodeBudgetValue(v UESidelinkAggregateMaximumBitrateValueCodec, a0 UESidelinkAggregateMaximumBitrate, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeUESidelinkAggregateMaximumBitrateValueCodecMethodEncodeChanged(v UESidelinkAggregateMaximumBitrateValueCodec, a0 UESidelinkAggregateMaximumBitrate, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeULCPSecurityInformationAPERValueFieldContext(v *ULCPSecurityInformationAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeULCPSecurityInformationAPERValueFieldReceived(v *ULCPSecurityInformationAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeULCPSecurityInformationAPERValueFieldReplay(v *ULCPSecurityInformationAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeULCPSecurityInformationAPERValueFieldWithoutReplay(v *ULCPSecurityInformationAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeULCPSecurityInformationFieldExtCount(v *ULCPSecurityInformation) *int64 {
	return &v.extCount
}
func BridgeULCPSecurityInformationFieldExtData(v *ULCPSecurityInformation) *[][]byte {
	return &v.extData
}
func BridgeULCPSecurityInformationFieldExtOrigin(v *ULCPSecurityInformation) *[]aper.OpaqueOrigin {
	return &v.extOrigin
}
func BridgeULCPSecurityInformationFieldExtPresent(v *ULCPSecurityInformation) *[]bool {
	return &v.extPresent
}
func BridgeULCPSecurityInformationFieldExtWire(v *ULCPSecurityInformation) *[]aper.WireSpan {
	return &v.extWire
}
func BridgeULCPSecurityInformationFieldIEExtensionsIndef(v *ULCPSecurityInformation) *bool {
	return &v.iEExtensionsIndef
}
func BridgeULCPSecurityInformationFieldPerExtPadding(v *ULCPSecurityInformation) *[]aper.CompletePadding {
	return &v.perExtPadding
}
func BridgeULCPSecurityInformationFieldPerPadding(v *ULCPSecurityInformation) *aper.FinalPadding {
	return &v.perPadding
}
func BridgeULCPSecurityInformationFieldReceived(v *ULCPSecurityInformation) *bool { return &v.received }
func BridgeULCPSecurityInformationFieldReceivedAbsolute(v *ULCPSecurityInformation) *bool {
	return &v.receivedAbsolute
}
func BridgeULCPSecurityInformationFieldReceivedBytes(v *ULCPSecurityInformation) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeULCPSecurityInformationFieldReceivedLocation(v *ULCPSecurityInformation) *aper.Location {
	return &v.receivedLocation
}
func BridgeULCPSecurityInformationFieldReplay(v *ULCPSecurityInformation) *aper.Snapshot {
	return &v.replay
}
func BridgeULCPSecurityInformationFieldStream(v *ULCPSecurityInformation) *aper.WireSpan {
	return &v.stream
}
func BridgeULCPSecurityInformationFieldWithoutReplay(v *ULCPSecurityInformation) *bool {
	return &v.withoutReplay
}
func BridgeULCPSecurityInformationMethodMarshalAPERBudget(v *ULCPSecurityInformation, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeULCPSecurityInformationMethodMarshalAPERBudgetValue(v *ULCPSecurityInformation, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudgetValue(a0, a1)
}
func BridgeULCPSecurityInformationMethodMarshalAPERChanged(v *ULCPSecurityInformation, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeULCPSecurityInformationMethodMarshalAPERChangedValue(v *ULCPSecurityInformation, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeULCPSecurityInformationMethodMarshalAPERLegacy(v *ULCPSecurityInformation) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeULCPSecurityInformationMethodMarshalAPERNewValue(v *ULCPSecurityInformation, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERNewValue(a0, a1)
}
func BridgeULCPSecurityInformationMethodMarshalAPERPlanned(v *ULCPSecurityInformation, a0 *aper.DecodeBudget, a1 bool, a2 *aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1, a2)
}
func BridgeULCPSecurityInformationMethodMarshalAPERTo(v *ULCPSecurityInformation, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeULCPSecurityInformationMethodUnmarshalAPERFrom(v *ULCPSecurityInformation, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeULCPSecurityInformationMethodUnmarshalAPERLegacy(v *ULCPSecurityInformation, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeULCPSecurityInformationMethodUnmarshalAPERWithOptions(v *ULCPSecurityInformation, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeULCPSecurityInformationValueCodecFieldCapture(v *ULCPSecurityInformationValueCodec) *func(ULCPSecurityInformation, aper.DecodeState) (ULCPSecurityInformation, aper.Snapshot) {
	return &v.capture
}
func BridgeULCPSecurityInformationValueCodecFieldCompare(v *ULCPSecurityInformationValueCodec) *func(ULCPSecurityInformation, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeULCPSecurityInformationValueCodecFieldContext(v *ULCPSecurityInformationValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeULCPSecurityInformationValueCodecFieldDecode(v *ULCPSecurityInformationValueCodec) *func([]byte, aper.DecodeState) (ULCPSecurityInformation, error) {
	return &v.decode
}
func BridgeULCPSecurityInformationValueCodecFieldEncode(v *ULCPSecurityInformationValueCodec) *func(ULCPSecurityInformation, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeULCPSecurityInformationValueCodecFieldPath(v *ULCPSecurityInformationValueCodec) *aper.Path {
	return &v.path
}
func BridgeULCPSecurityInformationValueCodecMethodEncodeBudgetValue(v ULCPSecurityInformationValueCodec, a0 ULCPSecurityInformation, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeULCPSecurityInformationValueCodecMethodEncodeChanged(v ULCPSecurityInformationValueCodec, a0 ULCPSecurityInformation, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}

// Selected returns the decoded value of the active alternative, as the matching As method returns it, or false when the value is opaque or empty.
func (v *ENBCPRelocationIndicationIEValue) Selected() (any, bool) {
	if v == nil || v.isOpaque {
		return nil, false
	}
	switch v.id {
	case 8:
		if value, ok := v.AsENBUES1APID(); ok {
			return value, true
		}
	case 96:
		if value, ok := v.AsSTMSI(); ok {
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
	case 254:
		if value, ok := v.AsULCPSecurityInformation(); ok {
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
func (v *ENBEarlyStatusTransferIEValue) Selected() (any, bool) {
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
	case 321:
		if value, ok := v.AsENBEarlyStatusTransferTransparentContainer(); ok {
			return value, true
		}
	}
	return nil, false
}

// Selected returns the decoded value of the active alternative, as the matching As method returns it, or false when the value is opaque or empty.
func (v *ENBEarlyStatusTransferTransparentContainerExtIEsValue) Selected() (any, bool) {
	if v == nil || v.isOpaque {
		return nil, false
	}
	switch v.id {
	case 352:
		if value, ok := v.AsBearersSubjectToDLDiscardingList(); ok {
			return value, true
		}
	}
	return nil, false
}

// Selected returns the decoded value of the active alternative, as the matching As method returns it, or false when the value is opaque or empty.
// The field's Id distinguishes alternatives with the same Go type.
func (v *MMEEarlyStatusTransferIEValue) Selected() (any, bool) {
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
	case 321:
		if value, ok := v.AsENBEarlyStatusTransferTransparentContainer(); ok {
			return value, true
		}
	}
	return nil, false
}

// Selected returns the decoded value of the active alternative, as the matching As method returns it, or false when the value is opaque or empty.
func (v *UEContextReleaseCommandIEValue) Selected() (any, bool) {
	if v == nil || v.isOpaque {
		return nil, false
	}
	switch v.id {
	case 99:
		if value, ok := v.AsUES1APIDs(); ok {
			return value, true
		}
	case 2:
		if value, ok := v.AsCause(); ok {
			return value, true
		}
	}
	return nil, false
}
