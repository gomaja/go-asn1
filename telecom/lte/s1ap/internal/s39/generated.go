// Code generated from the pinned S1AP source closure. DO NOT EDIT.

// Package s39 implements the github.com/gomaja/go-asn1/telecom/lte/s1ap root package.
package s39

import (
	fmt "fmt"
	s00 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s00"
	s01 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s01"
	s02 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s02"
	s06 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s06"
	s07 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s07"
	s13 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s13"
	s14 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s14"
	s15 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s15"
	s16 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s16"
	s17 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s17"
	s21 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s21"
	s22 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s22"
	s24 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s24"
	s25 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s25"
	s26 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s26"
	s29 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s29"
	s30 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s30"
	s35 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s35"
	s38 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s38"
	runtime "github.com/gomaja/go-asn1/telecom/lte/s1ap/runtime"
	aper "github.com/gomaja/go-asn1/telecom/lte/s1ap/runtime/aper"
)

// HandoverRequestAcknowledgeIEContainer is ProtocolIE-Container {{HandoverRequestAcknowledgeIEs}} of TS 36.413: a list of HandoverRequestAcknowledgeIEField values.
type HandoverRequestAcknowledgeIEContainer []HandoverRequestAcknowledgeIEField

// HandoverRequestAcknowledgeIEField is ProtocolIE-Field {{HandoverRequestAcknowledgeIEs}} of TS 36.413: an information element field.
type HandoverRequestAcknowledgeIEField struct {
	withoutReplay bool
	replay        aper.Snapshot
	stream        aper.WireSpan
	Id            s00.ProtocolIEID
	Criticality   s00.Criticality
	Value         HandoverRequestAcknowledgeIEValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v HandoverRequestAcknowledgeIEField) WithoutReplay() HandoverRequestAcknowledgeIEField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *HandoverRequestAcknowledgeIEField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *HandoverRequestAcknowledgeIEField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
func (v *HandoverRequestAcknowledgeIEField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolIEField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = HandoverRequestAcknowledgeIEField{}
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
	var zero HandoverRequestAcknowledgeIEValue

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

// ERABReleaseCommandIEContainer is ProtocolIE-Container {{E-RABReleaseCommandIEs}} of TS 36.413: a list of ERABReleaseCommandIEField values.
type ERABReleaseCommandIEContainer []ERABReleaseCommandIEField

// ERABReleaseCommandIEField is ProtocolIE-Field {{E-RABReleaseCommandIEs}} of TS 36.413: an information element field.
type ERABReleaseCommandIEField struct {
	withoutReplay bool
	replay        aper.Snapshot
	stream        aper.WireSpan
	Id            s00.ProtocolIEID
	Criticality   s00.Criticality
	Value         ERABReleaseCommandIEValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ERABReleaseCommandIEField) WithoutReplay() ERABReleaseCommandIEField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *ERABReleaseCommandIEField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *ERABReleaseCommandIEField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
func (v *ERABReleaseCommandIEField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolIEField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = ERABReleaseCommandIEField{}
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
	var zero ERABReleaseCommandIEValue

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

// InitialContextSetupResponseIEContainer is ProtocolIE-Container {{InitialContextSetupResponseIEs}} of TS 36.413: a list of InitialContextSetupResponseIEField values.
type InitialContextSetupResponseIEContainer []InitialContextSetupResponseIEField

// InitialContextSetupResponseIEField is ProtocolIE-Field {{InitialContextSetupResponseIEs}} of TS 36.413: an information element field.
type InitialContextSetupResponseIEField struct {
	withoutReplay bool
	replay        aper.Snapshot
	stream        aper.WireSpan
	Id            s00.ProtocolIEID
	Criticality   s00.Criticality
	Value         InitialContextSetupResponseIEValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v InitialContextSetupResponseIEField) WithoutReplay() InitialContextSetupResponseIEField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *InitialContextSetupResponseIEField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *InitialContextSetupResponseIEField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
func (v *InitialContextSetupResponseIEField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolIEField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = InitialContextSetupResponseIEField{}
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
	var zero InitialContextSetupResponseIEValue

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

// ERABModificationConfirmIEContainer is ProtocolIE-Container {{E-RABModificationConfirmIEs}} of TS 36.413: a list of ERABModificationConfirmIEField values.
type ERABModificationConfirmIEContainer []ERABModificationConfirmIEField

// ERABModificationConfirmIEField is ProtocolIE-Field {{E-RABModificationConfirmIEs}} of TS 36.413: an information element field.
type ERABModificationConfirmIEField struct {
	withoutReplay bool
	replay        aper.Snapshot
	stream        aper.WireSpan
	Id            s00.ProtocolIEID
	Criticality   s00.Criticality
	Value         ERABModificationConfirmIEValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ERABModificationConfirmIEField) WithoutReplay() ERABModificationConfirmIEField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *ERABModificationConfirmIEField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *ERABModificationConfirmIEField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
func (v *ERABModificationConfirmIEField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolIEField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = ERABModificationConfirmIEField{}
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
	var zero ERABModificationConfirmIEValue

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
func BridgeERABModificationConfirmIEValueCaptureS1APProtocolIEContainer(v *ERABModificationConfirmIEContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeERABModificationConfirmIEValueCaptureS1APProtocolIEField(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeERABModificationConfirmIEValueCompareS1APProtocolIEContainer(v *ERABModificationConfirmIEContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeERABModificationConfirmIEValueCompareS1APProtocolIEField(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeERABReleaseCommandIEValueCaptureS1APProtocolIEContainer(v *ERABReleaseCommandIEContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeERABReleaseCommandIEValueCaptureS1APProtocolIEField(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeERABReleaseCommandIEValueCompareS1APProtocolIEContainer(v *ERABReleaseCommandIEContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeERABReleaseCommandIEValueCompareS1APProtocolIEField(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeHandoverRequestAcknowledgeIEValueCaptureS1APProtocolIEContainer(v *HandoverRequestAcknowledgeIEContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeHandoverRequestAcknowledgeIEValueCaptureS1APProtocolIEField(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeHandoverRequestAcknowledgeIEValueCompareS1APProtocolIEContainer(v *HandoverRequestAcknowledgeIEContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeHandoverRequestAcknowledgeIEValueCompareS1APProtocolIEField(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeTargeteNBToSourceeNBTransparentContainerExtIEsValueCaptureS1APProtocolExtensionContainer(v *TargeteNBToSourceeNBTransparentContainerExtIEsExtContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeTargeteNBToSourceeNBTransparentContainerExtIEsValueCaptureS1APProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeTargeteNBToSourceeNBTransparentContainerExtIEsValueCompareS1APProtocolExtensionContainer(v *TargeteNBToSourceeNBTransparentContainerExtIEsExtContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeTargeteNBToSourceeNBTransparentContainerExtIEsValueCompareS1APProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}

// TargeteNBToSourceeNBTransparentContainerExtIEsExtContainer is ProtocolExtensionContainer {{TargeteNB-ToSourceeNB-TransparentContainer-ExtIEs}} of TS 36.413: a list of TargeteNBToSourceeNBTransparentContainerExtIEsExtField values.
type TargeteNBToSourceeNBTransparentContainerExtIEsExtContainer []TargeteNBToSourceeNBTransparentContainerExtIEsExtField

// TargeteNBToSourceeNBTransparentContainerExtIEsExtField is ProtocolExtensionField {{TargeteNB-ToSourceeNB-TransparentContainer-ExtIEs}} of TS 36.413: an extension field.
type TargeteNBToSourceeNBTransparentContainerExtIEsExtField struct {
	withoutReplay  bool
	replay         aper.Snapshot
	stream         aper.WireSpan
	Id             s00.ProtocolExtensionID
	Criticality    s00.Criticality
	ExtensionValue TargeteNBToSourceeNBTransparentContainerExtIEsValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v TargeteNBToSourceeNBTransparentContainerExtIEsExtField) WithoutReplay() TargeteNBToSourceeNBTransparentContainerExtIEsExtField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *TargeteNBToSourceeNBTransparentContainerExtIEsExtField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *TargeteNBToSourceeNBTransparentContainerExtIEsExtField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
func (v *TargeteNBToSourceeNBTransparentContainerExtIEsExtField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolExtensionField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = TargeteNBToSourceeNBTransparentContainerExtIEsExtField{}
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
	var zero TargeteNBToSourceeNBTransparentContainerExtIEsValue

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

// TargeteNBToSourceeNBTransparentContainerExtIEsDAPSResponseInfoListExtBinding binds DAPSResponseInfoList to the TargeteNB-ToSourceeNB-TransparentContainer-ExtIEs object set of TS 36.413.
type TargeteNBToSourceeNBTransparentContainerExtIEsDAPSResponseInfoListExtBinding struct {
	info   s00.ExtensionInfo
	codec  s14.DAPSResponseInfoListValueCodec
	inject func(s14.DAPSResponseInfoList,

	) TargeteNBToSourceeNBTransparentContainerExtIEsValue

	get func(*TargeteNBToSourceeNBTransparentContainerExtIEsValue,

	) (*s14.DAPSResponseInfoList,

		bool)
}

// Info returns the source descriptor for this binding.
func (b TargeteNBToSourceeNBTransparentContainerExtIEsDAPSResponseInfoListExtBinding) Info() s00.ExtensionInfo {
	return b.info
}

// Codec returns the complete value codec for this binding.
func (b TargeteNBToSourceeNBTransparentContainerExtIEsDAPSResponseInfoListExtBinding) Codec() s14.DAPSResponseInfoListValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b TargeteNBToSourceeNBTransparentContainerExtIEsDAPSResponseInfoListExtBinding) New(value s14.DAPSResponseInfoList,

) (TargeteNBToSourceeNBTransparentContainerExtIEsExtField, error) {
	if b.inject == nil {
		return TargeteNBToSourceeNBTransparentContainerExtIEsExtField{}, aper.OperationError(fmt.Errorf("unbound extension binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return TargeteNBToSourceeNBTransparentContainerExtIEsExtField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s14.BridgeDAPSResponseInfoListValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return TargeteNBToSourceeNBTransparentContainerExtIEsExtField{}, aper.OperationError(fmt.Errorf("extension %d: %w", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return TargeteNBToSourceeNBTransparentContainerExtIEsExtField{}, aper.OperationError(err, "Value.New")
	}
	return TargeteNBToSourceeNBTransparentContainerExtIEsExtField{Id: b.info.ID, Criticality: b.info.Criticality, ExtensionValue: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b TargeteNBToSourceeNBTransparentContainerExtIEsDAPSResponseInfoListExtBinding) Get(field *TargeteNBToSourceeNBTransparentContainerExtIEsExtField) (*s14.DAPSResponseInfoList,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.ExtensionValue)
}

// TargeteNBToSourceeNBTransparentContainerExtIEsRACSIndicationExtBinding binds RACSIndication to the TargeteNB-ToSourceeNB-TransparentContainer-ExtIEs object set of TS 36.413.
type TargeteNBToSourceeNBTransparentContainerExtIEsRACSIndicationExtBinding struct {
	info   s00.ExtensionInfo
	codec  s01.RACSIndicationValueCodec
	inject func(s00.RACSIndication,

	) TargeteNBToSourceeNBTransparentContainerExtIEsValue

	get func(*TargeteNBToSourceeNBTransparentContainerExtIEsValue,

	) (*s00.RACSIndication,

		bool)
}

// Info returns the source descriptor for this binding.
func (b TargeteNBToSourceeNBTransparentContainerExtIEsRACSIndicationExtBinding) Info() s00.ExtensionInfo {
	return b.info
}

// Codec returns the complete value codec for this binding.
func (b TargeteNBToSourceeNBTransparentContainerExtIEsRACSIndicationExtBinding) Codec() s01.RACSIndicationValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b TargeteNBToSourceeNBTransparentContainerExtIEsRACSIndicationExtBinding) New(value s00.RACSIndication,

) (TargeteNBToSourceeNBTransparentContainerExtIEsExtField, error) {
	if b.inject == nil {
		return TargeteNBToSourceeNBTransparentContainerExtIEsExtField{}, aper.OperationError(fmt.Errorf("unbound extension binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return TargeteNBToSourceeNBTransparentContainerExtIEsExtField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s01.BridgeRACSIndicationValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return TargeteNBToSourceeNBTransparentContainerExtIEsExtField{}, aper.OperationError(fmt.Errorf("extension %d: %w", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return TargeteNBToSourceeNBTransparentContainerExtIEsExtField{}, aper.OperationError(err, "Value.New")
	}
	return TargeteNBToSourceeNBTransparentContainerExtIEsExtField{Id: b.info.ID, Criticality: b.info.Criticality, ExtensionValue: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b TargeteNBToSourceeNBTransparentContainerExtIEsRACSIndicationExtBinding) Get(field *TargeteNBToSourceeNBTransparentContainerExtIEsExtField) (*s00.RACSIndication,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.ExtensionValue)
}

// TargeteNBToSourceeNBTransparentContainerExtIEsERABSecurityResultListExtBinding binds ERABSecurityResultList to the TargeteNB-ToSourceeNB-TransparentContainer-ExtIEs object set of TS 36.413.
type TargeteNBToSourceeNBTransparentContainerExtIEsERABSecurityResultListExtBinding struct {
	info   s00.ExtensionInfo
	codec  s30.ERABSecurityResultListValueCodec
	inject func(s30.ERABSecurityResultList,

	) TargeteNBToSourceeNBTransparentContainerExtIEsValue

	get func(*TargeteNBToSourceeNBTransparentContainerExtIEsValue,

	) (*s30.ERABSecurityResultList,

		bool)
}

// Info returns the source descriptor for this binding.
func (b TargeteNBToSourceeNBTransparentContainerExtIEsERABSecurityResultListExtBinding) Info() s00.ExtensionInfo {
	return b.info
}

// Codec returns the complete value codec for this binding.
func (b TargeteNBToSourceeNBTransparentContainerExtIEsERABSecurityResultListExtBinding) Codec() s30.ERABSecurityResultListValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b TargeteNBToSourceeNBTransparentContainerExtIEsERABSecurityResultListExtBinding) New(value s30.ERABSecurityResultList,

) (TargeteNBToSourceeNBTransparentContainerExtIEsExtField, error) {
	if b.inject == nil {
		return TargeteNBToSourceeNBTransparentContainerExtIEsExtField{}, aper.OperationError(fmt.Errorf("unbound extension binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return TargeteNBToSourceeNBTransparentContainerExtIEsExtField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s30.BridgeERABSecurityResultListValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return TargeteNBToSourceeNBTransparentContainerExtIEsExtField{}, aper.OperationError(fmt.Errorf("extension %d: %w", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return TargeteNBToSourceeNBTransparentContainerExtIEsExtField{}, aper.OperationError(err, "Value.New")
	}
	return TargeteNBToSourceeNBTransparentContainerExtIEsExtField{Id: b.info.ID, Criticality: b.info.Criticality, ExtensionValue: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b TargeteNBToSourceeNBTransparentContainerExtIEsERABSecurityResultListExtBinding) Get(field *TargeteNBToSourceeNBTransparentContainerExtIEsExtField) (*s30.ERABSecurityResultList,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.ExtensionValue)
}

// TargeteNBToSourceeNBTransparentContainerExtIEsDirectForwardingPathAvailabilityExtBinding binds DirectForwardingPathAvailability to the TargeteNB-ToSourceeNB-TransparentContainer-ExtIEs object set of TS 36.413.
type TargeteNBToSourceeNBTransparentContainerExtIEsDirectForwardingPathAvailabilityExtBinding struct {
	info   s00.ExtensionInfo
	codec  s00.DirectForwardingPathAvailabilityValueCodec
	inject func(s00.DirectForwardingPathAvailability,

	) TargeteNBToSourceeNBTransparentContainerExtIEsValue

	get func(*TargeteNBToSourceeNBTransparentContainerExtIEsValue,

	) (*s00.DirectForwardingPathAvailability,

		bool)
}

// Info returns the source descriptor for this binding.
func (b TargeteNBToSourceeNBTransparentContainerExtIEsDirectForwardingPathAvailabilityExtBinding) Info() s00.ExtensionInfo {
	return b.info
}

// Codec returns the complete value codec for this binding.
func (b TargeteNBToSourceeNBTransparentContainerExtIEsDirectForwardingPathAvailabilityExtBinding) Codec() s00.DirectForwardingPathAvailabilityValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b TargeteNBToSourceeNBTransparentContainerExtIEsDirectForwardingPathAvailabilityExtBinding) New(value s00.DirectForwardingPathAvailability,

) (TargeteNBToSourceeNBTransparentContainerExtIEsExtField, error) {
	if b.inject == nil {
		return TargeteNBToSourceeNBTransparentContainerExtIEsExtField{}, aper.OperationError(fmt.Errorf("unbound extension binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return TargeteNBToSourceeNBTransparentContainerExtIEsExtField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s00.BridgeDirectForwardingPathAvailabilityValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return TargeteNBToSourceeNBTransparentContainerExtIEsExtField{}, aper.OperationError(fmt.Errorf("extension %d: %w", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return TargeteNBToSourceeNBTransparentContainerExtIEsExtField{}, aper.OperationError(err, "Value.New")
	}
	return TargeteNBToSourceeNBTransparentContainerExtIEsExtField{Id: b.info.ID, Criticality: b.info.Criticality, ExtensionValue: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b TargeteNBToSourceeNBTransparentContainerExtIEsDirectForwardingPathAvailabilityExtBinding) Get(field *TargeteNBToSourceeNBTransparentContainerExtIEsExtField) (*s00.DirectForwardingPathAvailability,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.ExtensionValue)
}

// ERABModificationConfirmMMEUES1APIDIEBinding binds MMEUES1APID to the E-RABModificationConfirmIEs object set of TS 36.413.
type ERABModificationConfirmMMEUES1APIDIEBinding struct {
	info   s00.FieldInfo
	codec  s01.MMEUES1APIDValueCodec
	inject func(s00.MMEUES1APID,

	) ERABModificationConfirmIEValue

	get func(*ERABModificationConfirmIEValue,

	) (*s00.MMEUES1APID,

		bool)
}

// Info returns the source descriptor for this binding.
func (b ERABModificationConfirmMMEUES1APIDIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b ERABModificationConfirmMMEUES1APIDIEBinding) Codec() s01.MMEUES1APIDValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b ERABModificationConfirmMMEUES1APIDIEBinding) New(value s00.MMEUES1APID,

) (ERABModificationConfirmIEField, error) {
	if b.inject == nil {
		return ERABModificationConfirmIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ERABModificationConfirmIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s01.BridgeMMEUES1APIDValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return ERABModificationConfirmIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return ERABModificationConfirmIEField{}, aper.OperationError(err, "Value.New")
	}
	return ERABModificationConfirmIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b ERABModificationConfirmMMEUES1APIDIEBinding) Get(field *ERABModificationConfirmIEField) (*s00.MMEUES1APID,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// ERABModificationConfirmENBUES1APIDIEBinding binds ENBUES1APID to the E-RABModificationConfirmIEs object set of TS 36.413.
type ERABModificationConfirmENBUES1APIDIEBinding struct {
	info   s00.FieldInfo
	codec  s00.ENBUES1APIDValueCodec
	inject func(s00.ENBUES1APID,

	) ERABModificationConfirmIEValue

	get func(*ERABModificationConfirmIEValue,

	) (*s00.ENBUES1APID,

		bool)
}

// Info returns the source descriptor for this binding.
func (b ERABModificationConfirmENBUES1APIDIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b ERABModificationConfirmENBUES1APIDIEBinding) Codec() s00.ENBUES1APIDValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b ERABModificationConfirmENBUES1APIDIEBinding) New(value s00.ENBUES1APID,

) (ERABModificationConfirmIEField, error) {
	if b.inject == nil {
		return ERABModificationConfirmIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ERABModificationConfirmIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s00.BridgeENBUES1APIDValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return ERABModificationConfirmIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return ERABModificationConfirmIEField{}, aper.OperationError(err, "Value.New")
	}
	return ERABModificationConfirmIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b ERABModificationConfirmENBUES1APIDIEBinding) Get(field *ERABModificationConfirmIEField) (*s00.ENBUES1APID,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// ERABModificationConfirmERABModifyListBearerModConfIEBinding binds ERABModifyListBearerModConf to the E-RABModificationConfirmIEs object set of TS 36.413.
type ERABModificationConfirmERABModifyListBearerModConfIEBinding struct {
	info   s00.FieldInfo
	codec  s16.ERABModifyListBearerModConfValueCodec
	inject func(s16.ERABModifyListBearerModConf,

	) ERABModificationConfirmIEValue

	get func(*ERABModificationConfirmIEValue,

	) (*s16.ERABModifyListBearerModConf,

		bool)
}

// Info returns the source descriptor for this binding.
func (b ERABModificationConfirmERABModifyListBearerModConfIEBinding) Info() s00.FieldInfo {
	return b.info
}

// Codec returns the complete value codec for this binding.
func (b ERABModificationConfirmERABModifyListBearerModConfIEBinding) Codec() s16.ERABModifyListBearerModConfValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b ERABModificationConfirmERABModifyListBearerModConfIEBinding) New(value s16.ERABModifyListBearerModConf,

) (ERABModificationConfirmIEField, error) {
	if b.inject == nil {
		return ERABModificationConfirmIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ERABModificationConfirmIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s16.BridgeERABModifyListBearerModConfValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return ERABModificationConfirmIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return ERABModificationConfirmIEField{}, aper.OperationError(err, "Value.New")
	}
	return ERABModificationConfirmIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b ERABModificationConfirmERABModifyListBearerModConfIEBinding) Get(field *ERABModificationConfirmIEField) (*s16.ERABModifyListBearerModConf,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// ERABModificationConfirmERABListIEBinding binds ERABList to the E-RABModificationConfirmIEs object set of TS 36.413.
type ERABModificationConfirmERABListIEBinding struct {
	info   s00.FieldInfo
	codec  s16.ERABListValueCodec
	inject func(s16.ERABList,

	) ERABModificationConfirmIEValue

	get func(*ERABModificationConfirmIEValue,

	) (*s16.ERABList,

		bool)
}

// Info returns the source descriptor for this binding.
func (b ERABModificationConfirmERABListIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b ERABModificationConfirmERABListIEBinding) Codec() s16.ERABListValueCodec { return b.codec }

// New validates a source value and constructs its bound field.
func (b ERABModificationConfirmERABListIEBinding) New(value s16.ERABList,

) (ERABModificationConfirmIEField, error) {
	if b.inject == nil {
		return ERABModificationConfirmIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ERABModificationConfirmIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s16.BridgeERABListValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return ERABModificationConfirmIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return ERABModificationConfirmIEField{}, aper.OperationError(err, "Value.New")
	}
	return ERABModificationConfirmIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b ERABModificationConfirmERABListIEBinding) Get(field *ERABModificationConfirmIEField) (*s16.ERABList,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// ERABModificationConfirmCriticalityDiagnosticsIEBinding binds CriticalityDiagnostics to the E-RABModificationConfirmIEs object set of TS 36.413.
type ERABModificationConfirmCriticalityDiagnosticsIEBinding struct {
	info   s00.FieldInfo
	codec  s22.CriticalityDiagnosticsValueCodec
	inject func(s22.CriticalityDiagnostics,

	) ERABModificationConfirmIEValue

	get func(*ERABModificationConfirmIEValue,

	) (*s22.CriticalityDiagnostics,

		bool)
}

// Info returns the source descriptor for this binding.
func (b ERABModificationConfirmCriticalityDiagnosticsIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b ERABModificationConfirmCriticalityDiagnosticsIEBinding) Codec() s22.CriticalityDiagnosticsValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b ERABModificationConfirmCriticalityDiagnosticsIEBinding) New(value s22.CriticalityDiagnostics,

) (ERABModificationConfirmIEField, error) {
	if b.inject == nil {
		return ERABModificationConfirmIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ERABModificationConfirmIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s22.BridgeCriticalityDiagnosticsValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return ERABModificationConfirmIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return ERABModificationConfirmIEField{}, aper.OperationError(err, "Value.New")
	}
	return ERABModificationConfirmIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b ERABModificationConfirmCriticalityDiagnosticsIEBinding) Get(field *ERABModificationConfirmIEField) (*s22.CriticalityDiagnostics,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// ERABModificationConfirmCSGMembershipStatusIEBinding binds CSGMembershipStatus to the E-RABModificationConfirmIEs object set of TS 36.413.
type ERABModificationConfirmCSGMembershipStatusIEBinding struct {
	info   s00.FieldInfo
	codec  s00.CSGMembershipStatusValueCodec
	inject func(s00.CSGMembershipStatus,

	) ERABModificationConfirmIEValue

	get func(*ERABModificationConfirmIEValue,

	) (*s00.CSGMembershipStatus,

		bool)
}

// Info returns the source descriptor for this binding.
func (b ERABModificationConfirmCSGMembershipStatusIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b ERABModificationConfirmCSGMembershipStatusIEBinding) Codec() s00.CSGMembershipStatusValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b ERABModificationConfirmCSGMembershipStatusIEBinding) New(value s00.CSGMembershipStatus,

) (ERABModificationConfirmIEField, error) {
	if b.inject == nil {
		return ERABModificationConfirmIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ERABModificationConfirmIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s00.BridgeCSGMembershipStatusValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return ERABModificationConfirmIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return ERABModificationConfirmIEField{}, aper.OperationError(err, "Value.New")
	}
	return ERABModificationConfirmIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b ERABModificationConfirmCSGMembershipStatusIEBinding) Get(field *ERABModificationConfirmIEField) (*s00.CSGMembershipStatus,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// ERABReleaseCommandMMEUES1APIDIEBinding binds MMEUES1APID to the E-RABReleaseCommandIEs object set of TS 36.413.
type ERABReleaseCommandMMEUES1APIDIEBinding struct {
	info   s00.FieldInfo
	codec  s01.MMEUES1APIDValueCodec
	inject func(s00.MMEUES1APID,

	) ERABReleaseCommandIEValue

	get func(*ERABReleaseCommandIEValue,

	) (*s00.MMEUES1APID,

		bool)
}

// Info returns the source descriptor for this binding.
func (b ERABReleaseCommandMMEUES1APIDIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b ERABReleaseCommandMMEUES1APIDIEBinding) Codec() s01.MMEUES1APIDValueCodec { return b.codec }

// New validates a source value and constructs its bound field.
func (b ERABReleaseCommandMMEUES1APIDIEBinding) New(value s00.MMEUES1APID,

) (ERABReleaseCommandIEField, error) {
	if b.inject == nil {
		return ERABReleaseCommandIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ERABReleaseCommandIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s01.BridgeMMEUES1APIDValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return ERABReleaseCommandIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return ERABReleaseCommandIEField{}, aper.OperationError(err, "Value.New")
	}
	return ERABReleaseCommandIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b ERABReleaseCommandMMEUES1APIDIEBinding) Get(field *ERABReleaseCommandIEField) (*s00.MMEUES1APID,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// ERABReleaseCommandENBUES1APIDIEBinding binds ENBUES1APID to the E-RABReleaseCommandIEs object set of TS 36.413.
type ERABReleaseCommandENBUES1APIDIEBinding struct {
	info   s00.FieldInfo
	codec  s00.ENBUES1APIDValueCodec
	inject func(s00.ENBUES1APID,

	) ERABReleaseCommandIEValue

	get func(*ERABReleaseCommandIEValue,

	) (*s00.ENBUES1APID,

		bool)
}

// Info returns the source descriptor for this binding.
func (b ERABReleaseCommandENBUES1APIDIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b ERABReleaseCommandENBUES1APIDIEBinding) Codec() s00.ENBUES1APIDValueCodec { return b.codec }

// New validates a source value and constructs its bound field.
func (b ERABReleaseCommandENBUES1APIDIEBinding) New(value s00.ENBUES1APID,

) (ERABReleaseCommandIEField, error) {
	if b.inject == nil {
		return ERABReleaseCommandIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ERABReleaseCommandIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s00.BridgeENBUES1APIDValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return ERABReleaseCommandIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return ERABReleaseCommandIEField{}, aper.OperationError(err, "Value.New")
	}
	return ERABReleaseCommandIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b ERABReleaseCommandENBUES1APIDIEBinding) Get(field *ERABReleaseCommandIEField) (*s00.ENBUES1APID,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// ERABReleaseCommandUEAggregateMaximumBitrateIEBinding binds UEAggregateMaximumBitrate to the E-RABReleaseCommandIEs object set of TS 36.413.
type ERABReleaseCommandUEAggregateMaximumBitrateIEBinding struct {
	info   s00.FieldInfo
	codec  s35.UEAggregateMaximumBitrateValueCodec
	inject func(s35.UEAggregateMaximumBitrate,

	) ERABReleaseCommandIEValue

	get func(*ERABReleaseCommandIEValue,

	) (*s35.UEAggregateMaximumBitrate,

		bool)
}

// Info returns the source descriptor for this binding.
func (b ERABReleaseCommandUEAggregateMaximumBitrateIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b ERABReleaseCommandUEAggregateMaximumBitrateIEBinding) Codec() s35.UEAggregateMaximumBitrateValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b ERABReleaseCommandUEAggregateMaximumBitrateIEBinding) New(value s35.UEAggregateMaximumBitrate,

) (ERABReleaseCommandIEField, error) {
	if b.inject == nil {
		return ERABReleaseCommandIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ERABReleaseCommandIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s35.BridgeUEAggregateMaximumBitrateValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return ERABReleaseCommandIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return ERABReleaseCommandIEField{}, aper.OperationError(err, "Value.New")
	}
	return ERABReleaseCommandIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b ERABReleaseCommandUEAggregateMaximumBitrateIEBinding) Get(field *ERABReleaseCommandIEField) (*s35.UEAggregateMaximumBitrate,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// ERABReleaseCommandERABListIEBinding binds ERABList to the E-RABReleaseCommandIEs object set of TS 36.413.
type ERABReleaseCommandERABListIEBinding struct {
	info   s00.FieldInfo
	codec  s16.ERABListValueCodec
	inject func(s16.ERABList,

	) ERABReleaseCommandIEValue

	get func(*ERABReleaseCommandIEValue,

	) (*s16.ERABList,

		bool)
}

// Info returns the source descriptor for this binding.
func (b ERABReleaseCommandERABListIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b ERABReleaseCommandERABListIEBinding) Codec() s16.ERABListValueCodec { return b.codec }

// New validates a source value and constructs its bound field.
func (b ERABReleaseCommandERABListIEBinding) New(value s16.ERABList,

) (ERABReleaseCommandIEField, error) {
	if b.inject == nil {
		return ERABReleaseCommandIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ERABReleaseCommandIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s16.BridgeERABListValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return ERABReleaseCommandIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return ERABReleaseCommandIEField{}, aper.OperationError(err, "Value.New")
	}
	return ERABReleaseCommandIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b ERABReleaseCommandERABListIEBinding) Get(field *ERABReleaseCommandIEField) (*s16.ERABList,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// ERABReleaseCommandNASPDUIEBinding binds NASPDU to the E-RABReleaseCommandIEs object set of TS 36.413.
type ERABReleaseCommandNASPDUIEBinding struct {
	info   s00.FieldInfo
	codec  s01.NASPDUValueCodec
	inject func(s00.NASPDU,

	) ERABReleaseCommandIEValue

	get func(*ERABReleaseCommandIEValue,

	) (*s00.NASPDU,

		bool)
}

// Info returns the source descriptor for this binding.
func (b ERABReleaseCommandNASPDUIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b ERABReleaseCommandNASPDUIEBinding) Codec() s01.NASPDUValueCodec { return b.codec }

// New validates a source value and constructs its bound field.
func (b ERABReleaseCommandNASPDUIEBinding) New(value s00.NASPDU,

) (ERABReleaseCommandIEField, error) {
	if b.inject == nil {
		return ERABReleaseCommandIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ERABReleaseCommandIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s01.BridgeNASPDUValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return ERABReleaseCommandIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return ERABReleaseCommandIEField{}, aper.OperationError(err, "Value.New")
	}
	return ERABReleaseCommandIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b ERABReleaseCommandNASPDUIEBinding) Get(field *ERABReleaseCommandIEField) (*s00.NASPDU,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// HandoverRequestAcknowledgeMMEUES1APIDIEBinding binds MMEUES1APID to the HandoverRequestAcknowledgeIEs object set of TS 36.413.
type HandoverRequestAcknowledgeMMEUES1APIDIEBinding struct {
	info   s00.FieldInfo
	codec  s01.MMEUES1APIDValueCodec
	inject func(s00.MMEUES1APID,

	) HandoverRequestAcknowledgeIEValue

	get func(*HandoverRequestAcknowledgeIEValue,

	) (*s00.MMEUES1APID,

		bool)
}

// Info returns the source descriptor for this binding.
func (b HandoverRequestAcknowledgeMMEUES1APIDIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b HandoverRequestAcknowledgeMMEUES1APIDIEBinding) Codec() s01.MMEUES1APIDValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b HandoverRequestAcknowledgeMMEUES1APIDIEBinding) New(value s00.MMEUES1APID,

) (HandoverRequestAcknowledgeIEField, error) {
	if b.inject == nil {
		return HandoverRequestAcknowledgeIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return HandoverRequestAcknowledgeIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s01.BridgeMMEUES1APIDValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return HandoverRequestAcknowledgeIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return HandoverRequestAcknowledgeIEField{}, aper.OperationError(err, "Value.New")
	}
	return HandoverRequestAcknowledgeIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b HandoverRequestAcknowledgeMMEUES1APIDIEBinding) Get(field *HandoverRequestAcknowledgeIEField) (*s00.MMEUES1APID,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// HandoverRequestAcknowledgeENBUES1APIDIEBinding binds ENBUES1APID to the HandoverRequestAcknowledgeIEs object set of TS 36.413.
type HandoverRequestAcknowledgeENBUES1APIDIEBinding struct {
	info   s00.FieldInfo
	codec  s00.ENBUES1APIDValueCodec
	inject func(s00.ENBUES1APID,

	) HandoverRequestAcknowledgeIEValue

	get func(*HandoverRequestAcknowledgeIEValue,

	) (*s00.ENBUES1APID,

		bool)
}

// Info returns the source descriptor for this binding.
func (b HandoverRequestAcknowledgeENBUES1APIDIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b HandoverRequestAcknowledgeENBUES1APIDIEBinding) Codec() s00.ENBUES1APIDValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b HandoverRequestAcknowledgeENBUES1APIDIEBinding) New(value s00.ENBUES1APID,

) (HandoverRequestAcknowledgeIEField, error) {
	if b.inject == nil {
		return HandoverRequestAcknowledgeIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return HandoverRequestAcknowledgeIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s00.BridgeENBUES1APIDValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return HandoverRequestAcknowledgeIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return HandoverRequestAcknowledgeIEField{}, aper.OperationError(err, "Value.New")
	}
	return HandoverRequestAcknowledgeIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b HandoverRequestAcknowledgeENBUES1APIDIEBinding) Get(field *HandoverRequestAcknowledgeIEField) (*s00.ENBUES1APID,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// HandoverRequestAcknowledgeERABAdmittedListIEBinding binds ERABAdmittedList to the HandoverRequestAcknowledgeIEs object set of TS 36.413.
type HandoverRequestAcknowledgeERABAdmittedListIEBinding struct {
	info   s00.FieldInfo
	codec  s15.ERABAdmittedListValueCodec
	inject func(s15.ERABAdmittedList,

	) HandoverRequestAcknowledgeIEValue

	get func(*HandoverRequestAcknowledgeIEValue,

	) (*s15.ERABAdmittedList,

		bool)
}

// Info returns the source descriptor for this binding.
func (b HandoverRequestAcknowledgeERABAdmittedListIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b HandoverRequestAcknowledgeERABAdmittedListIEBinding) Codec() s15.ERABAdmittedListValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b HandoverRequestAcknowledgeERABAdmittedListIEBinding) New(value s15.ERABAdmittedList,

) (HandoverRequestAcknowledgeIEField, error) {
	if b.inject == nil {
		return HandoverRequestAcknowledgeIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return HandoverRequestAcknowledgeIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s15.BridgeERABAdmittedListValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return HandoverRequestAcknowledgeIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return HandoverRequestAcknowledgeIEField{}, aper.OperationError(err, "Value.New")
	}
	return HandoverRequestAcknowledgeIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b HandoverRequestAcknowledgeERABAdmittedListIEBinding) Get(field *HandoverRequestAcknowledgeIEField) (*s15.ERABAdmittedList,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// HandoverRequestAcknowledgeERABFailedtoSetupListHOReqAckIEBinding binds ERABFailedtoSetupListHOReqAck to the HandoverRequestAcknowledgeIEs object set of TS 36.413.
type HandoverRequestAcknowledgeERABFailedtoSetupListHOReqAckIEBinding struct {
	info   s00.FieldInfo
	codec  s16.ERABFailedtoSetupListHOReqAckValueCodec
	inject func(s16.ERABFailedtoSetupListHOReqAck,

	) HandoverRequestAcknowledgeIEValue

	get func(*HandoverRequestAcknowledgeIEValue,

	) (*s16.ERABFailedtoSetupListHOReqAck,

		bool)
}

// Info returns the source descriptor for this binding.
func (b HandoverRequestAcknowledgeERABFailedtoSetupListHOReqAckIEBinding) Info() s00.FieldInfo {
	return b.info
}

// Codec returns the complete value codec for this binding.
func (b HandoverRequestAcknowledgeERABFailedtoSetupListHOReqAckIEBinding) Codec() s16.ERABFailedtoSetupListHOReqAckValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b HandoverRequestAcknowledgeERABFailedtoSetupListHOReqAckIEBinding) New(value s16.ERABFailedtoSetupListHOReqAck,

) (HandoverRequestAcknowledgeIEField, error) {
	if b.inject == nil {
		return HandoverRequestAcknowledgeIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return HandoverRequestAcknowledgeIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s16.BridgeERABFailedtoSetupListHOReqAckValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return HandoverRequestAcknowledgeIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return HandoverRequestAcknowledgeIEField{}, aper.OperationError(err, "Value.New")
	}
	return HandoverRequestAcknowledgeIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b HandoverRequestAcknowledgeERABFailedtoSetupListHOReqAckIEBinding) Get(field *HandoverRequestAcknowledgeIEField) (*s16.ERABFailedtoSetupListHOReqAck,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// HandoverRequestAcknowledgeTargetToSourceTransparentContainerIEBinding binds TargetToSourceTransparentContainer to the HandoverRequestAcknowledgeIEs object set of TS 36.413.
type HandoverRequestAcknowledgeTargetToSourceTransparentContainerIEBinding struct {
	info   s00.FieldInfo
	codec  s01.TargetToSourceTransparentContainerValueCodec
	inject func(s00.TargetToSourceTransparentContainer,

	) HandoverRequestAcknowledgeIEValue

	get func(*HandoverRequestAcknowledgeIEValue,

	) (*s00.TargetToSourceTransparentContainer,

		bool)
}

// Info returns the source descriptor for this binding.
func (b HandoverRequestAcknowledgeTargetToSourceTransparentContainerIEBinding) Info() s00.FieldInfo {
	return b.info
}

// Codec returns the complete value codec for this binding.
func (b HandoverRequestAcknowledgeTargetToSourceTransparentContainerIEBinding) Codec() s01.TargetToSourceTransparentContainerValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b HandoverRequestAcknowledgeTargetToSourceTransparentContainerIEBinding) New(value s00.TargetToSourceTransparentContainer,

) (HandoverRequestAcknowledgeIEField, error) {
	if b.inject == nil {
		return HandoverRequestAcknowledgeIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return HandoverRequestAcknowledgeIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s01.BridgeTargetToSourceTransparentContainerValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return HandoverRequestAcknowledgeIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return HandoverRequestAcknowledgeIEField{}, aper.OperationError(err, "Value.New")
	}
	return HandoverRequestAcknowledgeIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b HandoverRequestAcknowledgeTargetToSourceTransparentContainerIEBinding) Get(field *HandoverRequestAcknowledgeIEField) (*s00.TargetToSourceTransparentContainer,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// HandoverRequestAcknowledgeCSGIdIEBinding binds CSGId to the HandoverRequestAcknowledgeIEs object set of TS 36.413.
type HandoverRequestAcknowledgeCSGIdIEBinding struct {
	info   s00.FieldInfo
	codec  s00.CSGIdValueCodec
	inject func(s00.CSGId,

	) HandoverRequestAcknowledgeIEValue

	get func(*HandoverRequestAcknowledgeIEValue,

	) (*s00.CSGId,

		bool)
}

// Info returns the source descriptor for this binding.
func (b HandoverRequestAcknowledgeCSGIdIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b HandoverRequestAcknowledgeCSGIdIEBinding) Codec() s00.CSGIdValueCodec { return b.codec }

// New validates a source value and constructs its bound field.
func (b HandoverRequestAcknowledgeCSGIdIEBinding) New(value s00.CSGId,

) (HandoverRequestAcknowledgeIEField, error) {
	if b.inject == nil {
		return HandoverRequestAcknowledgeIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return HandoverRequestAcknowledgeIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s00.BridgeCSGIdValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return HandoverRequestAcknowledgeIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return HandoverRequestAcknowledgeIEField{}, aper.OperationError(err, "Value.New")
	}
	return HandoverRequestAcknowledgeIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b HandoverRequestAcknowledgeCSGIdIEBinding) Get(field *HandoverRequestAcknowledgeIEField) (*s00.CSGId,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// HandoverRequestAcknowledgeCriticalityDiagnosticsIEBinding binds CriticalityDiagnostics to the HandoverRequestAcknowledgeIEs object set of TS 36.413.
type HandoverRequestAcknowledgeCriticalityDiagnosticsIEBinding struct {
	info   s00.FieldInfo
	codec  s22.CriticalityDiagnosticsValueCodec
	inject func(s22.CriticalityDiagnostics,

	) HandoverRequestAcknowledgeIEValue

	get func(*HandoverRequestAcknowledgeIEValue,

	) (*s22.CriticalityDiagnostics,

		bool)
}

// Info returns the source descriptor for this binding.
func (b HandoverRequestAcknowledgeCriticalityDiagnosticsIEBinding) Info() s00.FieldInfo {
	return b.info
}

// Codec returns the complete value codec for this binding.
func (b HandoverRequestAcknowledgeCriticalityDiagnosticsIEBinding) Codec() s22.CriticalityDiagnosticsValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b HandoverRequestAcknowledgeCriticalityDiagnosticsIEBinding) New(value s22.CriticalityDiagnostics,

) (HandoverRequestAcknowledgeIEField, error) {
	if b.inject == nil {
		return HandoverRequestAcknowledgeIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return HandoverRequestAcknowledgeIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s22.BridgeCriticalityDiagnosticsValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return HandoverRequestAcknowledgeIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return HandoverRequestAcknowledgeIEField{}, aper.OperationError(err, "Value.New")
	}
	return HandoverRequestAcknowledgeIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b HandoverRequestAcknowledgeCriticalityDiagnosticsIEBinding) Get(field *HandoverRequestAcknowledgeIEField) (*s22.CriticalityDiagnostics,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// HandoverRequestAcknowledgeCellAccessModeIEBinding binds CellAccessMode to the HandoverRequestAcknowledgeIEs object set of TS 36.413.
type HandoverRequestAcknowledgeCellAccessModeIEBinding struct {
	info   s00.FieldInfo
	codec  s00.CellAccessModeValueCodec
	inject func(s00.CellAccessMode,

	) HandoverRequestAcknowledgeIEValue

	get func(*HandoverRequestAcknowledgeIEValue,

	) (*s00.CellAccessMode,

		bool)
}

// Info returns the source descriptor for this binding.
func (b HandoverRequestAcknowledgeCellAccessModeIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b HandoverRequestAcknowledgeCellAccessModeIEBinding) Codec() s00.CellAccessModeValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b HandoverRequestAcknowledgeCellAccessModeIEBinding) New(value s00.CellAccessMode,

) (HandoverRequestAcknowledgeIEField, error) {
	if b.inject == nil {
		return HandoverRequestAcknowledgeIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return HandoverRequestAcknowledgeIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s00.BridgeCellAccessModeValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return HandoverRequestAcknowledgeIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return HandoverRequestAcknowledgeIEField{}, aper.OperationError(err, "Value.New")
	}
	return HandoverRequestAcknowledgeIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b HandoverRequestAcknowledgeCellAccessModeIEBinding) Get(field *HandoverRequestAcknowledgeIEField) (*s00.CellAccessMode,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// HandoverRequestAcknowledgeCEModeBSupportIndicatorIEBinding binds CEModeBSupportIndicator to the HandoverRequestAcknowledgeIEs object set of TS 36.413.
type HandoverRequestAcknowledgeCEModeBSupportIndicatorIEBinding struct {
	info   s00.FieldInfo
	codec  s00.CEModeBSupportIndicatorValueCodec
	inject func(s00.CEModeBSupportIndicator,

	) HandoverRequestAcknowledgeIEValue

	get func(*HandoverRequestAcknowledgeIEValue,

	) (*s00.CEModeBSupportIndicator,

		bool)
}

// Info returns the source descriptor for this binding.
func (b HandoverRequestAcknowledgeCEModeBSupportIndicatorIEBinding) Info() s00.FieldInfo {
	return b.info
}

// Codec returns the complete value codec for this binding.
func (b HandoverRequestAcknowledgeCEModeBSupportIndicatorIEBinding) Codec() s00.CEModeBSupportIndicatorValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b HandoverRequestAcknowledgeCEModeBSupportIndicatorIEBinding) New(value s00.CEModeBSupportIndicator,

) (HandoverRequestAcknowledgeIEField, error) {
	if b.inject == nil {
		return HandoverRequestAcknowledgeIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return HandoverRequestAcknowledgeIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s00.BridgeCEModeBSupportIndicatorValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return HandoverRequestAcknowledgeIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return HandoverRequestAcknowledgeIEField{}, aper.OperationError(err, "Value.New")
	}
	return HandoverRequestAcknowledgeIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b HandoverRequestAcknowledgeCEModeBSupportIndicatorIEBinding) Get(field *HandoverRequestAcknowledgeIEField) (*s00.CEModeBSupportIndicator,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// InitialContextSetupResponseENBUES1APIDIEBinding binds ENBUES1APID to the InitialContextSetupResponseIEs object set of TS 36.413.
type InitialContextSetupResponseENBUES1APIDIEBinding struct {
	info   s00.FieldInfo
	codec  s00.ENBUES1APIDValueCodec
	inject func(s00.ENBUES1APID,

	) InitialContextSetupResponseIEValue

	get func(*InitialContextSetupResponseIEValue,

	) (*s00.ENBUES1APID,

		bool)
}

// Info returns the source descriptor for this binding.
func (b InitialContextSetupResponseENBUES1APIDIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b InitialContextSetupResponseENBUES1APIDIEBinding) Codec() s00.ENBUES1APIDValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b InitialContextSetupResponseENBUES1APIDIEBinding) New(value s00.ENBUES1APID,

) (InitialContextSetupResponseIEField, error) {
	if b.inject == nil {
		return InitialContextSetupResponseIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return InitialContextSetupResponseIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s00.BridgeENBUES1APIDValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return InitialContextSetupResponseIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return InitialContextSetupResponseIEField{}, aper.OperationError(err, "Value.New")
	}
	return InitialContextSetupResponseIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b InitialContextSetupResponseENBUES1APIDIEBinding) Get(field *InitialContextSetupResponseIEField) (*s00.ENBUES1APID,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// InitialContextSetupResponseERABSetupListCtxtSUResIEBinding binds ERABSetupListCtxtSURes to the InitialContextSetupResponseIEs object set of TS 36.413.
type InitialContextSetupResponseERABSetupListCtxtSUResIEBinding struct {
	info   s00.FieldInfo
	codec  s17.ERABSetupListCtxtSUResValueCodec
	inject func(s17.ERABSetupListCtxtSURes,

	) InitialContextSetupResponseIEValue

	get func(*InitialContextSetupResponseIEValue,

	) (*s17.ERABSetupListCtxtSURes,

		bool)
}

// Info returns the source descriptor for this binding.
func (b InitialContextSetupResponseERABSetupListCtxtSUResIEBinding) Info() s00.FieldInfo {
	return b.info
}

// Codec returns the complete value codec for this binding.
func (b InitialContextSetupResponseERABSetupListCtxtSUResIEBinding) Codec() s17.ERABSetupListCtxtSUResValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b InitialContextSetupResponseERABSetupListCtxtSUResIEBinding) New(value s17.ERABSetupListCtxtSURes,

) (InitialContextSetupResponseIEField, error) {
	if b.inject == nil {
		return InitialContextSetupResponseIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return InitialContextSetupResponseIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s17.BridgeERABSetupListCtxtSUResValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return InitialContextSetupResponseIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return InitialContextSetupResponseIEField{}, aper.OperationError(err, "Value.New")
	}
	return InitialContextSetupResponseIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b InitialContextSetupResponseERABSetupListCtxtSUResIEBinding) Get(field *InitialContextSetupResponseIEField) (*s17.ERABSetupListCtxtSURes,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// InitialContextSetupResponseERABListIEBinding binds ERABList to the InitialContextSetupResponseIEs object set of TS 36.413.
type InitialContextSetupResponseERABListIEBinding struct {
	info   s00.FieldInfo
	codec  s16.ERABListValueCodec
	inject func(s16.ERABList,

	) InitialContextSetupResponseIEValue

	get func(*InitialContextSetupResponseIEValue,

	) (*s16.ERABList,

		bool)
}

// Info returns the source descriptor for this binding.
func (b InitialContextSetupResponseERABListIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b InitialContextSetupResponseERABListIEBinding) Codec() s16.ERABListValueCodec { return b.codec }

// New validates a source value and constructs its bound field.
func (b InitialContextSetupResponseERABListIEBinding) New(value s16.ERABList,

) (InitialContextSetupResponseIEField, error) {
	if b.inject == nil {
		return InitialContextSetupResponseIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return InitialContextSetupResponseIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s16.BridgeERABListValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return InitialContextSetupResponseIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return InitialContextSetupResponseIEField{}, aper.OperationError(err, "Value.New")
	}
	return InitialContextSetupResponseIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b InitialContextSetupResponseERABListIEBinding) Get(field *InitialContextSetupResponseIEField) (*s16.ERABList,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// InitialContextSetupResponseCriticalityDiagnosticsIEBinding binds CriticalityDiagnostics to the InitialContextSetupResponseIEs object set of TS 36.413.
type InitialContextSetupResponseCriticalityDiagnosticsIEBinding struct {
	info   s00.FieldInfo
	codec  s22.CriticalityDiagnosticsValueCodec
	inject func(s22.CriticalityDiagnostics,

	) InitialContextSetupResponseIEValue

	get func(*InitialContextSetupResponseIEValue,

	) (*s22.CriticalityDiagnostics,

		bool)
}

// Info returns the source descriptor for this binding.
func (b InitialContextSetupResponseCriticalityDiagnosticsIEBinding) Info() s00.FieldInfo {
	return b.info
}

// Codec returns the complete value codec for this binding.
func (b InitialContextSetupResponseCriticalityDiagnosticsIEBinding) Codec() s22.CriticalityDiagnosticsValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b InitialContextSetupResponseCriticalityDiagnosticsIEBinding) New(value s22.CriticalityDiagnostics,

) (InitialContextSetupResponseIEField, error) {
	if b.inject == nil {
		return InitialContextSetupResponseIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return InitialContextSetupResponseIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s22.BridgeCriticalityDiagnosticsValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return InitialContextSetupResponseIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return InitialContextSetupResponseIEField{}, aper.OperationError(err, "Value.New")
	}
	return InitialContextSetupResponseIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b InitialContextSetupResponseCriticalityDiagnosticsIEBinding) Get(field *InitialContextSetupResponseIEField) (*s22.CriticalityDiagnostics,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// ERABModificationConfirmValueCodec is the concrete ValueCodec[ERABModificationConfirm].
type ERABModificationConfirmValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ERABModificationConfirm,

		error)
	encode func(ERABModificationConfirm,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ERABModificationConfirm, aper.DecodeState,

	) (ERABModificationConfirm, aper.Snapshot,

	)
	compare func(ERABModificationConfirm, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ERABModificationConfirmValueCodec) New(value ERABModificationConfirm,

) (ERABModificationConfirmAPERValue, error) {
	if c.encode == nil {
		return ERABModificationConfirmAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ERABModificationConfirmAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ERABModificationConfirmAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ERABModificationConfirmAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ERABModificationConfirmValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ERABModificationConfirmAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ERABModificationConfirmAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ERABModificationConfirmAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ERABModificationConfirmAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ERABModificationConfirmAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ERABModificationConfirmValueCodec) EncodeAPER(value ERABModificationConfirmAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c ERABModificationConfirmValueCodec) encodeBudgetValue(value ERABModificationConfirm,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ERABModificationConfirmValueCodec) encodeChanged(value ERABModificationConfirm,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ERABReleaseCommandValueCodec is the concrete ValueCodec[ERABReleaseCommand].
type ERABReleaseCommandValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ERABReleaseCommand,

		error)
	encode func(ERABReleaseCommand,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ERABReleaseCommand, aper.DecodeState,

	) (ERABReleaseCommand, aper.Snapshot,

	)
	compare func(ERABReleaseCommand, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ERABReleaseCommandValueCodec) New(value ERABReleaseCommand,

) (ERABReleaseCommandAPERValue, error) {
	if c.encode == nil {
		return ERABReleaseCommandAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ERABReleaseCommandAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ERABReleaseCommandAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ERABReleaseCommandAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ERABReleaseCommandValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ERABReleaseCommandAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ERABReleaseCommandAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ERABReleaseCommandAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ERABReleaseCommandAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ERABReleaseCommandAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ERABReleaseCommandValueCodec) EncodeAPER(value ERABReleaseCommandAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c ERABReleaseCommandValueCodec) encodeBudgetValue(value ERABReleaseCommand,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ERABReleaseCommandValueCodec) encodeChanged(value ERABReleaseCommand,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// HandoverRequestAcknowledgeValueCodec is the concrete ValueCodec[HandoverRequestAcknowledge].
type HandoverRequestAcknowledgeValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (HandoverRequestAcknowledge,

		error)
	encode func(HandoverRequestAcknowledge,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(HandoverRequestAcknowledge, aper.DecodeState,

	) (HandoverRequestAcknowledge, aper.Snapshot,

	)
	compare func(HandoverRequestAcknowledge, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c HandoverRequestAcknowledgeValueCodec) New(value HandoverRequestAcknowledge,

) (HandoverRequestAcknowledgeAPERValue, error) {
	if c.encode == nil {
		return HandoverRequestAcknowledgeAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return HandoverRequestAcknowledgeAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return HandoverRequestAcknowledgeAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return HandoverRequestAcknowledgeAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c HandoverRequestAcknowledgeValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (HandoverRequestAcknowledgeAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return HandoverRequestAcknowledgeAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return HandoverRequestAcknowledgeAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return HandoverRequestAcknowledgeAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return HandoverRequestAcknowledgeAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c HandoverRequestAcknowledgeValueCodec) EncodeAPER(value HandoverRequestAcknowledgeAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c HandoverRequestAcknowledgeValueCodec) encodeBudgetValue(value HandoverRequestAcknowledge,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c HandoverRequestAcknowledgeValueCodec) encodeChanged(value HandoverRequestAcknowledge,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// TargeteNBToSourceeNBTransparentContainerValueCodec is the concrete ValueCodec[TargeteNBToSourceeNBTransparentContainer].
type TargeteNBToSourceeNBTransparentContainerValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (TargeteNBToSourceeNBTransparentContainer,

		error)
	encode func(TargeteNBToSourceeNBTransparentContainer,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(TargeteNBToSourceeNBTransparentContainer, aper.DecodeState,

	) (TargeteNBToSourceeNBTransparentContainer, aper.Snapshot,

	)
	compare func(TargeteNBToSourceeNBTransparentContainer, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c TargeteNBToSourceeNBTransparentContainerValueCodec) New(value TargeteNBToSourceeNBTransparentContainer,

) (TargeteNBToSourceeNBTransparentContainerAPERValue, error) {
	if c.encode == nil {
		return TargeteNBToSourceeNBTransparentContainerAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return TargeteNBToSourceeNBTransparentContainerAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return TargeteNBToSourceeNBTransparentContainerAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return TargeteNBToSourceeNBTransparentContainerAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c TargeteNBToSourceeNBTransparentContainerValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (TargeteNBToSourceeNBTransparentContainerAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return TargeteNBToSourceeNBTransparentContainerAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return TargeteNBToSourceeNBTransparentContainerAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return TargeteNBToSourceeNBTransparentContainerAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return TargeteNBToSourceeNBTransparentContainerAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c TargeteNBToSourceeNBTransparentContainerValueCodec) EncodeAPER(value TargeteNBToSourceeNBTransparentContainerAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c TargeteNBToSourceeNBTransparentContainerValueCodec) encodeBudgetValue(value TargeteNBToSourceeNBTransparentContainer,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c TargeteNBToSourceeNBTransparentContainerValueCodec) encodeChanged(value TargeteNBToSourceeNBTransparentContainer,

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
func BridgeHandoverRequestAcknowledgeIEValueValidateS1APIEContainer(fields HandoverRequestAcknowledgeIEContainer, rows []s00.FieldInfo, path string, budget *aper.DecodeBudget,

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
func BridgeERABReleaseCommandIEValueValidateS1APIEContainer(fields ERABReleaseCommandIEContainer, rows []s00.FieldInfo, path string, budget *aper.DecodeBudget,

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
func BridgeERABModificationConfirmIEValueValidateS1APIEContainer(fields ERABModificationConfirmIEContainer, rows []s00.FieldInfo, path string, budget *aper.DecodeBudget,

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
func BridgeUEContextResumeResponseIEValueValidateS1APIEContainer(fields s38.UEContextResumeResponseIEContainer, rows []s00.FieldInfo, path string, budget *aper.DecodeBudget,

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
		if !s38.BridgeUEContextResumeResponseIEValueMethodMatchesID(field.Value, field.Id, budget) {
			rule := s38.BridgeUEContextResumeResponseIEValueMethodRule(field.Value)
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.ValueIDMismatch, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: aper.Path(fmt.Sprintf("%s.id", location.Path))}, Table: func() s00.TableID {
				sealed := s00.TableID{}
				*s00.BridgeTableIDFieldSource(&sealed) = rule.Assignment
				return sealed
			}(), IEID: field.Id, HasIEID: true, Rule: s26.BridgeS1apValidationRule(s00.ValueIDMismatch), RelatedRules: []aper.SourceRule{rule}})
		}
		rank, allowed := byID[field.Id]
		table := func() s00.TableID {
			sealed := s00.TableID{}
			*s00.BridgeTableIDFieldSource(&sealed) = s38.BridgeUEContextResumeResponseIEValueMethodRule(field.Value).Assignment
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
func BridgeTargeteNBToSourceeNBTransparentContainerExtIEsValueValidateS1APExtensionContainer(fields TargeteNBToSourceeNBTransparentContainerExtIEsExtContainer, rows []s00.FieldInfo, path string, budget *aper.DecodeBudget) s21.ValidationReport {
	bb := aper.NewBudgetBuffer(budget)
	if err := aper.ChargeSlice[TargeteNBToSourceeNBTransparentContainerExtIEsIEField](bb, uint64(len(fields))); err != nil {
		return func() s21.ValidationReport {
			sealed := s21.ValidationReport{}
			*s21.BridgeValidationReportFieldErr(&sealed) = err
			*s21.BridgeValidationReportFieldBudget(&sealed) = budget
			return sealed
		}()
	}
	asIE := make(TargeteNBToSourceeNBTransparentContainerExtIEsIEContainer, len(fields))
	for i := range fields {
		asIE[i].Id = fields[i].Id
		asIE[i].Criticality = fields[i].Criticality
		asIE[i].Value = fields[i].ExtensionValue
	}
	return BridgeTargeteNBToSourceeNBTransparentContainerExtIEsValueValidateS1APIEContainer(asIE, rows, path, budget)
}

// ERABModificationConfirmIEValueERABIEContainerListCodec constructs the E-RAB-IE-ContainerList {{E-RABModificationConfirmIEs}} codec of TS 36.413.
func ERABModificationConfirmIEValueERABIEContainerListCodec(table s00.ERABModificationConfirmIEValueIETable) ERABModificationConfirmIEValueERABIEContainerListValueCodec {
	codec := ERABModificationConfirmIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if codec.decode == nil {
		return ERABModificationConfirmIEValueERABIEContainerListValueCodec{}
	}
	return ERABModificationConfirmIEValueERABIEContainerListValueCodec{decode: func(data []byte, options aper.DecodeState) (ERABModificationConfirmIEValueERABIEContainerList, error) {
		value, err := codec.decode(data, options)
		return ERABModificationConfirmIEValueERABIEContainerList(value), err
	}, encode: func(value ERABModificationConfirmIEValueERABIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return codec.encode(ERABModificationConfirmIEContainer(value), fresh, budget)
	}, capture: func(v ERABModificationConfirmIEValueERABIEContainerList, options aper.DecodeState) (ERABModificationConfirmIEValueERABIEContainerList, aper.Snapshot) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeERABModificationConfirmIEValueCaptureS1APERABIEContainerList(&v, &s)
		var root aper.Snapshot
		s.End(f, &root, false)
		return v, root
	}, compare: func(v ERABModificationConfirmIEValueERABIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
	) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		BridgeERABModificationConfirmIEValueCompareS1APERABIEContainerList(&v, &s)
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

// ERABReleaseCommandIEValueERABIEContainerListCodec constructs the E-RAB-IE-ContainerList {{E-RABReleaseCommandIEs}} codec of TS 36.413.
func ERABReleaseCommandIEValueERABIEContainerListCodec(table s00.ERABReleaseCommandIEValueIETable) ERABReleaseCommandIEValueERABIEContainerListValueCodec {
	codec := ERABReleaseCommandIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if codec.decode == nil {
		return ERABReleaseCommandIEValueERABIEContainerListValueCodec{}
	}
	return ERABReleaseCommandIEValueERABIEContainerListValueCodec{decode: func(data []byte, options aper.DecodeState) (ERABReleaseCommandIEValueERABIEContainerList, error) {
		value, err := codec.decode(data, options)
		return ERABReleaseCommandIEValueERABIEContainerList(value), err
	}, encode: func(value ERABReleaseCommandIEValueERABIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return codec.encode(ERABReleaseCommandIEContainer(value), fresh, budget)
	}, capture: func(v ERABReleaseCommandIEValueERABIEContainerList, options aper.DecodeState) (ERABReleaseCommandIEValueERABIEContainerList, aper.Snapshot) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeERABReleaseCommandIEValueCaptureS1APERABIEContainerList(&v, &s)
		var root aper.Snapshot
		s.End(f, &root, false)
		return v, root
	}, compare: func(v ERABReleaseCommandIEValueERABIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
	) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		BridgeERABReleaseCommandIEValueCompareS1APERABIEContainerList(&v, &s)
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

// HandoverRequestAcknowledgeIEValueERABIEContainerListCodec constructs the E-RAB-IE-ContainerList {{HandoverRequestAcknowledgeIEs}} codec of TS 36.413.
func HandoverRequestAcknowledgeIEValueERABIEContainerListCodec(table s00.HandoverRequestAcknowledgeIEValueIETable) HandoverRequestAcknowledgeIEValueERABIEContainerListValueCodec {
	codec := HandoverRequestAcknowledgeIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if codec.decode == nil {
		return HandoverRequestAcknowledgeIEValueERABIEContainerListValueCodec{}
	}
	return HandoverRequestAcknowledgeIEValueERABIEContainerListValueCodec{decode: func(data []byte, options aper.DecodeState) (HandoverRequestAcknowledgeIEValueERABIEContainerList, error) {
		value, err := codec.decode(data, options)
		return HandoverRequestAcknowledgeIEValueERABIEContainerList(value), err
	}, encode: func(value HandoverRequestAcknowledgeIEValueERABIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return codec.encode(HandoverRequestAcknowledgeIEContainer(value), fresh, budget)
	}, capture: func(v HandoverRequestAcknowledgeIEValueERABIEContainerList, options aper.DecodeState) (HandoverRequestAcknowledgeIEValueERABIEContainerList, aper.Snapshot) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeHandoverRequestAcknowledgeIEValueCaptureS1APERABIEContainerList(&v, &s)
		var root aper.Snapshot
		s.End(f, &root, false)
		return v, root
	}, compare: func(v HandoverRequestAcknowledgeIEValueERABIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
	) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		BridgeHandoverRequestAcknowledgeIEValueCompareS1APERABIEContainerList(&v, &s)
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

// TargeteNBToSourceeNBTransparentContainerExtIEsValueExtensionFieldTableCodec constructs the ProtocolExtensionField {{TargeteNB-ToSourceeNB-TransparentContainer-ExtIEs}} codec of TS 36.413.
func TargeteNBToSourceeNBTransparentContainerExtIEsValueExtensionFieldTableCodec(table s00.TargeteNBToSourceeNBTransparentContainerExtIEsValueExtensionTable) TargeteNBToSourceeNBTransparentContainerExtIEsExtFieldValueCodec {
	if !*s00.BridgeTargeteNBToSourceeNBTransparentContainerExtIEsValueExtensionTableFieldBound(&table) {
		return TargeteNBToSourceeNBTransparentContainerExtIEsExtFieldValueCodec{}
	}
	return TargeteNBToSourceeNBTransparentContainerExtIEsExtFieldValueCodec{decode: func(data []byte, options aper.DecodeState) (TargeteNBToSourceeNBTransparentContainerExtIEsExtField, error) {
		var field TargeteNBToSourceeNBTransparentContainerExtIEsExtField
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
	}, encode: func(field TargeteNBToSourceeNBTransparentContainerExtIEsExtField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		bb := aper.NewBudgetBuffer(budget)
		if err := field.marshalAPERTo(bb, fresh); err != nil {
			return nil, err
		}
		return bb.CompleteBytes(), nil
	}, capture: func(v TargeteNBToSourceeNBTransparentContainerExtIEsExtField, options aper.DecodeState) (TargeteNBToSourceeNBTransparentContainerExtIEsExtField, aper.Snapshot,
	) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeTargeteNBToSourceeNBTransparentContainerExtIEsValueCaptureS1APProtocolExtensionField(&v, &s)
		var root aper.Snapshot
		s.End(f, &root,
			false)
		return v, root
	}, compare: func(v TargeteNBToSourceeNBTransparentContainerExtIEsExtField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
	) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		BridgeTargeteNBToSourceeNBTransparentContainerExtIEsValueCompareS1APProtocolExtensionField(&v, &s)
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

// TargeteNBToSourceeNBTransparentContainerExtIEsValueExtensionTableCodec constructs the ProtocolExtensionContainer {{TargeteNB-ToSourceeNB-TransparentContainer-ExtIEs}} codec of TS 36.413.
func TargeteNBToSourceeNBTransparentContainerExtIEsValueExtensionTableCodec(table s00.TargeteNBToSourceeNBTransparentContainerExtIEsValueExtensionTable, bounds aper.ListBounds) TargeteNBToSourceeNBTransparentContainerExtIEsExtContainerValueCodec {
	if !*s00.BridgeTargeteNBToSourceeNBTransparentContainerExtIEsValueExtensionTableFieldBound(&table) {
		return TargeteNBToSourceeNBTransparentContainerExtIEsExtContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return TargeteNBToSourceeNBTransparentContainerExtIEsExtContainerValueCodec{decode: func(data []byte, options aper.DecodeState) (TargeteNBToSourceeNBTransparentContainerExtIEsExtContainer, error) {
		bb := aper.NewCompleteDecodeBuffer(data, options)
		if err := bb.SetDecodeOptionsAligned(options); err != nil {
			return nil, err
		}
		var fields TargeteNBToSourceeNBTransparentContainerExtIEsExtContainer
		_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
			for i := int64(0); i < length; i++ {
				var field TargeteNBToSourceeNBTransparentContainerExtIEsExtField
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
		encode: func(fields TargeteNBToSourceeNBTransparentContainerExtIEsExtContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
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
		}, capture: func(v TargeteNBToSourceeNBTransparentContainerExtIEsExtContainer, options aper.DecodeState) (TargeteNBToSourceeNBTransparentContainerExtIEsExtContainer, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeTargeteNBToSourceeNBTransparentContainerExtIEsValueCaptureS1APProtocolExtensionContainer(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}, compare: func(v TargeteNBToSourceeNBTransparentContainerExtIEsExtContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.
				Begin()
			BridgeTargeteNBToSourceeNBTransparentContainerExtIEsValueCompareS1APProtocolExtensionContainer(&v, &s)
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

// ERABModificationConfirmIEValueIEFieldTableCodec constructs the ProtocolIE-Field {{E-RABModificationConfirmIEs}} codec of TS 36.413.
func ERABModificationConfirmIEValueIEFieldTableCodec(table s00.ERABModificationConfirmIEValueIETable) ERABModificationConfirmIEFieldValueCodec {
	if !*s00.BridgeERABModificationConfirmIEValueIETableFieldBound(&table) {
		return ERABModificationConfirmIEFieldValueCodec{}
	}
	return ERABModificationConfirmIEFieldValueCodec{decode: func(data []byte, options aper.DecodeState) (ERABModificationConfirmIEField, error) {
		var field ERABModificationConfirmIEField
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
	}, encode: func(field ERABModificationConfirmIEField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		bb := aper.NewBudgetBuffer(budget)
		if err := field.marshalAPERTo(bb, fresh); err != nil {
			return nil, err
		}
		return bb.CompleteBytes(), nil
	}, capture: func(v ERABModificationConfirmIEField, options aper.DecodeState) (ERABModificationConfirmIEField, aper.Snapshot,
	) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeERABModificationConfirmIEValueCaptureS1APProtocolIEField(&v,
			&s)
		var root aper.Snapshot
		s.End(f, &root, false)
		return v,
			root
	}, compare: func(v ERABModificationConfirmIEField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

	) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		BridgeERABModificationConfirmIEValueCompareS1APProtocolIEField(&v, &s)
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

// ERABReleaseCommandIEValueIEFieldTableCodec constructs the ProtocolIE-Field {{E-RABReleaseCommandIEs}} codec of TS 36.413.
func ERABReleaseCommandIEValueIEFieldTableCodec(table s00.ERABReleaseCommandIEValueIETable) ERABReleaseCommandIEFieldValueCodec {
	if !*s00.BridgeERABReleaseCommandIEValueIETableFieldBound(&table) {
		return ERABReleaseCommandIEFieldValueCodec{}
	}
	return ERABReleaseCommandIEFieldValueCodec{decode: func(data []byte, options aper.DecodeState) (ERABReleaseCommandIEField, error) {
		var field ERABReleaseCommandIEField
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
	}, encode: func(field ERABReleaseCommandIEField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		bb := aper.NewBudgetBuffer(budget)
		if err := field.marshalAPERTo(bb, fresh); err != nil {
			return nil, err
		}
		return bb.CompleteBytes(), nil
	}, capture: func(v ERABReleaseCommandIEField, options aper.DecodeState) (ERABReleaseCommandIEField, aper.Snapshot,
	) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeERABReleaseCommandIEValueCaptureS1APProtocolIEField(&v,
			&s)
		var root aper.Snapshot
		s.End(f, &root, false)
		return v,
			root
	}, compare: func(v ERABReleaseCommandIEField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

	) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		BridgeERABReleaseCommandIEValueCompareS1APProtocolIEField(&v, &s)
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

// HandoverRequestAcknowledgeIEValueIEFieldTableCodec constructs the ProtocolIE-Field {{HandoverRequestAcknowledgeIEs}} codec of TS 36.413.
func HandoverRequestAcknowledgeIEValueIEFieldTableCodec(table s00.HandoverRequestAcknowledgeIEValueIETable) HandoverRequestAcknowledgeIEFieldValueCodec {
	if !*s00.BridgeHandoverRequestAcknowledgeIEValueIETableFieldBound(&table) {
		return HandoverRequestAcknowledgeIEFieldValueCodec{}
	}
	return HandoverRequestAcknowledgeIEFieldValueCodec{decode: func(data []byte, options aper.DecodeState) (HandoverRequestAcknowledgeIEField, error) {
		var field HandoverRequestAcknowledgeIEField
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
	}, encode: func(field HandoverRequestAcknowledgeIEField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		bb := aper.NewBudgetBuffer(budget)
		if err := field.marshalAPERTo(bb, fresh); err != nil {
			return nil, err
		}
		return bb.CompleteBytes(), nil
	}, capture: func(v HandoverRequestAcknowledgeIEField, options aper.DecodeState) (HandoverRequestAcknowledgeIEField, aper.Snapshot,
	) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeHandoverRequestAcknowledgeIEValueCaptureS1APProtocolIEField(&v,
			&s)
		var root aper.Snapshot
		s.End(f, &root, false)
		return v,
			root
	}, compare: func(v HandoverRequestAcknowledgeIEField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

	) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		BridgeHandoverRequestAcknowledgeIEValueCompareS1APProtocolIEField(&v, &s)
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

// ERABModificationConfirmIEValueIETableCodec constructs the ProtocolIE-Container {{E-RABModificationConfirmIEs}} codec of TS 36.413.
func ERABModificationConfirmIEValueIETableCodec(table s00.ERABModificationConfirmIEValueIETable, bounds aper.ListBounds) ERABModificationConfirmIEContainerValueCodec {
	if !*s00.BridgeERABModificationConfirmIEValueIETableFieldBound(&table) {
		return ERABModificationConfirmIEContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return ERABModificationConfirmIEContainerValueCodec{decode: func(data []byte, options aper.DecodeState) (ERABModificationConfirmIEContainer, error) {
		bb := aper.NewCompleteDecodeBuffer(data, options)
		if err := bb.SetDecodeOptionsAligned(options); err != nil {
			return nil, err
		}
		var fields ERABModificationConfirmIEContainer
		_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
			for i := int64(0); i < length; i++ {
				var field ERABModificationConfirmIEField
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
		encode: func(fields ERABModificationConfirmIEContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
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
		}, capture: func(v ERABModificationConfirmIEContainer, options aper.DecodeState) (ERABModificationConfirmIEContainer, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeERABModificationConfirmIEValueCaptureS1APProtocolIEContainer(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}, compare: func(v ERABModificationConfirmIEContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeERABModificationConfirmIEValueCompareS1APProtocolIEContainer(&v, &s)
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

// ERABReleaseCommandIEValueIETableCodec constructs the ProtocolIE-Container {{E-RABReleaseCommandIEs}} codec of TS 36.413.
func ERABReleaseCommandIEValueIETableCodec(table s00.ERABReleaseCommandIEValueIETable, bounds aper.ListBounds) ERABReleaseCommandIEContainerValueCodec {
	if !*s00.BridgeERABReleaseCommandIEValueIETableFieldBound(&table) {
		return ERABReleaseCommandIEContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return ERABReleaseCommandIEContainerValueCodec{decode: func(data []byte, options aper.DecodeState) (ERABReleaseCommandIEContainer, error) {
		bb := aper.NewCompleteDecodeBuffer(data, options)
		if err := bb.SetDecodeOptionsAligned(options); err != nil {
			return nil, err
		}
		var fields ERABReleaseCommandIEContainer
		_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
			for i := int64(0); i < length; i++ {
				var field ERABReleaseCommandIEField
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
		encode: func(fields ERABReleaseCommandIEContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
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
		}, capture: func(v ERABReleaseCommandIEContainer, options aper.DecodeState) (ERABReleaseCommandIEContainer, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeERABReleaseCommandIEValueCaptureS1APProtocolIEContainer(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}, compare: func(v ERABReleaseCommandIEContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeERABReleaseCommandIEValueCompareS1APProtocolIEContainer(&v, &s)
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

// HandoverRequestAcknowledgeIEValueIETableCodec constructs the ProtocolIE-Container {{HandoverRequestAcknowledgeIEs}} codec of TS 36.413.
func HandoverRequestAcknowledgeIEValueIETableCodec(table s00.HandoverRequestAcknowledgeIEValueIETable, bounds aper.ListBounds) HandoverRequestAcknowledgeIEContainerValueCodec {
	if !*s00.BridgeHandoverRequestAcknowledgeIEValueIETableFieldBound(&table) {
		return HandoverRequestAcknowledgeIEContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return HandoverRequestAcknowledgeIEContainerValueCodec{decode: func(data []byte, options aper.DecodeState) (HandoverRequestAcknowledgeIEContainer, error) {
		bb := aper.NewCompleteDecodeBuffer(data, options)
		if err := bb.SetDecodeOptionsAligned(options); err != nil {
			return nil, err
		}
		var fields HandoverRequestAcknowledgeIEContainer
		_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
			for i := int64(0); i < length; i++ {
				var field HandoverRequestAcknowledgeIEField
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
		encode: func(fields HandoverRequestAcknowledgeIEContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
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
		}, capture: func(v HandoverRequestAcknowledgeIEContainer, options aper.DecodeState) (HandoverRequestAcknowledgeIEContainer, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeHandoverRequestAcknowledgeIEValueCaptureS1APProtocolIEContainer(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}, compare: func(v HandoverRequestAcknowledgeIEContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeHandoverRequestAcknowledgeIEValueCompareS1APProtocolIEContainer(&v, &s)
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

// ERABModificationConfirmIEValueProtocolErrorIEContainerListCodec constructs the ProtocolError-IE-ContainerList {{E-RABModificationConfirmIEs}} codec of TS 36.413.
func ERABModificationConfirmIEValueProtocolErrorIEContainerListCodec(table s00.ERABModificationConfirmIEValueIETable) ERABModificationConfirmIEValueProtocolErrorIEContainerListValueCodec {
	codec := ERABModificationConfirmIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if codec.decode == nil {
		return ERABModificationConfirmIEValueProtocolErrorIEContainerListValueCodec{}
	}
	return ERABModificationConfirmIEValueProtocolErrorIEContainerListValueCodec{decode: func(data []byte, options aper.DecodeState) (ERABModificationConfirmIEValueProtocolErrorIEContainerList, error) {
		value, err := codec.decode(data, options)
		return ERABModificationConfirmIEValueProtocolErrorIEContainerList(value), err
	}, encode: func(value ERABModificationConfirmIEValueProtocolErrorIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return codec.encode(ERABModificationConfirmIEContainer(value), fresh, budget)
	}, capture: func(v ERABModificationConfirmIEValueProtocolErrorIEContainerList, options aper.DecodeState) (ERABModificationConfirmIEValueProtocolErrorIEContainerList, aper.Snapshot,
	) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeERABModificationConfirmIEValueCaptureS1APProtocolErrorIEContainerList(&v, &s)
		var root aper.Snapshot

		s.End(f, &root, false)
		return v, root
	}, compare: func(v ERABModificationConfirmIEValueProtocolErrorIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

	) {
		s := aper.NewSemanticComparison(root, budget)
		f :=
			s.
				Begin()
		BridgeERABModificationConfirmIEValueCompareS1APProtocolErrorIEContainerList(&v, &s)
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

// ERABReleaseCommandIEValueProtocolErrorIEContainerListCodec constructs the ProtocolError-IE-ContainerList {{E-RABReleaseCommandIEs}} codec of TS 36.413.
func ERABReleaseCommandIEValueProtocolErrorIEContainerListCodec(table s00.ERABReleaseCommandIEValueIETable) ERABReleaseCommandIEValueProtocolErrorIEContainerListValueCodec {
	codec := ERABReleaseCommandIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if codec.decode == nil {
		return ERABReleaseCommandIEValueProtocolErrorIEContainerListValueCodec{}
	}
	return ERABReleaseCommandIEValueProtocolErrorIEContainerListValueCodec{decode: func(data []byte, options aper.DecodeState) (ERABReleaseCommandIEValueProtocolErrorIEContainerList, error) {
		value, err := codec.decode(data, options)
		return ERABReleaseCommandIEValueProtocolErrorIEContainerList(value), err
	}, encode: func(value ERABReleaseCommandIEValueProtocolErrorIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return codec.encode(ERABReleaseCommandIEContainer(value), fresh, budget)
	}, capture: func(v ERABReleaseCommandIEValueProtocolErrorIEContainerList, options aper.DecodeState) (ERABReleaseCommandIEValueProtocolErrorIEContainerList, aper.Snapshot,
	) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeERABReleaseCommandIEValueCaptureS1APProtocolErrorIEContainerList(&v, &s)
		var root aper.Snapshot

		s.End(f, &root, false)
		return v, root
	}, compare: func(v ERABReleaseCommandIEValueProtocolErrorIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

	) {
		s := aper.NewSemanticComparison(root, budget)
		f :=
			s.
				Begin()
		BridgeERABReleaseCommandIEValueCompareS1APProtocolErrorIEContainerList(&v, &s)
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

// HandoverRequestAcknowledgeIEValueProtocolErrorIEContainerListCodec constructs the ProtocolError-IE-ContainerList {{HandoverRequestAcknowledgeIEs}} codec of TS 36.413.
func HandoverRequestAcknowledgeIEValueProtocolErrorIEContainerListCodec(table s00.HandoverRequestAcknowledgeIEValueIETable) HandoverRequestAcknowledgeIEValueProtocolErrorIEContainerListValueCodec {
	codec := HandoverRequestAcknowledgeIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if codec.decode == nil {
		return HandoverRequestAcknowledgeIEValueProtocolErrorIEContainerListValueCodec{}
	}
	return HandoverRequestAcknowledgeIEValueProtocolErrorIEContainerListValueCodec{decode: func(data []byte, options aper.DecodeState) (HandoverRequestAcknowledgeIEValueProtocolErrorIEContainerList, error) {
		value, err := codec.decode(data, options)
		return HandoverRequestAcknowledgeIEValueProtocolErrorIEContainerList(value), err
	}, encode: func(value HandoverRequestAcknowledgeIEValueProtocolErrorIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return codec.encode(HandoverRequestAcknowledgeIEContainer(value), fresh, budget)
	}, capture: func(v HandoverRequestAcknowledgeIEValueProtocolErrorIEContainerList, options aper.DecodeState) (HandoverRequestAcknowledgeIEValueProtocolErrorIEContainerList, aper.Snapshot,
	) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeHandoverRequestAcknowledgeIEValueCaptureS1APProtocolErrorIEContainerList(&v, &s)
		var root aper.Snapshot

		s.End(f, &root, false)
		return v, root
	}, compare: func(v HandoverRequestAcknowledgeIEValueProtocolErrorIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

	) {
		s := aper.NewSemanticComparison(root, budget)
		f :=
			s.
				Begin()
		BridgeHandoverRequestAcknowledgeIEValueCompareS1APProtocolErrorIEContainerList(&v, &s)
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

// ERABModificationConfirmIEValueProtocolIEContainerListCodec constructs a codec for ProtocolIE-ContainerList with IEsSetParam = {E-RABModificationConfirmIEs} of TS 36.413, with lowerBound and upperBound supplied by its arguments.
func ERABModificationConfirmIEValueProtocolIEContainerListCodec(table s00.ERABModificationConfirmIEValueIETable, bounds aper.ListBounds) ERABModificationConfirmIEValueProtocolIEContainerListValueCodec {
	codec := ERABModificationConfirmIEValueIETableCodec(table, bounds)
	if codec.decode == nil {
		return ERABModificationConfirmIEValueProtocolIEContainerListValueCodec{}
	}
	return ERABModificationConfirmIEValueProtocolIEContainerListValueCodec{decode: func(data []byte, options aper.DecodeState) (ERABModificationConfirmIEValueProtocolIEContainerList, error) {
		value, err := codec.decode(data, options)
		return ERABModificationConfirmIEValueProtocolIEContainerList(value), err
	}, encode: func(value ERABModificationConfirmIEValueProtocolIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return codec.encode(ERABModificationConfirmIEContainer(value), fresh, budget)
	}, capture: func(v ERABModificationConfirmIEValueProtocolIEContainerList, options aper.DecodeState) (ERABModificationConfirmIEValueProtocolIEContainerList, aper.Snapshot,
	) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeERABModificationConfirmIEValueCaptureS1APProtocolIEContainerList(&v, &s)
		var root aper.Snapshot
		s.End(
			f,
			&root, false)
		return v, root
	}, compare: func(v ERABModificationConfirmIEValueProtocolIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
	) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		BridgeERABModificationConfirmIEValueCompareS1APProtocolIEContainerList(&v, &s)
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

// ERABReleaseCommandIEValueProtocolIEContainerListCodec constructs a codec for ProtocolIE-ContainerList with IEsSetParam = {E-RABReleaseCommandIEs} of TS 36.413, with lowerBound and upperBound supplied by its arguments.
func ERABReleaseCommandIEValueProtocolIEContainerListCodec(table s00.ERABReleaseCommandIEValueIETable, bounds aper.ListBounds) ERABReleaseCommandIEValueProtocolIEContainerListValueCodec {
	codec := ERABReleaseCommandIEValueIETableCodec(table, bounds)
	if codec.decode == nil {
		return ERABReleaseCommandIEValueProtocolIEContainerListValueCodec{}
	}
	return ERABReleaseCommandIEValueProtocolIEContainerListValueCodec{decode: func(data []byte, options aper.DecodeState) (ERABReleaseCommandIEValueProtocolIEContainerList, error) {
		value, err := codec.decode(data, options)
		return ERABReleaseCommandIEValueProtocolIEContainerList(value), err
	}, encode: func(value ERABReleaseCommandIEValueProtocolIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return codec.encode(ERABReleaseCommandIEContainer(value), fresh, budget)
	}, capture: func(v ERABReleaseCommandIEValueProtocolIEContainerList, options aper.DecodeState) (ERABReleaseCommandIEValueProtocolIEContainerList, aper.Snapshot,
	) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeERABReleaseCommandIEValueCaptureS1APProtocolIEContainerList(&v, &s)
		var root aper.Snapshot
		s.End(
			f,
			&root, false)
		return v, root
	}, compare: func(v ERABReleaseCommandIEValueProtocolIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
	) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		BridgeERABReleaseCommandIEValueCompareS1APProtocolIEContainerList(&v, &s)
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

// HandoverRequestAcknowledgeIEValueProtocolIEContainerListCodec constructs a codec for ProtocolIE-ContainerList with IEsSetParam = {HandoverRequestAcknowledgeIEs} of TS 36.413, with lowerBound and upperBound supplied by its arguments.
func HandoverRequestAcknowledgeIEValueProtocolIEContainerListCodec(table s00.HandoverRequestAcknowledgeIEValueIETable, bounds aper.ListBounds) HandoverRequestAcknowledgeIEValueProtocolIEContainerListValueCodec {
	codec := HandoverRequestAcknowledgeIEValueIETableCodec(table, bounds)
	if codec.decode == nil {
		return HandoverRequestAcknowledgeIEValueProtocolIEContainerListValueCodec{}
	}
	return HandoverRequestAcknowledgeIEValueProtocolIEContainerListValueCodec{decode: func(data []byte, options aper.DecodeState) (HandoverRequestAcknowledgeIEValueProtocolIEContainerList, error) {
		value, err := codec.decode(data, options)
		return HandoverRequestAcknowledgeIEValueProtocolIEContainerList(value), err
	}, encode: func(value HandoverRequestAcknowledgeIEValueProtocolIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return codec.encode(HandoverRequestAcknowledgeIEContainer(value), fresh, budget)
	}, capture: func(v HandoverRequestAcknowledgeIEValueProtocolIEContainerList, options aper.DecodeState) (HandoverRequestAcknowledgeIEValueProtocolIEContainerList, aper.Snapshot,
	) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeHandoverRequestAcknowledgeIEValueCaptureS1APProtocolIEContainerList(&v, &s)
		var root aper.Snapshot
		s.End(
			f,
			&root, false)
		return v, root
	}, compare: func(v HandoverRequestAcknowledgeIEValueProtocolIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
	) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		BridgeHandoverRequestAcknowledgeIEValueCompareS1APProtocolIEContainerList(&v, &s)
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

// UEContextResumeResponseIEValueProtocolIEContainerListCodec constructs a codec for ProtocolIE-ContainerList with IEsSetParam = {UEContextResumeResponseIEs} of TS 36.413, with lowerBound and upperBound supplied by its arguments.
func UEContextResumeResponseIEValueProtocolIEContainerListCodec(table s00.UEContextResumeResponseIEValueIETable, bounds aper.ListBounds) s38.UEContextResumeResponseIEValueProtocolIEContainerListValueCodec {
	codec := s38.UEContextResumeResponseIEValueIETableCodec(table, bounds)
	if *s38.BridgeUEContextResumeResponseIEContainerValueCodecFieldDecode(&codec) == nil {
		return s38.UEContextResumeResponseIEValueProtocolIEContainerListValueCodec{}
	}
	return func() s38.UEContextResumeResponseIEValueProtocolIEContainerListValueCodec {
		sealed := s38.UEContextResumeResponseIEValueProtocolIEContainerListValueCodec{}
		*s38.BridgeUEContextResumeResponseIEValueProtocolIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s38.UEContextResumeResponseIEValueProtocolIEContainerList, error) {
			value, err := (*s38.BridgeUEContextResumeResponseIEContainerValueCodecFieldDecode(&codec))(data, options)
			return s38.UEContextResumeResponseIEValueProtocolIEContainerList(value), err
		}
		*s38.BridgeUEContextResumeResponseIEValueProtocolIEContainerListValueCodecFieldEncode(&sealed) = func(value s38.UEContextResumeResponseIEValueProtocolIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s38.BridgeUEContextResumeResponseIEContainerValueCodecFieldEncode(&codec))(s38.UEContextResumeResponseIEContainer(value), fresh, budget)
		}
		*s38.BridgeUEContextResumeResponseIEValueProtocolIEContainerListValueCodecFieldCapture(&sealed) = func(v s38.UEContextResumeResponseIEValueProtocolIEContainerList, options aper.DecodeState) (s38.UEContextResumeResponseIEValueProtocolIEContainerList, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s38.BridgeUEContextResumeResponseIEValueCaptureS1APProtocolIEContainerList(&v, &s)
			var root aper.Snapshot
			s.End(
				f,
				&root, false)
			return v, root
		}
		*s38.BridgeUEContextResumeResponseIEValueProtocolIEContainerListValueCodecFieldCompare(&sealed) = func(v s38.UEContextResumeResponseIEValueProtocolIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s38.BridgeUEContextResumeResponseIEValueCompareS1APProtocolIEContainerList(&v, &s)
			s.End(f, root,

				false)
			return s.Plan(), s.BudgetValue()
		}
		*s38.BridgeUEContextResumeResponseIEValueProtocolIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}

// eRABModificationConfirmIEValueProtocolOpenValue is the concrete protocolOpenValue[ERABModificationConfirmIEValue].
type ERABModificationConfirmIEValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) ERABModificationConfirmIEValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (ERABModificationConfirmIEValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

func BridgeERABModificationConfirmIEValueCaptureS1APProtocolIEField(v *ERABModificationConfirmIEField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolIEID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.Value = v.Value.captureSemantics(*s)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeERABModificationConfirmIEValueCompareS1APProtocolIEField(v *ERABModificationConfirmIEField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s02.BridgeCompareS1APProtocolIEID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = v.Value.compareSemantics(*s)
	s.End(f, v.replay, v.withoutReplay)
}

// eRABReleaseCommandIEValueProtocolOpenValue is the concrete protocolOpenValue[ERABReleaseCommandIEValue].
type ERABReleaseCommandIEValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) ERABReleaseCommandIEValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (ERABReleaseCommandIEValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

func BridgeERABReleaseCommandIEValueCaptureS1APProtocolIEField(v *ERABReleaseCommandIEField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolIEID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.Value = v.Value.captureSemantics(*s)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeERABReleaseCommandIEValueCompareS1APProtocolIEField(v *ERABReleaseCommandIEField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s02.BridgeCompareS1APProtocolIEID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = v.Value.compareSemantics(*s)
	s.End(f, v.replay, v.withoutReplay)
}

// handoverRequestAcknowledgeIEValueProtocolOpenValue is the concrete protocolOpenValue[HandoverRequestAcknowledgeIEValue].
type HandoverRequestAcknowledgeIEValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) HandoverRequestAcknowledgeIEValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (HandoverRequestAcknowledgeIEValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

func BridgeHandoverRequestAcknowledgeIEValueCaptureS1APProtocolIEField(v *HandoverRequestAcknowledgeIEField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolIEID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.Value = v.Value.captureSemantics(*s)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeHandoverRequestAcknowledgeIEValueCompareS1APProtocolIEField(v *HandoverRequestAcknowledgeIEField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s02.BridgeCompareS1APProtocolIEID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = v.Value.compareSemantics(*s)
	s.End(f, v.replay, v.withoutReplay)
}

// targeteNBToSourceeNBTransparentContainerExtIEsValueProtocolOpenValue is the concrete protocolOpenValue[TargeteNBToSourceeNBTransparentContainerExtIEsValue].
type TargeteNBToSourceeNBTransparentContainerExtIEsValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) TargeteNBToSourceeNBTransparentContainerExtIEsValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (TargeteNBToSourceeNBTransparentContainerExtIEsValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

func BridgeTargeteNBToSourceeNBTransparentContainerExtIEsValueCaptureS1APProtocolExtensionField(v *TargeteNBToSourceeNBTransparentContainerExtIEsExtField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolExtensionID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.ExtensionValue = v.ExtensionValue.captureSemantics(*s)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeTargeteNBToSourceeNBTransparentContainerExtIEsValueCompareS1APProtocolExtensionField(v *TargeteNBToSourceeNBTransparentContainerExtIEsExtField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s02.BridgeCompareS1APProtocolExtensionID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = v.ExtensionValue.compareSemantics(*s)
	s.End(f, v.replay, v.withoutReplay)
}

// uEContextResumeResponseIEValueProtocolOpenValue is the concrete protocolOpenValue[UEContextResumeResponseIEValue].
type UEContextResumeResponseIEValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) s38.UEContextResumeResponseIEValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (s38.UEContextResumeResponseIEValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

// ERABModificationConfirmAPERValue is the concrete APERValue[ERABModificationConfirm].
type ERABModificationConfirmAPERValue struct {
	context s00.BridgeCodecContext
	Value   ERABModificationConfirm

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ERABModificationConfirmAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ERABModificationConfirmAPERValue) WithoutReplay() ERABModificationConfirmAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ERABReleaseCommandAPERValue is the concrete APERValue[ERABReleaseCommand].
type ERABReleaseCommandAPERValue struct {
	context s00.BridgeCodecContext
	Value   ERABReleaseCommand

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ERABReleaseCommandAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ERABReleaseCommandAPERValue) WithoutReplay() ERABReleaseCommandAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// HandoverRequestAcknowledgeAPERValue is the concrete APERValue[HandoverRequestAcknowledge].
type HandoverRequestAcknowledgeAPERValue struct {
	context s00.BridgeCodecContext
	Value   HandoverRequestAcknowledge

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v HandoverRequestAcknowledgeAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v HandoverRequestAcknowledgeAPERValue) WithoutReplay() HandoverRequestAcknowledgeAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// TargeteNBToSourceeNBTransparentContainerAPERValue is the concrete APERValue[TargeteNBToSourceeNBTransparentContainer].
type TargeteNBToSourceeNBTransparentContainerAPERValue struct {
	context s00.BridgeCodecContext
	Value   TargeteNBToSourceeNBTransparentContainer

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v TargeteNBToSourceeNBTransparentContainerAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v TargeteNBToSourceeNBTransparentContainerAPERValue) WithoutReplay() TargeteNBToSourceeNBTransparentContainerAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// TargeteNBToSourceeNBTransparentContainerExtIEsIEField uses the ProtocolIE-Field shape for object set TargeteNB-ToSourceeNB-TransparentContainer-ExtIEs of TS 36.413.
type TargeteNBToSourceeNBTransparentContainerExtIEsIEField struct {
	withoutReplay bool
	replay        aper.Snapshot
	stream        aper.WireSpan
	Id            s00.ProtocolIEID
	Criticality   s00.Criticality
	Value         TargeteNBToSourceeNBTransparentContainerExtIEsValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v TargeteNBToSourceeNBTransparentContainerExtIEsIEField) WithoutReplay() TargeteNBToSourceeNBTransparentContainerExtIEsIEField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *TargeteNBToSourceeNBTransparentContainerExtIEsIEField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *TargeteNBToSourceeNBTransparentContainerExtIEsIEField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
func (v *TargeteNBToSourceeNBTransparentContainerExtIEsIEField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolIEField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = TargeteNBToSourceeNBTransparentContainerExtIEsIEField{}
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
	var zero TargeteNBToSourceeNBTransparentContainerExtIEsValue

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

// TargeteNBToSourceeNBTransparentContainerExtIEsIEContainer uses the ProtocolIE-Container shape for object set TargeteNB-ToSourceeNB-TransparentContainer-ExtIEs of TS 36.413: a list of TargeteNBToSourceeNBTransparentContainerExtIEsIEField values.
type TargeteNBToSourceeNBTransparentContainerExtIEsIEContainer []TargeteNBToSourceeNBTransparentContainerExtIEsIEField

// TS 36.413 V19.2.0 §§9.3.3–9.3.4 supply the selected object-set order and
// presence. §§10.3.1–10.3.6 define abstract-syntax diagnostics. Unknown IEs do
// not determine the order of known rows.
func BridgeTargeteNBToSourceeNBTransparentContainerExtIEsValueValidateS1APIEContainer(fields TargeteNBToSourceeNBTransparentContainerExtIEsIEContainer, rows []s00.FieldInfo, path string, budget *aper.DecodeBudget,

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

// ERABModificationConfirmIEValueERABIEContainerListValueCodec is the concrete ValueCodec[ERABModificationConfirmIEValueERABIEContainerList].
type ERABModificationConfirmIEValueERABIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ERABModificationConfirmIEValueERABIEContainerList, error)
	encode  func(ERABModificationConfirmIEValueERABIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ERABModificationConfirmIEValueERABIEContainerList, aper.DecodeState) (ERABModificationConfirmIEValueERABIEContainerList, aper.Snapshot)
	compare func(ERABModificationConfirmIEValueERABIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ERABModificationConfirmIEValueERABIEContainerListValueCodec) New(value ERABModificationConfirmIEValueERABIEContainerList) (ERABModificationConfirmIEValueERABIEContainerListAPERValue, error) {
	if c.encode == nil {
		return ERABModificationConfirmIEValueERABIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ERABModificationConfirmIEValueERABIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ERABModificationConfirmIEValueERABIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ERABModificationConfirmIEValueERABIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ERABModificationConfirmIEValueERABIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ERABModificationConfirmIEValueERABIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ERABModificationConfirmIEValueERABIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ERABModificationConfirmIEValueERABIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ERABModificationConfirmIEValueERABIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ERABModificationConfirmIEValueERABIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ERABModificationConfirmIEValueERABIEContainerListValueCodec) EncodeAPER(value ERABModificationConfirmIEValueERABIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c ERABModificationConfirmIEValueERABIEContainerListValueCodec) encodeBudgetValue(value ERABModificationConfirmIEValueERABIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ERABModificationConfirmIEValueERABIEContainerListValueCodec) encodeChanged(value ERABModificationConfirmIEValueERABIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ERABModificationConfirmIEValueERABIEContainerList is E-RAB-IE-ContainerList {{E-RABModificationConfirmIEs}} of TS 36.413: a list of information element fields.
type ERABModificationConfirmIEValueERABIEContainerList []ERABModificationConfirmIEValueProtocolIESingleContainer

func BridgeERABModificationConfirmIEValueCaptureS1APERABIEContainerList(v *ERABModificationConfirmIEValueERABIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeERABModificationConfirmIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeERABModificationConfirmIEValueCompareS1APERABIEContainerList(v *ERABModificationConfirmIEValueERABIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeERABModificationConfirmIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}

// ERABReleaseCommandIEValueERABIEContainerListValueCodec is the concrete ValueCodec[ERABReleaseCommandIEValueERABIEContainerList].
type ERABReleaseCommandIEValueERABIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ERABReleaseCommandIEValueERABIEContainerList, error)
	encode  func(ERABReleaseCommandIEValueERABIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ERABReleaseCommandIEValueERABIEContainerList, aper.DecodeState) (ERABReleaseCommandIEValueERABIEContainerList, aper.Snapshot)
	compare func(ERABReleaseCommandIEValueERABIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ERABReleaseCommandIEValueERABIEContainerListValueCodec) New(value ERABReleaseCommandIEValueERABIEContainerList) (ERABReleaseCommandIEValueERABIEContainerListAPERValue, error) {
	if c.encode == nil {
		return ERABReleaseCommandIEValueERABIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ERABReleaseCommandIEValueERABIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ERABReleaseCommandIEValueERABIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ERABReleaseCommandIEValueERABIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ERABReleaseCommandIEValueERABIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ERABReleaseCommandIEValueERABIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ERABReleaseCommandIEValueERABIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ERABReleaseCommandIEValueERABIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ERABReleaseCommandIEValueERABIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ERABReleaseCommandIEValueERABIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ERABReleaseCommandIEValueERABIEContainerListValueCodec) EncodeAPER(value ERABReleaseCommandIEValueERABIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c ERABReleaseCommandIEValueERABIEContainerListValueCodec) encodeBudgetValue(value ERABReleaseCommandIEValueERABIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ERABReleaseCommandIEValueERABIEContainerListValueCodec) encodeChanged(value ERABReleaseCommandIEValueERABIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ERABReleaseCommandIEValueERABIEContainerList is E-RAB-IE-ContainerList {{E-RABReleaseCommandIEs}} of TS 36.413: a list of information element fields.
type ERABReleaseCommandIEValueERABIEContainerList []ERABReleaseCommandIEValueProtocolIESingleContainer

func BridgeERABReleaseCommandIEValueCaptureS1APERABIEContainerList(v *ERABReleaseCommandIEValueERABIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeERABReleaseCommandIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeERABReleaseCommandIEValueCompareS1APERABIEContainerList(v *ERABReleaseCommandIEValueERABIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeERABReleaseCommandIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}

// HandoverRequestAcknowledgeIEValueERABIEContainerListValueCodec is the concrete ValueCodec[HandoverRequestAcknowledgeIEValueERABIEContainerList].
type HandoverRequestAcknowledgeIEValueERABIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (HandoverRequestAcknowledgeIEValueERABIEContainerList, error)
	encode  func(HandoverRequestAcknowledgeIEValueERABIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(HandoverRequestAcknowledgeIEValueERABIEContainerList, aper.DecodeState) (HandoverRequestAcknowledgeIEValueERABIEContainerList, aper.Snapshot)
	compare func(HandoverRequestAcknowledgeIEValueERABIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c HandoverRequestAcknowledgeIEValueERABIEContainerListValueCodec) New(value HandoverRequestAcknowledgeIEValueERABIEContainerList) (HandoverRequestAcknowledgeIEValueERABIEContainerListAPERValue, error) {
	if c.encode == nil {
		return HandoverRequestAcknowledgeIEValueERABIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return HandoverRequestAcknowledgeIEValueERABIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return HandoverRequestAcknowledgeIEValueERABIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return HandoverRequestAcknowledgeIEValueERABIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c HandoverRequestAcknowledgeIEValueERABIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (HandoverRequestAcknowledgeIEValueERABIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return HandoverRequestAcknowledgeIEValueERABIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return HandoverRequestAcknowledgeIEValueERABIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return HandoverRequestAcknowledgeIEValueERABIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return HandoverRequestAcknowledgeIEValueERABIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c HandoverRequestAcknowledgeIEValueERABIEContainerListValueCodec) EncodeAPER(value HandoverRequestAcknowledgeIEValueERABIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c HandoverRequestAcknowledgeIEValueERABIEContainerListValueCodec) encodeBudgetValue(value HandoverRequestAcknowledgeIEValueERABIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c HandoverRequestAcknowledgeIEValueERABIEContainerListValueCodec) encodeChanged(value HandoverRequestAcknowledgeIEValueERABIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// HandoverRequestAcknowledgeIEValueERABIEContainerList is E-RAB-IE-ContainerList {{HandoverRequestAcknowledgeIEs}} of TS 36.413: a list of information element fields.
type HandoverRequestAcknowledgeIEValueERABIEContainerList []HandoverRequestAcknowledgeIEValueProtocolIESingleContainer

func BridgeHandoverRequestAcknowledgeIEValueCaptureS1APERABIEContainerList(v *HandoverRequestAcknowledgeIEValueERABIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeHandoverRequestAcknowledgeIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeHandoverRequestAcknowledgeIEValueCompareS1APERABIEContainerList(v *HandoverRequestAcknowledgeIEValueERABIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeHandoverRequestAcknowledgeIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}

// InitialContextSetupResponseIEValueERABIEContainerListValueCodec is the concrete ValueCodec[InitialContextSetupResponseIEValueERABIEContainerList].
type InitialContextSetupResponseIEValueERABIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (InitialContextSetupResponseIEValueERABIEContainerList, error)
	encode  func(InitialContextSetupResponseIEValueERABIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(InitialContextSetupResponseIEValueERABIEContainerList, aper.DecodeState) (InitialContextSetupResponseIEValueERABIEContainerList, aper.Snapshot)
	compare func(InitialContextSetupResponseIEValueERABIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c InitialContextSetupResponseIEValueERABIEContainerListValueCodec) New(value InitialContextSetupResponseIEValueERABIEContainerList) (InitialContextSetupResponseIEValueERABIEContainerListAPERValue, error) {
	if c.encode == nil {
		return InitialContextSetupResponseIEValueERABIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return InitialContextSetupResponseIEValueERABIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return InitialContextSetupResponseIEValueERABIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return InitialContextSetupResponseIEValueERABIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c InitialContextSetupResponseIEValueERABIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (InitialContextSetupResponseIEValueERABIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return InitialContextSetupResponseIEValueERABIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return InitialContextSetupResponseIEValueERABIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return InitialContextSetupResponseIEValueERABIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return InitialContextSetupResponseIEValueERABIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c InitialContextSetupResponseIEValueERABIEContainerListValueCodec) EncodeAPER(value InitialContextSetupResponseIEValueERABIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c InitialContextSetupResponseIEValueERABIEContainerListValueCodec) encodeBudgetValue(value InitialContextSetupResponseIEValueERABIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c InitialContextSetupResponseIEValueERABIEContainerListValueCodec) encodeChanged(value InitialContextSetupResponseIEValueERABIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// InitialContextSetupResponseIEValueERABIEContainerList is E-RAB-IE-ContainerList {{InitialContextSetupResponseIEs}} of TS 36.413: a list of information element fields.
type InitialContextSetupResponseIEValueERABIEContainerList []InitialContextSetupResponseIEValueProtocolIESingleContainer

// TargeteNBToSourceeNBTransparentContainerExtIEsExtFieldValueCodec is the concrete ValueCodec[TargeteNBToSourceeNBTransparentContainerExtIEsExtField].
type TargeteNBToSourceeNBTransparentContainerExtIEsExtFieldValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (TargeteNBToSourceeNBTransparentContainerExtIEsExtField, error)
	encode  func(TargeteNBToSourceeNBTransparentContainerExtIEsExtField, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(TargeteNBToSourceeNBTransparentContainerExtIEsExtField, aper.DecodeState) (TargeteNBToSourceeNBTransparentContainerExtIEsExtField, aper.Snapshot)
	compare func(TargeteNBToSourceeNBTransparentContainerExtIEsExtField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c TargeteNBToSourceeNBTransparentContainerExtIEsExtFieldValueCodec) New(value TargeteNBToSourceeNBTransparentContainerExtIEsExtField) (TargeteNBToSourceeNBTransparentContainerExtIEsExtFieldAPERValue, error) {
	if c.encode == nil {
		return TargeteNBToSourceeNBTransparentContainerExtIEsExtFieldAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return TargeteNBToSourceeNBTransparentContainerExtIEsExtFieldAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return TargeteNBToSourceeNBTransparentContainerExtIEsExtFieldAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return TargeteNBToSourceeNBTransparentContainerExtIEsExtFieldAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c TargeteNBToSourceeNBTransparentContainerExtIEsExtFieldValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (TargeteNBToSourceeNBTransparentContainerExtIEsExtFieldAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return TargeteNBToSourceeNBTransparentContainerExtIEsExtFieldAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return TargeteNBToSourceeNBTransparentContainerExtIEsExtFieldAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return TargeteNBToSourceeNBTransparentContainerExtIEsExtFieldAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return TargeteNBToSourceeNBTransparentContainerExtIEsExtFieldAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c TargeteNBToSourceeNBTransparentContainerExtIEsExtFieldValueCodec) EncodeAPER(value TargeteNBToSourceeNBTransparentContainerExtIEsExtFieldAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c TargeteNBToSourceeNBTransparentContainerExtIEsExtFieldValueCodec) encodeBudgetValue(value TargeteNBToSourceeNBTransparentContainerExtIEsExtField, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c TargeteNBToSourceeNBTransparentContainerExtIEsExtFieldValueCodec) encodeChanged(value TargeteNBToSourceeNBTransparentContainerExtIEsExtField, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// TargeteNBToSourceeNBTransparentContainerExtIEsExtContainerValueCodec is the concrete ValueCodec[TargeteNBToSourceeNBTransparentContainerExtIEsExtContainer].
type TargeteNBToSourceeNBTransparentContainerExtIEsExtContainerValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (TargeteNBToSourceeNBTransparentContainerExtIEsExtContainer, error)
	encode  func(TargeteNBToSourceeNBTransparentContainerExtIEsExtContainer, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(TargeteNBToSourceeNBTransparentContainerExtIEsExtContainer, aper.DecodeState) (TargeteNBToSourceeNBTransparentContainerExtIEsExtContainer, aper.Snapshot)
	compare func(TargeteNBToSourceeNBTransparentContainerExtIEsExtContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c TargeteNBToSourceeNBTransparentContainerExtIEsExtContainerValueCodec) New(value TargeteNBToSourceeNBTransparentContainerExtIEsExtContainer) (TargeteNBToSourceeNBTransparentContainerExtIEsExtContainerAPERValue, error) {
	if c.encode == nil {
		return TargeteNBToSourceeNBTransparentContainerExtIEsExtContainerAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return TargeteNBToSourceeNBTransparentContainerExtIEsExtContainerAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return TargeteNBToSourceeNBTransparentContainerExtIEsExtContainerAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return TargeteNBToSourceeNBTransparentContainerExtIEsExtContainerAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c TargeteNBToSourceeNBTransparentContainerExtIEsExtContainerValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (TargeteNBToSourceeNBTransparentContainerExtIEsExtContainerAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return TargeteNBToSourceeNBTransparentContainerExtIEsExtContainerAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return TargeteNBToSourceeNBTransparentContainerExtIEsExtContainerAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return TargeteNBToSourceeNBTransparentContainerExtIEsExtContainerAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return TargeteNBToSourceeNBTransparentContainerExtIEsExtContainerAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c TargeteNBToSourceeNBTransparentContainerExtIEsExtContainerValueCodec) EncodeAPER(value TargeteNBToSourceeNBTransparentContainerExtIEsExtContainerAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c TargeteNBToSourceeNBTransparentContainerExtIEsExtContainerValueCodec) encodeBudgetValue(value TargeteNBToSourceeNBTransparentContainerExtIEsExtContainer, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c TargeteNBToSourceeNBTransparentContainerExtIEsExtContainerValueCodec) encodeChanged(value TargeteNBToSourceeNBTransparentContainerExtIEsExtContainer, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ERABModificationConfirmIEFieldValueCodec is the concrete ValueCodec[ERABModificationConfirmIEField].
type ERABModificationConfirmIEFieldValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ERABModificationConfirmIEField, error)
	encode  func(ERABModificationConfirmIEField, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ERABModificationConfirmIEField, aper.DecodeState) (ERABModificationConfirmIEField, aper.Snapshot)
	compare func(ERABModificationConfirmIEField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ERABModificationConfirmIEFieldValueCodec) New(value ERABModificationConfirmIEField) (ERABModificationConfirmIEFieldAPERValue, error) {
	if c.encode == nil {
		return ERABModificationConfirmIEFieldAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ERABModificationConfirmIEFieldAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ERABModificationConfirmIEFieldAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ERABModificationConfirmIEFieldAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ERABModificationConfirmIEFieldValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ERABModificationConfirmIEFieldAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ERABModificationConfirmIEFieldAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ERABModificationConfirmIEFieldAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ERABModificationConfirmIEFieldAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ERABModificationConfirmIEFieldAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ERABModificationConfirmIEFieldValueCodec) EncodeAPER(value ERABModificationConfirmIEFieldAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c ERABModificationConfirmIEFieldValueCodec) encodeBudgetValue(value ERABModificationConfirmIEField, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ERABModificationConfirmIEFieldValueCodec) encodeChanged(value ERABModificationConfirmIEField, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ERABReleaseCommandIEFieldValueCodec is the concrete ValueCodec[ERABReleaseCommandIEField].
type ERABReleaseCommandIEFieldValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ERABReleaseCommandIEField, error)
	encode  func(ERABReleaseCommandIEField, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ERABReleaseCommandIEField, aper.DecodeState) (ERABReleaseCommandIEField, aper.Snapshot)
	compare func(ERABReleaseCommandIEField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ERABReleaseCommandIEFieldValueCodec) New(value ERABReleaseCommandIEField) (ERABReleaseCommandIEFieldAPERValue, error) {
	if c.encode == nil {
		return ERABReleaseCommandIEFieldAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ERABReleaseCommandIEFieldAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ERABReleaseCommandIEFieldAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ERABReleaseCommandIEFieldAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ERABReleaseCommandIEFieldValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ERABReleaseCommandIEFieldAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ERABReleaseCommandIEFieldAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ERABReleaseCommandIEFieldAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ERABReleaseCommandIEFieldAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ERABReleaseCommandIEFieldAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ERABReleaseCommandIEFieldValueCodec) EncodeAPER(value ERABReleaseCommandIEFieldAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c ERABReleaseCommandIEFieldValueCodec) encodeBudgetValue(value ERABReleaseCommandIEField, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ERABReleaseCommandIEFieldValueCodec) encodeChanged(value ERABReleaseCommandIEField, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// HandoverRequestAcknowledgeIEFieldValueCodec is the concrete ValueCodec[HandoverRequestAcknowledgeIEField].
type HandoverRequestAcknowledgeIEFieldValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (HandoverRequestAcknowledgeIEField, error)
	encode  func(HandoverRequestAcknowledgeIEField, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(HandoverRequestAcknowledgeIEField, aper.DecodeState) (HandoverRequestAcknowledgeIEField, aper.Snapshot)
	compare func(HandoverRequestAcknowledgeIEField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c HandoverRequestAcknowledgeIEFieldValueCodec) New(value HandoverRequestAcknowledgeIEField) (HandoverRequestAcknowledgeIEFieldAPERValue, error) {
	if c.encode == nil {
		return HandoverRequestAcknowledgeIEFieldAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return HandoverRequestAcknowledgeIEFieldAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return HandoverRequestAcknowledgeIEFieldAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return HandoverRequestAcknowledgeIEFieldAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c HandoverRequestAcknowledgeIEFieldValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (HandoverRequestAcknowledgeIEFieldAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return HandoverRequestAcknowledgeIEFieldAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return HandoverRequestAcknowledgeIEFieldAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return HandoverRequestAcknowledgeIEFieldAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return HandoverRequestAcknowledgeIEFieldAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c HandoverRequestAcknowledgeIEFieldValueCodec) EncodeAPER(value HandoverRequestAcknowledgeIEFieldAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c HandoverRequestAcknowledgeIEFieldValueCodec) encodeBudgetValue(value HandoverRequestAcknowledgeIEField, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c HandoverRequestAcknowledgeIEFieldValueCodec) encodeChanged(value HandoverRequestAcknowledgeIEField, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// InitialContextSetupResponseIEFieldValueCodec is the concrete ValueCodec[InitialContextSetupResponseIEField].
type InitialContextSetupResponseIEFieldValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (InitialContextSetupResponseIEField, error)
	encode  func(InitialContextSetupResponseIEField, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(InitialContextSetupResponseIEField, aper.DecodeState) (InitialContextSetupResponseIEField, aper.Snapshot)
	compare func(InitialContextSetupResponseIEField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c InitialContextSetupResponseIEFieldValueCodec) New(value InitialContextSetupResponseIEField) (InitialContextSetupResponseIEFieldAPERValue, error) {
	if c.encode == nil {
		return InitialContextSetupResponseIEFieldAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return InitialContextSetupResponseIEFieldAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return InitialContextSetupResponseIEFieldAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return InitialContextSetupResponseIEFieldAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c InitialContextSetupResponseIEFieldValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (InitialContextSetupResponseIEFieldAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return InitialContextSetupResponseIEFieldAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return InitialContextSetupResponseIEFieldAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return InitialContextSetupResponseIEFieldAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return InitialContextSetupResponseIEFieldAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c InitialContextSetupResponseIEFieldValueCodec) EncodeAPER(value InitialContextSetupResponseIEFieldAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c InitialContextSetupResponseIEFieldValueCodec) encodeBudgetValue(value InitialContextSetupResponseIEField, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c InitialContextSetupResponseIEFieldValueCodec) encodeChanged(value InitialContextSetupResponseIEField, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ERABModificationConfirmIEContainerValueCodec is the concrete ValueCodec[ERABModificationConfirmIEContainer].
type ERABModificationConfirmIEContainerValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ERABModificationConfirmIEContainer, error)
	encode  func(ERABModificationConfirmIEContainer, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ERABModificationConfirmIEContainer, aper.DecodeState) (ERABModificationConfirmIEContainer, aper.Snapshot)
	compare func(ERABModificationConfirmIEContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ERABModificationConfirmIEContainerValueCodec) New(value ERABModificationConfirmIEContainer) (ERABModificationConfirmIEContainerAPERValue, error) {
	if c.encode == nil {
		return ERABModificationConfirmIEContainerAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ERABModificationConfirmIEContainerAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ERABModificationConfirmIEContainerAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ERABModificationConfirmIEContainerAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ERABModificationConfirmIEContainerValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ERABModificationConfirmIEContainerAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ERABModificationConfirmIEContainerAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ERABModificationConfirmIEContainerAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ERABModificationConfirmIEContainerAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ERABModificationConfirmIEContainerAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ERABModificationConfirmIEContainerValueCodec) EncodeAPER(value ERABModificationConfirmIEContainerAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c ERABModificationConfirmIEContainerValueCodec) encodeBudgetValue(value ERABModificationConfirmIEContainer, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ERABModificationConfirmIEContainerValueCodec) encodeChanged(value ERABModificationConfirmIEContainer, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ERABReleaseCommandIEContainerValueCodec is the concrete ValueCodec[ERABReleaseCommandIEContainer].
type ERABReleaseCommandIEContainerValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ERABReleaseCommandIEContainer, error)
	encode  func(ERABReleaseCommandIEContainer, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ERABReleaseCommandIEContainer, aper.DecodeState) (ERABReleaseCommandIEContainer, aper.Snapshot)
	compare func(ERABReleaseCommandIEContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ERABReleaseCommandIEContainerValueCodec) New(value ERABReleaseCommandIEContainer) (ERABReleaseCommandIEContainerAPERValue, error) {
	if c.encode == nil {
		return ERABReleaseCommandIEContainerAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ERABReleaseCommandIEContainerAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ERABReleaseCommandIEContainerAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ERABReleaseCommandIEContainerAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ERABReleaseCommandIEContainerValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ERABReleaseCommandIEContainerAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ERABReleaseCommandIEContainerAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ERABReleaseCommandIEContainerAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ERABReleaseCommandIEContainerAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ERABReleaseCommandIEContainerAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ERABReleaseCommandIEContainerValueCodec) EncodeAPER(value ERABReleaseCommandIEContainerAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c ERABReleaseCommandIEContainerValueCodec) encodeBudgetValue(value ERABReleaseCommandIEContainer, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ERABReleaseCommandIEContainerValueCodec) encodeChanged(value ERABReleaseCommandIEContainer, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// HandoverRequestAcknowledgeIEContainerValueCodec is the concrete ValueCodec[HandoverRequestAcknowledgeIEContainer].
type HandoverRequestAcknowledgeIEContainerValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (HandoverRequestAcknowledgeIEContainer, error)
	encode  func(HandoverRequestAcknowledgeIEContainer, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(HandoverRequestAcknowledgeIEContainer, aper.DecodeState) (HandoverRequestAcknowledgeIEContainer, aper.Snapshot)
	compare func(HandoverRequestAcknowledgeIEContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c HandoverRequestAcknowledgeIEContainerValueCodec) New(value HandoverRequestAcknowledgeIEContainer) (HandoverRequestAcknowledgeIEContainerAPERValue, error) {
	if c.encode == nil {
		return HandoverRequestAcknowledgeIEContainerAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return HandoverRequestAcknowledgeIEContainerAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return HandoverRequestAcknowledgeIEContainerAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return HandoverRequestAcknowledgeIEContainerAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c HandoverRequestAcknowledgeIEContainerValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (HandoverRequestAcknowledgeIEContainerAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return HandoverRequestAcknowledgeIEContainerAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return HandoverRequestAcknowledgeIEContainerAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return HandoverRequestAcknowledgeIEContainerAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return HandoverRequestAcknowledgeIEContainerAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c HandoverRequestAcknowledgeIEContainerValueCodec) EncodeAPER(value HandoverRequestAcknowledgeIEContainerAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c HandoverRequestAcknowledgeIEContainerValueCodec) encodeBudgetValue(value HandoverRequestAcknowledgeIEContainer, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c HandoverRequestAcknowledgeIEContainerValueCodec) encodeChanged(value HandoverRequestAcknowledgeIEContainer, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// InitialContextSetupResponseIEContainerValueCodec is the concrete ValueCodec[InitialContextSetupResponseIEContainer].
type InitialContextSetupResponseIEContainerValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (InitialContextSetupResponseIEContainer, error)
	encode  func(InitialContextSetupResponseIEContainer, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(InitialContextSetupResponseIEContainer, aper.DecodeState) (InitialContextSetupResponseIEContainer, aper.Snapshot)
	compare func(InitialContextSetupResponseIEContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c InitialContextSetupResponseIEContainerValueCodec) New(value InitialContextSetupResponseIEContainer) (InitialContextSetupResponseIEContainerAPERValue, error) {
	if c.encode == nil {
		return InitialContextSetupResponseIEContainerAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return InitialContextSetupResponseIEContainerAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return InitialContextSetupResponseIEContainerAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return InitialContextSetupResponseIEContainerAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c InitialContextSetupResponseIEContainerValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (InitialContextSetupResponseIEContainerAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return InitialContextSetupResponseIEContainerAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return InitialContextSetupResponseIEContainerAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return InitialContextSetupResponseIEContainerAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return InitialContextSetupResponseIEContainerAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c InitialContextSetupResponseIEContainerValueCodec) EncodeAPER(value InitialContextSetupResponseIEContainerAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c InitialContextSetupResponseIEContainerValueCodec) encodeBudgetValue(value InitialContextSetupResponseIEContainer, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c InitialContextSetupResponseIEContainerValueCodec) encodeChanged(value InitialContextSetupResponseIEContainer, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ERABModificationConfirmIEValueProtocolErrorIEContainerListValueCodec is the concrete ValueCodec[ERABModificationConfirmIEValueProtocolErrorIEContainerList].
type ERABModificationConfirmIEValueProtocolErrorIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ERABModificationConfirmIEValueProtocolErrorIEContainerList, error)
	encode  func(ERABModificationConfirmIEValueProtocolErrorIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ERABModificationConfirmIEValueProtocolErrorIEContainerList, aper.DecodeState) (ERABModificationConfirmIEValueProtocolErrorIEContainerList, aper.Snapshot)
	compare func(ERABModificationConfirmIEValueProtocolErrorIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ERABModificationConfirmIEValueProtocolErrorIEContainerListValueCodec) New(value ERABModificationConfirmIEValueProtocolErrorIEContainerList) (ERABModificationConfirmIEValueProtocolErrorIEContainerListAPERValue, error) {
	if c.encode == nil {
		return ERABModificationConfirmIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ERABModificationConfirmIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ERABModificationConfirmIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ERABModificationConfirmIEValueProtocolErrorIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ERABModificationConfirmIEValueProtocolErrorIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ERABModificationConfirmIEValueProtocolErrorIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ERABModificationConfirmIEValueProtocolErrorIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ERABModificationConfirmIEValueProtocolErrorIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ERABModificationConfirmIEValueProtocolErrorIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ERABModificationConfirmIEValueProtocolErrorIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ERABModificationConfirmIEValueProtocolErrorIEContainerListValueCodec) EncodeAPER(value ERABModificationConfirmIEValueProtocolErrorIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c ERABModificationConfirmIEValueProtocolErrorIEContainerListValueCodec) encodeBudgetValue(value ERABModificationConfirmIEValueProtocolErrorIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ERABModificationConfirmIEValueProtocolErrorIEContainerListValueCodec) encodeChanged(value ERABModificationConfirmIEValueProtocolErrorIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ERABModificationConfirmIEValueProtocolErrorIEContainerList is ProtocolError-IE-ContainerList {{E-RABModificationConfirmIEs}} of TS 36.413: a list of information element fields.
type ERABModificationConfirmIEValueProtocolErrorIEContainerList []ERABModificationConfirmIEValueProtocolIESingleContainer

func BridgeERABModificationConfirmIEValueCaptureS1APProtocolErrorIEContainerList(v *ERABModificationConfirmIEValueProtocolErrorIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeERABModificationConfirmIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeERABModificationConfirmIEValueCompareS1APProtocolErrorIEContainerList(v *ERABModificationConfirmIEValueProtocolErrorIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeERABModificationConfirmIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}

// ERABReleaseCommandIEValueProtocolErrorIEContainerListValueCodec is the concrete ValueCodec[ERABReleaseCommandIEValueProtocolErrorIEContainerList].
type ERABReleaseCommandIEValueProtocolErrorIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ERABReleaseCommandIEValueProtocolErrorIEContainerList, error)
	encode  func(ERABReleaseCommandIEValueProtocolErrorIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ERABReleaseCommandIEValueProtocolErrorIEContainerList, aper.DecodeState) (ERABReleaseCommandIEValueProtocolErrorIEContainerList, aper.Snapshot)
	compare func(ERABReleaseCommandIEValueProtocolErrorIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ERABReleaseCommandIEValueProtocolErrorIEContainerListValueCodec) New(value ERABReleaseCommandIEValueProtocolErrorIEContainerList) (ERABReleaseCommandIEValueProtocolErrorIEContainerListAPERValue, error) {
	if c.encode == nil {
		return ERABReleaseCommandIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ERABReleaseCommandIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ERABReleaseCommandIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ERABReleaseCommandIEValueProtocolErrorIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ERABReleaseCommandIEValueProtocolErrorIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ERABReleaseCommandIEValueProtocolErrorIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ERABReleaseCommandIEValueProtocolErrorIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ERABReleaseCommandIEValueProtocolErrorIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ERABReleaseCommandIEValueProtocolErrorIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ERABReleaseCommandIEValueProtocolErrorIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ERABReleaseCommandIEValueProtocolErrorIEContainerListValueCodec) EncodeAPER(value ERABReleaseCommandIEValueProtocolErrorIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c ERABReleaseCommandIEValueProtocolErrorIEContainerListValueCodec) encodeBudgetValue(value ERABReleaseCommandIEValueProtocolErrorIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ERABReleaseCommandIEValueProtocolErrorIEContainerListValueCodec) encodeChanged(value ERABReleaseCommandIEValueProtocolErrorIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ERABReleaseCommandIEValueProtocolErrorIEContainerList is ProtocolError-IE-ContainerList {{E-RABReleaseCommandIEs}} of TS 36.413: a list of information element fields.
type ERABReleaseCommandIEValueProtocolErrorIEContainerList []ERABReleaseCommandIEValueProtocolIESingleContainer

func BridgeERABReleaseCommandIEValueCaptureS1APProtocolErrorIEContainerList(v *ERABReleaseCommandIEValueProtocolErrorIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeERABReleaseCommandIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeERABReleaseCommandIEValueCompareS1APProtocolErrorIEContainerList(v *ERABReleaseCommandIEValueProtocolErrorIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeERABReleaseCommandIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}

// HandoverRequestAcknowledgeIEValueProtocolErrorIEContainerListValueCodec is the concrete ValueCodec[HandoverRequestAcknowledgeIEValueProtocolErrorIEContainerList].
type HandoverRequestAcknowledgeIEValueProtocolErrorIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (HandoverRequestAcknowledgeIEValueProtocolErrorIEContainerList, error)
	encode  func(HandoverRequestAcknowledgeIEValueProtocolErrorIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(HandoverRequestAcknowledgeIEValueProtocolErrorIEContainerList, aper.DecodeState) (HandoverRequestAcknowledgeIEValueProtocolErrorIEContainerList, aper.Snapshot)
	compare func(HandoverRequestAcknowledgeIEValueProtocolErrorIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c HandoverRequestAcknowledgeIEValueProtocolErrorIEContainerListValueCodec) New(value HandoverRequestAcknowledgeIEValueProtocolErrorIEContainerList) (HandoverRequestAcknowledgeIEValueProtocolErrorIEContainerListAPERValue, error) {
	if c.encode == nil {
		return HandoverRequestAcknowledgeIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return HandoverRequestAcknowledgeIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return HandoverRequestAcknowledgeIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return HandoverRequestAcknowledgeIEValueProtocolErrorIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c HandoverRequestAcknowledgeIEValueProtocolErrorIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (HandoverRequestAcknowledgeIEValueProtocolErrorIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return HandoverRequestAcknowledgeIEValueProtocolErrorIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return HandoverRequestAcknowledgeIEValueProtocolErrorIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return HandoverRequestAcknowledgeIEValueProtocolErrorIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return HandoverRequestAcknowledgeIEValueProtocolErrorIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c HandoverRequestAcknowledgeIEValueProtocolErrorIEContainerListValueCodec) EncodeAPER(value HandoverRequestAcknowledgeIEValueProtocolErrorIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c HandoverRequestAcknowledgeIEValueProtocolErrorIEContainerListValueCodec) encodeBudgetValue(value HandoverRequestAcknowledgeIEValueProtocolErrorIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c HandoverRequestAcknowledgeIEValueProtocolErrorIEContainerListValueCodec) encodeChanged(value HandoverRequestAcknowledgeIEValueProtocolErrorIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// HandoverRequestAcknowledgeIEValueProtocolErrorIEContainerList is ProtocolError-IE-ContainerList {{HandoverRequestAcknowledgeIEs}} of TS 36.413: a list of information element fields.
type HandoverRequestAcknowledgeIEValueProtocolErrorIEContainerList []HandoverRequestAcknowledgeIEValueProtocolIESingleContainer

func BridgeHandoverRequestAcknowledgeIEValueCaptureS1APProtocolErrorIEContainerList(v *HandoverRequestAcknowledgeIEValueProtocolErrorIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeHandoverRequestAcknowledgeIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeHandoverRequestAcknowledgeIEValueCompareS1APProtocolErrorIEContainerList(v *HandoverRequestAcknowledgeIEValueProtocolErrorIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeHandoverRequestAcknowledgeIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}

// InitialContextSetupResponseIEValueProtocolErrorIEContainerListValueCodec is the concrete ValueCodec[InitialContextSetupResponseIEValueProtocolErrorIEContainerList].
type InitialContextSetupResponseIEValueProtocolErrorIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (InitialContextSetupResponseIEValueProtocolErrorIEContainerList, error)
	encode  func(InitialContextSetupResponseIEValueProtocolErrorIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(InitialContextSetupResponseIEValueProtocolErrorIEContainerList, aper.DecodeState) (InitialContextSetupResponseIEValueProtocolErrorIEContainerList, aper.Snapshot)
	compare func(InitialContextSetupResponseIEValueProtocolErrorIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c InitialContextSetupResponseIEValueProtocolErrorIEContainerListValueCodec) New(value InitialContextSetupResponseIEValueProtocolErrorIEContainerList) (InitialContextSetupResponseIEValueProtocolErrorIEContainerListAPERValue, error) {
	if c.encode == nil {
		return InitialContextSetupResponseIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return InitialContextSetupResponseIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return InitialContextSetupResponseIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return InitialContextSetupResponseIEValueProtocolErrorIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c InitialContextSetupResponseIEValueProtocolErrorIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (InitialContextSetupResponseIEValueProtocolErrorIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return InitialContextSetupResponseIEValueProtocolErrorIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return InitialContextSetupResponseIEValueProtocolErrorIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return InitialContextSetupResponseIEValueProtocolErrorIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return InitialContextSetupResponseIEValueProtocolErrorIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c InitialContextSetupResponseIEValueProtocolErrorIEContainerListValueCodec) EncodeAPER(value InitialContextSetupResponseIEValueProtocolErrorIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c InitialContextSetupResponseIEValueProtocolErrorIEContainerListValueCodec) encodeBudgetValue(value InitialContextSetupResponseIEValueProtocolErrorIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c InitialContextSetupResponseIEValueProtocolErrorIEContainerListValueCodec) encodeChanged(value InitialContextSetupResponseIEValueProtocolErrorIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// InitialContextSetupResponseIEValueProtocolErrorIEContainerList is ProtocolError-IE-ContainerList {{InitialContextSetupResponseIEs}} of TS 36.413: a list of information element fields.
type InitialContextSetupResponseIEValueProtocolErrorIEContainerList []InitialContextSetupResponseIEValueProtocolIESingleContainer

// ERABModificationConfirmIEValueProtocolIEContainerListValueCodec is the concrete ValueCodec[ERABModificationConfirmIEValueProtocolIEContainerList].
type ERABModificationConfirmIEValueProtocolIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ERABModificationConfirmIEValueProtocolIEContainerList, error)
	encode  func(ERABModificationConfirmIEValueProtocolIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ERABModificationConfirmIEValueProtocolIEContainerList, aper.DecodeState) (ERABModificationConfirmIEValueProtocolIEContainerList, aper.Snapshot)
	compare func(ERABModificationConfirmIEValueProtocolIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ERABModificationConfirmIEValueProtocolIEContainerListValueCodec) New(value ERABModificationConfirmIEValueProtocolIEContainerList) (ERABModificationConfirmIEValueProtocolIEContainerListAPERValue, error) {
	if c.encode == nil {
		return ERABModificationConfirmIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ERABModificationConfirmIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ERABModificationConfirmIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ERABModificationConfirmIEValueProtocolIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ERABModificationConfirmIEValueProtocolIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ERABModificationConfirmIEValueProtocolIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ERABModificationConfirmIEValueProtocolIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ERABModificationConfirmIEValueProtocolIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ERABModificationConfirmIEValueProtocolIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ERABModificationConfirmIEValueProtocolIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ERABModificationConfirmIEValueProtocolIEContainerListValueCodec) EncodeAPER(value ERABModificationConfirmIEValueProtocolIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c ERABModificationConfirmIEValueProtocolIEContainerListValueCodec) encodeBudgetValue(value ERABModificationConfirmIEValueProtocolIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ERABModificationConfirmIEValueProtocolIEContainerListValueCodec) encodeChanged(value ERABModificationConfirmIEValueProtocolIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ERABModificationConfirmIEValueProtocolIEContainerList is ProtocolIE-ContainerList with IEsSetParam = {E-RABModificationConfirmIEs} of TS 36.413: a list of information element fields with lowerBound and upperBound supplied by its concrete factory.
type ERABModificationConfirmIEValueProtocolIEContainerList []ERABModificationConfirmIEValueProtocolIESingleContainer

func BridgeERABModificationConfirmIEValueCaptureS1APProtocolIEContainerList(v *ERABModificationConfirmIEValueProtocolIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeERABModificationConfirmIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeERABModificationConfirmIEValueCompareS1APProtocolIEContainerList(v *ERABModificationConfirmIEValueProtocolIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeERABModificationConfirmIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}

// ERABReleaseCommandIEValueProtocolIEContainerListValueCodec is the concrete ValueCodec[ERABReleaseCommandIEValueProtocolIEContainerList].
type ERABReleaseCommandIEValueProtocolIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ERABReleaseCommandIEValueProtocolIEContainerList, error)
	encode  func(ERABReleaseCommandIEValueProtocolIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ERABReleaseCommandIEValueProtocolIEContainerList, aper.DecodeState) (ERABReleaseCommandIEValueProtocolIEContainerList, aper.Snapshot)
	compare func(ERABReleaseCommandIEValueProtocolIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ERABReleaseCommandIEValueProtocolIEContainerListValueCodec) New(value ERABReleaseCommandIEValueProtocolIEContainerList) (ERABReleaseCommandIEValueProtocolIEContainerListAPERValue, error) {
	if c.encode == nil {
		return ERABReleaseCommandIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ERABReleaseCommandIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ERABReleaseCommandIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ERABReleaseCommandIEValueProtocolIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ERABReleaseCommandIEValueProtocolIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ERABReleaseCommandIEValueProtocolIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ERABReleaseCommandIEValueProtocolIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ERABReleaseCommandIEValueProtocolIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ERABReleaseCommandIEValueProtocolIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ERABReleaseCommandIEValueProtocolIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ERABReleaseCommandIEValueProtocolIEContainerListValueCodec) EncodeAPER(value ERABReleaseCommandIEValueProtocolIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c ERABReleaseCommandIEValueProtocolIEContainerListValueCodec) encodeBudgetValue(value ERABReleaseCommandIEValueProtocolIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ERABReleaseCommandIEValueProtocolIEContainerListValueCodec) encodeChanged(value ERABReleaseCommandIEValueProtocolIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ERABReleaseCommandIEValueProtocolIEContainerList is ProtocolIE-ContainerList with IEsSetParam = {E-RABReleaseCommandIEs} of TS 36.413: a list of information element fields with lowerBound and upperBound supplied by its concrete factory.
type ERABReleaseCommandIEValueProtocolIEContainerList []ERABReleaseCommandIEValueProtocolIESingleContainer

func BridgeERABReleaseCommandIEValueCaptureS1APProtocolIEContainerList(v *ERABReleaseCommandIEValueProtocolIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeERABReleaseCommandIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeERABReleaseCommandIEValueCompareS1APProtocolIEContainerList(v *ERABReleaseCommandIEValueProtocolIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeERABReleaseCommandIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}

// HandoverRequestAcknowledgeIEValueProtocolIEContainerListValueCodec is the concrete ValueCodec[HandoverRequestAcknowledgeIEValueProtocolIEContainerList].
type HandoverRequestAcknowledgeIEValueProtocolIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (HandoverRequestAcknowledgeIEValueProtocolIEContainerList, error)
	encode  func(HandoverRequestAcknowledgeIEValueProtocolIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(HandoverRequestAcknowledgeIEValueProtocolIEContainerList, aper.DecodeState) (HandoverRequestAcknowledgeIEValueProtocolIEContainerList, aper.Snapshot)
	compare func(HandoverRequestAcknowledgeIEValueProtocolIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c HandoverRequestAcknowledgeIEValueProtocolIEContainerListValueCodec) New(value HandoverRequestAcknowledgeIEValueProtocolIEContainerList) (HandoverRequestAcknowledgeIEValueProtocolIEContainerListAPERValue, error) {
	if c.encode == nil {
		return HandoverRequestAcknowledgeIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return HandoverRequestAcknowledgeIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return HandoverRequestAcknowledgeIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return HandoverRequestAcknowledgeIEValueProtocolIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c HandoverRequestAcknowledgeIEValueProtocolIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (HandoverRequestAcknowledgeIEValueProtocolIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return HandoverRequestAcknowledgeIEValueProtocolIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return HandoverRequestAcknowledgeIEValueProtocolIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return HandoverRequestAcknowledgeIEValueProtocolIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return HandoverRequestAcknowledgeIEValueProtocolIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c HandoverRequestAcknowledgeIEValueProtocolIEContainerListValueCodec) EncodeAPER(value HandoverRequestAcknowledgeIEValueProtocolIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c HandoverRequestAcknowledgeIEValueProtocolIEContainerListValueCodec) encodeBudgetValue(value HandoverRequestAcknowledgeIEValueProtocolIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c HandoverRequestAcknowledgeIEValueProtocolIEContainerListValueCodec) encodeChanged(value HandoverRequestAcknowledgeIEValueProtocolIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// HandoverRequestAcknowledgeIEValueProtocolIEContainerList is ProtocolIE-ContainerList with IEsSetParam = {HandoverRequestAcknowledgeIEs} of TS 36.413: a list of information element fields with lowerBound and upperBound supplied by its concrete factory.
type HandoverRequestAcknowledgeIEValueProtocolIEContainerList []HandoverRequestAcknowledgeIEValueProtocolIESingleContainer

func BridgeHandoverRequestAcknowledgeIEValueCaptureS1APProtocolIEContainerList(v *HandoverRequestAcknowledgeIEValueProtocolIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeHandoverRequestAcknowledgeIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeHandoverRequestAcknowledgeIEValueCompareS1APProtocolIEContainerList(v *HandoverRequestAcknowledgeIEValueProtocolIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeHandoverRequestAcknowledgeIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}

// InitialContextSetupResponseIEValueProtocolIEContainerList is ProtocolIE-ContainerList with IEsSetParam = {InitialContextSetupResponseIEs} of TS 36.413: a list of information element fields with lowerBound and upperBound supplied by its concrete factory.
type InitialContextSetupResponseIEValueProtocolIEContainerList []InitialContextSetupResponseIEValueProtocolIESingleContainer

// ERABModificationConfirmIEValueERABIEContainerListAPERValue is the concrete APERValue[ERABModificationConfirmIEValueERABIEContainerList].
type ERABModificationConfirmIEValueERABIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         ERABModificationConfirmIEValueERABIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ERABModificationConfirmIEValueERABIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ERABModificationConfirmIEValueERABIEContainerListAPERValue) WithoutReplay() ERABModificationConfirmIEValueERABIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ERABModificationConfirmIEValueProtocolIESingleContainer is ProtocolIE-SingleContainer {{E-RABModificationConfirmIEs}} of TS 36.413: a single information element field.
type ERABModificationConfirmIEValueProtocolIESingleContainer = ERABModificationConfirmIEField

func BridgeERABModificationConfirmIEValueCaptureS1APProtocolIESingleContainer(v *ERABModificationConfirmIEValueProtocolIESingleContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeERABModificationConfirmIEValueCaptureS1APProtocolIEField(v, s)
	s.End(f, nil, false)
}
func BridgeERABModificationConfirmIEValueCompareS1APProtocolIESingleContainer(v *ERABModificationConfirmIEValueProtocolIESingleContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeERABModificationConfirmIEValueCompareS1APProtocolIEField(v, s)
	s.End(f, aper.Snapshot{}, false)
}

// ERABReleaseCommandIEValueERABIEContainerListAPERValue is the concrete APERValue[ERABReleaseCommandIEValueERABIEContainerList].
type ERABReleaseCommandIEValueERABIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         ERABReleaseCommandIEValueERABIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ERABReleaseCommandIEValueERABIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ERABReleaseCommandIEValueERABIEContainerListAPERValue) WithoutReplay() ERABReleaseCommandIEValueERABIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ERABReleaseCommandIEValueProtocolIESingleContainer is ProtocolIE-SingleContainer {{E-RABReleaseCommandIEs}} of TS 36.413: a single information element field.
type ERABReleaseCommandIEValueProtocolIESingleContainer = ERABReleaseCommandIEField

func BridgeERABReleaseCommandIEValueCaptureS1APProtocolIESingleContainer(v *ERABReleaseCommandIEValueProtocolIESingleContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeERABReleaseCommandIEValueCaptureS1APProtocolIEField(v, s)
	s.End(f, nil, false)
}
func BridgeERABReleaseCommandIEValueCompareS1APProtocolIESingleContainer(v *ERABReleaseCommandIEValueProtocolIESingleContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeERABReleaseCommandIEValueCompareS1APProtocolIEField(v, s)
	s.End(f, aper.Snapshot{}, false)
}

// HandoverRequestAcknowledgeIEValueERABIEContainerListAPERValue is the concrete APERValue[HandoverRequestAcknowledgeIEValueERABIEContainerList].
type HandoverRequestAcknowledgeIEValueERABIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         HandoverRequestAcknowledgeIEValueERABIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v HandoverRequestAcknowledgeIEValueERABIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v HandoverRequestAcknowledgeIEValueERABIEContainerListAPERValue) WithoutReplay() HandoverRequestAcknowledgeIEValueERABIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// HandoverRequestAcknowledgeIEValueProtocolIESingleContainer is ProtocolIE-SingleContainer {{HandoverRequestAcknowledgeIEs}} of TS 36.413: a single information element field.
type HandoverRequestAcknowledgeIEValueProtocolIESingleContainer = HandoverRequestAcknowledgeIEField

func BridgeHandoverRequestAcknowledgeIEValueCaptureS1APProtocolIESingleContainer(v *HandoverRequestAcknowledgeIEValueProtocolIESingleContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeHandoverRequestAcknowledgeIEValueCaptureS1APProtocolIEField(v, s)
	s.End(f, nil, false)
}
func BridgeHandoverRequestAcknowledgeIEValueCompareS1APProtocolIESingleContainer(v *HandoverRequestAcknowledgeIEValueProtocolIESingleContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeHandoverRequestAcknowledgeIEValueCompareS1APProtocolIEField(v, s)
	s.End(f, aper.Snapshot{}, false)
}

// InitialContextSetupResponseIEValueERABIEContainerListAPERValue is the concrete APERValue[InitialContextSetupResponseIEValueERABIEContainerList].
type InitialContextSetupResponseIEValueERABIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         InitialContextSetupResponseIEValueERABIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v InitialContextSetupResponseIEValueERABIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v InitialContextSetupResponseIEValueERABIEContainerListAPERValue) WithoutReplay() InitialContextSetupResponseIEValueERABIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// InitialContextSetupResponseIEValueProtocolIESingleContainer is ProtocolIE-SingleContainer {{InitialContextSetupResponseIEs}} of TS 36.413: a single information element field.
type InitialContextSetupResponseIEValueProtocolIESingleContainer = InitialContextSetupResponseIEField

// TargeteNBToSourceeNBTransparentContainerExtIEsExtFieldAPERValue is the concrete APERValue[TargeteNBToSourceeNBTransparentContainerExtIEsExtField].
type TargeteNBToSourceeNBTransparentContainerExtIEsExtFieldAPERValue struct {
	context       s00.BridgeCodecContext
	Value         TargeteNBToSourceeNBTransparentContainerExtIEsExtField
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v TargeteNBToSourceeNBTransparentContainerExtIEsExtFieldAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v TargeteNBToSourceeNBTransparentContainerExtIEsExtFieldAPERValue) WithoutReplay() TargeteNBToSourceeNBTransparentContainerExtIEsExtFieldAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// TargeteNBToSourceeNBTransparentContainerExtIEsExtContainerAPERValue is the concrete APERValue[TargeteNBToSourceeNBTransparentContainerExtIEsExtContainer].
type TargeteNBToSourceeNBTransparentContainerExtIEsExtContainerAPERValue struct {
	context       s00.BridgeCodecContext
	Value         TargeteNBToSourceeNBTransparentContainerExtIEsExtContainer
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v TargeteNBToSourceeNBTransparentContainerExtIEsExtContainerAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v TargeteNBToSourceeNBTransparentContainerExtIEsExtContainerAPERValue) WithoutReplay() TargeteNBToSourceeNBTransparentContainerExtIEsExtContainerAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ERABModificationConfirmIEFieldAPERValue is the concrete APERValue[ERABModificationConfirmIEField].
type ERABModificationConfirmIEFieldAPERValue struct {
	context       s00.BridgeCodecContext
	Value         ERABModificationConfirmIEField
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ERABModificationConfirmIEFieldAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ERABModificationConfirmIEFieldAPERValue) WithoutReplay() ERABModificationConfirmIEFieldAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ERABReleaseCommandIEFieldAPERValue is the concrete APERValue[ERABReleaseCommandIEField].
type ERABReleaseCommandIEFieldAPERValue struct {
	context       s00.BridgeCodecContext
	Value         ERABReleaseCommandIEField
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ERABReleaseCommandIEFieldAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ERABReleaseCommandIEFieldAPERValue) WithoutReplay() ERABReleaseCommandIEFieldAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// HandoverRequestAcknowledgeIEFieldAPERValue is the concrete APERValue[HandoverRequestAcknowledgeIEField].
type HandoverRequestAcknowledgeIEFieldAPERValue struct {
	context       s00.BridgeCodecContext
	Value         HandoverRequestAcknowledgeIEField
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v HandoverRequestAcknowledgeIEFieldAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v HandoverRequestAcknowledgeIEFieldAPERValue) WithoutReplay() HandoverRequestAcknowledgeIEFieldAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// InitialContextSetupResponseIEFieldAPERValue is the concrete APERValue[InitialContextSetupResponseIEField].
type InitialContextSetupResponseIEFieldAPERValue struct {
	context       s00.BridgeCodecContext
	Value         InitialContextSetupResponseIEField
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v InitialContextSetupResponseIEFieldAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v InitialContextSetupResponseIEFieldAPERValue) WithoutReplay() InitialContextSetupResponseIEFieldAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ERABModificationConfirmIEContainerAPERValue is the concrete APERValue[ERABModificationConfirmIEContainer].
type ERABModificationConfirmIEContainerAPERValue struct {
	context       s00.BridgeCodecContext
	Value         ERABModificationConfirmIEContainer
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ERABModificationConfirmIEContainerAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ERABModificationConfirmIEContainerAPERValue) WithoutReplay() ERABModificationConfirmIEContainerAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ERABReleaseCommandIEContainerAPERValue is the concrete APERValue[ERABReleaseCommandIEContainer].
type ERABReleaseCommandIEContainerAPERValue struct {
	context       s00.BridgeCodecContext
	Value         ERABReleaseCommandIEContainer
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ERABReleaseCommandIEContainerAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ERABReleaseCommandIEContainerAPERValue) WithoutReplay() ERABReleaseCommandIEContainerAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// HandoverRequestAcknowledgeIEContainerAPERValue is the concrete APERValue[HandoverRequestAcknowledgeIEContainer].
type HandoverRequestAcknowledgeIEContainerAPERValue struct {
	context       s00.BridgeCodecContext
	Value         HandoverRequestAcknowledgeIEContainer
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v HandoverRequestAcknowledgeIEContainerAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v HandoverRequestAcknowledgeIEContainerAPERValue) WithoutReplay() HandoverRequestAcknowledgeIEContainerAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// InitialContextSetupResponseIEContainerAPERValue is the concrete APERValue[InitialContextSetupResponseIEContainer].
type InitialContextSetupResponseIEContainerAPERValue struct {
	context       s00.BridgeCodecContext
	Value         InitialContextSetupResponseIEContainer
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v InitialContextSetupResponseIEContainerAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v InitialContextSetupResponseIEContainerAPERValue) WithoutReplay() InitialContextSetupResponseIEContainerAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ERABModificationConfirmIEValueProtocolErrorIEContainerListAPERValue is the concrete APERValue[ERABModificationConfirmIEValueProtocolErrorIEContainerList].
type ERABModificationConfirmIEValueProtocolErrorIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         ERABModificationConfirmIEValueProtocolErrorIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ERABModificationConfirmIEValueProtocolErrorIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ERABModificationConfirmIEValueProtocolErrorIEContainerListAPERValue) WithoutReplay() ERABModificationConfirmIEValueProtocolErrorIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ERABReleaseCommandIEValueProtocolErrorIEContainerListAPERValue is the concrete APERValue[ERABReleaseCommandIEValueProtocolErrorIEContainerList].
type ERABReleaseCommandIEValueProtocolErrorIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         ERABReleaseCommandIEValueProtocolErrorIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ERABReleaseCommandIEValueProtocolErrorIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ERABReleaseCommandIEValueProtocolErrorIEContainerListAPERValue) WithoutReplay() ERABReleaseCommandIEValueProtocolErrorIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// HandoverRequestAcknowledgeIEValueProtocolErrorIEContainerListAPERValue is the concrete APERValue[HandoverRequestAcknowledgeIEValueProtocolErrorIEContainerList].
type HandoverRequestAcknowledgeIEValueProtocolErrorIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         HandoverRequestAcknowledgeIEValueProtocolErrorIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v HandoverRequestAcknowledgeIEValueProtocolErrorIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v HandoverRequestAcknowledgeIEValueProtocolErrorIEContainerListAPERValue) WithoutReplay() HandoverRequestAcknowledgeIEValueProtocolErrorIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// InitialContextSetupResponseIEValueProtocolErrorIEContainerListAPERValue is the concrete APERValue[InitialContextSetupResponseIEValueProtocolErrorIEContainerList].
type InitialContextSetupResponseIEValueProtocolErrorIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         InitialContextSetupResponseIEValueProtocolErrorIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v InitialContextSetupResponseIEValueProtocolErrorIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v InitialContextSetupResponseIEValueProtocolErrorIEContainerListAPERValue) WithoutReplay() InitialContextSetupResponseIEValueProtocolErrorIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ERABModificationConfirmIEValueProtocolIEContainerListAPERValue is the concrete APERValue[ERABModificationConfirmIEValueProtocolIEContainerList].
type ERABModificationConfirmIEValueProtocolIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         ERABModificationConfirmIEValueProtocolIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ERABModificationConfirmIEValueProtocolIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ERABModificationConfirmIEValueProtocolIEContainerListAPERValue) WithoutReplay() ERABModificationConfirmIEValueProtocolIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ERABReleaseCommandIEValueProtocolIEContainerListAPERValue is the concrete APERValue[ERABReleaseCommandIEValueProtocolIEContainerList].
type ERABReleaseCommandIEValueProtocolIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         ERABReleaseCommandIEValueProtocolIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ERABReleaseCommandIEValueProtocolIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ERABReleaseCommandIEValueProtocolIEContainerListAPERValue) WithoutReplay() ERABReleaseCommandIEValueProtocolIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// HandoverRequestAcknowledgeIEValueProtocolIEContainerListAPERValue is the concrete APERValue[HandoverRequestAcknowledgeIEValueProtocolIEContainerList].
type HandoverRequestAcknowledgeIEValueProtocolIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         HandoverRequestAcknowledgeIEValueProtocolIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v HandoverRequestAcknowledgeIEValueProtocolIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v HandoverRequestAcknowledgeIEValueProtocolIEContainerListAPERValue) WithoutReplay() HandoverRequestAcknowledgeIEValueProtocolIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// InitialContextSetupResponseIEValueProtocolIEContainerListAPERValue is the concrete APERValue[InitialContextSetupResponseIEValueProtocolIEContainerList].
type InitialContextSetupResponseIEValueProtocolIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         InitialContextSetupResponseIEValueProtocolIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v InitialContextSetupResponseIEValueProtocolIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v InitialContextSetupResponseIEValueProtocolIEContainerListAPERValue) WithoutReplay() InitialContextSetupResponseIEValueProtocolIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}
func BridgeCaptureS1APERABFailedtoSetupListHOReqAckComplete(v *ERABFailedtoSetupListHOReqAckComplete, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s24.BridgeCaptureS1APERABFailedtoSetupListHOReqAck(&v.Value, s)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APERABFailedtoSetupListHOReqAckComplete(v *ERABFailedtoSetupListHOReqAckComplete, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s24.BridgeCompareS1APERABFailedtoSetupListHOReqAck(&v.Value, s)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APERABInformationListComplete(v *ERABInformationListComplete, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s29.BridgeCaptureS1APERABInformationList(&v.Value, s)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APERABInformationListComplete(v *ERABInformationListComplete, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s29.BridgeCompareS1APERABInformationList(&v.Value, s)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APERABListComplete(v *ERABListComplete, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s24.BridgeCaptureS1APERABList(&v.Value, s)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APERABListComplete(v *ERABListComplete, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s24.BridgeCompareS1APERABList(&v.Value, s)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APERABModificationConfirm(v *ERABModificationConfirm, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeERABModificationConfirmIEValueCaptureS1APProtocolIEContainer(&v.ProtocolIEs, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APERABModificationConfirm(v *ERABModificationConfirm, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeERABModificationConfirmIEValueCompareS1APProtocolIEContainer(&v.ProtocolIEs, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APERABModificationConfirmIEValue(v *ERABModificationConfirmIEValue, s *aper.SemanticCapture) {
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
		case s00.ProtocolIEID(203):
			{
				f := s.Begin()
				s.Bool(v.rowERABModifyListBearerModConf == nil)
				if v.rowERABModifyListBearerModConf != nil {
					s24.BridgeCaptureS1APERABModifyListBearerModConf(v.rowERABModifyListBearerModConf, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(205):
			{
				f := s.Begin()
				s.Bool(v.rowERABFailedToModifyListBearerModConf == nil)
				if v.rowERABFailedToModifyListBearerModConf != nil {
					s24.BridgeCaptureS1APERABList(v.rowERABFailedToModifyListBearerModConf, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(210):
			{
				f := s.Begin()
				s.Bool(v.rowERABToBeReleasedListBearerModConf == nil)
				if v.rowERABToBeReleasedListBearerModConf != nil {
					s24.BridgeCaptureS1APERABList(v.rowERABToBeReleasedListBearerModConf, s)
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
		case s00.ProtocolIEID(146):
			{
				f := s.Begin()
				s.Bool(v.rowCSGMembershipStatus == nil)
				if v.rowCSGMembershipStatus != nil {
					s00.BridgeCaptureS1APCSGMembershipStatus(v.rowCSGMembershipStatus, s)
				}
				s.End(f, nil, false)
			}
		}
	}
	s.End(f, &v.replay, false)
	s.CheckReceived(v.replay, v.received)
}
func (v ERABModificationConfirmIEValue) captureSemantics(s aper.SemanticCapture) ERABModificationConfirmIEValue {
	BridgeCaptureS1APERABModificationConfirmIEValue(&v, &s)
	return v
}
func BridgeCompareS1APERABModificationConfirmIEValue(v *ERABModificationConfirmIEValue, s *aper.SemanticComparison) {
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
		case s00.ProtocolIEID(203):
			{
				f := s.Begin()
				s.Bool(v.rowERABModifyListBearerModConf == nil)
				if v.rowERABModifyListBearerModConf != nil {
					s24.BridgeCompareS1APERABModifyListBearerModConf(v.rowERABModifyListBearerModConf, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(205):
			{
				f := s.Begin()
				s.Bool(v.rowERABFailedToModifyListBearerModConf == nil)
				if v.rowERABFailedToModifyListBearerModConf != nil {
					s24.BridgeCompareS1APERABList(v.rowERABFailedToModifyListBearerModConf, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(210):
			{
				f := s.Begin()
				s.Bool(v.rowERABToBeReleasedListBearerModConf == nil)
				if v.rowERABToBeReleasedListBearerModConf != nil {
					s24.BridgeCompareS1APERABList(v.rowERABToBeReleasedListBearerModConf, s)
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
		case s00.ProtocolIEID(146):
			{
				f := s.Begin()
				s.Bool(v.rowCSGMembershipStatus == nil)
				if v.rowCSGMembershipStatus != nil {
					s02.BridgeCompareS1APCSGMembershipStatus(v.rowCSGMembershipStatus, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		}
	}
	s.End(f, v.replay, false)
	s.CheckReceived(v.replay, v.received)
}
func (v ERABModificationConfirmIEValue) compareSemantics(s aper.SemanticComparison) aper.SemanticComparison {
	BridgeCompareS1APERABModificationConfirmIEValue(&v, &s)
	return s
}
func BridgeCaptureS1APERABModifyListBearerModConfComplete(v *ERABModifyListBearerModConfComplete, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s24.BridgeCaptureS1APERABModifyListBearerModConf(&v.Value, s)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APERABModifyListBearerModConfComplete(v *ERABModifyListBearerModConfComplete, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s24.BridgeCompareS1APERABModifyListBearerModConf(&v.Value, s)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APERABModifyListBearerModResComplete(v *ERABModifyListBearerModResComplete, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s24.BridgeCaptureS1APERABModifyListBearerModRes(&v.Value, s)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APERABModifyListBearerModResComplete(v *ERABModifyListBearerModResComplete, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s24.BridgeCompareS1APERABModifyListBearerModRes(&v.Value, s)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APERABNotToBeModifiedListBearerModIndComplete(v *ERABNotToBeModifiedListBearerModIndComplete, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s24.BridgeCaptureS1APERABNotToBeModifiedListBearerModInd(&v.Value, s)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APERABNotToBeModifiedListBearerModIndComplete(v *ERABNotToBeModifiedListBearerModIndComplete, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s24.BridgeCompareS1APERABNotToBeModifiedListBearerModInd(&v.Value, s)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APERABReleaseCommand(v *ERABReleaseCommand, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeERABReleaseCommandIEValueCaptureS1APProtocolIEContainer(&v.ProtocolIEs, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APERABReleaseCommand(v *ERABReleaseCommand, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeERABReleaseCommandIEValueCompareS1APProtocolIEContainer(&v.ProtocolIEs, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APERABReleaseCommandIEValue(v *ERABReleaseCommandIEValue, s *aper.SemanticCapture) {
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
		case s00.ProtocolIEID(66):
			{
				f := s.Begin()
				s.Bool(v.rowUEaggregateMaximumBitrate == nil)
				if v.rowUEaggregateMaximumBitrate != nil {
					s35.BridgeCaptureS1APUEAggregateMaximumBitrate(v.rowUEaggregateMaximumBitrate, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(33):
			{
				f := s.Begin()
				s.Bool(v.rowERABToBeReleasedList == nil)
				if v.rowERABToBeReleasedList != nil {
					s24.BridgeCaptureS1APERABList(v.rowERABToBeReleasedList, s)
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
		}
	}
	s.End(f, &v.replay, false)
	s.CheckReceived(v.replay, v.received)
}
func (v ERABReleaseCommandIEValue) captureSemantics(s aper.SemanticCapture) ERABReleaseCommandIEValue {
	BridgeCaptureS1APERABReleaseCommandIEValue(&v, &s)
	return v
}
func BridgeCompareS1APERABReleaseCommandIEValue(v *ERABReleaseCommandIEValue, s *aper.SemanticComparison) {
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
		case s00.ProtocolIEID(66):
			{
				f := s.Begin()
				s.Bool(v.rowUEaggregateMaximumBitrate == nil)
				if v.rowUEaggregateMaximumBitrate != nil {
					s35.BridgeCompareS1APUEAggregateMaximumBitrate(v.rowUEaggregateMaximumBitrate, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(33):
			{
				f := s.Begin()
				s.Bool(v.rowERABToBeReleasedList == nil)
				if v.rowERABToBeReleasedList != nil {
					s24.BridgeCompareS1APERABList(v.rowERABToBeReleasedList, s)
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
		}
	}
	s.End(f, v.replay, false)
	s.CheckReceived(v.replay, v.received)
}
func (v ERABReleaseCommandIEValue) compareSemantics(s aper.SemanticComparison) aper.SemanticComparison {
	BridgeCompareS1APERABReleaseCommandIEValue(&v, &s)
	return s
}
func BridgeCaptureS1APERABReleaseListBearerRelCompComplete(v *ERABReleaseListBearerRelCompComplete, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s25.BridgeCaptureS1APERABReleaseListBearerRelComp(&v.Value, s)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APERABReleaseListBearerRelCompComplete(v *ERABReleaseListBearerRelCompComplete, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s25.BridgeCompareS1APERABReleaseListBearerRelComp(&v.Value, s)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APERABSecurityResultListComplete(v *ERABSecurityResultListComplete, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s30.BridgeCaptureS1APERABSecurityResultList(&v.Value, s)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APERABSecurityResultListComplete(v *ERABSecurityResultListComplete, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s30.BridgeCompareS1APERABSecurityResultList(&v.Value, s)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APERABSetupListBearerSUResComplete(v *ERABSetupListBearerSUResComplete, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s25.BridgeCaptureS1APERABSetupListBearerSURes(&v.Value, s)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APERABSetupListBearerSUResComplete(v *ERABSetupListBearerSUResComplete, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s25.BridgeCompareS1APERABSetupListBearerSURes(&v.Value, s)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APERABSetupListCtxtSUResComplete(v *ERABSetupListCtxtSUResComplete, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s25.BridgeCaptureS1APERABSetupListCtxtSURes(&v.Value, s)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APERABSetupListCtxtSUResComplete(v *ERABSetupListCtxtSUResComplete, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s25.BridgeCompareS1APERABSetupListCtxtSURes(&v.Value, s)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APHandoverRequestAcknowledge(v *HandoverRequestAcknowledge, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeHandoverRequestAcknowledgeIEValueCaptureS1APProtocolIEContainer(&v.ProtocolIEs, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APHandoverRequestAcknowledge(v *HandoverRequestAcknowledge, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeHandoverRequestAcknowledgeIEValueCompareS1APProtocolIEContainer(&v.ProtocolIEs, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APHandoverRequestAcknowledgeIEValue(v *HandoverRequestAcknowledgeIEValue, s *aper.SemanticCapture) {
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
		case s00.ProtocolIEID(18):
			{
				f := s.Begin()
				s.Bool(v.rowERABAdmittedList == nil)
				if v.rowERABAdmittedList != nil {
					s24.BridgeCaptureS1APERABAdmittedList(v.rowERABAdmittedList, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(19):
			{
				f := s.Begin()
				s.Bool(v.rowERABFailedToSetupListHOReqAck == nil)
				if v.rowERABFailedToSetupListHOReqAck != nil {
					s24.BridgeCaptureS1APERABFailedtoSetupListHOReqAck(v.rowERABFailedToSetupListHOReqAck, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(123):
			{
				f := s.Begin()
				s.Bool(v.rowTargetToSourceTransparentContainer == nil)
				if v.rowTargetToSourceTransparentContainer != nil {
					s00.BridgeCaptureS1APTargetToSourceTransparentContainer(v.rowTargetToSourceTransparentContainer, s)
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
		case s00.ProtocolIEID(58):
			{
				f := s.Begin()
				s.Bool(v.rowCriticalityDiagnostics == nil)
				if v.rowCriticalityDiagnostics != nil {
					s22.BridgeCaptureS1APCriticalityDiagnostics(v.rowCriticalityDiagnostics, s)
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
		case s00.ProtocolIEID(242):
			{
				f := s.Begin()
				s.Bool(v.rowCEModeBSupportIndicator == nil)
				if v.rowCEModeBSupportIndicator != nil {
					s00.BridgeCaptureS1APCEModeBSupportIndicator(v.rowCEModeBSupportIndicator, s)
				}
				s.End(f, nil, false)
			}
		}
	}
	s.End(f, &v.replay, false)
	s.CheckReceived(v.replay, v.received)
}
func (v HandoverRequestAcknowledgeIEValue) captureSemantics(s aper.SemanticCapture) HandoverRequestAcknowledgeIEValue {
	BridgeCaptureS1APHandoverRequestAcknowledgeIEValue(&v, &s)
	return v
}
func BridgeCompareS1APHandoverRequestAcknowledgeIEValue(v *HandoverRequestAcknowledgeIEValue, s *aper.SemanticComparison) {
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
		case s00.ProtocolIEID(18):
			{
				f := s.Begin()
				s.Bool(v.rowERABAdmittedList == nil)
				if v.rowERABAdmittedList != nil {
					s24.BridgeCompareS1APERABAdmittedList(v.rowERABAdmittedList, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(19):
			{
				f := s.Begin()
				s.Bool(v.rowERABFailedToSetupListHOReqAck == nil)
				if v.rowERABFailedToSetupListHOReqAck != nil {
					s24.BridgeCompareS1APERABFailedtoSetupListHOReqAck(v.rowERABFailedToSetupListHOReqAck, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(123):
			{
				f := s.Begin()
				s.Bool(v.rowTargetToSourceTransparentContainer == nil)
				if v.rowTargetToSourceTransparentContainer != nil {
					s07.BridgeCompareS1APTargetToSourceTransparentContainer(v.rowTargetToSourceTransparentContainer, s)
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
		case s00.ProtocolIEID(58):
			{
				f := s.Begin()
				s.Bool(v.rowCriticalityDiagnostics == nil)
				if v.rowCriticalityDiagnostics != nil {
					s22.BridgeCompareS1APCriticalityDiagnostics(v.rowCriticalityDiagnostics, s)
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
		case s00.ProtocolIEID(242):
			{
				f := s.Begin()
				s.Bool(v.rowCEModeBSupportIndicator == nil)
				if v.rowCEModeBSupportIndicator != nil {
					s02.BridgeCompareS1APCEModeBSupportIndicator(v.rowCEModeBSupportIndicator, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		}
	}
	s.End(f, v.replay, false)
	s.CheckReceived(v.replay, v.received)
}
func (v HandoverRequestAcknowledgeIEValue) compareSemantics(s aper.SemanticComparison) aper.SemanticComparison {
	BridgeCompareS1APHandoverRequestAcknowledgeIEValue(&v, &s)
	return s
}
func BridgeCaptureS1APInitialContextSetupResponseIEValue(v *InitialContextSetupResponseIEValue, s *aper.SemanticCapture) {
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
		case s00.ProtocolIEID(51):
			{
				f := s.Begin()
				s.Bool(v.rowERABSetupListCtxtSURes == nil)
				if v.rowERABSetupListCtxtSURes != nil {
					s25.BridgeCaptureS1APERABSetupListCtxtSURes(v.rowERABSetupListCtxtSURes, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(48):
			{
				f := s.Begin()
				s.Bool(v.rowERABFailedToSetupListCtxtSURes == nil)
				if v.rowERABFailedToSetupListCtxtSURes != nil {
					s24.BridgeCaptureS1APERABList(v.rowERABFailedToSetupListCtxtSURes, s)
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
func (v InitialContextSetupResponseIEValue) captureSemantics(s aper.SemanticCapture) InitialContextSetupResponseIEValue {
	BridgeCaptureS1APInitialContextSetupResponseIEValue(&v, &s)
	return v
}
func BridgeCompareS1APInitialContextSetupResponseIEValue(v *InitialContextSetupResponseIEValue, s *aper.SemanticComparison) {
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
		case s00.ProtocolIEID(51):
			{
				f := s.Begin()
				s.Bool(v.rowERABSetupListCtxtSURes == nil)
				if v.rowERABSetupListCtxtSURes != nil {
					s25.BridgeCompareS1APERABSetupListCtxtSURes(v.rowERABSetupListCtxtSURes, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(48):
			{
				f := s.Begin()
				s.Bool(v.rowERABFailedToSetupListCtxtSURes == nil)
				if v.rowERABFailedToSetupListCtxtSURes != nil {
					s24.BridgeCompareS1APERABList(v.rowERABFailedToSetupListCtxtSURes, s)
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
func (v InitialContextSetupResponseIEValue) compareSemantics(s aper.SemanticComparison) aper.SemanticComparison {
	BridgeCompareS1APInitialContextSetupResponseIEValue(&v, &s)
	return s
}
func BridgeCaptureS1APTargeteNBToSourceeNBTransparentContainer(v *TargeteNBToSourceeNBTransparentContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APRRCContainer(&v.RRCContainer, s)
	s.Bool(v.IEExtensions == nil)
	BridgeTargeteNBToSourceeNBTransparentContainerExtIEsValueCaptureS1APProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APTargeteNBToSourceeNBTransparentContainer(v *TargeteNBToSourceeNBTransparentContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s06.BridgeCompareS1APRRCContainer(&v.RRCContainer, s)
	s.Bool(v.IEExtensions == nil)
	BridgeTargeteNBToSourceeNBTransparentContainerExtIEsValueCompareS1APProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APTargeteNBToSourceeNBTransparentContainerExtIEsValue(v *TargeteNBToSourceeNBTransparentContainerExtIEsValue, s *aper.SemanticCapture) {
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
		case s00.ProtocolIEID(318):
			{
				f := s.Begin()
				s.Bool(v.rowDAPSResponseInfoList == nil)
				if v.rowDAPSResponseInfoList != nil {
					s24.BridgeCaptureS1APDAPSResponseInfoList(v.rowDAPSResponseInfoList, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(330):
			{
				f := s.Begin()
				s.Bool(v.rowRACSIndication == nil)
				if v.rowRACSIndication != nil {
					s00.BridgeCaptureS1APRACSIndication(v.rowRACSIndication, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(335):
			{
				f := s.Begin()
				s.Bool(v.rowERABSecurityResultList == nil)
				if v.rowERABSecurityResultList != nil {
					s30.BridgeCaptureS1APERABSecurityResultList(v.rowERABSecurityResultList, s)
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
		}
	}
	s.End(f, &v.replay, false)
	s.CheckReceived(v.replay, v.received)
}
func (v TargeteNBToSourceeNBTransparentContainerExtIEsValue) captureSemantics(s aper.SemanticCapture) TargeteNBToSourceeNBTransparentContainerExtIEsValue {
	BridgeCaptureS1APTargeteNBToSourceeNBTransparentContainerExtIEsValue(&v, &s)
	return v
}
func BridgeCompareS1APTargeteNBToSourceeNBTransparentContainerExtIEsValue(v *TargeteNBToSourceeNBTransparentContainerExtIEsValue, s *aper.SemanticComparison) {
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
		case s00.ProtocolIEID(318):
			{
				f := s.Begin()
				s.Bool(v.rowDAPSResponseInfoList == nil)
				if v.rowDAPSResponseInfoList != nil {
					s24.BridgeCompareS1APDAPSResponseInfoList(v.rowDAPSResponseInfoList, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(330):
			{
				f := s.Begin()
				s.Bool(v.rowRACSIndication == nil)
				if v.rowRACSIndication != nil {
					s06.BridgeCompareS1APRACSIndication(v.rowRACSIndication, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(335):
			{
				f := s.Begin()
				s.Bool(v.rowERABSecurityResultList == nil)
				if v.rowERABSecurityResultList != nil {
					s30.BridgeCompareS1APERABSecurityResultList(v.rowERABSecurityResultList, s)
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
		}
	}
	s.End(f, v.replay, false)
	s.CheckReceived(v.replay, v.received)
}
func (v TargeteNBToSourceeNBTransparentContainerExtIEsValue) compareSemantics(s aper.SemanticComparison) aper.SemanticComparison {
	BridgeCompareS1APTargeteNBToSourceeNBTransparentContainerExtIEsValue(&v, &s)
	return s
}

// TargeteNBToSourceeNBTransparentContainer represents the ASN.1 type TargeteNB-ToSourceeNB-TransparentContainer (SEQUENCE).
type TargeteNBToSourceeNBTransparentContainer struct {
	replay            aper.Snapshot
	stream            aper.WireSpan
	received          bool
	withoutReplay     bool
	receivedAbsolute  bool
	receivedBytes     aper.WireSpan
	receivedLocation  aper.Location
	RRCContainer      s00.RRCContainer                                           `asn1:"tag:0,context,implicit"`
	IEExtensions      TargeteNBToSourceeNBTransparentContainerExtIEsExtContainer `asn1:"tag:1,context,implicit,optional" json:"IEExtensions,omitzero"`
	iEExtensionsIndef bool                                                       `asn1:"-" json:"-"`
	extCount          int64                                                      `asn1:"-" json:"-"`
	extPresent        []bool                                                     `asn1:"-" json:"-"`
	extData           [][]byte                                                   `asn1:"-" json:"-"`
	perPadding        aper.FinalPadding                                          `asn1:"-" json:"-"`
	perExtPadding     []aper.CompletePadding                                     `asn1:"-" json:"-"`
	extOrigin         []aper.OpaqueOrigin
	extWire           []aper.WireSpan
}

// ERABInformationListComplete carries a complete ERABInformationList encoding, including observed terminal bits.
// ITU-T X.691 (02/2021) 11.1.3.1 and 11.1.4 require new encodings to pad with zero bits.
type ERABInformationListComplete struct {
	replay           aper.Snapshot
	stream           aper.WireSpan
	received         bool
	withoutReplay    bool
	receivedAbsolute bool
	receivedBytes    aper.WireSpan
	receivedLocation aper.Location
	Value            s29.ERABInformationList
	perPadding       aper.CompletePadding `json:"-"`
}

func (v *ERABInformationListComplete) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := s30.BridgeMarshalAPERERABInformationListTo(v.Value, bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.perPadding)
}

// UnmarshalAPER decodes ERABInformationList from APER format.
func (v *ERABInformationListComplete) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes ERABInformationList with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *ERABInformationListComplete) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "ERABInformationList")
	}
	bb.EnterComponent("ERABInformationList")
	value, err := BridgeUnmarshalAPERERABInformationListFrom(bb)
	if err != nil {
		return runtime.WrapDecodePath(err, "ERABInformationList")
	}
	padding, err := aper.CaptureFinalBits(bb, "ERABInformationList")
	if err != nil {
		return runtime.WrapDecodePath(err, "ERABInformationList")
	}
	v.Value, v.perPadding = value, padding.Padding()
	return nil
}

// MarshalAPERERABInformationList encodes a ERABInformationList list to APER.
func BridgeMarshalAPERERABInformationList(list ERABInformationListComplete) ([]byte, error) {
	return list.marshalAPERLegacy()
}

// UnmarshalAPERERABInformationList decodes a ERABInformationList list from APER.
func BridgeUnmarshalAPERERABInformationList(data []byte) (ERABInformationListComplete, error) {
	var value ERABInformationListComplete
	if err := value.unmarshalAPERLegacy(data); err != nil {
		return value, err
	}
	return value, nil
}

// UnmarshalAPERERABInformationListFrom decodes a ERABInformationList list from bb.
func BridgeUnmarshalAPERERABInformationListFrom(bb *aper.BitBuffer) (s29.ERABInformationList, error) {
	if err := bb.EnterDecodeValue(); err != nil {
		return nil, err
	}
	defer bb.LeaveDecodeValue()
	var v s29.BridgeAsn1cAPERERABInformationListListValue
	if err := BridgeUnmarshalAPERERABInformationListInto(&v, bb); err != nil {
		return nil, err
	}
	return v.Value, nil
}
func BridgeUnmarshalAPERERABInformationListInto(v *s29.BridgeAsn1cAPERERABInformationListListValue, bb *aper.BitBuffer) error {
	toleranceMark_value := bb.EnterComponent("Value")
	v.Value = make(s29.ERABInformationList, 0)
	_, errCollection_value := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 256, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1128
		if fragmentOffset_value < 0 || fragmentLength_value < 0 || fragmentLength_value > int64(^uint(0)>>1) || fragmentOffset_value > int64(^uint(0)>>1)-fragmentLength_value {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_value; i++ {
			var elem s29.ERABInformationListIEValueProtocolIESingleContainer
			elementMark := bb.EnterIndex(fragmentOffset_value + i)
			if err := s29.BridgeERABInformationListIEFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
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

// ERABListComplete carries a complete ERABList encoding, including observed terminal bits.
// ITU-T X.691 (02/2021) 11.1.3.1 and 11.1.4 require new encodings to pad with zero bits.
type ERABListComplete struct {
	replay           aper.Snapshot
	stream           aper.WireSpan
	received         bool
	withoutReplay    bool
	receivedAbsolute bool
	receivedBytes    aper.WireSpan
	receivedLocation aper.Location
	Value            s16.ERABList
	perPadding       aper.CompletePadding `json:"-"`
}

func (v *ERABListComplete) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := s25.BridgeMarshalAPERERABListTo(v.Value, bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.perPadding)
}

// UnmarshalAPER decodes ERABList from APER format.
func (v *ERABListComplete) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes ERABList with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *ERABListComplete) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "ERABList")
	}
	bb.EnterComponent("ERABList")
	value, err := BridgeUnmarshalAPERERABListFrom(bb)
	if err != nil {
		return runtime.WrapDecodePath(err, "ERABList")
	}
	padding, err := aper.CaptureFinalBits(bb, "ERABList")
	if err != nil {
		return runtime.WrapDecodePath(err, "ERABList")
	}
	v.Value, v.perPadding = value, padding.Padding()
	return nil
}

// MarshalAPERERABList encodes a ERABList list to APER.
func BridgeMarshalAPERERABList(list ERABListComplete) ([]byte, error) {
	return list.marshalAPERLegacy()
}

// UnmarshalAPERERABList decodes a ERABList list from APER.
func BridgeUnmarshalAPERERABList(data []byte) (ERABListComplete, error) {
	var value ERABListComplete
	if err := value.unmarshalAPERLegacy(data); err != nil {
		return value, err
	}
	return value, nil
}

// UnmarshalAPERERABListFrom decodes a ERABList list from bb.
func BridgeUnmarshalAPERERABListFrom(bb *aper.BitBuffer) (s16.ERABList, error) {
	if err := bb.EnterDecodeValue(); err != nil {
		return nil, err
	}
	defer bb.LeaveDecodeValue()
	var v s21.BridgeAsn1cAPERERABListListValue
	if err := BridgeUnmarshalAPERERABListInto(&v, bb); err != nil {
		return nil, err
	}
	return v.Value, nil
}
func BridgeUnmarshalAPERERABListInto(v *s21.BridgeAsn1cAPERERABListListValue, bb *aper.BitBuffer) error {
	toleranceMark_value := bb.EnterComponent("Value")
	v.Value = make(s16.ERABList, 0)
	_, errCollection_value := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 256, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1128
		if fragmentOffset_value < 0 || fragmentLength_value < 0 || fragmentLength_value > int64(^uint(0)>>1) || fragmentOffset_value > int64(^uint(0)>>1)-fragmentLength_value {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_value; i++ {
			var elem s16.ERABItemIEValueProtocolIESingleContainer
			elementMark := bb.EnterIndex(fragmentOffset_value + i)
			if err := s16.BridgeERABItemIEFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
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

// ERABSecurityResultListComplete carries a complete ERABSecurityResultList encoding, including observed terminal bits.
// ITU-T X.691 (02/2021) 11.1.3.1 and 11.1.4 require new encodings to pad with zero bits.
type ERABSecurityResultListComplete struct {
	replay           aper.Snapshot
	stream           aper.WireSpan
	received         bool
	withoutReplay    bool
	receivedAbsolute bool
	receivedBytes    aper.WireSpan
	receivedLocation aper.Location
	Value            s30.ERABSecurityResultList
	perPadding       aper.CompletePadding `json:"-"`
}

func (v *ERABSecurityResultListComplete) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := s30.BridgeMarshalAPERERABSecurityResultListTo(v.Value, bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.perPadding)
}

// UnmarshalAPER decodes ERABSecurityResultList from APER format.
func (v *ERABSecurityResultListComplete) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes ERABSecurityResultList with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *ERABSecurityResultListComplete) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "ERABSecurityResultList")
	}
	bb.EnterComponent("ERABSecurityResultList")
	value, err := BridgeUnmarshalAPERERABSecurityResultListFrom(bb)
	if err != nil {
		return runtime.WrapDecodePath(err, "ERABSecurityResultList")
	}
	padding, err := aper.CaptureFinalBits(bb, "ERABSecurityResultList")
	if err != nil {
		return runtime.WrapDecodePath(err, "ERABSecurityResultList")
	}
	v.Value, v.perPadding = value, padding.Padding()
	return nil
}

// MarshalAPERERABSecurityResultList encodes a ERABSecurityResultList list to APER.
func BridgeMarshalAPERERABSecurityResultList(list ERABSecurityResultListComplete) ([]byte, error) {
	return list.marshalAPERLegacy()
}

// UnmarshalAPERERABSecurityResultList decodes a ERABSecurityResultList list from APER.
func BridgeUnmarshalAPERERABSecurityResultList(data []byte) (ERABSecurityResultListComplete, error) {
	var value ERABSecurityResultListComplete
	if err := value.unmarshalAPERLegacy(data); err != nil {
		return value, err
	}
	return value, nil
}

// UnmarshalAPERERABSecurityResultListFrom decodes a ERABSecurityResultList list from bb.
func BridgeUnmarshalAPERERABSecurityResultListFrom(bb *aper.BitBuffer) (s30.ERABSecurityResultList, error) {
	if err := bb.EnterDecodeValue(); err != nil {
		return nil, err
	}
	defer bb.LeaveDecodeValue()
	var v s30.BridgeAsn1cAPERERABSecurityResultListListValue
	if err := BridgeUnmarshalAPERERABSecurityResultListInto(&v, bb); err != nil {
		return nil, err
	}
	return v.Value, nil
}
func BridgeUnmarshalAPERERABSecurityResultListInto(v *s30.BridgeAsn1cAPERERABSecurityResultListListValue, bb *aper.BitBuffer) error {
	toleranceMark_value := bb.EnterComponent("Value")
	v.Value = make(s30.ERABSecurityResultList, 0)
	_, errCollection_value := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 256, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1128
		if fragmentOffset_value < 0 || fragmentLength_value < 0 || fragmentLength_value > int64(^uint(0)>>1) || fragmentOffset_value > int64(^uint(0)>>1)-fragmentLength_value {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_value; i++ {
			var elem s30.ERABSecurityResultListIEValueProtocolIESingleContainer
			elementMark := bb.EnterIndex(fragmentOffset_value + i)
			if err := s30.BridgeERABSecurityResultListIEFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
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

// MarshalAPER encodes TargeteNBToSourceeNBTransparentContainer to APER format.
func (v *TargeteNBToSourceeNBTransparentContainer) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *TargeteNBToSourceeNBTransparentContainer) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
	if err := aper.EncodeOctetStringAligned(bb, []byte(v.RRCContainer), 0, 0, false); err != nil {
		return fmt.Errorf("encoding rRC-Container: %w", err)
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

// UnmarshalAPER decodes TargeteNBToSourceeNBTransparentContainer from APER format.
func (v *TargeteNBToSourceeNBTransparentContainer) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes TargeteNBToSourceeNBTransparentContainer with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *TargeteNBToSourceeNBTransparentContainer) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "TargeteNBToSourceeNBTransparentContainer")
	}
	bb.EnterComponent("TargeteNBToSourceeNBTransparentContainer")
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "TargeteNBToSourceeNBTransparentContainer")
	}
	padding, err := aper.CaptureFinalBits(bb, "TargeteNBToSourceeNBTransparentContainer")
	if err != nil {
		return runtime.WrapDecodePath(err, "TargeteNBToSourceeNBTransparentContainer")
	}
	v.perPadding = padding.WithRecords(v.perPadding)
	return nil
}
func (v *TargeteNBToSourceeNBTransparentContainer) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = TargeteNBToSourceeNBTransparentContainer{}
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
	val_rrccontainer, err := aper.DecodeOctetStringAligned(bb, 0, 0, false)
	if err != nil {
		return runtime.WrapDecodePath(err, "RRCContainer")
	}
	v.RRCContainer = s00.RRCContainer(val_rrccontainer)
	if opt_ieextensions {
		toleranceMark_ieextensions := bb.EnterComponent("IEExtensions")
		tmp_ieextensions := make(TargeteNBToSourceeNBTransparentContainerExtIEsExtContainer, 0)
		_, errCollection_ieextensions := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1128
			if fragmentOffset_ieextensions < 0 || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(^uint(0)>>1) || fragmentOffset_ieextensions > int64(^uint(0)>>1)-fragmentLength_ieextensions {
				return fmt.Errorf("collection fragment count out of range")
			}
			for i := int64(0); i < fragmentLength_ieextensions; i++ {
				var elem TargeteNBToSourceeNBTransparentContainerExtIEsExtField
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

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *ERABInformationListComplete) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s14.BridgeReceivedFormAt(v.received, v.receivedBytes, "ERABInformationListComplete", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "ERABInformationListComplete", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v ERABInformationListComplete) WithoutReplay() ERABInformationListComplete {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero ERABInformationListComplete
	v.perPadding = zero.perPadding
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *ERABListComplete) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s14.BridgeReceivedFormAt(v.received, v.receivedBytes, "ERABListComplete", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "ERABListComplete", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v ERABListComplete) WithoutReplay() ERABListComplete {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero ERABListComplete
	v.perPadding = zero.perPadding
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *ERABSecurityResultListComplete) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s14.BridgeReceivedFormAt(v.received, v.receivedBytes, "ERABSecurityResultListComplete", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "ERABSecurityResultListComplete", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v ERABSecurityResultListComplete) WithoutReplay() ERABSecurityResultListComplete {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero ERABSecurityResultListComplete
	v.perPadding = zero.perPadding
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *TargeteNBToSourceeNBTransparentContainer) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s14.BridgeReceivedFormAt(v.received, v.receivedBytes, "TargeteNBToSourceeNBTransparentContainer", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "TargeteNBToSourceeNBTransparentContainer", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v TargeteNBToSourceeNBTransparentContainer) WithoutReplay() TargeteNBToSourceeNBTransparentContainer {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero TargeteNBToSourceeNBTransparentContainer
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// Extensions returns owned unknown sequence additions.
func (v *TargeteNBToSourceeNBTransparentContainer) Extensions() []aper.SequenceExtension {
	if v == nil {
		return nil
	}
	views := aper.SequenceExtensionViews(v.extPresent, aper.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *TargeteNBToSourceeNBTransparentContainer) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("TargeteNBToSourceeNBTransparentContainer.Extensions[%d]", index))
	}
	if err := aper.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("TargeteNBToSourceeNBTransparentContainer.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *TargeteNBToSourceeNBTransparentContainer) RemoveExtension(index uint64) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("TargeteNBToSourceeNBTransparentContainer.Extensions[%d]", index))
	}
	if err := aper.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("TargeteNBToSourceeNBTransparentContainer.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// MarshalAPER encodes a complete value using one per-call change plan.
func (v *ERABInformationListComplete) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "ERABInformationListComplete")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *ERABInformationListComplete) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "ERABInformationListComplete")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APERABInformationListComplete(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "ERABInformationListComplete")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "ERABInformationListComplete")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *ERABInformationListComplete) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "ERABInformationListComplete")
}
func (v *ERABInformationListComplete) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "ERABInformationListComplete")
}
func (v *ERABInformationListComplete) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APERABInformationListComplete(v, &s)
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
func (v *ERABInformationListComplete) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *ERABInformationListComplete) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
	if err := s30.BridgeMarshalAPERERABInformationListTo(v.Value, bb, fresh); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.perPadding)
}

// MarshalAPER encodes a complete value using one per-call change plan.
func (v *ERABListComplete) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "ERABListComplete")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *ERABListComplete) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "ERABListComplete")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APERABListComplete(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "ERABListComplete")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "ERABListComplete")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *ERABListComplete) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "ERABListComplete")
}
func (v *ERABListComplete) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "ERABListComplete")
}
func (v *ERABListComplete) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APERABListComplete(v, &s)
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
func (v *ERABListComplete) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *ERABListComplete) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
	if err := s25.BridgeMarshalAPERERABListTo(v.Value, bb, fresh); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.perPadding)
}

// MarshalAPER encodes a complete value using one per-call change plan.
func (v *ERABSecurityResultListComplete) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "ERABSecurityResultListComplete")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *ERABSecurityResultListComplete) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "ERABSecurityResultListComplete")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APERABSecurityResultListComplete(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "ERABSecurityResultListComplete")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "ERABSecurityResultListComplete")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *ERABSecurityResultListComplete) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "ERABSecurityResultListComplete")
}
func (v *ERABSecurityResultListComplete) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "ERABSecurityResultListComplete")
}
func (v *ERABSecurityResultListComplete) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APERABSecurityResultListComplete(v, &s)
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
func (v *ERABSecurityResultListComplete) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *ERABSecurityResultListComplete) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
	if err := s30.BridgeMarshalAPERERABSecurityResultListTo(v.Value, bb, fresh); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.perPadding)
}

// MarshalAPER encodes a complete value using one per-call change plan.
func (v *TargeteNBToSourceeNBTransparentContainer) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "TargeteNBToSourceeNBTransparentContainer")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *TargeteNBToSourceeNBTransparentContainer) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "TargeteNBToSourceeNBTransparentContainer")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APTargeteNBToSourceeNBTransparentContainer(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "TargeteNBToSourceeNBTransparentContainer")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "TargeteNBToSourceeNBTransparentContainer")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *TargeteNBToSourceeNBTransparentContainer) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "TargeteNBToSourceeNBTransparentContainer")
}
func (v *TargeteNBToSourceeNBTransparentContainer) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "TargeteNBToSourceeNBTransparentContainer")
}
func (v *TargeteNBToSourceeNBTransparentContainer) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APTargeteNBToSourceeNBTransparentContainer(v, &s)
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
func (v *TargeteNBToSourceeNBTransparentContainer) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *TargeteNBToSourceeNBTransparentContainer) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
func (v *ERABInformationListComplete) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "ERABInformationListComplete")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded ERABInformationListComplete
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APERABInformationListComplete(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = ERABInformationListComplete{}
		return report, aper.OperationError(err, "ERABInformationListComplete")
	}
	*v = decoded
	return report, aper.OperationError(nil, "ERABInformationListComplete")
}

// UnmarshalAPER decodes one complete value and returns its report.
func (v *ERABListComplete) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "ERABListComplete")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded ERABListComplete
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APERABListComplete(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = ERABListComplete{}
		return report, aper.OperationError(err, "ERABListComplete")
	}
	*v = decoded
	return report, aper.OperationError(nil, "ERABListComplete")
}

// UnmarshalAPER decodes one complete value and returns its report.
func (v *ERABSecurityResultListComplete) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "ERABSecurityResultListComplete")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded ERABSecurityResultListComplete
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APERABSecurityResultListComplete(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = ERABSecurityResultListComplete{}
		return report, aper.OperationError(err, "ERABSecurityResultListComplete")
	}
	*v = decoded
	return report, aper.OperationError(nil, "ERABSecurityResultListComplete")
}

// UnmarshalAPER decodes one complete value and returns its report.
func (v *TargeteNBToSourceeNBTransparentContainer) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "TargeteNBToSourceeNBTransparentContainer")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded TargeteNBToSourceeNBTransparentContainer
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APTargeteNBToSourceeNBTransparentContainer(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = TargeteNBToSourceeNBTransparentContainer{}
		return report, aper.OperationError(err, "TargeteNBToSourceeNBTransparentContainer")
	}
	*v = decoded
	return report, aper.OperationError(nil, "TargeteNBToSourceeNBTransparentContainer")
}

// MarshalAPERERABInformationList encodes a complete named list.
func MarshalAPERERABInformationList(v ERABInformationListComplete, options ...aper.EncodeOption) ([]byte, error) {
	return v.MarshalAPER(options...)
}

// MarshalAPERERABList encodes a complete named list.
func MarshalAPERERABList(v ERABListComplete, options ...aper.EncodeOption) ([]byte, error) {
	return v.MarshalAPER(options...)
}

// MarshalAPERERABSecurityResultList encodes a complete named list.
func MarshalAPERERABSecurityResultList(v ERABSecurityResultListComplete, options ...aper.EncodeOption) ([]byte, error) {
	return v.MarshalAPER(options...)
}

// UnmarshalAPERERABInformationList decodes a complete named list.
func UnmarshalAPERERABInformationList(data []byte, options ...aper.DecodeOption) (ERABInformationListComplete, aper.DecodeReport, error) {
	var v ERABInformationListComplete
	report, err := v.UnmarshalAPER(data, options...)
	return v, report, err
}

// UnmarshalAPERERABList decodes a complete named list.
func UnmarshalAPERERABList(data []byte, options ...aper.DecodeOption) (ERABListComplete, aper.DecodeReport, error) {
	var v ERABListComplete
	report, err := v.UnmarshalAPER(data, options...)
	return v, report, err
}

// UnmarshalAPERERABSecurityResultList decodes a complete named list.
func UnmarshalAPERERABSecurityResultList(data []byte, options ...aper.DecodeOption) (ERABSecurityResultListComplete, aper.DecodeReport, error) {
	var v ERABSecurityResultListComplete
	report, err := v.UnmarshalAPER(data, options...)
	return v, report, err
}

// HandoverRequestAcknowledge represents the ASN.1 type HandoverRequestAcknowledge (SEQUENCE).
type HandoverRequestAcknowledge struct {
	replay           aper.Snapshot
	stream           aper.WireSpan
	received         bool
	withoutReplay    bool
	receivedAbsolute bool
	receivedBytes    aper.WireSpan
	receivedLocation aper.Location
	ProtocolIEs      HandoverRequestAcknowledgeIEContainer `asn1:"tag:0,context,implicit"`
	protocolIEsIndef bool                                  `asn1:"-" json:"-"`
	extCount         int64                                 `asn1:"-" json:"-"`
	extPresent       []bool                                `asn1:"-" json:"-"`
	extData          [][]byte                              `asn1:"-" json:"-"`
	perPadding       aper.FinalPadding                     `asn1:"-" json:"-"`
	perExtPadding    []aper.CompletePadding                `asn1:"-" json:"-"`
	extOrigin        []aper.OpaqueOrigin
	extWire          []aper.WireSpan
}

// ERABReleaseCommand represents the ASN.1 type E-RABReleaseCommand (SEQUENCE).
type ERABReleaseCommand struct {
	replay           aper.Snapshot
	stream           aper.WireSpan
	received         bool
	withoutReplay    bool
	receivedAbsolute bool
	receivedBytes    aper.WireSpan
	receivedLocation aper.Location
	ProtocolIEs      ERABReleaseCommandIEContainer `asn1:"tag:0,context,implicit"`
	protocolIEsIndef bool                          `asn1:"-" json:"-"`
	extCount         int64                         `asn1:"-" json:"-"`
	extPresent       []bool                        `asn1:"-" json:"-"`
	extData          [][]byte                      `asn1:"-" json:"-"`
	perPadding       aper.FinalPadding             `asn1:"-" json:"-"`
	perExtPadding    []aper.CompletePadding        `asn1:"-" json:"-"`
	extOrigin        []aper.OpaqueOrigin
	extWire          []aper.WireSpan
}

// ERABModificationConfirm represents the ASN.1 type E-RABModificationConfirm (SEQUENCE).
type ERABModificationConfirm struct {
	replay           aper.Snapshot
	stream           aper.WireSpan
	received         bool
	withoutReplay    bool
	receivedAbsolute bool
	receivedBytes    aper.WireSpan
	receivedLocation aper.Location
	ProtocolIEs      ERABModificationConfirmIEContainer `asn1:"tag:0,context,implicit"`
	protocolIEsIndef bool                               `asn1:"-" json:"-"`
	extCount         int64                              `asn1:"-" json:"-"`
	extPresent       []bool                             `asn1:"-" json:"-"`
	extData          [][]byte                           `asn1:"-" json:"-"`
	perPadding       aper.FinalPadding                  `asn1:"-" json:"-"`
	perExtPadding    []aper.CompletePadding             `asn1:"-" json:"-"`
	extOrigin        []aper.OpaqueOrigin
	extWire          []aper.WireSpan
}

// MarshalAPER encodes HandoverRequestAcknowledge to APER format.
func (v *HandoverRequestAcknowledge) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *HandoverRequestAcknowledge) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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

// UnmarshalAPER decodes HandoverRequestAcknowledge from APER format.
func (v *HandoverRequestAcknowledge) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes HandoverRequestAcknowledge with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *HandoverRequestAcknowledge) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "HandoverRequestAcknowledge")
	}
	bb.EnterComponent("HandoverRequestAcknowledge")
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "HandoverRequestAcknowledge")
	}
	padding, err := aper.CaptureFinalBits(bb, "HandoverRequestAcknowledge")
	if err != nil {
		return runtime.WrapDecodePath(err, "HandoverRequestAcknowledge")
	}
	v.perPadding = padding.WithRecords(v.perPadding)
	return nil
}
func (v *HandoverRequestAcknowledge) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = HandoverRequestAcknowledge{}
	extAdditions := aper.BeginExtensionAdditions(bb)
	hasExtensions, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	toleranceMark_protocolies := bb.EnterComponent("ProtocolIEs")
	v.ProtocolIEs = make(HandoverRequestAcknowledgeIEContainer, 0)
	_, errCollection_protocolies := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1128
		if fragmentOffset_protocolies < 0 || fragmentLength_protocolies < 0 || fragmentLength_protocolies > int64(^uint(0)>>1) || fragmentOffset_protocolies > int64(^uint(0)>>1)-fragmentLength_protocolies {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_protocolies; i++ {
			var elem HandoverRequestAcknowledgeIEField
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

// ERABFailedtoSetupListHOReqAckComplete carries a complete ERABFailedtoSetupListHOReqAck encoding, including observed terminal bits.
// ITU-T X.691 (02/2021) 11.1.3.1 and 11.1.4 require new encodings to pad with zero bits.
type ERABFailedtoSetupListHOReqAckComplete struct {
	replay           aper.Snapshot
	stream           aper.WireSpan
	received         bool
	withoutReplay    bool
	receivedAbsolute bool
	receivedBytes    aper.WireSpan
	receivedLocation aper.Location
	Value            s16.ERABFailedtoSetupListHOReqAck
	perPadding       aper.CompletePadding `json:"-"`
}

func (v *ERABFailedtoSetupListHOReqAckComplete) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := s25.BridgeMarshalAPERERABFailedtoSetupListHOReqAckTo(v.Value, bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.perPadding)
}

// UnmarshalAPER decodes ERABFailedtoSetupListHOReqAck from APER format.
func (v *ERABFailedtoSetupListHOReqAckComplete) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes ERABFailedtoSetupListHOReqAck with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *ERABFailedtoSetupListHOReqAckComplete) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "ERABFailedtoSetupListHOReqAck")
	}
	bb.EnterComponent("ERABFailedtoSetupListHOReqAck")
	value, err := BridgeUnmarshalAPERERABFailedtoSetupListHOReqAckFrom(bb)
	if err != nil {
		return runtime.WrapDecodePath(err, "ERABFailedtoSetupListHOReqAck")
	}
	padding, err := aper.CaptureFinalBits(bb, "ERABFailedtoSetupListHOReqAck")
	if err != nil {
		return runtime.WrapDecodePath(err, "ERABFailedtoSetupListHOReqAck")
	}
	v.Value, v.perPadding = value, padding.Padding()
	return nil
}

// MarshalAPERERABFailedtoSetupListHOReqAck encodes a ERABFailedtoSetupListHOReqAck list to APER.
func BridgeMarshalAPERERABFailedtoSetupListHOReqAck(list ERABFailedtoSetupListHOReqAckComplete) ([]byte, error) {
	return list.marshalAPERLegacy()
}

// UnmarshalAPERERABFailedtoSetupListHOReqAck decodes a ERABFailedtoSetupListHOReqAck list from APER.
func BridgeUnmarshalAPERERABFailedtoSetupListHOReqAck(data []byte) (ERABFailedtoSetupListHOReqAckComplete, error) {
	var value ERABFailedtoSetupListHOReqAckComplete
	if err := value.unmarshalAPERLegacy(data); err != nil {
		return value, err
	}
	return value, nil
}

// UnmarshalAPERERABFailedtoSetupListHOReqAckFrom decodes a ERABFailedtoSetupListHOReqAck list from bb.
func BridgeUnmarshalAPERERABFailedtoSetupListHOReqAckFrom(bb *aper.BitBuffer) (s16.ERABFailedtoSetupListHOReqAck, error) {
	if err := bb.EnterDecodeValue(); err != nil {
		return nil, err
	}
	defer bb.LeaveDecodeValue()
	var v s21.BridgeAsn1cAPERERABFailedtoSetupListHOReqAckListValue
	if err := BridgeUnmarshalAPERERABFailedtoSetupListHOReqAckInto(&v, bb); err != nil {
		return nil, err
	}
	return v.Value, nil
}
func BridgeUnmarshalAPERERABFailedtoSetupListHOReqAckInto(v *s21.BridgeAsn1cAPERERABFailedtoSetupListHOReqAckListValue, bb *aper.BitBuffer) error {
	toleranceMark_value := bb.EnterComponent("Value")
	v.Value = make(s16.ERABFailedtoSetupListHOReqAck, 0)
	_, errCollection_value := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 256, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1128
		if fragmentOffset_value < 0 || fragmentLength_value < 0 || fragmentLength_value > int64(^uint(0)>>1) || fragmentOffset_value > int64(^uint(0)>>1)-fragmentLength_value {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_value; i++ {
			var elem s16.ERABFailedtoSetupItemHOReqAckIEValueProtocolIESingleContainer
			elementMark := bb.EnterIndex(fragmentOffset_value + i)
			if err := s16.BridgeERABFailedtoSetupItemHOReqAckIEFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
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

// ERABSetupListBearerSUResComplete carries a complete ERABSetupListBearerSURes encoding, including observed terminal bits.
// ITU-T X.691 (02/2021) 11.1.3.1 and 11.1.4 require new encodings to pad with zero bits.
type ERABSetupListBearerSUResComplete struct {
	replay           aper.Snapshot
	stream           aper.WireSpan
	received         bool
	withoutReplay    bool
	receivedAbsolute bool
	receivedBytes    aper.WireSpan
	receivedLocation aper.Location
	Value            s17.ERABSetupListBearerSURes
	perPadding       aper.CompletePadding `json:"-"`
}

func (v *ERABSetupListBearerSUResComplete) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := s25.BridgeMarshalAPERERABSetupListBearerSUResTo(v.Value, bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.perPadding)
}

// UnmarshalAPER decodes ERABSetupListBearerSURes from APER format.
func (v *ERABSetupListBearerSUResComplete) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes ERABSetupListBearerSURes with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *ERABSetupListBearerSUResComplete) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "ERABSetupListBearerSURes")
	}
	bb.EnterComponent("ERABSetupListBearerSURes")
	value, err := BridgeUnmarshalAPERERABSetupListBearerSUResFrom(bb)
	if err != nil {
		return runtime.WrapDecodePath(err, "ERABSetupListBearerSURes")
	}
	padding, err := aper.CaptureFinalBits(bb, "ERABSetupListBearerSURes")
	if err != nil {
		return runtime.WrapDecodePath(err, "ERABSetupListBearerSURes")
	}
	v.Value, v.perPadding = value, padding.Padding()
	return nil
}

// MarshalAPERERABSetupListBearerSURes encodes a ERABSetupListBearerSURes list to APER.
func BridgeMarshalAPERERABSetupListBearerSURes(list ERABSetupListBearerSUResComplete) ([]byte, error) {
	return list.marshalAPERLegacy()
}

// UnmarshalAPERERABSetupListBearerSURes decodes a ERABSetupListBearerSURes list from APER.
func BridgeUnmarshalAPERERABSetupListBearerSURes(data []byte) (ERABSetupListBearerSUResComplete, error) {
	var value ERABSetupListBearerSUResComplete
	if err := value.unmarshalAPERLegacy(data); err != nil {
		return value, err
	}
	return value, nil
}

// UnmarshalAPERERABSetupListBearerSUResFrom decodes a ERABSetupListBearerSURes list from bb.
func BridgeUnmarshalAPERERABSetupListBearerSUResFrom(bb *aper.BitBuffer) (s17.ERABSetupListBearerSURes, error) {
	if err := bb.EnterDecodeValue(); err != nil {
		return nil, err
	}
	defer bb.LeaveDecodeValue()
	var v s21.BridgeAsn1cAPERERABSetupListBearerSUResListValue
	if err := BridgeUnmarshalAPERERABSetupListBearerSUResInto(&v, bb); err != nil {
		return nil, err
	}
	return v.Value, nil
}
func BridgeUnmarshalAPERERABSetupListBearerSUResInto(v *s21.BridgeAsn1cAPERERABSetupListBearerSUResListValue, bb *aper.BitBuffer) error {
	toleranceMark_value := bb.EnterComponent("Value")
	v.Value = make(s17.ERABSetupListBearerSURes, 0)
	_, errCollection_value := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 256, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1128
		if fragmentOffset_value < 0 || fragmentLength_value < 0 || fragmentLength_value > int64(^uint(0)>>1) || fragmentOffset_value > int64(^uint(0)>>1)-fragmentLength_value {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_value; i++ {
			var elem s16.ERABSetupItemBearerSUResIEValueProtocolIESingleContainer
			elementMark := bb.EnterIndex(fragmentOffset_value + i)
			if err := s16.BridgeERABSetupItemBearerSUResIEFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
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

// ERABModifyListBearerModResComplete carries a complete ERABModifyListBearerModRes encoding, including observed terminal bits.
// ITU-T X.691 (02/2021) 11.1.3.1 and 11.1.4 require new encodings to pad with zero bits.
type ERABModifyListBearerModResComplete struct {
	replay           aper.Snapshot
	stream           aper.WireSpan
	received         bool
	withoutReplay    bool
	receivedAbsolute bool
	receivedBytes    aper.WireSpan
	receivedLocation aper.Location
	Value            s16.ERABModifyListBearerModRes
	perPadding       aper.CompletePadding `json:"-"`
}

func (v *ERABModifyListBearerModResComplete) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := s25.BridgeMarshalAPERERABModifyListBearerModResTo(v.Value, bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.perPadding)
}

// UnmarshalAPER decodes ERABModifyListBearerModRes from APER format.
func (v *ERABModifyListBearerModResComplete) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes ERABModifyListBearerModRes with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *ERABModifyListBearerModResComplete) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "ERABModifyListBearerModRes")
	}
	bb.EnterComponent("ERABModifyListBearerModRes")
	value, err := BridgeUnmarshalAPERERABModifyListBearerModResFrom(bb)
	if err != nil {
		return runtime.WrapDecodePath(err, "ERABModifyListBearerModRes")
	}
	padding, err := aper.CaptureFinalBits(bb, "ERABModifyListBearerModRes")
	if err != nil {
		return runtime.WrapDecodePath(err, "ERABModifyListBearerModRes")
	}
	v.Value, v.perPadding = value, padding.Padding()
	return nil
}

// MarshalAPERERABModifyListBearerModRes encodes a ERABModifyListBearerModRes list to APER.
func BridgeMarshalAPERERABModifyListBearerModRes(list ERABModifyListBearerModResComplete) ([]byte, error) {
	return list.marshalAPERLegacy()
}

// UnmarshalAPERERABModifyListBearerModRes decodes a ERABModifyListBearerModRes list from APER.
func BridgeUnmarshalAPERERABModifyListBearerModRes(data []byte) (ERABModifyListBearerModResComplete, error) {
	var value ERABModifyListBearerModResComplete
	if err := value.unmarshalAPERLegacy(data); err != nil {
		return value, err
	}
	return value, nil
}

// UnmarshalAPERERABModifyListBearerModResFrom decodes a ERABModifyListBearerModRes list from bb.
func BridgeUnmarshalAPERERABModifyListBearerModResFrom(bb *aper.BitBuffer) (s16.ERABModifyListBearerModRes, error) {
	if err := bb.EnterDecodeValue(); err != nil {
		return nil, err
	}
	defer bb.LeaveDecodeValue()
	var v s21.BridgeAsn1cAPERERABModifyListBearerModResListValue
	if err := BridgeUnmarshalAPERERABModifyListBearerModResInto(&v, bb); err != nil {
		return nil, err
	}
	return v.Value, nil
}
func BridgeUnmarshalAPERERABModifyListBearerModResInto(v *s21.BridgeAsn1cAPERERABModifyListBearerModResListValue, bb *aper.BitBuffer) error {
	toleranceMark_value := bb.EnterComponent("Value")
	v.Value = make(s16.ERABModifyListBearerModRes, 0)
	_, errCollection_value := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 256, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1128
		if fragmentOffset_value < 0 || fragmentLength_value < 0 || fragmentLength_value > int64(^uint(0)>>1) || fragmentOffset_value > int64(^uint(0)>>1)-fragmentLength_value {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_value; i++ {
			var elem s16.ERABModifyItemBearerModResIEValueProtocolIESingleContainer
			elementMark := bb.EnterIndex(fragmentOffset_value + i)
			if err := s16.BridgeERABModifyItemBearerModResIEFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
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

// MarshalAPER encodes ERABReleaseCommand to APER format.
func (v *ERABReleaseCommand) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *ERABReleaseCommand) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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

// UnmarshalAPER decodes ERABReleaseCommand from APER format.
func (v *ERABReleaseCommand) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes ERABReleaseCommand with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *ERABReleaseCommand) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "ERABReleaseCommand")
	}
	bb.EnterComponent("ERABReleaseCommand")
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "ERABReleaseCommand")
	}
	padding, err := aper.CaptureFinalBits(bb, "ERABReleaseCommand")
	if err != nil {
		return runtime.WrapDecodePath(err, "ERABReleaseCommand")
	}
	v.perPadding = padding.WithRecords(v.perPadding)
	return nil
}
func (v *ERABReleaseCommand) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = ERABReleaseCommand{}
	extAdditions := aper.BeginExtensionAdditions(bb)
	hasExtensions, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	toleranceMark_protocolies := bb.EnterComponent("ProtocolIEs")
	v.ProtocolIEs = make(ERABReleaseCommandIEContainer, 0)
	_, errCollection_protocolies := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1128
		if fragmentOffset_protocolies < 0 || fragmentLength_protocolies < 0 || fragmentLength_protocolies > int64(^uint(0)>>1) || fragmentOffset_protocolies > int64(^uint(0)>>1)-fragmentLength_protocolies {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_protocolies; i++ {
			var elem ERABReleaseCommandIEField
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

// ERABReleaseListBearerRelCompComplete carries a complete ERABReleaseListBearerRelComp encoding, including observed terminal bits.
// ITU-T X.691 (02/2021) 11.1.3.1 and 11.1.4 require new encodings to pad with zero bits.
type ERABReleaseListBearerRelCompComplete struct {
	replay           aper.Snapshot
	stream           aper.WireSpan
	received         bool
	withoutReplay    bool
	receivedAbsolute bool
	receivedBytes    aper.WireSpan
	receivedLocation aper.Location
	Value            s16.ERABReleaseListBearerRelComp
	perPadding       aper.CompletePadding `json:"-"`
}

func (v *ERABReleaseListBearerRelCompComplete) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := s25.BridgeMarshalAPERERABReleaseListBearerRelCompTo(v.Value, bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.perPadding)
}

// UnmarshalAPER decodes ERABReleaseListBearerRelComp from APER format.
func (v *ERABReleaseListBearerRelCompComplete) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes ERABReleaseListBearerRelComp with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *ERABReleaseListBearerRelCompComplete) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "ERABReleaseListBearerRelComp")
	}
	bb.EnterComponent("ERABReleaseListBearerRelComp")
	value, err := BridgeUnmarshalAPERERABReleaseListBearerRelCompFrom(bb)
	if err != nil {
		return runtime.WrapDecodePath(err, "ERABReleaseListBearerRelComp")
	}
	padding, err := aper.CaptureFinalBits(bb, "ERABReleaseListBearerRelComp")
	if err != nil {
		return runtime.WrapDecodePath(err, "ERABReleaseListBearerRelComp")
	}
	v.Value, v.perPadding = value, padding.Padding()
	return nil
}

// MarshalAPERERABReleaseListBearerRelComp encodes a ERABReleaseListBearerRelComp list to APER.
func BridgeMarshalAPERERABReleaseListBearerRelComp(list ERABReleaseListBearerRelCompComplete) ([]byte, error) {
	return list.marshalAPERLegacy()
}

// UnmarshalAPERERABReleaseListBearerRelComp decodes a ERABReleaseListBearerRelComp list from APER.
func BridgeUnmarshalAPERERABReleaseListBearerRelComp(data []byte) (ERABReleaseListBearerRelCompComplete, error) {
	var value ERABReleaseListBearerRelCompComplete
	if err := value.unmarshalAPERLegacy(data); err != nil {
		return value, err
	}
	return value, nil
}

// UnmarshalAPERERABReleaseListBearerRelCompFrom decodes a ERABReleaseListBearerRelComp list from bb.
func BridgeUnmarshalAPERERABReleaseListBearerRelCompFrom(bb *aper.BitBuffer) (s16.ERABReleaseListBearerRelComp, error) {
	if err := bb.EnterDecodeValue(); err != nil {
		return nil, err
	}
	defer bb.LeaveDecodeValue()
	var v s21.BridgeAsn1cAPERERABReleaseListBearerRelCompListValue
	if err := BridgeUnmarshalAPERERABReleaseListBearerRelCompInto(&v, bb); err != nil {
		return nil, err
	}
	return v.Value, nil
}
func BridgeUnmarshalAPERERABReleaseListBearerRelCompInto(v *s21.BridgeAsn1cAPERERABReleaseListBearerRelCompListValue, bb *aper.BitBuffer) error {
	toleranceMark_value := bb.EnterComponent("Value")
	v.Value = make(s16.ERABReleaseListBearerRelComp, 0)
	_, errCollection_value := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 256, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1128
		if fragmentOffset_value < 0 || fragmentLength_value < 0 || fragmentLength_value > int64(^uint(0)>>1) || fragmentOffset_value > int64(^uint(0)>>1)-fragmentLength_value {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_value; i++ {
			var elem s16.ERABReleaseItemBearerRelCompIEValueProtocolIESingleContainer
			elementMark := bb.EnterIndex(fragmentOffset_value + i)
			if err := s16.BridgeERABReleaseItemBearerRelCompIEFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
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

// ERABSetupListCtxtSUResComplete carries a complete ERABSetupListCtxtSURes encoding, including observed terminal bits.
// ITU-T X.691 (02/2021) 11.1.3.1 and 11.1.4 require new encodings to pad with zero bits.
type ERABSetupListCtxtSUResComplete struct {
	replay           aper.Snapshot
	stream           aper.WireSpan
	received         bool
	withoutReplay    bool
	receivedAbsolute bool
	receivedBytes    aper.WireSpan
	receivedLocation aper.Location
	Value            s17.ERABSetupListCtxtSURes
	perPadding       aper.CompletePadding `json:"-"`
}

func (v *ERABSetupListCtxtSUResComplete) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := s25.BridgeMarshalAPERERABSetupListCtxtSUResTo(v.Value, bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.perPadding)
}

// UnmarshalAPER decodes ERABSetupListCtxtSURes from APER format.
func (v *ERABSetupListCtxtSUResComplete) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes ERABSetupListCtxtSURes with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *ERABSetupListCtxtSUResComplete) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "ERABSetupListCtxtSURes")
	}
	bb.EnterComponent("ERABSetupListCtxtSURes")
	value, err := BridgeUnmarshalAPERERABSetupListCtxtSUResFrom(bb)
	if err != nil {
		return runtime.WrapDecodePath(err, "ERABSetupListCtxtSURes")
	}
	padding, err := aper.CaptureFinalBits(bb, "ERABSetupListCtxtSURes")
	if err != nil {
		return runtime.WrapDecodePath(err, "ERABSetupListCtxtSURes")
	}
	v.Value, v.perPadding = value, padding.Padding()
	return nil
}

// UnmarshalAPERERABSetupListCtxtSUResFrom decodes a ERABSetupListCtxtSURes list from bb.
func BridgeUnmarshalAPERERABSetupListCtxtSUResFrom(bb *aper.BitBuffer) (s17.ERABSetupListCtxtSURes, error) {
	if err := bb.EnterDecodeValue(); err != nil {
		return nil, err
	}
	defer bb.LeaveDecodeValue()
	var v s21.BridgeAsn1cAPERERABSetupListCtxtSUResListValue
	if err := BridgeUnmarshalAPERERABSetupListCtxtSUResInto(&v, bb); err != nil {
		return nil, err
	}
	return v.Value, nil
}
func BridgeUnmarshalAPERERABSetupListCtxtSUResInto(v *s21.BridgeAsn1cAPERERABSetupListCtxtSUResListValue, bb *aper.BitBuffer) error {
	toleranceMark_value := bb.EnterComponent("Value")
	v.Value = make(s17.ERABSetupListCtxtSURes, 0)
	_, errCollection_value := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 256, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1128
		if fragmentOffset_value < 0 || fragmentLength_value < 0 || fragmentLength_value > int64(^uint(0)>>1) || fragmentOffset_value > int64(^uint(0)>>1)-fragmentLength_value {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_value; i++ {
			var elem s17.ERABSetupItemCtxtSUResIEValueProtocolIESingleContainer
			elementMark := bb.EnterIndex(fragmentOffset_value + i)
			if err := s16.BridgeERABSetupItemCtxtSUResIEFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
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

// ERABNotToBeModifiedListBearerModIndComplete carries a complete ERABNotToBeModifiedListBearerModInd encoding, including observed terminal bits.
// ITU-T X.691 (02/2021) 11.1.3.1 and 11.1.4 require new encodings to pad with zero bits.
type ERABNotToBeModifiedListBearerModIndComplete struct {
	replay           aper.Snapshot
	stream           aper.WireSpan
	received         bool
	withoutReplay    bool
	receivedAbsolute bool
	receivedBytes    aper.WireSpan
	receivedLocation aper.Location
	Value            s16.ERABNotToBeModifiedListBearerModInd
	perPadding       aper.CompletePadding `json:"-"`
}

func (v *ERABNotToBeModifiedListBearerModIndComplete) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := s25.BridgeMarshalAPERERABNotToBeModifiedListBearerModIndTo(v.Value, bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.perPadding)
}

// UnmarshalAPER decodes ERABNotToBeModifiedListBearerModInd from APER format.
func (v *ERABNotToBeModifiedListBearerModIndComplete) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes ERABNotToBeModifiedListBearerModInd with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *ERABNotToBeModifiedListBearerModIndComplete) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "ERABNotToBeModifiedListBearerModInd")
	}
	bb.EnterComponent("ERABNotToBeModifiedListBearerModInd")
	value, err := BridgeUnmarshalAPERERABNotToBeModifiedListBearerModIndFrom(bb)
	if err != nil {
		return runtime.WrapDecodePath(err, "ERABNotToBeModifiedListBearerModInd")
	}
	padding, err := aper.CaptureFinalBits(bb, "ERABNotToBeModifiedListBearerModInd")
	if err != nil {
		return runtime.WrapDecodePath(err, "ERABNotToBeModifiedListBearerModInd")
	}
	v.Value, v.perPadding = value, padding.Padding()
	return nil
}

// MarshalAPERERABNotToBeModifiedListBearerModInd encodes a ERABNotToBeModifiedListBearerModInd list to APER.
func BridgeMarshalAPERERABNotToBeModifiedListBearerModInd(list ERABNotToBeModifiedListBearerModIndComplete) ([]byte, error) {
	return list.marshalAPERLegacy()
}

// UnmarshalAPERERABNotToBeModifiedListBearerModInd decodes a ERABNotToBeModifiedListBearerModInd list from APER.
func BridgeUnmarshalAPERERABNotToBeModifiedListBearerModInd(data []byte) (ERABNotToBeModifiedListBearerModIndComplete, error) {
	var value ERABNotToBeModifiedListBearerModIndComplete
	if err := value.unmarshalAPERLegacy(data); err != nil {
		return value, err
	}
	return value, nil
}

// UnmarshalAPERERABNotToBeModifiedListBearerModIndFrom decodes a ERABNotToBeModifiedListBearerModInd list from bb.
func BridgeUnmarshalAPERERABNotToBeModifiedListBearerModIndFrom(bb *aper.BitBuffer) (s16.ERABNotToBeModifiedListBearerModInd, error) {
	if err := bb.EnterDecodeValue(); err != nil {
		return nil, err
	}
	defer bb.LeaveDecodeValue()
	var v s21.BridgeAsn1cAPERERABNotToBeModifiedListBearerModIndListValue
	if err := BridgeUnmarshalAPERERABNotToBeModifiedListBearerModIndInto(&v, bb); err != nil {
		return nil, err
	}
	return v.Value, nil
}
func BridgeUnmarshalAPERERABNotToBeModifiedListBearerModIndInto(v *s21.BridgeAsn1cAPERERABNotToBeModifiedListBearerModIndListValue, bb *aper.BitBuffer) error {
	toleranceMark_value := bb.EnterComponent("Value")
	v.Value = make(s16.ERABNotToBeModifiedListBearerModInd, 0)
	_, errCollection_value := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 256, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1128
		if fragmentOffset_value < 0 || fragmentLength_value < 0 || fragmentLength_value > int64(^uint(0)>>1) || fragmentOffset_value > int64(^uint(0)>>1)-fragmentLength_value {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_value; i++ {
			var elem s16.ERABNotToBeModifiedItemBearerModIndIEValueProtocolIESingleContainer
			elementMark := bb.EnterIndex(fragmentOffset_value + i)
			if err := s16.BridgeERABNotToBeModifiedItemBearerModIndIEFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
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

// MarshalAPER encodes ERABModificationConfirm to APER format.
func (v *ERABModificationConfirm) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *ERABModificationConfirm) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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

// UnmarshalAPER decodes ERABModificationConfirm from APER format.
func (v *ERABModificationConfirm) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes ERABModificationConfirm with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *ERABModificationConfirm) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "ERABModificationConfirm")
	}
	bb.EnterComponent("ERABModificationConfirm")
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "ERABModificationConfirm")
	}
	padding, err := aper.CaptureFinalBits(bb, "ERABModificationConfirm")
	if err != nil {
		return runtime.WrapDecodePath(err, "ERABModificationConfirm")
	}
	v.perPadding = padding.WithRecords(v.perPadding)
	return nil
}
func (v *ERABModificationConfirm) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = ERABModificationConfirm{}
	extAdditions := aper.BeginExtensionAdditions(bb)
	hasExtensions, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	toleranceMark_protocolies := bb.EnterComponent("ProtocolIEs")
	v.ProtocolIEs = make(ERABModificationConfirmIEContainer, 0)
	_, errCollection_protocolies := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1128
		if fragmentOffset_protocolies < 0 || fragmentLength_protocolies < 0 || fragmentLength_protocolies > int64(^uint(0)>>1) || fragmentOffset_protocolies > int64(^uint(0)>>1)-fragmentLength_protocolies {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_protocolies; i++ {
			var elem ERABModificationConfirmIEField
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

// ERABModifyListBearerModConfComplete carries a complete ERABModifyListBearerModConf encoding, including observed terminal bits.
// ITU-T X.691 (02/2021) 11.1.3.1 and 11.1.4 require new encodings to pad with zero bits.
type ERABModifyListBearerModConfComplete struct {
	replay           aper.Snapshot
	stream           aper.WireSpan
	received         bool
	withoutReplay    bool
	receivedAbsolute bool
	receivedBytes    aper.WireSpan
	receivedLocation aper.Location
	Value            s16.ERABModifyListBearerModConf
	perPadding       aper.CompletePadding `json:"-"`
}

func (v *ERABModifyListBearerModConfComplete) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := s25.BridgeMarshalAPERERABModifyListBearerModConfTo(v.Value, bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.perPadding)
}

// UnmarshalAPER decodes ERABModifyListBearerModConf from APER format.
func (v *ERABModifyListBearerModConfComplete) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes ERABModifyListBearerModConf with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *ERABModifyListBearerModConfComplete) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "ERABModifyListBearerModConf")
	}
	bb.EnterComponent("ERABModifyListBearerModConf")
	value, err := BridgeUnmarshalAPERERABModifyListBearerModConfFrom(bb)
	if err != nil {
		return runtime.WrapDecodePath(err, "ERABModifyListBearerModConf")
	}
	padding, err := aper.CaptureFinalBits(bb, "ERABModifyListBearerModConf")
	if err != nil {
		return runtime.WrapDecodePath(err, "ERABModifyListBearerModConf")
	}
	v.Value, v.perPadding = value, padding.Padding()
	return nil
}

// MarshalAPERERABModifyListBearerModConf encodes a ERABModifyListBearerModConf list to APER.
func BridgeMarshalAPERERABModifyListBearerModConf(list ERABModifyListBearerModConfComplete) ([]byte, error) {
	return list.marshalAPERLegacy()
}

// UnmarshalAPERERABModifyListBearerModConf decodes a ERABModifyListBearerModConf list from APER.
func BridgeUnmarshalAPERERABModifyListBearerModConf(data []byte) (ERABModifyListBearerModConfComplete, error) {
	var value ERABModifyListBearerModConfComplete
	if err := value.unmarshalAPERLegacy(data); err != nil {
		return value, err
	}
	return value, nil
}

// UnmarshalAPERERABModifyListBearerModConfFrom decodes a ERABModifyListBearerModConf list from bb.
func BridgeUnmarshalAPERERABModifyListBearerModConfFrom(bb *aper.BitBuffer) (s16.ERABModifyListBearerModConf, error) {
	if err := bb.EnterDecodeValue(); err != nil {
		return nil, err
	}
	defer bb.LeaveDecodeValue()
	var v s21.BridgeAsn1cAPERERABModifyListBearerModConfListValue
	if err := BridgeUnmarshalAPERERABModifyListBearerModConfInto(&v, bb); err != nil {
		return nil, err
	}
	return v.Value, nil
}
func BridgeUnmarshalAPERERABModifyListBearerModConfInto(v *s21.BridgeAsn1cAPERERABModifyListBearerModConfListValue, bb *aper.BitBuffer) error {
	toleranceMark_value := bb.EnterComponent("Value")
	v.Value = make(s16.ERABModifyListBearerModConf, 0)
	_, errCollection_value := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 256, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1128
		if fragmentOffset_value < 0 || fragmentLength_value < 0 || fragmentLength_value > int64(^uint(0)>>1) || fragmentOffset_value > int64(^uint(0)>>1)-fragmentLength_value {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_value; i++ {
			var elem s16.ERABModifyItemBearerModConfIEValueProtocolIESingleContainer
			elementMark := bb.EnterIndex(fragmentOffset_value + i)
			if err := s16.BridgeERABModifyItemBearerModConfIEFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
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

// UnmarshalAPERERABFailedToResumeListResumeRes decodes a ERABFailedToResumeListResumeRes list from APER.
func BridgeUnmarshalAPERERABFailedToResumeListResumeRes(data []byte) (s38.ERABFailedToResumeListResumeResComplete, error) {
	var value s38.ERABFailedToResumeListResumeResComplete
	if err := s38.BridgeERABFailedToResumeListResumeResCompleteMethodUnmarshalAPERLegacy(&value, data); err != nil {
		return value, err
	}
	return value, nil
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *ERABFailedtoSetupListHOReqAckComplete) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s14.BridgeReceivedFormAt(v.received, v.receivedBytes, "ERABFailedtoSetupListHOReqAckComplete", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "ERABFailedtoSetupListHOReqAckComplete", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v ERABFailedtoSetupListHOReqAckComplete) WithoutReplay() ERABFailedtoSetupListHOReqAckComplete {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero ERABFailedtoSetupListHOReqAckComplete
	v.perPadding = zero.perPadding
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *ERABModificationConfirm) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s14.BridgeReceivedFormAt(v.received, v.receivedBytes, "ERABModificationConfirm", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "ERABModificationConfirm", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v ERABModificationConfirm) WithoutReplay() ERABModificationConfirm {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero ERABModificationConfirm
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *ERABModifyListBearerModConfComplete) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s14.BridgeReceivedFormAt(v.received, v.receivedBytes, "ERABModifyListBearerModConfComplete", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "ERABModifyListBearerModConfComplete", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v ERABModifyListBearerModConfComplete) WithoutReplay() ERABModifyListBearerModConfComplete {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero ERABModifyListBearerModConfComplete
	v.perPadding = zero.perPadding
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *ERABModifyListBearerModResComplete) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s14.BridgeReceivedFormAt(v.received, v.receivedBytes, "ERABModifyListBearerModResComplete", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "ERABModifyListBearerModResComplete", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v ERABModifyListBearerModResComplete) WithoutReplay() ERABModifyListBearerModResComplete {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero ERABModifyListBearerModResComplete
	v.perPadding = zero.perPadding
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *ERABNotToBeModifiedListBearerModIndComplete) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s14.BridgeReceivedFormAt(v.received, v.receivedBytes, "ERABNotToBeModifiedListBearerModIndComplete", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "ERABNotToBeModifiedListBearerModIndComplete", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v ERABNotToBeModifiedListBearerModIndComplete) WithoutReplay() ERABNotToBeModifiedListBearerModIndComplete {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero ERABNotToBeModifiedListBearerModIndComplete
	v.perPadding = zero.perPadding
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *ERABReleaseCommand) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s14.BridgeReceivedFormAt(v.received, v.receivedBytes, "ERABReleaseCommand", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "ERABReleaseCommand", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v ERABReleaseCommand) WithoutReplay() ERABReleaseCommand {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero ERABReleaseCommand
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *ERABReleaseListBearerRelCompComplete) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s14.BridgeReceivedFormAt(v.received, v.receivedBytes, "ERABReleaseListBearerRelCompComplete", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "ERABReleaseListBearerRelCompComplete", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v ERABReleaseListBearerRelCompComplete) WithoutReplay() ERABReleaseListBearerRelCompComplete {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero ERABReleaseListBearerRelCompComplete
	v.perPadding = zero.perPadding
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *ERABSetupListBearerSUResComplete) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s14.BridgeReceivedFormAt(v.received, v.receivedBytes, "ERABSetupListBearerSUResComplete", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "ERABSetupListBearerSUResComplete", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v ERABSetupListBearerSUResComplete) WithoutReplay() ERABSetupListBearerSUResComplete {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero ERABSetupListBearerSUResComplete
	v.perPadding = zero.perPadding
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *ERABSetupListCtxtSUResComplete) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s14.BridgeReceivedFormAt(v.received, v.receivedBytes, "ERABSetupListCtxtSUResComplete", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "ERABSetupListCtxtSUResComplete", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v ERABSetupListCtxtSUResComplete) WithoutReplay() ERABSetupListCtxtSUResComplete {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero ERABSetupListCtxtSUResComplete
	v.perPadding = zero.perPadding
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *HandoverRequestAcknowledge) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s14.BridgeReceivedFormAt(v.received, v.receivedBytes, "HandoverRequestAcknowledge", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "HandoverRequestAcknowledge", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v HandoverRequestAcknowledge) WithoutReplay() HandoverRequestAcknowledge {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero HandoverRequestAcknowledge
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// Extensions returns owned unknown sequence additions.
func (v *ERABModificationConfirm) Extensions() []aper.SequenceExtension {
	if v == nil {
		return nil
	}
	views := aper.SequenceExtensionViews(v.extPresent, aper.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *ERABModificationConfirm) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("ERABModificationConfirm.Extensions[%d]", index))
	}
	if err := aper.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("ERABModificationConfirm.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *ERABModificationConfirm) RemoveExtension(index uint64) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("ERABModificationConfirm.Extensions[%d]", index))
	}
	if err := aper.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("ERABModificationConfirm.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// Extensions returns owned unknown sequence additions.
func (v *ERABReleaseCommand) Extensions() []aper.SequenceExtension {
	if v == nil {
		return nil
	}
	views := aper.SequenceExtensionViews(v.extPresent, aper.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *ERABReleaseCommand) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("ERABReleaseCommand.Extensions[%d]", index))
	}
	if err := aper.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("ERABReleaseCommand.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *ERABReleaseCommand) RemoveExtension(index uint64) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("ERABReleaseCommand.Extensions[%d]", index))
	}
	if err := aper.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("ERABReleaseCommand.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// Extensions returns owned unknown sequence additions.
func (v *HandoverRequestAcknowledge) Extensions() []aper.SequenceExtension {
	if v == nil {
		return nil
	}
	views := aper.SequenceExtensionViews(v.extPresent, aper.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *HandoverRequestAcknowledge) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("HandoverRequestAcknowledge.Extensions[%d]", index))
	}
	if err := aper.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("HandoverRequestAcknowledge.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *HandoverRequestAcknowledge) RemoveExtension(index uint64) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("HandoverRequestAcknowledge.Extensions[%d]", index))
	}
	if err := aper.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("HandoverRequestAcknowledge.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// MarshalAPER encodes a complete value using one per-call change plan.
func (v *ERABFailedtoSetupListHOReqAckComplete) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "ERABFailedtoSetupListHOReqAckComplete")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *ERABFailedtoSetupListHOReqAckComplete) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "ERABFailedtoSetupListHOReqAckComplete")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APERABFailedtoSetupListHOReqAckComplete(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "ERABFailedtoSetupListHOReqAckComplete")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "ERABFailedtoSetupListHOReqAckComplete")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *ERABFailedtoSetupListHOReqAckComplete) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "ERABFailedtoSetupListHOReqAckComplete")
}
func (v *ERABFailedtoSetupListHOReqAckComplete) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "ERABFailedtoSetupListHOReqAckComplete")
}
func (v *ERABFailedtoSetupListHOReqAckComplete) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APERABFailedtoSetupListHOReqAckComplete(v, &s)
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
func (v *ERABFailedtoSetupListHOReqAckComplete) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *ERABFailedtoSetupListHOReqAckComplete) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
	if err := s25.BridgeMarshalAPERERABFailedtoSetupListHOReqAckTo(v.Value, bb, fresh); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.perPadding)
}

// MarshalAPER encodes a complete value using one per-call change plan.
func (v *ERABModificationConfirm) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "ERABModificationConfirm")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *ERABModificationConfirm) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "ERABModificationConfirm")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APERABModificationConfirm(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "ERABModificationConfirm")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "ERABModificationConfirm")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *ERABModificationConfirm) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "ERABModificationConfirm")
}
func (v *ERABModificationConfirm) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "ERABModificationConfirm")
}
func (v *ERABModificationConfirm) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APERABModificationConfirm(v, &s)
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
func (v *ERABModificationConfirm) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *ERABModificationConfirm) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
func (v *ERABModifyListBearerModConfComplete) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "ERABModifyListBearerModConfComplete")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *ERABModifyListBearerModConfComplete) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "ERABModifyListBearerModConfComplete")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APERABModifyListBearerModConfComplete(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "ERABModifyListBearerModConfComplete")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "ERABModifyListBearerModConfComplete")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *ERABModifyListBearerModConfComplete) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "ERABModifyListBearerModConfComplete")
}
func (v *ERABModifyListBearerModConfComplete) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "ERABModifyListBearerModConfComplete")
}
func (v *ERABModifyListBearerModConfComplete) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APERABModifyListBearerModConfComplete(v, &s)
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
func (v *ERABModifyListBearerModConfComplete) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *ERABModifyListBearerModConfComplete) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
	if err := s25.BridgeMarshalAPERERABModifyListBearerModConfTo(v.Value, bb, fresh); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.perPadding)
}

// MarshalAPER encodes a complete value using one per-call change plan.
func (v *ERABModifyListBearerModResComplete) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "ERABModifyListBearerModResComplete")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *ERABModifyListBearerModResComplete) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "ERABModifyListBearerModResComplete")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APERABModifyListBearerModResComplete(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "ERABModifyListBearerModResComplete")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "ERABModifyListBearerModResComplete")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *ERABModifyListBearerModResComplete) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "ERABModifyListBearerModResComplete")
}
func (v *ERABModifyListBearerModResComplete) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "ERABModifyListBearerModResComplete")
}
func (v *ERABModifyListBearerModResComplete) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APERABModifyListBearerModResComplete(v, &s)
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
func (v *ERABModifyListBearerModResComplete) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *ERABModifyListBearerModResComplete) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
	if err := s25.BridgeMarshalAPERERABModifyListBearerModResTo(v.Value, bb, fresh); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.perPadding)
}

// MarshalAPER encodes a complete value using one per-call change plan.
func (v *ERABNotToBeModifiedListBearerModIndComplete) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "ERABNotToBeModifiedListBearerModIndComplete")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *ERABNotToBeModifiedListBearerModIndComplete) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "ERABNotToBeModifiedListBearerModIndComplete")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APERABNotToBeModifiedListBearerModIndComplete(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "ERABNotToBeModifiedListBearerModIndComplete")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "ERABNotToBeModifiedListBearerModIndComplete")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *ERABNotToBeModifiedListBearerModIndComplete) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "ERABNotToBeModifiedListBearerModIndComplete")
}
func (v *ERABNotToBeModifiedListBearerModIndComplete) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "ERABNotToBeModifiedListBearerModIndComplete")
}
func (v *ERABNotToBeModifiedListBearerModIndComplete) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APERABNotToBeModifiedListBearerModIndComplete(v, &s)
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
func (v *ERABNotToBeModifiedListBearerModIndComplete) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *ERABNotToBeModifiedListBearerModIndComplete) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
	if err := s25.BridgeMarshalAPERERABNotToBeModifiedListBearerModIndTo(v.Value, bb, fresh); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.perPadding)
}

// MarshalAPER encodes a complete value using one per-call change plan.
func (v *ERABReleaseCommand) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "ERABReleaseCommand")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *ERABReleaseCommand) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "ERABReleaseCommand")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APERABReleaseCommand(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "ERABReleaseCommand")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "ERABReleaseCommand")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *ERABReleaseCommand) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "ERABReleaseCommand")
}
func (v *ERABReleaseCommand) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "ERABReleaseCommand")
}
func (v *ERABReleaseCommand) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APERABReleaseCommand(v, &s)
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
func (v *ERABReleaseCommand) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *ERABReleaseCommand) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
func (v *ERABReleaseListBearerRelCompComplete) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "ERABReleaseListBearerRelCompComplete")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *ERABReleaseListBearerRelCompComplete) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "ERABReleaseListBearerRelCompComplete")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APERABReleaseListBearerRelCompComplete(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "ERABReleaseListBearerRelCompComplete")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "ERABReleaseListBearerRelCompComplete")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *ERABReleaseListBearerRelCompComplete) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "ERABReleaseListBearerRelCompComplete")
}
func (v *ERABReleaseListBearerRelCompComplete) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "ERABReleaseListBearerRelCompComplete")
}
func (v *ERABReleaseListBearerRelCompComplete) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APERABReleaseListBearerRelCompComplete(v, &s)
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
func (v *ERABReleaseListBearerRelCompComplete) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *ERABReleaseListBearerRelCompComplete) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
	if err := s25.BridgeMarshalAPERERABReleaseListBearerRelCompTo(v.Value, bb, fresh); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.perPadding)
}

// MarshalAPER encodes a complete value using one per-call change plan.
func (v *ERABSetupListBearerSUResComplete) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "ERABSetupListBearerSUResComplete")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *ERABSetupListBearerSUResComplete) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "ERABSetupListBearerSUResComplete")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APERABSetupListBearerSUResComplete(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "ERABSetupListBearerSUResComplete")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "ERABSetupListBearerSUResComplete")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *ERABSetupListBearerSUResComplete) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "ERABSetupListBearerSUResComplete")
}
func (v *ERABSetupListBearerSUResComplete) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "ERABSetupListBearerSUResComplete")
}
func (v *ERABSetupListBearerSUResComplete) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APERABSetupListBearerSUResComplete(v, &s)
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
func (v *ERABSetupListBearerSUResComplete) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *ERABSetupListBearerSUResComplete) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
	if err := s25.BridgeMarshalAPERERABSetupListBearerSUResTo(v.Value, bb, fresh); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.perPadding)
}

// MarshalAPER encodes a complete value using one per-call change plan.
func (v *ERABSetupListCtxtSUResComplete) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "ERABSetupListCtxtSUResComplete")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *ERABSetupListCtxtSUResComplete) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "ERABSetupListCtxtSUResComplete")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APERABSetupListCtxtSUResComplete(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "ERABSetupListCtxtSUResComplete")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "ERABSetupListCtxtSUResComplete")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *ERABSetupListCtxtSUResComplete) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "ERABSetupListCtxtSUResComplete")
}
func (v *ERABSetupListCtxtSUResComplete) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "ERABSetupListCtxtSUResComplete")
}
func (v *ERABSetupListCtxtSUResComplete) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APERABSetupListCtxtSUResComplete(v, &s)
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
func (v *ERABSetupListCtxtSUResComplete) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *ERABSetupListCtxtSUResComplete) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
	if err := s25.BridgeMarshalAPERERABSetupListCtxtSUResTo(v.Value, bb, fresh); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.perPadding)
}

// MarshalAPER encodes a complete value using one per-call change plan.
func (v *HandoverRequestAcknowledge) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "HandoverRequestAcknowledge")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *HandoverRequestAcknowledge) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "HandoverRequestAcknowledge")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APHandoverRequestAcknowledge(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "HandoverRequestAcknowledge")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "HandoverRequestAcknowledge")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *HandoverRequestAcknowledge) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "HandoverRequestAcknowledge")
}
func (v *HandoverRequestAcknowledge) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "HandoverRequestAcknowledge")
}
func (v *HandoverRequestAcknowledge) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APHandoverRequestAcknowledge(v, &s)
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
func (v *HandoverRequestAcknowledge) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *HandoverRequestAcknowledge) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
func (v *ERABFailedtoSetupListHOReqAckComplete) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "ERABFailedtoSetupListHOReqAckComplete")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded ERABFailedtoSetupListHOReqAckComplete
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APERABFailedtoSetupListHOReqAckComplete(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = ERABFailedtoSetupListHOReqAckComplete{}
		return report, aper.OperationError(err, "ERABFailedtoSetupListHOReqAckComplete")
	}
	*v = decoded
	return report, aper.OperationError(nil, "ERABFailedtoSetupListHOReqAckComplete")
}

// UnmarshalAPER decodes one complete value and returns its report.
func (v *ERABModificationConfirm) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "ERABModificationConfirm")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded ERABModificationConfirm
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APERABModificationConfirm(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = ERABModificationConfirm{}
		return report, aper.OperationError(err, "ERABModificationConfirm")
	}
	*v = decoded
	return report, aper.OperationError(nil, "ERABModificationConfirm")
}

// UnmarshalAPER decodes one complete value and returns its report.
func (v *ERABModifyListBearerModConfComplete) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "ERABModifyListBearerModConfComplete")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded ERABModifyListBearerModConfComplete
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APERABModifyListBearerModConfComplete(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = ERABModifyListBearerModConfComplete{}
		return report, aper.OperationError(err, "ERABModifyListBearerModConfComplete")
	}
	*v = decoded
	return report, aper.OperationError(nil, "ERABModifyListBearerModConfComplete")
}

// UnmarshalAPER decodes one complete value and returns its report.
func (v *ERABModifyListBearerModResComplete) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "ERABModifyListBearerModResComplete")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded ERABModifyListBearerModResComplete
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APERABModifyListBearerModResComplete(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = ERABModifyListBearerModResComplete{}
		return report, aper.OperationError(err, "ERABModifyListBearerModResComplete")
	}
	*v = decoded
	return report, aper.OperationError(nil, "ERABModifyListBearerModResComplete")
}

// UnmarshalAPER decodes one complete value and returns its report.
func (v *ERABNotToBeModifiedListBearerModIndComplete) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "ERABNotToBeModifiedListBearerModIndComplete")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded ERABNotToBeModifiedListBearerModIndComplete
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APERABNotToBeModifiedListBearerModIndComplete(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = ERABNotToBeModifiedListBearerModIndComplete{}
		return report, aper.OperationError(err, "ERABNotToBeModifiedListBearerModIndComplete")
	}
	*v = decoded
	return report, aper.OperationError(nil, "ERABNotToBeModifiedListBearerModIndComplete")
}

// UnmarshalAPER decodes one complete value and returns its report.
func (v *ERABReleaseCommand) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "ERABReleaseCommand")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded ERABReleaseCommand
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APERABReleaseCommand(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = ERABReleaseCommand{}
		return report, aper.OperationError(err, "ERABReleaseCommand")
	}
	*v = decoded
	return report, aper.OperationError(nil, "ERABReleaseCommand")
}

// UnmarshalAPER decodes one complete value and returns its report.
func (v *ERABReleaseListBearerRelCompComplete) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "ERABReleaseListBearerRelCompComplete")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded ERABReleaseListBearerRelCompComplete
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APERABReleaseListBearerRelCompComplete(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = ERABReleaseListBearerRelCompComplete{}
		return report, aper.OperationError(err, "ERABReleaseListBearerRelCompComplete")
	}
	*v = decoded
	return report, aper.OperationError(nil, "ERABReleaseListBearerRelCompComplete")
}

// UnmarshalAPER decodes one complete value and returns its report.
func (v *ERABSetupListBearerSUResComplete) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "ERABSetupListBearerSUResComplete")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded ERABSetupListBearerSUResComplete
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APERABSetupListBearerSUResComplete(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = ERABSetupListBearerSUResComplete{}
		return report, aper.OperationError(err, "ERABSetupListBearerSUResComplete")
	}
	*v = decoded
	return report, aper.OperationError(nil, "ERABSetupListBearerSUResComplete")
}

// UnmarshalAPER decodes one complete value and returns its report.
func (v *ERABSetupListCtxtSUResComplete) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "ERABSetupListCtxtSUResComplete")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded ERABSetupListCtxtSUResComplete
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APERABSetupListCtxtSUResComplete(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = ERABSetupListCtxtSUResComplete{}
		return report, aper.OperationError(err, "ERABSetupListCtxtSUResComplete")
	}
	*v = decoded
	return report, aper.OperationError(nil, "ERABSetupListCtxtSUResComplete")
}

// UnmarshalAPER decodes one complete value and returns its report.
func (v *HandoverRequestAcknowledge) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "HandoverRequestAcknowledge")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded HandoverRequestAcknowledge
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APHandoverRequestAcknowledge(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = HandoverRequestAcknowledge{}
		return report, aper.OperationError(err, "HandoverRequestAcknowledge")
	}
	*v = decoded
	return report, aper.OperationError(nil, "HandoverRequestAcknowledge")
}

// MarshalAPERERABFailedtoSetupListHOReqAck encodes a complete named list.
func MarshalAPERERABFailedtoSetupListHOReqAck(v ERABFailedtoSetupListHOReqAckComplete, options ...aper.EncodeOption) ([]byte, error) {
	return v.MarshalAPER(options...)
}

// MarshalAPERERABSetupListBearerSURes encodes a complete named list.
func MarshalAPERERABSetupListBearerSURes(v ERABSetupListBearerSUResComplete, options ...aper.EncodeOption) ([]byte, error) {
	return v.MarshalAPER(options...)
}

// MarshalAPERERABModifyListBearerModRes encodes a complete named list.
func MarshalAPERERABModifyListBearerModRes(v ERABModifyListBearerModResComplete, options ...aper.EncodeOption) ([]byte, error) {
	return v.MarshalAPER(options...)
}

// MarshalAPERERABReleaseListBearerRelComp encodes a complete named list.
func MarshalAPERERABReleaseListBearerRelComp(v ERABReleaseListBearerRelCompComplete, options ...aper.EncodeOption) ([]byte, error) {
	return v.MarshalAPER(options...)
}

// MarshalAPERERABNotToBeModifiedListBearerModInd encodes a complete named list.
func MarshalAPERERABNotToBeModifiedListBearerModInd(v ERABNotToBeModifiedListBearerModIndComplete, options ...aper.EncodeOption) ([]byte, error) {
	return v.MarshalAPER(options...)
}

// MarshalAPERERABModifyListBearerModConf encodes a complete named list.
func MarshalAPERERABModifyListBearerModConf(v ERABModifyListBearerModConfComplete, options ...aper.EncodeOption) ([]byte, error) {
	return v.MarshalAPER(options...)
}

// UnmarshalAPERERABFailedtoSetupListHOReqAck decodes a complete named list.
func UnmarshalAPERERABFailedtoSetupListHOReqAck(data []byte, options ...aper.DecodeOption) (ERABFailedtoSetupListHOReqAckComplete, aper.DecodeReport, error) {
	var v ERABFailedtoSetupListHOReqAckComplete
	report, err := v.UnmarshalAPER(data, options...)
	return v, report, err
}

// UnmarshalAPERERABSetupListBearerSURes decodes a complete named list.
func UnmarshalAPERERABSetupListBearerSURes(data []byte, options ...aper.DecodeOption) (ERABSetupListBearerSUResComplete, aper.DecodeReport, error) {
	var v ERABSetupListBearerSUResComplete
	report, err := v.UnmarshalAPER(data, options...)
	return v, report, err
}

// UnmarshalAPERERABModifyListBearerModRes decodes a complete named list.
func UnmarshalAPERERABModifyListBearerModRes(data []byte, options ...aper.DecodeOption) (ERABModifyListBearerModResComplete, aper.DecodeReport, error) {
	var v ERABModifyListBearerModResComplete
	report, err := v.UnmarshalAPER(data, options...)
	return v, report, err
}

// UnmarshalAPERERABReleaseListBearerRelComp decodes a complete named list.
func UnmarshalAPERERABReleaseListBearerRelComp(data []byte, options ...aper.DecodeOption) (ERABReleaseListBearerRelCompComplete, aper.DecodeReport, error) {
	var v ERABReleaseListBearerRelCompComplete
	report, err := v.UnmarshalAPER(data, options...)
	return v, report, err
}

// UnmarshalAPERERABNotToBeModifiedListBearerModInd decodes a complete named list.
func UnmarshalAPERERABNotToBeModifiedListBearerModInd(data []byte, options ...aper.DecodeOption) (ERABNotToBeModifiedListBearerModIndComplete, aper.DecodeReport, error) {
	var v ERABNotToBeModifiedListBearerModIndComplete
	report, err := v.UnmarshalAPER(data, options...)
	return v, report, err
}

// UnmarshalAPERERABModifyListBearerModConf decodes a complete named list.
func UnmarshalAPERERABModifyListBearerModConf(data []byte, options ...aper.DecodeOption) (ERABModifyListBearerModConfComplete, aper.DecodeReport, error) {
	var v ERABModifyListBearerModConfComplete
	report, err := v.UnmarshalAPER(data, options...)
	return v, report, err
}

type TargeteNBToSourceeNBTransparentContainerExtIEsValue struct {
	id                                  s00.ProtocolIEID
	received                            aper.WireSpan
	replay                              aper.Snapshot
	opaque                              aper.OpaqueOpenType
	isOpaque                            bool
	rowDAPSResponseInfoList             *s14.DAPSResponseInfoList
	rowRACSIndication                   *s00.RACSIndication
	rowERABSecurityResultList           *s30.ERABSecurityResultList
	rowDirectForwardingPathAvailability *s00.DirectForwardingPathAvailability
}

func (v TargeteNBToSourceeNBTransparentContainerExtIEsValue) matchesID(id s00.ProtocolIEID, _ ...*aper.DecodeBudget) bool {
	if v.id != id {
		return false
	}
	if v.isOpaque {
		return true
	}
	switch id {
	case s00.ProtocolIEID(318):
		return v.rowDAPSResponseInfoList != nil
	case s00.ProtocolIEID(330):
		return v.rowRACSIndication != nil
	case s00.ProtocolIEID(335):
		return v.rowERABSecurityResultList != nil
	case s00.ProtocolIEID(79):
		return v.rowDirectForwardingPathAvailability != nil
	}
	return false
}

// Opaque returns the retained opaque open value of TargeteNBToSourceeNBTransparentContainerExtIEsValue and reports whether the opaque alternative is selected.
func (v *TargeteNBToSourceeNBTransparentContainerExtIEsValue) Opaque() (aper.OpaqueOpenType, bool) {
	if v == nil || !v.isOpaque {
		return aper.OpaqueOpenType{}, false
	}
	return v.opaque, true
}
func (TargeteNBToSourceeNBTransparentContainerExtIEsValue) rule() aper.SourceRule {
	return aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.4", Assignment: aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "TargeteNB-ToSourceeNB-TransparentContainer-ExtIEs"}}
}
func (TargeteNBToSourceeNBTransparentContainerExtIEsValue) reason(id s00.ProtocolIEID) aper.OpaqueReason {
	switch id {
	case s00.ProtocolIEID(318):
		return aper.UnknownSelector
	case s00.ProtocolIEID(330):
		return aper.UnknownSelector
	case s00.ProtocolIEID(335):
		return aper.UnknownSelector
	case s00.ProtocolIEID(79):
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
	case s00.ProtocolIEID(331):
		return aper.NotInTable
	case s00.ProtocolIEID(332):
		return aper.NotInTable
	case s00.ProtocolIEID(334):
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

// AsDAPSResponseInfoList returns the selected DAPSResponseInfoList value of TargeteNBToSourceeNBTransparentContainerExtIEsValue and reports whether that alternative is active.
func (v *TargeteNBToSourceeNBTransparentContainerExtIEsValue) AsDAPSResponseInfoList() (*s14.DAPSResponseInfoList, bool) {
	if v == nil || v.id != s00.ProtocolIEID(318) || v.rowDAPSResponseInfoList == nil {
		return nil, false
	}
	return v.rowDAPSResponseInfoList, true
}

// AsRACSIndication returns the selected RACSIndication value of TargeteNBToSourceeNBTransparentContainerExtIEsValue and reports whether that alternative is active.
func (v *TargeteNBToSourceeNBTransparentContainerExtIEsValue) AsRACSIndication() (*s00.RACSIndication, bool) {
	if v == nil || v.id != s00.ProtocolIEID(330) || v.rowRACSIndication == nil {
		return nil, false
	}
	return v.rowRACSIndication, true
}

// AsERABSecurityResultList returns the selected ERABSecurityResultList value of TargeteNBToSourceeNBTransparentContainerExtIEsValue and reports whether that alternative is active.
func (v *TargeteNBToSourceeNBTransparentContainerExtIEsValue) AsERABSecurityResultList() (*s30.ERABSecurityResultList, bool) {
	if v == nil || v.id != s00.ProtocolIEID(335) || v.rowERABSecurityResultList == nil {
		return nil, false
	}
	return v.rowERABSecurityResultList, true
}

// AsDirectForwardingPathAvailability returns the selected DirectForwardingPathAvailability value of TargeteNBToSourceeNBTransparentContainerExtIEsValue and reports whether that alternative is active.
func (v *TargeteNBToSourceeNBTransparentContainerExtIEsValue) AsDirectForwardingPathAvailability() (*s00.DirectForwardingPathAvailability, bool) {
	if v == nil || v.id != s00.ProtocolIEID(79) || v.rowDirectForwardingPathAvailability == nil {
		return nil, false
	}
	return v.rowDirectForwardingPathAvailability, true
}
func (v TargeteNBToSourceeNBTransparentContainerExtIEsValue) decode(id s00.ProtocolIEID, raw aper.OpaqueOpenType) (TargeteNBToSourceeNBTransparentContainerExtIEsValue, error) {
	out := TargeteNBToSourceeNBTransparentContainerExtIEsValue{id: id}
	switch id {
	case s00.ProtocolIEID(318):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		child := scope
		list, err := s38.BridgeUnmarshalAPERDAPSResponseInfoListFrom(child)
		if err != nil {
			return out, fmt.Errorf("%s %w", "DAPSResponseInfoList:", err)
		}
		padding, err := aper.CaptureOpenTypePadding(child)
		if err != nil {
			return out, err
		}
		_ = padding
		value := list
		out.rowDAPSResponseInfoList = &value
		raw.RetainContents(&out.received)
	case s00.ProtocolIEID(330):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		bb := scope
		decoded, err := aper.DecodeEnumeratedAligned(bb, 1, true, aper.EnumerationSource{KnownExtensions: 0, Path: "RACSIndication"})
		value := s00.RACSIndication(decoded)
		if err != nil {
			return out, fmt.Errorf("%s %w", "RACSIndication:", err)
		}
		if _, err := aper.CompleteOpenTypeValue(bb, value); err != nil {
			return out, err
		}
		out.rowRACSIndication = &value
		raw.RetainContents(&out.received)
	case s00.ProtocolIEID(335):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		child := scope
		list, err := BridgeUnmarshalAPERERABSecurityResultListFrom(child)
		if err != nil {
			return out, fmt.Errorf("%s %w", "ERABSecurityResultList:", err)
		}
		padding, err := aper.CaptureOpenTypePadding(child)
		if err != nil {
			return out, err
		}
		_ = padding
		value := list
		out.rowERABSecurityResultList = &value
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
	default:
		if err := raw.Observe(aper.UnknownIE); err != nil {
			return out, err
		}
		out.opaque = raw.Detached()
		out.isOpaque = true
	}
	return out, nil
}
func (v TargeteNBToSourceeNBTransparentContainerExtIEsValue) encode() ([]byte, error) {
	return v.encodeFresh(false, nil)
}
func (v TargeteNBToSourceeNBTransparentContainerExtIEsValue) encodeFresh(fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
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
	case s00.ProtocolIEID(318):
		if v.rowDAPSResponseInfoList == nil {
			return nil, fmt.Errorf("%s missing value", "TargeteNB-ToSourceeNB-TransparentContainer-ExtIEs.id-DAPSResponseInfoList:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		complete := s38.DAPSResponseInfoListComplete{Value: *v.rowDAPSResponseInfoList}
		candidate, err := s38.BridgeDAPSResponseInfoListCompleteMethodMarshalAPERBudget(&complete, budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	case s00.ProtocolIEID(330):
		if v.rowRACSIndication == nil {
			return nil, fmt.Errorf("%s missing value", "TargeteNB-ToSourceeNB-TransparentContainer-ExtIEs.id-RACSIndication:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		encodeBB := aper.NewBudgetBuffer(budget)
		if err := aper.EncodeEnumeratedAligned(encodeBB, int64(*v.rowRACSIndication), 1, true); err != nil {
			return nil, err
		}
		candidate := encodeBB.CompleteBytes()
		return candidate, nil
	case s00.ProtocolIEID(335):
		if v.rowERABSecurityResultList == nil {
			return nil, fmt.Errorf("%s missing value", "TargeteNB-ToSourceeNB-TransparentContainer-ExtIEs.id-E-RABSecurityResultList:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		complete := ERABSecurityResultListComplete{Value: *v.rowERABSecurityResultList}
		candidate, err := complete.marshalAPERBudget(budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	case s00.ProtocolIEID(79):
		if v.rowDirectForwardingPathAvailability == nil {
			return nil, fmt.Errorf("%s missing value", "TargeteNB-ToSourceeNB-TransparentContainer-ExtIEs.id-Direct-Forwarding-Path-Availability:")
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
	default:
		return nil, fmt.Errorf("%s id %d has no value", "TargeteNBToSourceeNBTransparentContainerExtIEsValue:", v.id)
	}
}

type ERABModificationConfirmIEValue struct {
	id                                     s00.ProtocolIEID
	received                               aper.WireSpan
	replay                                 aper.Snapshot
	opaque                                 aper.OpaqueOpenType
	isOpaque                               bool
	rowMMEUES1APID                         *s00.MMEUES1APID
	rowENBUES1APID                         *s00.ENBUES1APID
	rowERABModifyListBearerModConf         *s16.ERABModifyListBearerModConf
	rowERABFailedToModifyListBearerModConf *s16.ERABList
	rowERABToBeReleasedListBearerModConf   *s16.ERABList
	rowCriticalityDiagnostics              *s22.CriticalityDiagnostics
	rowCSGMembershipStatus                 *s00.CSGMembershipStatus
}

func (v ERABModificationConfirmIEValue) matchesID(id s00.ProtocolIEID, _ ...*aper.DecodeBudget) bool {
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
	case s00.ProtocolIEID(203):
		return v.rowERABModifyListBearerModConf != nil
	case s00.ProtocolIEID(205):
		return v.rowERABFailedToModifyListBearerModConf != nil
	case s00.ProtocolIEID(210):
		return v.rowERABToBeReleasedListBearerModConf != nil
	case s00.ProtocolIEID(58):
		return v.rowCriticalityDiagnostics != nil
	case s00.ProtocolIEID(146):
		return v.rowCSGMembershipStatus != nil
	}
	return false
}

// Opaque returns the retained opaque open value of ERABModificationConfirmIEValue and reports whether the opaque alternative is selected.
func (v *ERABModificationConfirmIEValue) Opaque() (aper.OpaqueOpenType, bool) {
	if v == nil || !v.isOpaque {
		return aper.OpaqueOpenType{}, false
	}
	return v.opaque, true
}
func (ERABModificationConfirmIEValue) rule() aper.SourceRule {
	return aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "E-RABModificationConfirmIEs"}}
}
func (ERABModificationConfirmIEValue) reason(id s00.ProtocolIEID) aper.OpaqueReason {
	switch id {
	case s00.ProtocolIEID(0):
		return aper.UnknownSelector
	case s00.ProtocolIEID(8):
		return aper.UnknownSelector
	case s00.ProtocolIEID(203):
		return aper.UnknownSelector
	case s00.ProtocolIEID(205):
		return aper.UnknownSelector
	case s00.ProtocolIEID(210):
		return aper.UnknownSelector
	case s00.ProtocolIEID(58):
		return aper.UnknownSelector
	case s00.ProtocolIEID(146):
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
	case s00.ProtocolIEID(204):
		return aper.NotInTable
	case s00.ProtocolIEID(206):
		return aper.NotInTable
	case s00.ProtocolIEID(207):
		return aper.NotInTable
	case s00.ProtocolIEID(208):
		return aper.NotInTable
	case s00.ProtocolIEID(209):
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

// AsMMEUES1APID returns the selected MMEUES1APID value of ERABModificationConfirmIEValue and reports whether that alternative is active.
func (v *ERABModificationConfirmIEValue) AsMMEUES1APID() (*s00.MMEUES1APID, bool) {
	if v == nil || v.id != s00.ProtocolIEID(0) || v.rowMMEUES1APID == nil {
		return nil, false
	}
	return v.rowMMEUES1APID, true
}

// AsENBUES1APID returns the selected ENBUES1APID value of ERABModificationConfirmIEValue and reports whether that alternative is active.
func (v *ERABModificationConfirmIEValue) AsENBUES1APID() (*s00.ENBUES1APID, bool) {
	if v == nil || v.id != s00.ProtocolIEID(8) || v.rowENBUES1APID == nil {
		return nil, false
	}
	return v.rowENBUES1APID, true
}

// AsERABModifyListBearerModConf returns the selected ERABModifyListBearerModConf value of ERABModificationConfirmIEValue and reports whether that alternative is active.
func (v *ERABModificationConfirmIEValue) AsERABModifyListBearerModConf() (*s16.ERABModifyListBearerModConf, bool) {
	if v == nil || v.id != s00.ProtocolIEID(203) || v.rowERABModifyListBearerModConf == nil {
		return nil, false
	}
	return v.rowERABModifyListBearerModConf, true
}

// AsERABFailedToModifyListBearerModConf returns the selected ERABFailedToModifyListBearerModConf value of ERABModificationConfirmIEValue and reports whether that alternative is active.
func (v *ERABModificationConfirmIEValue) AsERABFailedToModifyListBearerModConf() (*s16.ERABList, bool) {
	if v == nil || v.id != s00.ProtocolIEID(205) || v.rowERABFailedToModifyListBearerModConf == nil {
		return nil, false
	}
	return v.rowERABFailedToModifyListBearerModConf, true
}

// AsERABToBeReleasedListBearerModConf returns the selected ERABToBeReleasedListBearerModConf value of ERABModificationConfirmIEValue and reports whether that alternative is active.
func (v *ERABModificationConfirmIEValue) AsERABToBeReleasedListBearerModConf() (*s16.ERABList, bool) {
	if v == nil || v.id != s00.ProtocolIEID(210) || v.rowERABToBeReleasedListBearerModConf == nil {
		return nil, false
	}
	return v.rowERABToBeReleasedListBearerModConf, true
}

// AsCriticalityDiagnostics returns the selected CriticalityDiagnostics value of ERABModificationConfirmIEValue and reports whether that alternative is active.
func (v *ERABModificationConfirmIEValue) AsCriticalityDiagnostics() (*s22.CriticalityDiagnostics, bool) {
	if v == nil || v.id != s00.ProtocolIEID(58) || v.rowCriticalityDiagnostics == nil {
		return nil, false
	}
	return v.rowCriticalityDiagnostics, true
}

// AsCSGMembershipStatus returns the selected CSGMembershipStatus value of ERABModificationConfirmIEValue and reports whether that alternative is active.
func (v *ERABModificationConfirmIEValue) AsCSGMembershipStatus() (*s00.CSGMembershipStatus, bool) {
	if v == nil || v.id != s00.ProtocolIEID(146) || v.rowCSGMembershipStatus == nil {
		return nil, false
	}
	return v.rowCSGMembershipStatus, true
}
func (v ERABModificationConfirmIEValue) decode(id s00.ProtocolIEID, raw aper.OpaqueOpenType) (ERABModificationConfirmIEValue, error) {
	out := ERABModificationConfirmIEValue{id: id}
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
	case s00.ProtocolIEID(203):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		child := scope
		list, err := BridgeUnmarshalAPERERABModifyListBearerModConfFrom(child)
		if err != nil {
			return out, fmt.Errorf("%s %w", "ERABModifyListBearerModConf:", err)
		}
		padding, err := aper.CaptureOpenTypePadding(child)
		if err != nil {
			return out, err
		}
		_ = padding
		value := list
		out.rowERABModifyListBearerModConf = &value
		raw.RetainContents(&out.received)
	case s00.ProtocolIEID(205):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		child := scope
		list, err := BridgeUnmarshalAPERERABListFrom(child)
		if err != nil {
			return out, fmt.Errorf("%s %w", "ERABFailedToModifyListBearerModConf:", err)
		}
		padding, err := aper.CaptureOpenTypePadding(child)
		if err != nil {
			return out, err
		}
		_ = padding
		value := list
		out.rowERABFailedToModifyListBearerModConf = &value
		raw.RetainContents(&out.received)
	case s00.ProtocolIEID(210):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		child := scope
		list, err := BridgeUnmarshalAPERERABListFrom(child)
		if err != nil {
			return out, fmt.Errorf("%s %w", "ERABToBeReleasedListBearerModConf:", err)
		}
		padding, err := aper.CaptureOpenTypePadding(child)
		if err != nil {
			return out, err
		}
		_ = padding
		value := list
		out.rowERABToBeReleasedListBearerModConf = &value
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
	default:
		if err := raw.Observe(aper.UnknownIE); err != nil {
			return out, err
		}
		out.opaque = raw.Detached()
		out.isOpaque = true
	}
	return out, nil
}
func (v ERABModificationConfirmIEValue) encode() ([]byte, error) { return v.encodeFresh(false, nil) }
func (v ERABModificationConfirmIEValue) encodeFresh(fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
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
			return nil, fmt.Errorf("%s missing value", "E-RABModificationConfirmIEs.id-MME-UE-S1AP-ID:")
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
			return nil, fmt.Errorf("%s missing value", "E-RABModificationConfirmIEs.id-eNB-UE-S1AP-ID:")
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
	case s00.ProtocolIEID(203):
		if v.rowERABModifyListBearerModConf == nil {
			return nil, fmt.Errorf("%s missing value", "E-RABModificationConfirmIEs.id-E-RABModifyListBearerModConf:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		complete := ERABModifyListBearerModConfComplete{Value: *v.rowERABModifyListBearerModConf}
		candidate, err := complete.marshalAPERBudget(budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	case s00.ProtocolIEID(205):
		if v.rowERABFailedToModifyListBearerModConf == nil {
			return nil, fmt.Errorf("%s missing value", "E-RABModificationConfirmIEs.id-E-RABFailedToModifyListBearerModConf:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		complete := ERABListComplete{Value: *v.rowERABFailedToModifyListBearerModConf}
		candidate, err := complete.marshalAPERBudget(budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	case s00.ProtocolIEID(210):
		if v.rowERABToBeReleasedListBearerModConf == nil {
			return nil, fmt.Errorf("%s missing value", "E-RABModificationConfirmIEs.id-E-RABToBeReleasedListBearerModConf:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		complete := ERABListComplete{Value: *v.rowERABToBeReleasedListBearerModConf}
		candidate, err := complete.marshalAPERBudget(budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	case s00.ProtocolIEID(58):
		if v.rowCriticalityDiagnostics == nil {
			return nil, fmt.Errorf("%s missing value", "E-RABModificationConfirmIEs.id-CriticalityDiagnostics:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		candidate, err := s22.BridgeCriticalityDiagnosticsMethodMarshalAPERBudget(v.rowCriticalityDiagnostics, budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	case s00.ProtocolIEID(146):
		if v.rowCSGMembershipStatus == nil {
			return nil, fmt.Errorf("%s missing value", "E-RABModificationConfirmIEs.id-CSGMembershipStatus:")
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
	default:
		return nil, fmt.Errorf("%s id %d has no value", "ERABModificationConfirmIEValue:", v.id)
	}
}

type ERABReleaseCommandIEValue struct {
	id                           s00.ProtocolIEID
	received                     aper.WireSpan
	replay                       aper.Snapshot
	opaque                       aper.OpaqueOpenType
	isOpaque                     bool
	rowMMEUES1APID               *s00.MMEUES1APID
	rowENBUES1APID               *s00.ENBUES1APID
	rowUEaggregateMaximumBitrate *s35.UEAggregateMaximumBitrate
	rowERABToBeReleasedList      *s16.ERABList
	rowNASPDU                    *s00.NASPDU
}

func (v ERABReleaseCommandIEValue) matchesID(id s00.ProtocolIEID, _ ...*aper.DecodeBudget) bool {
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
	case s00.ProtocolIEID(66):
		return v.rowUEaggregateMaximumBitrate != nil
	case s00.ProtocolIEID(33):
		return v.rowERABToBeReleasedList != nil
	case s00.ProtocolIEID(26):
		return v.rowNASPDU != nil
	}
	return false
}

// Opaque returns the retained opaque open value of ERABReleaseCommandIEValue and reports whether the opaque alternative is selected.
func (v *ERABReleaseCommandIEValue) Opaque() (aper.OpaqueOpenType, bool) {
	if v == nil || !v.isOpaque {
		return aper.OpaqueOpenType{}, false
	}
	return v.opaque, true
}
func (ERABReleaseCommandIEValue) rule() aper.SourceRule {
	return aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "E-RABReleaseCommandIEs"}}
}
func (ERABReleaseCommandIEValue) reason(id s00.ProtocolIEID) aper.OpaqueReason {
	switch id {
	case s00.ProtocolIEID(0):
		return aper.UnknownSelector
	case s00.ProtocolIEID(8):
		return aper.UnknownSelector
	case s00.ProtocolIEID(66):
		return aper.UnknownSelector
	case s00.ProtocolIEID(33):
		return aper.UnknownSelector
	case s00.ProtocolIEID(26):
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

// AsMMEUES1APID returns the selected MMEUES1APID value of ERABReleaseCommandIEValue and reports whether that alternative is active.
func (v *ERABReleaseCommandIEValue) AsMMEUES1APID() (*s00.MMEUES1APID, bool) {
	if v == nil || v.id != s00.ProtocolIEID(0) || v.rowMMEUES1APID == nil {
		return nil, false
	}
	return v.rowMMEUES1APID, true
}

// AsENBUES1APID returns the selected ENBUES1APID value of ERABReleaseCommandIEValue and reports whether that alternative is active.
func (v *ERABReleaseCommandIEValue) AsENBUES1APID() (*s00.ENBUES1APID, bool) {
	if v == nil || v.id != s00.ProtocolIEID(8) || v.rowENBUES1APID == nil {
		return nil, false
	}
	return v.rowENBUES1APID, true
}

// AsUEaggregateMaximumBitrate returns the selected UEaggregateMaximumBitrate value of ERABReleaseCommandIEValue and reports whether that alternative is active.
func (v *ERABReleaseCommandIEValue) AsUEaggregateMaximumBitrate() (*s35.UEAggregateMaximumBitrate, bool) {
	if v == nil || v.id != s00.ProtocolIEID(66) || v.rowUEaggregateMaximumBitrate == nil {
		return nil, false
	}
	return v.rowUEaggregateMaximumBitrate, true
}

// AsERABToBeReleasedList returns the selected ERABToBeReleasedList value of ERABReleaseCommandIEValue and reports whether that alternative is active.
func (v *ERABReleaseCommandIEValue) AsERABToBeReleasedList() (*s16.ERABList, bool) {
	if v == nil || v.id != s00.ProtocolIEID(33) || v.rowERABToBeReleasedList == nil {
		return nil, false
	}
	return v.rowERABToBeReleasedList, true
}

// AsNASPDU returns the selected NASPDU value of ERABReleaseCommandIEValue and reports whether that alternative is active.
func (v *ERABReleaseCommandIEValue) AsNASPDU() (*s00.NASPDU, bool) {
	if v == nil || v.id != s00.ProtocolIEID(26) || v.rowNASPDU == nil {
		return nil, false
	}
	return v.rowNASPDU, true
}
func (v ERABReleaseCommandIEValue) decode(id s00.ProtocolIEID, raw aper.OpaqueOpenType) (ERABReleaseCommandIEValue, error) {
	out := ERABReleaseCommandIEValue{id: id}
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
	case s00.ProtocolIEID(66):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		var value s35.UEAggregateMaximumBitrate
		child := scope
		if err := s35.BridgeUEAggregateMaximumBitrateMethodUnmarshalAPERFrom(&value, child); err != nil {
			return out, fmt.Errorf("%s %w", "UEaggregateMaximumBitrate:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "UEAggregateMaximumBitrate")
		if err != nil {
			return out, err
		}
		*s35.BridgeUEAggregateMaximumBitrateFieldPerPadding(&value) = padding
		*s35.BridgeUEAggregateMaximumBitrateFieldReceived(&value) = true
		raw.RetainContents(s35.BridgeUEAggregateMaximumBitrateFieldReceivedBytes(&value))
		*s35.BridgeUEAggregateMaximumBitrateFieldReceivedLocation(&value) = raw.ContentLocation()
		out.rowUEaggregateMaximumBitrate = &value
		raw.RetainContents(&out.received)
	case s00.ProtocolIEID(33):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		child := scope
		list, err := BridgeUnmarshalAPERERABListFrom(child)
		if err != nil {
			return out, fmt.Errorf("%s %w", "ERABToBeReleasedList:", err)
		}
		padding, err := aper.CaptureOpenTypePadding(child)
		if err != nil {
			return out, err
		}
		_ = padding
		value := list
		out.rowERABToBeReleasedList = &value
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
	default:
		if err := raw.Observe(aper.UnknownIE); err != nil {
			return out, err
		}
		out.opaque = raw.Detached()
		out.isOpaque = true
	}
	return out, nil
}
func (v ERABReleaseCommandIEValue) encode() ([]byte, error) { return v.encodeFresh(false, nil) }
func (v ERABReleaseCommandIEValue) encodeFresh(fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
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
			return nil, fmt.Errorf("%s missing value", "E-RABReleaseCommandIEs.id-MME-UE-S1AP-ID:")
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
			return nil, fmt.Errorf("%s missing value", "E-RABReleaseCommandIEs.id-eNB-UE-S1AP-ID:")
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
	case s00.ProtocolIEID(66):
		if v.rowUEaggregateMaximumBitrate == nil {
			return nil, fmt.Errorf("%s missing value", "E-RABReleaseCommandIEs.id-uEaggregateMaximumBitrate:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		candidate, err := s35.BridgeUEAggregateMaximumBitrateMethodMarshalAPERBudget(v.rowUEaggregateMaximumBitrate, budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	case s00.ProtocolIEID(33):
		if v.rowERABToBeReleasedList == nil {
			return nil, fmt.Errorf("%s missing value", "E-RABReleaseCommandIEs.id-E-RABToBeReleasedList:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		complete := ERABListComplete{Value: *v.rowERABToBeReleasedList}
		candidate, err := complete.marshalAPERBudget(budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	case s00.ProtocolIEID(26):
		if v.rowNASPDU == nil {
			return nil, fmt.Errorf("%s missing value", "E-RABReleaseCommandIEs.id-NAS-PDU:")
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
	default:
		return nil, fmt.Errorf("%s id %d has no value", "ERABReleaseCommandIEValue:", v.id)
	}
}

type HandoverRequestAcknowledgeIEValue struct {
	id                                    s00.ProtocolIEID
	received                              aper.WireSpan
	replay                                aper.Snapshot
	opaque                                aper.OpaqueOpenType
	isOpaque                              bool
	rowMMEUES1APID                        *s00.MMEUES1APID
	rowENBUES1APID                        *s00.ENBUES1APID
	rowERABAdmittedList                   *s15.ERABAdmittedList
	rowERABFailedToSetupListHOReqAck      *s16.ERABFailedtoSetupListHOReqAck
	rowTargetToSourceTransparentContainer *s00.TargetToSourceTransparentContainer
	rowCSGId                              *s00.CSGId
	rowCriticalityDiagnostics             *s22.CriticalityDiagnostics
	rowCellAccessMode                     *s00.CellAccessMode
	rowCEModeBSupportIndicator            *s00.CEModeBSupportIndicator
}

func (v HandoverRequestAcknowledgeIEValue) matchesID(id s00.ProtocolIEID, _ ...*aper.DecodeBudget) bool {
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
	case s00.ProtocolIEID(18):
		return v.rowERABAdmittedList != nil
	case s00.ProtocolIEID(19):
		return v.rowERABFailedToSetupListHOReqAck != nil
	case s00.ProtocolIEID(123):
		return v.rowTargetToSourceTransparentContainer != nil
	case s00.ProtocolIEID(127):
		return v.rowCSGId != nil
	case s00.ProtocolIEID(58):
		return v.rowCriticalityDiagnostics != nil
	case s00.ProtocolIEID(145):
		return v.rowCellAccessMode != nil
	case s00.ProtocolIEID(242):
		return v.rowCEModeBSupportIndicator != nil
	}
	return false
}

// Opaque returns the retained opaque open value of HandoverRequestAcknowledgeIEValue and reports whether the opaque alternative is selected.
func (v *HandoverRequestAcknowledgeIEValue) Opaque() (aper.OpaqueOpenType, bool) {
	if v == nil || !v.isOpaque {
		return aper.OpaqueOpenType{}, false
	}
	return v.opaque, true
}
func (HandoverRequestAcknowledgeIEValue) rule() aper.SourceRule {
	return aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "HandoverRequestAcknowledgeIEs"}}
}
func (HandoverRequestAcknowledgeIEValue) reason(id s00.ProtocolIEID) aper.OpaqueReason {
	switch id {
	case s00.ProtocolIEID(0):
		return aper.UnknownSelector
	case s00.ProtocolIEID(8):
		return aper.UnknownSelector
	case s00.ProtocolIEID(18):
		return aper.UnknownSelector
	case s00.ProtocolIEID(19):
		return aper.UnknownSelector
	case s00.ProtocolIEID(123):
		return aper.UnknownSelector
	case s00.ProtocolIEID(127):
		return aper.UnknownSelector
	case s00.ProtocolIEID(58):
		return aper.UnknownSelector
	case s00.ProtocolIEID(145):
		return aper.UnknownSelector
	case s00.ProtocolIEID(242):
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

// AsMMEUES1APID returns the selected MMEUES1APID value of HandoverRequestAcknowledgeIEValue and reports whether that alternative is active.
func (v *HandoverRequestAcknowledgeIEValue) AsMMEUES1APID() (*s00.MMEUES1APID, bool) {
	if v == nil || v.id != s00.ProtocolIEID(0) || v.rowMMEUES1APID == nil {
		return nil, false
	}
	return v.rowMMEUES1APID, true
}

// AsENBUES1APID returns the selected ENBUES1APID value of HandoverRequestAcknowledgeIEValue and reports whether that alternative is active.
func (v *HandoverRequestAcknowledgeIEValue) AsENBUES1APID() (*s00.ENBUES1APID, bool) {
	if v == nil || v.id != s00.ProtocolIEID(8) || v.rowENBUES1APID == nil {
		return nil, false
	}
	return v.rowENBUES1APID, true
}

// AsERABAdmittedList returns the selected ERABAdmittedList value of HandoverRequestAcknowledgeIEValue and reports whether that alternative is active.
func (v *HandoverRequestAcknowledgeIEValue) AsERABAdmittedList() (*s15.ERABAdmittedList, bool) {
	if v == nil || v.id != s00.ProtocolIEID(18) || v.rowERABAdmittedList == nil {
		return nil, false
	}
	return v.rowERABAdmittedList, true
}

// AsERABFailedToSetupListHOReqAck returns the selected ERABFailedToSetupListHOReqAck value of HandoverRequestAcknowledgeIEValue and reports whether that alternative is active.
func (v *HandoverRequestAcknowledgeIEValue) AsERABFailedToSetupListHOReqAck() (*s16.ERABFailedtoSetupListHOReqAck, bool) {
	if v == nil || v.id != s00.ProtocolIEID(19) || v.rowERABFailedToSetupListHOReqAck == nil {
		return nil, false
	}
	return v.rowERABFailedToSetupListHOReqAck, true
}

// AsTargetToSourceTransparentContainer returns the selected TargetToSourceTransparentContainer value of HandoverRequestAcknowledgeIEValue and reports whether that alternative is active.
func (v *HandoverRequestAcknowledgeIEValue) AsTargetToSourceTransparentContainer() (*s00.TargetToSourceTransparentContainer, bool) {
	if v == nil || v.id != s00.ProtocolIEID(123) || v.rowTargetToSourceTransparentContainer == nil {
		return nil, false
	}
	return v.rowTargetToSourceTransparentContainer, true
}

// AsCSGId returns the selected CSGId value of HandoverRequestAcknowledgeIEValue and reports whether that alternative is active.
func (v *HandoverRequestAcknowledgeIEValue) AsCSGId() (*s00.CSGId, bool) {
	if v == nil || v.id != s00.ProtocolIEID(127) || v.rowCSGId == nil {
		return nil, false
	}
	return v.rowCSGId, true
}

// AsCriticalityDiagnostics returns the selected CriticalityDiagnostics value of HandoverRequestAcknowledgeIEValue and reports whether that alternative is active.
func (v *HandoverRequestAcknowledgeIEValue) AsCriticalityDiagnostics() (*s22.CriticalityDiagnostics, bool) {
	if v == nil || v.id != s00.ProtocolIEID(58) || v.rowCriticalityDiagnostics == nil {
		return nil, false
	}
	return v.rowCriticalityDiagnostics, true
}

// AsCellAccessMode returns the selected CellAccessMode value of HandoverRequestAcknowledgeIEValue and reports whether that alternative is active.
func (v *HandoverRequestAcknowledgeIEValue) AsCellAccessMode() (*s00.CellAccessMode, bool) {
	if v == nil || v.id != s00.ProtocolIEID(145) || v.rowCellAccessMode == nil {
		return nil, false
	}
	return v.rowCellAccessMode, true
}

// AsCEModeBSupportIndicator returns the selected CEModeBSupportIndicator value of HandoverRequestAcknowledgeIEValue and reports whether that alternative is active.
func (v *HandoverRequestAcknowledgeIEValue) AsCEModeBSupportIndicator() (*s00.CEModeBSupportIndicator, bool) {
	if v == nil || v.id != s00.ProtocolIEID(242) || v.rowCEModeBSupportIndicator == nil {
		return nil, false
	}
	return v.rowCEModeBSupportIndicator, true
}
func (v HandoverRequestAcknowledgeIEValue) decode(id s00.ProtocolIEID, raw aper.OpaqueOpenType) (HandoverRequestAcknowledgeIEValue, error) {
	out := HandoverRequestAcknowledgeIEValue{id: id}
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
	case s00.ProtocolIEID(18):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		child := scope
		list, err := s38.BridgeUnmarshalAPERERABAdmittedListFrom(child)
		if err != nil {
			return out, fmt.Errorf("%s %w", "ERABAdmittedList:", err)
		}
		padding, err := aper.CaptureOpenTypePadding(child)
		if err != nil {
			return out, err
		}
		_ = padding
		value := list
		out.rowERABAdmittedList = &value
		raw.RetainContents(&out.received)
	case s00.ProtocolIEID(19):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		child := scope
		list, err := BridgeUnmarshalAPERERABFailedtoSetupListHOReqAckFrom(child)
		if err != nil {
			return out, fmt.Errorf("%s %w", "ERABFailedToSetupListHOReqAck:", err)
		}
		padding, err := aper.CaptureOpenTypePadding(child)
		if err != nil {
			return out, err
		}
		_ = padding
		value := list
		out.rowERABFailedToSetupListHOReqAck = &value
		raw.RetainContents(&out.received)
	case s00.ProtocolIEID(123):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		child := scope
		value, err := (func(bb *aper.BitBuffer) (s00.TargetToSourceTransparentContainer, error) {
			var v struct {
				Value s00.TargetToSourceTransparentContainer
			}
			err := func() error {
				val_value, err := aper.DecodeOctetStringAligned(bb, 0, 0, false)
				if err != nil {
					return runtime.WrapDecodePath(err, "Value")
				}
				v.Value = s00.TargetToSourceTransparentContainer(val_value)
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
		out.rowTargetToSourceTransparentContainer = &value
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
	default:
		if err := raw.Observe(aper.UnknownIE); err != nil {
			return out, err
		}
		out.opaque = raw.Detached()
		out.isOpaque = true
	}
	return out, nil
}
func (v HandoverRequestAcknowledgeIEValue) encode() ([]byte, error) {
	return v.encodeFresh(false, nil)
}
func (v HandoverRequestAcknowledgeIEValue) encodeFresh(fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
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
			return nil, fmt.Errorf("%s missing value", "HandoverRequestAcknowledgeIEs.id-MME-UE-S1AP-ID:")
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
			return nil, fmt.Errorf("%s missing value", "HandoverRequestAcknowledgeIEs.id-eNB-UE-S1AP-ID:")
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
	case s00.ProtocolIEID(18):
		if v.rowERABAdmittedList == nil {
			return nil, fmt.Errorf("%s missing value", "HandoverRequestAcknowledgeIEs.id-E-RABAdmittedList:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		complete := s38.ERABAdmittedListComplete{Value: *v.rowERABAdmittedList}
		candidate, err := s38.BridgeERABAdmittedListCompleteMethodMarshalAPERBudget(&complete, budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	case s00.ProtocolIEID(19):
		if v.rowERABFailedToSetupListHOReqAck == nil {
			return nil, fmt.Errorf("%s missing value", "HandoverRequestAcknowledgeIEs.id-E-RABFailedToSetupListHOReqAck:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		complete := ERABFailedtoSetupListHOReqAckComplete{Value: *v.rowERABFailedToSetupListHOReqAck}
		candidate, err := complete.marshalAPERBudget(budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	case s00.ProtocolIEID(123):
		if v.rowTargetToSourceTransparentContainer == nil {
			return nil, fmt.Errorf("%s missing value", "HandoverRequestAcknowledgeIEs.id-Target-ToSource-TransparentContainer:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		candidate, err := (func(value s00.TargetToSourceTransparentContainer, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			v := struct {
				Value s00.TargetToSourceTransparentContainer
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
		})(*v.rowTargetToSourceTransparentContainer, budget)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	case s00.ProtocolIEID(127):
		if v.rowCSGId == nil {
			return nil, fmt.Errorf("%s missing value", "HandoverRequestAcknowledgeIEs.id-CSG-Id:")
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
	case s00.ProtocolIEID(58):
		if v.rowCriticalityDiagnostics == nil {
			return nil, fmt.Errorf("%s missing value", "HandoverRequestAcknowledgeIEs.id-CriticalityDiagnostics:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		candidate, err := s22.BridgeCriticalityDiagnosticsMethodMarshalAPERBudget(v.rowCriticalityDiagnostics, budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	case s00.ProtocolIEID(145):
		if v.rowCellAccessMode == nil {
			return nil, fmt.Errorf("%s missing value", "HandoverRequestAcknowledgeIEs.id-CellAccessMode:")
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
	case s00.ProtocolIEID(242):
		if v.rowCEModeBSupportIndicator == nil {
			return nil, fmt.Errorf("%s missing value", "HandoverRequestAcknowledgeIEs.id-CE-mode-B-SupportIndicator:")
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
	default:
		return nil, fmt.Errorf("%s id %d has no value", "HandoverRequestAcknowledgeIEValue:", v.id)
	}
}

type InitialContextSetupResponseIEValue struct {
	id                                s00.ProtocolIEID
	received                          aper.WireSpan
	replay                            aper.Snapshot
	opaque                            aper.OpaqueOpenType
	isOpaque                          bool
	rowMMEUES1APID                    *s00.MMEUES1APID
	rowENBUES1APID                    *s00.ENBUES1APID
	rowERABSetupListCtxtSURes         *s17.ERABSetupListCtxtSURes
	rowERABFailedToSetupListCtxtSURes *s16.ERABList
	rowCriticalityDiagnostics         *s22.CriticalityDiagnostics
}

func (v InitialContextSetupResponseIEValue) matchesID(id s00.ProtocolIEID, _ ...*aper.DecodeBudget) bool {
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
	case s00.ProtocolIEID(51):
		return v.rowERABSetupListCtxtSURes != nil
	case s00.ProtocolIEID(48):
		return v.rowERABFailedToSetupListCtxtSURes != nil
	case s00.ProtocolIEID(58):
		return v.rowCriticalityDiagnostics != nil
	}
	return false
}

// Opaque returns the retained opaque open value of InitialContextSetupResponseIEValue and reports whether the opaque alternative is selected.
func (v *InitialContextSetupResponseIEValue) Opaque() (aper.OpaqueOpenType, bool) {
	if v == nil || !v.isOpaque {
		return aper.OpaqueOpenType{}, false
	}
	return v.opaque, true
}
func (InitialContextSetupResponseIEValue) rule() aper.SourceRule {
	return aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "InitialContextSetupResponseIEs"}}
}
func (InitialContextSetupResponseIEValue) reason(id s00.ProtocolIEID) aper.OpaqueReason {
	switch id {
	case s00.ProtocolIEID(0):
		return aper.UnknownSelector
	case s00.ProtocolIEID(8):
		return aper.UnknownSelector
	case s00.ProtocolIEID(51):
		return aper.UnknownSelector
	case s00.ProtocolIEID(48):
		return aper.UnknownSelector
	case s00.ProtocolIEID(58):
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
	case s00.ProtocolIEID(50):
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

// AsMMEUES1APID returns the selected MMEUES1APID value of InitialContextSetupResponseIEValue and reports whether that alternative is active.
func (v *InitialContextSetupResponseIEValue) AsMMEUES1APID() (*s00.MMEUES1APID, bool) {
	if v == nil || v.id != s00.ProtocolIEID(0) || v.rowMMEUES1APID == nil {
		return nil, false
	}
	return v.rowMMEUES1APID, true
}

// AsENBUES1APID returns the selected ENBUES1APID value of InitialContextSetupResponseIEValue and reports whether that alternative is active.
func (v *InitialContextSetupResponseIEValue) AsENBUES1APID() (*s00.ENBUES1APID, bool) {
	if v == nil || v.id != s00.ProtocolIEID(8) || v.rowENBUES1APID == nil {
		return nil, false
	}
	return v.rowENBUES1APID, true
}

// AsERABSetupListCtxtSURes returns the selected ERABSetupListCtxtSURes value of InitialContextSetupResponseIEValue and reports whether that alternative is active.
func (v *InitialContextSetupResponseIEValue) AsERABSetupListCtxtSURes() (*s17.ERABSetupListCtxtSURes, bool) {
	if v == nil || v.id != s00.ProtocolIEID(51) || v.rowERABSetupListCtxtSURes == nil {
		return nil, false
	}
	return v.rowERABSetupListCtxtSURes, true
}

// AsERABFailedToSetupListCtxtSURes returns the selected ERABFailedToSetupListCtxtSURes value of InitialContextSetupResponseIEValue and reports whether that alternative is active.
func (v *InitialContextSetupResponseIEValue) AsERABFailedToSetupListCtxtSURes() (*s16.ERABList, bool) {
	if v == nil || v.id != s00.ProtocolIEID(48) || v.rowERABFailedToSetupListCtxtSURes == nil {
		return nil, false
	}
	return v.rowERABFailedToSetupListCtxtSURes, true
}

// AsCriticalityDiagnostics returns the selected CriticalityDiagnostics value of InitialContextSetupResponseIEValue and reports whether that alternative is active.
func (v *InitialContextSetupResponseIEValue) AsCriticalityDiagnostics() (*s22.CriticalityDiagnostics, bool) {
	if v == nil || v.id != s00.ProtocolIEID(58) || v.rowCriticalityDiagnostics == nil {
		return nil, false
	}
	return v.rowCriticalityDiagnostics, true
}
func (v InitialContextSetupResponseIEValue) decode(id s00.ProtocolIEID, raw aper.OpaqueOpenType) (InitialContextSetupResponseIEValue, error) {
	out := InitialContextSetupResponseIEValue{id: id}
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
	case s00.ProtocolIEID(51):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		child := scope
		list, err := BridgeUnmarshalAPERERABSetupListCtxtSUResFrom(child)
		if err != nil {
			return out, fmt.Errorf("%s %w", "ERABSetupListCtxtSURes:", err)
		}
		padding, err := aper.CaptureOpenTypePadding(child)
		if err != nil {
			return out, err
		}
		_ = padding
		value := list
		out.rowERABSetupListCtxtSURes = &value
		raw.RetainContents(&out.received)
	case s00.ProtocolIEID(48):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		child := scope
		list, err := BridgeUnmarshalAPERERABListFrom(child)
		if err != nil {
			return out, fmt.Errorf("%s %w", "ERABFailedToSetupListCtxtSURes:", err)
		}
		padding, err := aper.CaptureOpenTypePadding(child)
		if err != nil {
			return out, err
		}
		_ = padding
		value := list
		out.rowERABFailedToSetupListCtxtSURes = &value
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
func (v InitialContextSetupResponseIEValue) encode() ([]byte, error) {
	return v.encodeFresh(false, nil)
}
func (v InitialContextSetupResponseIEValue) encodeFresh(fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
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
			return nil, fmt.Errorf("%s missing value", "InitialContextSetupResponseIEs.id-MME-UE-S1AP-ID:")
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
			return nil, fmt.Errorf("%s missing value", "InitialContextSetupResponseIEs.id-eNB-UE-S1AP-ID:")
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
	case s00.ProtocolIEID(51):
		if v.rowERABSetupListCtxtSURes == nil {
			return nil, fmt.Errorf("%s missing value", "InitialContextSetupResponseIEs.id-E-RABSetupListCtxtSURes:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		complete := ERABSetupListCtxtSUResComplete{Value: *v.rowERABSetupListCtxtSURes}
		candidate, err := complete.marshalAPERBudget(budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	case s00.ProtocolIEID(48):
		if v.rowERABFailedToSetupListCtxtSURes == nil {
			return nil, fmt.Errorf("%s missing value", "InitialContextSetupResponseIEs.id-E-RABFailedToSetupListCtxtSURes:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		complete := ERABListComplete{Value: *v.rowERABFailedToSetupListCtxtSURes}
		candidate, err := complete.marshalAPERBudget(budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	case s00.ProtocolIEID(58):
		if v.rowCriticalityDiagnostics == nil {
			return nil, fmt.Errorf("%s missing value", "InitialContextSetupResponseIEs.id-CriticalityDiagnostics:")
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
		return nil, fmt.Errorf("%s id %d has no value", "InitialContextSetupResponseIEValue:", v.id)
	}
}

type TargeteNBToSourceeNBTransparentContainerExtIETable struct{}

func TargeteNBToSourceeNBTransparentContainerExtIEs() TargeteNBToSourceeNBTransparentContainerExtIETable {
	return TargeteNBToSourceeNBTransparentContainerExtIETable{}
}

// ID returns the ASN.1 object-set identity of TargeteNBToSourceeNBTransparentContainerExtIETable.
func (TargeteNBToSourceeNBTransparentContainerExtIETable) ID() s00.TableID {
	return func() s00.TableID {
		sealed := s00.TableID{}
		*s00.BridgeTableIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "TargeteNB-ToSourceeNB-TransparentContainer-ExtIEs"}
		return sealed
	}()
}

// Table returns the ASN.1 object-set table described by TargeteNBToSourceeNBTransparentContainerExtIETable.
func (TargeteNBToSourceeNBTransparentContainerExtIETable) Table() s00.TargeteNBToSourceeNBTransparentContainerExtIEsValueExtensionTable {
	return func() s00.TargeteNBToSourceeNBTransparentContainerExtIEsValueExtensionTable {
		sealed := s00.TargeteNBToSourceeNBTransparentContainerExtIEsValueExtensionTable{}
		*s00.BridgeTargeteNBToSourceeNBTransparentContainerExtIEsValueExtensionTableFieldBound(&sealed) = true
		return sealed
	}()
}
func (TargeteNBToSourceeNBTransparentContainerExtIETable) infoDAPSResponseInfoList() s00.ExtensionInfo {
	return s00.ExtensionInfo{Table: TargeteNBToSourceeNBTransparentContainerExtIEs().ID(), ID: s00.ProtocolExtensionID(318), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "DAPSResponseInfoList"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.4", Assignment: aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "TargeteNB-ToSourceeNB-TransparentContainer-ExtIEs", Row: "id-DAPSResponseInfoList"}}}
}

// DAPSResponseInfoList returns the typed binding for the DAPSResponseInfoList row of TargeteNBToSourceeNBTransparentContainerExtIETable.
func (t TargeteNBToSourceeNBTransparentContainerExtIETable) DAPSResponseInfoList() TargeteNBToSourceeNBTransparentContainerExtIEsDAPSResponseInfoListExtBinding {
	return TargeteNBToSourceeNBTransparentContainerExtIEsDAPSResponseInfoListExtBinding{info: t.infoDAPSResponseInfoList(), codec: func() s14.DAPSResponseInfoListValueCodec {
		sealed := s14.DAPSResponseInfoListValueCodec{}
		*s14.BridgeDAPSResponseInfoListValueCodecFieldPath(&sealed) = "DAPSResponseInfoList"
		*s14.BridgeDAPSResponseInfoListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s14.DAPSResponseInfoList, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s14.DAPSResponseInfoList
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("DAPSResponseInfoList")
			var zero TargeteNBToSourceeNBTransparentContainerExtIEsValue
			decoded, err := zero.decode(s00.ProtocolIEID(318), raw)
			if err != nil {
				var empty s14.DAPSResponseInfoList
				return empty, runtime.WrapDecodePath(err, "DAPSResponseInfoList")
			}
			value, ok := decoded.AsDAPSResponseInfoList()
			if !ok {
				var empty s14.DAPSResponseInfoList
				return empty, fmt.Errorf("binding TargeteNB-ToSourceeNB-TransparentContainer-ExtIEs.id-DAPSResponseInfoList: no selected value")
			}
			return *value, nil
		}
		*s14.BridgeDAPSResponseInfoListValueCodecFieldEncode(&sealed) = func(value s14.DAPSResponseInfoList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (TargeteNBToSourceeNBTransparentContainerExtIEsValue{id: s00.ProtocolIEID(318), rowDAPSResponseInfoList: &value}).encodeFresh(fresh, budget)
		}
		*s14.BridgeDAPSResponseInfoListValueCodecFieldCapture(&sealed) = func(v s14.DAPSResponseInfoList, options aper.DecodeState) (s14.DAPSResponseInfoList, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s24.BridgeCaptureS1APDAPSResponseInfoList(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s14.BridgeDAPSResponseInfoListValueCodecFieldCompare(&sealed) = func(v s14.DAPSResponseInfoList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s24.BridgeCompareS1APDAPSResponseInfoList(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s14.BridgeDAPSResponseInfoListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:DAPSResponseInfoList"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s14.DAPSResponseInfoList) TargeteNBToSourceeNBTransparentContainerExtIEsValue {
			return TargeteNBToSourceeNBTransparentContainerExtIEsValue{id: s00.ProtocolIEID(318), rowDAPSResponseInfoList: &value}
		}, get: func(value *TargeteNBToSourceeNBTransparentContainerExtIEsValue) (*s14.DAPSResponseInfoList, bool) {
			return value.AsDAPSResponseInfoList()
		}}
}
func (TargeteNBToSourceeNBTransparentContainerExtIETable) infoRACSIndication() s00.ExtensionInfo {
	return s00.ExtensionInfo{Table: TargeteNBToSourceeNBTransparentContainerExtIEs().ID(), ID: s00.ProtocolExtensionID(330), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "RACSIndication"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.4", Assignment: aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "TargeteNB-ToSourceeNB-TransparentContainer-ExtIEs", Row: "id-RACSIndication"}}}
}

// RACSIndication returns the typed binding for the RACSIndication row of TargeteNBToSourceeNBTransparentContainerExtIETable.
func (t TargeteNBToSourceeNBTransparentContainerExtIETable) RACSIndication() TargeteNBToSourceeNBTransparentContainerExtIEsRACSIndicationExtBinding {
	return TargeteNBToSourceeNBTransparentContainerExtIEsRACSIndicationExtBinding{info: t.infoRACSIndication(), codec: func() s01.RACSIndicationValueCodec {
		sealed := s01.RACSIndicationValueCodec{}
		*s01.BridgeRACSIndicationValueCodecFieldPath(&sealed) = "RACSIndication"
		*s01.BridgeRACSIndicationValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.RACSIndication, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s00.RACSIndication
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("RACSIndication")
			var zero TargeteNBToSourceeNBTransparentContainerExtIEsValue
			decoded, err := zero.decode(s00.ProtocolIEID(330), raw)
			if err != nil {
				var empty s00.RACSIndication
				return empty, runtime.WrapDecodePath(err, "RACSIndication")
			}
			value, ok := decoded.AsRACSIndication()
			if !ok {
				var empty s00.RACSIndication
				return empty, fmt.Errorf("binding TargeteNB-ToSourceeNB-TransparentContainer-ExtIEs.id-RACSIndication: no selected value")
			}
			return *value, nil
		}
		*s01.BridgeRACSIndicationValueCodecFieldEncode(&sealed) = func(value s00.RACSIndication, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (TargeteNBToSourceeNBTransparentContainerExtIEsValue{id: s00.ProtocolIEID(330), rowRACSIndication: &value}).encodeFresh(fresh, budget)
		}
		*s01.BridgeRACSIndicationValueCodecFieldCapture(&sealed) = func(v s00.RACSIndication, options aper.DecodeState) (s00.RACSIndication, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s00.BridgeCaptureS1APRACSIndication(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s01.BridgeRACSIndicationValueCodecFieldCompare(&sealed) = func(v s00.RACSIndication, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s06.BridgeCompareS1APRACSIndication(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s01.BridgeRACSIndicationValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:RACSIndication"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s00.RACSIndication) TargeteNBToSourceeNBTransparentContainerExtIEsValue {
			return TargeteNBToSourceeNBTransparentContainerExtIEsValue{id: s00.ProtocolIEID(330), rowRACSIndication: &value}
		}, get: func(value *TargeteNBToSourceeNBTransparentContainerExtIEsValue) (*s00.RACSIndication, bool) {
			return value.AsRACSIndication()
		}}
}
func (TargeteNBToSourceeNBTransparentContainerExtIETable) infoERABSecurityResultList() s00.ExtensionInfo {
	return s00.ExtensionInfo{Table: TargeteNBToSourceeNBTransparentContainerExtIEs().ID(), ID: s00.ProtocolExtensionID(335), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "E-RABSecurityResultList"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.4", Assignment: aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "TargeteNB-ToSourceeNB-TransparentContainer-ExtIEs", Row: "id-E-RABSecurityResultList"}}}
}

// ERABSecurityResultList returns the typed binding for the ERABSecurityResultList row of TargeteNBToSourceeNBTransparentContainerExtIETable.
func (t TargeteNBToSourceeNBTransparentContainerExtIETable) ERABSecurityResultList() TargeteNBToSourceeNBTransparentContainerExtIEsERABSecurityResultListExtBinding {
	return TargeteNBToSourceeNBTransparentContainerExtIEsERABSecurityResultListExtBinding{info: t.infoERABSecurityResultList(), codec: func() s30.ERABSecurityResultListValueCodec {
		sealed := s30.ERABSecurityResultListValueCodec{}
		*s30.BridgeERABSecurityResultListValueCodecFieldPath(&sealed) = "ERABSecurityResultList"
		*s30.BridgeERABSecurityResultListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s30.ERABSecurityResultList, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s30.ERABSecurityResultList
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("ERABSecurityResultList")
			var zero TargeteNBToSourceeNBTransparentContainerExtIEsValue
			decoded, err := zero.decode(s00.ProtocolIEID(335), raw)
			if err != nil {
				var empty s30.ERABSecurityResultList
				return empty, runtime.WrapDecodePath(err, "ERABSecurityResultList")
			}
			value, ok := decoded.AsERABSecurityResultList()
			if !ok {
				var empty s30.ERABSecurityResultList
				return empty, fmt.Errorf("binding TargeteNB-ToSourceeNB-TransparentContainer-ExtIEs.id-E-RABSecurityResultList: no selected value")
			}
			return *value, nil
		}
		*s30.BridgeERABSecurityResultListValueCodecFieldEncode(&sealed) = func(value s30.ERABSecurityResultList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (TargeteNBToSourceeNBTransparentContainerExtIEsValue{id: s00.ProtocolIEID(335), rowERABSecurityResultList: &value}).encodeFresh(fresh, budget)
		}
		*s30.BridgeERABSecurityResultListValueCodecFieldCapture(&sealed) = func(v s30.ERABSecurityResultList, options aper.DecodeState) (s30.ERABSecurityResultList, aper.Snapshot,

		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s30.BridgeCaptureS1APERABSecurityResultList(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s30.BridgeERABSecurityResultListValueCodecFieldCompare(&sealed) = func(v s30.ERABSecurityResultList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s30.BridgeCompareS1APERABSecurityResultList(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s30.BridgeERABSecurityResultListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ERABSecurityResultList"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s30.ERABSecurityResultList) TargeteNBToSourceeNBTransparentContainerExtIEsValue {
			return TargeteNBToSourceeNBTransparentContainerExtIEsValue{id: s00.ProtocolIEID(335), rowERABSecurityResultList: &value}
		}, get: func(value *TargeteNBToSourceeNBTransparentContainerExtIEsValue) (*s30.ERABSecurityResultList, bool) {
			return value.AsERABSecurityResultList()
		}}
}
func (TargeteNBToSourceeNBTransparentContainerExtIETable) infoDirectForwardingPathAvailability() s00.ExtensionInfo {
	return s00.ExtensionInfo{Table: TargeteNBToSourceeNBTransparentContainerExtIEs().ID(), ID: s00.ProtocolExtensionID(79), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "Direct-Forwarding-Path-Availability"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.4", Assignment: aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "TargeteNB-ToSourceeNB-TransparentContainer-ExtIEs", Row: "id-Direct-Forwarding-Path-Availability"}}}
}

// DirectForwardingPathAvailability returns the typed binding for the DirectForwardingPathAvailability row of TargeteNBToSourceeNBTransparentContainerExtIETable.
func (t TargeteNBToSourceeNBTransparentContainerExtIETable) DirectForwardingPathAvailability() TargeteNBToSourceeNBTransparentContainerExtIEsDirectForwardingPathAvailabilityExtBinding {
	return TargeteNBToSourceeNBTransparentContainerExtIEsDirectForwardingPathAvailabilityExtBinding{info: t.infoDirectForwardingPathAvailability(), codec: func() s00.DirectForwardingPathAvailabilityValueCodec {
		sealed := s00.DirectForwardingPathAvailabilityValueCodec{}
		*s00.BridgeDirectForwardingPathAvailabilityValueCodecFieldPath(&sealed) = "DirectForwardingPathAvailability"
		*s00.BridgeDirectForwardingPathAvailabilityValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.DirectForwardingPathAvailability, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s00.DirectForwardingPathAvailability
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("DirectForwardingPathAvailability")
			var zero TargeteNBToSourceeNBTransparentContainerExtIEsValue
			decoded, err := zero.decode(s00.ProtocolIEID(79), raw)
			if err != nil {
				var empty s00.DirectForwardingPathAvailability
				return empty, runtime.WrapDecodePath(err, "DirectForwardingPathAvailability")
			}
			value, ok := decoded.AsDirectForwardingPathAvailability()
			if !ok {
				var empty s00.DirectForwardingPathAvailability
				return empty, fmt.Errorf("binding TargeteNB-ToSourceeNB-TransparentContainer-ExtIEs.id-Direct-Forwarding-Path-Availability: no selected value")
			}
			return *value, nil
		}
		*s00.BridgeDirectForwardingPathAvailabilityValueCodecFieldEncode(&sealed) = func(value s00.DirectForwardingPathAvailability, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (TargeteNBToSourceeNBTransparentContainerExtIEsValue{id: s00.ProtocolIEID(79), rowDirectForwardingPathAvailability: &value}).encodeFresh(fresh, budget)
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
		inject: func(value s00.DirectForwardingPathAvailability) TargeteNBToSourceeNBTransparentContainerExtIEsValue {
			return TargeteNBToSourceeNBTransparentContainerExtIEsValue{id: s00.ProtocolIEID(79), rowDirectForwardingPathAvailability: &value}
		}, get: func(value *TargeteNBToSourceeNBTransparentContainerExtIEsValue) (*s00.DirectForwardingPathAvailability, bool) {
			return value.AsDirectForwardingPathAvailability()
		}}
}

// NewOpaque constructs an owned opaque field for an identifier without a typed row in TargeteNBToSourceeNBTransparentContainerExtIETable.
func (t TargeteNBToSourceeNBTransparentContainerExtIETable) NewOpaque(id s00.ProtocolExtensionID, criticality s00.Criticality, data []byte) (TargeteNBToSourceeNBTransparentContainerExtIEsExtField, error) {
	if id < 0 || id > 65535 || criticality < 0 || criticality > 2 {
		return TargeteNBToSourceeNBTransparentContainerExtIEsExtField{}, aper.OperationError(fmt.Errorf("invalid opaque extension selector or criticality"), "Opaque")
	}
	switch id {
	case s00.ProtocolIEID(318):
		return TargeteNBToSourceeNBTransparentContainerExtIEsExtField{}, aper.OperationError(fmt.Errorf("known extension id-DAPSResponseInfoList requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(330):
		return TargeteNBToSourceeNBTransparentContainerExtIEsExtField{}, aper.OperationError(fmt.Errorf("known extension id-RACSIndication requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(335):
		return TargeteNBToSourceeNBTransparentContainerExtIEsExtField{}, aper.OperationError(fmt.Errorf("known extension id-E-RABSecurityResultList requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(79):
		return TargeteNBToSourceeNBTransparentContainerExtIEsExtField{}, aper.OperationError(fmt.Errorf("known extension id-Direct-Forwarding-Path-Availability requires its typed binding"), "Opaque")
	default:
		budget, err := aper.BuildBudget()
		if err != nil {
			return TargeteNBToSourceeNBTransparentContainerExtIEsExtField{}, aper.OperationError(err, "Opaque")
		}
		opaque, err := aper.BuildOpaqueOpenType(data, budget)
		if err != nil {
			return TargeteNBToSourceeNBTransparentContainerExtIEsExtField{}, aper.OperationError(err, "Opaque")
		}
		return TargeteNBToSourceeNBTransparentContainerExtIEsExtField{Id: id, Criticality: criticality, ExtensionValue: TargeteNBToSourceeNBTransparentContainerExtIEsValue{id: id, opaque: opaque, isOpaque: true}}, aper.OperationError(nil, "Opaque")
	}
}

type ERABModificationConfirmIETable struct{}

func ERABModificationConfirmIEs() ERABModificationConfirmIETable {
	return ERABModificationConfirmIETable{}
}

// ID returns the ASN.1 object-set identity of ERABModificationConfirmIETable.
func (ERABModificationConfirmIETable) ID() s00.TableID {
	return func() s00.TableID {
		sealed := s00.TableID{}
		*s00.BridgeTableIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "E-RABModificationConfirmIEs"}
		return sealed
	}()
}

// Table returns the ASN.1 object-set table described by ERABModificationConfirmIETable.
func (ERABModificationConfirmIETable) Table() s00.ERABModificationConfirmIEValueIETable {
	return func() s00.ERABModificationConfirmIEValueIETable {
		sealed := s00.ERABModificationConfirmIEValueIETable{}
		*s00.BridgeERABModificationConfirmIEValueIETableFieldBound(&sealed) = true
		return sealed
	}()
}
func (ERABModificationConfirmIETable) infoMMEUES1APID() s00.FieldInfo {
	return s00.FieldInfo{Table: ERABModificationConfirmIEs().ID(), ID: s00.ProtocolIEID(0), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceMandatory, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "MME-UE-S1AP-ID"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "E-RABModificationConfirmIEs", Row: "id-MME-UE-S1AP-ID"}}}
}

// MMEUES1APID returns the typed binding for the MMEUES1APID row of ERABModificationConfirmIETable.
func (t ERABModificationConfirmIETable) MMEUES1APID() ERABModificationConfirmMMEUES1APIDIEBinding {
	return ERABModificationConfirmMMEUES1APIDIEBinding{info: t.infoMMEUES1APID(), codec: func() s01.MMEUES1APIDValueCodec {
		sealed := s01.MMEUES1APIDValueCodec{}
		*s01.BridgeMMEUES1APIDValueCodecFieldPath(&sealed) = "MMEUES1APID"
		*s01.BridgeMMEUES1APIDValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.MMEUES1APID, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s00.MMEUES1APID
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("MMEUES1APID")
			var zero ERABModificationConfirmIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(0), raw)
			if err != nil {
				var empty s00.MMEUES1APID
				return empty, runtime.WrapDecodePath(err, "MMEUES1APID")
			}
			value, ok := decoded.AsMMEUES1APID()
			if !ok {
				var empty s00.MMEUES1APID
				return empty, fmt.Errorf("binding E-RABModificationConfirmIEs.id-MME-UE-S1AP-ID: no selected value")
			}
			return *value, nil
		}
		*s01.BridgeMMEUES1APIDValueCodecFieldEncode(&sealed) = func(value s00.MMEUES1APID, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (ERABModificationConfirmIEValue{id: s00.ProtocolIEID(0), rowMMEUES1APID: &value}).encodeFresh(fresh, budget)
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
		inject: func(value s00.MMEUES1APID) ERABModificationConfirmIEValue {
			return ERABModificationConfirmIEValue{id: s00.ProtocolIEID(0), rowMMEUES1APID: &value}
		}, get: func(value *ERABModificationConfirmIEValue) (*s00.MMEUES1APID, bool) { return value.AsMMEUES1APID() }}
}
func (ERABModificationConfirmIETable) infoENBUES1APID() s00.FieldInfo {
	return s00.FieldInfo{Table: ERABModificationConfirmIEs().ID(), ID: s00.ProtocolIEID(8), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceMandatory, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "ENB-UE-S1AP-ID"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "E-RABModificationConfirmIEs", Row: "id-eNB-UE-S1AP-ID"}}}
}

// ENBUES1APID returns the typed binding for the ENBUES1APID row of ERABModificationConfirmIETable.
func (t ERABModificationConfirmIETable) ENBUES1APID() ERABModificationConfirmENBUES1APIDIEBinding {
	return ERABModificationConfirmENBUES1APIDIEBinding{info: t.infoENBUES1APID(), codec: func() s00.ENBUES1APIDValueCodec {
		sealed := s00.ENBUES1APIDValueCodec{}
		*s00.BridgeENBUES1APIDValueCodecFieldPath(&sealed) = "ENBUES1APID"
		*s00.BridgeENBUES1APIDValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.ENBUES1APID, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s00.ENBUES1APID
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("ENBUES1APID")
			var zero ERABModificationConfirmIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(8), raw)
			if err != nil {
				var empty s00.ENBUES1APID
				return empty, runtime.WrapDecodePath(err, "ENBUES1APID")
			}
			value, ok := decoded.AsENBUES1APID()
			if !ok {
				var empty s00.ENBUES1APID
				return empty, fmt.Errorf("binding E-RABModificationConfirmIEs.id-eNB-UE-S1AP-ID: no selected value")
			}
			return *value, nil
		}
		*s00.BridgeENBUES1APIDValueCodecFieldEncode(&sealed) = func(value s00.ENBUES1APID, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (ERABModificationConfirmIEValue{id: s00.ProtocolIEID(8), rowENBUES1APID: &value}).encodeFresh(fresh, budget)
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
		inject: func(value s00.ENBUES1APID) ERABModificationConfirmIEValue {
			return ERABModificationConfirmIEValue{id: s00.ProtocolIEID(8), rowENBUES1APID: &value}
		}, get: func(value *ERABModificationConfirmIEValue) (*s00.ENBUES1APID, bool) { return value.AsENBUES1APID() }}
}
func (ERABModificationConfirmIETable) infoERABModifyListBearerModConf() s00.FieldInfo {
	return s00.FieldInfo{Table: ERABModificationConfirmIEs().ID(), ID: s00.ProtocolIEID(203), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "E-RABModifyListBearerModConf"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "E-RABModificationConfirmIEs", Row: "id-E-RABModifyListBearerModConf"}}}
}

// ERABModifyListBearerModConf returns the typed binding for the ERABModifyListBearerModConf row of ERABModificationConfirmIETable.
func (t ERABModificationConfirmIETable) ERABModifyListBearerModConf() ERABModificationConfirmERABModifyListBearerModConfIEBinding {
	return ERABModificationConfirmERABModifyListBearerModConfIEBinding{info: t.infoERABModifyListBearerModConf(), codec: func() s16.ERABModifyListBearerModConfValueCodec {
		sealed := s16.ERABModifyListBearerModConfValueCodec{}
		*s16.BridgeERABModifyListBearerModConfValueCodecFieldPath(&sealed) = "ERABModifyListBearerModConf"
		*s16.BridgeERABModifyListBearerModConfValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s16.ERABModifyListBearerModConf, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s16.ERABModifyListBearerModConf
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("ERABModifyListBearerModConf")
			var zero ERABModificationConfirmIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(203), raw)
			if err != nil {
				var empty s16.ERABModifyListBearerModConf
				return empty, runtime.WrapDecodePath(err, "ERABModifyListBearerModConf")
			}
			value, ok := decoded.AsERABModifyListBearerModConf()
			if !ok {
				var empty s16.ERABModifyListBearerModConf
				return empty, fmt.Errorf("binding E-RABModificationConfirmIEs.id-E-RABModifyListBearerModConf: no selected value")
			}
			return *value, nil
		}
		*s16.BridgeERABModifyListBearerModConfValueCodecFieldEncode(&sealed) = func(value s16.ERABModifyListBearerModConf, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (ERABModificationConfirmIEValue{id: s00.ProtocolIEID(203), rowERABModifyListBearerModConf: &value}).encodeFresh(fresh, budget)
		}
		*s16.BridgeERABModifyListBearerModConfValueCodecFieldCapture(&sealed) = func(v s16.ERABModifyListBearerModConf, options aper.DecodeState) (s16.ERABModifyListBearerModConf, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s24.BridgeCaptureS1APERABModifyListBearerModConf(&v, &s)
			var root aper.Snapshot
			s.
				End(f, &root, false)
			return v, root
		}
		*s16.BridgeERABModifyListBearerModConfValueCodecFieldCompare(&sealed) = func(v s16.ERABModifyListBearerModConf, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.
				Begin()
			s24.BridgeCompareS1APERABModifyListBearerModConf(&v, &s)
			s.End(f,

				root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s16.BridgeERABModifyListBearerModConfValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ERABModifyListBearerModConf"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s16.ERABModifyListBearerModConf) ERABModificationConfirmIEValue {
			return ERABModificationConfirmIEValue{id: s00.ProtocolIEID(203), rowERABModifyListBearerModConf: &value}
		}, get: func(value *ERABModificationConfirmIEValue) (*s16.ERABModifyListBearerModConf, bool) {
			return value.AsERABModifyListBearerModConf()
		}}
}
func (ERABModificationConfirmIETable) infoERABFailedToModifyListBearerModConf() s00.FieldInfo {
	return s00.FieldInfo{Table: ERABModificationConfirmIEs().ID(), ID: s00.ProtocolIEID(205), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "E-RABList"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "E-RABModificationConfirmIEs", Row: "id-E-RABFailedToModifyListBearerModConf"}}}
}

// ERABFailedToModifyListBearerModConf returns the typed binding for the ERABFailedToModifyListBearerModConf row of ERABModificationConfirmIETable.
func (t ERABModificationConfirmIETable) ERABFailedToModifyListBearerModConf() ERABModificationConfirmERABListIEBinding {
	return ERABModificationConfirmERABListIEBinding{info: t.infoERABFailedToModifyListBearerModConf(), codec: func() s16.ERABListValueCodec {
		sealed := s16.ERABListValueCodec{}
		*s16.BridgeERABListValueCodecFieldPath(&sealed) = "ERABList"
		*s16.BridgeERABListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s16.ERABList, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s16.ERABList
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("ERABList")
			var zero ERABModificationConfirmIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(205), raw)
			if err != nil {
				var empty s16.ERABList
				return empty, runtime.WrapDecodePath(err, "ERABList")
			}
			value, ok := decoded.AsERABFailedToModifyListBearerModConf()
			if !ok {
				var empty s16.ERABList
				return empty, fmt.Errorf("binding E-RABModificationConfirmIEs.id-E-RABFailedToModifyListBearerModConf: no selected value")
			}
			return *value, nil
		}
		*s16.BridgeERABListValueCodecFieldEncode(&sealed) = func(value s16.ERABList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (ERABModificationConfirmIEValue{id: s00.ProtocolIEID(205), rowERABFailedToModifyListBearerModConf: &value}).encodeFresh(fresh, budget)
		}
		*s16.BridgeERABListValueCodecFieldCapture(&sealed) = func(v s16.ERABList, options aper.DecodeState) (s16.ERABList, aper.Snapshot) {
			s := aper.SemanticCaptureFor(
				options)
			f := s.Begin()
			s24.BridgeCaptureS1APERABList(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s16.BridgeERABListValueCodecFieldCompare(&sealed) = func(v s16.ERABList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s24.BridgeCompareS1APERABList(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s16.BridgeERABListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ERABList"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s16.ERABList) ERABModificationConfirmIEValue {
			return ERABModificationConfirmIEValue{id: s00.ProtocolIEID(205), rowERABFailedToModifyListBearerModConf: &value}
		}, get: func(value *ERABModificationConfirmIEValue) (*s16.ERABList, bool) {
			return value.AsERABFailedToModifyListBearerModConf()
		}}
}
func (ERABModificationConfirmIETable) infoERABToBeReleasedListBearerModConf() s00.FieldInfo {
	return s00.FieldInfo{Table: ERABModificationConfirmIEs().ID(), ID: s00.ProtocolIEID(210), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "E-RABList"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "E-RABModificationConfirmIEs", Row: "id-E-RABToBeReleasedListBearerModConf"}}}
}

// ERABToBeReleasedListBearerModConf returns the typed binding for the ERABToBeReleasedListBearerModConf row of ERABModificationConfirmIETable.
func (t ERABModificationConfirmIETable) ERABToBeReleasedListBearerModConf() ERABModificationConfirmERABListIEBinding {
	return ERABModificationConfirmERABListIEBinding{info: t.infoERABToBeReleasedListBearerModConf(), codec: func() s16.ERABListValueCodec {
		sealed := s16.ERABListValueCodec{}
		*s16.BridgeERABListValueCodecFieldPath(&sealed) = "ERABList"
		*s16.BridgeERABListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s16.ERABList, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s16.ERABList
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("ERABList")
			var zero ERABModificationConfirmIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(210), raw)
			if err != nil {
				var empty s16.ERABList
				return empty, runtime.WrapDecodePath(err, "ERABList")
			}
			value, ok := decoded.AsERABToBeReleasedListBearerModConf()
			if !ok {
				var empty s16.ERABList
				return empty, fmt.Errorf("binding E-RABModificationConfirmIEs.id-E-RABToBeReleasedListBearerModConf: no selected value")
			}
			return *value, nil
		}
		*s16.BridgeERABListValueCodecFieldEncode(&sealed) = func(value s16.ERABList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (ERABModificationConfirmIEValue{id: s00.ProtocolIEID(210), rowERABToBeReleasedListBearerModConf: &value}).encodeFresh(fresh, budget)
		}
		*s16.BridgeERABListValueCodecFieldCapture(&sealed) = func(v s16.ERABList, options aper.DecodeState) (s16.ERABList, aper.Snapshot) {
			s := aper.SemanticCaptureFor(
				options)
			f := s.Begin()
			s24.BridgeCaptureS1APERABList(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s16.BridgeERABListValueCodecFieldCompare(&sealed) = func(v s16.ERABList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s24.BridgeCompareS1APERABList(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s16.BridgeERABListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ERABList"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s16.ERABList) ERABModificationConfirmIEValue {
			return ERABModificationConfirmIEValue{id: s00.ProtocolIEID(210), rowERABToBeReleasedListBearerModConf: &value}
		}, get: func(value *ERABModificationConfirmIEValue) (*s16.ERABList, bool) {
			return value.AsERABToBeReleasedListBearerModConf()
		}}
}
func (ERABModificationConfirmIETable) infoCriticalityDiagnostics() s00.FieldInfo {
	return s00.FieldInfo{Table: ERABModificationConfirmIEs().ID(), ID: s00.ProtocolIEID(58), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "CriticalityDiagnostics"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "E-RABModificationConfirmIEs", Row: "id-CriticalityDiagnostics"}}}
}

// CriticalityDiagnostics returns the typed binding for the CriticalityDiagnostics row of ERABModificationConfirmIETable.
func (t ERABModificationConfirmIETable) CriticalityDiagnostics() ERABModificationConfirmCriticalityDiagnosticsIEBinding {
	return ERABModificationConfirmCriticalityDiagnosticsIEBinding{info: t.infoCriticalityDiagnostics(), codec: func() s22.CriticalityDiagnosticsValueCodec {
		sealed := s22.CriticalityDiagnosticsValueCodec{}
		*s22.BridgeCriticalityDiagnosticsValueCodecFieldPath(&sealed) = "CriticalityDiagnostics"
		*s22.BridgeCriticalityDiagnosticsValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s22.CriticalityDiagnostics, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s22.CriticalityDiagnostics
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("CriticalityDiagnostics")
			var zero ERABModificationConfirmIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(58), raw)
			if err != nil {
				var empty s22.CriticalityDiagnostics
				return empty, runtime.WrapDecodePath(err, "CriticalityDiagnostics")
			}
			value, ok := decoded.AsCriticalityDiagnostics()
			if !ok {
				var empty s22.CriticalityDiagnostics
				return empty, fmt.Errorf("binding E-RABModificationConfirmIEs.id-CriticalityDiagnostics: no selected value")
			}
			return *value, nil
		}
		*s22.BridgeCriticalityDiagnosticsValueCodecFieldEncode(&sealed) = func(value s22.CriticalityDiagnostics, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (ERABModificationConfirmIEValue{id: s00.ProtocolIEID(58), rowCriticalityDiagnostics: &value}).encodeFresh(fresh, budget)
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
		inject: func(value s22.CriticalityDiagnostics) ERABModificationConfirmIEValue {
			return ERABModificationConfirmIEValue{id: s00.ProtocolIEID(58), rowCriticalityDiagnostics: &value}
		}, get: func(value *ERABModificationConfirmIEValue) (*s22.CriticalityDiagnostics, bool) {
			return value.AsCriticalityDiagnostics()
		}}
}
func (ERABModificationConfirmIETable) infoCSGMembershipStatus() s00.FieldInfo {
	return s00.FieldInfo{Table: ERABModificationConfirmIEs().ID(), ID: s00.ProtocolIEID(146), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "CSGMembershipStatus"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "E-RABModificationConfirmIEs", Row: "id-CSGMembershipStatus"}}}
}

// CSGMembershipStatus returns the typed binding for the CSGMembershipStatus row of ERABModificationConfirmIETable.
func (t ERABModificationConfirmIETable) CSGMembershipStatus() ERABModificationConfirmCSGMembershipStatusIEBinding {
	return ERABModificationConfirmCSGMembershipStatusIEBinding{info: t.infoCSGMembershipStatus(), codec: func() s00.CSGMembershipStatusValueCodec {
		sealed := s00.CSGMembershipStatusValueCodec{}
		*s00.BridgeCSGMembershipStatusValueCodecFieldPath(&sealed) = "CSGMembershipStatus"
		*s00.BridgeCSGMembershipStatusValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.CSGMembershipStatus, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s00.CSGMembershipStatus
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("CSGMembershipStatus")
			var zero ERABModificationConfirmIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(146), raw)
			if err != nil {
				var empty s00.CSGMembershipStatus
				return empty, runtime.WrapDecodePath(err, "CSGMembershipStatus")
			}
			value, ok := decoded.AsCSGMembershipStatus()
			if !ok {
				var empty s00.CSGMembershipStatus
				return empty, fmt.Errorf("binding E-RABModificationConfirmIEs.id-CSGMembershipStatus: no selected value")
			}
			return *value, nil
		}
		*s00.BridgeCSGMembershipStatusValueCodecFieldEncode(&sealed) = func(value s00.CSGMembershipStatus, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (ERABModificationConfirmIEValue{id: s00.ProtocolIEID(146), rowCSGMembershipStatus: &value}).encodeFresh(fresh, budget)
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
		inject: func(value s00.CSGMembershipStatus) ERABModificationConfirmIEValue {
			return ERABModificationConfirmIEValue{id: s00.ProtocolIEID(146), rowCSGMembershipStatus: &value}
		}, get: func(value *ERABModificationConfirmIEValue) (*s00.CSGMembershipStatus, bool) {
			return value.AsCSGMembershipStatus()
		}}
}

// NewOpaque constructs an owned opaque field for an identifier without a typed row in ERABModificationConfirmIETable.
func (t ERABModificationConfirmIETable) NewOpaque(id s00.ProtocolIEID, criticality s00.Criticality, data []byte) (ERABModificationConfirmIEField, error) {
	if id < 0 || id > 65535 || criticality < 0 || criticality > 2 {
		return ERABModificationConfirmIEField{}, aper.OperationError(fmt.Errorf("invalid opaque IE selector or criticality"), "Opaque")
	}
	switch id {
	case s00.ProtocolIEID(0):
		return ERABModificationConfirmIEField{}, aper.OperationError(fmt.Errorf("known IE id-MME-UE-S1AP-ID requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(8):
		return ERABModificationConfirmIEField{}, aper.OperationError(fmt.Errorf("known IE id-eNB-UE-S1AP-ID requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(203):
		return ERABModificationConfirmIEField{}, aper.OperationError(fmt.Errorf("known IE id-E-RABModifyListBearerModConf requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(205):
		return ERABModificationConfirmIEField{}, aper.OperationError(fmt.Errorf("known IE id-E-RABFailedToModifyListBearerModConf requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(210):
		return ERABModificationConfirmIEField{}, aper.OperationError(fmt.Errorf("known IE id-E-RABToBeReleasedListBearerModConf requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(58):
		return ERABModificationConfirmIEField{}, aper.OperationError(fmt.Errorf("known IE id-CriticalityDiagnostics requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(146):
		return ERABModificationConfirmIEField{}, aper.OperationError(fmt.Errorf("known IE id-CSGMembershipStatus requires its typed binding"), "Opaque")
	default:
		budget, err := aper.BuildBudget()
		if err != nil {
			return ERABModificationConfirmIEField{}, aper.OperationError(err, "Opaque")
		}
		opaque, err := aper.BuildOpaqueOpenType(data, budget)
		if err != nil {
			return ERABModificationConfirmIEField{}, aper.OperationError(err, "Opaque")
		}
		return ERABModificationConfirmIEField{Id: id, Criticality: criticality, Value: ERABModificationConfirmIEValue{id: id, opaque: opaque, isOpaque: true}}, aper.OperationError(nil, "Opaque")
	}
}

type ERABReleaseCommandIETable struct{}

func ERABReleaseCommandIEs() ERABReleaseCommandIETable { return ERABReleaseCommandIETable{} }

// ID returns the ASN.1 object-set identity of ERABReleaseCommandIETable.
func (ERABReleaseCommandIETable) ID() s00.TableID {
	return func() s00.TableID {
		sealed := s00.TableID{}
		*s00.BridgeTableIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "E-RABReleaseCommandIEs"}
		return sealed
	}()
}

// Table returns the ASN.1 object-set table described by ERABReleaseCommandIETable.
func (ERABReleaseCommandIETable) Table() s00.ERABReleaseCommandIEValueIETable {
	return func() s00.ERABReleaseCommandIEValueIETable {
		sealed := s00.ERABReleaseCommandIEValueIETable{}
		*s00.BridgeERABReleaseCommandIEValueIETableFieldBound(&sealed) = true
		return sealed
	}()
}
func (ERABReleaseCommandIETable) infoMMEUES1APID() s00.FieldInfo {
	return s00.FieldInfo{Table: ERABReleaseCommandIEs().ID(), ID: s00.ProtocolIEID(0), Criticality: s00.CriticalityReject, Presence: s00.PresenceMandatory, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "MME-UE-S1AP-ID"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "E-RABReleaseCommandIEs", Row: "id-MME-UE-S1AP-ID"}}}
}

// MMEUES1APID returns the typed binding for the MMEUES1APID row of ERABReleaseCommandIETable.
func (t ERABReleaseCommandIETable) MMEUES1APID() ERABReleaseCommandMMEUES1APIDIEBinding {
	return ERABReleaseCommandMMEUES1APIDIEBinding{info: t.infoMMEUES1APID(), codec: func() s01.MMEUES1APIDValueCodec {
		sealed := s01.MMEUES1APIDValueCodec{}
		*s01.BridgeMMEUES1APIDValueCodecFieldPath(&sealed) = "MMEUES1APID"
		*s01.BridgeMMEUES1APIDValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.MMEUES1APID, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s00.MMEUES1APID
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("MMEUES1APID")
			var zero ERABReleaseCommandIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(0), raw)
			if err != nil {
				var empty s00.MMEUES1APID
				return empty, runtime.WrapDecodePath(err, "MMEUES1APID")
			}
			value, ok := decoded.AsMMEUES1APID()
			if !ok {
				var empty s00.MMEUES1APID
				return empty, fmt.Errorf("binding E-RABReleaseCommandIEs.id-MME-UE-S1AP-ID: no selected value")
			}
			return *value, nil
		}
		*s01.BridgeMMEUES1APIDValueCodecFieldEncode(&sealed) = func(value s00.MMEUES1APID, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (ERABReleaseCommandIEValue{id: s00.ProtocolIEID(0), rowMMEUES1APID: &value}).encodeFresh(fresh, budget)
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
		inject: func(value s00.MMEUES1APID) ERABReleaseCommandIEValue {
			return ERABReleaseCommandIEValue{id: s00.ProtocolIEID(0), rowMMEUES1APID: &value}
		}, get: func(value *ERABReleaseCommandIEValue) (*s00.MMEUES1APID, bool) { return value.AsMMEUES1APID() }}
}
func (ERABReleaseCommandIETable) infoENBUES1APID() s00.FieldInfo {
	return s00.FieldInfo{Table: ERABReleaseCommandIEs().ID(), ID: s00.ProtocolIEID(8), Criticality: s00.CriticalityReject, Presence: s00.PresenceMandatory, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "ENB-UE-S1AP-ID"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "E-RABReleaseCommandIEs", Row: "id-eNB-UE-S1AP-ID"}}}
}

// ENBUES1APID returns the typed binding for the ENBUES1APID row of ERABReleaseCommandIETable.
func (t ERABReleaseCommandIETable) ENBUES1APID() ERABReleaseCommandENBUES1APIDIEBinding {
	return ERABReleaseCommandENBUES1APIDIEBinding{info: t.infoENBUES1APID(), codec: func() s00.ENBUES1APIDValueCodec {
		sealed := s00.ENBUES1APIDValueCodec{}
		*s00.BridgeENBUES1APIDValueCodecFieldPath(&sealed) = "ENBUES1APID"
		*s00.BridgeENBUES1APIDValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.ENBUES1APID, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s00.ENBUES1APID
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("ENBUES1APID")
			var zero ERABReleaseCommandIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(8), raw)
			if err != nil {
				var empty s00.ENBUES1APID
				return empty, runtime.WrapDecodePath(err, "ENBUES1APID")
			}
			value, ok := decoded.AsENBUES1APID()
			if !ok {
				var empty s00.ENBUES1APID
				return empty, fmt.Errorf("binding E-RABReleaseCommandIEs.id-eNB-UE-S1AP-ID: no selected value")
			}
			return *value, nil
		}
		*s00.BridgeENBUES1APIDValueCodecFieldEncode(&sealed) = func(value s00.ENBUES1APID, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (ERABReleaseCommandIEValue{id: s00.ProtocolIEID(8), rowENBUES1APID: &value}).encodeFresh(fresh, budget)
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
		inject: func(value s00.ENBUES1APID) ERABReleaseCommandIEValue {
			return ERABReleaseCommandIEValue{id: s00.ProtocolIEID(8), rowENBUES1APID: &value}
		}, get: func(value *ERABReleaseCommandIEValue) (*s00.ENBUES1APID, bool) { return value.AsENBUES1APID() }}
}
func (ERABReleaseCommandIETable) infoUEaggregateMaximumBitrate() s00.FieldInfo {
	return s00.FieldInfo{Table: ERABReleaseCommandIEs().ID(), ID: s00.ProtocolIEID(66), Criticality: s00.CriticalityReject, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "UEAggregateMaximumBitrate"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "E-RABReleaseCommandIEs", Row: "id-uEaggregateMaximumBitrate"}}}
}

// UEaggregateMaximumBitrate returns the typed binding for the UEaggregateMaximumBitrate row of ERABReleaseCommandIETable.
func (t ERABReleaseCommandIETable) UEaggregateMaximumBitrate() ERABReleaseCommandUEAggregateMaximumBitrateIEBinding {
	return ERABReleaseCommandUEAggregateMaximumBitrateIEBinding{info: t.infoUEaggregateMaximumBitrate(), codec: func() s35.UEAggregateMaximumBitrateValueCodec {
		sealed := s35.UEAggregateMaximumBitrateValueCodec{}
		*s35.BridgeUEAggregateMaximumBitrateValueCodecFieldPath(&sealed) = "UEAggregateMaximumBitrate"
		*s35.BridgeUEAggregateMaximumBitrateValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s35.UEAggregateMaximumBitrate, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s35.UEAggregateMaximumBitrate
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("UEAggregateMaximumBitrate")
			var zero ERABReleaseCommandIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(66), raw)
			if err != nil {
				var empty s35.UEAggregateMaximumBitrate
				return empty, runtime.WrapDecodePath(err, "UEAggregateMaximumBitrate")
			}
			value, ok := decoded.AsUEaggregateMaximumBitrate()
			if !ok {
				var empty s35.UEAggregateMaximumBitrate
				return empty, fmt.Errorf("binding E-RABReleaseCommandIEs.id-uEaggregateMaximumBitrate: no selected value")
			}
			return *value, nil
		}
		*s35.BridgeUEAggregateMaximumBitrateValueCodecFieldEncode(&sealed) = func(value s35.UEAggregateMaximumBitrate, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (ERABReleaseCommandIEValue{id: s00.ProtocolIEID(66), rowUEaggregateMaximumBitrate: &value}).encodeFresh(fresh, budget)
		}
		*s35.BridgeUEAggregateMaximumBitrateValueCodecFieldCapture(&sealed) = func(v s35.UEAggregateMaximumBitrate, options aper.DecodeState) (s35.UEAggregateMaximumBitrate, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s35.BridgeCaptureS1APUEAggregateMaximumBitrate(&v, &s)
			var root aper.Snapshot
			s.End(
				f,
				&root, false)
			return v, root
		}
		*s35.BridgeUEAggregateMaximumBitrateValueCodecFieldCompare(&sealed) = func(v s35.UEAggregateMaximumBitrate, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s35.BridgeCompareS1APUEAggregateMaximumBitrate(&v, &s)
			s.End(f, root,

				false)
			return s.Plan(), s.BudgetValue()
		}
		*s35.BridgeUEAggregateMaximumBitrateValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:UEAggregateMaximumBitrate"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s35.UEAggregateMaximumBitrate) ERABReleaseCommandIEValue {
			return ERABReleaseCommandIEValue{id: s00.ProtocolIEID(66), rowUEaggregateMaximumBitrate: &value}
		}, get: func(value *ERABReleaseCommandIEValue) (*s35.UEAggregateMaximumBitrate, bool) {
			return value.AsUEaggregateMaximumBitrate()
		}}
}
func (ERABReleaseCommandIETable) infoERABToBeReleasedList() s00.FieldInfo {
	return s00.FieldInfo{Table: ERABReleaseCommandIEs().ID(), ID: s00.ProtocolIEID(33), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceMandatory, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "E-RABList"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "E-RABReleaseCommandIEs", Row: "id-E-RABToBeReleasedList"}}}
}

// ERABToBeReleasedList returns the typed binding for the ERABToBeReleasedList row of ERABReleaseCommandIETable.
func (t ERABReleaseCommandIETable) ERABToBeReleasedList() ERABReleaseCommandERABListIEBinding {
	return ERABReleaseCommandERABListIEBinding{info: t.infoERABToBeReleasedList(), codec: func() s16.ERABListValueCodec {
		sealed := s16.ERABListValueCodec{}
		*s16.BridgeERABListValueCodecFieldPath(&sealed) = "ERABList"
		*s16.BridgeERABListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s16.ERABList, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s16.ERABList
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("ERABList")
			var zero ERABReleaseCommandIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(33), raw)
			if err != nil {
				var empty s16.ERABList
				return empty, runtime.WrapDecodePath(err, "ERABList")
			}
			value, ok := decoded.AsERABToBeReleasedList()
			if !ok {
				var empty s16.ERABList
				return empty, fmt.Errorf("binding E-RABReleaseCommandIEs.id-E-RABToBeReleasedList: no selected value")
			}
			return *value, nil
		}
		*s16.BridgeERABListValueCodecFieldEncode(&sealed) = func(value s16.ERABList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (ERABReleaseCommandIEValue{id: s00.ProtocolIEID(33), rowERABToBeReleasedList: &value}).encodeFresh(fresh, budget)
		}
		*s16.BridgeERABListValueCodecFieldCapture(&sealed) = func(v s16.ERABList, options aper.DecodeState) (s16.ERABList, aper.Snapshot) {
			s := aper.SemanticCaptureFor(
				options)
			f := s.Begin()
			s24.BridgeCaptureS1APERABList(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s16.BridgeERABListValueCodecFieldCompare(&sealed) = func(v s16.ERABList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s24.BridgeCompareS1APERABList(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s16.BridgeERABListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ERABList"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s16.ERABList) ERABReleaseCommandIEValue {
			return ERABReleaseCommandIEValue{id: s00.ProtocolIEID(33), rowERABToBeReleasedList: &value}
		}, get: func(value *ERABReleaseCommandIEValue) (*s16.ERABList, bool) { return value.AsERABToBeReleasedList() }}
}
func (ERABReleaseCommandIETable) infoNASPDU() s00.FieldInfo {
	return s00.FieldInfo{Table: ERABReleaseCommandIEs().ID(), ID: s00.ProtocolIEID(26), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "NAS-PDU"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "E-RABReleaseCommandIEs", Row: "id-NAS-PDU"}}}
}

// NASPDU returns the typed binding for the NASPDU row of ERABReleaseCommandIETable.
func (t ERABReleaseCommandIETable) NASPDU() ERABReleaseCommandNASPDUIEBinding {
	return ERABReleaseCommandNASPDUIEBinding{info: t.infoNASPDU(), codec: func() s01.NASPDUValueCodec {
		sealed := s01.NASPDUValueCodec{}
		*s01.BridgeNASPDUValueCodecFieldPath(&sealed) = "NASPDU"
		*s01.BridgeNASPDUValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.NASPDU, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s00.NASPDU
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("NASPDU")
			var zero ERABReleaseCommandIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(26), raw)
			if err != nil {
				var empty s00.NASPDU
				return empty, runtime.WrapDecodePath(err, "NASPDU")
			}
			value, ok := decoded.AsNASPDU()
			if !ok {
				var empty s00.NASPDU
				return empty, fmt.Errorf("binding E-RABReleaseCommandIEs.id-NAS-PDU: no selected value")
			}
			return *value, nil
		}
		*s01.BridgeNASPDUValueCodecFieldEncode(&sealed) = func(value s00.NASPDU, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (ERABReleaseCommandIEValue{id: s00.ProtocolIEID(26), rowNASPDU: &value}).encodeFresh(fresh, budget)
		}
		*s01.BridgeNASPDUValueCodecFieldCapture(&sealed) = func(v s00.NASPDU, options aper.DecodeState) (s00.NASPDU, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.
				Begin()
			s00.BridgeCaptureS1APNASPDU(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s01.BridgeNASPDUValueCodecFieldCompare(&sealed) = func(v s00.NASPDU, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s02.BridgeCompareS1APNASPDU(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s01.BridgeNASPDUValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:NASPDU"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s00.NASPDU) ERABReleaseCommandIEValue {
			return ERABReleaseCommandIEValue{id: s00.ProtocolIEID(26), rowNASPDU: &value}
		}, get: func(value *ERABReleaseCommandIEValue) (*s00.NASPDU, bool) { return value.AsNASPDU() }}
}

// NewOpaque constructs an owned opaque field for an identifier without a typed row in ERABReleaseCommandIETable.
func (t ERABReleaseCommandIETable) NewOpaque(id s00.ProtocolIEID, criticality s00.Criticality, data []byte) (ERABReleaseCommandIEField, error) {
	if id < 0 || id > 65535 || criticality < 0 || criticality > 2 {
		return ERABReleaseCommandIEField{}, aper.OperationError(fmt.Errorf("invalid opaque IE selector or criticality"), "Opaque")
	}
	switch id {
	case s00.ProtocolIEID(0):
		return ERABReleaseCommandIEField{}, aper.OperationError(fmt.Errorf("known IE id-MME-UE-S1AP-ID requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(8):
		return ERABReleaseCommandIEField{}, aper.OperationError(fmt.Errorf("known IE id-eNB-UE-S1AP-ID requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(66):
		return ERABReleaseCommandIEField{}, aper.OperationError(fmt.Errorf("known IE id-uEaggregateMaximumBitrate requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(33):
		return ERABReleaseCommandIEField{}, aper.OperationError(fmt.Errorf("known IE id-E-RABToBeReleasedList requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(26):
		return ERABReleaseCommandIEField{}, aper.OperationError(fmt.Errorf("known IE id-NAS-PDU requires its typed binding"), "Opaque")
	default:
		budget, err := aper.BuildBudget()
		if err != nil {
			return ERABReleaseCommandIEField{}, aper.OperationError(err, "Opaque")
		}
		opaque, err := aper.BuildOpaqueOpenType(data, budget)
		if err != nil {
			return ERABReleaseCommandIEField{}, aper.OperationError(err, "Opaque")
		}
		return ERABReleaseCommandIEField{Id: id, Criticality: criticality, Value: ERABReleaseCommandIEValue{id: id, opaque: opaque, isOpaque: true}}, aper.OperationError(nil, "Opaque")
	}
}

type HandoverRequestAcknowledgeIETable struct{}

func HandoverRequestAcknowledgeIEs() HandoverRequestAcknowledgeIETable {
	return HandoverRequestAcknowledgeIETable{}
}

// ID returns the ASN.1 object-set identity of HandoverRequestAcknowledgeIETable.
func (HandoverRequestAcknowledgeIETable) ID() s00.TableID {
	return func() s00.TableID {
		sealed := s00.TableID{}
		*s00.BridgeTableIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "HandoverRequestAcknowledgeIEs"}
		return sealed
	}()
}

// Table returns the ASN.1 object-set table described by HandoverRequestAcknowledgeIETable.
func (HandoverRequestAcknowledgeIETable) Table() s00.HandoverRequestAcknowledgeIEValueIETable {
	return func() s00.HandoverRequestAcknowledgeIEValueIETable {
		sealed := s00.HandoverRequestAcknowledgeIEValueIETable{}
		*s00.BridgeHandoverRequestAcknowledgeIEValueIETableFieldBound(&sealed) = true
		return sealed
	}()
}
func (HandoverRequestAcknowledgeIETable) infoMMEUES1APID() s00.FieldInfo {
	return s00.FieldInfo{Table: HandoverRequestAcknowledgeIEs().ID(), ID: s00.ProtocolIEID(0), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceMandatory, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "MME-UE-S1AP-ID"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "HandoverRequestAcknowledgeIEs", Row: "id-MME-UE-S1AP-ID"}}}
}

// MMEUES1APID returns the typed binding for the MMEUES1APID row of HandoverRequestAcknowledgeIETable.
func (t HandoverRequestAcknowledgeIETable) MMEUES1APID() HandoverRequestAcknowledgeMMEUES1APIDIEBinding {
	return HandoverRequestAcknowledgeMMEUES1APIDIEBinding{info: t.infoMMEUES1APID(), codec: func() s01.MMEUES1APIDValueCodec {
		sealed := s01.MMEUES1APIDValueCodec{}
		*s01.BridgeMMEUES1APIDValueCodecFieldPath(&sealed) = "MMEUES1APID"
		*s01.BridgeMMEUES1APIDValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.MMEUES1APID, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s00.MMEUES1APID
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("MMEUES1APID")
			var zero HandoverRequestAcknowledgeIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(0), raw)
			if err != nil {
				var empty s00.MMEUES1APID
				return empty, runtime.WrapDecodePath(err, "MMEUES1APID")
			}
			value, ok := decoded.AsMMEUES1APID()
			if !ok {
				var empty s00.MMEUES1APID
				return empty, fmt.Errorf("binding HandoverRequestAcknowledgeIEs.id-MME-UE-S1AP-ID: no selected value")
			}
			return *value, nil
		}
		*s01.BridgeMMEUES1APIDValueCodecFieldEncode(&sealed) = func(value s00.MMEUES1APID, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (HandoverRequestAcknowledgeIEValue{id: s00.ProtocolIEID(0), rowMMEUES1APID: &value}).encodeFresh(fresh, budget)
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
		inject: func(value s00.MMEUES1APID) HandoverRequestAcknowledgeIEValue {
			return HandoverRequestAcknowledgeIEValue{id: s00.ProtocolIEID(0), rowMMEUES1APID: &value}
		}, get: func(value *HandoverRequestAcknowledgeIEValue) (*s00.MMEUES1APID, bool) { return value.AsMMEUES1APID() }}
}
func (HandoverRequestAcknowledgeIETable) infoENBUES1APID() s00.FieldInfo {
	return s00.FieldInfo{Table: HandoverRequestAcknowledgeIEs().ID(), ID: s00.ProtocolIEID(8), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceMandatory, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "ENB-UE-S1AP-ID"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "HandoverRequestAcknowledgeIEs", Row: "id-eNB-UE-S1AP-ID"}}}
}

// ENBUES1APID returns the typed binding for the ENBUES1APID row of HandoverRequestAcknowledgeIETable.
func (t HandoverRequestAcknowledgeIETable) ENBUES1APID() HandoverRequestAcknowledgeENBUES1APIDIEBinding {
	return HandoverRequestAcknowledgeENBUES1APIDIEBinding{info: t.infoENBUES1APID(), codec: func() s00.ENBUES1APIDValueCodec {
		sealed := s00.ENBUES1APIDValueCodec{}
		*s00.BridgeENBUES1APIDValueCodecFieldPath(&sealed) = "ENBUES1APID"
		*s00.BridgeENBUES1APIDValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.ENBUES1APID, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s00.ENBUES1APID
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("ENBUES1APID")
			var zero HandoverRequestAcknowledgeIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(8), raw)
			if err != nil {
				var empty s00.ENBUES1APID
				return empty, runtime.WrapDecodePath(err, "ENBUES1APID")
			}
			value, ok := decoded.AsENBUES1APID()
			if !ok {
				var empty s00.ENBUES1APID
				return empty, fmt.Errorf("binding HandoverRequestAcknowledgeIEs.id-eNB-UE-S1AP-ID: no selected value")
			}
			return *value, nil
		}
		*s00.BridgeENBUES1APIDValueCodecFieldEncode(&sealed) = func(value s00.ENBUES1APID, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (HandoverRequestAcknowledgeIEValue{id: s00.ProtocolIEID(8), rowENBUES1APID: &value}).encodeFresh(fresh, budget)
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
		inject: func(value s00.ENBUES1APID) HandoverRequestAcknowledgeIEValue {
			return HandoverRequestAcknowledgeIEValue{id: s00.ProtocolIEID(8), rowENBUES1APID: &value}
		}, get: func(value *HandoverRequestAcknowledgeIEValue) (*s00.ENBUES1APID, bool) { return value.AsENBUES1APID() }}
}
func (HandoverRequestAcknowledgeIETable) infoERABAdmittedList() s00.FieldInfo {
	return s00.FieldInfo{Table: HandoverRequestAcknowledgeIEs().ID(), ID: s00.ProtocolIEID(18), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceMandatory, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "E-RABAdmittedList"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "HandoverRequestAcknowledgeIEs", Row: "id-E-RABAdmittedList"}}}
}

// ERABAdmittedList returns the typed binding for the ERABAdmittedList row of HandoverRequestAcknowledgeIETable.
func (t HandoverRequestAcknowledgeIETable) ERABAdmittedList() HandoverRequestAcknowledgeERABAdmittedListIEBinding {
	return HandoverRequestAcknowledgeERABAdmittedListIEBinding{info: t.infoERABAdmittedList(), codec: func() s15.ERABAdmittedListValueCodec {
		sealed := s15.ERABAdmittedListValueCodec{}
		*s15.BridgeERABAdmittedListValueCodecFieldPath(&sealed) = "ERABAdmittedList"
		*s15.BridgeERABAdmittedListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s15.ERABAdmittedList, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s15.ERABAdmittedList
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("ERABAdmittedList")
			var zero HandoverRequestAcknowledgeIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(18), raw)
			if err != nil {
				var empty s15.ERABAdmittedList
				return empty, runtime.WrapDecodePath(err, "ERABAdmittedList")
			}
			value, ok := decoded.AsERABAdmittedList()
			if !ok {
				var empty s15.ERABAdmittedList
				return empty, fmt.Errorf("binding HandoverRequestAcknowledgeIEs.id-E-RABAdmittedList: no selected value")
			}
			return *value, nil
		}
		*s15.BridgeERABAdmittedListValueCodecFieldEncode(&sealed) = func(value s15.ERABAdmittedList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (HandoverRequestAcknowledgeIEValue{id: s00.ProtocolIEID(18), rowERABAdmittedList: &value}).encodeFresh(fresh, budget)
		}
		*s15.BridgeERABAdmittedListValueCodecFieldCapture(&sealed) = func(v s15.ERABAdmittedList, options aper.DecodeState) (s15.ERABAdmittedList, aper.Snapshot) {
			s := aper.SemanticCaptureFor(
				options)
			f := s.Begin()
			s24.BridgeCaptureS1APERABAdmittedList(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s15.BridgeERABAdmittedListValueCodecFieldCompare(&sealed) = func(v s15.ERABAdmittedList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s24.BridgeCompareS1APERABAdmittedList(&v, &s)
			s.End(f, root, false)
			return s.
				Plan(), s.BudgetValue()
		}
		*s15.BridgeERABAdmittedListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ERABAdmittedList"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s15.ERABAdmittedList) HandoverRequestAcknowledgeIEValue {
			return HandoverRequestAcknowledgeIEValue{id: s00.ProtocolIEID(18), rowERABAdmittedList: &value}
		}, get: func(value *HandoverRequestAcknowledgeIEValue) (*s15.ERABAdmittedList, bool) {
			return value.AsERABAdmittedList()
		}}
}
func (HandoverRequestAcknowledgeIETable) infoERABFailedToSetupListHOReqAck() s00.FieldInfo {
	return s00.FieldInfo{Table: HandoverRequestAcknowledgeIEs().ID(), ID: s00.ProtocolIEID(19), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "E-RABFailedtoSetupListHOReqAck"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "HandoverRequestAcknowledgeIEs", Row: "id-E-RABFailedToSetupListHOReqAck"}}}
}

// ERABFailedToSetupListHOReqAck returns the typed binding for the ERABFailedToSetupListHOReqAck row of HandoverRequestAcknowledgeIETable.
func (t HandoverRequestAcknowledgeIETable) ERABFailedToSetupListHOReqAck() HandoverRequestAcknowledgeERABFailedtoSetupListHOReqAckIEBinding {
	return HandoverRequestAcknowledgeERABFailedtoSetupListHOReqAckIEBinding{info: t.infoERABFailedToSetupListHOReqAck(), codec: func() s16.ERABFailedtoSetupListHOReqAckValueCodec {
		sealed := s16.ERABFailedtoSetupListHOReqAckValueCodec{}
		*s16.BridgeERABFailedtoSetupListHOReqAckValueCodecFieldPath(&sealed) = "ERABFailedtoSetupListHOReqAck"
		*s16.BridgeERABFailedtoSetupListHOReqAckValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s16.ERABFailedtoSetupListHOReqAck, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s16.ERABFailedtoSetupListHOReqAck
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("ERABFailedtoSetupListHOReqAck")
			var zero HandoverRequestAcknowledgeIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(19), raw)
			if err != nil {
				var empty s16.ERABFailedtoSetupListHOReqAck
				return empty, runtime.WrapDecodePath(err, "ERABFailedtoSetupListHOReqAck")
			}
			value, ok := decoded.AsERABFailedToSetupListHOReqAck()
			if !ok {
				var empty s16.ERABFailedtoSetupListHOReqAck
				return empty, fmt.Errorf("binding HandoverRequestAcknowledgeIEs.id-E-RABFailedToSetupListHOReqAck: no selected value")
			}
			return *value, nil
		}
		*s16.BridgeERABFailedtoSetupListHOReqAckValueCodecFieldEncode(&sealed) = func(value s16.ERABFailedtoSetupListHOReqAck, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (HandoverRequestAcknowledgeIEValue{id: s00.ProtocolIEID(19), rowERABFailedToSetupListHOReqAck: &value}).encodeFresh(fresh, budget)
		}
		*s16.BridgeERABFailedtoSetupListHOReqAckValueCodecFieldCapture(&sealed) = func(v s16.ERABFailedtoSetupListHOReqAck, options aper.DecodeState) (s16.ERABFailedtoSetupListHOReqAck, aper.Snapshot,

		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s24.BridgeCaptureS1APERABFailedtoSetupListHOReqAck(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s16.BridgeERABFailedtoSetupListHOReqAckValueCodecFieldCompare(&sealed) = func(v s16.ERABFailedtoSetupListHOReqAck, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f :=
				s.Begin()
			s24.BridgeCompareS1APERABFailedtoSetupListHOReqAck(&v, &s)
			s.
				End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s16.BridgeERABFailedtoSetupListHOReqAckValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ERABFailedtoSetupListHOReqAck"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s16.ERABFailedtoSetupListHOReqAck) HandoverRequestAcknowledgeIEValue {
			return HandoverRequestAcknowledgeIEValue{id: s00.ProtocolIEID(19), rowERABFailedToSetupListHOReqAck: &value}
		}, get: func(value *HandoverRequestAcknowledgeIEValue) (*s16.ERABFailedtoSetupListHOReqAck, bool) {
			return value.AsERABFailedToSetupListHOReqAck()
		}}
}
func (HandoverRequestAcknowledgeIETable) infoTargetToSourceTransparentContainer() s00.FieldInfo {
	return s00.FieldInfo{Table: HandoverRequestAcknowledgeIEs().ID(), ID: s00.ProtocolIEID(123), Criticality: s00.CriticalityReject, Presence: s00.PresenceMandatory, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "Target-ToSource-TransparentContainer"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "HandoverRequestAcknowledgeIEs", Row: "id-Target-ToSource-TransparentContainer"}}}
}

// TargetToSourceTransparentContainer returns the typed binding for the TargetToSourceTransparentContainer row of HandoverRequestAcknowledgeIETable.
func (t HandoverRequestAcknowledgeIETable) TargetToSourceTransparentContainer() HandoverRequestAcknowledgeTargetToSourceTransparentContainerIEBinding {
	return HandoverRequestAcknowledgeTargetToSourceTransparentContainerIEBinding{info: t.infoTargetToSourceTransparentContainer(), codec: func() s01.TargetToSourceTransparentContainerValueCodec {
		sealed := s01.TargetToSourceTransparentContainerValueCodec{}
		*s01.BridgeTargetToSourceTransparentContainerValueCodecFieldPath(&sealed) = "TargetToSourceTransparentContainer"
		*s01.BridgeTargetToSourceTransparentContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.TargetToSourceTransparentContainer, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s00.TargetToSourceTransparentContainer
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("TargetToSourceTransparentContainer")
			var zero HandoverRequestAcknowledgeIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(123), raw)
			if err != nil {
				var empty s00.TargetToSourceTransparentContainer
				return empty, runtime.WrapDecodePath(err, "TargetToSourceTransparentContainer")
			}
			value, ok := decoded.AsTargetToSourceTransparentContainer()
			if !ok {
				var empty s00.TargetToSourceTransparentContainer
				return empty, fmt.Errorf("binding HandoverRequestAcknowledgeIEs.id-Target-ToSource-TransparentContainer: no selected value")
			}
			return *value, nil
		}
		*s01.BridgeTargetToSourceTransparentContainerValueCodecFieldEncode(&sealed) = func(value s00.TargetToSourceTransparentContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (HandoverRequestAcknowledgeIEValue{id: s00.ProtocolIEID(123), rowTargetToSourceTransparentContainer: &value}).encodeFresh(fresh, budget)
		}
		*s01.BridgeTargetToSourceTransparentContainerValueCodecFieldCapture(&sealed) = func(v s00.TargetToSourceTransparentContainer, options aper.DecodeState) (s00.TargetToSourceTransparentContainer, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s00.BridgeCaptureS1APTargetToSourceTransparentContainer(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s01.BridgeTargetToSourceTransparentContainerValueCodecFieldCompare(&sealed) = func(v s00.TargetToSourceTransparentContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s07.BridgeCompareS1APTargetToSourceTransparentContainer(
				&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s01.BridgeTargetToSourceTransparentContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:TargetToSourceTransparentContainer"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s00.TargetToSourceTransparentContainer) HandoverRequestAcknowledgeIEValue {
			return HandoverRequestAcknowledgeIEValue{id: s00.ProtocolIEID(123), rowTargetToSourceTransparentContainer: &value}
		}, get: func(value *HandoverRequestAcknowledgeIEValue) (*s00.TargetToSourceTransparentContainer, bool) {
			return value.AsTargetToSourceTransparentContainer()
		}}
}
func (HandoverRequestAcknowledgeIETable) infoCSGId() s00.FieldInfo {
	return s00.FieldInfo{Table: HandoverRequestAcknowledgeIEs().ID(), ID: s00.ProtocolIEID(127), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "CSG-Id"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "HandoverRequestAcknowledgeIEs", Row: "id-CSG-Id"}}}
}

// CSGId returns the typed binding for the CSGId row of HandoverRequestAcknowledgeIETable.
func (t HandoverRequestAcknowledgeIETable) CSGId() HandoverRequestAcknowledgeCSGIdIEBinding {
	return HandoverRequestAcknowledgeCSGIdIEBinding{info: t.infoCSGId(), codec: func() s00.CSGIdValueCodec {
		sealed := s00.CSGIdValueCodec{}
		*s00.BridgeCSGIdValueCodecFieldPath(&sealed) = "CSGId"
		*s00.BridgeCSGIdValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.CSGId, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s00.CSGId
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("CSGId")
			var zero HandoverRequestAcknowledgeIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(127), raw)
			if err != nil {
				var empty s00.CSGId
				return empty, runtime.WrapDecodePath(err, "CSGId")
			}
			value, ok := decoded.AsCSGId()
			if !ok {
				var empty s00.CSGId
				return empty, fmt.Errorf("binding HandoverRequestAcknowledgeIEs.id-CSG-Id: no selected value")
			}
			return *value, nil
		}
		*s00.BridgeCSGIdValueCodecFieldEncode(&sealed) = func(value s00.CSGId, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (HandoverRequestAcknowledgeIEValue{id: s00.ProtocolIEID(127), rowCSGId: &value}).encodeFresh(fresh, budget)
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
		inject: func(value s00.CSGId) HandoverRequestAcknowledgeIEValue {
			return HandoverRequestAcknowledgeIEValue{id: s00.ProtocolIEID(127), rowCSGId: &value}
		}, get: func(value *HandoverRequestAcknowledgeIEValue) (*s00.CSGId, bool) { return value.AsCSGId() }}
}
func (HandoverRequestAcknowledgeIETable) infoCriticalityDiagnostics() s00.FieldInfo {
	return s00.FieldInfo{Table: HandoverRequestAcknowledgeIEs().ID(), ID: s00.ProtocolIEID(58), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "CriticalityDiagnostics"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "HandoverRequestAcknowledgeIEs", Row: "id-CriticalityDiagnostics"}}}
}

// CriticalityDiagnostics returns the typed binding for the CriticalityDiagnostics row of HandoverRequestAcknowledgeIETable.
func (t HandoverRequestAcknowledgeIETable) CriticalityDiagnostics() HandoverRequestAcknowledgeCriticalityDiagnosticsIEBinding {
	return HandoverRequestAcknowledgeCriticalityDiagnosticsIEBinding{info: t.infoCriticalityDiagnostics(), codec: func() s22.CriticalityDiagnosticsValueCodec {
		sealed := s22.CriticalityDiagnosticsValueCodec{}
		*s22.BridgeCriticalityDiagnosticsValueCodecFieldPath(&sealed) = "CriticalityDiagnostics"
		*s22.BridgeCriticalityDiagnosticsValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s22.CriticalityDiagnostics, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s22.CriticalityDiagnostics
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("CriticalityDiagnostics")
			var zero HandoverRequestAcknowledgeIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(58), raw)
			if err != nil {
				var empty s22.CriticalityDiagnostics
				return empty, runtime.WrapDecodePath(err, "CriticalityDiagnostics")
			}
			value, ok := decoded.AsCriticalityDiagnostics()
			if !ok {
				var empty s22.CriticalityDiagnostics
				return empty, fmt.Errorf("binding HandoverRequestAcknowledgeIEs.id-CriticalityDiagnostics: no selected value")
			}
			return *value, nil
		}
		*s22.BridgeCriticalityDiagnosticsValueCodecFieldEncode(&sealed) = func(value s22.CriticalityDiagnostics, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (HandoverRequestAcknowledgeIEValue{id: s00.ProtocolIEID(58), rowCriticalityDiagnostics: &value}).encodeFresh(fresh, budget)
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
		inject: func(value s22.CriticalityDiagnostics) HandoverRequestAcknowledgeIEValue {
			return HandoverRequestAcknowledgeIEValue{id: s00.ProtocolIEID(58), rowCriticalityDiagnostics: &value}
		}, get: func(value *HandoverRequestAcknowledgeIEValue) (*s22.CriticalityDiagnostics, bool) {
			return value.AsCriticalityDiagnostics()
		}}
}
func (HandoverRequestAcknowledgeIETable) infoCellAccessMode() s00.FieldInfo {
	return s00.FieldInfo{Table: HandoverRequestAcknowledgeIEs().ID(), ID: s00.ProtocolIEID(145), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "CellAccessMode"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "HandoverRequestAcknowledgeIEs", Row: "id-CellAccessMode"}}}
}

// CellAccessMode returns the typed binding for the CellAccessMode row of HandoverRequestAcknowledgeIETable.
func (t HandoverRequestAcknowledgeIETable) CellAccessMode() HandoverRequestAcknowledgeCellAccessModeIEBinding {
	return HandoverRequestAcknowledgeCellAccessModeIEBinding{info: t.infoCellAccessMode(), codec: func() s00.CellAccessModeValueCodec {
		sealed := s00.CellAccessModeValueCodec{}
		*s00.BridgeCellAccessModeValueCodecFieldPath(&sealed) = "CellAccessMode"
		*s00.BridgeCellAccessModeValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.CellAccessMode, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s00.CellAccessMode
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("CellAccessMode")
			var zero HandoverRequestAcknowledgeIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(145), raw)
			if err != nil {
				var empty s00.CellAccessMode
				return empty, runtime.WrapDecodePath(err, "CellAccessMode")
			}
			value, ok := decoded.AsCellAccessMode()
			if !ok {
				var empty s00.CellAccessMode
				return empty, fmt.Errorf("binding HandoverRequestAcknowledgeIEs.id-CellAccessMode: no selected value")
			}
			return *value, nil
		}
		*s00.BridgeCellAccessModeValueCodecFieldEncode(&sealed) = func(value s00.CellAccessMode, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (HandoverRequestAcknowledgeIEValue{id: s00.ProtocolIEID(145), rowCellAccessMode: &value}).encodeFresh(fresh, budget)
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
		inject: func(value s00.CellAccessMode) HandoverRequestAcknowledgeIEValue {
			return HandoverRequestAcknowledgeIEValue{id: s00.ProtocolIEID(145), rowCellAccessMode: &value}
		}, get: func(value *HandoverRequestAcknowledgeIEValue) (*s00.CellAccessMode, bool) {
			return value.AsCellAccessMode()
		}}
}
func (HandoverRequestAcknowledgeIETable) infoCEModeBSupportIndicator() s00.FieldInfo {
	return s00.FieldInfo{Table: HandoverRequestAcknowledgeIEs().ID(), ID: s00.ProtocolIEID(242), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "CE-mode-B-SupportIndicator"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "HandoverRequestAcknowledgeIEs", Row: "id-CE-mode-B-SupportIndicator"}}}
}

// CEModeBSupportIndicator returns the typed binding for the CEModeBSupportIndicator row of HandoverRequestAcknowledgeIETable.
func (t HandoverRequestAcknowledgeIETable) CEModeBSupportIndicator() HandoverRequestAcknowledgeCEModeBSupportIndicatorIEBinding {
	return HandoverRequestAcknowledgeCEModeBSupportIndicatorIEBinding{info: t.infoCEModeBSupportIndicator(), codec: func() s00.CEModeBSupportIndicatorValueCodec {
		sealed := s00.CEModeBSupportIndicatorValueCodec{}
		*s00.BridgeCEModeBSupportIndicatorValueCodecFieldPath(&sealed) = "CEModeBSupportIndicator"
		*s00.BridgeCEModeBSupportIndicatorValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.CEModeBSupportIndicator, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s00.CEModeBSupportIndicator
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("CEModeBSupportIndicator")
			var zero HandoverRequestAcknowledgeIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(242), raw)
			if err != nil {
				var empty s00.CEModeBSupportIndicator
				return empty, runtime.WrapDecodePath(err, "CEModeBSupportIndicator")
			}
			value, ok := decoded.AsCEModeBSupportIndicator()
			if !ok {
				var empty s00.CEModeBSupportIndicator
				return empty, fmt.Errorf("binding HandoverRequestAcknowledgeIEs.id-CE-mode-B-SupportIndicator: no selected value")
			}
			return *value, nil
		}
		*s00.BridgeCEModeBSupportIndicatorValueCodecFieldEncode(&sealed) = func(value s00.CEModeBSupportIndicator, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (HandoverRequestAcknowledgeIEValue{id: s00.ProtocolIEID(242), rowCEModeBSupportIndicator: &value}).encodeFresh(fresh, budget)
		}
		*s00.BridgeCEModeBSupportIndicatorValueCodecFieldCapture(&sealed) = func(v s00.CEModeBSupportIndicator, options aper.DecodeState) (s00.CEModeBSupportIndicator, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s00.BridgeCaptureS1APCEModeBSupportIndicator(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,

				false,
			)
			return v, root
		}
		*s00.BridgeCEModeBSupportIndicatorValueCodecFieldCompare(&sealed) = func(v s00.CEModeBSupportIndicator, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s02.BridgeCompareS1APCEModeBSupportIndicator(&v, &s)
			s.End(f, root,
				false,
			)
			return s.Plan(), s.BudgetValue()
		}
		*s00.BridgeCEModeBSupportIndicatorValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:CEModeBSupportIndicator"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s00.CEModeBSupportIndicator) HandoverRequestAcknowledgeIEValue {
			return HandoverRequestAcknowledgeIEValue{id: s00.ProtocolIEID(242), rowCEModeBSupportIndicator: &value}
		}, get: func(value *HandoverRequestAcknowledgeIEValue) (*s00.CEModeBSupportIndicator, bool) {
			return value.AsCEModeBSupportIndicator()
		}}
}

// NewOpaque constructs an owned opaque field for an identifier without a typed row in HandoverRequestAcknowledgeIETable.
func (t HandoverRequestAcknowledgeIETable) NewOpaque(id s00.ProtocolIEID, criticality s00.Criticality, data []byte) (HandoverRequestAcknowledgeIEField, error) {
	if id < 0 || id > 65535 || criticality < 0 || criticality > 2 {
		return HandoverRequestAcknowledgeIEField{}, aper.OperationError(fmt.Errorf("invalid opaque IE selector or criticality"), "Opaque")
	}
	switch id {
	case s00.ProtocolIEID(0):
		return HandoverRequestAcknowledgeIEField{}, aper.OperationError(fmt.Errorf("known IE id-MME-UE-S1AP-ID requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(8):
		return HandoverRequestAcknowledgeIEField{}, aper.OperationError(fmt.Errorf("known IE id-eNB-UE-S1AP-ID requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(18):
		return HandoverRequestAcknowledgeIEField{}, aper.OperationError(fmt.Errorf("known IE id-E-RABAdmittedList requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(19):
		return HandoverRequestAcknowledgeIEField{}, aper.OperationError(fmt.Errorf("known IE id-E-RABFailedToSetupListHOReqAck requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(123):
		return HandoverRequestAcknowledgeIEField{}, aper.OperationError(fmt.Errorf("known IE id-Target-ToSource-TransparentContainer requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(127):
		return HandoverRequestAcknowledgeIEField{}, aper.OperationError(fmt.Errorf("known IE id-CSG-Id requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(58):
		return HandoverRequestAcknowledgeIEField{}, aper.OperationError(fmt.Errorf("known IE id-CriticalityDiagnostics requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(145):
		return HandoverRequestAcknowledgeIEField{}, aper.OperationError(fmt.Errorf("known IE id-CellAccessMode requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(242):
		return HandoverRequestAcknowledgeIEField{}, aper.OperationError(fmt.Errorf("known IE id-CE-mode-B-SupportIndicator requires its typed binding"), "Opaque")
	default:
		budget, err := aper.BuildBudget()
		if err != nil {
			return HandoverRequestAcknowledgeIEField{}, aper.OperationError(err, "Opaque")
		}
		opaque, err := aper.BuildOpaqueOpenType(data, budget)
		if err != nil {
			return HandoverRequestAcknowledgeIEField{}, aper.OperationError(err, "Opaque")
		}
		return HandoverRequestAcknowledgeIEField{Id: id, Criticality: criticality, Value: HandoverRequestAcknowledgeIEValue{id: id, opaque: opaque, isOpaque: true}}, aper.OperationError(nil, "Opaque")
	}
}

// CEModeBSupportIndicatorCodec binds the complete APER value type.
func CEModeBSupportIndicatorCodec() s00.CEModeBSupportIndicatorValueCodec {
	return HandoverRequestAcknowledgeIEs().CEModeBSupportIndicator().Codec()
}

// CSGIdCodec binds the complete APER value type.
func CSGIdCodec() s00.CSGIdValueCodec { return HandoverRequestAcknowledgeIEs().CSGId().Codec() }

// CSGMembershipStatusCodec binds the complete APER value type.
func CSGMembershipStatusCodec() s00.CSGMembershipStatusValueCodec {
	return ERABModificationConfirmIEs().CSGMembershipStatus().Codec()
}

// CellAccessModeCodec binds the complete APER value type.
func CellAccessModeCodec() s00.CellAccessModeValueCodec {
	return HandoverRequestAcknowledgeIEs().CellAccessMode().Codec()
}

// CriticalityDiagnosticsCodec binds the complete APER value type.
func CriticalityDiagnosticsCodec() s22.CriticalityDiagnosticsValueCodec {
	return ERABModificationConfirmIEs().CriticalityDiagnostics().Codec()
}

// DAPSResponseInfoListCodec binds the complete APER value type.
func DAPSResponseInfoListCodec() s14.DAPSResponseInfoListValueCodec {
	return TargeteNBToSourceeNBTransparentContainerExtIEs().DAPSResponseInfoList().Codec()
}

// ERABAdmittedListCodec binds the complete APER value type.
func ERABAdmittedListCodec() s15.ERABAdmittedListValueCodec {
	return HandoverRequestAcknowledgeIEs().ERABAdmittedList().Codec()
}

// ERABFailedtoSetupListHOReqAckCodec binds the complete APER value type.
func ERABFailedtoSetupListHOReqAckCodec() s16.ERABFailedtoSetupListHOReqAckValueCodec {
	return HandoverRequestAcknowledgeIEs().ERABFailedToSetupListHOReqAck().Codec()
}

// ERABInformationListCodec binds the complete source value type.
func ERABInformationListCodec() s29.ERABInformationListValueCodec {
	return func() s29.ERABInformationListValueCodec {
		sealed := s29.ERABInformationListValueCodec{}
		*s29.BridgeERABInformationListValueCodecFieldPath(&sealed) = "ERABInformationList"
		*s29.BridgeERABInformationListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s29.ERABInformationList, error) {
			var complete ERABInformationListComplete
			if err := complete.unmarshalAPERWithOptions(data, options); err != nil {
				var zero s29.ERABInformationList
				return zero, err
			}
			return complete.Value, nil
		}
		*s29.BridgeERABInformationListValueCodecFieldEncode(&sealed) = func(value s29.ERABInformationList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			complete := ERABInformationListComplete{Value: value}
			return complete.marshalAPERBudget(budget, fresh)
		}
		*s29.BridgeERABInformationListValueCodecFieldCapture(&sealed) = func(v s29.ERABInformationList, options aper.DecodeState) (s29.ERABInformationList, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s29.BridgeCaptureS1APERABInformationList(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s29.BridgeERABInformationListValueCodecFieldCompare(&sealed) = func(v s29.ERABInformationList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s29.BridgeCompareS1APERABInformationList(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s29.BridgeERABInformationListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ERABInformationList"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// ERABListCodec binds the complete APER value type.
func ERABListCodec() s16.ERABListValueCodec {
	return ERABModificationConfirmIEs().ERABFailedToModifyListBearerModConf().Codec()
}

// ERABModifyListBearerModConfCodec binds the complete APER value type.
func ERABModifyListBearerModConfCodec() s16.ERABModifyListBearerModConfValueCodec {
	return ERABModificationConfirmIEs().ERABModifyListBearerModConf().Codec()
}

// ERABSecurityResultListCodec binds the complete APER value type.
func ERABSecurityResultListCodec() s30.ERABSecurityResultListValueCodec {
	return TargeteNBToSourceeNBTransparentContainerExtIEs().ERABSecurityResultList().Codec()
}

// RACSIndicationCodec binds the complete APER value type.
func RACSIndicationCodec() s01.RACSIndicationValueCodec {
	return TargeteNBToSourceeNBTransparentContainerExtIEs().RACSIndication().Codec()
}

// TargeteNBToSourceeNBTransparentContainerCodec binds the complete source value type.
func TargeteNBToSourceeNBTransparentContainerCodec() TargeteNBToSourceeNBTransparentContainerValueCodec {
	return TargeteNBToSourceeNBTransparentContainerValueCodec{path: "TargeteNBToSourceeNBTransparentContainer", decode: func(data []byte, options aper.DecodeState) (TargeteNBToSourceeNBTransparentContainer, error) {
		var value TargeteNBToSourceeNBTransparentContainer
		if err := value.unmarshalAPERWithOptions(data, options); err != nil {
			return TargeteNBToSourceeNBTransparentContainer{}, err
		}
		value.received = true
		value.receivedAbsolute = true
		value.receivedBytes = aper.OriginalWire(data)
		return value, nil
	}, encode: func(value TargeteNBToSourceeNBTransparentContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return (&value).marshalAPERBudget(budget, fresh)
	}, capture: func(v TargeteNBToSourceeNBTransparentContainer, options aper.DecodeState) (TargeteNBToSourceeNBTransparentContainer, aper.Snapshot) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeCaptureS1APTargeteNBToSourceeNBTransparentContainer(&v, &s)
		var root aper.Snapshot
		s.End(f, &root, false)
		return v, root
	}, compare: func(v TargeteNBToSourceeNBTransparentContainer, root aper.Snapshot, budget aper.DecodeBudget,
	) (aper.ReplayPlan, aper.DecodeBudget,

	) {
		s := aper.NewSemanticComparison(root,
			budget)
		f := s.Begin()
		BridgeCompareS1APTargeteNBToSourceeNBTransparentContainer(&v, &s)
		s.End(f, root, false)
		return s.Plan(),
			s.BudgetValue()
	}, context: func() s00.BridgeCodecContext {
		sealed := s00.BridgeCodecContext{}
		*s00.BridgecodecContextFieldSource(&sealed) = "source-value:TargeteNBToSourceeNBTransparentContainer"
		*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
		return sealed
	}(),
	}
}
func BridgeERABFailedtoSetupListHOReqAckCompleteFieldPerPadding(v *ERABFailedtoSetupListHOReqAckComplete) *aper.CompletePadding {
	return &v.perPadding
}
func BridgeERABFailedtoSetupListHOReqAckCompleteFieldReceived(v *ERABFailedtoSetupListHOReqAckComplete) *bool {
	return &v.received
}
func BridgeERABFailedtoSetupListHOReqAckCompleteFieldReceivedAbsolute(v *ERABFailedtoSetupListHOReqAckComplete) *bool {
	return &v.receivedAbsolute
}
func BridgeERABFailedtoSetupListHOReqAckCompleteFieldReceivedBytes(v *ERABFailedtoSetupListHOReqAckComplete) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeERABFailedtoSetupListHOReqAckCompleteFieldReceivedLocation(v *ERABFailedtoSetupListHOReqAckComplete) *aper.Location {
	return &v.receivedLocation
}
func BridgeERABFailedtoSetupListHOReqAckCompleteFieldReplay(v *ERABFailedtoSetupListHOReqAckComplete) *aper.Snapshot {
	return &v.replay
}
func BridgeERABFailedtoSetupListHOReqAckCompleteFieldStream(v *ERABFailedtoSetupListHOReqAckComplete) *aper.WireSpan {
	return &v.stream
}
func BridgeERABFailedtoSetupListHOReqAckCompleteFieldWithoutReplay(v *ERABFailedtoSetupListHOReqAckComplete) *bool {
	return &v.withoutReplay
}
func BridgeERABFailedtoSetupListHOReqAckCompleteMethodMarshalAPERBudget(v *ERABFailedtoSetupListHOReqAckComplete, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeERABFailedtoSetupListHOReqAckCompleteMethodMarshalAPERBudgetValue(v *ERABFailedtoSetupListHOReqAckComplete, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudgetValue(a0, a1)
}
func BridgeERABFailedtoSetupListHOReqAckCompleteMethodMarshalAPERChanged(v *ERABFailedtoSetupListHOReqAckComplete, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeERABFailedtoSetupListHOReqAckCompleteMethodMarshalAPERChangedValue(v *ERABFailedtoSetupListHOReqAckComplete, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeERABFailedtoSetupListHOReqAckCompleteMethodMarshalAPERLegacy(v *ERABFailedtoSetupListHOReqAckComplete) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeERABFailedtoSetupListHOReqAckCompleteMethodMarshalAPERNewValue(v *ERABFailedtoSetupListHOReqAckComplete, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERNewValue(a0, a1)
}
func BridgeERABFailedtoSetupListHOReqAckCompleteMethodMarshalAPERPlanned(v *ERABFailedtoSetupListHOReqAckComplete, a0 *aper.DecodeBudget, a1 bool, a2 *aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1, a2)
}
func BridgeERABFailedtoSetupListHOReqAckCompleteMethodUnmarshalAPERLegacy(v *ERABFailedtoSetupListHOReqAckComplete, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeERABFailedtoSetupListHOReqAckCompleteMethodUnmarshalAPERWithOptions(v *ERABFailedtoSetupListHOReqAckComplete, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeERABInformationListCompleteFieldPerPadding(v *ERABInformationListComplete) *aper.CompletePadding {
	return &v.perPadding
}
func BridgeERABInformationListCompleteFieldReceived(v *ERABInformationListComplete) *bool {
	return &v.received
}
func BridgeERABInformationListCompleteFieldReceivedAbsolute(v *ERABInformationListComplete) *bool {
	return &v.receivedAbsolute
}
func BridgeERABInformationListCompleteFieldReceivedBytes(v *ERABInformationListComplete) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeERABInformationListCompleteFieldReceivedLocation(v *ERABInformationListComplete) *aper.Location {
	return &v.receivedLocation
}
func BridgeERABInformationListCompleteFieldReplay(v *ERABInformationListComplete) *aper.Snapshot {
	return &v.replay
}
func BridgeERABInformationListCompleteFieldStream(v *ERABInformationListComplete) *aper.WireSpan {
	return &v.stream
}
func BridgeERABInformationListCompleteFieldWithoutReplay(v *ERABInformationListComplete) *bool {
	return &v.withoutReplay
}
func BridgeERABInformationListCompleteMethodMarshalAPERBudget(v *ERABInformationListComplete, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeERABInformationListCompleteMethodMarshalAPERBudgetValue(v *ERABInformationListComplete, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudgetValue(a0, a1)
}
func BridgeERABInformationListCompleteMethodMarshalAPERChanged(v *ERABInformationListComplete, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeERABInformationListCompleteMethodMarshalAPERChangedValue(v *ERABInformationListComplete, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeERABInformationListCompleteMethodMarshalAPERLegacy(v *ERABInformationListComplete) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeERABInformationListCompleteMethodMarshalAPERNewValue(v *ERABInformationListComplete, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERNewValue(a0, a1)
}
func BridgeERABInformationListCompleteMethodMarshalAPERPlanned(v *ERABInformationListComplete, a0 *aper.DecodeBudget, a1 bool, a2 *aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1, a2)
}
func BridgeERABInformationListCompleteMethodUnmarshalAPERLegacy(v *ERABInformationListComplete, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeERABInformationListCompleteMethodUnmarshalAPERWithOptions(v *ERABInformationListComplete, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeERABListCompleteFieldPerPadding(v *ERABListComplete) *aper.CompletePadding {
	return &v.perPadding
}
func BridgeERABListCompleteFieldReceived(v *ERABListComplete) *bool { return &v.received }
func BridgeERABListCompleteFieldReceivedAbsolute(v *ERABListComplete) *bool {
	return &v.receivedAbsolute
}
func BridgeERABListCompleteFieldReceivedBytes(v *ERABListComplete) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeERABListCompleteFieldReceivedLocation(v *ERABListComplete) *aper.Location {
	return &v.receivedLocation
}
func BridgeERABListCompleteFieldReplay(v *ERABListComplete) *aper.Snapshot { return &v.replay }
func BridgeERABListCompleteFieldStream(v *ERABListComplete) *aper.WireSpan { return &v.stream }
func BridgeERABListCompleteFieldWithoutReplay(v *ERABListComplete) *bool   { return &v.withoutReplay }
func BridgeERABListCompleteMethodMarshalAPERBudget(v *ERABListComplete, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeERABListCompleteMethodMarshalAPERBudgetValue(v *ERABListComplete, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudgetValue(a0, a1)
}
func BridgeERABListCompleteMethodMarshalAPERChanged(v *ERABListComplete, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeERABListCompleteMethodMarshalAPERChangedValue(v *ERABListComplete, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeERABListCompleteMethodMarshalAPERLegacy(v *ERABListComplete) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeERABListCompleteMethodMarshalAPERNewValue(v *ERABListComplete, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERNewValue(a0, a1)
}
func BridgeERABListCompleteMethodMarshalAPERPlanned(v *ERABListComplete, a0 *aper.DecodeBudget, a1 bool, a2 *aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1, a2)
}
func BridgeERABListCompleteMethodUnmarshalAPERLegacy(v *ERABListComplete, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeERABListCompleteMethodUnmarshalAPERWithOptions(v *ERABListComplete, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeERABModificationConfirmAPERValueFieldContext(v *ERABModificationConfirmAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABModificationConfirmAPERValueFieldReceived(v *ERABModificationConfirmAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeERABModificationConfirmAPERValueFieldReplay(v *ERABModificationConfirmAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeERABModificationConfirmAPERValueFieldWithoutReplay(v *ERABModificationConfirmAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeERABModificationConfirmCSGMembershipStatusIEBindingFieldCodec(v *ERABModificationConfirmCSGMembershipStatusIEBinding) *s00.CSGMembershipStatusValueCodec {
	return &v.codec
}
func BridgeERABModificationConfirmCSGMembershipStatusIEBindingFieldGet(v *ERABModificationConfirmCSGMembershipStatusIEBinding) *func(*ERABModificationConfirmIEValue) (*s00.CSGMembershipStatus, bool) {
	return &v.get
}
func BridgeERABModificationConfirmCSGMembershipStatusIEBindingFieldInfo(v *ERABModificationConfirmCSGMembershipStatusIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeERABModificationConfirmCSGMembershipStatusIEBindingFieldInject(v *ERABModificationConfirmCSGMembershipStatusIEBinding) *func(s00.CSGMembershipStatus) ERABModificationConfirmIEValue {
	return &v.inject
}
func BridgeERABModificationConfirmCriticalityDiagnosticsIEBindingFieldCodec(v *ERABModificationConfirmCriticalityDiagnosticsIEBinding) *s22.CriticalityDiagnosticsValueCodec {
	return &v.codec
}
func BridgeERABModificationConfirmCriticalityDiagnosticsIEBindingFieldGet(v *ERABModificationConfirmCriticalityDiagnosticsIEBinding) *func(*ERABModificationConfirmIEValue) (*s22.CriticalityDiagnostics, bool) {
	return &v.get
}
func BridgeERABModificationConfirmCriticalityDiagnosticsIEBindingFieldInfo(v *ERABModificationConfirmCriticalityDiagnosticsIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeERABModificationConfirmCriticalityDiagnosticsIEBindingFieldInject(v *ERABModificationConfirmCriticalityDiagnosticsIEBinding) *func(s22.CriticalityDiagnostics) ERABModificationConfirmIEValue {
	return &v.inject
}
func BridgeERABModificationConfirmENBUES1APIDIEBindingFieldCodec(v *ERABModificationConfirmENBUES1APIDIEBinding) *s00.ENBUES1APIDValueCodec {
	return &v.codec
}
func BridgeERABModificationConfirmENBUES1APIDIEBindingFieldGet(v *ERABModificationConfirmENBUES1APIDIEBinding) *func(*ERABModificationConfirmIEValue) (*s00.ENBUES1APID, bool) {
	return &v.get
}
func BridgeERABModificationConfirmENBUES1APIDIEBindingFieldInfo(v *ERABModificationConfirmENBUES1APIDIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeERABModificationConfirmENBUES1APIDIEBindingFieldInject(v *ERABModificationConfirmENBUES1APIDIEBinding) *func(s00.ENBUES1APID) ERABModificationConfirmIEValue {
	return &v.inject
}
func BridgeERABModificationConfirmERABListIEBindingFieldCodec(v *ERABModificationConfirmERABListIEBinding) *s16.ERABListValueCodec {
	return &v.codec
}
func BridgeERABModificationConfirmERABListIEBindingFieldGet(v *ERABModificationConfirmERABListIEBinding) *func(*ERABModificationConfirmIEValue) (*s16.ERABList, bool) {
	return &v.get
}
func BridgeERABModificationConfirmERABListIEBindingFieldInfo(v *ERABModificationConfirmERABListIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeERABModificationConfirmERABListIEBindingFieldInject(v *ERABModificationConfirmERABListIEBinding) *func(s16.ERABList) ERABModificationConfirmIEValue {
	return &v.inject
}
func BridgeERABModificationConfirmERABModifyListBearerModConfIEBindingFieldCodec(v *ERABModificationConfirmERABModifyListBearerModConfIEBinding) *s16.ERABModifyListBearerModConfValueCodec {
	return &v.codec
}
func BridgeERABModificationConfirmERABModifyListBearerModConfIEBindingFieldGet(v *ERABModificationConfirmERABModifyListBearerModConfIEBinding) *func(*ERABModificationConfirmIEValue) (*s16.ERABModifyListBearerModConf, bool) {
	return &v.get
}
func BridgeERABModificationConfirmERABModifyListBearerModConfIEBindingFieldInfo(v *ERABModificationConfirmERABModifyListBearerModConfIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeERABModificationConfirmERABModifyListBearerModConfIEBindingFieldInject(v *ERABModificationConfirmERABModifyListBearerModConfIEBinding) *func(s16.ERABModifyListBearerModConf) ERABModificationConfirmIEValue {
	return &v.inject
}
func BridgeERABModificationConfirmFieldExtCount(v *ERABModificationConfirm) *int64 {
	return &v.extCount
}
func BridgeERABModificationConfirmFieldExtData(v *ERABModificationConfirm) *[][]byte {
	return &v.extData
}
func BridgeERABModificationConfirmFieldExtOrigin(v *ERABModificationConfirm) *[]aper.OpaqueOrigin {
	return &v.extOrigin
}
func BridgeERABModificationConfirmFieldExtPresent(v *ERABModificationConfirm) *[]bool {
	return &v.extPresent
}
func BridgeERABModificationConfirmFieldExtWire(v *ERABModificationConfirm) *[]aper.WireSpan {
	return &v.extWire
}
func BridgeERABModificationConfirmFieldPerExtPadding(v *ERABModificationConfirm) *[]aper.CompletePadding {
	return &v.perExtPadding
}
func BridgeERABModificationConfirmFieldPerPadding(v *ERABModificationConfirm) *aper.FinalPadding {
	return &v.perPadding
}
func BridgeERABModificationConfirmFieldProtocolIEsIndef(v *ERABModificationConfirm) *bool {
	return &v.protocolIEsIndef
}
func BridgeERABModificationConfirmFieldReceived(v *ERABModificationConfirm) *bool { return &v.received }
func BridgeERABModificationConfirmFieldReceivedAbsolute(v *ERABModificationConfirm) *bool {
	return &v.receivedAbsolute
}
func BridgeERABModificationConfirmFieldReceivedBytes(v *ERABModificationConfirm) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeERABModificationConfirmFieldReceivedLocation(v *ERABModificationConfirm) *aper.Location {
	return &v.receivedLocation
}
func BridgeERABModificationConfirmFieldReplay(v *ERABModificationConfirm) *aper.Snapshot {
	return &v.replay
}
func BridgeERABModificationConfirmFieldStream(v *ERABModificationConfirm) *aper.WireSpan {
	return &v.stream
}
func BridgeERABModificationConfirmFieldWithoutReplay(v *ERABModificationConfirm) *bool {
	return &v.withoutReplay
}
func BridgeERABModificationConfirmIEContainerAPERValueFieldContext(v *ERABModificationConfirmIEContainerAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABModificationConfirmIEContainerAPERValueFieldReceived(v *ERABModificationConfirmIEContainerAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeERABModificationConfirmIEContainerAPERValueFieldReplay(v *ERABModificationConfirmIEContainerAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeERABModificationConfirmIEContainerAPERValueFieldWithoutReplay(v *ERABModificationConfirmIEContainerAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeERABModificationConfirmIEContainerValueCodecFieldCapture(v *ERABModificationConfirmIEContainerValueCodec) *func(ERABModificationConfirmIEContainer, aper.DecodeState) (ERABModificationConfirmIEContainer, aper.Snapshot) {
	return &v.capture
}
func BridgeERABModificationConfirmIEContainerValueCodecFieldCompare(v *ERABModificationConfirmIEContainerValueCodec) *func(ERABModificationConfirmIEContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeERABModificationConfirmIEContainerValueCodecFieldContext(v *ERABModificationConfirmIEContainerValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABModificationConfirmIEContainerValueCodecFieldDecode(v *ERABModificationConfirmIEContainerValueCodec) *func([]byte, aper.DecodeState) (ERABModificationConfirmIEContainer, error) {
	return &v.decode
}
func BridgeERABModificationConfirmIEContainerValueCodecFieldEncode(v *ERABModificationConfirmIEContainerValueCodec) *func(ERABModificationConfirmIEContainer, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeERABModificationConfirmIEContainerValueCodecFieldPath(v *ERABModificationConfirmIEContainerValueCodec) *aper.Path {
	return &v.path
}
func BridgeERABModificationConfirmIEContainerValueCodecMethodEncodeBudgetValue(v ERABModificationConfirmIEContainerValueCodec, a0 ERABModificationConfirmIEContainer, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeERABModificationConfirmIEContainerValueCodecMethodEncodeChanged(v ERABModificationConfirmIEContainerValueCodec, a0 ERABModificationConfirmIEContainer, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeERABModificationConfirmIEFieldAPERValueFieldContext(v *ERABModificationConfirmIEFieldAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABModificationConfirmIEFieldAPERValueFieldReceived(v *ERABModificationConfirmIEFieldAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeERABModificationConfirmIEFieldAPERValueFieldReplay(v *ERABModificationConfirmIEFieldAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeERABModificationConfirmIEFieldAPERValueFieldWithoutReplay(v *ERABModificationConfirmIEFieldAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeERABModificationConfirmIEFieldFieldReceived(v *ERABModificationConfirmIEField) *aper.CompletePadding {
	return &v.received
}
func BridgeERABModificationConfirmIEFieldFieldReplay(v *ERABModificationConfirmIEField) *aper.Snapshot {
	return &v.replay
}
func BridgeERABModificationConfirmIEFieldFieldStream(v *ERABModificationConfirmIEField) *aper.WireSpan {
	return &v.stream
}
func BridgeERABModificationConfirmIEFieldFieldWithoutReplay(v *ERABModificationConfirmIEField) *bool {
	return &v.withoutReplay
}
func BridgeERABModificationConfirmIEFieldMethodMarshalAPERTo(v *ERABModificationConfirmIEField, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeERABModificationConfirmIEFieldMethodUnmarshalAPERFrom(v *ERABModificationConfirmIEField, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeERABModificationConfirmIEFieldValueCodecFieldCapture(v *ERABModificationConfirmIEFieldValueCodec) *func(ERABModificationConfirmIEField, aper.DecodeState) (ERABModificationConfirmIEField, aper.Snapshot) {
	return &v.capture
}
func BridgeERABModificationConfirmIEFieldValueCodecFieldCompare(v *ERABModificationConfirmIEFieldValueCodec) *func(ERABModificationConfirmIEField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeERABModificationConfirmIEFieldValueCodecFieldContext(v *ERABModificationConfirmIEFieldValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABModificationConfirmIEFieldValueCodecFieldDecode(v *ERABModificationConfirmIEFieldValueCodec) *func([]byte, aper.DecodeState) (ERABModificationConfirmIEField, error) {
	return &v.decode
}
func BridgeERABModificationConfirmIEFieldValueCodecFieldEncode(v *ERABModificationConfirmIEFieldValueCodec) *func(ERABModificationConfirmIEField, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeERABModificationConfirmIEFieldValueCodecFieldPath(v *ERABModificationConfirmIEFieldValueCodec) *aper.Path {
	return &v.path
}
func BridgeERABModificationConfirmIEFieldValueCodecMethodEncodeBudgetValue(v ERABModificationConfirmIEFieldValueCodec, a0 ERABModificationConfirmIEField, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeERABModificationConfirmIEFieldValueCodecMethodEncodeChanged(v ERABModificationConfirmIEFieldValueCodec, a0 ERABModificationConfirmIEField, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeERABModificationConfirmIETableMethodInfoCSGMembershipStatus(v ERABModificationConfirmIETable) s00.FieldInfo {
	return v.infoCSGMembershipStatus()
}
func BridgeERABModificationConfirmIETableMethodInfoCriticalityDiagnostics(v ERABModificationConfirmIETable) s00.FieldInfo {
	return v.infoCriticalityDiagnostics()
}
func BridgeERABModificationConfirmIETableMethodInfoENBUES1APID(v ERABModificationConfirmIETable) s00.FieldInfo {
	return v.infoENBUES1APID()
}
func BridgeERABModificationConfirmIETableMethodInfoERABFailedToModifyListBearerModConf(v ERABModificationConfirmIETable) s00.FieldInfo {
	return v.infoERABFailedToModifyListBearerModConf()
}
func BridgeERABModificationConfirmIETableMethodInfoERABModifyListBearerModConf(v ERABModificationConfirmIETable) s00.FieldInfo {
	return v.infoERABModifyListBearerModConf()
}
func BridgeERABModificationConfirmIETableMethodInfoERABToBeReleasedListBearerModConf(v ERABModificationConfirmIETable) s00.FieldInfo {
	return v.infoERABToBeReleasedListBearerModConf()
}
func BridgeERABModificationConfirmIETableMethodInfoMMEUES1APID(v ERABModificationConfirmIETable) s00.FieldInfo {
	return v.infoMMEUES1APID()
}
func BridgeERABModificationConfirmIEValueERABIEContainerListAPERValueFieldContext(v *ERABModificationConfirmIEValueERABIEContainerListAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABModificationConfirmIEValueERABIEContainerListAPERValueFieldReceived(v *ERABModificationConfirmIEValueERABIEContainerListAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeERABModificationConfirmIEValueERABIEContainerListAPERValueFieldReplay(v *ERABModificationConfirmIEValueERABIEContainerListAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeERABModificationConfirmIEValueERABIEContainerListAPERValueFieldWithoutReplay(v *ERABModificationConfirmIEValueERABIEContainerListAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeERABModificationConfirmIEValueERABIEContainerListValueCodecFieldCapture(v *ERABModificationConfirmIEValueERABIEContainerListValueCodec) *func(ERABModificationConfirmIEValueERABIEContainerList, aper.DecodeState) (ERABModificationConfirmIEValueERABIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgeERABModificationConfirmIEValueERABIEContainerListValueCodecFieldCompare(v *ERABModificationConfirmIEValueERABIEContainerListValueCodec) *func(ERABModificationConfirmIEValueERABIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeERABModificationConfirmIEValueERABIEContainerListValueCodecFieldContext(v *ERABModificationConfirmIEValueERABIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABModificationConfirmIEValueERABIEContainerListValueCodecFieldDecode(v *ERABModificationConfirmIEValueERABIEContainerListValueCodec) *func([]byte, aper.DecodeState) (ERABModificationConfirmIEValueERABIEContainerList, error) {
	return &v.decode
}
func BridgeERABModificationConfirmIEValueERABIEContainerListValueCodecFieldEncode(v *ERABModificationConfirmIEValueERABIEContainerListValueCodec) *func(ERABModificationConfirmIEValueERABIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeERABModificationConfirmIEValueERABIEContainerListValueCodecFieldPath(v *ERABModificationConfirmIEValueERABIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgeERABModificationConfirmIEValueERABIEContainerListValueCodecMethodEncodeBudgetValue(v ERABModificationConfirmIEValueERABIEContainerListValueCodec, a0 ERABModificationConfirmIEValueERABIEContainerList, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeERABModificationConfirmIEValueERABIEContainerListValueCodecMethodEncodeChanged(v ERABModificationConfirmIEValueERABIEContainerListValueCodec, a0 ERABModificationConfirmIEValueERABIEContainerList, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeERABModificationConfirmIEValueFieldId(v *ERABModificationConfirmIEValue) *s00.ProtocolIEID {
	return &v.id
}
func BridgeERABModificationConfirmIEValueFieldIsOpaque(v *ERABModificationConfirmIEValue) *bool {
	return &v.isOpaque
}
func BridgeERABModificationConfirmIEValueFieldOpaque(v *ERABModificationConfirmIEValue) *aper.OpaqueOpenType {
	return &v.opaque
}
func BridgeERABModificationConfirmIEValueFieldReceived(v *ERABModificationConfirmIEValue) *aper.WireSpan {
	return &v.received
}
func BridgeERABModificationConfirmIEValueFieldReplay(v *ERABModificationConfirmIEValue) *aper.Snapshot {
	return &v.replay
}
func BridgeERABModificationConfirmIEValueFieldRowCSGMembershipStatus(v *ERABModificationConfirmIEValue) **s00.CSGMembershipStatus {
	return &v.rowCSGMembershipStatus
}
func BridgeERABModificationConfirmIEValueFieldRowCriticalityDiagnostics(v *ERABModificationConfirmIEValue) **s22.CriticalityDiagnostics {
	return &v.rowCriticalityDiagnostics
}
func BridgeERABModificationConfirmIEValueFieldRowENBUES1APID(v *ERABModificationConfirmIEValue) **s00.ENBUES1APID {
	return &v.rowENBUES1APID
}
func BridgeERABModificationConfirmIEValueFieldRowERABFailedToModifyListBearerModConf(v *ERABModificationConfirmIEValue) **s16.ERABList {
	return &v.rowERABFailedToModifyListBearerModConf
}
func BridgeERABModificationConfirmIEValueFieldRowERABModifyListBearerModConf(v *ERABModificationConfirmIEValue) **s16.ERABModifyListBearerModConf {
	return &v.rowERABModifyListBearerModConf
}
func BridgeERABModificationConfirmIEValueFieldRowERABToBeReleasedListBearerModConf(v *ERABModificationConfirmIEValue) **s16.ERABList {
	return &v.rowERABToBeReleasedListBearerModConf
}
func BridgeERABModificationConfirmIEValueFieldRowMMEUES1APID(v *ERABModificationConfirmIEValue) **s00.MMEUES1APID {
	return &v.rowMMEUES1APID
}
func BridgeERABModificationConfirmIEValueMethodCaptureSemantics(v ERABModificationConfirmIEValue, a0 aper.SemanticCapture) ERABModificationConfirmIEValue {
	return v.captureSemantics(a0)
}
func BridgeERABModificationConfirmIEValueMethodCompareSemantics(v ERABModificationConfirmIEValue, a0 aper.SemanticComparison) aper.SemanticComparison {
	return v.compareSemantics(a0)
}
func BridgeERABModificationConfirmIEValueMethodDecode(v ERABModificationConfirmIEValue, a0 s00.ProtocolIEID, a1 aper.OpaqueOpenType) (ERABModificationConfirmIEValue, error) {
	return v.decode(a0, a1)
}
func BridgeERABModificationConfirmIEValueMethodEncode(v ERABModificationConfirmIEValue) ([]byte, error) {
	return v.encode()
}
func BridgeERABModificationConfirmIEValueMethodEncodeFresh(v ERABModificationConfirmIEValue, a0 bool, a1 *aper.DecodeBudget) ([]byte, error) {
	return v.encodeFresh(a0, a1)
}
func BridgeERABModificationConfirmIEValueMethodMatchesID(v ERABModificationConfirmIEValue, a0 s00.ProtocolIEID, a1 ...*aper.DecodeBudget) bool {
	return v.matchesID(a0, a1...)
}
func BridgeERABModificationConfirmIEValueMethodReason(v ERABModificationConfirmIEValue, a0 s00.ProtocolIEID) aper.OpaqueReason {
	return v.reason(a0)
}
func BridgeERABModificationConfirmIEValueMethodRule(v ERABModificationConfirmIEValue) aper.SourceRule {
	return v.rule()
}
func BridgeERABModificationConfirmIEValueProtocolErrorIEContainerListAPERValueFieldContext(v *ERABModificationConfirmIEValueProtocolErrorIEContainerListAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABModificationConfirmIEValueProtocolErrorIEContainerListAPERValueFieldReceived(v *ERABModificationConfirmIEValueProtocolErrorIEContainerListAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeERABModificationConfirmIEValueProtocolErrorIEContainerListAPERValueFieldReplay(v *ERABModificationConfirmIEValueProtocolErrorIEContainerListAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeERABModificationConfirmIEValueProtocolErrorIEContainerListAPERValueFieldWithoutReplay(v *ERABModificationConfirmIEValueProtocolErrorIEContainerListAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeERABModificationConfirmIEValueProtocolErrorIEContainerListValueCodecFieldCapture(v *ERABModificationConfirmIEValueProtocolErrorIEContainerListValueCodec) *func(ERABModificationConfirmIEValueProtocolErrorIEContainerList, aper.DecodeState) (ERABModificationConfirmIEValueProtocolErrorIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgeERABModificationConfirmIEValueProtocolErrorIEContainerListValueCodecFieldCompare(v *ERABModificationConfirmIEValueProtocolErrorIEContainerListValueCodec) *func(ERABModificationConfirmIEValueProtocolErrorIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeERABModificationConfirmIEValueProtocolErrorIEContainerListValueCodecFieldContext(v *ERABModificationConfirmIEValueProtocolErrorIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABModificationConfirmIEValueProtocolErrorIEContainerListValueCodecFieldDecode(v *ERABModificationConfirmIEValueProtocolErrorIEContainerListValueCodec) *func([]byte, aper.DecodeState) (ERABModificationConfirmIEValueProtocolErrorIEContainerList, error) {
	return &v.decode
}
func BridgeERABModificationConfirmIEValueProtocolErrorIEContainerListValueCodecFieldEncode(v *ERABModificationConfirmIEValueProtocolErrorIEContainerListValueCodec) *func(ERABModificationConfirmIEValueProtocolErrorIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeERABModificationConfirmIEValueProtocolErrorIEContainerListValueCodecFieldPath(v *ERABModificationConfirmIEValueProtocolErrorIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgeERABModificationConfirmIEValueProtocolErrorIEContainerListValueCodecMethodEncodeBudgetValue(v ERABModificationConfirmIEValueProtocolErrorIEContainerListValueCodec, a0 ERABModificationConfirmIEValueProtocolErrorIEContainerList, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeERABModificationConfirmIEValueProtocolErrorIEContainerListValueCodecMethodEncodeChanged(v ERABModificationConfirmIEValueProtocolErrorIEContainerListValueCodec, a0 ERABModificationConfirmIEValueProtocolErrorIEContainerList, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeERABModificationConfirmIEValueProtocolIEContainerListAPERValueFieldContext(v *ERABModificationConfirmIEValueProtocolIEContainerListAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABModificationConfirmIEValueProtocolIEContainerListAPERValueFieldReceived(v *ERABModificationConfirmIEValueProtocolIEContainerListAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeERABModificationConfirmIEValueProtocolIEContainerListAPERValueFieldReplay(v *ERABModificationConfirmIEValueProtocolIEContainerListAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeERABModificationConfirmIEValueProtocolIEContainerListAPERValueFieldWithoutReplay(v *ERABModificationConfirmIEValueProtocolIEContainerListAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeERABModificationConfirmIEValueProtocolIEContainerListValueCodecFieldCapture(v *ERABModificationConfirmIEValueProtocolIEContainerListValueCodec) *func(ERABModificationConfirmIEValueProtocolIEContainerList, aper.DecodeState) (ERABModificationConfirmIEValueProtocolIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgeERABModificationConfirmIEValueProtocolIEContainerListValueCodecFieldCompare(v *ERABModificationConfirmIEValueProtocolIEContainerListValueCodec) *func(ERABModificationConfirmIEValueProtocolIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeERABModificationConfirmIEValueProtocolIEContainerListValueCodecFieldContext(v *ERABModificationConfirmIEValueProtocolIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABModificationConfirmIEValueProtocolIEContainerListValueCodecFieldDecode(v *ERABModificationConfirmIEValueProtocolIEContainerListValueCodec) *func([]byte, aper.DecodeState) (ERABModificationConfirmIEValueProtocolIEContainerList, error) {
	return &v.decode
}
func BridgeERABModificationConfirmIEValueProtocolIEContainerListValueCodecFieldEncode(v *ERABModificationConfirmIEValueProtocolIEContainerListValueCodec) *func(ERABModificationConfirmIEValueProtocolIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeERABModificationConfirmIEValueProtocolIEContainerListValueCodecFieldPath(v *ERABModificationConfirmIEValueProtocolIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgeERABModificationConfirmIEValueProtocolIEContainerListValueCodecMethodEncodeBudgetValue(v ERABModificationConfirmIEValueProtocolIEContainerListValueCodec, a0 ERABModificationConfirmIEValueProtocolIEContainerList, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeERABModificationConfirmIEValueProtocolIEContainerListValueCodecMethodEncodeChanged(v ERABModificationConfirmIEValueProtocolIEContainerListValueCodec, a0 ERABModificationConfirmIEValueProtocolIEContainerList, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeERABModificationConfirmMMEUES1APIDIEBindingFieldCodec(v *ERABModificationConfirmMMEUES1APIDIEBinding) *s01.MMEUES1APIDValueCodec {
	return &v.codec
}
func BridgeERABModificationConfirmMMEUES1APIDIEBindingFieldGet(v *ERABModificationConfirmMMEUES1APIDIEBinding) *func(*ERABModificationConfirmIEValue) (*s00.MMEUES1APID, bool) {
	return &v.get
}
func BridgeERABModificationConfirmMMEUES1APIDIEBindingFieldInfo(v *ERABModificationConfirmMMEUES1APIDIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeERABModificationConfirmMMEUES1APIDIEBindingFieldInject(v *ERABModificationConfirmMMEUES1APIDIEBinding) *func(s00.MMEUES1APID) ERABModificationConfirmIEValue {
	return &v.inject
}
func BridgeERABModificationConfirmMethodMarshalAPERBudget(v *ERABModificationConfirm, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeERABModificationConfirmMethodMarshalAPERBudgetValue(v *ERABModificationConfirm, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudgetValue(a0, a1)
}
func BridgeERABModificationConfirmMethodMarshalAPERChanged(v *ERABModificationConfirm, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeERABModificationConfirmMethodMarshalAPERChangedValue(v *ERABModificationConfirm, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeERABModificationConfirmMethodMarshalAPERLegacy(v *ERABModificationConfirm) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeERABModificationConfirmMethodMarshalAPERNewValue(v *ERABModificationConfirm, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERNewValue(a0, a1)
}
func BridgeERABModificationConfirmMethodMarshalAPERPlanned(v *ERABModificationConfirm, a0 *aper.DecodeBudget, a1 bool, a2 *aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1, a2)
}
func BridgeERABModificationConfirmMethodMarshalAPERTo(v *ERABModificationConfirm, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeERABModificationConfirmMethodUnmarshalAPERFrom(v *ERABModificationConfirm, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeERABModificationConfirmMethodUnmarshalAPERLegacy(v *ERABModificationConfirm, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeERABModificationConfirmMethodUnmarshalAPERWithOptions(v *ERABModificationConfirm, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeERABModificationConfirmValueCodecFieldCapture(v *ERABModificationConfirmValueCodec) *func(ERABModificationConfirm, aper.DecodeState) (ERABModificationConfirm, aper.Snapshot) {
	return &v.capture
}
func BridgeERABModificationConfirmValueCodecFieldCompare(v *ERABModificationConfirmValueCodec) *func(ERABModificationConfirm, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeERABModificationConfirmValueCodecFieldContext(v *ERABModificationConfirmValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABModificationConfirmValueCodecFieldDecode(v *ERABModificationConfirmValueCodec) *func([]byte, aper.DecodeState) (ERABModificationConfirm, error) {
	return &v.decode
}
func BridgeERABModificationConfirmValueCodecFieldEncode(v *ERABModificationConfirmValueCodec) *func(ERABModificationConfirm, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeERABModificationConfirmValueCodecFieldPath(v *ERABModificationConfirmValueCodec) *aper.Path {
	return &v.path
}
func BridgeERABModificationConfirmValueCodecMethodEncodeBudgetValue(v ERABModificationConfirmValueCodec, a0 ERABModificationConfirm, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeERABModificationConfirmValueCodecMethodEncodeChanged(v ERABModificationConfirmValueCodec, a0 ERABModificationConfirm, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeERABModifyListBearerModConfCompleteFieldPerPadding(v *ERABModifyListBearerModConfComplete) *aper.CompletePadding {
	return &v.perPadding
}
func BridgeERABModifyListBearerModConfCompleteFieldReceived(v *ERABModifyListBearerModConfComplete) *bool {
	return &v.received
}
func BridgeERABModifyListBearerModConfCompleteFieldReceivedAbsolute(v *ERABModifyListBearerModConfComplete) *bool {
	return &v.receivedAbsolute
}
func BridgeERABModifyListBearerModConfCompleteFieldReceivedBytes(v *ERABModifyListBearerModConfComplete) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeERABModifyListBearerModConfCompleteFieldReceivedLocation(v *ERABModifyListBearerModConfComplete) *aper.Location {
	return &v.receivedLocation
}
func BridgeERABModifyListBearerModConfCompleteFieldReplay(v *ERABModifyListBearerModConfComplete) *aper.Snapshot {
	return &v.replay
}
func BridgeERABModifyListBearerModConfCompleteFieldStream(v *ERABModifyListBearerModConfComplete) *aper.WireSpan {
	return &v.stream
}
func BridgeERABModifyListBearerModConfCompleteFieldWithoutReplay(v *ERABModifyListBearerModConfComplete) *bool {
	return &v.withoutReplay
}
func BridgeERABModifyListBearerModConfCompleteMethodMarshalAPERBudget(v *ERABModifyListBearerModConfComplete, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeERABModifyListBearerModConfCompleteMethodMarshalAPERBudgetValue(v *ERABModifyListBearerModConfComplete, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudgetValue(a0, a1)
}
func BridgeERABModifyListBearerModConfCompleteMethodMarshalAPERChanged(v *ERABModifyListBearerModConfComplete, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeERABModifyListBearerModConfCompleteMethodMarshalAPERChangedValue(v *ERABModifyListBearerModConfComplete, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeERABModifyListBearerModConfCompleteMethodMarshalAPERLegacy(v *ERABModifyListBearerModConfComplete) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeERABModifyListBearerModConfCompleteMethodMarshalAPERNewValue(v *ERABModifyListBearerModConfComplete, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERNewValue(a0, a1)
}
func BridgeERABModifyListBearerModConfCompleteMethodMarshalAPERPlanned(v *ERABModifyListBearerModConfComplete, a0 *aper.DecodeBudget, a1 bool, a2 *aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1, a2)
}
func BridgeERABModifyListBearerModConfCompleteMethodUnmarshalAPERLegacy(v *ERABModifyListBearerModConfComplete, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeERABModifyListBearerModConfCompleteMethodUnmarshalAPERWithOptions(v *ERABModifyListBearerModConfComplete, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeERABModifyListBearerModResCompleteFieldPerPadding(v *ERABModifyListBearerModResComplete) *aper.CompletePadding {
	return &v.perPadding
}
func BridgeERABModifyListBearerModResCompleteFieldReceived(v *ERABModifyListBearerModResComplete) *bool {
	return &v.received
}
func BridgeERABModifyListBearerModResCompleteFieldReceivedAbsolute(v *ERABModifyListBearerModResComplete) *bool {
	return &v.receivedAbsolute
}
func BridgeERABModifyListBearerModResCompleteFieldReceivedBytes(v *ERABModifyListBearerModResComplete) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeERABModifyListBearerModResCompleteFieldReceivedLocation(v *ERABModifyListBearerModResComplete) *aper.Location {
	return &v.receivedLocation
}
func BridgeERABModifyListBearerModResCompleteFieldReplay(v *ERABModifyListBearerModResComplete) *aper.Snapshot {
	return &v.replay
}
func BridgeERABModifyListBearerModResCompleteFieldStream(v *ERABModifyListBearerModResComplete) *aper.WireSpan {
	return &v.stream
}
func BridgeERABModifyListBearerModResCompleteFieldWithoutReplay(v *ERABModifyListBearerModResComplete) *bool {
	return &v.withoutReplay
}
func BridgeERABModifyListBearerModResCompleteMethodMarshalAPERBudget(v *ERABModifyListBearerModResComplete, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeERABModifyListBearerModResCompleteMethodMarshalAPERBudgetValue(v *ERABModifyListBearerModResComplete, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudgetValue(a0, a1)
}
func BridgeERABModifyListBearerModResCompleteMethodMarshalAPERChanged(v *ERABModifyListBearerModResComplete, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeERABModifyListBearerModResCompleteMethodMarshalAPERChangedValue(v *ERABModifyListBearerModResComplete, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeERABModifyListBearerModResCompleteMethodMarshalAPERLegacy(v *ERABModifyListBearerModResComplete) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeERABModifyListBearerModResCompleteMethodMarshalAPERNewValue(v *ERABModifyListBearerModResComplete, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERNewValue(a0, a1)
}
func BridgeERABModifyListBearerModResCompleteMethodMarshalAPERPlanned(v *ERABModifyListBearerModResComplete, a0 *aper.DecodeBudget, a1 bool, a2 *aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1, a2)
}
func BridgeERABModifyListBearerModResCompleteMethodUnmarshalAPERLegacy(v *ERABModifyListBearerModResComplete, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeERABModifyListBearerModResCompleteMethodUnmarshalAPERWithOptions(v *ERABModifyListBearerModResComplete, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeERABNotToBeModifiedListBearerModIndCompleteFieldPerPadding(v *ERABNotToBeModifiedListBearerModIndComplete) *aper.CompletePadding {
	return &v.perPadding
}
func BridgeERABNotToBeModifiedListBearerModIndCompleteFieldReceived(v *ERABNotToBeModifiedListBearerModIndComplete) *bool {
	return &v.received
}
func BridgeERABNotToBeModifiedListBearerModIndCompleteFieldReceivedAbsolute(v *ERABNotToBeModifiedListBearerModIndComplete) *bool {
	return &v.receivedAbsolute
}
func BridgeERABNotToBeModifiedListBearerModIndCompleteFieldReceivedBytes(v *ERABNotToBeModifiedListBearerModIndComplete) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeERABNotToBeModifiedListBearerModIndCompleteFieldReceivedLocation(v *ERABNotToBeModifiedListBearerModIndComplete) *aper.Location {
	return &v.receivedLocation
}
func BridgeERABNotToBeModifiedListBearerModIndCompleteFieldReplay(v *ERABNotToBeModifiedListBearerModIndComplete) *aper.Snapshot {
	return &v.replay
}
func BridgeERABNotToBeModifiedListBearerModIndCompleteFieldStream(v *ERABNotToBeModifiedListBearerModIndComplete) *aper.WireSpan {
	return &v.stream
}
func BridgeERABNotToBeModifiedListBearerModIndCompleteFieldWithoutReplay(v *ERABNotToBeModifiedListBearerModIndComplete) *bool {
	return &v.withoutReplay
}
func BridgeERABNotToBeModifiedListBearerModIndCompleteMethodMarshalAPERBudget(v *ERABNotToBeModifiedListBearerModIndComplete, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeERABNotToBeModifiedListBearerModIndCompleteMethodMarshalAPERBudgetValue(v *ERABNotToBeModifiedListBearerModIndComplete, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudgetValue(a0, a1)
}
func BridgeERABNotToBeModifiedListBearerModIndCompleteMethodMarshalAPERChanged(v *ERABNotToBeModifiedListBearerModIndComplete, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeERABNotToBeModifiedListBearerModIndCompleteMethodMarshalAPERChangedValue(v *ERABNotToBeModifiedListBearerModIndComplete, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeERABNotToBeModifiedListBearerModIndCompleteMethodMarshalAPERLegacy(v *ERABNotToBeModifiedListBearerModIndComplete) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeERABNotToBeModifiedListBearerModIndCompleteMethodMarshalAPERNewValue(v *ERABNotToBeModifiedListBearerModIndComplete, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERNewValue(a0, a1)
}
func BridgeERABNotToBeModifiedListBearerModIndCompleteMethodMarshalAPERPlanned(v *ERABNotToBeModifiedListBearerModIndComplete, a0 *aper.DecodeBudget, a1 bool, a2 *aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1, a2)
}
func BridgeERABNotToBeModifiedListBearerModIndCompleteMethodUnmarshalAPERLegacy(v *ERABNotToBeModifiedListBearerModIndComplete, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeERABNotToBeModifiedListBearerModIndCompleteMethodUnmarshalAPERWithOptions(v *ERABNotToBeModifiedListBearerModIndComplete, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeERABReleaseCommandAPERValueFieldContext(v *ERABReleaseCommandAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABReleaseCommandAPERValueFieldReceived(v *ERABReleaseCommandAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeERABReleaseCommandAPERValueFieldReplay(v *ERABReleaseCommandAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeERABReleaseCommandAPERValueFieldWithoutReplay(v *ERABReleaseCommandAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeERABReleaseCommandENBUES1APIDIEBindingFieldCodec(v *ERABReleaseCommandENBUES1APIDIEBinding) *s00.ENBUES1APIDValueCodec {
	return &v.codec
}
func BridgeERABReleaseCommandENBUES1APIDIEBindingFieldGet(v *ERABReleaseCommandENBUES1APIDIEBinding) *func(*ERABReleaseCommandIEValue) (*s00.ENBUES1APID, bool) {
	return &v.get
}
func BridgeERABReleaseCommandENBUES1APIDIEBindingFieldInfo(v *ERABReleaseCommandENBUES1APIDIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeERABReleaseCommandENBUES1APIDIEBindingFieldInject(v *ERABReleaseCommandENBUES1APIDIEBinding) *func(s00.ENBUES1APID) ERABReleaseCommandIEValue {
	return &v.inject
}
func BridgeERABReleaseCommandERABListIEBindingFieldCodec(v *ERABReleaseCommandERABListIEBinding) *s16.ERABListValueCodec {
	return &v.codec
}
func BridgeERABReleaseCommandERABListIEBindingFieldGet(v *ERABReleaseCommandERABListIEBinding) *func(*ERABReleaseCommandIEValue) (*s16.ERABList, bool) {
	return &v.get
}
func BridgeERABReleaseCommandERABListIEBindingFieldInfo(v *ERABReleaseCommandERABListIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeERABReleaseCommandERABListIEBindingFieldInject(v *ERABReleaseCommandERABListIEBinding) *func(s16.ERABList) ERABReleaseCommandIEValue {
	return &v.inject
}
func BridgeERABReleaseCommandFieldExtCount(v *ERABReleaseCommand) *int64   { return &v.extCount }
func BridgeERABReleaseCommandFieldExtData(v *ERABReleaseCommand) *[][]byte { return &v.extData }
func BridgeERABReleaseCommandFieldExtOrigin(v *ERABReleaseCommand) *[]aper.OpaqueOrigin {
	return &v.extOrigin
}
func BridgeERABReleaseCommandFieldExtPresent(v *ERABReleaseCommand) *[]bool       { return &v.extPresent }
func BridgeERABReleaseCommandFieldExtWire(v *ERABReleaseCommand) *[]aper.WireSpan { return &v.extWire }
func BridgeERABReleaseCommandFieldPerExtPadding(v *ERABReleaseCommand) *[]aper.CompletePadding {
	return &v.perExtPadding
}
func BridgeERABReleaseCommandFieldPerPadding(v *ERABReleaseCommand) *aper.FinalPadding {
	return &v.perPadding
}
func BridgeERABReleaseCommandFieldProtocolIEsIndef(v *ERABReleaseCommand) *bool {
	return &v.protocolIEsIndef
}
func BridgeERABReleaseCommandFieldReceived(v *ERABReleaseCommand) *bool { return &v.received }
func BridgeERABReleaseCommandFieldReceivedAbsolute(v *ERABReleaseCommand) *bool {
	return &v.receivedAbsolute
}
func BridgeERABReleaseCommandFieldReceivedBytes(v *ERABReleaseCommand) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeERABReleaseCommandFieldReceivedLocation(v *ERABReleaseCommand) *aper.Location {
	return &v.receivedLocation
}
func BridgeERABReleaseCommandFieldReplay(v *ERABReleaseCommand) *aper.Snapshot { return &v.replay }
func BridgeERABReleaseCommandFieldStream(v *ERABReleaseCommand) *aper.WireSpan { return &v.stream }
func BridgeERABReleaseCommandFieldWithoutReplay(v *ERABReleaseCommand) *bool   { return &v.withoutReplay }
func BridgeERABReleaseCommandIEContainerAPERValueFieldContext(v *ERABReleaseCommandIEContainerAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABReleaseCommandIEContainerAPERValueFieldReceived(v *ERABReleaseCommandIEContainerAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeERABReleaseCommandIEContainerAPERValueFieldReplay(v *ERABReleaseCommandIEContainerAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeERABReleaseCommandIEContainerAPERValueFieldWithoutReplay(v *ERABReleaseCommandIEContainerAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeERABReleaseCommandIEContainerValueCodecFieldCapture(v *ERABReleaseCommandIEContainerValueCodec) *func(ERABReleaseCommandIEContainer, aper.DecodeState) (ERABReleaseCommandIEContainer, aper.Snapshot) {
	return &v.capture
}
func BridgeERABReleaseCommandIEContainerValueCodecFieldCompare(v *ERABReleaseCommandIEContainerValueCodec) *func(ERABReleaseCommandIEContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeERABReleaseCommandIEContainerValueCodecFieldContext(v *ERABReleaseCommandIEContainerValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABReleaseCommandIEContainerValueCodecFieldDecode(v *ERABReleaseCommandIEContainerValueCodec) *func([]byte, aper.DecodeState) (ERABReleaseCommandIEContainer, error) {
	return &v.decode
}
func BridgeERABReleaseCommandIEContainerValueCodecFieldEncode(v *ERABReleaseCommandIEContainerValueCodec) *func(ERABReleaseCommandIEContainer, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeERABReleaseCommandIEContainerValueCodecFieldPath(v *ERABReleaseCommandIEContainerValueCodec) *aper.Path {
	return &v.path
}
func BridgeERABReleaseCommandIEContainerValueCodecMethodEncodeBudgetValue(v ERABReleaseCommandIEContainerValueCodec, a0 ERABReleaseCommandIEContainer, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeERABReleaseCommandIEContainerValueCodecMethodEncodeChanged(v ERABReleaseCommandIEContainerValueCodec, a0 ERABReleaseCommandIEContainer, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeERABReleaseCommandIEFieldAPERValueFieldContext(v *ERABReleaseCommandIEFieldAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABReleaseCommandIEFieldAPERValueFieldReceived(v *ERABReleaseCommandIEFieldAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeERABReleaseCommandIEFieldAPERValueFieldReplay(v *ERABReleaseCommandIEFieldAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeERABReleaseCommandIEFieldAPERValueFieldWithoutReplay(v *ERABReleaseCommandIEFieldAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeERABReleaseCommandIEFieldFieldReceived(v *ERABReleaseCommandIEField) *aper.CompletePadding {
	return &v.received
}
func BridgeERABReleaseCommandIEFieldFieldReplay(v *ERABReleaseCommandIEField) *aper.Snapshot {
	return &v.replay
}
func BridgeERABReleaseCommandIEFieldFieldStream(v *ERABReleaseCommandIEField) *aper.WireSpan {
	return &v.stream
}
func BridgeERABReleaseCommandIEFieldFieldWithoutReplay(v *ERABReleaseCommandIEField) *bool {
	return &v.withoutReplay
}
func BridgeERABReleaseCommandIEFieldMethodMarshalAPERTo(v *ERABReleaseCommandIEField, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeERABReleaseCommandIEFieldMethodUnmarshalAPERFrom(v *ERABReleaseCommandIEField, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeERABReleaseCommandIEFieldValueCodecFieldCapture(v *ERABReleaseCommandIEFieldValueCodec) *func(ERABReleaseCommandIEField, aper.DecodeState) (ERABReleaseCommandIEField, aper.Snapshot) {
	return &v.capture
}
func BridgeERABReleaseCommandIEFieldValueCodecFieldCompare(v *ERABReleaseCommandIEFieldValueCodec) *func(ERABReleaseCommandIEField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeERABReleaseCommandIEFieldValueCodecFieldContext(v *ERABReleaseCommandIEFieldValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABReleaseCommandIEFieldValueCodecFieldDecode(v *ERABReleaseCommandIEFieldValueCodec) *func([]byte, aper.DecodeState) (ERABReleaseCommandIEField, error) {
	return &v.decode
}
func BridgeERABReleaseCommandIEFieldValueCodecFieldEncode(v *ERABReleaseCommandIEFieldValueCodec) *func(ERABReleaseCommandIEField, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeERABReleaseCommandIEFieldValueCodecFieldPath(v *ERABReleaseCommandIEFieldValueCodec) *aper.Path {
	return &v.path
}
func BridgeERABReleaseCommandIEFieldValueCodecMethodEncodeBudgetValue(v ERABReleaseCommandIEFieldValueCodec, a0 ERABReleaseCommandIEField, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeERABReleaseCommandIEFieldValueCodecMethodEncodeChanged(v ERABReleaseCommandIEFieldValueCodec, a0 ERABReleaseCommandIEField, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeERABReleaseCommandIETableMethodInfoENBUES1APID(v ERABReleaseCommandIETable) s00.FieldInfo {
	return v.infoENBUES1APID()
}
func BridgeERABReleaseCommandIETableMethodInfoERABToBeReleasedList(v ERABReleaseCommandIETable) s00.FieldInfo {
	return v.infoERABToBeReleasedList()
}
func BridgeERABReleaseCommandIETableMethodInfoMMEUES1APID(v ERABReleaseCommandIETable) s00.FieldInfo {
	return v.infoMMEUES1APID()
}
func BridgeERABReleaseCommandIETableMethodInfoNASPDU(v ERABReleaseCommandIETable) s00.FieldInfo {
	return v.infoNASPDU()
}
func BridgeERABReleaseCommandIETableMethodInfoUEaggregateMaximumBitrate(v ERABReleaseCommandIETable) s00.FieldInfo {
	return v.infoUEaggregateMaximumBitrate()
}
func BridgeERABReleaseCommandIEValueERABIEContainerListAPERValueFieldContext(v *ERABReleaseCommandIEValueERABIEContainerListAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABReleaseCommandIEValueERABIEContainerListAPERValueFieldReceived(v *ERABReleaseCommandIEValueERABIEContainerListAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeERABReleaseCommandIEValueERABIEContainerListAPERValueFieldReplay(v *ERABReleaseCommandIEValueERABIEContainerListAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeERABReleaseCommandIEValueERABIEContainerListAPERValueFieldWithoutReplay(v *ERABReleaseCommandIEValueERABIEContainerListAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeERABReleaseCommandIEValueERABIEContainerListValueCodecFieldCapture(v *ERABReleaseCommandIEValueERABIEContainerListValueCodec) *func(ERABReleaseCommandIEValueERABIEContainerList, aper.DecodeState) (ERABReleaseCommandIEValueERABIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgeERABReleaseCommandIEValueERABIEContainerListValueCodecFieldCompare(v *ERABReleaseCommandIEValueERABIEContainerListValueCodec) *func(ERABReleaseCommandIEValueERABIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeERABReleaseCommandIEValueERABIEContainerListValueCodecFieldContext(v *ERABReleaseCommandIEValueERABIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABReleaseCommandIEValueERABIEContainerListValueCodecFieldDecode(v *ERABReleaseCommandIEValueERABIEContainerListValueCodec) *func([]byte, aper.DecodeState) (ERABReleaseCommandIEValueERABIEContainerList, error) {
	return &v.decode
}
func BridgeERABReleaseCommandIEValueERABIEContainerListValueCodecFieldEncode(v *ERABReleaseCommandIEValueERABIEContainerListValueCodec) *func(ERABReleaseCommandIEValueERABIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeERABReleaseCommandIEValueERABIEContainerListValueCodecFieldPath(v *ERABReleaseCommandIEValueERABIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgeERABReleaseCommandIEValueERABIEContainerListValueCodecMethodEncodeBudgetValue(v ERABReleaseCommandIEValueERABIEContainerListValueCodec, a0 ERABReleaseCommandIEValueERABIEContainerList, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeERABReleaseCommandIEValueERABIEContainerListValueCodecMethodEncodeChanged(v ERABReleaseCommandIEValueERABIEContainerListValueCodec, a0 ERABReleaseCommandIEValueERABIEContainerList, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeERABReleaseCommandIEValueFieldId(v *ERABReleaseCommandIEValue) *s00.ProtocolIEID {
	return &v.id
}
func BridgeERABReleaseCommandIEValueFieldIsOpaque(v *ERABReleaseCommandIEValue) *bool {
	return &v.isOpaque
}
func BridgeERABReleaseCommandIEValueFieldOpaque(v *ERABReleaseCommandIEValue) *aper.OpaqueOpenType {
	return &v.opaque
}
func BridgeERABReleaseCommandIEValueFieldReceived(v *ERABReleaseCommandIEValue) *aper.WireSpan {
	return &v.received
}
func BridgeERABReleaseCommandIEValueFieldReplay(v *ERABReleaseCommandIEValue) *aper.Snapshot {
	return &v.replay
}
func BridgeERABReleaseCommandIEValueFieldRowENBUES1APID(v *ERABReleaseCommandIEValue) **s00.ENBUES1APID {
	return &v.rowENBUES1APID
}
func BridgeERABReleaseCommandIEValueFieldRowERABToBeReleasedList(v *ERABReleaseCommandIEValue) **s16.ERABList {
	return &v.rowERABToBeReleasedList
}
func BridgeERABReleaseCommandIEValueFieldRowMMEUES1APID(v *ERABReleaseCommandIEValue) **s00.MMEUES1APID {
	return &v.rowMMEUES1APID
}
func BridgeERABReleaseCommandIEValueFieldRowNASPDU(v *ERABReleaseCommandIEValue) **s00.NASPDU {
	return &v.rowNASPDU
}
func BridgeERABReleaseCommandIEValueFieldRowUEaggregateMaximumBitrate(v *ERABReleaseCommandIEValue) **s35.UEAggregateMaximumBitrate {
	return &v.rowUEaggregateMaximumBitrate
}
func BridgeERABReleaseCommandIEValueMethodCaptureSemantics(v ERABReleaseCommandIEValue, a0 aper.SemanticCapture) ERABReleaseCommandIEValue {
	return v.captureSemantics(a0)
}
func BridgeERABReleaseCommandIEValueMethodCompareSemantics(v ERABReleaseCommandIEValue, a0 aper.SemanticComparison) aper.SemanticComparison {
	return v.compareSemantics(a0)
}
func BridgeERABReleaseCommandIEValueMethodDecode(v ERABReleaseCommandIEValue, a0 s00.ProtocolIEID, a1 aper.OpaqueOpenType) (ERABReleaseCommandIEValue, error) {
	return v.decode(a0, a1)
}
func BridgeERABReleaseCommandIEValueMethodEncode(v ERABReleaseCommandIEValue) ([]byte, error) {
	return v.encode()
}
func BridgeERABReleaseCommandIEValueMethodEncodeFresh(v ERABReleaseCommandIEValue, a0 bool, a1 *aper.DecodeBudget) ([]byte, error) {
	return v.encodeFresh(a0, a1)
}
func BridgeERABReleaseCommandIEValueMethodMatchesID(v ERABReleaseCommandIEValue, a0 s00.ProtocolIEID, a1 ...*aper.DecodeBudget) bool {
	return v.matchesID(a0, a1...)
}
func BridgeERABReleaseCommandIEValueMethodReason(v ERABReleaseCommandIEValue, a0 s00.ProtocolIEID) aper.OpaqueReason {
	return v.reason(a0)
}
func BridgeERABReleaseCommandIEValueMethodRule(v ERABReleaseCommandIEValue) aper.SourceRule {
	return v.rule()
}
func BridgeERABReleaseCommandIEValueProtocolErrorIEContainerListAPERValueFieldContext(v *ERABReleaseCommandIEValueProtocolErrorIEContainerListAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABReleaseCommandIEValueProtocolErrorIEContainerListAPERValueFieldReceived(v *ERABReleaseCommandIEValueProtocolErrorIEContainerListAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeERABReleaseCommandIEValueProtocolErrorIEContainerListAPERValueFieldReplay(v *ERABReleaseCommandIEValueProtocolErrorIEContainerListAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeERABReleaseCommandIEValueProtocolErrorIEContainerListAPERValueFieldWithoutReplay(v *ERABReleaseCommandIEValueProtocolErrorIEContainerListAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeERABReleaseCommandIEValueProtocolErrorIEContainerListValueCodecFieldCapture(v *ERABReleaseCommandIEValueProtocolErrorIEContainerListValueCodec) *func(ERABReleaseCommandIEValueProtocolErrorIEContainerList, aper.DecodeState) (ERABReleaseCommandIEValueProtocolErrorIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgeERABReleaseCommandIEValueProtocolErrorIEContainerListValueCodecFieldCompare(v *ERABReleaseCommandIEValueProtocolErrorIEContainerListValueCodec) *func(ERABReleaseCommandIEValueProtocolErrorIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeERABReleaseCommandIEValueProtocolErrorIEContainerListValueCodecFieldContext(v *ERABReleaseCommandIEValueProtocolErrorIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABReleaseCommandIEValueProtocolErrorIEContainerListValueCodecFieldDecode(v *ERABReleaseCommandIEValueProtocolErrorIEContainerListValueCodec) *func([]byte, aper.DecodeState) (ERABReleaseCommandIEValueProtocolErrorIEContainerList, error) {
	return &v.decode
}
func BridgeERABReleaseCommandIEValueProtocolErrorIEContainerListValueCodecFieldEncode(v *ERABReleaseCommandIEValueProtocolErrorIEContainerListValueCodec) *func(ERABReleaseCommandIEValueProtocolErrorIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeERABReleaseCommandIEValueProtocolErrorIEContainerListValueCodecFieldPath(v *ERABReleaseCommandIEValueProtocolErrorIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgeERABReleaseCommandIEValueProtocolErrorIEContainerListValueCodecMethodEncodeBudgetValue(v ERABReleaseCommandIEValueProtocolErrorIEContainerListValueCodec, a0 ERABReleaseCommandIEValueProtocolErrorIEContainerList, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeERABReleaseCommandIEValueProtocolErrorIEContainerListValueCodecMethodEncodeChanged(v ERABReleaseCommandIEValueProtocolErrorIEContainerListValueCodec, a0 ERABReleaseCommandIEValueProtocolErrorIEContainerList, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeERABReleaseCommandIEValueProtocolIEContainerListAPERValueFieldContext(v *ERABReleaseCommandIEValueProtocolIEContainerListAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABReleaseCommandIEValueProtocolIEContainerListAPERValueFieldReceived(v *ERABReleaseCommandIEValueProtocolIEContainerListAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeERABReleaseCommandIEValueProtocolIEContainerListAPERValueFieldReplay(v *ERABReleaseCommandIEValueProtocolIEContainerListAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeERABReleaseCommandIEValueProtocolIEContainerListAPERValueFieldWithoutReplay(v *ERABReleaseCommandIEValueProtocolIEContainerListAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeERABReleaseCommandIEValueProtocolIEContainerListValueCodecFieldCapture(v *ERABReleaseCommandIEValueProtocolIEContainerListValueCodec) *func(ERABReleaseCommandIEValueProtocolIEContainerList, aper.DecodeState) (ERABReleaseCommandIEValueProtocolIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgeERABReleaseCommandIEValueProtocolIEContainerListValueCodecFieldCompare(v *ERABReleaseCommandIEValueProtocolIEContainerListValueCodec) *func(ERABReleaseCommandIEValueProtocolIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeERABReleaseCommandIEValueProtocolIEContainerListValueCodecFieldContext(v *ERABReleaseCommandIEValueProtocolIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABReleaseCommandIEValueProtocolIEContainerListValueCodecFieldDecode(v *ERABReleaseCommandIEValueProtocolIEContainerListValueCodec) *func([]byte, aper.DecodeState) (ERABReleaseCommandIEValueProtocolIEContainerList, error) {
	return &v.decode
}
func BridgeERABReleaseCommandIEValueProtocolIEContainerListValueCodecFieldEncode(v *ERABReleaseCommandIEValueProtocolIEContainerListValueCodec) *func(ERABReleaseCommandIEValueProtocolIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeERABReleaseCommandIEValueProtocolIEContainerListValueCodecFieldPath(v *ERABReleaseCommandIEValueProtocolIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgeERABReleaseCommandIEValueProtocolIEContainerListValueCodecMethodEncodeBudgetValue(v ERABReleaseCommandIEValueProtocolIEContainerListValueCodec, a0 ERABReleaseCommandIEValueProtocolIEContainerList, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeERABReleaseCommandIEValueProtocolIEContainerListValueCodecMethodEncodeChanged(v ERABReleaseCommandIEValueProtocolIEContainerListValueCodec, a0 ERABReleaseCommandIEValueProtocolIEContainerList, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeERABReleaseCommandMMEUES1APIDIEBindingFieldCodec(v *ERABReleaseCommandMMEUES1APIDIEBinding) *s01.MMEUES1APIDValueCodec {
	return &v.codec
}
func BridgeERABReleaseCommandMMEUES1APIDIEBindingFieldGet(v *ERABReleaseCommandMMEUES1APIDIEBinding) *func(*ERABReleaseCommandIEValue) (*s00.MMEUES1APID, bool) {
	return &v.get
}
func BridgeERABReleaseCommandMMEUES1APIDIEBindingFieldInfo(v *ERABReleaseCommandMMEUES1APIDIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeERABReleaseCommandMMEUES1APIDIEBindingFieldInject(v *ERABReleaseCommandMMEUES1APIDIEBinding) *func(s00.MMEUES1APID) ERABReleaseCommandIEValue {
	return &v.inject
}
func BridgeERABReleaseCommandMethodMarshalAPERBudget(v *ERABReleaseCommand, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeERABReleaseCommandMethodMarshalAPERBudgetValue(v *ERABReleaseCommand, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudgetValue(a0, a1)
}
func BridgeERABReleaseCommandMethodMarshalAPERChanged(v *ERABReleaseCommand, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeERABReleaseCommandMethodMarshalAPERChangedValue(v *ERABReleaseCommand, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeERABReleaseCommandMethodMarshalAPERLegacy(v *ERABReleaseCommand) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeERABReleaseCommandMethodMarshalAPERNewValue(v *ERABReleaseCommand, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERNewValue(a0, a1)
}
func BridgeERABReleaseCommandMethodMarshalAPERPlanned(v *ERABReleaseCommand, a0 *aper.DecodeBudget, a1 bool, a2 *aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1, a2)
}
func BridgeERABReleaseCommandMethodMarshalAPERTo(v *ERABReleaseCommand, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeERABReleaseCommandMethodUnmarshalAPERFrom(v *ERABReleaseCommand, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeERABReleaseCommandMethodUnmarshalAPERLegacy(v *ERABReleaseCommand, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeERABReleaseCommandMethodUnmarshalAPERWithOptions(v *ERABReleaseCommand, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeERABReleaseCommandNASPDUIEBindingFieldCodec(v *ERABReleaseCommandNASPDUIEBinding) *s01.NASPDUValueCodec {
	return &v.codec
}
func BridgeERABReleaseCommandNASPDUIEBindingFieldGet(v *ERABReleaseCommandNASPDUIEBinding) *func(*ERABReleaseCommandIEValue) (*s00.NASPDU, bool) {
	return &v.get
}
func BridgeERABReleaseCommandNASPDUIEBindingFieldInfo(v *ERABReleaseCommandNASPDUIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeERABReleaseCommandNASPDUIEBindingFieldInject(v *ERABReleaseCommandNASPDUIEBinding) *func(s00.NASPDU) ERABReleaseCommandIEValue {
	return &v.inject
}
func BridgeERABReleaseCommandUEAggregateMaximumBitrateIEBindingFieldCodec(v *ERABReleaseCommandUEAggregateMaximumBitrateIEBinding) *s35.UEAggregateMaximumBitrateValueCodec {
	return &v.codec
}
func BridgeERABReleaseCommandUEAggregateMaximumBitrateIEBindingFieldGet(v *ERABReleaseCommandUEAggregateMaximumBitrateIEBinding) *func(*ERABReleaseCommandIEValue) (*s35.UEAggregateMaximumBitrate, bool) {
	return &v.get
}
func BridgeERABReleaseCommandUEAggregateMaximumBitrateIEBindingFieldInfo(v *ERABReleaseCommandUEAggregateMaximumBitrateIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeERABReleaseCommandUEAggregateMaximumBitrateIEBindingFieldInject(v *ERABReleaseCommandUEAggregateMaximumBitrateIEBinding) *func(s35.UEAggregateMaximumBitrate) ERABReleaseCommandIEValue {
	return &v.inject
}
func BridgeERABReleaseCommandValueCodecFieldCapture(v *ERABReleaseCommandValueCodec) *func(ERABReleaseCommand, aper.DecodeState) (ERABReleaseCommand, aper.Snapshot) {
	return &v.capture
}
func BridgeERABReleaseCommandValueCodecFieldCompare(v *ERABReleaseCommandValueCodec) *func(ERABReleaseCommand, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeERABReleaseCommandValueCodecFieldContext(v *ERABReleaseCommandValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABReleaseCommandValueCodecFieldDecode(v *ERABReleaseCommandValueCodec) *func([]byte, aper.DecodeState) (ERABReleaseCommand, error) {
	return &v.decode
}
func BridgeERABReleaseCommandValueCodecFieldEncode(v *ERABReleaseCommandValueCodec) *func(ERABReleaseCommand, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeERABReleaseCommandValueCodecFieldPath(v *ERABReleaseCommandValueCodec) *aper.Path {
	return &v.path
}
func BridgeERABReleaseCommandValueCodecMethodEncodeBudgetValue(v ERABReleaseCommandValueCodec, a0 ERABReleaseCommand, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeERABReleaseCommandValueCodecMethodEncodeChanged(v ERABReleaseCommandValueCodec, a0 ERABReleaseCommand, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeERABReleaseListBearerRelCompCompleteFieldPerPadding(v *ERABReleaseListBearerRelCompComplete) *aper.CompletePadding {
	return &v.perPadding
}
func BridgeERABReleaseListBearerRelCompCompleteFieldReceived(v *ERABReleaseListBearerRelCompComplete) *bool {
	return &v.received
}
func BridgeERABReleaseListBearerRelCompCompleteFieldReceivedAbsolute(v *ERABReleaseListBearerRelCompComplete) *bool {
	return &v.receivedAbsolute
}
func BridgeERABReleaseListBearerRelCompCompleteFieldReceivedBytes(v *ERABReleaseListBearerRelCompComplete) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeERABReleaseListBearerRelCompCompleteFieldReceivedLocation(v *ERABReleaseListBearerRelCompComplete) *aper.Location {
	return &v.receivedLocation
}
func BridgeERABReleaseListBearerRelCompCompleteFieldReplay(v *ERABReleaseListBearerRelCompComplete) *aper.Snapshot {
	return &v.replay
}
func BridgeERABReleaseListBearerRelCompCompleteFieldStream(v *ERABReleaseListBearerRelCompComplete) *aper.WireSpan {
	return &v.stream
}
func BridgeERABReleaseListBearerRelCompCompleteFieldWithoutReplay(v *ERABReleaseListBearerRelCompComplete) *bool {
	return &v.withoutReplay
}
func BridgeERABReleaseListBearerRelCompCompleteMethodMarshalAPERBudget(v *ERABReleaseListBearerRelCompComplete, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeERABReleaseListBearerRelCompCompleteMethodMarshalAPERBudgetValue(v *ERABReleaseListBearerRelCompComplete, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudgetValue(a0, a1)
}
func BridgeERABReleaseListBearerRelCompCompleteMethodMarshalAPERChanged(v *ERABReleaseListBearerRelCompComplete, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeERABReleaseListBearerRelCompCompleteMethodMarshalAPERChangedValue(v *ERABReleaseListBearerRelCompComplete, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeERABReleaseListBearerRelCompCompleteMethodMarshalAPERLegacy(v *ERABReleaseListBearerRelCompComplete) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeERABReleaseListBearerRelCompCompleteMethodMarshalAPERNewValue(v *ERABReleaseListBearerRelCompComplete, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERNewValue(a0, a1)
}
func BridgeERABReleaseListBearerRelCompCompleteMethodMarshalAPERPlanned(v *ERABReleaseListBearerRelCompComplete, a0 *aper.DecodeBudget, a1 bool, a2 *aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1, a2)
}
func BridgeERABReleaseListBearerRelCompCompleteMethodUnmarshalAPERLegacy(v *ERABReleaseListBearerRelCompComplete, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeERABReleaseListBearerRelCompCompleteMethodUnmarshalAPERWithOptions(v *ERABReleaseListBearerRelCompComplete, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeERABSecurityResultListCompleteFieldPerPadding(v *ERABSecurityResultListComplete) *aper.CompletePadding {
	return &v.perPadding
}
func BridgeERABSecurityResultListCompleteFieldReceived(v *ERABSecurityResultListComplete) *bool {
	return &v.received
}
func BridgeERABSecurityResultListCompleteFieldReceivedAbsolute(v *ERABSecurityResultListComplete) *bool {
	return &v.receivedAbsolute
}
func BridgeERABSecurityResultListCompleteFieldReceivedBytes(v *ERABSecurityResultListComplete) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeERABSecurityResultListCompleteFieldReceivedLocation(v *ERABSecurityResultListComplete) *aper.Location {
	return &v.receivedLocation
}
func BridgeERABSecurityResultListCompleteFieldReplay(v *ERABSecurityResultListComplete) *aper.Snapshot {
	return &v.replay
}
func BridgeERABSecurityResultListCompleteFieldStream(v *ERABSecurityResultListComplete) *aper.WireSpan {
	return &v.stream
}
func BridgeERABSecurityResultListCompleteFieldWithoutReplay(v *ERABSecurityResultListComplete) *bool {
	return &v.withoutReplay
}
func BridgeERABSecurityResultListCompleteMethodMarshalAPERBudget(v *ERABSecurityResultListComplete, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeERABSecurityResultListCompleteMethodMarshalAPERBudgetValue(v *ERABSecurityResultListComplete, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudgetValue(a0, a1)
}
func BridgeERABSecurityResultListCompleteMethodMarshalAPERChanged(v *ERABSecurityResultListComplete, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeERABSecurityResultListCompleteMethodMarshalAPERChangedValue(v *ERABSecurityResultListComplete, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeERABSecurityResultListCompleteMethodMarshalAPERLegacy(v *ERABSecurityResultListComplete) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeERABSecurityResultListCompleteMethodMarshalAPERNewValue(v *ERABSecurityResultListComplete, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERNewValue(a0, a1)
}
func BridgeERABSecurityResultListCompleteMethodMarshalAPERPlanned(v *ERABSecurityResultListComplete, a0 *aper.DecodeBudget, a1 bool, a2 *aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1, a2)
}
func BridgeERABSecurityResultListCompleteMethodUnmarshalAPERLegacy(v *ERABSecurityResultListComplete, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeERABSecurityResultListCompleteMethodUnmarshalAPERWithOptions(v *ERABSecurityResultListComplete, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeERABSetupListBearerSUResCompleteFieldPerPadding(v *ERABSetupListBearerSUResComplete) *aper.CompletePadding {
	return &v.perPadding
}
func BridgeERABSetupListBearerSUResCompleteFieldReceived(v *ERABSetupListBearerSUResComplete) *bool {
	return &v.received
}
func BridgeERABSetupListBearerSUResCompleteFieldReceivedAbsolute(v *ERABSetupListBearerSUResComplete) *bool {
	return &v.receivedAbsolute
}
func BridgeERABSetupListBearerSUResCompleteFieldReceivedBytes(v *ERABSetupListBearerSUResComplete) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeERABSetupListBearerSUResCompleteFieldReceivedLocation(v *ERABSetupListBearerSUResComplete) *aper.Location {
	return &v.receivedLocation
}
func BridgeERABSetupListBearerSUResCompleteFieldReplay(v *ERABSetupListBearerSUResComplete) *aper.Snapshot {
	return &v.replay
}
func BridgeERABSetupListBearerSUResCompleteFieldStream(v *ERABSetupListBearerSUResComplete) *aper.WireSpan {
	return &v.stream
}
func BridgeERABSetupListBearerSUResCompleteFieldWithoutReplay(v *ERABSetupListBearerSUResComplete) *bool {
	return &v.withoutReplay
}
func BridgeERABSetupListBearerSUResCompleteMethodMarshalAPERBudget(v *ERABSetupListBearerSUResComplete, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeERABSetupListBearerSUResCompleteMethodMarshalAPERBudgetValue(v *ERABSetupListBearerSUResComplete, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudgetValue(a0, a1)
}
func BridgeERABSetupListBearerSUResCompleteMethodMarshalAPERChanged(v *ERABSetupListBearerSUResComplete, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeERABSetupListBearerSUResCompleteMethodMarshalAPERChangedValue(v *ERABSetupListBearerSUResComplete, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeERABSetupListBearerSUResCompleteMethodMarshalAPERLegacy(v *ERABSetupListBearerSUResComplete) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeERABSetupListBearerSUResCompleteMethodMarshalAPERNewValue(v *ERABSetupListBearerSUResComplete, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERNewValue(a0, a1)
}
func BridgeERABSetupListBearerSUResCompleteMethodMarshalAPERPlanned(v *ERABSetupListBearerSUResComplete, a0 *aper.DecodeBudget, a1 bool, a2 *aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1, a2)
}
func BridgeERABSetupListBearerSUResCompleteMethodUnmarshalAPERLegacy(v *ERABSetupListBearerSUResComplete, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeERABSetupListBearerSUResCompleteMethodUnmarshalAPERWithOptions(v *ERABSetupListBearerSUResComplete, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeERABSetupListCtxtSUResCompleteFieldPerPadding(v *ERABSetupListCtxtSUResComplete) *aper.CompletePadding {
	return &v.perPadding
}
func BridgeERABSetupListCtxtSUResCompleteFieldReceived(v *ERABSetupListCtxtSUResComplete) *bool {
	return &v.received
}
func BridgeERABSetupListCtxtSUResCompleteFieldReceivedAbsolute(v *ERABSetupListCtxtSUResComplete) *bool {
	return &v.receivedAbsolute
}
func BridgeERABSetupListCtxtSUResCompleteFieldReceivedBytes(v *ERABSetupListCtxtSUResComplete) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeERABSetupListCtxtSUResCompleteFieldReceivedLocation(v *ERABSetupListCtxtSUResComplete) *aper.Location {
	return &v.receivedLocation
}
func BridgeERABSetupListCtxtSUResCompleteFieldReplay(v *ERABSetupListCtxtSUResComplete) *aper.Snapshot {
	return &v.replay
}
func BridgeERABSetupListCtxtSUResCompleteFieldStream(v *ERABSetupListCtxtSUResComplete) *aper.WireSpan {
	return &v.stream
}
func BridgeERABSetupListCtxtSUResCompleteFieldWithoutReplay(v *ERABSetupListCtxtSUResComplete) *bool {
	return &v.withoutReplay
}
func BridgeERABSetupListCtxtSUResCompleteMethodMarshalAPERBudget(v *ERABSetupListCtxtSUResComplete, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeERABSetupListCtxtSUResCompleteMethodMarshalAPERBudgetValue(v *ERABSetupListCtxtSUResComplete, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudgetValue(a0, a1)
}
func BridgeERABSetupListCtxtSUResCompleteMethodMarshalAPERChanged(v *ERABSetupListCtxtSUResComplete, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeERABSetupListCtxtSUResCompleteMethodMarshalAPERChangedValue(v *ERABSetupListCtxtSUResComplete, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeERABSetupListCtxtSUResCompleteMethodMarshalAPERLegacy(v *ERABSetupListCtxtSUResComplete) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeERABSetupListCtxtSUResCompleteMethodMarshalAPERNewValue(v *ERABSetupListCtxtSUResComplete, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERNewValue(a0, a1)
}
func BridgeERABSetupListCtxtSUResCompleteMethodMarshalAPERPlanned(v *ERABSetupListCtxtSUResComplete, a0 *aper.DecodeBudget, a1 bool, a2 *aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1, a2)
}
func BridgeERABSetupListCtxtSUResCompleteMethodUnmarshalAPERLegacy(v *ERABSetupListCtxtSUResComplete, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeERABSetupListCtxtSUResCompleteMethodUnmarshalAPERWithOptions(v *ERABSetupListCtxtSUResComplete, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeHandoverRequestAcknowledgeAPERValueFieldContext(v *HandoverRequestAcknowledgeAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeHandoverRequestAcknowledgeAPERValueFieldReceived(v *HandoverRequestAcknowledgeAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeHandoverRequestAcknowledgeAPERValueFieldReplay(v *HandoverRequestAcknowledgeAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeHandoverRequestAcknowledgeAPERValueFieldWithoutReplay(v *HandoverRequestAcknowledgeAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeHandoverRequestAcknowledgeCEModeBSupportIndicatorIEBindingFieldCodec(v *HandoverRequestAcknowledgeCEModeBSupportIndicatorIEBinding) *s00.CEModeBSupportIndicatorValueCodec {
	return &v.codec
}
func BridgeHandoverRequestAcknowledgeCEModeBSupportIndicatorIEBindingFieldGet(v *HandoverRequestAcknowledgeCEModeBSupportIndicatorIEBinding) *func(*HandoverRequestAcknowledgeIEValue) (*s00.CEModeBSupportIndicator, bool) {
	return &v.get
}
func BridgeHandoverRequestAcknowledgeCEModeBSupportIndicatorIEBindingFieldInfo(v *HandoverRequestAcknowledgeCEModeBSupportIndicatorIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeHandoverRequestAcknowledgeCEModeBSupportIndicatorIEBindingFieldInject(v *HandoverRequestAcknowledgeCEModeBSupportIndicatorIEBinding) *func(s00.CEModeBSupportIndicator) HandoverRequestAcknowledgeIEValue {
	return &v.inject
}
func BridgeHandoverRequestAcknowledgeCSGIdIEBindingFieldCodec(v *HandoverRequestAcknowledgeCSGIdIEBinding) *s00.CSGIdValueCodec {
	return &v.codec
}
func BridgeHandoverRequestAcknowledgeCSGIdIEBindingFieldGet(v *HandoverRequestAcknowledgeCSGIdIEBinding) *func(*HandoverRequestAcknowledgeIEValue) (*s00.CSGId, bool) {
	return &v.get
}
func BridgeHandoverRequestAcknowledgeCSGIdIEBindingFieldInfo(v *HandoverRequestAcknowledgeCSGIdIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeHandoverRequestAcknowledgeCSGIdIEBindingFieldInject(v *HandoverRequestAcknowledgeCSGIdIEBinding) *func(s00.CSGId) HandoverRequestAcknowledgeIEValue {
	return &v.inject
}
func BridgeHandoverRequestAcknowledgeCellAccessModeIEBindingFieldCodec(v *HandoverRequestAcknowledgeCellAccessModeIEBinding) *s00.CellAccessModeValueCodec {
	return &v.codec
}
func BridgeHandoverRequestAcknowledgeCellAccessModeIEBindingFieldGet(v *HandoverRequestAcknowledgeCellAccessModeIEBinding) *func(*HandoverRequestAcknowledgeIEValue) (*s00.CellAccessMode, bool) {
	return &v.get
}
func BridgeHandoverRequestAcknowledgeCellAccessModeIEBindingFieldInfo(v *HandoverRequestAcknowledgeCellAccessModeIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeHandoverRequestAcknowledgeCellAccessModeIEBindingFieldInject(v *HandoverRequestAcknowledgeCellAccessModeIEBinding) *func(s00.CellAccessMode) HandoverRequestAcknowledgeIEValue {
	return &v.inject
}
func BridgeHandoverRequestAcknowledgeCriticalityDiagnosticsIEBindingFieldCodec(v *HandoverRequestAcknowledgeCriticalityDiagnosticsIEBinding) *s22.CriticalityDiagnosticsValueCodec {
	return &v.codec
}
func BridgeHandoverRequestAcknowledgeCriticalityDiagnosticsIEBindingFieldGet(v *HandoverRequestAcknowledgeCriticalityDiagnosticsIEBinding) *func(*HandoverRequestAcknowledgeIEValue) (*s22.CriticalityDiagnostics, bool) {
	return &v.get
}
func BridgeHandoverRequestAcknowledgeCriticalityDiagnosticsIEBindingFieldInfo(v *HandoverRequestAcknowledgeCriticalityDiagnosticsIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeHandoverRequestAcknowledgeCriticalityDiagnosticsIEBindingFieldInject(v *HandoverRequestAcknowledgeCriticalityDiagnosticsIEBinding) *func(s22.CriticalityDiagnostics) HandoverRequestAcknowledgeIEValue {
	return &v.inject
}
func BridgeHandoverRequestAcknowledgeENBUES1APIDIEBindingFieldCodec(v *HandoverRequestAcknowledgeENBUES1APIDIEBinding) *s00.ENBUES1APIDValueCodec {
	return &v.codec
}
func BridgeHandoverRequestAcknowledgeENBUES1APIDIEBindingFieldGet(v *HandoverRequestAcknowledgeENBUES1APIDIEBinding) *func(*HandoverRequestAcknowledgeIEValue) (*s00.ENBUES1APID, bool) {
	return &v.get
}
func BridgeHandoverRequestAcknowledgeENBUES1APIDIEBindingFieldInfo(v *HandoverRequestAcknowledgeENBUES1APIDIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeHandoverRequestAcknowledgeENBUES1APIDIEBindingFieldInject(v *HandoverRequestAcknowledgeENBUES1APIDIEBinding) *func(s00.ENBUES1APID) HandoverRequestAcknowledgeIEValue {
	return &v.inject
}
func BridgeHandoverRequestAcknowledgeERABAdmittedListIEBindingFieldCodec(v *HandoverRequestAcknowledgeERABAdmittedListIEBinding) *s15.ERABAdmittedListValueCodec {
	return &v.codec
}
func BridgeHandoverRequestAcknowledgeERABAdmittedListIEBindingFieldGet(v *HandoverRequestAcknowledgeERABAdmittedListIEBinding) *func(*HandoverRequestAcknowledgeIEValue) (*s15.ERABAdmittedList, bool) {
	return &v.get
}
func BridgeHandoverRequestAcknowledgeERABAdmittedListIEBindingFieldInfo(v *HandoverRequestAcknowledgeERABAdmittedListIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeHandoverRequestAcknowledgeERABAdmittedListIEBindingFieldInject(v *HandoverRequestAcknowledgeERABAdmittedListIEBinding) *func(s15.ERABAdmittedList) HandoverRequestAcknowledgeIEValue {
	return &v.inject
}
func BridgeHandoverRequestAcknowledgeERABFailedtoSetupListHOReqAckIEBindingFieldCodec(v *HandoverRequestAcknowledgeERABFailedtoSetupListHOReqAckIEBinding) *s16.ERABFailedtoSetupListHOReqAckValueCodec {
	return &v.codec
}
func BridgeHandoverRequestAcknowledgeERABFailedtoSetupListHOReqAckIEBindingFieldGet(v *HandoverRequestAcknowledgeERABFailedtoSetupListHOReqAckIEBinding) *func(*HandoverRequestAcknowledgeIEValue) (*s16.ERABFailedtoSetupListHOReqAck, bool) {
	return &v.get
}
func BridgeHandoverRequestAcknowledgeERABFailedtoSetupListHOReqAckIEBindingFieldInfo(v *HandoverRequestAcknowledgeERABFailedtoSetupListHOReqAckIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeHandoverRequestAcknowledgeERABFailedtoSetupListHOReqAckIEBindingFieldInject(v *HandoverRequestAcknowledgeERABFailedtoSetupListHOReqAckIEBinding) *func(s16.ERABFailedtoSetupListHOReqAck) HandoverRequestAcknowledgeIEValue {
	return &v.inject
}
func BridgeHandoverRequestAcknowledgeFieldExtCount(v *HandoverRequestAcknowledge) *int64 {
	return &v.extCount
}
func BridgeHandoverRequestAcknowledgeFieldExtData(v *HandoverRequestAcknowledge) *[][]byte {
	return &v.extData
}
func BridgeHandoverRequestAcknowledgeFieldExtOrigin(v *HandoverRequestAcknowledge) *[]aper.OpaqueOrigin {
	return &v.extOrigin
}
func BridgeHandoverRequestAcknowledgeFieldExtPresent(v *HandoverRequestAcknowledge) *[]bool {
	return &v.extPresent
}
func BridgeHandoverRequestAcknowledgeFieldExtWire(v *HandoverRequestAcknowledge) *[]aper.WireSpan {
	return &v.extWire
}
func BridgeHandoverRequestAcknowledgeFieldPerExtPadding(v *HandoverRequestAcknowledge) *[]aper.CompletePadding {
	return &v.perExtPadding
}
func BridgeHandoverRequestAcknowledgeFieldPerPadding(v *HandoverRequestAcknowledge) *aper.FinalPadding {
	return &v.perPadding
}
func BridgeHandoverRequestAcknowledgeFieldProtocolIEsIndef(v *HandoverRequestAcknowledge) *bool {
	return &v.protocolIEsIndef
}
func BridgeHandoverRequestAcknowledgeFieldReceived(v *HandoverRequestAcknowledge) *bool {
	return &v.received
}
func BridgeHandoverRequestAcknowledgeFieldReceivedAbsolute(v *HandoverRequestAcknowledge) *bool {
	return &v.receivedAbsolute
}
func BridgeHandoverRequestAcknowledgeFieldReceivedBytes(v *HandoverRequestAcknowledge) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeHandoverRequestAcknowledgeFieldReceivedLocation(v *HandoverRequestAcknowledge) *aper.Location {
	return &v.receivedLocation
}
func BridgeHandoverRequestAcknowledgeFieldReplay(v *HandoverRequestAcknowledge) *aper.Snapshot {
	return &v.replay
}
func BridgeHandoverRequestAcknowledgeFieldStream(v *HandoverRequestAcknowledge) *aper.WireSpan {
	return &v.stream
}
func BridgeHandoverRequestAcknowledgeFieldWithoutReplay(v *HandoverRequestAcknowledge) *bool {
	return &v.withoutReplay
}
func BridgeHandoverRequestAcknowledgeIEContainerAPERValueFieldContext(v *HandoverRequestAcknowledgeIEContainerAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeHandoverRequestAcknowledgeIEContainerAPERValueFieldReceived(v *HandoverRequestAcknowledgeIEContainerAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeHandoverRequestAcknowledgeIEContainerAPERValueFieldReplay(v *HandoverRequestAcknowledgeIEContainerAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeHandoverRequestAcknowledgeIEContainerAPERValueFieldWithoutReplay(v *HandoverRequestAcknowledgeIEContainerAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeHandoverRequestAcknowledgeIEContainerValueCodecFieldCapture(v *HandoverRequestAcknowledgeIEContainerValueCodec) *func(HandoverRequestAcknowledgeIEContainer, aper.DecodeState) (HandoverRequestAcknowledgeIEContainer, aper.Snapshot) {
	return &v.capture
}
func BridgeHandoverRequestAcknowledgeIEContainerValueCodecFieldCompare(v *HandoverRequestAcknowledgeIEContainerValueCodec) *func(HandoverRequestAcknowledgeIEContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeHandoverRequestAcknowledgeIEContainerValueCodecFieldContext(v *HandoverRequestAcknowledgeIEContainerValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeHandoverRequestAcknowledgeIEContainerValueCodecFieldDecode(v *HandoverRequestAcknowledgeIEContainerValueCodec) *func([]byte, aper.DecodeState) (HandoverRequestAcknowledgeIEContainer, error) {
	return &v.decode
}
func BridgeHandoverRequestAcknowledgeIEContainerValueCodecFieldEncode(v *HandoverRequestAcknowledgeIEContainerValueCodec) *func(HandoverRequestAcknowledgeIEContainer, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeHandoverRequestAcknowledgeIEContainerValueCodecFieldPath(v *HandoverRequestAcknowledgeIEContainerValueCodec) *aper.Path {
	return &v.path
}
func BridgeHandoverRequestAcknowledgeIEContainerValueCodecMethodEncodeBudgetValue(v HandoverRequestAcknowledgeIEContainerValueCodec, a0 HandoverRequestAcknowledgeIEContainer, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeHandoverRequestAcknowledgeIEContainerValueCodecMethodEncodeChanged(v HandoverRequestAcknowledgeIEContainerValueCodec, a0 HandoverRequestAcknowledgeIEContainer, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeHandoverRequestAcknowledgeIEFieldAPERValueFieldContext(v *HandoverRequestAcknowledgeIEFieldAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeHandoverRequestAcknowledgeIEFieldAPERValueFieldReceived(v *HandoverRequestAcknowledgeIEFieldAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeHandoverRequestAcknowledgeIEFieldAPERValueFieldReplay(v *HandoverRequestAcknowledgeIEFieldAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeHandoverRequestAcknowledgeIEFieldAPERValueFieldWithoutReplay(v *HandoverRequestAcknowledgeIEFieldAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeHandoverRequestAcknowledgeIEFieldFieldReceived(v *HandoverRequestAcknowledgeIEField) *aper.CompletePadding {
	return &v.received
}
func BridgeHandoverRequestAcknowledgeIEFieldFieldReplay(v *HandoverRequestAcknowledgeIEField) *aper.Snapshot {
	return &v.replay
}
func BridgeHandoverRequestAcknowledgeIEFieldFieldStream(v *HandoverRequestAcknowledgeIEField) *aper.WireSpan {
	return &v.stream
}
func BridgeHandoverRequestAcknowledgeIEFieldFieldWithoutReplay(v *HandoverRequestAcknowledgeIEField) *bool {
	return &v.withoutReplay
}
func BridgeHandoverRequestAcknowledgeIEFieldMethodMarshalAPERTo(v *HandoverRequestAcknowledgeIEField, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeHandoverRequestAcknowledgeIEFieldMethodUnmarshalAPERFrom(v *HandoverRequestAcknowledgeIEField, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeHandoverRequestAcknowledgeIEFieldValueCodecFieldCapture(v *HandoverRequestAcknowledgeIEFieldValueCodec) *func(HandoverRequestAcknowledgeIEField, aper.DecodeState) (HandoverRequestAcknowledgeIEField, aper.Snapshot) {
	return &v.capture
}
func BridgeHandoverRequestAcknowledgeIEFieldValueCodecFieldCompare(v *HandoverRequestAcknowledgeIEFieldValueCodec) *func(HandoverRequestAcknowledgeIEField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeHandoverRequestAcknowledgeIEFieldValueCodecFieldContext(v *HandoverRequestAcknowledgeIEFieldValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeHandoverRequestAcknowledgeIEFieldValueCodecFieldDecode(v *HandoverRequestAcknowledgeIEFieldValueCodec) *func([]byte, aper.DecodeState) (HandoverRequestAcknowledgeIEField, error) {
	return &v.decode
}
func BridgeHandoverRequestAcknowledgeIEFieldValueCodecFieldEncode(v *HandoverRequestAcknowledgeIEFieldValueCodec) *func(HandoverRequestAcknowledgeIEField, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeHandoverRequestAcknowledgeIEFieldValueCodecFieldPath(v *HandoverRequestAcknowledgeIEFieldValueCodec) *aper.Path {
	return &v.path
}
func BridgeHandoverRequestAcknowledgeIEFieldValueCodecMethodEncodeBudgetValue(v HandoverRequestAcknowledgeIEFieldValueCodec, a0 HandoverRequestAcknowledgeIEField, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeHandoverRequestAcknowledgeIEFieldValueCodecMethodEncodeChanged(v HandoverRequestAcknowledgeIEFieldValueCodec, a0 HandoverRequestAcknowledgeIEField, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeHandoverRequestAcknowledgeIETableMethodInfoCEModeBSupportIndicator(v HandoverRequestAcknowledgeIETable) s00.FieldInfo {
	return v.infoCEModeBSupportIndicator()
}
func BridgeHandoverRequestAcknowledgeIETableMethodInfoCSGId(v HandoverRequestAcknowledgeIETable) s00.FieldInfo {
	return v.infoCSGId()
}
func BridgeHandoverRequestAcknowledgeIETableMethodInfoCellAccessMode(v HandoverRequestAcknowledgeIETable) s00.FieldInfo {
	return v.infoCellAccessMode()
}
func BridgeHandoverRequestAcknowledgeIETableMethodInfoCriticalityDiagnostics(v HandoverRequestAcknowledgeIETable) s00.FieldInfo {
	return v.infoCriticalityDiagnostics()
}
func BridgeHandoverRequestAcknowledgeIETableMethodInfoENBUES1APID(v HandoverRequestAcknowledgeIETable) s00.FieldInfo {
	return v.infoENBUES1APID()
}
func BridgeHandoverRequestAcknowledgeIETableMethodInfoERABAdmittedList(v HandoverRequestAcknowledgeIETable) s00.FieldInfo {
	return v.infoERABAdmittedList()
}
func BridgeHandoverRequestAcknowledgeIETableMethodInfoERABFailedToSetupListHOReqAck(v HandoverRequestAcknowledgeIETable) s00.FieldInfo {
	return v.infoERABFailedToSetupListHOReqAck()
}
func BridgeHandoverRequestAcknowledgeIETableMethodInfoMMEUES1APID(v HandoverRequestAcknowledgeIETable) s00.FieldInfo {
	return v.infoMMEUES1APID()
}
func BridgeHandoverRequestAcknowledgeIETableMethodInfoTargetToSourceTransparentContainer(v HandoverRequestAcknowledgeIETable) s00.FieldInfo {
	return v.infoTargetToSourceTransparentContainer()
}
func BridgeHandoverRequestAcknowledgeIEValueERABIEContainerListAPERValueFieldContext(v *HandoverRequestAcknowledgeIEValueERABIEContainerListAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeHandoverRequestAcknowledgeIEValueERABIEContainerListAPERValueFieldReceived(v *HandoverRequestAcknowledgeIEValueERABIEContainerListAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeHandoverRequestAcknowledgeIEValueERABIEContainerListAPERValueFieldReplay(v *HandoverRequestAcknowledgeIEValueERABIEContainerListAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeHandoverRequestAcknowledgeIEValueERABIEContainerListAPERValueFieldWithoutReplay(v *HandoverRequestAcknowledgeIEValueERABIEContainerListAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeHandoverRequestAcknowledgeIEValueERABIEContainerListValueCodecFieldCapture(v *HandoverRequestAcknowledgeIEValueERABIEContainerListValueCodec) *func(HandoverRequestAcknowledgeIEValueERABIEContainerList, aper.DecodeState) (HandoverRequestAcknowledgeIEValueERABIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgeHandoverRequestAcknowledgeIEValueERABIEContainerListValueCodecFieldCompare(v *HandoverRequestAcknowledgeIEValueERABIEContainerListValueCodec) *func(HandoverRequestAcknowledgeIEValueERABIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeHandoverRequestAcknowledgeIEValueERABIEContainerListValueCodecFieldContext(v *HandoverRequestAcknowledgeIEValueERABIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeHandoverRequestAcknowledgeIEValueERABIEContainerListValueCodecFieldDecode(v *HandoverRequestAcknowledgeIEValueERABIEContainerListValueCodec) *func([]byte, aper.DecodeState) (HandoverRequestAcknowledgeIEValueERABIEContainerList, error) {
	return &v.decode
}
func BridgeHandoverRequestAcknowledgeIEValueERABIEContainerListValueCodecFieldEncode(v *HandoverRequestAcknowledgeIEValueERABIEContainerListValueCodec) *func(HandoverRequestAcknowledgeIEValueERABIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeHandoverRequestAcknowledgeIEValueERABIEContainerListValueCodecFieldPath(v *HandoverRequestAcknowledgeIEValueERABIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgeHandoverRequestAcknowledgeIEValueERABIEContainerListValueCodecMethodEncodeBudgetValue(v HandoverRequestAcknowledgeIEValueERABIEContainerListValueCodec, a0 HandoverRequestAcknowledgeIEValueERABIEContainerList, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeHandoverRequestAcknowledgeIEValueERABIEContainerListValueCodecMethodEncodeChanged(v HandoverRequestAcknowledgeIEValueERABIEContainerListValueCodec, a0 HandoverRequestAcknowledgeIEValueERABIEContainerList, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeHandoverRequestAcknowledgeIEValueFieldId(v *HandoverRequestAcknowledgeIEValue) *s00.ProtocolIEID {
	return &v.id
}
func BridgeHandoverRequestAcknowledgeIEValueFieldIsOpaque(v *HandoverRequestAcknowledgeIEValue) *bool {
	return &v.isOpaque
}
func BridgeHandoverRequestAcknowledgeIEValueFieldOpaque(v *HandoverRequestAcknowledgeIEValue) *aper.OpaqueOpenType {
	return &v.opaque
}
func BridgeHandoverRequestAcknowledgeIEValueFieldReceived(v *HandoverRequestAcknowledgeIEValue) *aper.WireSpan {
	return &v.received
}
func BridgeHandoverRequestAcknowledgeIEValueFieldReplay(v *HandoverRequestAcknowledgeIEValue) *aper.Snapshot {
	return &v.replay
}
func BridgeHandoverRequestAcknowledgeIEValueFieldRowCEModeBSupportIndicator(v *HandoverRequestAcknowledgeIEValue) **s00.CEModeBSupportIndicator {
	return &v.rowCEModeBSupportIndicator
}
func BridgeHandoverRequestAcknowledgeIEValueFieldRowCSGId(v *HandoverRequestAcknowledgeIEValue) **s00.CSGId {
	return &v.rowCSGId
}
func BridgeHandoverRequestAcknowledgeIEValueFieldRowCellAccessMode(v *HandoverRequestAcknowledgeIEValue) **s00.CellAccessMode {
	return &v.rowCellAccessMode
}
func BridgeHandoverRequestAcknowledgeIEValueFieldRowCriticalityDiagnostics(v *HandoverRequestAcknowledgeIEValue) **s22.CriticalityDiagnostics {
	return &v.rowCriticalityDiagnostics
}
func BridgeHandoverRequestAcknowledgeIEValueFieldRowENBUES1APID(v *HandoverRequestAcknowledgeIEValue) **s00.ENBUES1APID {
	return &v.rowENBUES1APID
}
func BridgeHandoverRequestAcknowledgeIEValueFieldRowERABAdmittedList(v *HandoverRequestAcknowledgeIEValue) **s15.ERABAdmittedList {
	return &v.rowERABAdmittedList
}
func BridgeHandoverRequestAcknowledgeIEValueFieldRowERABFailedToSetupListHOReqAck(v *HandoverRequestAcknowledgeIEValue) **s16.ERABFailedtoSetupListHOReqAck {
	return &v.rowERABFailedToSetupListHOReqAck
}
func BridgeHandoverRequestAcknowledgeIEValueFieldRowMMEUES1APID(v *HandoverRequestAcknowledgeIEValue) **s00.MMEUES1APID {
	return &v.rowMMEUES1APID
}
func BridgeHandoverRequestAcknowledgeIEValueFieldRowTargetToSourceTransparentContainer(v *HandoverRequestAcknowledgeIEValue) **s00.TargetToSourceTransparentContainer {
	return &v.rowTargetToSourceTransparentContainer
}
func BridgeHandoverRequestAcknowledgeIEValueMethodCaptureSemantics(v HandoverRequestAcknowledgeIEValue, a0 aper.SemanticCapture) HandoverRequestAcknowledgeIEValue {
	return v.captureSemantics(a0)
}
func BridgeHandoverRequestAcknowledgeIEValueMethodCompareSemantics(v HandoverRequestAcknowledgeIEValue, a0 aper.SemanticComparison) aper.SemanticComparison {
	return v.compareSemantics(a0)
}
func BridgeHandoverRequestAcknowledgeIEValueMethodDecode(v HandoverRequestAcknowledgeIEValue, a0 s00.ProtocolIEID, a1 aper.OpaqueOpenType) (HandoverRequestAcknowledgeIEValue, error) {
	return v.decode(a0, a1)
}
func BridgeHandoverRequestAcknowledgeIEValueMethodEncode(v HandoverRequestAcknowledgeIEValue) ([]byte, error) {
	return v.encode()
}
func BridgeHandoverRequestAcknowledgeIEValueMethodEncodeFresh(v HandoverRequestAcknowledgeIEValue, a0 bool, a1 *aper.DecodeBudget) ([]byte, error) {
	return v.encodeFresh(a0, a1)
}
func BridgeHandoverRequestAcknowledgeIEValueMethodMatchesID(v HandoverRequestAcknowledgeIEValue, a0 s00.ProtocolIEID, a1 ...*aper.DecodeBudget) bool {
	return v.matchesID(a0, a1...)
}
func BridgeHandoverRequestAcknowledgeIEValueMethodReason(v HandoverRequestAcknowledgeIEValue, a0 s00.ProtocolIEID) aper.OpaqueReason {
	return v.reason(a0)
}
func BridgeHandoverRequestAcknowledgeIEValueMethodRule(v HandoverRequestAcknowledgeIEValue) aper.SourceRule {
	return v.rule()
}
func BridgeHandoverRequestAcknowledgeIEValueProtocolErrorIEContainerListAPERValueFieldContext(v *HandoverRequestAcknowledgeIEValueProtocolErrorIEContainerListAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeHandoverRequestAcknowledgeIEValueProtocolErrorIEContainerListAPERValueFieldReceived(v *HandoverRequestAcknowledgeIEValueProtocolErrorIEContainerListAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeHandoverRequestAcknowledgeIEValueProtocolErrorIEContainerListAPERValueFieldReplay(v *HandoverRequestAcknowledgeIEValueProtocolErrorIEContainerListAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeHandoverRequestAcknowledgeIEValueProtocolErrorIEContainerListAPERValueFieldWithoutReplay(v *HandoverRequestAcknowledgeIEValueProtocolErrorIEContainerListAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeHandoverRequestAcknowledgeIEValueProtocolErrorIEContainerListValueCodecFieldCapture(v *HandoverRequestAcknowledgeIEValueProtocolErrorIEContainerListValueCodec) *func(HandoverRequestAcknowledgeIEValueProtocolErrorIEContainerList, aper.DecodeState) (HandoverRequestAcknowledgeIEValueProtocolErrorIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgeHandoverRequestAcknowledgeIEValueProtocolErrorIEContainerListValueCodecFieldCompare(v *HandoverRequestAcknowledgeIEValueProtocolErrorIEContainerListValueCodec) *func(HandoverRequestAcknowledgeIEValueProtocolErrorIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeHandoverRequestAcknowledgeIEValueProtocolErrorIEContainerListValueCodecFieldContext(v *HandoverRequestAcknowledgeIEValueProtocolErrorIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeHandoverRequestAcknowledgeIEValueProtocolErrorIEContainerListValueCodecFieldDecode(v *HandoverRequestAcknowledgeIEValueProtocolErrorIEContainerListValueCodec) *func([]byte, aper.DecodeState) (HandoverRequestAcknowledgeIEValueProtocolErrorIEContainerList, error) {
	return &v.decode
}
func BridgeHandoverRequestAcknowledgeIEValueProtocolErrorIEContainerListValueCodecFieldEncode(v *HandoverRequestAcknowledgeIEValueProtocolErrorIEContainerListValueCodec) *func(HandoverRequestAcknowledgeIEValueProtocolErrorIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeHandoverRequestAcknowledgeIEValueProtocolErrorIEContainerListValueCodecFieldPath(v *HandoverRequestAcknowledgeIEValueProtocolErrorIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgeHandoverRequestAcknowledgeIEValueProtocolErrorIEContainerListValueCodecMethodEncodeBudgetValue(v HandoverRequestAcknowledgeIEValueProtocolErrorIEContainerListValueCodec, a0 HandoverRequestAcknowledgeIEValueProtocolErrorIEContainerList, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeHandoverRequestAcknowledgeIEValueProtocolErrorIEContainerListValueCodecMethodEncodeChanged(v HandoverRequestAcknowledgeIEValueProtocolErrorIEContainerListValueCodec, a0 HandoverRequestAcknowledgeIEValueProtocolErrorIEContainerList, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeHandoverRequestAcknowledgeIEValueProtocolIEContainerListAPERValueFieldContext(v *HandoverRequestAcknowledgeIEValueProtocolIEContainerListAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeHandoverRequestAcknowledgeIEValueProtocolIEContainerListAPERValueFieldReceived(v *HandoverRequestAcknowledgeIEValueProtocolIEContainerListAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeHandoverRequestAcknowledgeIEValueProtocolIEContainerListAPERValueFieldReplay(v *HandoverRequestAcknowledgeIEValueProtocolIEContainerListAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeHandoverRequestAcknowledgeIEValueProtocolIEContainerListAPERValueFieldWithoutReplay(v *HandoverRequestAcknowledgeIEValueProtocolIEContainerListAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeHandoverRequestAcknowledgeIEValueProtocolIEContainerListValueCodecFieldCapture(v *HandoverRequestAcknowledgeIEValueProtocolIEContainerListValueCodec) *func(HandoverRequestAcknowledgeIEValueProtocolIEContainerList, aper.DecodeState) (HandoverRequestAcknowledgeIEValueProtocolIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgeHandoverRequestAcknowledgeIEValueProtocolIEContainerListValueCodecFieldCompare(v *HandoverRequestAcknowledgeIEValueProtocolIEContainerListValueCodec) *func(HandoverRequestAcknowledgeIEValueProtocolIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeHandoverRequestAcknowledgeIEValueProtocolIEContainerListValueCodecFieldContext(v *HandoverRequestAcknowledgeIEValueProtocolIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeHandoverRequestAcknowledgeIEValueProtocolIEContainerListValueCodecFieldDecode(v *HandoverRequestAcknowledgeIEValueProtocolIEContainerListValueCodec) *func([]byte, aper.DecodeState) (HandoverRequestAcknowledgeIEValueProtocolIEContainerList, error) {
	return &v.decode
}
func BridgeHandoverRequestAcknowledgeIEValueProtocolIEContainerListValueCodecFieldEncode(v *HandoverRequestAcknowledgeIEValueProtocolIEContainerListValueCodec) *func(HandoverRequestAcknowledgeIEValueProtocolIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeHandoverRequestAcknowledgeIEValueProtocolIEContainerListValueCodecFieldPath(v *HandoverRequestAcknowledgeIEValueProtocolIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgeHandoverRequestAcknowledgeIEValueProtocolIEContainerListValueCodecMethodEncodeBudgetValue(v HandoverRequestAcknowledgeIEValueProtocolIEContainerListValueCodec, a0 HandoverRequestAcknowledgeIEValueProtocolIEContainerList, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeHandoverRequestAcknowledgeIEValueProtocolIEContainerListValueCodecMethodEncodeChanged(v HandoverRequestAcknowledgeIEValueProtocolIEContainerListValueCodec, a0 HandoverRequestAcknowledgeIEValueProtocolIEContainerList, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeHandoverRequestAcknowledgeMMEUES1APIDIEBindingFieldCodec(v *HandoverRequestAcknowledgeMMEUES1APIDIEBinding) *s01.MMEUES1APIDValueCodec {
	return &v.codec
}
func BridgeHandoverRequestAcknowledgeMMEUES1APIDIEBindingFieldGet(v *HandoverRequestAcknowledgeMMEUES1APIDIEBinding) *func(*HandoverRequestAcknowledgeIEValue) (*s00.MMEUES1APID, bool) {
	return &v.get
}
func BridgeHandoverRequestAcknowledgeMMEUES1APIDIEBindingFieldInfo(v *HandoverRequestAcknowledgeMMEUES1APIDIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeHandoverRequestAcknowledgeMMEUES1APIDIEBindingFieldInject(v *HandoverRequestAcknowledgeMMEUES1APIDIEBinding) *func(s00.MMEUES1APID) HandoverRequestAcknowledgeIEValue {
	return &v.inject
}
func BridgeHandoverRequestAcknowledgeMethodMarshalAPERBudget(v *HandoverRequestAcknowledge, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeHandoverRequestAcknowledgeMethodMarshalAPERBudgetValue(v *HandoverRequestAcknowledge, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudgetValue(a0, a1)
}
func BridgeHandoverRequestAcknowledgeMethodMarshalAPERChanged(v *HandoverRequestAcknowledge, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeHandoverRequestAcknowledgeMethodMarshalAPERChangedValue(v *HandoverRequestAcknowledge, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeHandoverRequestAcknowledgeMethodMarshalAPERLegacy(v *HandoverRequestAcknowledge) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeHandoverRequestAcknowledgeMethodMarshalAPERNewValue(v *HandoverRequestAcknowledge, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERNewValue(a0, a1)
}
func BridgeHandoverRequestAcknowledgeMethodMarshalAPERPlanned(v *HandoverRequestAcknowledge, a0 *aper.DecodeBudget, a1 bool, a2 *aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1, a2)
}
func BridgeHandoverRequestAcknowledgeMethodMarshalAPERTo(v *HandoverRequestAcknowledge, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeHandoverRequestAcknowledgeMethodUnmarshalAPERFrom(v *HandoverRequestAcknowledge, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeHandoverRequestAcknowledgeMethodUnmarshalAPERLegacy(v *HandoverRequestAcknowledge, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeHandoverRequestAcknowledgeMethodUnmarshalAPERWithOptions(v *HandoverRequestAcknowledge, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeHandoverRequestAcknowledgeTargetToSourceTransparentContainerIEBindingFieldCodec(v *HandoverRequestAcknowledgeTargetToSourceTransparentContainerIEBinding) *s01.TargetToSourceTransparentContainerValueCodec {
	return &v.codec
}
func BridgeHandoverRequestAcknowledgeTargetToSourceTransparentContainerIEBindingFieldGet(v *HandoverRequestAcknowledgeTargetToSourceTransparentContainerIEBinding) *func(*HandoverRequestAcknowledgeIEValue) (*s00.TargetToSourceTransparentContainer, bool) {
	return &v.get
}
func BridgeHandoverRequestAcknowledgeTargetToSourceTransparentContainerIEBindingFieldInfo(v *HandoverRequestAcknowledgeTargetToSourceTransparentContainerIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeHandoverRequestAcknowledgeTargetToSourceTransparentContainerIEBindingFieldInject(v *HandoverRequestAcknowledgeTargetToSourceTransparentContainerIEBinding) *func(s00.TargetToSourceTransparentContainer) HandoverRequestAcknowledgeIEValue {
	return &v.inject
}
func BridgeHandoverRequestAcknowledgeValueCodecFieldCapture(v *HandoverRequestAcknowledgeValueCodec) *func(HandoverRequestAcknowledge, aper.DecodeState) (HandoverRequestAcknowledge, aper.Snapshot) {
	return &v.capture
}
func BridgeHandoverRequestAcknowledgeValueCodecFieldCompare(v *HandoverRequestAcknowledgeValueCodec) *func(HandoverRequestAcknowledge, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeHandoverRequestAcknowledgeValueCodecFieldContext(v *HandoverRequestAcknowledgeValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeHandoverRequestAcknowledgeValueCodecFieldDecode(v *HandoverRequestAcknowledgeValueCodec) *func([]byte, aper.DecodeState) (HandoverRequestAcknowledge, error) {
	return &v.decode
}
func BridgeHandoverRequestAcknowledgeValueCodecFieldEncode(v *HandoverRequestAcknowledgeValueCodec) *func(HandoverRequestAcknowledge, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeHandoverRequestAcknowledgeValueCodecFieldPath(v *HandoverRequestAcknowledgeValueCodec) *aper.Path {
	return &v.path
}
func BridgeHandoverRequestAcknowledgeValueCodecMethodEncodeBudgetValue(v HandoverRequestAcknowledgeValueCodec, a0 HandoverRequestAcknowledge, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeHandoverRequestAcknowledgeValueCodecMethodEncodeChanged(v HandoverRequestAcknowledgeValueCodec, a0 HandoverRequestAcknowledge, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeInitialContextSetupResponseCriticalityDiagnosticsIEBindingFieldCodec(v *InitialContextSetupResponseCriticalityDiagnosticsIEBinding) *s22.CriticalityDiagnosticsValueCodec {
	return &v.codec
}
func BridgeInitialContextSetupResponseCriticalityDiagnosticsIEBindingFieldGet(v *InitialContextSetupResponseCriticalityDiagnosticsIEBinding) *func(*InitialContextSetupResponseIEValue) (*s22.CriticalityDiagnostics, bool) {
	return &v.get
}
func BridgeInitialContextSetupResponseCriticalityDiagnosticsIEBindingFieldInfo(v *InitialContextSetupResponseCriticalityDiagnosticsIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeInitialContextSetupResponseCriticalityDiagnosticsIEBindingFieldInject(v *InitialContextSetupResponseCriticalityDiagnosticsIEBinding) *func(s22.CriticalityDiagnostics) InitialContextSetupResponseIEValue {
	return &v.inject
}
func BridgeInitialContextSetupResponseENBUES1APIDIEBindingFieldCodec(v *InitialContextSetupResponseENBUES1APIDIEBinding) *s00.ENBUES1APIDValueCodec {
	return &v.codec
}
func BridgeInitialContextSetupResponseENBUES1APIDIEBindingFieldGet(v *InitialContextSetupResponseENBUES1APIDIEBinding) *func(*InitialContextSetupResponseIEValue) (*s00.ENBUES1APID, bool) {
	return &v.get
}
func BridgeInitialContextSetupResponseENBUES1APIDIEBindingFieldInfo(v *InitialContextSetupResponseENBUES1APIDIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeInitialContextSetupResponseENBUES1APIDIEBindingFieldInject(v *InitialContextSetupResponseENBUES1APIDIEBinding) *func(s00.ENBUES1APID) InitialContextSetupResponseIEValue {
	return &v.inject
}
func BridgeInitialContextSetupResponseERABListIEBindingFieldCodec(v *InitialContextSetupResponseERABListIEBinding) *s16.ERABListValueCodec {
	return &v.codec
}
func BridgeInitialContextSetupResponseERABListIEBindingFieldGet(v *InitialContextSetupResponseERABListIEBinding) *func(*InitialContextSetupResponseIEValue) (*s16.ERABList, bool) {
	return &v.get
}
func BridgeInitialContextSetupResponseERABListIEBindingFieldInfo(v *InitialContextSetupResponseERABListIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeInitialContextSetupResponseERABListIEBindingFieldInject(v *InitialContextSetupResponseERABListIEBinding) *func(s16.ERABList) InitialContextSetupResponseIEValue {
	return &v.inject
}
func BridgeInitialContextSetupResponseERABSetupListCtxtSUResIEBindingFieldCodec(v *InitialContextSetupResponseERABSetupListCtxtSUResIEBinding) *s17.ERABSetupListCtxtSUResValueCodec {
	return &v.codec
}
func BridgeInitialContextSetupResponseERABSetupListCtxtSUResIEBindingFieldGet(v *InitialContextSetupResponseERABSetupListCtxtSUResIEBinding) *func(*InitialContextSetupResponseIEValue) (*s17.ERABSetupListCtxtSURes, bool) {
	return &v.get
}
func BridgeInitialContextSetupResponseERABSetupListCtxtSUResIEBindingFieldInfo(v *InitialContextSetupResponseERABSetupListCtxtSUResIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeInitialContextSetupResponseERABSetupListCtxtSUResIEBindingFieldInject(v *InitialContextSetupResponseERABSetupListCtxtSUResIEBinding) *func(s17.ERABSetupListCtxtSURes) InitialContextSetupResponseIEValue {
	return &v.inject
}
func BridgeInitialContextSetupResponseIEContainerAPERValueFieldContext(v *InitialContextSetupResponseIEContainerAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeInitialContextSetupResponseIEContainerAPERValueFieldReceived(v *InitialContextSetupResponseIEContainerAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeInitialContextSetupResponseIEContainerAPERValueFieldReplay(v *InitialContextSetupResponseIEContainerAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeInitialContextSetupResponseIEContainerAPERValueFieldWithoutReplay(v *InitialContextSetupResponseIEContainerAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeInitialContextSetupResponseIEContainerValueCodecFieldCapture(v *InitialContextSetupResponseIEContainerValueCodec) *func(InitialContextSetupResponseIEContainer, aper.DecodeState) (InitialContextSetupResponseIEContainer, aper.Snapshot) {
	return &v.capture
}
func BridgeInitialContextSetupResponseIEContainerValueCodecFieldCompare(v *InitialContextSetupResponseIEContainerValueCodec) *func(InitialContextSetupResponseIEContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeInitialContextSetupResponseIEContainerValueCodecFieldContext(v *InitialContextSetupResponseIEContainerValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeInitialContextSetupResponseIEContainerValueCodecFieldDecode(v *InitialContextSetupResponseIEContainerValueCodec) *func([]byte, aper.DecodeState) (InitialContextSetupResponseIEContainer, error) {
	return &v.decode
}
func BridgeInitialContextSetupResponseIEContainerValueCodecFieldEncode(v *InitialContextSetupResponseIEContainerValueCodec) *func(InitialContextSetupResponseIEContainer, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeInitialContextSetupResponseIEContainerValueCodecFieldPath(v *InitialContextSetupResponseIEContainerValueCodec) *aper.Path {
	return &v.path
}
func BridgeInitialContextSetupResponseIEContainerValueCodecMethodEncodeBudgetValue(v InitialContextSetupResponseIEContainerValueCodec, a0 InitialContextSetupResponseIEContainer, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeInitialContextSetupResponseIEContainerValueCodecMethodEncodeChanged(v InitialContextSetupResponseIEContainerValueCodec, a0 InitialContextSetupResponseIEContainer, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeInitialContextSetupResponseIEFieldAPERValueFieldContext(v *InitialContextSetupResponseIEFieldAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeInitialContextSetupResponseIEFieldAPERValueFieldReceived(v *InitialContextSetupResponseIEFieldAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeInitialContextSetupResponseIEFieldAPERValueFieldReplay(v *InitialContextSetupResponseIEFieldAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeInitialContextSetupResponseIEFieldAPERValueFieldWithoutReplay(v *InitialContextSetupResponseIEFieldAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeInitialContextSetupResponseIEFieldFieldReceived(v *InitialContextSetupResponseIEField) *aper.CompletePadding {
	return &v.received
}
func BridgeInitialContextSetupResponseIEFieldFieldReplay(v *InitialContextSetupResponseIEField) *aper.Snapshot {
	return &v.replay
}
func BridgeInitialContextSetupResponseIEFieldFieldStream(v *InitialContextSetupResponseIEField) *aper.WireSpan {
	return &v.stream
}
func BridgeInitialContextSetupResponseIEFieldFieldWithoutReplay(v *InitialContextSetupResponseIEField) *bool {
	return &v.withoutReplay
}
func BridgeInitialContextSetupResponseIEFieldMethodMarshalAPERTo(v *InitialContextSetupResponseIEField, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeInitialContextSetupResponseIEFieldMethodUnmarshalAPERFrom(v *InitialContextSetupResponseIEField, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeInitialContextSetupResponseIEFieldValueCodecFieldCapture(v *InitialContextSetupResponseIEFieldValueCodec) *func(InitialContextSetupResponseIEField, aper.DecodeState) (InitialContextSetupResponseIEField, aper.Snapshot) {
	return &v.capture
}
func BridgeInitialContextSetupResponseIEFieldValueCodecFieldCompare(v *InitialContextSetupResponseIEFieldValueCodec) *func(InitialContextSetupResponseIEField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeInitialContextSetupResponseIEFieldValueCodecFieldContext(v *InitialContextSetupResponseIEFieldValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeInitialContextSetupResponseIEFieldValueCodecFieldDecode(v *InitialContextSetupResponseIEFieldValueCodec) *func([]byte, aper.DecodeState) (InitialContextSetupResponseIEField, error) {
	return &v.decode
}
func BridgeInitialContextSetupResponseIEFieldValueCodecFieldEncode(v *InitialContextSetupResponseIEFieldValueCodec) *func(InitialContextSetupResponseIEField, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeInitialContextSetupResponseIEFieldValueCodecFieldPath(v *InitialContextSetupResponseIEFieldValueCodec) *aper.Path {
	return &v.path
}
func BridgeInitialContextSetupResponseIEFieldValueCodecMethodEncodeBudgetValue(v InitialContextSetupResponseIEFieldValueCodec, a0 InitialContextSetupResponseIEField, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeInitialContextSetupResponseIEFieldValueCodecMethodEncodeChanged(v InitialContextSetupResponseIEFieldValueCodec, a0 InitialContextSetupResponseIEField, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeInitialContextSetupResponseIEValueERABIEContainerListAPERValueFieldContext(v *InitialContextSetupResponseIEValueERABIEContainerListAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeInitialContextSetupResponseIEValueERABIEContainerListAPERValueFieldReceived(v *InitialContextSetupResponseIEValueERABIEContainerListAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeInitialContextSetupResponseIEValueERABIEContainerListAPERValueFieldReplay(v *InitialContextSetupResponseIEValueERABIEContainerListAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeInitialContextSetupResponseIEValueERABIEContainerListAPERValueFieldWithoutReplay(v *InitialContextSetupResponseIEValueERABIEContainerListAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeInitialContextSetupResponseIEValueERABIEContainerListValueCodecFieldCapture(v *InitialContextSetupResponseIEValueERABIEContainerListValueCodec) *func(InitialContextSetupResponseIEValueERABIEContainerList, aper.DecodeState) (InitialContextSetupResponseIEValueERABIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgeInitialContextSetupResponseIEValueERABIEContainerListValueCodecFieldCompare(v *InitialContextSetupResponseIEValueERABIEContainerListValueCodec) *func(InitialContextSetupResponseIEValueERABIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeInitialContextSetupResponseIEValueERABIEContainerListValueCodecFieldContext(v *InitialContextSetupResponseIEValueERABIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeInitialContextSetupResponseIEValueERABIEContainerListValueCodecFieldDecode(v *InitialContextSetupResponseIEValueERABIEContainerListValueCodec) *func([]byte, aper.DecodeState) (InitialContextSetupResponseIEValueERABIEContainerList, error) {
	return &v.decode
}
func BridgeInitialContextSetupResponseIEValueERABIEContainerListValueCodecFieldEncode(v *InitialContextSetupResponseIEValueERABIEContainerListValueCodec) *func(InitialContextSetupResponseIEValueERABIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeInitialContextSetupResponseIEValueERABIEContainerListValueCodecFieldPath(v *InitialContextSetupResponseIEValueERABIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgeInitialContextSetupResponseIEValueERABIEContainerListValueCodecMethodEncodeBudgetValue(v InitialContextSetupResponseIEValueERABIEContainerListValueCodec, a0 InitialContextSetupResponseIEValueERABIEContainerList, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeInitialContextSetupResponseIEValueERABIEContainerListValueCodecMethodEncodeChanged(v InitialContextSetupResponseIEValueERABIEContainerListValueCodec, a0 InitialContextSetupResponseIEValueERABIEContainerList, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeInitialContextSetupResponseIEValueFieldId(v *InitialContextSetupResponseIEValue) *s00.ProtocolIEID {
	return &v.id
}
func BridgeInitialContextSetupResponseIEValueFieldIsOpaque(v *InitialContextSetupResponseIEValue) *bool {
	return &v.isOpaque
}
func BridgeInitialContextSetupResponseIEValueFieldOpaque(v *InitialContextSetupResponseIEValue) *aper.OpaqueOpenType {
	return &v.opaque
}
func BridgeInitialContextSetupResponseIEValueFieldReceived(v *InitialContextSetupResponseIEValue) *aper.WireSpan {
	return &v.received
}
func BridgeInitialContextSetupResponseIEValueFieldReplay(v *InitialContextSetupResponseIEValue) *aper.Snapshot {
	return &v.replay
}
func BridgeInitialContextSetupResponseIEValueFieldRowCriticalityDiagnostics(v *InitialContextSetupResponseIEValue) **s22.CriticalityDiagnostics {
	return &v.rowCriticalityDiagnostics
}
func BridgeInitialContextSetupResponseIEValueFieldRowENBUES1APID(v *InitialContextSetupResponseIEValue) **s00.ENBUES1APID {
	return &v.rowENBUES1APID
}
func BridgeInitialContextSetupResponseIEValueFieldRowERABFailedToSetupListCtxtSURes(v *InitialContextSetupResponseIEValue) **s16.ERABList {
	return &v.rowERABFailedToSetupListCtxtSURes
}
func BridgeInitialContextSetupResponseIEValueFieldRowERABSetupListCtxtSURes(v *InitialContextSetupResponseIEValue) **s17.ERABSetupListCtxtSURes {
	return &v.rowERABSetupListCtxtSURes
}
func BridgeInitialContextSetupResponseIEValueFieldRowMMEUES1APID(v *InitialContextSetupResponseIEValue) **s00.MMEUES1APID {
	return &v.rowMMEUES1APID
}
func BridgeInitialContextSetupResponseIEValueMethodCaptureSemantics(v InitialContextSetupResponseIEValue, a0 aper.SemanticCapture) InitialContextSetupResponseIEValue {
	return v.captureSemantics(a0)
}
func BridgeInitialContextSetupResponseIEValueMethodCompareSemantics(v InitialContextSetupResponseIEValue, a0 aper.SemanticComparison) aper.SemanticComparison {
	return v.compareSemantics(a0)
}
func BridgeInitialContextSetupResponseIEValueMethodDecode(v InitialContextSetupResponseIEValue, a0 s00.ProtocolIEID, a1 aper.OpaqueOpenType) (InitialContextSetupResponseIEValue, error) {
	return v.decode(a0, a1)
}
func BridgeInitialContextSetupResponseIEValueMethodEncode(v InitialContextSetupResponseIEValue) ([]byte, error) {
	return v.encode()
}
func BridgeInitialContextSetupResponseIEValueMethodEncodeFresh(v InitialContextSetupResponseIEValue, a0 bool, a1 *aper.DecodeBudget) ([]byte, error) {
	return v.encodeFresh(a0, a1)
}
func BridgeInitialContextSetupResponseIEValueMethodMatchesID(v InitialContextSetupResponseIEValue, a0 s00.ProtocolIEID, a1 ...*aper.DecodeBudget) bool {
	return v.matchesID(a0, a1...)
}
func BridgeInitialContextSetupResponseIEValueMethodReason(v InitialContextSetupResponseIEValue, a0 s00.ProtocolIEID) aper.OpaqueReason {
	return v.reason(a0)
}
func BridgeInitialContextSetupResponseIEValueMethodRule(v InitialContextSetupResponseIEValue) aper.SourceRule {
	return v.rule()
}
func BridgeInitialContextSetupResponseIEValueProtocolErrorIEContainerListAPERValueFieldContext(v *InitialContextSetupResponseIEValueProtocolErrorIEContainerListAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeInitialContextSetupResponseIEValueProtocolErrorIEContainerListAPERValueFieldReceived(v *InitialContextSetupResponseIEValueProtocolErrorIEContainerListAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeInitialContextSetupResponseIEValueProtocolErrorIEContainerListAPERValueFieldReplay(v *InitialContextSetupResponseIEValueProtocolErrorIEContainerListAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeInitialContextSetupResponseIEValueProtocolErrorIEContainerListAPERValueFieldWithoutReplay(v *InitialContextSetupResponseIEValueProtocolErrorIEContainerListAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeInitialContextSetupResponseIEValueProtocolErrorIEContainerListValueCodecFieldCapture(v *InitialContextSetupResponseIEValueProtocolErrorIEContainerListValueCodec) *func(InitialContextSetupResponseIEValueProtocolErrorIEContainerList, aper.DecodeState) (InitialContextSetupResponseIEValueProtocolErrorIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgeInitialContextSetupResponseIEValueProtocolErrorIEContainerListValueCodecFieldCompare(v *InitialContextSetupResponseIEValueProtocolErrorIEContainerListValueCodec) *func(InitialContextSetupResponseIEValueProtocolErrorIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeInitialContextSetupResponseIEValueProtocolErrorIEContainerListValueCodecFieldContext(v *InitialContextSetupResponseIEValueProtocolErrorIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeInitialContextSetupResponseIEValueProtocolErrorIEContainerListValueCodecFieldDecode(v *InitialContextSetupResponseIEValueProtocolErrorIEContainerListValueCodec) *func([]byte, aper.DecodeState) (InitialContextSetupResponseIEValueProtocolErrorIEContainerList, error) {
	return &v.decode
}
func BridgeInitialContextSetupResponseIEValueProtocolErrorIEContainerListValueCodecFieldEncode(v *InitialContextSetupResponseIEValueProtocolErrorIEContainerListValueCodec) *func(InitialContextSetupResponseIEValueProtocolErrorIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeInitialContextSetupResponseIEValueProtocolErrorIEContainerListValueCodecFieldPath(v *InitialContextSetupResponseIEValueProtocolErrorIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgeInitialContextSetupResponseIEValueProtocolErrorIEContainerListValueCodecMethodEncodeBudgetValue(v InitialContextSetupResponseIEValueProtocolErrorIEContainerListValueCodec, a0 InitialContextSetupResponseIEValueProtocolErrorIEContainerList, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeInitialContextSetupResponseIEValueProtocolErrorIEContainerListValueCodecMethodEncodeChanged(v InitialContextSetupResponseIEValueProtocolErrorIEContainerListValueCodec, a0 InitialContextSetupResponseIEValueProtocolErrorIEContainerList, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeInitialContextSetupResponseIEValueProtocolIEContainerListAPERValueFieldContext(v *InitialContextSetupResponseIEValueProtocolIEContainerListAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeInitialContextSetupResponseIEValueProtocolIEContainerListAPERValueFieldReceived(v *InitialContextSetupResponseIEValueProtocolIEContainerListAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeInitialContextSetupResponseIEValueProtocolIEContainerListAPERValueFieldReplay(v *InitialContextSetupResponseIEValueProtocolIEContainerListAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeInitialContextSetupResponseIEValueProtocolIEContainerListAPERValueFieldWithoutReplay(v *InitialContextSetupResponseIEValueProtocolIEContainerListAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeTargeteNBToSourceeNBTransparentContainerAPERValueFieldContext(v *TargeteNBToSourceeNBTransparentContainerAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeTargeteNBToSourceeNBTransparentContainerAPERValueFieldReceived(v *TargeteNBToSourceeNBTransparentContainerAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeTargeteNBToSourceeNBTransparentContainerAPERValueFieldReplay(v *TargeteNBToSourceeNBTransparentContainerAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeTargeteNBToSourceeNBTransparentContainerAPERValueFieldWithoutReplay(v *TargeteNBToSourceeNBTransparentContainerAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeTargeteNBToSourceeNBTransparentContainerExtIETableMethodInfoDAPSResponseInfoList(v TargeteNBToSourceeNBTransparentContainerExtIETable) s00.ExtensionInfo {
	return v.infoDAPSResponseInfoList()
}
func BridgeTargeteNBToSourceeNBTransparentContainerExtIETableMethodInfoDirectForwardingPathAvailability(v TargeteNBToSourceeNBTransparentContainerExtIETable) s00.ExtensionInfo {
	return v.infoDirectForwardingPathAvailability()
}
func BridgeTargeteNBToSourceeNBTransparentContainerExtIETableMethodInfoERABSecurityResultList(v TargeteNBToSourceeNBTransparentContainerExtIETable) s00.ExtensionInfo {
	return v.infoERABSecurityResultList()
}
func BridgeTargeteNBToSourceeNBTransparentContainerExtIETableMethodInfoRACSIndication(v TargeteNBToSourceeNBTransparentContainerExtIETable) s00.ExtensionInfo {
	return v.infoRACSIndication()
}
func BridgeTargeteNBToSourceeNBTransparentContainerExtIEsDAPSResponseInfoListExtBindingFieldCodec(v *TargeteNBToSourceeNBTransparentContainerExtIEsDAPSResponseInfoListExtBinding) *s14.DAPSResponseInfoListValueCodec {
	return &v.codec
}
func BridgeTargeteNBToSourceeNBTransparentContainerExtIEsDAPSResponseInfoListExtBindingFieldGet(v *TargeteNBToSourceeNBTransparentContainerExtIEsDAPSResponseInfoListExtBinding) *func(*TargeteNBToSourceeNBTransparentContainerExtIEsValue) (*s14.DAPSResponseInfoList, bool) {
	return &v.get
}
func BridgeTargeteNBToSourceeNBTransparentContainerExtIEsDAPSResponseInfoListExtBindingFieldInfo(v *TargeteNBToSourceeNBTransparentContainerExtIEsDAPSResponseInfoListExtBinding) *s00.ExtensionInfo {
	return &v.info
}
func BridgeTargeteNBToSourceeNBTransparentContainerExtIEsDAPSResponseInfoListExtBindingFieldInject(v *TargeteNBToSourceeNBTransparentContainerExtIEsDAPSResponseInfoListExtBinding) *func(s14.DAPSResponseInfoList) TargeteNBToSourceeNBTransparentContainerExtIEsValue {
	return &v.inject
}
func BridgeTargeteNBToSourceeNBTransparentContainerExtIEsDirectForwardingPathAvailabilityExtBindingFieldCodec(v *TargeteNBToSourceeNBTransparentContainerExtIEsDirectForwardingPathAvailabilityExtBinding) *s00.DirectForwardingPathAvailabilityValueCodec {
	return &v.codec
}
func BridgeTargeteNBToSourceeNBTransparentContainerExtIEsDirectForwardingPathAvailabilityExtBindingFieldGet(v *TargeteNBToSourceeNBTransparentContainerExtIEsDirectForwardingPathAvailabilityExtBinding) *func(*TargeteNBToSourceeNBTransparentContainerExtIEsValue) (*s00.DirectForwardingPathAvailability, bool) {
	return &v.get
}
func BridgeTargeteNBToSourceeNBTransparentContainerExtIEsDirectForwardingPathAvailabilityExtBindingFieldInfo(v *TargeteNBToSourceeNBTransparentContainerExtIEsDirectForwardingPathAvailabilityExtBinding) *s00.ExtensionInfo {
	return &v.info
}
func BridgeTargeteNBToSourceeNBTransparentContainerExtIEsDirectForwardingPathAvailabilityExtBindingFieldInject(v *TargeteNBToSourceeNBTransparentContainerExtIEsDirectForwardingPathAvailabilityExtBinding) *func(s00.DirectForwardingPathAvailability) TargeteNBToSourceeNBTransparentContainerExtIEsValue {
	return &v.inject
}
func BridgeTargeteNBToSourceeNBTransparentContainerExtIEsERABSecurityResultListExtBindingFieldCodec(v *TargeteNBToSourceeNBTransparentContainerExtIEsERABSecurityResultListExtBinding) *s30.ERABSecurityResultListValueCodec {
	return &v.codec
}
func BridgeTargeteNBToSourceeNBTransparentContainerExtIEsERABSecurityResultListExtBindingFieldGet(v *TargeteNBToSourceeNBTransparentContainerExtIEsERABSecurityResultListExtBinding) *func(*TargeteNBToSourceeNBTransparentContainerExtIEsValue) (*s30.ERABSecurityResultList, bool) {
	return &v.get
}
func BridgeTargeteNBToSourceeNBTransparentContainerExtIEsERABSecurityResultListExtBindingFieldInfo(v *TargeteNBToSourceeNBTransparentContainerExtIEsERABSecurityResultListExtBinding) *s00.ExtensionInfo {
	return &v.info
}
func BridgeTargeteNBToSourceeNBTransparentContainerExtIEsERABSecurityResultListExtBindingFieldInject(v *TargeteNBToSourceeNBTransparentContainerExtIEsERABSecurityResultListExtBinding) *func(s30.ERABSecurityResultList) TargeteNBToSourceeNBTransparentContainerExtIEsValue {
	return &v.inject
}
func BridgeTargeteNBToSourceeNBTransparentContainerExtIEsExtContainerAPERValueFieldContext(v *TargeteNBToSourceeNBTransparentContainerExtIEsExtContainerAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeTargeteNBToSourceeNBTransparentContainerExtIEsExtContainerAPERValueFieldReceived(v *TargeteNBToSourceeNBTransparentContainerExtIEsExtContainerAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeTargeteNBToSourceeNBTransparentContainerExtIEsExtContainerAPERValueFieldReplay(v *TargeteNBToSourceeNBTransparentContainerExtIEsExtContainerAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeTargeteNBToSourceeNBTransparentContainerExtIEsExtContainerAPERValueFieldWithoutReplay(v *TargeteNBToSourceeNBTransparentContainerExtIEsExtContainerAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeTargeteNBToSourceeNBTransparentContainerExtIEsExtContainerValueCodecFieldCapture(v *TargeteNBToSourceeNBTransparentContainerExtIEsExtContainerValueCodec) *func(TargeteNBToSourceeNBTransparentContainerExtIEsExtContainer, aper.DecodeState) (TargeteNBToSourceeNBTransparentContainerExtIEsExtContainer, aper.Snapshot) {
	return &v.capture
}
func BridgeTargeteNBToSourceeNBTransparentContainerExtIEsExtContainerValueCodecFieldCompare(v *TargeteNBToSourceeNBTransparentContainerExtIEsExtContainerValueCodec) *func(TargeteNBToSourceeNBTransparentContainerExtIEsExtContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeTargeteNBToSourceeNBTransparentContainerExtIEsExtContainerValueCodecFieldContext(v *TargeteNBToSourceeNBTransparentContainerExtIEsExtContainerValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeTargeteNBToSourceeNBTransparentContainerExtIEsExtContainerValueCodecFieldDecode(v *TargeteNBToSourceeNBTransparentContainerExtIEsExtContainerValueCodec) *func([]byte, aper.DecodeState) (TargeteNBToSourceeNBTransparentContainerExtIEsExtContainer, error) {
	return &v.decode
}
func BridgeTargeteNBToSourceeNBTransparentContainerExtIEsExtContainerValueCodecFieldEncode(v *TargeteNBToSourceeNBTransparentContainerExtIEsExtContainerValueCodec) *func(TargeteNBToSourceeNBTransparentContainerExtIEsExtContainer, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeTargeteNBToSourceeNBTransparentContainerExtIEsExtContainerValueCodecFieldPath(v *TargeteNBToSourceeNBTransparentContainerExtIEsExtContainerValueCodec) *aper.Path {
	return &v.path
}
func BridgeTargeteNBToSourceeNBTransparentContainerExtIEsExtContainerValueCodecMethodEncodeBudgetValue(v TargeteNBToSourceeNBTransparentContainerExtIEsExtContainerValueCodec, a0 TargeteNBToSourceeNBTransparentContainerExtIEsExtContainer, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeTargeteNBToSourceeNBTransparentContainerExtIEsExtContainerValueCodecMethodEncodeChanged(v TargeteNBToSourceeNBTransparentContainerExtIEsExtContainerValueCodec, a0 TargeteNBToSourceeNBTransparentContainerExtIEsExtContainer, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeTargeteNBToSourceeNBTransparentContainerExtIEsExtFieldAPERValueFieldContext(v *TargeteNBToSourceeNBTransparentContainerExtIEsExtFieldAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeTargeteNBToSourceeNBTransparentContainerExtIEsExtFieldAPERValueFieldReceived(v *TargeteNBToSourceeNBTransparentContainerExtIEsExtFieldAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeTargeteNBToSourceeNBTransparentContainerExtIEsExtFieldAPERValueFieldReplay(v *TargeteNBToSourceeNBTransparentContainerExtIEsExtFieldAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeTargeteNBToSourceeNBTransparentContainerExtIEsExtFieldAPERValueFieldWithoutReplay(v *TargeteNBToSourceeNBTransparentContainerExtIEsExtFieldAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeTargeteNBToSourceeNBTransparentContainerExtIEsExtFieldFieldReceived(v *TargeteNBToSourceeNBTransparentContainerExtIEsExtField) *aper.CompletePadding {
	return &v.received
}
func BridgeTargeteNBToSourceeNBTransparentContainerExtIEsExtFieldFieldReplay(v *TargeteNBToSourceeNBTransparentContainerExtIEsExtField) *aper.Snapshot {
	return &v.replay
}
func BridgeTargeteNBToSourceeNBTransparentContainerExtIEsExtFieldFieldStream(v *TargeteNBToSourceeNBTransparentContainerExtIEsExtField) *aper.WireSpan {
	return &v.stream
}
func BridgeTargeteNBToSourceeNBTransparentContainerExtIEsExtFieldFieldWithoutReplay(v *TargeteNBToSourceeNBTransparentContainerExtIEsExtField) *bool {
	return &v.withoutReplay
}
func BridgeTargeteNBToSourceeNBTransparentContainerExtIEsExtFieldMethodMarshalAPERTo(v *TargeteNBToSourceeNBTransparentContainerExtIEsExtField, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeTargeteNBToSourceeNBTransparentContainerExtIEsExtFieldMethodUnmarshalAPERFrom(v *TargeteNBToSourceeNBTransparentContainerExtIEsExtField, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeTargeteNBToSourceeNBTransparentContainerExtIEsExtFieldValueCodecFieldCapture(v *TargeteNBToSourceeNBTransparentContainerExtIEsExtFieldValueCodec) *func(TargeteNBToSourceeNBTransparentContainerExtIEsExtField, aper.DecodeState) (TargeteNBToSourceeNBTransparentContainerExtIEsExtField, aper.Snapshot) {
	return &v.capture
}
func BridgeTargeteNBToSourceeNBTransparentContainerExtIEsExtFieldValueCodecFieldCompare(v *TargeteNBToSourceeNBTransparentContainerExtIEsExtFieldValueCodec) *func(TargeteNBToSourceeNBTransparentContainerExtIEsExtField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeTargeteNBToSourceeNBTransparentContainerExtIEsExtFieldValueCodecFieldContext(v *TargeteNBToSourceeNBTransparentContainerExtIEsExtFieldValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeTargeteNBToSourceeNBTransparentContainerExtIEsExtFieldValueCodecFieldDecode(v *TargeteNBToSourceeNBTransparentContainerExtIEsExtFieldValueCodec) *func([]byte, aper.DecodeState) (TargeteNBToSourceeNBTransparentContainerExtIEsExtField, error) {
	return &v.decode
}
func BridgeTargeteNBToSourceeNBTransparentContainerExtIEsExtFieldValueCodecFieldEncode(v *TargeteNBToSourceeNBTransparentContainerExtIEsExtFieldValueCodec) *func(TargeteNBToSourceeNBTransparentContainerExtIEsExtField, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeTargeteNBToSourceeNBTransparentContainerExtIEsExtFieldValueCodecFieldPath(v *TargeteNBToSourceeNBTransparentContainerExtIEsExtFieldValueCodec) *aper.Path {
	return &v.path
}
func BridgeTargeteNBToSourceeNBTransparentContainerExtIEsExtFieldValueCodecMethodEncodeBudgetValue(v TargeteNBToSourceeNBTransparentContainerExtIEsExtFieldValueCodec, a0 TargeteNBToSourceeNBTransparentContainerExtIEsExtField, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeTargeteNBToSourceeNBTransparentContainerExtIEsExtFieldValueCodecMethodEncodeChanged(v TargeteNBToSourceeNBTransparentContainerExtIEsExtFieldValueCodec, a0 TargeteNBToSourceeNBTransparentContainerExtIEsExtField, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeTargeteNBToSourceeNBTransparentContainerExtIEsIEFieldFieldReceived(v *TargeteNBToSourceeNBTransparentContainerExtIEsIEField) *aper.CompletePadding {
	return &v.received
}
func BridgeTargeteNBToSourceeNBTransparentContainerExtIEsIEFieldFieldReplay(v *TargeteNBToSourceeNBTransparentContainerExtIEsIEField) *aper.Snapshot {
	return &v.replay
}
func BridgeTargeteNBToSourceeNBTransparentContainerExtIEsIEFieldFieldStream(v *TargeteNBToSourceeNBTransparentContainerExtIEsIEField) *aper.WireSpan {
	return &v.stream
}
func BridgeTargeteNBToSourceeNBTransparentContainerExtIEsIEFieldFieldWithoutReplay(v *TargeteNBToSourceeNBTransparentContainerExtIEsIEField) *bool {
	return &v.withoutReplay
}
func BridgeTargeteNBToSourceeNBTransparentContainerExtIEsIEFieldMethodMarshalAPERTo(v *TargeteNBToSourceeNBTransparentContainerExtIEsIEField, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeTargeteNBToSourceeNBTransparentContainerExtIEsIEFieldMethodUnmarshalAPERFrom(v *TargeteNBToSourceeNBTransparentContainerExtIEsIEField, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeTargeteNBToSourceeNBTransparentContainerExtIEsRACSIndicationExtBindingFieldCodec(v *TargeteNBToSourceeNBTransparentContainerExtIEsRACSIndicationExtBinding) *s01.RACSIndicationValueCodec {
	return &v.codec
}
func BridgeTargeteNBToSourceeNBTransparentContainerExtIEsRACSIndicationExtBindingFieldGet(v *TargeteNBToSourceeNBTransparentContainerExtIEsRACSIndicationExtBinding) *func(*TargeteNBToSourceeNBTransparentContainerExtIEsValue) (*s00.RACSIndication, bool) {
	return &v.get
}
func BridgeTargeteNBToSourceeNBTransparentContainerExtIEsRACSIndicationExtBindingFieldInfo(v *TargeteNBToSourceeNBTransparentContainerExtIEsRACSIndicationExtBinding) *s00.ExtensionInfo {
	return &v.info
}
func BridgeTargeteNBToSourceeNBTransparentContainerExtIEsRACSIndicationExtBindingFieldInject(v *TargeteNBToSourceeNBTransparentContainerExtIEsRACSIndicationExtBinding) *func(s00.RACSIndication) TargeteNBToSourceeNBTransparentContainerExtIEsValue {
	return &v.inject
}
func BridgeTargeteNBToSourceeNBTransparentContainerExtIEsValueFieldId(v *TargeteNBToSourceeNBTransparentContainerExtIEsValue) *s00.ProtocolIEID {
	return &v.id
}
func BridgeTargeteNBToSourceeNBTransparentContainerExtIEsValueFieldIsOpaque(v *TargeteNBToSourceeNBTransparentContainerExtIEsValue) *bool {
	return &v.isOpaque
}
func BridgeTargeteNBToSourceeNBTransparentContainerExtIEsValueFieldOpaque(v *TargeteNBToSourceeNBTransparentContainerExtIEsValue) *aper.OpaqueOpenType {
	return &v.opaque
}
func BridgeTargeteNBToSourceeNBTransparentContainerExtIEsValueFieldReceived(v *TargeteNBToSourceeNBTransparentContainerExtIEsValue) *aper.WireSpan {
	return &v.received
}
func BridgeTargeteNBToSourceeNBTransparentContainerExtIEsValueFieldReplay(v *TargeteNBToSourceeNBTransparentContainerExtIEsValue) *aper.Snapshot {
	return &v.replay
}
func BridgeTargeteNBToSourceeNBTransparentContainerExtIEsValueFieldRowDAPSResponseInfoList(v *TargeteNBToSourceeNBTransparentContainerExtIEsValue) **s14.DAPSResponseInfoList {
	return &v.rowDAPSResponseInfoList
}
func BridgeTargeteNBToSourceeNBTransparentContainerExtIEsValueFieldRowDirectForwardingPathAvailability(v *TargeteNBToSourceeNBTransparentContainerExtIEsValue) **s00.DirectForwardingPathAvailability {
	return &v.rowDirectForwardingPathAvailability
}
func BridgeTargeteNBToSourceeNBTransparentContainerExtIEsValueFieldRowERABSecurityResultList(v *TargeteNBToSourceeNBTransparentContainerExtIEsValue) **s30.ERABSecurityResultList {
	return &v.rowERABSecurityResultList
}
func BridgeTargeteNBToSourceeNBTransparentContainerExtIEsValueFieldRowRACSIndication(v *TargeteNBToSourceeNBTransparentContainerExtIEsValue) **s00.RACSIndication {
	return &v.rowRACSIndication
}
func BridgeTargeteNBToSourceeNBTransparentContainerExtIEsValueMethodCaptureSemantics(v TargeteNBToSourceeNBTransparentContainerExtIEsValue, a0 aper.SemanticCapture) TargeteNBToSourceeNBTransparentContainerExtIEsValue {
	return v.captureSemantics(a0)
}
func BridgeTargeteNBToSourceeNBTransparentContainerExtIEsValueMethodCompareSemantics(v TargeteNBToSourceeNBTransparentContainerExtIEsValue, a0 aper.SemanticComparison) aper.SemanticComparison {
	return v.compareSemantics(a0)
}
func BridgeTargeteNBToSourceeNBTransparentContainerExtIEsValueMethodDecode(v TargeteNBToSourceeNBTransparentContainerExtIEsValue, a0 s00.ProtocolIEID, a1 aper.OpaqueOpenType) (TargeteNBToSourceeNBTransparentContainerExtIEsValue, error) {
	return v.decode(a0, a1)
}
func BridgeTargeteNBToSourceeNBTransparentContainerExtIEsValueMethodEncode(v TargeteNBToSourceeNBTransparentContainerExtIEsValue) ([]byte, error) {
	return v.encode()
}
func BridgeTargeteNBToSourceeNBTransparentContainerExtIEsValueMethodEncodeFresh(v TargeteNBToSourceeNBTransparentContainerExtIEsValue, a0 bool, a1 *aper.DecodeBudget) ([]byte, error) {
	return v.encodeFresh(a0, a1)
}
func BridgeTargeteNBToSourceeNBTransparentContainerExtIEsValueMethodMatchesID(v TargeteNBToSourceeNBTransparentContainerExtIEsValue, a0 s00.ProtocolIEID, a1 ...*aper.DecodeBudget) bool {
	return v.matchesID(a0, a1...)
}
func BridgeTargeteNBToSourceeNBTransparentContainerExtIEsValueMethodReason(v TargeteNBToSourceeNBTransparentContainerExtIEsValue, a0 s00.ProtocolIEID) aper.OpaqueReason {
	return v.reason(a0)
}
func BridgeTargeteNBToSourceeNBTransparentContainerExtIEsValueMethodRule(v TargeteNBToSourceeNBTransparentContainerExtIEsValue) aper.SourceRule {
	return v.rule()
}
func BridgeTargeteNBToSourceeNBTransparentContainerFieldExtCount(v *TargeteNBToSourceeNBTransparentContainer) *int64 {
	return &v.extCount
}
func BridgeTargeteNBToSourceeNBTransparentContainerFieldExtData(v *TargeteNBToSourceeNBTransparentContainer) *[][]byte {
	return &v.extData
}
func BridgeTargeteNBToSourceeNBTransparentContainerFieldExtOrigin(v *TargeteNBToSourceeNBTransparentContainer) *[]aper.OpaqueOrigin {
	return &v.extOrigin
}
func BridgeTargeteNBToSourceeNBTransparentContainerFieldExtPresent(v *TargeteNBToSourceeNBTransparentContainer) *[]bool {
	return &v.extPresent
}
func BridgeTargeteNBToSourceeNBTransparentContainerFieldExtWire(v *TargeteNBToSourceeNBTransparentContainer) *[]aper.WireSpan {
	return &v.extWire
}
func BridgeTargeteNBToSourceeNBTransparentContainerFieldIEExtensionsIndef(v *TargeteNBToSourceeNBTransparentContainer) *bool {
	return &v.iEExtensionsIndef
}
func BridgeTargeteNBToSourceeNBTransparentContainerFieldPerExtPadding(v *TargeteNBToSourceeNBTransparentContainer) *[]aper.CompletePadding {
	return &v.perExtPadding
}
func BridgeTargeteNBToSourceeNBTransparentContainerFieldPerPadding(v *TargeteNBToSourceeNBTransparentContainer) *aper.FinalPadding {
	return &v.perPadding
}
func BridgeTargeteNBToSourceeNBTransparentContainerFieldReceived(v *TargeteNBToSourceeNBTransparentContainer) *bool {
	return &v.received
}
func BridgeTargeteNBToSourceeNBTransparentContainerFieldReceivedAbsolute(v *TargeteNBToSourceeNBTransparentContainer) *bool {
	return &v.receivedAbsolute
}
func BridgeTargeteNBToSourceeNBTransparentContainerFieldReceivedBytes(v *TargeteNBToSourceeNBTransparentContainer) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeTargeteNBToSourceeNBTransparentContainerFieldReceivedLocation(v *TargeteNBToSourceeNBTransparentContainer) *aper.Location {
	return &v.receivedLocation
}
func BridgeTargeteNBToSourceeNBTransparentContainerFieldReplay(v *TargeteNBToSourceeNBTransparentContainer) *aper.Snapshot {
	return &v.replay
}
func BridgeTargeteNBToSourceeNBTransparentContainerFieldStream(v *TargeteNBToSourceeNBTransparentContainer) *aper.WireSpan {
	return &v.stream
}
func BridgeTargeteNBToSourceeNBTransparentContainerFieldWithoutReplay(v *TargeteNBToSourceeNBTransparentContainer) *bool {
	return &v.withoutReplay
}
func BridgeTargeteNBToSourceeNBTransparentContainerMethodMarshalAPERBudget(v *TargeteNBToSourceeNBTransparentContainer, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeTargeteNBToSourceeNBTransparentContainerMethodMarshalAPERBudgetValue(v *TargeteNBToSourceeNBTransparentContainer, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudgetValue(a0, a1)
}
func BridgeTargeteNBToSourceeNBTransparentContainerMethodMarshalAPERChanged(v *TargeteNBToSourceeNBTransparentContainer, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeTargeteNBToSourceeNBTransparentContainerMethodMarshalAPERChangedValue(v *TargeteNBToSourceeNBTransparentContainer, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeTargeteNBToSourceeNBTransparentContainerMethodMarshalAPERLegacy(v *TargeteNBToSourceeNBTransparentContainer) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeTargeteNBToSourceeNBTransparentContainerMethodMarshalAPERNewValue(v *TargeteNBToSourceeNBTransparentContainer, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERNewValue(a0, a1)
}
func BridgeTargeteNBToSourceeNBTransparentContainerMethodMarshalAPERPlanned(v *TargeteNBToSourceeNBTransparentContainer, a0 *aper.DecodeBudget, a1 bool, a2 *aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1, a2)
}
func BridgeTargeteNBToSourceeNBTransparentContainerMethodMarshalAPERTo(v *TargeteNBToSourceeNBTransparentContainer, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeTargeteNBToSourceeNBTransparentContainerMethodUnmarshalAPERFrom(v *TargeteNBToSourceeNBTransparentContainer, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeTargeteNBToSourceeNBTransparentContainerMethodUnmarshalAPERLegacy(v *TargeteNBToSourceeNBTransparentContainer, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeTargeteNBToSourceeNBTransparentContainerMethodUnmarshalAPERWithOptions(v *TargeteNBToSourceeNBTransparentContainer, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeTargeteNBToSourceeNBTransparentContainerValueCodecFieldCapture(v *TargeteNBToSourceeNBTransparentContainerValueCodec) *func(TargeteNBToSourceeNBTransparentContainer, aper.DecodeState) (TargeteNBToSourceeNBTransparentContainer, aper.Snapshot) {
	return &v.capture
}
func BridgeTargeteNBToSourceeNBTransparentContainerValueCodecFieldCompare(v *TargeteNBToSourceeNBTransparentContainerValueCodec) *func(TargeteNBToSourceeNBTransparentContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeTargeteNBToSourceeNBTransparentContainerValueCodecFieldContext(v *TargeteNBToSourceeNBTransparentContainerValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeTargeteNBToSourceeNBTransparentContainerValueCodecFieldDecode(v *TargeteNBToSourceeNBTransparentContainerValueCodec) *func([]byte, aper.DecodeState) (TargeteNBToSourceeNBTransparentContainer, error) {
	return &v.decode
}
func BridgeTargeteNBToSourceeNBTransparentContainerValueCodecFieldEncode(v *TargeteNBToSourceeNBTransparentContainerValueCodec) *func(TargeteNBToSourceeNBTransparentContainer, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeTargeteNBToSourceeNBTransparentContainerValueCodecFieldPath(v *TargeteNBToSourceeNBTransparentContainerValueCodec) *aper.Path {
	return &v.path
}
func BridgeTargeteNBToSourceeNBTransparentContainerValueCodecMethodEncodeBudgetValue(v TargeteNBToSourceeNBTransparentContainerValueCodec, a0 TargeteNBToSourceeNBTransparentContainer, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeTargeteNBToSourceeNBTransparentContainerValueCodecMethodEncodeChanged(v TargeteNBToSourceeNBTransparentContainerValueCodec, a0 TargeteNBToSourceeNBTransparentContainer, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}

// Selected returns the decoded value of the active alternative, as the matching As method returns it, or false when the value is opaque or empty.
// The field's Id distinguishes alternatives with the same Go type.
func (v *ERABModificationConfirmIEValue) Selected() (any, bool) {
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
	case 203:
		if value, ok := v.AsERABModifyListBearerModConf(); ok {
			return value, true
		}
	case 205:
		if value, ok := v.AsERABFailedToModifyListBearerModConf(); ok {
			return value, true
		}
	case 210:
		if value, ok := v.AsERABToBeReleasedListBearerModConf(); ok {
			return value, true
		}
	case 58:
		if value, ok := v.AsCriticalityDiagnostics(); ok {
			return value, true
		}
	case 146:
		if value, ok := v.AsCSGMembershipStatus(); ok {
			return value, true
		}
	}
	return nil, false
}

// Selected returns the decoded value of the active alternative, as the matching As method returns it, or false when the value is opaque or empty.
// The field's Id distinguishes alternatives with the same Go type.
func (v *ERABReleaseCommandIEValue) Selected() (any, bool) {
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
	case 66:
		if value, ok := v.AsUEaggregateMaximumBitrate(); ok {
			return value, true
		}
	case 33:
		if value, ok := v.AsERABToBeReleasedList(); ok {
			return value, true
		}
	case 26:
		if value, ok := v.AsNASPDU(); ok {
			return value, true
		}
	}
	return nil, false
}

// Selected returns the decoded value of the active alternative, as the matching As method returns it, or false when the value is opaque or empty.
// The field's Id distinguishes alternatives with the same Go type.
func (v *HandoverRequestAcknowledgeIEValue) Selected() (any, bool) {
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
	case 18:
		if value, ok := v.AsERABAdmittedList(); ok {
			return value, true
		}
	case 19:
		if value, ok := v.AsERABFailedToSetupListHOReqAck(); ok {
			return value, true
		}
	case 123:
		if value, ok := v.AsTargetToSourceTransparentContainer(); ok {
			return value, true
		}
	case 127:
		if value, ok := v.AsCSGId(); ok {
			return value, true
		}
	case 58:
		if value, ok := v.AsCriticalityDiagnostics(); ok {
			return value, true
		}
	case 145:
		if value, ok := v.AsCellAccessMode(); ok {
			return value, true
		}
	case 242:
		if value, ok := v.AsCEModeBSupportIndicator(); ok {
			return value, true
		}
	}
	return nil, false
}

// Selected returns the decoded value of the active alternative, as the matching As method returns it, or false when the value is opaque or empty.
// The field's Id distinguishes alternatives with the same Go type.
func (v *InitialContextSetupResponseIEValue) Selected() (any, bool) {
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
	case 51:
		if value, ok := v.AsERABSetupListCtxtSURes(); ok {
			return value, true
		}
	case 48:
		if value, ok := v.AsERABFailedToSetupListCtxtSURes(); ok {
			return value, true
		}
	case 58:
		if value, ok := v.AsCriticalityDiagnostics(); ok {
			return value, true
		}
	}
	return nil, false
}

// Selected returns the decoded value of the active alternative, as the matching As method returns it, or false when the value is opaque or empty.
func (v *TargeteNBToSourceeNBTransparentContainerExtIEsValue) Selected() (any, bool) {
	if v == nil || v.isOpaque {
		return nil, false
	}
	switch v.id {
	case 318:
		if value, ok := v.AsDAPSResponseInfoList(); ok {
			return value, true
		}
	case 330:
		if value, ok := v.AsRACSIndication(); ok {
			return value, true
		}
	case 335:
		if value, ok := v.AsERABSecurityResultList(); ok {
			return value, true
		}
	case 79:
		if value, ok := v.AsDirectForwardingPathAvailability(); ok {
			return value, true
		}
	}
	return nil, false
}
