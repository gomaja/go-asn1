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
	s11 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s11"
	s13 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s13"
	s14 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s14"
	s17 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s17"
	s18 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s18"
	s20 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s20"
	s21 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s21"
	s22 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s22"
	s24 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s24"
	s26 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s26"
	s27 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s27"
	s32 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s32"
	runtime "github.com/gomaja/go-asn1/telecom/lte/s1ap/runtime"
	aper "github.com/gomaja/go-asn1/telecom/lte/s1ap/runtime/aper"
)

// WriteReplaceWarningRequestIEContainer is ProtocolIE-Container {{WriteReplaceWarningRequestIEs}} of TS 36.413: a list of WriteReplaceWarningRequestIEField values.
type WriteReplaceWarningRequestIEContainer []WriteReplaceWarningRequestIEField

// WriteReplaceWarningRequestIEField is ProtocolIE-Field {{WriteReplaceWarningRequestIEs}} of TS 36.413: an information element field.
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

// WriteReplaceWarningResponseIEContainer is ProtocolIE-Container {{WriteReplaceWarningResponseIEs}} of TS 36.413: a list of WriteReplaceWarningResponseIEField values.
type WriteReplaceWarningResponseIEContainer []WriteReplaceWarningResponseIEField

// WriteReplaceWarningResponseIEField is ProtocolIE-Field {{WriteReplaceWarningResponseIEs}} of TS 36.413: an information element field.
type WriteReplaceWarningResponseIEField struct {
	withoutReplay bool
	replay        aper.Snapshot
	stream        aper.WireSpan
	Id            s00.ProtocolIEID
	Criticality   s00.Criticality
	Value         WriteReplaceWarningResponseIEValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v WriteReplaceWarningResponseIEField) WithoutReplay() WriteReplaceWarningResponseIEField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *WriteReplaceWarningResponseIEField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *WriteReplaceWarningResponseIEField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
func (v *WriteReplaceWarningResponseIEField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolIEField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = WriteReplaceWarningResponseIEField{}
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
	var zero WriteReplaceWarningResponseIEValue

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

// KillRequestIEContainer is ProtocolIE-Container {{KillRequestIEs}} of TS 36.413: a list of KillRequestIEField values.
type KillRequestIEContainer []KillRequestIEField

// KillRequestIEField is ProtocolIE-Field {{KillRequestIEs}} of TS 36.413: an information element field.
type KillRequestIEField struct {
	withoutReplay bool
	replay        aper.Snapshot
	stream        aper.WireSpan
	Id            s00.ProtocolIEID
	Criticality   s00.Criticality
	Value         KillRequestIEValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v KillRequestIEField) WithoutReplay() KillRequestIEField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *KillRequestIEField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *KillRequestIEField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
func (v *KillRequestIEField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolIEField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = KillRequestIEField{}
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
	var zero KillRequestIEValue

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

// KillResponseIEContainer is ProtocolIE-Container {{KillResponseIEs}} of TS 36.413: a list of KillResponseIEField values.
type KillResponseIEContainer []KillResponseIEField

// KillResponseIEField is ProtocolIE-Field {{KillResponseIEs}} of TS 36.413: an information element field.
type KillResponseIEField struct {
	withoutReplay bool
	replay        aper.Snapshot
	stream        aper.WireSpan
	Id            s00.ProtocolIEID
	Criticality   s00.Criticality
	Value         KillResponseIEValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v KillResponseIEField) WithoutReplay() KillResponseIEField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *KillResponseIEField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *KillResponseIEField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
func (v *KillResponseIEField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolIEField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = KillResponseIEField{}
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
	var zero KillResponseIEValue

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
func BridgeKillRequestIEValueCaptureS1APProtocolIEContainer(v *KillRequestIEContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
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
func BridgeKillRequestIEValueCompareS1APProtocolIEContainer(v *KillRequestIEContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
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
func BridgeKillResponseIEValueCaptureS1APProtocolIEContainer(v *KillResponseIEContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
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
func BridgeKillResponseIEValueCompareS1APProtocolIEContainer(v *KillResponseIEContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
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
func BridgeLocationReportIEValueCaptureS1APProtocolIEContainer(v *s32.LocationReportIEContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
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
func BridgeLocationReportIEValueCompareS1APProtocolIEContainer(v *s32.LocationReportIEContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
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

// KillRequestMessageIdentifierIEBinding binds MessageIdentifier to the KillRequestIEs object set of TS 36.413.
type KillRequestMessageIdentifierIEBinding struct {
	info   s00.FieldInfo
	codec  s01.MessageIdentifierValueCodec
	inject func(s00.MessageIdentifier,

	) KillRequestIEValue

	get func(*KillRequestIEValue,

	) (*s00.MessageIdentifier,

		bool)
}

// Info returns the source descriptor for this binding.
func (b KillRequestMessageIdentifierIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b KillRequestMessageIdentifierIEBinding) Codec() s01.MessageIdentifierValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b KillRequestMessageIdentifierIEBinding) New(value s00.MessageIdentifier,

) (KillRequestIEField, error) {
	if b.inject == nil {
		return KillRequestIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return KillRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s01.BridgeMessageIdentifierValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return KillRequestIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return KillRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	return KillRequestIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b KillRequestMessageIdentifierIEBinding) Get(field *KillRequestIEField) (*s00.MessageIdentifier,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// KillRequestSerialNumberIEBinding binds SerialNumber to the KillRequestIEs object set of TS 36.413.
type KillRequestSerialNumberIEBinding struct {
	info   s00.FieldInfo
	codec  s01.SerialNumberValueCodec
	inject func(s00.SerialNumber,

	) KillRequestIEValue

	get func(*KillRequestIEValue,

	) (*s00.SerialNumber,

		bool)
}

// Info returns the source descriptor for this binding.
func (b KillRequestSerialNumberIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b KillRequestSerialNumberIEBinding) Codec() s01.SerialNumberValueCodec { return b.codec }

// New validates a source value and constructs its bound field.
func (b KillRequestSerialNumberIEBinding) New(value s00.SerialNumber,

) (KillRequestIEField, error) {
	if b.inject == nil {
		return KillRequestIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return KillRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s01.BridgeSerialNumberValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return KillRequestIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return KillRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	return KillRequestIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b KillRequestSerialNumberIEBinding) Get(field *KillRequestIEField) (*s00.SerialNumber,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// KillRequestWarningAreaListIEBinding binds WarningAreaList to the KillRequestIEs object set of TS 36.413.
type KillRequestWarningAreaListIEBinding struct {
	info   s00.FieldInfo
	codec  WarningAreaListValueCodec
	inject func(WarningAreaList,

	) KillRequestIEValue

	get func(*KillRequestIEValue,

	) (*WarningAreaList,

		bool)
}

// Info returns the source descriptor for this binding.
func (b KillRequestWarningAreaListIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b KillRequestWarningAreaListIEBinding) Codec() WarningAreaListValueCodec { return b.codec }

// New validates a source value and constructs its bound field.
func (b KillRequestWarningAreaListIEBinding) New(value WarningAreaList,

) (KillRequestIEField, error) {
	if b.inject == nil {
		return KillRequestIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return KillRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := b.codec.encode(value, false, budget); err != nil {
		return KillRequestIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return KillRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	return KillRequestIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b KillRequestWarningAreaListIEBinding) Get(field *KillRequestIEField) (*WarningAreaList,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// WarningAreaListValueCodec is the concrete ValueCodec[WarningAreaList].
type WarningAreaListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (WarningAreaList,

		error)
	encode func(WarningAreaList,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(WarningAreaList, aper.DecodeState,

	) (WarningAreaList, aper.Snapshot,

	)
	compare func(WarningAreaList, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c WarningAreaListValueCodec) New(value WarningAreaList,

) (WarningAreaListAPERValue, error) {
	if c.encode == nil {
		return WarningAreaListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return WarningAreaListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return WarningAreaListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return WarningAreaListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c WarningAreaListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (WarningAreaListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return WarningAreaListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return WarningAreaListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return WarningAreaListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return WarningAreaListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c WarningAreaListValueCodec) EncodeAPER(value WarningAreaListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c WarningAreaListValueCodec) encodeBudgetValue(value WarningAreaList,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c WarningAreaListValueCodec) encodeChanged(value WarningAreaList,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// KillRequestKillAllWarningMessagesIEBinding binds KillAllWarningMessages to the KillRequestIEs object set of TS 36.413.
type KillRequestKillAllWarningMessagesIEBinding struct {
	info   s00.FieldInfo
	codec  s01.KillAllWarningMessagesValueCodec
	inject func(s00.KillAllWarningMessages,

	) KillRequestIEValue

	get func(*KillRequestIEValue,

	) (*s00.KillAllWarningMessages,

		bool)
}

// Info returns the source descriptor for this binding.
func (b KillRequestKillAllWarningMessagesIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b KillRequestKillAllWarningMessagesIEBinding) Codec() s01.KillAllWarningMessagesValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b KillRequestKillAllWarningMessagesIEBinding) New(value s00.KillAllWarningMessages,

) (KillRequestIEField, error) {
	if b.inject == nil {
		return KillRequestIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return KillRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s01.BridgeKillAllWarningMessagesValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return KillRequestIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return KillRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	return KillRequestIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b KillRequestKillAllWarningMessagesIEBinding) Get(field *KillRequestIEField) (*s00.KillAllWarningMessages,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// KillResponseMessageIdentifierIEBinding binds MessageIdentifier to the KillResponseIEs object set of TS 36.413.
type KillResponseMessageIdentifierIEBinding struct {
	info   s00.FieldInfo
	codec  s01.MessageIdentifierValueCodec
	inject func(s00.MessageIdentifier,

	) KillResponseIEValue

	get func(*KillResponseIEValue,

	) (*s00.MessageIdentifier,

		bool)
}

// Info returns the source descriptor for this binding.
func (b KillResponseMessageIdentifierIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b KillResponseMessageIdentifierIEBinding) Codec() s01.MessageIdentifierValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b KillResponseMessageIdentifierIEBinding) New(value s00.MessageIdentifier,

) (KillResponseIEField, error) {
	if b.inject == nil {
		return KillResponseIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return KillResponseIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s01.BridgeMessageIdentifierValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return KillResponseIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return KillResponseIEField{}, aper.OperationError(err, "Value.New")
	}
	return KillResponseIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b KillResponseMessageIdentifierIEBinding) Get(field *KillResponseIEField) (*s00.MessageIdentifier,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// KillResponseSerialNumberIEBinding binds SerialNumber to the KillResponseIEs object set of TS 36.413.
type KillResponseSerialNumberIEBinding struct {
	info   s00.FieldInfo
	codec  s01.SerialNumberValueCodec
	inject func(s00.SerialNumber,

	) KillResponseIEValue

	get func(*KillResponseIEValue,

	) (*s00.SerialNumber,

		bool)
}

// Info returns the source descriptor for this binding.
func (b KillResponseSerialNumberIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b KillResponseSerialNumberIEBinding) Codec() s01.SerialNumberValueCodec { return b.codec }

// New validates a source value and constructs its bound field.
func (b KillResponseSerialNumberIEBinding) New(value s00.SerialNumber,

) (KillResponseIEField, error) {
	if b.inject == nil {
		return KillResponseIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return KillResponseIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s01.BridgeSerialNumberValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return KillResponseIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return KillResponseIEField{}, aper.OperationError(err, "Value.New")
	}
	return KillResponseIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b KillResponseSerialNumberIEBinding) Get(field *KillResponseIEField) (*s00.SerialNumber,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// KillResponseBroadcastCancelledAreaListIEBinding binds BroadcastCancelledAreaList to the KillResponseIEs object set of TS 36.413.
type KillResponseBroadcastCancelledAreaListIEBinding struct {
	info   s00.FieldInfo
	codec  BroadcastCancelledAreaListValueCodec
	inject func(BroadcastCancelledAreaList,

	) KillResponseIEValue

	get func(*KillResponseIEValue,

	) (*BroadcastCancelledAreaList,

		bool)
}

// Info returns the source descriptor for this binding.
func (b KillResponseBroadcastCancelledAreaListIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b KillResponseBroadcastCancelledAreaListIEBinding) Codec() BroadcastCancelledAreaListValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b KillResponseBroadcastCancelledAreaListIEBinding) New(value BroadcastCancelledAreaList,

) (KillResponseIEField, error) {
	if b.inject == nil {
		return KillResponseIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return KillResponseIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := b.codec.encode(value, false, budget); err != nil {
		return KillResponseIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return KillResponseIEField{}, aper.OperationError(err, "Value.New")
	}
	return KillResponseIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b KillResponseBroadcastCancelledAreaListIEBinding) Get(field *KillResponseIEField) (*BroadcastCancelledAreaList,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// BroadcastCancelledAreaListValueCodec is the concrete ValueCodec[BroadcastCancelledAreaList].
type BroadcastCancelledAreaListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (BroadcastCancelledAreaList,

		error)
	encode func(BroadcastCancelledAreaList,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(BroadcastCancelledAreaList, aper.DecodeState,

	) (BroadcastCancelledAreaList, aper.Snapshot,

	)
	compare func(BroadcastCancelledAreaList, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c BroadcastCancelledAreaListValueCodec) New(value BroadcastCancelledAreaList,

) (BroadcastCancelledAreaListAPERValue, error) {
	if c.encode == nil {
		return BroadcastCancelledAreaListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return BroadcastCancelledAreaListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return BroadcastCancelledAreaListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return BroadcastCancelledAreaListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c BroadcastCancelledAreaListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (BroadcastCancelledAreaListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return BroadcastCancelledAreaListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return BroadcastCancelledAreaListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return BroadcastCancelledAreaListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return BroadcastCancelledAreaListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c BroadcastCancelledAreaListValueCodec) EncodeAPER(value BroadcastCancelledAreaListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c BroadcastCancelledAreaListValueCodec) encodeBudgetValue(value BroadcastCancelledAreaList,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c BroadcastCancelledAreaListValueCodec) encodeChanged(value BroadcastCancelledAreaList,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// KillResponseCriticalityDiagnosticsIEBinding binds CriticalityDiagnostics to the KillResponseIEs object set of TS 36.413.
type KillResponseCriticalityDiagnosticsIEBinding struct {
	info   s00.FieldInfo
	codec  s22.CriticalityDiagnosticsValueCodec
	inject func(s22.CriticalityDiagnostics,

	) KillResponseIEValue

	get func(*KillResponseIEValue,

	) (*s22.CriticalityDiagnostics,

		bool)
}

// Info returns the source descriptor for this binding.
func (b KillResponseCriticalityDiagnosticsIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b KillResponseCriticalityDiagnosticsIEBinding) Codec() s22.CriticalityDiagnosticsValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b KillResponseCriticalityDiagnosticsIEBinding) New(value s22.CriticalityDiagnostics,

) (KillResponseIEField, error) {
	if b.inject == nil {
		return KillResponseIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return KillResponseIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s22.BridgeCriticalityDiagnosticsValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return KillResponseIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return KillResponseIEField{}, aper.OperationError(err, "Value.New")
	}
	return KillResponseIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b KillResponseCriticalityDiagnosticsIEBinding) Get(field *KillResponseIEField) (*s22.CriticalityDiagnostics,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// WriteReplaceWarningRequestMessageIdentifierIEBinding binds MessageIdentifier to the WriteReplaceWarningRequestIEs object set of TS 36.413.
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

// WriteReplaceWarningRequestSerialNumberIEBinding binds SerialNumber to the WriteReplaceWarningRequestIEs object set of TS 36.413.
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

// WriteReplaceWarningRequestWarningAreaListIEBinding binds WarningAreaList to the WriteReplaceWarningRequestIEs object set of TS 36.413.
type WriteReplaceWarningRequestWarningAreaListIEBinding struct {
	info   s00.FieldInfo
	codec  WarningAreaListValueCodec
	inject func(WarningAreaList,

	) WriteReplaceWarningRequestIEValue

	get func(*WriteReplaceWarningRequestIEValue,

	) (*WarningAreaList,

		bool)
}

// Info returns the source descriptor for this binding.
func (b WriteReplaceWarningRequestWarningAreaListIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b WriteReplaceWarningRequestWarningAreaListIEBinding) Codec() WarningAreaListValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b WriteReplaceWarningRequestWarningAreaListIEBinding) New(value WarningAreaList,

) (WriteReplaceWarningRequestIEField, error) {
	if b.inject == nil {
		return WriteReplaceWarningRequestIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return WriteReplaceWarningRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := b.codec.encode(value, false, budget); err != nil {
		return WriteReplaceWarningRequestIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return WriteReplaceWarningRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	return WriteReplaceWarningRequestIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b WriteReplaceWarningRequestWarningAreaListIEBinding) Get(field *WriteReplaceWarningRequestIEField) (*WarningAreaList,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// WriteReplaceWarningRequestRepetitionPeriodIEBinding binds RepetitionPeriod to the WriteReplaceWarningRequestIEs object set of TS 36.413.
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

// WriteReplaceWarningRequestExtendedRepetitionPeriodIEBinding binds ExtendedRepetitionPeriod to the WriteReplaceWarningRequestIEs object set of TS 36.413.
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

// WriteReplaceWarningRequestNumberofBroadcastRequestIEBinding binds NumberofBroadcastRequest to the WriteReplaceWarningRequestIEs object set of TS 36.413.
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

// WriteReplaceWarningRequestWarningTypeIEBinding binds WarningType to the WriteReplaceWarningRequestIEs object set of TS 36.413.
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

// WriteReplaceWarningRequestWarningSecurityInfoIEBinding binds WarningSecurityInfo to the WriteReplaceWarningRequestIEs object set of TS 36.413.
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

// WriteReplaceWarningRequestDataCodingSchemeIEBinding binds DataCodingScheme to the WriteReplaceWarningRequestIEs object set of TS 36.413.
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

// WriteReplaceWarningRequestWarningMessageContentsIEBinding binds WarningMessageContents to the WriteReplaceWarningRequestIEs object set of TS 36.413.
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

// WriteReplaceWarningRequestConcurrentWarningMessageIndicatorIEBinding binds ConcurrentWarningMessageIndicator to the WriteReplaceWarningRequestIEs object set of TS 36.413.
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

// WriteReplaceWarningRequestWarningAreaCoordinatesIEBinding binds WarningAreaCoordinates to the WriteReplaceWarningRequestIEs object set of TS 36.413.
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

// WriteReplaceWarningResponseMessageIdentifierIEBinding binds MessageIdentifier to the WriteReplaceWarningResponseIEs object set of TS 36.413.
type WriteReplaceWarningResponseMessageIdentifierIEBinding struct {
	info   s00.FieldInfo
	codec  s01.MessageIdentifierValueCodec
	inject func(s00.MessageIdentifier,

	) WriteReplaceWarningResponseIEValue

	get func(*WriteReplaceWarningResponseIEValue,

	) (*s00.MessageIdentifier,

		bool)
}

// Info returns the source descriptor for this binding.
func (b WriteReplaceWarningResponseMessageIdentifierIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b WriteReplaceWarningResponseMessageIdentifierIEBinding) Codec() s01.MessageIdentifierValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b WriteReplaceWarningResponseMessageIdentifierIEBinding) New(value s00.MessageIdentifier,

) (WriteReplaceWarningResponseIEField, error) {
	if b.inject == nil {
		return WriteReplaceWarningResponseIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return WriteReplaceWarningResponseIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s01.BridgeMessageIdentifierValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return WriteReplaceWarningResponseIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return WriteReplaceWarningResponseIEField{}, aper.OperationError(err, "Value.New")
	}
	return WriteReplaceWarningResponseIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b WriteReplaceWarningResponseMessageIdentifierIEBinding) Get(field *WriteReplaceWarningResponseIEField) (*s00.MessageIdentifier,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// WriteReplaceWarningResponseSerialNumberIEBinding binds SerialNumber to the WriteReplaceWarningResponseIEs object set of TS 36.413.
type WriteReplaceWarningResponseSerialNumberIEBinding struct {
	info   s00.FieldInfo
	codec  s01.SerialNumberValueCodec
	inject func(s00.SerialNumber,

	) WriteReplaceWarningResponseIEValue

	get func(*WriteReplaceWarningResponseIEValue,

	) (*s00.SerialNumber,

		bool)
}

// Info returns the source descriptor for this binding.
func (b WriteReplaceWarningResponseSerialNumberIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b WriteReplaceWarningResponseSerialNumberIEBinding) Codec() s01.SerialNumberValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b WriteReplaceWarningResponseSerialNumberIEBinding) New(value s00.SerialNumber,

) (WriteReplaceWarningResponseIEField, error) {
	if b.inject == nil {
		return WriteReplaceWarningResponseIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return WriteReplaceWarningResponseIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s01.BridgeSerialNumberValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return WriteReplaceWarningResponseIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return WriteReplaceWarningResponseIEField{}, aper.OperationError(err, "Value.New")
	}
	return WriteReplaceWarningResponseIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b WriteReplaceWarningResponseSerialNumberIEBinding) Get(field *WriteReplaceWarningResponseIEField) (*s00.SerialNumber,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// WriteReplaceWarningResponseBroadcastCompletedAreaListIEBinding binds BroadcastCompletedAreaList to the WriteReplaceWarningResponseIEs object set of TS 36.413.
type WriteReplaceWarningResponseBroadcastCompletedAreaListIEBinding struct {
	info   s00.FieldInfo
	codec  s32.BroadcastCompletedAreaListValueCodec
	inject func(s32.BroadcastCompletedAreaList,

	) WriteReplaceWarningResponseIEValue

	get func(*WriteReplaceWarningResponseIEValue,

	) (*s32.BroadcastCompletedAreaList,

		bool)
}

// Info returns the source descriptor for this binding.
func (b WriteReplaceWarningResponseBroadcastCompletedAreaListIEBinding) Info() s00.FieldInfo {
	return b.info
}

// Codec returns the complete value codec for this binding.
func (b WriteReplaceWarningResponseBroadcastCompletedAreaListIEBinding) Codec() s32.BroadcastCompletedAreaListValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b WriteReplaceWarningResponseBroadcastCompletedAreaListIEBinding) New(value s32.BroadcastCompletedAreaList,

) (WriteReplaceWarningResponseIEField, error) {
	if b.inject == nil {
		return WriteReplaceWarningResponseIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return WriteReplaceWarningResponseIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s32.BridgeBroadcastCompletedAreaListValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return WriteReplaceWarningResponseIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return WriteReplaceWarningResponseIEField{}, aper.OperationError(err, "Value.New")
	}
	return WriteReplaceWarningResponseIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b WriteReplaceWarningResponseBroadcastCompletedAreaListIEBinding) Get(field *WriteReplaceWarningResponseIEField) (*s32.BroadcastCompletedAreaList,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// WriteReplaceWarningResponseCriticalityDiagnosticsIEBinding binds CriticalityDiagnostics to the WriteReplaceWarningResponseIEs object set of TS 36.413.
type WriteReplaceWarningResponseCriticalityDiagnosticsIEBinding struct {
	info   s00.FieldInfo
	codec  s22.CriticalityDiagnosticsValueCodec
	inject func(s22.CriticalityDiagnostics,

	) WriteReplaceWarningResponseIEValue

	get func(*WriteReplaceWarningResponseIEValue,

	) (*s22.CriticalityDiagnostics,

		bool)
}

// Info returns the source descriptor for this binding.
func (b WriteReplaceWarningResponseCriticalityDiagnosticsIEBinding) Info() s00.FieldInfo {
	return b.info
}

// Codec returns the complete value codec for this binding.
func (b WriteReplaceWarningResponseCriticalityDiagnosticsIEBinding) Codec() s22.CriticalityDiagnosticsValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b WriteReplaceWarningResponseCriticalityDiagnosticsIEBinding) New(value s22.CriticalityDiagnostics,

) (WriteReplaceWarningResponseIEField, error) {
	if b.inject == nil {
		return WriteReplaceWarningResponseIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return WriteReplaceWarningResponseIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s22.BridgeCriticalityDiagnosticsValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return WriteReplaceWarningResponseIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return WriteReplaceWarningResponseIEField{}, aper.OperationError(err, "Value.New")
	}
	return WriteReplaceWarningResponseIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b WriteReplaceWarningResponseCriticalityDiagnosticsIEBinding) Get(field *WriteReplaceWarningResponseIEField) (*s22.CriticalityDiagnostics,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// AreaScopeOfMDTValueCodec is the concrete ValueCodec[AreaScopeOfMDT].
type AreaScopeOfMDTValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (AreaScopeOfMDT,

		error)
	encode func(AreaScopeOfMDT,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(AreaScopeOfMDT, aper.DecodeState,

	) (AreaScopeOfMDT, aper.Snapshot,

	)
	compare func(AreaScopeOfMDT, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c AreaScopeOfMDTValueCodec) New(value AreaScopeOfMDT,

) (AreaScopeOfMDTAPERValue, error) {
	if c.encode == nil {
		return AreaScopeOfMDTAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return AreaScopeOfMDTAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return AreaScopeOfMDTAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return AreaScopeOfMDTAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c AreaScopeOfMDTValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (AreaScopeOfMDTAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return AreaScopeOfMDTAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return AreaScopeOfMDTAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return AreaScopeOfMDTAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return AreaScopeOfMDTAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c AreaScopeOfMDTValueCodec) EncodeAPER(value AreaScopeOfMDTAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c AreaScopeOfMDTValueCodec) encodeBudgetValue(value AreaScopeOfMDT,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c AreaScopeOfMDTValueCodec) encodeChanged(value AreaScopeOfMDT,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// AreaScopeOfQMCValueCodec is the concrete ValueCodec[AreaScopeOfQMC].
type AreaScopeOfQMCValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (AreaScopeOfQMC,

		error)
	encode func(AreaScopeOfQMC,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(AreaScopeOfQMC, aper.DecodeState,

	) (AreaScopeOfQMC, aper.Snapshot,

	)
	compare func(AreaScopeOfQMC, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c AreaScopeOfQMCValueCodec) New(value AreaScopeOfQMC,

) (AreaScopeOfQMCAPERValue, error) {
	if c.encode == nil {
		return AreaScopeOfQMCAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return AreaScopeOfQMCAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return AreaScopeOfQMCAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return AreaScopeOfQMCAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c AreaScopeOfQMCValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (AreaScopeOfQMCAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return AreaScopeOfQMCAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return AreaScopeOfQMCAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return AreaScopeOfQMCAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return AreaScopeOfQMCAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c AreaScopeOfQMCValueCodec) EncodeAPER(value AreaScopeOfQMCAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c AreaScopeOfQMCValueCodec) encodeBudgetValue(value AreaScopeOfQMC,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c AreaScopeOfQMCValueCodec) encodeChanged(value AreaScopeOfQMC,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
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

// TAIBasedMDTValueCodec is the concrete ValueCodec[TAIBasedMDT].
type TAIBasedMDTValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (TAIBasedMDT,

		error)
	encode func(TAIBasedMDT,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(TAIBasedMDT, aper.DecodeState,

	) (TAIBasedMDT, aper.Snapshot,

	)
	compare func(TAIBasedMDT, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c TAIBasedMDTValueCodec) New(value TAIBasedMDT,

) (TAIBasedMDTAPERValue, error) {
	if c.encode == nil {
		return TAIBasedMDTAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return TAIBasedMDTAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return TAIBasedMDTAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return TAIBasedMDTAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c TAIBasedMDTValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (TAIBasedMDTAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return TAIBasedMDTAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return TAIBasedMDTAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return TAIBasedMDTAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return TAIBasedMDTAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c TAIBasedMDTValueCodec) EncodeAPER(value TAIBasedMDTAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c TAIBasedMDTValueCodec) encodeBudgetValue(value TAIBasedMDT,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c TAIBasedMDTValueCodec) encodeChanged(value TAIBasedMDT,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// TAIBasedQMCValueCodec is the concrete ValueCodec[TAIBasedQMC].
type TAIBasedQMCValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (TAIBasedQMC,

		error)
	encode func(TAIBasedQMC,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(TAIBasedQMC, aper.DecodeState,

	) (TAIBasedQMC, aper.Snapshot,

	)
	compare func(TAIBasedQMC, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c TAIBasedQMCValueCodec) New(value TAIBasedQMC,

) (TAIBasedQMCAPERValue, error) {
	if c.encode == nil {
		return TAIBasedQMCAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return TAIBasedQMCAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return TAIBasedQMCAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return TAIBasedQMCAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c TAIBasedQMCValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (TAIBasedQMCAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return TAIBasedQMCAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return TAIBasedQMCAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return TAIBasedQMCAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return TAIBasedQMCAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c TAIBasedQMCValueCodec) EncodeAPER(value TAIBasedQMCAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c TAIBasedQMCValueCodec) encodeBudgetValue(value TAIBasedQMC,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c TAIBasedQMCValueCodec) encodeChanged(value TAIBasedQMC,

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
func BridgeLocationReportIEValueValidateS1APIEContainer(fields s32.LocationReportIEContainer, rows []s00.FieldInfo, path string, budget *aper.DecodeBudget,

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
		if !s32.BridgeLocationReportIEValueMethodMatchesID(field.Value, field.Id, budget) {
			rule := s32.BridgeLocationReportIEValueMethodRule(field.Value)
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.ValueIDMismatch, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: aper.Path(fmt.Sprintf("%s.id", location.Path))}, Table: func() s00.TableID {
				sealed := s00.TableID{}
				*s00.BridgeTableIDFieldSource(&sealed) = rule.Assignment
				return sealed
			}(), IEID: field.Id, HasIEID: true, Rule: s27.BridgeS1apValidationRule(s00.ValueIDMismatch), RelatedRules: []aper.SourceRule{rule}})
		}
		rank, allowed := byID[field.Id]
		table := func() s00.TableID {
			sealed := s00.TableID{}
			*s00.BridgeTableIDFieldSource(&sealed) = s32.BridgeLocationReportIEValueMethodRule(field.Value).Assignment
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
func BridgeKillRequestIEValueValidateS1APIEContainer(fields KillRequestIEContainer, rows []s00.FieldInfo, path string, budget *aper.DecodeBudget,

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
func BridgeKillResponseIEValueValidateS1APIEContainer(fields KillResponseIEContainer, rows []s00.FieldInfo, path string, budget *aper.DecodeBudget,

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

// KillRequestIEValueERABIEContainerListCodec constructs the E-RAB-IE-ContainerList {{KillRequestIEs}} codec of TS 36.413.
func KillRequestIEValueERABIEContainerListCodec(table s00.KillRequestIEValueIETable) KillRequestIEValueERABIEContainerListValueCodec {
	codec := KillRequestIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if codec.decode == nil {
		return KillRequestIEValueERABIEContainerListValueCodec{}
	}
	size := aper.SizeConstraint{Lower: (aper.ListBounds{Lower: 1, Upper: 256}).Lower, Upper: (aper.ListBounds{Lower: 1, Upper: 256}).Upper, HasLower: true, HasUpper: true}
	return KillRequestIEValueERABIEContainerListValueCodec{decode: func(data []byte, options aper.DecodeState) (KillRequestIEValueERABIEContainerList, error) {
		bb := aper.NewCompleteDecodeBuffer(data, options)
		if err := bb.SetDecodeOptionsAligned(options); err != nil {
			return nil, err
		}
		var fields KillRequestIEValueERABIEContainerList
		_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
			for i := int64(0); i < length; i++ {
				var field KillRequestIEField
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
			return nil, runtime.WrapDecodePath(err, "KillRequestIEValueERABIEContainerList")
		}
		if _, err := aper.CaptureFinalBits(bb, "KillRequestIEValueERABIEContainerList"); err != nil {
			return nil, runtime.WrapDecodePath(err, "KillRequestIEValueERABIEContainerList")
		}
		return fields, nil
	}, encode: func(value KillRequestIEValueERABIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return codec.encode(KillRequestIEContainer(value), fresh, budget)
	}, capture: func(v KillRequestIEValueERABIEContainerList, options aper.DecodeState) (KillRequestIEValueERABIEContainerList, aper.Snapshot) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeKillRequestIEValueCaptureS1APERABIEContainerList(&v, &s)
		var root aper.Snapshot
		s.End(f, &root,

			false)
		return v, root
	}, compare: func(v KillRequestIEValueERABIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
	) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		BridgeKillRequestIEValueCompareS1APERABIEContainerList(&v, &s)
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

// KillResponseIEValueERABIEContainerListCodec constructs the E-RAB-IE-ContainerList {{KillResponseIEs}} codec of TS 36.413.
func KillResponseIEValueERABIEContainerListCodec(table s00.KillResponseIEValueIETable) KillResponseIEValueERABIEContainerListValueCodec {
	codec := KillResponseIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if codec.decode == nil {
		return KillResponseIEValueERABIEContainerListValueCodec{}
	}
	size := aper.SizeConstraint{Lower: (aper.ListBounds{Lower: 1, Upper: 256}).Lower, Upper: (aper.ListBounds{Lower: 1, Upper: 256}).Upper, HasLower: true, HasUpper: true}
	return KillResponseIEValueERABIEContainerListValueCodec{decode: func(data []byte, options aper.DecodeState) (KillResponseIEValueERABIEContainerList, error) {
		bb := aper.NewCompleteDecodeBuffer(data, options)
		if err := bb.SetDecodeOptionsAligned(options); err != nil {
			return nil, err
		}
		var fields KillResponseIEValueERABIEContainerList
		_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
			for i := int64(0); i < length; i++ {
				var field KillResponseIEField
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
			return nil, runtime.WrapDecodePath(err, "KillResponseIEValueERABIEContainerList")
		}
		if _, err := aper.CaptureFinalBits(bb, "KillResponseIEValueERABIEContainerList"); err != nil {
			return nil, runtime.WrapDecodePath(err, "KillResponseIEValueERABIEContainerList")
		}
		return fields, nil
	}, encode: func(value KillResponseIEValueERABIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return codec.encode(KillResponseIEContainer(value), fresh, budget)
	}, capture: func(v KillResponseIEValueERABIEContainerList, options aper.DecodeState) (KillResponseIEValueERABIEContainerList, aper.Snapshot) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeKillResponseIEValueCaptureS1APERABIEContainerList(&v, &s)
		var root aper.Snapshot
		s.End(f, &root,

			false)
		return v, root
	}, compare: func(v KillResponseIEValueERABIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
	) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		BridgeKillResponseIEValueCompareS1APERABIEContainerList(&v, &s)
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

// LocationReportIEValueERABIEContainerListCodec constructs the E-RAB-IE-ContainerList {{LocationReportIEs}} codec of TS 36.413.
func LocationReportIEValueERABIEContainerListCodec(table s00.LocationReportIEValueIETable) s32.LocationReportIEValueERABIEContainerListValueCodec {
	codec := LocationReportIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if *s32.BridgeLocationReportIEContainerValueCodecFieldDecode(&codec) == nil {
		return s32.LocationReportIEValueERABIEContainerListValueCodec{}
	}
	size := aper.SizeConstraint{Lower: (aper.ListBounds{Lower: 1, Upper: 256}).Lower, Upper: (aper.ListBounds{Lower: 1, Upper: 256}).Upper, HasLower: true, HasUpper: true}
	return func() s32.LocationReportIEValueERABIEContainerListValueCodec {
		sealed := s32.LocationReportIEValueERABIEContainerListValueCodec{}
		*s32.BridgeLocationReportIEValueERABIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s32.LocationReportIEValueERABIEContainerList, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s32.LocationReportIEValueERABIEContainerList
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s32.LocationReportIEField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s32.BridgeLocationReportIEFieldMethodUnmarshalAPERFrom(&field, bb)
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
				return nil, runtime.WrapDecodePath(err, "LocationReportIEValueERABIEContainerList")
			}
			if _, err := aper.CaptureFinalBits(bb, "LocationReportIEValueERABIEContainerList"); err != nil {
				return nil, runtime.WrapDecodePath(err, "LocationReportIEValueERABIEContainerList")
			}
			return fields, nil
		}
		*s32.BridgeLocationReportIEValueERABIEContainerListValueCodecFieldEncode(&sealed) = func(value s32.LocationReportIEValueERABIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s32.BridgeLocationReportIEContainerValueCodecFieldEncode(&codec))(s32.LocationReportIEContainer(value), fresh, budget)
		}
		*s32.BridgeLocationReportIEValueERABIEContainerListValueCodecFieldCapture(&sealed) = func(v s32.LocationReportIEValueERABIEContainerList, options aper.DecodeState) (s32.LocationReportIEValueERABIEContainerList, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeLocationReportIEValueCaptureS1APERABIEContainerList(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,

				false)
			return v, root
		}
		*s32.BridgeLocationReportIEValueERABIEContainerListValueCodecFieldCompare(&sealed) = func(v s32.LocationReportIEValueERABIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeLocationReportIEValueCompareS1APERABIEContainerList(&v, &s)
			s.End(f, root,

				false,
			)
			return s.Plan(), s.BudgetValue()
		}
		*s32.BridgeLocationReportIEValueERABIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ERABIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// KillRequestIEValueIEFieldTableCodec constructs the ProtocolIE-Field {{KillRequestIEs}} codec of TS 36.413.
func KillRequestIEValueIEFieldTableCodec(table s00.KillRequestIEValueIETable) KillRequestIEFieldValueCodec {
	if !*s00.BridgeKillRequestIEValueIETableFieldBound(&table) {
		return KillRequestIEFieldValueCodec{}
	}
	return KillRequestIEFieldValueCodec{decode: func(data []byte, options aper.DecodeState) (KillRequestIEField, error) {
		var field KillRequestIEField
		bb := aper.NewCompleteDecodeBuffer(data, options)
		if err := bb.SetDecodeOptionsAligned(options); err != nil {
			return field, err
		}
		if err := field.unmarshalAPERFrom(bb); err != nil {
			return field, runtime.WrapDecodePath(err, "KillRequestIEField")
		}
		if _, err := aper.CaptureFinalBits(bb, "KillRequestIEField"); err != nil {
			return field, runtime.WrapDecodePath(err, "KillRequestIEField")
		}
		return field, nil
	}, encode: func(field KillRequestIEField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		bb := aper.NewBudgetBuffer(budget)
		if err := field.marshalAPERTo(bb, fresh); err != nil {
			return nil, err
		}
		return bb.CompleteBytes(), nil
	}, capture: func(v KillRequestIEField, options aper.DecodeState) (KillRequestIEField, aper.Snapshot,
	) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeKillRequestIEValueCaptureS1APProtocolIEField(&v, &s)
		var root aper.Snapshot
		s.End(f, &root, false)
		return v, root
	}, compare: func(v KillRequestIEField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

	) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		BridgeKillRequestIEValueCompareS1APProtocolIEField(&v, &s)
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

// KillResponseIEValueIEFieldTableCodec constructs the ProtocolIE-Field {{KillResponseIEs}} codec of TS 36.413.
func KillResponseIEValueIEFieldTableCodec(table s00.KillResponseIEValueIETable) KillResponseIEFieldValueCodec {
	if !*s00.BridgeKillResponseIEValueIETableFieldBound(&table) {
		return KillResponseIEFieldValueCodec{}
	}
	return KillResponseIEFieldValueCodec{decode: func(data []byte, options aper.DecodeState) (KillResponseIEField, error) {
		var field KillResponseIEField
		bb := aper.NewCompleteDecodeBuffer(data, options)
		if err := bb.SetDecodeOptionsAligned(options); err != nil {
			return field, err
		}
		if err := field.unmarshalAPERFrom(bb); err != nil {
			return field, runtime.WrapDecodePath(err, "KillResponseIEField")
		}
		if _, err := aper.CaptureFinalBits(bb, "KillResponseIEField"); err != nil {
			return field, runtime.WrapDecodePath(err, "KillResponseIEField")
		}
		return field, nil
	}, encode: func(field KillResponseIEField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		bb := aper.NewBudgetBuffer(budget)
		if err := field.marshalAPERTo(bb, fresh); err != nil {
			return nil, err
		}
		return bb.CompleteBytes(), nil
	}, capture: func(v KillResponseIEField, options aper.DecodeState) (KillResponseIEField, aper.Snapshot,
	) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeKillResponseIEValueCaptureS1APProtocolIEField(&v, &s)
		var root aper.Snapshot
		s.End(f, &root, false)
		return v, root
	}, compare: func(v KillResponseIEField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

	) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		BridgeKillResponseIEValueCompareS1APProtocolIEField(&v, &s)
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

// LocationReportIEValueIEFieldTableCodec constructs the ProtocolIE-Field {{LocationReportIEs}} codec of TS 36.413.
func LocationReportIEValueIEFieldTableCodec(table s00.LocationReportIEValueIETable) s32.LocationReportIEFieldValueCodec {
	if !*s00.BridgeLocationReportIEValueIETableFieldBound(&table) {
		return s32.LocationReportIEFieldValueCodec{}
	}
	return func() s32.LocationReportIEFieldValueCodec {
		sealed := s32.LocationReportIEFieldValueCodec{}
		*s32.BridgeLocationReportIEFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s32.LocationReportIEField, error) {
			var field s32.LocationReportIEField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s32.BridgeLocationReportIEFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, runtime.WrapDecodePath(err, "LocationReportIEField")
			}
			if _, err := aper.CaptureFinalBits(bb, "LocationReportIEField"); err != nil {
				return field, runtime.WrapDecodePath(err, "LocationReportIEField")
			}
			return field, nil
		}
		*s32.BridgeLocationReportIEFieldValueCodecFieldEncode(&sealed) = func(field s32.LocationReportIEField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s32.BridgeLocationReportIEFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s32.BridgeLocationReportIEFieldValueCodecFieldCapture(&sealed) = func(v s32.LocationReportIEField, options aper.DecodeState) (s32.LocationReportIEField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeLocationReportIEValueCaptureS1APProtocolIEField(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s32.BridgeLocationReportIEFieldValueCodecFieldCompare(&sealed) = func(v s32.LocationReportIEField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeLocationReportIEValueCompareS1APProtocolIEField(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s32.BridgeLocationReportIEFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// RecommendedENBItemIEValueIEFieldTableCodec constructs the ProtocolIE-Field {{RecommendedENBItemIEs}} codec of TS 36.413.
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
				return field, runtime.WrapDecodePath(err, "RecommendedENBItemIEField")
			}
			if _, err := aper.CaptureFinalBits(bb, "RecommendedENBItemIEField"); err != nil {
				return field, runtime.WrapDecodePath(err, "RecommendedENBItemIEField")
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
			BridgeRecommendedENBItemIEValueCaptureS1APProtocolIEField(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
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

// KillRequestIEValueIETableCodec constructs the ProtocolIE-Container {{KillRequestIEs}} codec of TS 36.413.
func KillRequestIEValueIETableCodec(table s00.KillRequestIEValueIETable, bounds aper.ListBounds) KillRequestIEContainerValueCodec {
	if !*s00.BridgeKillRequestIEValueIETableFieldBound(&table) {
		return KillRequestIEContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return KillRequestIEContainerValueCodec{decode: func(data []byte, options aper.DecodeState) (KillRequestIEContainer, error) {
		bb := aper.NewCompleteDecodeBuffer(data, options)
		if err := bb.SetDecodeOptionsAligned(options); err != nil {
			return nil, err
		}
		var fields KillRequestIEContainer
		_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
			for i := int64(0); i < length; i++ {
				var field KillRequestIEField
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
			return nil, runtime.WrapDecodePath(err, "KillRequestIEContainer")
		}
		if _, err := aper.CaptureFinalBits(bb, "KillRequestIEContainer"); err != nil {
			return nil, runtime.WrapDecodePath(err, "KillRequestIEContainer")
		}
		return fields, nil
	},
		encode: func(fields KillRequestIEContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
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
		}, capture: func(v KillRequestIEContainer, options aper.DecodeState) (KillRequestIEContainer, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeKillRequestIEValueCaptureS1APProtocolIEContainer(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,

				false)
			return v, root
		}, compare: func(v KillRequestIEContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeKillRequestIEValueCompareS1APProtocolIEContainer(&v, &s)
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

// KillResponseIEValueIETableCodec constructs the ProtocolIE-Container {{KillResponseIEs}} codec of TS 36.413.
func KillResponseIEValueIETableCodec(table s00.KillResponseIEValueIETable, bounds aper.ListBounds) KillResponseIEContainerValueCodec {
	if !*s00.BridgeKillResponseIEValueIETableFieldBound(&table) {
		return KillResponseIEContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return KillResponseIEContainerValueCodec{decode: func(data []byte, options aper.DecodeState) (KillResponseIEContainer, error) {
		bb := aper.NewCompleteDecodeBuffer(data, options)
		if err := bb.SetDecodeOptionsAligned(options); err != nil {
			return nil, err
		}
		var fields KillResponseIEContainer
		_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
			for i := int64(0); i < length; i++ {
				var field KillResponseIEField
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
			return nil, runtime.WrapDecodePath(err, "KillResponseIEContainer")
		}
		if _, err := aper.CaptureFinalBits(bb, "KillResponseIEContainer"); err != nil {
			return nil, runtime.WrapDecodePath(err, "KillResponseIEContainer")
		}
		return fields, nil
	},
		encode: func(fields KillResponseIEContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
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
		}, capture: func(v KillResponseIEContainer, options aper.DecodeState) (KillResponseIEContainer, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeKillResponseIEValueCaptureS1APProtocolIEContainer(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,

				false)
			return v, root
		}, compare: func(v KillResponseIEContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeKillResponseIEValueCompareS1APProtocolIEContainer(&v, &s)
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

// LocationReportIEValueIETableCodec constructs the ProtocolIE-Container {{LocationReportIEs}} codec of TS 36.413.
func LocationReportIEValueIETableCodec(table s00.LocationReportIEValueIETable, bounds aper.ListBounds) s32.LocationReportIEContainerValueCodec {
	if !*s00.BridgeLocationReportIEValueIETableFieldBound(&table) {
		return s32.LocationReportIEContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s32.LocationReportIEContainerValueCodec {
		sealed := s32.LocationReportIEContainerValueCodec{}
		*s32.BridgeLocationReportIEContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s32.LocationReportIEContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s32.LocationReportIEContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s32.LocationReportIEField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s32.BridgeLocationReportIEFieldMethodUnmarshalAPERFrom(&field, bb)
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
				return nil, runtime.WrapDecodePath(err, "LocationReportIEContainer")
			}
			if _, err := aper.CaptureFinalBits(bb, "LocationReportIEContainer"); err != nil {
				return nil, runtime.WrapDecodePath(err, "LocationReportIEContainer")
			}
			return fields, nil
		}
		*s32.BridgeLocationReportIEContainerValueCodecFieldEncode(&sealed) = func(fields s32.LocationReportIEContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s32.BridgeLocationReportIEFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
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
		*s32.BridgeLocationReportIEContainerValueCodecFieldCapture(&sealed) = func(v s32.LocationReportIEContainer, options aper.DecodeState) (s32.LocationReportIEContainer, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeLocationReportIEValueCaptureS1APProtocolIEContainer(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,

				false)
			return v, root
		}
		*s32.BridgeLocationReportIEContainerValueCodecFieldCompare(&sealed) = func(v s32.LocationReportIEContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeLocationReportIEValueCompareS1APProtocolIEContainer(&v, &s)
			s.End(f, root,

				false,
			)
			return s.Plan(), s.BudgetValue()
		}
		*s32.BridgeLocationReportIEContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}

// RecommendedENBItemIEValueIETableCodec constructs the ProtocolIE-Container {{RecommendedENBItemIEs}} codec of TS 36.413.
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
					mark := bb.EnterIndex(int64(len(fields)))
					err := s32.BridgeRecommendedENBItemIEFieldMethodUnmarshalAPERFrom(&field, bb)
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
				return nil, runtime.WrapDecodePath(err, "RecommendedENBItemIEContainer")
			}
			if _, err := aper.CaptureFinalBits(bb, "RecommendedENBItemIEContainer"); err != nil {
				return nil, runtime.WrapDecodePath(err, "RecommendedENBItemIEContainer")
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
			s.End(f, &root,

				false)
			return v, root
		}
		*s32.BridgeRecommendedENBItemIEContainerValueCodecFieldCompare(&sealed) = func(v s32.RecommendedENBItemIEContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeRecommendedENBItemIEValueCompareS1APProtocolIEContainer(&v, &s)
			s.End(f, root,

				false,
			)
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

// KillRequestIEValueProtocolErrorIEContainerListCodec constructs the ProtocolError-IE-ContainerList {{KillRequestIEs}} codec of TS 36.413.
func KillRequestIEValueProtocolErrorIEContainerListCodec(table s00.KillRequestIEValueIETable) KillRequestIEValueProtocolErrorIEContainerListValueCodec {
	codec := KillRequestIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if codec.decode == nil {
		return KillRequestIEValueProtocolErrorIEContainerListValueCodec{}
	}
	size := aper.SizeConstraint{Lower: (aper.ListBounds{Lower: 1, Upper: 256}).Lower, Upper: (aper.ListBounds{Lower: 1, Upper: 256}).Upper, HasLower: true, HasUpper: true}
	return KillRequestIEValueProtocolErrorIEContainerListValueCodec{decode: func(data []byte, options aper.DecodeState) (KillRequestIEValueProtocolErrorIEContainerList, error) {
		bb := aper.NewCompleteDecodeBuffer(data, options)
		if err := bb.SetDecodeOptionsAligned(options); err != nil {
			return nil, err
		}
		var fields KillRequestIEValueProtocolErrorIEContainerList
		_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
			for i := int64(0); i < length; i++ {
				var field KillRequestIEField
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
			return nil, runtime.WrapDecodePath(err, "KillRequestIEValueProtocolErrorIEContainerList")
		}
		if _, err := aper.CaptureFinalBits(bb, "KillRequestIEValueProtocolErrorIEContainerList"); err != nil {
			return nil, runtime.WrapDecodePath(err, "KillRequestIEValueProtocolErrorIEContainerList")
		}
		return fields, nil
	}, encode: func(value KillRequestIEValueProtocolErrorIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return codec.encode(KillRequestIEContainer(value), fresh, budget)
	}, capture: func(v KillRequestIEValueProtocolErrorIEContainerList, options aper.DecodeState) (KillRequestIEValueProtocolErrorIEContainerList, aper.Snapshot,
	) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeKillRequestIEValueCaptureS1APProtocolErrorIEContainerList(&v, &s)
		var root aper.Snapshot

		s.End(f, &root, false)
		return v, root
	}, compare: func(v KillRequestIEValueProtocolErrorIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

	) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		BridgeKillRequestIEValueCompareS1APProtocolErrorIEContainerList(
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

// KillResponseIEValueProtocolErrorIEContainerListCodec constructs the ProtocolError-IE-ContainerList {{KillResponseIEs}} codec of TS 36.413.
func KillResponseIEValueProtocolErrorIEContainerListCodec(table s00.KillResponseIEValueIETable) KillResponseIEValueProtocolErrorIEContainerListValueCodec {
	codec := KillResponseIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if codec.decode == nil {
		return KillResponseIEValueProtocolErrorIEContainerListValueCodec{}
	}
	size := aper.SizeConstraint{Lower: (aper.ListBounds{Lower: 1, Upper: 256}).Lower, Upper: (aper.ListBounds{Lower: 1, Upper: 256}).Upper, HasLower: true, HasUpper: true}
	return KillResponseIEValueProtocolErrorIEContainerListValueCodec{decode: func(data []byte, options aper.DecodeState) (KillResponseIEValueProtocolErrorIEContainerList, error) {
		bb := aper.NewCompleteDecodeBuffer(data, options)
		if err := bb.SetDecodeOptionsAligned(options); err != nil {
			return nil, err
		}
		var fields KillResponseIEValueProtocolErrorIEContainerList
		_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
			for i := int64(0); i < length; i++ {
				var field KillResponseIEField
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
			return nil, runtime.WrapDecodePath(err, "KillResponseIEValueProtocolErrorIEContainerList")
		}
		if _, err := aper.CaptureFinalBits(bb, "KillResponseIEValueProtocolErrorIEContainerList"); err != nil {
			return nil, runtime.WrapDecodePath(err, "KillResponseIEValueProtocolErrorIEContainerList")
		}
		return fields, nil
	}, encode: func(value KillResponseIEValueProtocolErrorIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return codec.encode(KillResponseIEContainer(value), fresh, budget)
	}, capture: func(v KillResponseIEValueProtocolErrorIEContainerList, options aper.DecodeState) (KillResponseIEValueProtocolErrorIEContainerList, aper.Snapshot,
	) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeKillResponseIEValueCaptureS1APProtocolErrorIEContainerList(&v, &s)
		var root aper.Snapshot

		s.End(f, &root, false)
		return v, root
	}, compare: func(v KillResponseIEValueProtocolErrorIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

	) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		BridgeKillResponseIEValueCompareS1APProtocolErrorIEContainerList(
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

// LocationReportIEValueProtocolErrorIEContainerListCodec constructs the ProtocolError-IE-ContainerList {{LocationReportIEs}} codec of TS 36.413.
func LocationReportIEValueProtocolErrorIEContainerListCodec(table s00.LocationReportIEValueIETable) s32.LocationReportIEValueProtocolErrorIEContainerListValueCodec {
	codec := LocationReportIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if *s32.BridgeLocationReportIEContainerValueCodecFieldDecode(&codec) == nil {
		return s32.LocationReportIEValueProtocolErrorIEContainerListValueCodec{}
	}
	size := aper.SizeConstraint{Lower: (aper.ListBounds{Lower: 1, Upper: 256}).Lower, Upper: (aper.ListBounds{Lower: 1, Upper: 256}).Upper, HasLower: true, HasUpper: true}
	return func() s32.LocationReportIEValueProtocolErrorIEContainerListValueCodec {
		sealed := s32.LocationReportIEValueProtocolErrorIEContainerListValueCodec{}
		*s32.BridgeLocationReportIEValueProtocolErrorIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s32.LocationReportIEValueProtocolErrorIEContainerList, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s32.LocationReportIEValueProtocolErrorIEContainerList
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s32.LocationReportIEField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s32.BridgeLocationReportIEFieldMethodUnmarshalAPERFrom(&field, bb)
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
				return nil, runtime.WrapDecodePath(err, "LocationReportIEValueProtocolErrorIEContainerList")
			}
			if _, err := aper.CaptureFinalBits(bb, "LocationReportIEValueProtocolErrorIEContainerList"); err != nil {
				return nil, runtime.WrapDecodePath(err, "LocationReportIEValueProtocolErrorIEContainerList")
			}
			return fields, nil
		}
		*s32.BridgeLocationReportIEValueProtocolErrorIEContainerListValueCodecFieldEncode(&sealed) = func(value s32.LocationReportIEValueProtocolErrorIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s32.BridgeLocationReportIEContainerValueCodecFieldEncode(&codec))(s32.LocationReportIEContainer(value), fresh, budget)
		}
		*s32.BridgeLocationReportIEValueProtocolErrorIEContainerListValueCodecFieldCapture(&sealed) = func(v s32.LocationReportIEValueProtocolErrorIEContainerList, options aper.DecodeState) (s32.LocationReportIEValueProtocolErrorIEContainerList, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeLocationReportIEValueCaptureS1APProtocolErrorIEContainerList(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s32.BridgeLocationReportIEValueProtocolErrorIEContainerListValueCodecFieldCompare(&sealed) = func(v s32.LocationReportIEValueProtocolErrorIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeLocationReportIEValueCompareS1APProtocolErrorIEContainerList(
				&v,

				&s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s32.BridgeLocationReportIEValueProtocolErrorIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolErrorIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// KillRequestIEValueProtocolIEContainerListCodec constructs a codec for ProtocolIE-ContainerList with IEsSetParam = {KillRequestIEs} of TS 36.413, with lowerBound and upperBound supplied by its arguments.
func KillRequestIEValueProtocolIEContainerListCodec(table s00.KillRequestIEValueIETable, bounds aper.ListBounds) KillRequestIEValueProtocolIEContainerListValueCodec {
	codec := KillRequestIEValueIETableCodec(table, bounds)
	if codec.decode == nil {
		return KillRequestIEValueProtocolIEContainerListValueCodec{}
	}
	size := aper.SizeConstraint{Lower: (bounds).Lower, Upper: (bounds).Upper, HasLower: true, HasUpper: true}
	return KillRequestIEValueProtocolIEContainerListValueCodec{decode: func(data []byte, options aper.DecodeState) (KillRequestIEValueProtocolIEContainerList, error) {
		bb := aper.NewCompleteDecodeBuffer(data, options)
		if err := bb.SetDecodeOptionsAligned(options); err != nil {
			return nil, err
		}
		var fields KillRequestIEValueProtocolIEContainerList
		_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
			for i := int64(0); i < length; i++ {
				var field KillRequestIEField
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
			return nil, runtime.WrapDecodePath(err, "KillRequestIEValueProtocolIEContainerList")
		}
		if _, err := aper.CaptureFinalBits(bb, "KillRequestIEValueProtocolIEContainerList"); err != nil {
			return nil, runtime.WrapDecodePath(err, "KillRequestIEValueProtocolIEContainerList")
		}
		return fields, nil
	}, encode: func(value KillRequestIEValueProtocolIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return codec.encode(KillRequestIEContainer(value), fresh, budget)
	}, capture: func(v KillRequestIEValueProtocolIEContainerList, options aper.DecodeState) (KillRequestIEValueProtocolIEContainerList, aper.Snapshot,
	) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeKillRequestIEValueCaptureS1APProtocolIEContainerList(&v, &s)
		var root aper.Snapshot
		s.
			End(f, &root, false)
		return v, root
	}, compare: func(v KillRequestIEValueProtocolIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
	) {
		s := aper.NewSemanticComparison(root, budget)
		f :=
			s.Begin()
		BridgeKillRequestIEValueCompareS1APProtocolIEContainerList(&v, &s)
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

// KillResponseIEValueProtocolIEContainerListCodec constructs a codec for ProtocolIE-ContainerList with IEsSetParam = {KillResponseIEs} of TS 36.413, with lowerBound and upperBound supplied by its arguments.
func KillResponseIEValueProtocolIEContainerListCodec(table s00.KillResponseIEValueIETable, bounds aper.ListBounds) KillResponseIEValueProtocolIEContainerListValueCodec {
	codec := KillResponseIEValueIETableCodec(table, bounds)
	if codec.decode == nil {
		return KillResponseIEValueProtocolIEContainerListValueCodec{}
	}
	size := aper.SizeConstraint{Lower: (bounds).Lower, Upper: (bounds).Upper, HasLower: true, HasUpper: true}
	return KillResponseIEValueProtocolIEContainerListValueCodec{decode: func(data []byte, options aper.DecodeState) (KillResponseIEValueProtocolIEContainerList, error) {
		bb := aper.NewCompleteDecodeBuffer(data, options)
		if err := bb.SetDecodeOptionsAligned(options); err != nil {
			return nil, err
		}
		var fields KillResponseIEValueProtocolIEContainerList
		_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
			for i := int64(0); i < length; i++ {
				var field KillResponseIEField
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
			return nil, runtime.WrapDecodePath(err, "KillResponseIEValueProtocolIEContainerList")
		}
		if _, err := aper.CaptureFinalBits(bb, "KillResponseIEValueProtocolIEContainerList"); err != nil {
			return nil, runtime.WrapDecodePath(err, "KillResponseIEValueProtocolIEContainerList")
		}
		return fields, nil
	}, encode: func(value KillResponseIEValueProtocolIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return codec.encode(KillResponseIEContainer(value), fresh, budget)
	}, capture: func(v KillResponseIEValueProtocolIEContainerList, options aper.DecodeState) (KillResponseIEValueProtocolIEContainerList, aper.Snapshot,
	) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeKillResponseIEValueCaptureS1APProtocolIEContainerList(&v, &s)
		var root aper.Snapshot
		s.
			End(f, &root, false)
		return v, root
	}, compare: func(v KillResponseIEValueProtocolIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
	) {
		s := aper.NewSemanticComparison(root, budget)
		f :=
			s.Begin()
		BridgeKillResponseIEValueCompareS1APProtocolIEContainerList(&v, &s)
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

// LocationReportIEValueProtocolIEContainerListCodec constructs a codec for ProtocolIE-ContainerList with IEsSetParam = {LocationReportIEs} of TS 36.413, with lowerBound and upperBound supplied by its arguments.
func LocationReportIEValueProtocolIEContainerListCodec(table s00.LocationReportIEValueIETable, bounds aper.ListBounds) s32.LocationReportIEValueProtocolIEContainerListValueCodec {
	codec := LocationReportIEValueIETableCodec(table, bounds)
	if *s32.BridgeLocationReportIEContainerValueCodecFieldDecode(&codec) == nil {
		return s32.LocationReportIEValueProtocolIEContainerListValueCodec{}
	}
	size := aper.SizeConstraint{Lower: (bounds).Lower, Upper: (bounds).Upper, HasLower: true, HasUpper: true}
	return func() s32.LocationReportIEValueProtocolIEContainerListValueCodec {
		sealed := s32.LocationReportIEValueProtocolIEContainerListValueCodec{}
		*s32.BridgeLocationReportIEValueProtocolIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s32.LocationReportIEValueProtocolIEContainerList, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s32.LocationReportIEValueProtocolIEContainerList
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s32.LocationReportIEField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s32.BridgeLocationReportIEFieldMethodUnmarshalAPERFrom(&field, bb)
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
				return nil, runtime.WrapDecodePath(err, "LocationReportIEValueProtocolIEContainerList")
			}
			if _, err := aper.CaptureFinalBits(bb, "LocationReportIEValueProtocolIEContainerList"); err != nil {
				return nil, runtime.WrapDecodePath(err, "LocationReportIEValueProtocolIEContainerList")
			}
			return fields, nil
		}
		*s32.BridgeLocationReportIEValueProtocolIEContainerListValueCodecFieldEncode(&sealed) = func(value s32.LocationReportIEValueProtocolIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s32.BridgeLocationReportIEContainerValueCodecFieldEncode(&codec))(s32.LocationReportIEContainer(value), fresh, budget)
		}
		*s32.BridgeLocationReportIEValueProtocolIEContainerListValueCodecFieldCapture(&sealed) = func(v s32.LocationReportIEValueProtocolIEContainerList, options aper.DecodeState) (s32.LocationReportIEValueProtocolIEContainerList, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeLocationReportIEValueCaptureS1APProtocolIEContainerList(&v, &s)
			var root aper.Snapshot
			s.
				End(f, &root, false)
			return v, root
		}
		*s32.BridgeLocationReportIEValueProtocolIEContainerListValueCodecFieldCompare(&sealed) = func(v s32.LocationReportIEValueProtocolIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f :=
				s.Begin()
			BridgeLocationReportIEValueCompareS1APProtocolIEContainerList(&v, &s)
			s.End(
				f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s32.BridgeLocationReportIEValueProtocolIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}

// killRequestIEValueProtocolOpenValue is the concrete protocolOpenValue[KillRequestIEValue].
type KillRequestIEValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) KillRequestIEValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (KillRequestIEValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

func BridgeKillRequestIEValueCaptureS1APProtocolIEField(v *KillRequestIEField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolIEID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.Value = v.Value.captureSemantics(*s)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeKillRequestIEValueCompareS1APProtocolIEField(v *KillRequestIEField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s02.BridgeCompareS1APProtocolIEID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = v.Value.compareSemantics(*s)
	s.End(f, v.replay, v.withoutReplay)
}

// killResponseIEValueProtocolOpenValue is the concrete protocolOpenValue[KillResponseIEValue].
type KillResponseIEValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) KillResponseIEValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (KillResponseIEValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

func BridgeKillResponseIEValueCaptureS1APProtocolIEField(v *KillResponseIEField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolIEID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.Value = v.Value.captureSemantics(*s)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeKillResponseIEValueCompareS1APProtocolIEField(v *KillResponseIEField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s02.BridgeCompareS1APProtocolIEID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = v.Value.compareSemantics(*s)
	s.End(f, v.replay, v.withoutReplay)
}

// locationReportIEValueProtocolOpenValue is the concrete protocolOpenValue[LocationReportIEValue].
type LocationReportIEValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) s32.LocationReportIEValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (s32.LocationReportIEValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

func BridgeLocationReportIEValueCaptureS1APProtocolIEField(v *s32.LocationReportIEField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolIEID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.Value = s32.BridgeLocationReportIEValueMethodCaptureSemantics(v.Value, *s)
	s.End(f, s32.BridgeLocationReportIEFieldFieldReplay(v), *s32.BridgeLocationReportIEFieldFieldWithoutReplay(v))
}
func BridgeLocationReportIEValueCompareS1APProtocolIEField(v *s32.LocationReportIEField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s02.BridgeCompareS1APProtocolIEID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s32.BridgeLocationReportIEValueMethodCompareSemantics(v.Value, *s)
	s.End(f, *s32.BridgeLocationReportIEFieldFieldReplay(v), *s32.BridgeLocationReportIEFieldFieldWithoutReplay(v))
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

// WarningAreaListAPERValue is the concrete APERValue[WarningAreaList].
type WarningAreaListAPERValue struct {
	context s00.BridgeCodecContext
	Value   WarningAreaList

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v WarningAreaListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v WarningAreaListAPERValue) WithoutReplay() WarningAreaListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// BroadcastCancelledAreaListAPERValue is the concrete APERValue[BroadcastCancelledAreaList].
type BroadcastCancelledAreaListAPERValue struct {
	context s00.BridgeCodecContext
	Value   BroadcastCancelledAreaList

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v BroadcastCancelledAreaListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v BroadcastCancelledAreaListAPERValue) WithoutReplay() BroadcastCancelledAreaListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// AreaScopeOfMDTAPERValue is the concrete APERValue[AreaScopeOfMDT].
type AreaScopeOfMDTAPERValue struct {
	context s00.BridgeCodecContext
	Value   AreaScopeOfMDT

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v AreaScopeOfMDTAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v AreaScopeOfMDTAPERValue) WithoutReplay() AreaScopeOfMDTAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// AreaScopeOfQMCAPERValue is the concrete APERValue[AreaScopeOfQMC].
type AreaScopeOfQMCAPERValue struct {
	context s00.BridgeCodecContext
	Value   AreaScopeOfQMC

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v AreaScopeOfQMCAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v AreaScopeOfQMCAPERValue) WithoutReplay() AreaScopeOfQMCAPERValue {
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

// TAIBasedMDTAPERValue is the concrete APERValue[TAIBasedMDT].
type TAIBasedMDTAPERValue struct {
	context s00.BridgeCodecContext
	Value   TAIBasedMDT

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v TAIBasedMDTAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v TAIBasedMDTAPERValue) WithoutReplay() TAIBasedMDTAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// TAIBasedQMCAPERValue is the concrete APERValue[TAIBasedQMC].
type TAIBasedQMCAPERValue struct {
	context s00.BridgeCodecContext
	Value   TAIBasedQMC

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v TAIBasedQMCAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v TAIBasedQMCAPERValue) WithoutReplay() TAIBasedQMCAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// KillRequestIEValueERABIEContainerListValueCodec is the concrete ValueCodec[KillRequestIEValueERABIEContainerList].
type KillRequestIEValueERABIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (KillRequestIEValueERABIEContainerList, error)
	encode  func(KillRequestIEValueERABIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(KillRequestIEValueERABIEContainerList, aper.DecodeState) (KillRequestIEValueERABIEContainerList, aper.Snapshot)
	compare func(KillRequestIEValueERABIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c KillRequestIEValueERABIEContainerListValueCodec) New(value KillRequestIEValueERABIEContainerList) (KillRequestIEValueERABIEContainerListAPERValue, error) {
	if c.encode == nil {
		return KillRequestIEValueERABIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return KillRequestIEValueERABIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return KillRequestIEValueERABIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return KillRequestIEValueERABIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c KillRequestIEValueERABIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (KillRequestIEValueERABIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return KillRequestIEValueERABIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return KillRequestIEValueERABIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return KillRequestIEValueERABIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return KillRequestIEValueERABIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c KillRequestIEValueERABIEContainerListValueCodec) EncodeAPER(value KillRequestIEValueERABIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c KillRequestIEValueERABIEContainerListValueCodec) encodeBudgetValue(value KillRequestIEValueERABIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c KillRequestIEValueERABIEContainerListValueCodec) encodeChanged(value KillRequestIEValueERABIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// KillRequestIEValueERABIEContainerList is E-RAB-IE-ContainerList {{KillRequestIEs}} of TS 36.413: a list of information element fields.
type KillRequestIEValueERABIEContainerList []KillRequestIEValueProtocolIESingleContainer

func BridgeKillRequestIEValueCaptureS1APERABIEContainerList(v *KillRequestIEValueERABIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
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
func BridgeKillRequestIEValueCompareS1APERABIEContainerList(v *KillRequestIEValueERABIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
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

// KillResponseIEValueERABIEContainerListValueCodec is the concrete ValueCodec[KillResponseIEValueERABIEContainerList].
type KillResponseIEValueERABIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (KillResponseIEValueERABIEContainerList, error)
	encode  func(KillResponseIEValueERABIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(KillResponseIEValueERABIEContainerList, aper.DecodeState) (KillResponseIEValueERABIEContainerList, aper.Snapshot)
	compare func(KillResponseIEValueERABIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c KillResponseIEValueERABIEContainerListValueCodec) New(value KillResponseIEValueERABIEContainerList) (KillResponseIEValueERABIEContainerListAPERValue, error) {
	if c.encode == nil {
		return KillResponseIEValueERABIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return KillResponseIEValueERABIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return KillResponseIEValueERABIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return KillResponseIEValueERABIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c KillResponseIEValueERABIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (KillResponseIEValueERABIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return KillResponseIEValueERABIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return KillResponseIEValueERABIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return KillResponseIEValueERABIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return KillResponseIEValueERABIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c KillResponseIEValueERABIEContainerListValueCodec) EncodeAPER(value KillResponseIEValueERABIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c KillResponseIEValueERABIEContainerListValueCodec) encodeBudgetValue(value KillResponseIEValueERABIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c KillResponseIEValueERABIEContainerListValueCodec) encodeChanged(value KillResponseIEValueERABIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// KillResponseIEValueERABIEContainerList is E-RAB-IE-ContainerList {{KillResponseIEs}} of TS 36.413: a list of information element fields.
type KillResponseIEValueERABIEContainerList []KillResponseIEValueProtocolIESingleContainer

func BridgeKillResponseIEValueCaptureS1APERABIEContainerList(v *KillResponseIEValueERABIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
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
func BridgeKillResponseIEValueCompareS1APERABIEContainerList(v *KillResponseIEValueERABIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
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
func BridgeLocationReportIEValueCaptureS1APERABIEContainerList(v *s32.LocationReportIEValueERABIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
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
func BridgeLocationReportIEValueCompareS1APERABIEContainerList(v *s32.LocationReportIEValueERABIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
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

// WriteReplaceWarningRequestIEValueERABIEContainerListValueCodec is the concrete ValueCodec[WriteReplaceWarningRequestIEValueERABIEContainerList].
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

// WriteReplaceWarningRequestIEValueERABIEContainerList is E-RAB-IE-ContainerList {{WriteReplaceWarningRequestIEs}} of TS 36.413: a list of information element fields.
type WriteReplaceWarningRequestIEValueERABIEContainerList []WriteReplaceWarningRequestIEValueProtocolIESingleContainer

// WriteReplaceWarningResponseIEValueERABIEContainerListValueCodec is the concrete ValueCodec[WriteReplaceWarningResponseIEValueERABIEContainerList].
type WriteReplaceWarningResponseIEValueERABIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (WriteReplaceWarningResponseIEValueERABIEContainerList, error)
	encode  func(WriteReplaceWarningResponseIEValueERABIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(WriteReplaceWarningResponseIEValueERABIEContainerList, aper.DecodeState) (WriteReplaceWarningResponseIEValueERABIEContainerList, aper.Snapshot)
	compare func(WriteReplaceWarningResponseIEValueERABIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c WriteReplaceWarningResponseIEValueERABIEContainerListValueCodec) New(value WriteReplaceWarningResponseIEValueERABIEContainerList) (WriteReplaceWarningResponseIEValueERABIEContainerListAPERValue, error) {
	if c.encode == nil {
		return WriteReplaceWarningResponseIEValueERABIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return WriteReplaceWarningResponseIEValueERABIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return WriteReplaceWarningResponseIEValueERABIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return WriteReplaceWarningResponseIEValueERABIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c WriteReplaceWarningResponseIEValueERABIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (WriteReplaceWarningResponseIEValueERABIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return WriteReplaceWarningResponseIEValueERABIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return WriteReplaceWarningResponseIEValueERABIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return WriteReplaceWarningResponseIEValueERABIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return WriteReplaceWarningResponseIEValueERABIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c WriteReplaceWarningResponseIEValueERABIEContainerListValueCodec) EncodeAPER(value WriteReplaceWarningResponseIEValueERABIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c WriteReplaceWarningResponseIEValueERABIEContainerListValueCodec) encodeBudgetValue(value WriteReplaceWarningResponseIEValueERABIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c WriteReplaceWarningResponseIEValueERABIEContainerListValueCodec) encodeChanged(value WriteReplaceWarningResponseIEValueERABIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// WriteReplaceWarningResponseIEValueERABIEContainerList is E-RAB-IE-ContainerList {{WriteReplaceWarningResponseIEs}} of TS 36.413: a list of information element fields.
type WriteReplaceWarningResponseIEValueERABIEContainerList []WriteReplaceWarningResponseIEValueProtocolIESingleContainer

// KillRequestIEFieldValueCodec is the concrete ValueCodec[KillRequestIEField].
type KillRequestIEFieldValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (KillRequestIEField, error)
	encode  func(KillRequestIEField, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(KillRequestIEField, aper.DecodeState) (KillRequestIEField, aper.Snapshot)
	compare func(KillRequestIEField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c KillRequestIEFieldValueCodec) New(value KillRequestIEField) (KillRequestIEFieldAPERValue, error) {
	if c.encode == nil {
		return KillRequestIEFieldAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return KillRequestIEFieldAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return KillRequestIEFieldAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return KillRequestIEFieldAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c KillRequestIEFieldValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (KillRequestIEFieldAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return KillRequestIEFieldAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return KillRequestIEFieldAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return KillRequestIEFieldAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return KillRequestIEFieldAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c KillRequestIEFieldValueCodec) EncodeAPER(value KillRequestIEFieldAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c KillRequestIEFieldValueCodec) encodeBudgetValue(value KillRequestIEField, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c KillRequestIEFieldValueCodec) encodeChanged(value KillRequestIEField, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// KillResponseIEFieldValueCodec is the concrete ValueCodec[KillResponseIEField].
type KillResponseIEFieldValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (KillResponseIEField, error)
	encode  func(KillResponseIEField, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(KillResponseIEField, aper.DecodeState) (KillResponseIEField, aper.Snapshot)
	compare func(KillResponseIEField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c KillResponseIEFieldValueCodec) New(value KillResponseIEField) (KillResponseIEFieldAPERValue, error) {
	if c.encode == nil {
		return KillResponseIEFieldAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return KillResponseIEFieldAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return KillResponseIEFieldAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return KillResponseIEFieldAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c KillResponseIEFieldValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (KillResponseIEFieldAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return KillResponseIEFieldAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return KillResponseIEFieldAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return KillResponseIEFieldAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return KillResponseIEFieldAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c KillResponseIEFieldValueCodec) EncodeAPER(value KillResponseIEFieldAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c KillResponseIEFieldValueCodec) encodeBudgetValue(value KillResponseIEField, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c KillResponseIEFieldValueCodec) encodeChanged(value KillResponseIEField, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// WriteReplaceWarningRequestIEFieldValueCodec is the concrete ValueCodec[WriteReplaceWarningRequestIEField].
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

// WriteReplaceWarningResponseIEFieldValueCodec is the concrete ValueCodec[WriteReplaceWarningResponseIEField].
type WriteReplaceWarningResponseIEFieldValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (WriteReplaceWarningResponseIEField, error)
	encode  func(WriteReplaceWarningResponseIEField, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(WriteReplaceWarningResponseIEField, aper.DecodeState) (WriteReplaceWarningResponseIEField, aper.Snapshot)
	compare func(WriteReplaceWarningResponseIEField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c WriteReplaceWarningResponseIEFieldValueCodec) New(value WriteReplaceWarningResponseIEField) (WriteReplaceWarningResponseIEFieldAPERValue, error) {
	if c.encode == nil {
		return WriteReplaceWarningResponseIEFieldAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return WriteReplaceWarningResponseIEFieldAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return WriteReplaceWarningResponseIEFieldAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return WriteReplaceWarningResponseIEFieldAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c WriteReplaceWarningResponseIEFieldValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (WriteReplaceWarningResponseIEFieldAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return WriteReplaceWarningResponseIEFieldAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return WriteReplaceWarningResponseIEFieldAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return WriteReplaceWarningResponseIEFieldAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return WriteReplaceWarningResponseIEFieldAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c WriteReplaceWarningResponseIEFieldValueCodec) EncodeAPER(value WriteReplaceWarningResponseIEFieldAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c WriteReplaceWarningResponseIEFieldValueCodec) encodeBudgetValue(value WriteReplaceWarningResponseIEField, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c WriteReplaceWarningResponseIEFieldValueCodec) encodeChanged(value WriteReplaceWarningResponseIEField, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// KillRequestIEContainerValueCodec is the concrete ValueCodec[KillRequestIEContainer].
type KillRequestIEContainerValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (KillRequestIEContainer, error)
	encode  func(KillRequestIEContainer, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(KillRequestIEContainer, aper.DecodeState) (KillRequestIEContainer, aper.Snapshot)
	compare func(KillRequestIEContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c KillRequestIEContainerValueCodec) New(value KillRequestIEContainer) (KillRequestIEContainerAPERValue, error) {
	if c.encode == nil {
		return KillRequestIEContainerAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return KillRequestIEContainerAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return KillRequestIEContainerAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return KillRequestIEContainerAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c KillRequestIEContainerValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (KillRequestIEContainerAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return KillRequestIEContainerAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return KillRequestIEContainerAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return KillRequestIEContainerAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return KillRequestIEContainerAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c KillRequestIEContainerValueCodec) EncodeAPER(value KillRequestIEContainerAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c KillRequestIEContainerValueCodec) encodeBudgetValue(value KillRequestIEContainer, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c KillRequestIEContainerValueCodec) encodeChanged(value KillRequestIEContainer, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// KillResponseIEContainerValueCodec is the concrete ValueCodec[KillResponseIEContainer].
type KillResponseIEContainerValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (KillResponseIEContainer, error)
	encode  func(KillResponseIEContainer, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(KillResponseIEContainer, aper.DecodeState) (KillResponseIEContainer, aper.Snapshot)
	compare func(KillResponseIEContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c KillResponseIEContainerValueCodec) New(value KillResponseIEContainer) (KillResponseIEContainerAPERValue, error) {
	if c.encode == nil {
		return KillResponseIEContainerAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return KillResponseIEContainerAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return KillResponseIEContainerAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return KillResponseIEContainerAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c KillResponseIEContainerValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (KillResponseIEContainerAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return KillResponseIEContainerAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return KillResponseIEContainerAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return KillResponseIEContainerAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return KillResponseIEContainerAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c KillResponseIEContainerValueCodec) EncodeAPER(value KillResponseIEContainerAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c KillResponseIEContainerValueCodec) encodeBudgetValue(value KillResponseIEContainer, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c KillResponseIEContainerValueCodec) encodeChanged(value KillResponseIEContainer, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
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

// WriteReplaceWarningRequestIEContainerValueCodec is the concrete ValueCodec[WriteReplaceWarningRequestIEContainer].
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

// WriteReplaceWarningResponseIEContainerValueCodec is the concrete ValueCodec[WriteReplaceWarningResponseIEContainer].
type WriteReplaceWarningResponseIEContainerValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (WriteReplaceWarningResponseIEContainer, error)
	encode  func(WriteReplaceWarningResponseIEContainer, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(WriteReplaceWarningResponseIEContainer, aper.DecodeState) (WriteReplaceWarningResponseIEContainer, aper.Snapshot)
	compare func(WriteReplaceWarningResponseIEContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c WriteReplaceWarningResponseIEContainerValueCodec) New(value WriteReplaceWarningResponseIEContainer) (WriteReplaceWarningResponseIEContainerAPERValue, error) {
	if c.encode == nil {
		return WriteReplaceWarningResponseIEContainerAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return WriteReplaceWarningResponseIEContainerAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return WriteReplaceWarningResponseIEContainerAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return WriteReplaceWarningResponseIEContainerAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c WriteReplaceWarningResponseIEContainerValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (WriteReplaceWarningResponseIEContainerAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return WriteReplaceWarningResponseIEContainerAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return WriteReplaceWarningResponseIEContainerAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return WriteReplaceWarningResponseIEContainerAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return WriteReplaceWarningResponseIEContainerAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c WriteReplaceWarningResponseIEContainerValueCodec) EncodeAPER(value WriteReplaceWarningResponseIEContainerAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c WriteReplaceWarningResponseIEContainerValueCodec) encodeBudgetValue(value WriteReplaceWarningResponseIEContainer, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c WriteReplaceWarningResponseIEContainerValueCodec) encodeChanged(value WriteReplaceWarningResponseIEContainer, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// KillRequestIEValueProtocolErrorIEContainerListValueCodec is the concrete ValueCodec[KillRequestIEValueProtocolErrorIEContainerList].
type KillRequestIEValueProtocolErrorIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (KillRequestIEValueProtocolErrorIEContainerList, error)
	encode  func(KillRequestIEValueProtocolErrorIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(KillRequestIEValueProtocolErrorIEContainerList, aper.DecodeState) (KillRequestIEValueProtocolErrorIEContainerList, aper.Snapshot)
	compare func(KillRequestIEValueProtocolErrorIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c KillRequestIEValueProtocolErrorIEContainerListValueCodec) New(value KillRequestIEValueProtocolErrorIEContainerList) (KillRequestIEValueProtocolErrorIEContainerListAPERValue, error) {
	if c.encode == nil {
		return KillRequestIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return KillRequestIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return KillRequestIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return KillRequestIEValueProtocolErrorIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c KillRequestIEValueProtocolErrorIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (KillRequestIEValueProtocolErrorIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return KillRequestIEValueProtocolErrorIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return KillRequestIEValueProtocolErrorIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return KillRequestIEValueProtocolErrorIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return KillRequestIEValueProtocolErrorIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c KillRequestIEValueProtocolErrorIEContainerListValueCodec) EncodeAPER(value KillRequestIEValueProtocolErrorIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c KillRequestIEValueProtocolErrorIEContainerListValueCodec) encodeBudgetValue(value KillRequestIEValueProtocolErrorIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c KillRequestIEValueProtocolErrorIEContainerListValueCodec) encodeChanged(value KillRequestIEValueProtocolErrorIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// KillRequestIEValueProtocolErrorIEContainerList is ProtocolError-IE-ContainerList {{KillRequestIEs}} of TS 36.413: a list of information element fields.
type KillRequestIEValueProtocolErrorIEContainerList []KillRequestIEValueProtocolIESingleContainer

func BridgeKillRequestIEValueCaptureS1APProtocolErrorIEContainerList(v *KillRequestIEValueProtocolErrorIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
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
func BridgeKillRequestIEValueCompareS1APProtocolErrorIEContainerList(v *KillRequestIEValueProtocolErrorIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
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

// KillResponseIEValueProtocolErrorIEContainerListValueCodec is the concrete ValueCodec[KillResponseIEValueProtocolErrorIEContainerList].
type KillResponseIEValueProtocolErrorIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (KillResponseIEValueProtocolErrorIEContainerList, error)
	encode  func(KillResponseIEValueProtocolErrorIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(KillResponseIEValueProtocolErrorIEContainerList, aper.DecodeState) (KillResponseIEValueProtocolErrorIEContainerList, aper.Snapshot)
	compare func(KillResponseIEValueProtocolErrorIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c KillResponseIEValueProtocolErrorIEContainerListValueCodec) New(value KillResponseIEValueProtocolErrorIEContainerList) (KillResponseIEValueProtocolErrorIEContainerListAPERValue, error) {
	if c.encode == nil {
		return KillResponseIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return KillResponseIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return KillResponseIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return KillResponseIEValueProtocolErrorIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c KillResponseIEValueProtocolErrorIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (KillResponseIEValueProtocolErrorIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return KillResponseIEValueProtocolErrorIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return KillResponseIEValueProtocolErrorIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return KillResponseIEValueProtocolErrorIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return KillResponseIEValueProtocolErrorIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c KillResponseIEValueProtocolErrorIEContainerListValueCodec) EncodeAPER(value KillResponseIEValueProtocolErrorIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c KillResponseIEValueProtocolErrorIEContainerListValueCodec) encodeBudgetValue(value KillResponseIEValueProtocolErrorIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c KillResponseIEValueProtocolErrorIEContainerListValueCodec) encodeChanged(value KillResponseIEValueProtocolErrorIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// KillResponseIEValueProtocolErrorIEContainerList is ProtocolError-IE-ContainerList {{KillResponseIEs}} of TS 36.413: a list of information element fields.
type KillResponseIEValueProtocolErrorIEContainerList []KillResponseIEValueProtocolIESingleContainer

func BridgeKillResponseIEValueCaptureS1APProtocolErrorIEContainerList(v *KillResponseIEValueProtocolErrorIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
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
func BridgeKillResponseIEValueCompareS1APProtocolErrorIEContainerList(v *KillResponseIEValueProtocolErrorIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
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
func BridgeLocationReportIEValueCaptureS1APProtocolErrorIEContainerList(v *s32.LocationReportIEValueProtocolErrorIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
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
func BridgeLocationReportIEValueCompareS1APProtocolErrorIEContainerList(v *s32.LocationReportIEValueProtocolErrorIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
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

// WriteReplaceWarningRequestIEValueProtocolErrorIEContainerListValueCodec is the concrete ValueCodec[WriteReplaceWarningRequestIEValueProtocolErrorIEContainerList].
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

// WriteReplaceWarningRequestIEValueProtocolErrorIEContainerList is ProtocolError-IE-ContainerList {{WriteReplaceWarningRequestIEs}} of TS 36.413: a list of information element fields.
type WriteReplaceWarningRequestIEValueProtocolErrorIEContainerList []WriteReplaceWarningRequestIEValueProtocolIESingleContainer

// WriteReplaceWarningResponseIEValueProtocolErrorIEContainerListValueCodec is the concrete ValueCodec[WriteReplaceWarningResponseIEValueProtocolErrorIEContainerList].
type WriteReplaceWarningResponseIEValueProtocolErrorIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (WriteReplaceWarningResponseIEValueProtocolErrorIEContainerList, error)
	encode  func(WriteReplaceWarningResponseIEValueProtocolErrorIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(WriteReplaceWarningResponseIEValueProtocolErrorIEContainerList, aper.DecodeState) (WriteReplaceWarningResponseIEValueProtocolErrorIEContainerList, aper.Snapshot)
	compare func(WriteReplaceWarningResponseIEValueProtocolErrorIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c WriteReplaceWarningResponseIEValueProtocolErrorIEContainerListValueCodec) New(value WriteReplaceWarningResponseIEValueProtocolErrorIEContainerList) (WriteReplaceWarningResponseIEValueProtocolErrorIEContainerListAPERValue, error) {
	if c.encode == nil {
		return WriteReplaceWarningResponseIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return WriteReplaceWarningResponseIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return WriteReplaceWarningResponseIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return WriteReplaceWarningResponseIEValueProtocolErrorIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c WriteReplaceWarningResponseIEValueProtocolErrorIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (WriteReplaceWarningResponseIEValueProtocolErrorIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return WriteReplaceWarningResponseIEValueProtocolErrorIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return WriteReplaceWarningResponseIEValueProtocolErrorIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return WriteReplaceWarningResponseIEValueProtocolErrorIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return WriteReplaceWarningResponseIEValueProtocolErrorIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c WriteReplaceWarningResponseIEValueProtocolErrorIEContainerListValueCodec) EncodeAPER(value WriteReplaceWarningResponseIEValueProtocolErrorIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c WriteReplaceWarningResponseIEValueProtocolErrorIEContainerListValueCodec) encodeBudgetValue(value WriteReplaceWarningResponseIEValueProtocolErrorIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c WriteReplaceWarningResponseIEValueProtocolErrorIEContainerListValueCodec) encodeChanged(value WriteReplaceWarningResponseIEValueProtocolErrorIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// WriteReplaceWarningResponseIEValueProtocolErrorIEContainerList is ProtocolError-IE-ContainerList {{WriteReplaceWarningResponseIEs}} of TS 36.413: a list of information element fields.
type WriteReplaceWarningResponseIEValueProtocolErrorIEContainerList []WriteReplaceWarningResponseIEValueProtocolIESingleContainer

// KillRequestIEValueProtocolIEContainerListValueCodec is the concrete ValueCodec[KillRequestIEValueProtocolIEContainerList].
type KillRequestIEValueProtocolIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (KillRequestIEValueProtocolIEContainerList, error)
	encode  func(KillRequestIEValueProtocolIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(KillRequestIEValueProtocolIEContainerList, aper.DecodeState) (KillRequestIEValueProtocolIEContainerList, aper.Snapshot)
	compare func(KillRequestIEValueProtocolIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c KillRequestIEValueProtocolIEContainerListValueCodec) New(value KillRequestIEValueProtocolIEContainerList) (KillRequestIEValueProtocolIEContainerListAPERValue, error) {
	if c.encode == nil {
		return KillRequestIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return KillRequestIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return KillRequestIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return KillRequestIEValueProtocolIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c KillRequestIEValueProtocolIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (KillRequestIEValueProtocolIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return KillRequestIEValueProtocolIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return KillRequestIEValueProtocolIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return KillRequestIEValueProtocolIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return KillRequestIEValueProtocolIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c KillRequestIEValueProtocolIEContainerListValueCodec) EncodeAPER(value KillRequestIEValueProtocolIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c KillRequestIEValueProtocolIEContainerListValueCodec) encodeBudgetValue(value KillRequestIEValueProtocolIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c KillRequestIEValueProtocolIEContainerListValueCodec) encodeChanged(value KillRequestIEValueProtocolIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// KillRequestIEValueProtocolIEContainerList is ProtocolIE-ContainerList with IEsSetParam = {KillRequestIEs} of TS 36.413: a list of information element fields with lowerBound and upperBound supplied by its concrete factory.
type KillRequestIEValueProtocolIEContainerList []KillRequestIEValueProtocolIESingleContainer

func BridgeKillRequestIEValueCaptureS1APProtocolIEContainerList(v *KillRequestIEValueProtocolIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
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
func BridgeKillRequestIEValueCompareS1APProtocolIEContainerList(v *KillRequestIEValueProtocolIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
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

// KillResponseIEValueProtocolIEContainerListValueCodec is the concrete ValueCodec[KillResponseIEValueProtocolIEContainerList].
type KillResponseIEValueProtocolIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (KillResponseIEValueProtocolIEContainerList, error)
	encode  func(KillResponseIEValueProtocolIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(KillResponseIEValueProtocolIEContainerList, aper.DecodeState) (KillResponseIEValueProtocolIEContainerList, aper.Snapshot)
	compare func(KillResponseIEValueProtocolIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c KillResponseIEValueProtocolIEContainerListValueCodec) New(value KillResponseIEValueProtocolIEContainerList) (KillResponseIEValueProtocolIEContainerListAPERValue, error) {
	if c.encode == nil {
		return KillResponseIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return KillResponseIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return KillResponseIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return KillResponseIEValueProtocolIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c KillResponseIEValueProtocolIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (KillResponseIEValueProtocolIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return KillResponseIEValueProtocolIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return KillResponseIEValueProtocolIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return KillResponseIEValueProtocolIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return KillResponseIEValueProtocolIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c KillResponseIEValueProtocolIEContainerListValueCodec) EncodeAPER(value KillResponseIEValueProtocolIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c KillResponseIEValueProtocolIEContainerListValueCodec) encodeBudgetValue(value KillResponseIEValueProtocolIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c KillResponseIEValueProtocolIEContainerListValueCodec) encodeChanged(value KillResponseIEValueProtocolIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// KillResponseIEValueProtocolIEContainerList is ProtocolIE-ContainerList with IEsSetParam = {KillResponseIEs} of TS 36.413: a list of information element fields with lowerBound and upperBound supplied by its concrete factory.
type KillResponseIEValueProtocolIEContainerList []KillResponseIEValueProtocolIESingleContainer

func BridgeKillResponseIEValueCaptureS1APProtocolIEContainerList(v *KillResponseIEValueProtocolIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
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
func BridgeKillResponseIEValueCompareS1APProtocolIEContainerList(v *KillResponseIEValueProtocolIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
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
func BridgeLocationReportIEValueCaptureS1APProtocolIEContainerList(v *s32.LocationReportIEValueProtocolIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
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
func BridgeLocationReportIEValueCompareS1APProtocolIEContainerList(v *s32.LocationReportIEValueProtocolIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
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

// WriteReplaceWarningRequestIEValueProtocolIEContainerListValueCodec is the concrete ValueCodec[WriteReplaceWarningRequestIEValueProtocolIEContainerList].
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

// WriteReplaceWarningRequestIEValueProtocolIEContainerList is ProtocolIE-ContainerList with IEsSetParam = {WriteReplaceWarningRequestIEs} of TS 36.413: a list of information element fields with lowerBound and upperBound supplied by its concrete factory.
type WriteReplaceWarningRequestIEValueProtocolIEContainerList []WriteReplaceWarningRequestIEValueProtocolIESingleContainer

// WriteReplaceWarningResponseIEValueProtocolIEContainerListValueCodec is the concrete ValueCodec[WriteReplaceWarningResponseIEValueProtocolIEContainerList].
type WriteReplaceWarningResponseIEValueProtocolIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (WriteReplaceWarningResponseIEValueProtocolIEContainerList, error)
	encode  func(WriteReplaceWarningResponseIEValueProtocolIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(WriteReplaceWarningResponseIEValueProtocolIEContainerList, aper.DecodeState) (WriteReplaceWarningResponseIEValueProtocolIEContainerList, aper.Snapshot)
	compare func(WriteReplaceWarningResponseIEValueProtocolIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c WriteReplaceWarningResponseIEValueProtocolIEContainerListValueCodec) New(value WriteReplaceWarningResponseIEValueProtocolIEContainerList) (WriteReplaceWarningResponseIEValueProtocolIEContainerListAPERValue, error) {
	if c.encode == nil {
		return WriteReplaceWarningResponseIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return WriteReplaceWarningResponseIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return WriteReplaceWarningResponseIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return WriteReplaceWarningResponseIEValueProtocolIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c WriteReplaceWarningResponseIEValueProtocolIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (WriteReplaceWarningResponseIEValueProtocolIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return WriteReplaceWarningResponseIEValueProtocolIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return WriteReplaceWarningResponseIEValueProtocolIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return WriteReplaceWarningResponseIEValueProtocolIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return WriteReplaceWarningResponseIEValueProtocolIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c WriteReplaceWarningResponseIEValueProtocolIEContainerListValueCodec) EncodeAPER(value WriteReplaceWarningResponseIEValueProtocolIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c WriteReplaceWarningResponseIEValueProtocolIEContainerListValueCodec) encodeBudgetValue(value WriteReplaceWarningResponseIEValueProtocolIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c WriteReplaceWarningResponseIEValueProtocolIEContainerListValueCodec) encodeChanged(value WriteReplaceWarningResponseIEValueProtocolIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// WriteReplaceWarningResponseIEValueProtocolIEContainerList is ProtocolIE-ContainerList with IEsSetParam = {WriteReplaceWarningResponseIEs} of TS 36.413: a list of information element fields with lowerBound and upperBound supplied by its concrete factory.
type WriteReplaceWarningResponseIEValueProtocolIEContainerList []WriteReplaceWarningResponseIEValueProtocolIESingleContainer

// KillRequestIEValueERABIEContainerListAPERValue is the concrete APERValue[KillRequestIEValueERABIEContainerList].
type KillRequestIEValueERABIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         KillRequestIEValueERABIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v KillRequestIEValueERABIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v KillRequestIEValueERABIEContainerListAPERValue) WithoutReplay() KillRequestIEValueERABIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// KillRequestIEValueProtocolIESingleContainer is ProtocolIE-SingleContainer {{KillRequestIEs}} of TS 36.413: a single information element field.
type KillRequestIEValueProtocolIESingleContainer = KillRequestIEField

func BridgeKillRequestIEValueCaptureS1APProtocolIESingleContainer(v *KillRequestIEValueProtocolIESingleContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeKillRequestIEValueCaptureS1APProtocolIEField(v, s)
	s.End(f, nil, false)
}
func BridgeKillRequestIEValueCompareS1APProtocolIESingleContainer(v *KillRequestIEValueProtocolIESingleContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeKillRequestIEValueCompareS1APProtocolIEField(v, s)
	s.End(f, aper.Snapshot{}, false)
}

// KillResponseIEValueERABIEContainerListAPERValue is the concrete APERValue[KillResponseIEValueERABIEContainerList].
type KillResponseIEValueERABIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         KillResponseIEValueERABIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v KillResponseIEValueERABIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v KillResponseIEValueERABIEContainerListAPERValue) WithoutReplay() KillResponseIEValueERABIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// KillResponseIEValueProtocolIESingleContainer is ProtocolIE-SingleContainer {{KillResponseIEs}} of TS 36.413: a single information element field.
type KillResponseIEValueProtocolIESingleContainer = KillResponseIEField

func BridgeKillResponseIEValueCaptureS1APProtocolIESingleContainer(v *KillResponseIEValueProtocolIESingleContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeKillResponseIEValueCaptureS1APProtocolIEField(v, s)
	s.End(f, nil, false)
}
func BridgeKillResponseIEValueCompareS1APProtocolIESingleContainer(v *KillResponseIEValueProtocolIESingleContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeKillResponseIEValueCompareS1APProtocolIEField(v, s)
	s.End(f, aper.Snapshot{}, false)
}
func BridgeLocationReportIEValueCaptureS1APProtocolIESingleContainer(v *s32.LocationReportIEValueProtocolIESingleContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeLocationReportIEValueCaptureS1APProtocolIEField(v, s)
	s.End(f, nil, false)
}
func BridgeLocationReportIEValueCompareS1APProtocolIESingleContainer(v *s32.LocationReportIEValueProtocolIESingleContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeLocationReportIEValueCompareS1APProtocolIEField(v, s)
	s.End(f, aper.Snapshot{}, false)
}

// WriteReplaceWarningRequestIEValueERABIEContainerListAPERValue is the concrete APERValue[WriteReplaceWarningRequestIEValueERABIEContainerList].
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

// WriteReplaceWarningRequestIEValueProtocolIESingleContainer is ProtocolIE-SingleContainer {{WriteReplaceWarningRequestIEs}} of TS 36.413: a single information element field.
type WriteReplaceWarningRequestIEValueProtocolIESingleContainer = WriteReplaceWarningRequestIEField

// WriteReplaceWarningResponseIEValueERABIEContainerListAPERValue is the concrete APERValue[WriteReplaceWarningResponseIEValueERABIEContainerList].
type WriteReplaceWarningResponseIEValueERABIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         WriteReplaceWarningResponseIEValueERABIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v WriteReplaceWarningResponseIEValueERABIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v WriteReplaceWarningResponseIEValueERABIEContainerListAPERValue) WithoutReplay() WriteReplaceWarningResponseIEValueERABIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// WriteReplaceWarningResponseIEValueProtocolIESingleContainer is ProtocolIE-SingleContainer {{WriteReplaceWarningResponseIEs}} of TS 36.413: a single information element field.
type WriteReplaceWarningResponseIEValueProtocolIESingleContainer = WriteReplaceWarningResponseIEField

// KillRequestIEFieldAPERValue is the concrete APERValue[KillRequestIEField].
type KillRequestIEFieldAPERValue struct {
	context       s00.BridgeCodecContext
	Value         KillRequestIEField
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v KillRequestIEFieldAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v KillRequestIEFieldAPERValue) WithoutReplay() KillRequestIEFieldAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// KillResponseIEFieldAPERValue is the concrete APERValue[KillResponseIEField].
type KillResponseIEFieldAPERValue struct {
	context       s00.BridgeCodecContext
	Value         KillResponseIEField
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v KillResponseIEFieldAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v KillResponseIEFieldAPERValue) WithoutReplay() KillResponseIEFieldAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// WriteReplaceWarningRequestIEFieldAPERValue is the concrete APERValue[WriteReplaceWarningRequestIEField].
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

// WriteReplaceWarningResponseIEFieldAPERValue is the concrete APERValue[WriteReplaceWarningResponseIEField].
type WriteReplaceWarningResponseIEFieldAPERValue struct {
	context       s00.BridgeCodecContext
	Value         WriteReplaceWarningResponseIEField
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v WriteReplaceWarningResponseIEFieldAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v WriteReplaceWarningResponseIEFieldAPERValue) WithoutReplay() WriteReplaceWarningResponseIEFieldAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// KillRequestIEContainerAPERValue is the concrete APERValue[KillRequestIEContainer].
type KillRequestIEContainerAPERValue struct {
	context       s00.BridgeCodecContext
	Value         KillRequestIEContainer
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v KillRequestIEContainerAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v KillRequestIEContainerAPERValue) WithoutReplay() KillRequestIEContainerAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// KillResponseIEContainerAPERValue is the concrete APERValue[KillResponseIEContainer].
type KillResponseIEContainerAPERValue struct {
	context       s00.BridgeCodecContext
	Value         KillResponseIEContainer
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v KillResponseIEContainerAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v KillResponseIEContainerAPERValue) WithoutReplay() KillResponseIEContainerAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// WriteReplaceWarningRequestIEContainerAPERValue is the concrete APERValue[WriteReplaceWarningRequestIEContainer].
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

// WriteReplaceWarningResponseIEContainerAPERValue is the concrete APERValue[WriteReplaceWarningResponseIEContainer].
type WriteReplaceWarningResponseIEContainerAPERValue struct {
	context       s00.BridgeCodecContext
	Value         WriteReplaceWarningResponseIEContainer
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v WriteReplaceWarningResponseIEContainerAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v WriteReplaceWarningResponseIEContainerAPERValue) WithoutReplay() WriteReplaceWarningResponseIEContainerAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// KillRequestIEValueProtocolErrorIEContainerListAPERValue is the concrete APERValue[KillRequestIEValueProtocolErrorIEContainerList].
type KillRequestIEValueProtocolErrorIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         KillRequestIEValueProtocolErrorIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v KillRequestIEValueProtocolErrorIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v KillRequestIEValueProtocolErrorIEContainerListAPERValue) WithoutReplay() KillRequestIEValueProtocolErrorIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// KillResponseIEValueProtocolErrorIEContainerListAPERValue is the concrete APERValue[KillResponseIEValueProtocolErrorIEContainerList].
type KillResponseIEValueProtocolErrorIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         KillResponseIEValueProtocolErrorIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v KillResponseIEValueProtocolErrorIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v KillResponseIEValueProtocolErrorIEContainerListAPERValue) WithoutReplay() KillResponseIEValueProtocolErrorIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// WriteReplaceWarningRequestIEValueProtocolErrorIEContainerListAPERValue is the concrete APERValue[WriteReplaceWarningRequestIEValueProtocolErrorIEContainerList].
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

// WriteReplaceWarningResponseIEValueProtocolErrorIEContainerListAPERValue is the concrete APERValue[WriteReplaceWarningResponseIEValueProtocolErrorIEContainerList].
type WriteReplaceWarningResponseIEValueProtocolErrorIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         WriteReplaceWarningResponseIEValueProtocolErrorIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v WriteReplaceWarningResponseIEValueProtocolErrorIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v WriteReplaceWarningResponseIEValueProtocolErrorIEContainerListAPERValue) WithoutReplay() WriteReplaceWarningResponseIEValueProtocolErrorIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// KillRequestIEValueProtocolIEContainerListAPERValue is the concrete APERValue[KillRequestIEValueProtocolIEContainerList].
type KillRequestIEValueProtocolIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         KillRequestIEValueProtocolIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v KillRequestIEValueProtocolIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v KillRequestIEValueProtocolIEContainerListAPERValue) WithoutReplay() KillRequestIEValueProtocolIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// KillResponseIEValueProtocolIEContainerListAPERValue is the concrete APERValue[KillResponseIEValueProtocolIEContainerList].
type KillResponseIEValueProtocolIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         KillResponseIEValueProtocolIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v KillResponseIEValueProtocolIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v KillResponseIEValueProtocolIEContainerListAPERValue) WithoutReplay() KillResponseIEValueProtocolIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// WriteReplaceWarningRequestIEValueProtocolIEContainerListAPERValue is the concrete APERValue[WriteReplaceWarningRequestIEValueProtocolIEContainerList].
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

// WriteReplaceWarningResponseIEValueProtocolIEContainerListAPERValue is the concrete APERValue[WriteReplaceWarningResponseIEValueProtocolIEContainerList].
type WriteReplaceWarningResponseIEValueProtocolIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         WriteReplaceWarningResponseIEValueProtocolIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v WriteReplaceWarningResponseIEValueProtocolIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v WriteReplaceWarningResponseIEValueProtocolIEContainerListAPERValue) WithoutReplay() WriteReplaceWarningResponseIEValueProtocolIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}
func BridgeCaptureS1APAreaScopeOfMDT(v *AreaScopeOfMDT, s *aper.SemanticCapture) {
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
	case s00.AreaScopeOfMDTChoiceCellBased:
		{
			f := s.Begin()
			s.Bool(v.CellBased == nil)
			if v.CellBased != nil {
				s22.BridgeCaptureS1APCellBasedMDT(v.CellBased, s)
			}
			s.End(f, nil, false)
		}
	case s00.AreaScopeOfMDTChoiceTABased:
		{
			f := s.Begin()
			s.Bool(v.TABased == nil)
			if v.TABased != nil {
				s32.BridgeCaptureS1APTABasedMDT(v.TABased, s)
			}
			s.End(f, nil, false)
		}
	case s00.AreaScopeOfMDTChoicePLMNWide:
		{
			f := s.Begin()
			s.Bool(v.PLMNWide == nil)
			if v.PLMNWide != nil {
			}
			s.End(f, nil, false)
		}
	case s00.AreaScopeOfMDTChoiceTAIBased:
		{
			f := s.Begin()
			s.Bool(v.TAIBased == nil)
			if v.TAIBased != nil {
				BridgeCaptureS1APTAIBasedMDT(v.TAIBased, s)
			}
			s.End(f, nil, false)
		}
	}
	s.End(f, &v.replay, v.withoutReplay)
	if v.UnknownExtension == nil && v.Choice > 3 {
		s.CheckChoice(v.replay, v.stream)
	}
}
func BridgeCompareS1APAreaScopeOfMDT(v *AreaScopeOfMDT, s *aper.SemanticComparison) {
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
	case s00.AreaScopeOfMDTChoiceCellBased:
		{
			f := s.Begin()
			s.Bool(v.CellBased == nil)
			if v.CellBased != nil {
				s22.BridgeCompareS1APCellBasedMDT(v.CellBased, s)
			}
			s.End(f, aper.Snapshot{}, false)
		}
	case s00.AreaScopeOfMDTChoiceTABased:
		{
			f := s.Begin()
			s.Bool(v.TABased == nil)
			if v.TABased != nil {
				s32.BridgeCompareS1APTABasedMDT(v.TABased, s)
			}
			s.End(f, aper.Snapshot{}, false)
		}
	case s00.AreaScopeOfMDTChoicePLMNWide:
		{
			f := s.Begin()
			s.Bool(v.PLMNWide == nil)
			if v.PLMNWide != nil {
			}
			s.End(f, aper.Snapshot{}, false)
		}
	case s00.AreaScopeOfMDTChoiceTAIBased:
		{
			f := s.Begin()
			s.Bool(v.TAIBased == nil)
			if v.TAIBased != nil {
				BridgeCompareS1APTAIBasedMDT(v.TAIBased, s)
			}
			s.End(f, aper.Snapshot{}, false)
		}
	}
	s.End(f, v.replay, v.withoutReplay)
	if v.UnknownExtension == nil && v.Choice > 3 {
		s.CheckChoice(v.replay, v.stream)
	}
}
func BridgeCaptureS1APAreaScopeOfQMC(v *AreaScopeOfQMC, s *aper.SemanticCapture) {
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
	case s00.AreaScopeOfQMCChoiceCellBased:
		{
			f := s.Begin()
			s.Bool(v.CellBased == nil)
			if v.CellBased != nil {
				s22.BridgeCaptureS1APCellBasedQMC(v.CellBased, s)
			}
			s.End(f, nil, false)
		}
	case s00.AreaScopeOfQMCChoiceTABased:
		{
			f := s.Begin()
			s.Bool(v.TABased == nil)
			if v.TABased != nil {
				s32.BridgeCaptureS1APTABasedQMC(v.TABased, s)
			}
			s.End(f, nil, false)
		}
	case s00.AreaScopeOfQMCChoiceTAIBased:
		{
			f := s.Begin()
			s.Bool(v.TAIBased == nil)
			if v.TAIBased != nil {
				BridgeCaptureS1APTAIBasedQMC(v.TAIBased, s)
			}
			s.End(f, nil, false)
		}
	case s00.AreaScopeOfQMCChoicePLMNAreaBased:
		{
			f := s.Begin()
			s.Bool(v.PLMNAreaBased == nil)
			if v.PLMNAreaBased != nil {
				s20.BridgeCaptureS1APPLMNAreaBasedQMC(v.PLMNAreaBased, s)
			}
			s.End(f, nil, false)
		}
	}
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APAreaScopeOfQMC(v *AreaScopeOfQMC, s *aper.SemanticComparison) {
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
	case s00.AreaScopeOfQMCChoiceCellBased:
		{
			f := s.Begin()
			s.Bool(v.CellBased == nil)
			if v.CellBased != nil {
				s22.BridgeCompareS1APCellBasedQMC(v.CellBased, s)
			}
			s.End(f, aper.Snapshot{}, false)
		}
	case s00.AreaScopeOfQMCChoiceTABased:
		{
			f := s.Begin()
			s.Bool(v.TABased == nil)
			if v.TABased != nil {
				s32.BridgeCompareS1APTABasedQMC(v.TABased, s)
			}
			s.End(f, aper.Snapshot{}, false)
		}
	case s00.AreaScopeOfQMCChoiceTAIBased:
		{
			f := s.Begin()
			s.Bool(v.TAIBased == nil)
			if v.TAIBased != nil {
				BridgeCompareS1APTAIBasedQMC(v.TAIBased, s)
			}
			s.End(f, aper.Snapshot{}, false)
		}
	case s00.AreaScopeOfQMCChoicePLMNAreaBased:
		{
			f := s.Begin()
			s.Bool(v.PLMNAreaBased == nil)
			if v.PLMNAreaBased != nil {
				s20.BridgeCompareS1APPLMNAreaBasedQMC(v.PLMNAreaBased, s)
			}
			s.End(f, aper.Snapshot{}, false)
		}
	}
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APBroadcastCancelledAreaList(v *BroadcastCancelledAreaList, s *aper.SemanticCapture) {
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
	case s00.BroadcastCancelledAreaListChoiceCellIDCancelled:
		s21.BridgeCaptureS1APCellIDCancelled(&v.CellIDCancelled, s)
	case s00.BroadcastCancelledAreaListChoiceTAICancelled:
		s32.BridgeCaptureS1APTAICancelled(&v.TAICancelled, s)
	case s00.BroadcastCancelledAreaListChoiceEmergencyAreaIDCancelled:
		s22.BridgeCaptureS1APEmergencyAreaIDCancelled(&v.EmergencyAreaIDCancelled, s)
	}
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APBroadcastCancelledAreaList(v *BroadcastCancelledAreaList, s *aper.SemanticComparison) {
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
	case s00.BroadcastCancelledAreaListChoiceCellIDCancelled:
		s22.BridgeCompareS1APCellIDCancelled(&v.CellIDCancelled, s)
	case s00.BroadcastCancelledAreaListChoiceTAICancelled:
		BridgeCompareS1APTAICancelled(&v.TAICancelled, s)
	case s00.BroadcastCancelledAreaListChoiceEmergencyAreaIDCancelled:
		s24.BridgeCompareS1APEmergencyAreaIDCancelled(&v.EmergencyAreaIDCancelled, s)
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
func BridgeCaptureS1APKillRequestIEValue(v *KillRequestIEValue, s *aper.SemanticCapture) {
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
					BridgeCaptureS1APWarningAreaList(v.rowWarningAreaList, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(191):
			{
				f := s.Begin()
				s.Bool(v.rowKillAllWarningMessages == nil)
				if v.rowKillAllWarningMessages != nil {
					s00.BridgeCaptureS1APKillAllWarningMessages(v.rowKillAllWarningMessages, s)
				}
				s.End(f, nil, false)
			}
		}
	}
	s.End(f, &v.replay, false)
	s.CheckReceived(v.replay, v.received)
}
func (v KillRequestIEValue) captureSemantics(s aper.SemanticCapture) KillRequestIEValue {
	BridgeCaptureS1APKillRequestIEValue(&v, &s)
	return v
}
func BridgeCompareS1APKillRequestIEValue(v *KillRequestIEValue, s *aper.SemanticComparison) {
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
					BridgeCompareS1APWarningAreaList(v.rowWarningAreaList, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(191):
			{
				f := s.Begin()
				s.Bool(v.rowKillAllWarningMessages == nil)
				if v.rowKillAllWarningMessages != nil {
					s02.BridgeCompareS1APKillAllWarningMessages(v.rowKillAllWarningMessages, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		}
	}
	s.End(f, v.replay, false)
	s.CheckReceived(v.replay, v.received)
}
func (v KillRequestIEValue) compareSemantics(s aper.SemanticComparison) aper.SemanticComparison {
	BridgeCompareS1APKillRequestIEValue(&v, &s)
	return s
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
func BridgeCaptureS1APKillResponseIEValue(v *KillResponseIEValue, s *aper.SemanticCapture) {
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
		case s00.ProtocolIEID(141):
			{
				f := s.Begin()
				s.Bool(v.rowBroadcastCancelledAreaList == nil)
				if v.rowBroadcastCancelledAreaList != nil {
					BridgeCaptureS1APBroadcastCancelledAreaList(v.rowBroadcastCancelledAreaList, s)
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
func (v KillResponseIEValue) captureSemantics(s aper.SemanticCapture) KillResponseIEValue {
	BridgeCaptureS1APKillResponseIEValue(&v, &s)
	return v
}
func BridgeCompareS1APKillResponseIEValue(v *KillResponseIEValue, s *aper.SemanticComparison) {
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
		case s00.ProtocolIEID(141):
			{
				f := s.Begin()
				s.Bool(v.rowBroadcastCancelledAreaList == nil)
				if v.rowBroadcastCancelledAreaList != nil {
					BridgeCompareS1APBroadcastCancelledAreaList(v.rowBroadcastCancelledAreaList, s)
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
func (v KillResponseIEValue) compareSemantics(s aper.SemanticComparison) aper.SemanticComparison {
	BridgeCompareS1APKillResponseIEValue(&v, &s)
	return s
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
func BridgeCaptureS1APTAIBasedMDT(v *TAIBasedMDT, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s32.BridgeCaptureS1APTAIListforMDT(&v.TAIListforMDT, s)
	s.Bool(v.IEExtensions == nil)
	s32.BridgeTAIBasedMDTExtIEsValueCaptureS1APProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APTAIBasedMDT(v *TAIBasedMDT, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeCompareS1APTAIListforMDT(&v.TAIListforMDT, s)
	s.Bool(v.IEExtensions == nil)
	s32.BridgeTAIBasedMDTExtIEsValueCompareS1APProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APTAIBasedQMC(v *TAIBasedQMC, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s32.BridgeCaptureS1APTAIListforQMC(&v.TAIListforQMC, s)
	s.Bool(v.IEExtensions == nil)
	s32.BridgeTAIBasedQMCExtIEsValueCaptureS1APProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APTAIBasedQMC(v *TAIBasedQMC, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeCompareS1APTAIListforQMC(&v.TAIListforQMC, s)
	s.Bool(v.IEExtensions == nil)
	s32.BridgeTAIBasedQMCExtIEsValueCompareS1APProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCompareS1APTAICancelled(v *s32.TAICancelled, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			s32.BridgeCompareS1APTAICancelledItem(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCompareS1APTAIListForRestart(v *s32.TAIListForRestart, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			s32.BridgeCompareS1APTAI(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCompareS1APTAIListforMDT(v *s32.TAIListforMDT, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			s32.BridgeCompareS1APTAI(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCompareS1APTAIListforQMC(v *s32.TAIListforQMC, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			s32.BridgeCompareS1APTAI(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCompareS1APTAIListforWarning(v *s32.TAIListforWarning, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			s32.BridgeCompareS1APTAI(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCaptureS1APWarningAreaList(v *WarningAreaList, s *aper.SemanticCapture) {
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
	case s00.WarningAreaListChoiceCellIDList:
		s21.BridgeCaptureS1APECGIList(&v.CellIDList, s)
	case s00.WarningAreaListChoiceTrackingAreaListforWarning:
		s32.BridgeCaptureS1APTAIListforWarning(&v.TrackingAreaListforWarning, s)
	case s00.WarningAreaListChoiceEmergencyAreaIDList:
		s00.BridgeCaptureS1APEmergencyAreaIDList(&v.EmergencyAreaIDList, s)
	}
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APWarningAreaList(v *WarningAreaList, s *aper.SemanticComparison) {
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
	case s00.WarningAreaListChoiceCellIDList:
		s24.BridgeCompareS1APECGIList(&v.CellIDList, s)
	case s00.WarningAreaListChoiceTrackingAreaListforWarning:
		BridgeCompareS1APTAIListforWarning(&v.TrackingAreaListforWarning, s)
	case s00.WarningAreaListChoiceEmergencyAreaIDList:
		s02.BridgeCompareS1APEmergencyAreaIDList(&v.EmergencyAreaIDList, s)
	}
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
					BridgeCaptureS1APWarningAreaList(v.rowWarningAreaList, s)
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
					BridgeCompareS1APWarningAreaList(v.rowWarningAreaList, s)
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
func BridgeCaptureS1APWriteReplaceWarningResponseIEValue(v *WriteReplaceWarningResponseIEValue, s *aper.SemanticCapture) {
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
		case s00.ProtocolIEID(120):
			{
				f := s.Begin()
				s.Bool(v.rowBroadcastCompletedAreaList == nil)
				if v.rowBroadcastCompletedAreaList != nil {
					s32.BridgeCaptureS1APBroadcastCompletedAreaList(v.rowBroadcastCompletedAreaList, s)
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
func (v WriteReplaceWarningResponseIEValue) captureSemantics(s aper.SemanticCapture) WriteReplaceWarningResponseIEValue {
	BridgeCaptureS1APWriteReplaceWarningResponseIEValue(&v, &s)
	return v
}
func BridgeCompareS1APWriteReplaceWarningResponseIEValue(v *WriteReplaceWarningResponseIEValue, s *aper.SemanticComparison) {
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
		case s00.ProtocolIEID(120):
			{
				f := s.Begin()
				s.Bool(v.rowBroadcastCompletedAreaList == nil)
				if v.rowBroadcastCompletedAreaList != nil {
					s32.BridgeCompareS1APBroadcastCompletedAreaList(v.rowBroadcastCompletedAreaList, s)
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
func (v WriteReplaceWarningResponseIEValue) compareSemantics(s aper.SemanticComparison) aper.SemanticComparison {
	BridgeCompareS1APWriteReplaceWarningResponseIEValue(&v, &s)
	return s
}

// AreaScopeOfMDT represents the ASN.1 CHOICE type AreaScopeOfMDT.
type AreaScopeOfMDT struct {
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
	CellBased          *s22.CellBasedMDT     `json:"CellBased,omitempty"`
	TABased            *s32.TABasedMDT       `json:"TABased,omitempty"`
	PLMNWide           *struct{}             `json:"PLMNWide,omitempty"`
	TAIBased           *TAIBasedMDT          `json:"TAIBased,omitempty"`
}

// NewAreaScopeOfMDTCellBased creates a AreaScopeOfMDT with the cellBased alternative.
func BridgeNewAreaScopeOfMDTCellBasedLegacy(v s22.CellBasedMDT) AreaScopeOfMDT {
	return AreaScopeOfMDT{
		Choice:    s00.AreaScopeOfMDTChoiceCellBased,
		CellBased: &v,
	}
}

// NewAreaScopeOfMDTTABased creates a AreaScopeOfMDT with the tABased alternative.
func BridgeNewAreaScopeOfMDTTABasedLegacy(v s32.TABasedMDT) AreaScopeOfMDT {
	return AreaScopeOfMDT{
		Choice:  s00.AreaScopeOfMDTChoiceTABased,
		TABased: &v,
	}
}

// NewAreaScopeOfMDTPLMNWide creates a AreaScopeOfMDT with the pLMNWide alternative.
func BridgeNewAreaScopeOfMDTPLMNWideLegacy(v struct{}) AreaScopeOfMDT {
	return AreaScopeOfMDT{
		Choice:   s00.AreaScopeOfMDTChoicePLMNWide,
		PLMNWide: &v,
	}
}

// NewAreaScopeOfMDTTAIBased creates a AreaScopeOfMDT with the tAIBased alternative.
func BridgeNewAreaScopeOfMDTTAIBasedLegacy(v TAIBasedMDT) AreaScopeOfMDT {
	return AreaScopeOfMDT{
		Choice:   s00.AreaScopeOfMDTChoiceTAIBased,
		TAIBased: &v,
	}
}

// AreaScopeOfQMC represents the ASN.1 CHOICE type AreaScopeOfQMC.
type AreaScopeOfQMC struct {
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
	CellBased          *s22.CellBasedQMC     `json:"CellBased,omitempty"`
	TABased            *s32.TABasedQMC       `json:"TABased,omitempty"`
	TAIBased           *TAIBasedQMC          `json:"TAIBased,omitempty"`
	PLMNAreaBased      *s20.PLMNAreaBasedQMC `json:"PLMNAreaBased,omitempty"`
}

// NewAreaScopeOfQMCCellBased creates a AreaScopeOfQMC with the cellBased alternative.
func BridgeNewAreaScopeOfQMCCellBasedLegacy(v s22.CellBasedQMC) AreaScopeOfQMC {
	return AreaScopeOfQMC{
		Choice:    s00.AreaScopeOfQMCChoiceCellBased,
		CellBased: &v,
	}
}

// NewAreaScopeOfQMCTABased creates a AreaScopeOfQMC with the tABased alternative.
func BridgeNewAreaScopeOfQMCTABasedLegacy(v s32.TABasedQMC) AreaScopeOfQMC {
	return AreaScopeOfQMC{
		Choice:  s00.AreaScopeOfQMCChoiceTABased,
		TABased: &v,
	}
}

// NewAreaScopeOfQMCTAIBased creates a AreaScopeOfQMC with the tAIBased alternative.
func BridgeNewAreaScopeOfQMCTAIBasedLegacy(v TAIBasedQMC) AreaScopeOfQMC {
	return AreaScopeOfQMC{
		Choice:   s00.AreaScopeOfQMCChoiceTAIBased,
		TAIBased: &v,
	}
}

// NewAreaScopeOfQMCPLMNAreaBased creates a AreaScopeOfQMC with the pLMNAreaBased alternative.
func BridgeNewAreaScopeOfQMCPLMNAreaBasedLegacy(v s20.PLMNAreaBasedQMC) AreaScopeOfQMC {
	return AreaScopeOfQMC{
		Choice:        s00.AreaScopeOfQMCChoicePLMNAreaBased,
		PLMNAreaBased: &v,
	}
}

// BroadcastCancelledAreaList represents the ASN.1 CHOICE type BroadcastCancelledAreaList.
type BroadcastCancelledAreaList struct {
	replay                   aper.Snapshot
	stream                   aper.WireSpan
	received                 bool
	withoutReplay            bool
	receivedAbsolute         bool
	receivedBytes            aper.WireSpan
	receivedLocation         aper.Location
	Choice                   int
	perPadding               aper.CompletePadding         `json:"-"`
	perOpenTypePadding       aper.CompletePadding         `json:"-"`
	UnknownExtension         *aper.ChoiceExtension        `json:"UnknownExtension,omitempty"`
	CellIDCancelled          s17.CellIDCancelled          `json:"CellIDCancelled,omitzero"`
	TAICancelled             s32.TAICancelled             `json:"TAICancelled,omitzero"`
	EmergencyAreaIDCancelled s22.EmergencyAreaIDCancelled `json:"EmergencyAreaIDCancelled,omitzero"`
}

// NewBroadcastCancelledAreaListCellIDCancelled creates a BroadcastCancelledAreaList with the cellID-Cancelled alternative.
func BridgeNewBroadcastCancelledAreaListCellIDCancelledLegacy(v s17.CellIDCancelled) BroadcastCancelledAreaList {
	return BroadcastCancelledAreaList{
		Choice:          s00.BroadcastCancelledAreaListChoiceCellIDCancelled,
		CellIDCancelled: v,
	}
}

// NewBroadcastCancelledAreaListTAICancelled creates a BroadcastCancelledAreaList with the tAI-Cancelled alternative.
func BridgeNewBroadcastCancelledAreaListTAICancelledLegacy(v s32.TAICancelled) BroadcastCancelledAreaList {
	return BroadcastCancelledAreaList{
		Choice:       s00.BroadcastCancelledAreaListChoiceTAICancelled,
		TAICancelled: v,
	}
}

// NewBroadcastCancelledAreaListEmergencyAreaIDCancelled creates a BroadcastCancelledAreaList with the emergencyAreaID-Cancelled alternative.
func BridgeNewBroadcastCancelledAreaListEmergencyAreaIDCancelledLegacy(v s22.EmergencyAreaIDCancelled) BroadcastCancelledAreaList {
	return BroadcastCancelledAreaList{
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
func BridgeNewENDCSONTransferTypeRequestLegacy(v s32.ENDCTransferTypeRequest) s32.ENDCSONTransferType {
	return s32.ENDCSONTransferType{
		Choice:  s00.ENDCSONTransferTypeChoiceRequest,
		Request: &v,
	}
}

// NewENDCSONTransferTypeReply creates a ENDCSONTransferType with the reply alternative.
func BridgeNewENDCSONTransferTypeReplyLegacy(v s32.ENDCTransferTypeReply) s32.ENDCSONTransferType {
	return s32.ENDCSONTransferType{
		Choice: s00.ENDCSONTransferTypeChoiceReply,
		Reply:  &v,
	}
}

// NewMMEPagingTargetGlobalENBID creates a MMEPagingTarget with the global-ENB-ID alternative.
func BridgeNewMMEPagingTargetGlobalENBIDLegacy(v s18.GlobalENBID) s32.MMEPagingTarget {
	return s32.MMEPagingTarget{
		Choice:      s00.MMEPagingTargetChoiceGlobalENBID,
		GlobalENBID: &v,
	}
}

// NewMMEPagingTargetTAI creates a MMEPagingTarget with the tAI alternative.
func BridgeNewMMEPagingTargetTAILegacy(v s32.TAI) s32.MMEPagingTarget {
	return s32.MMEPagingTarget{
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

// TAIBasedMDT represents the ASN.1 type TAIBasedMDT (SEQUENCE).
type TAIBasedMDT struct {
	replay             aper.Snapshot
	stream             aper.WireSpan
	received           bool
	withoutReplay      bool
	receivedAbsolute   bool
	receivedBytes      aper.WireSpan
	receivedLocation   aper.Location
	TAIListforMDT      s32.TAIListforMDT                 `asn1:"tag:0,context,implicit"`
	tAIListforMDTIndef bool                              `asn1:"-" json:"-"`
	IEExtensions       s11.TAIBasedMDTExtIEsExtContainer `asn1:"tag:1,context,implicit,optional" json:"IEExtensions,omitzero"`
	iEExtensionsIndef  bool                              `asn1:"-" json:"-"`
	extCount           int64                             `asn1:"-" json:"-"`
	extPresent         []bool                            `asn1:"-" json:"-"`
	extData            [][]byte                          `asn1:"-" json:"-"`
	perPadding         aper.FinalPadding                 `asn1:"-" json:"-"`
	perExtPadding      []aper.CompletePadding            `asn1:"-" json:"-"`
	extOrigin          []aper.OpaqueOrigin
	extWire            []aper.WireSpan
}

// TAIBasedQMC represents the ASN.1 type TAIBasedQMC (SEQUENCE).
type TAIBasedQMC struct {
	replay             aper.Snapshot
	stream             aper.WireSpan
	received           bool
	withoutReplay      bool
	receivedAbsolute   bool
	receivedBytes      aper.WireSpan
	receivedLocation   aper.Location
	TAIListforQMC      s32.TAIListforQMC                 `asn1:"tag:0,context,implicit"`
	tAIListforQMCIndef bool                              `asn1:"-" json:"-"`
	IEExtensions       s11.TAIBasedQMCExtIEsExtContainer `asn1:"tag:1,context,implicit,optional" json:"IEExtensions,omitzero"`
	iEExtensionsIndef  bool                              `asn1:"-" json:"-"`
	extCount           int64                             `asn1:"-" json:"-"`
	extPresent         []bool                            `asn1:"-" json:"-"`
	extData            [][]byte                          `asn1:"-" json:"-"`
	perPadding         aper.FinalPadding                 `asn1:"-" json:"-"`
	perExtPadding      []aper.CompletePadding            `asn1:"-" json:"-"`
	extOrigin          []aper.OpaqueOrigin
	extWire            []aper.WireSpan
}

// WarningAreaList represents the ASN.1 CHOICE type WarningAreaList.
type WarningAreaList struct {
	replay                     aper.Snapshot
	stream                     aper.WireSpan
	received                   bool
	withoutReplay              bool
	receivedAbsolute           bool
	receivedBytes              aper.WireSpan
	receivedLocation           aper.Location
	Choice                     int
	perPadding                 aper.CompletePadding    `json:"-"`
	perOpenTypePadding         aper.CompletePadding    `json:"-"`
	UnknownExtension           *aper.ChoiceExtension   `json:"UnknownExtension,omitempty"`
	CellIDList                 s17.ECGIList            `json:"CellIDList,omitzero"`
	TrackingAreaListforWarning s32.TAIListforWarning   `json:"TrackingAreaListforWarning,omitzero"`
	EmergencyAreaIDList        s00.EmergencyAreaIDList `json:"EmergencyAreaIDList,omitzero"`
}

// NewWarningAreaListCellIDList creates a WarningAreaList with the cellIDList alternative.
func BridgeNewWarningAreaListCellIDListLegacy(v s17.ECGIList) WarningAreaList {
	return WarningAreaList{
		Choice:     s00.WarningAreaListChoiceCellIDList,
		CellIDList: v,
	}
}

// NewWarningAreaListTrackingAreaListforWarning creates a WarningAreaList with the trackingAreaListforWarning alternative.
func BridgeNewWarningAreaListTrackingAreaListforWarningLegacy(v s32.TAIListforWarning) WarningAreaList {
	return WarningAreaList{
		Choice:                     s00.WarningAreaListChoiceTrackingAreaListforWarning,
		TrackingAreaListforWarning: v,
	}
}

// NewWarningAreaListEmergencyAreaIDList creates a WarningAreaList with the emergencyAreaIDList alternative.
func BridgeNewWarningAreaListEmergencyAreaIDListLegacy(v s00.EmergencyAreaIDList) WarningAreaList {
	return WarningAreaList{
		Choice:              s00.WarningAreaListChoiceEmergencyAreaIDList,
		EmergencyAreaIDList: v,
	}
}

// MarshalAPER encodes AreaScopeOfMDT to APER format.
func (v *AreaScopeOfMDT) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.perPadding)
}
func (v *AreaScopeOfMDT) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
			return fmt.Errorf("%s known choice %d and unknown extension are both selected", "AreaScopeOfMDT:", v.Choice)
		}
		if v.UnknownExtension.Index() < 0 {
			return fmt.Errorf("%s extension index %d must be non-negative", "AreaScopeOfMDT:", v.UnknownExtension.Index())
		}
		if v.UnknownExtension.Index() < 1 {
			return fmt.Errorf("%s extension index %d is known to this schema", "AreaScopeOfMDT:", v.UnknownExtension.Index())
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
		return fmt.Errorf("%s choice %d must be positive", "AreaScopeOfMDT:", v.Choice)
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
		case s00.AreaScopeOfMDTChoiceTAIBased:
			if v.TAIBased == nil {
				return fmt.Errorf("choice alternative tAIBased is nil")
			}
			if err := v.TAIBased.marshalAPERTo(inner, len(fresh) != 0 && fresh[0]); err != nil {
				return fmt.Errorf("encoding tAIBased: %w", err)
			}
		default:
			return fmt.Errorf("unknown AreaScopeOfMDT extension choice %d", v.Choice)
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
	case s00.AreaScopeOfMDTChoiceCellBased:
		if v.CellBased == nil {
			return fmt.Errorf("choice alternative cellBased is nil")
		}
		if err := s22.BridgeCellBasedMDTMethodMarshalAPERTo(v.CellBased, bb, len(fresh) != 0 && fresh[0]); err != nil {
			return fmt.Errorf("encoding cellBased: %w", err)
		}
	case s00.AreaScopeOfMDTChoiceTABased:
		if v.TABased == nil {
			return fmt.Errorf("choice alternative tABased is nil")
		}
		if err := s32.BridgeTABasedMDTMethodMarshalAPERTo(v.TABased, bb, len(fresh) != 0 && fresh[0]); err != nil {
			return fmt.Errorf("encoding tABased: %w", err)
		}
	case s00.AreaScopeOfMDTChoicePLMNWide:
	default:
		return fmt.Errorf("unknown AreaScopeOfMDT choice %d", v.Choice)
	}
	return nil
}

// UnmarshalAPER decodes AreaScopeOfMDT from APER format.
func (v *AreaScopeOfMDT) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes AreaScopeOfMDT with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *AreaScopeOfMDT) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "AreaScopeOfMDT")
	}
	bb.EnterComponent("AreaScopeOfMDT")
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "AreaScopeOfMDT")
	}
	padding, err := aper.CaptureFinalBits(bb, "AreaScopeOfMDT")
	if err != nil {
		return runtime.WrapDecodePath(err, "AreaScopeOfMDT")
	}
	v.perPadding = padding.Padding()
	return nil
}
func (v *AreaScopeOfMDT) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = AreaScopeOfMDT{}
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
		case s00.AreaScopeOfMDTChoiceTAIBased:
			extensionPath = "TAIBased"
			toleranceMark_taibased := inner.EnterComponent("TAIBased")
			var dec_taibased TAIBasedMDT
			if err := dec_taibased.unmarshalAPERFrom(inner); err != nil {
				return runtime.WrapDecodePath(err, "TAIBased")
			}
			if err := aper.ChargeValue(inner, dec_taibased); err != nil {
				return err
			}
			v.TAIBased = &dec_taibased
			inner.LeaveComponent(toleranceMark_taibased)
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
	case s00.AreaScopeOfMDTChoiceCellBased:
		toleranceMark_cellbased := bb.EnterComponent("CellBased")
		var dec_cellbased s22.CellBasedMDT
		if err := s22.BridgeCellBasedMDTMethodUnmarshalAPERFrom(&dec_cellbased, bb); err != nil {
			return runtime.WrapDecodePath(err, "CellBased")
		}
		if err := aper.ChargeValue(bb, dec_cellbased); err != nil {
			return err
		}
		v.CellBased = &dec_cellbased
		bb.LeaveComponent(toleranceMark_cellbased)
	case s00.AreaScopeOfMDTChoiceTABased:
		toleranceMark_tabased := bb.EnterComponent("TABased")
		var dec_tabased s32.TABasedMDT
		if err := s32.BridgeTABasedMDTMethodUnmarshalAPERFrom(&dec_tabased, bb); err != nil {
			return runtime.WrapDecodePath(err, "TABased")
		}
		if err := aper.ChargeValue(bb, dec_tabased); err != nil {
			return err
		}
		v.TABased = &dec_tabased
		bb.LeaveComponent(toleranceMark_tabased)
	case s00.AreaScopeOfMDTChoicePLMNWide:
		v.PLMNWide = new(struct{})
	}
	v.stream = bb.CaptureWireSpan(replayStart)

	return nil
}

// MarshalAPER encodes AreaScopeOfQMC to APER format.
func (v *AreaScopeOfQMC) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.perPadding)
}
func (v *AreaScopeOfQMC) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
			return fmt.Errorf("%s known choice %d and unknown extension are both selected", "AreaScopeOfQMC:", v.Choice)
		}
		if v.UnknownExtension.Index() < 0 {
			return fmt.Errorf("%s extension index %d must be non-negative", "AreaScopeOfQMC:", v.UnknownExtension.Index())
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
		return fmt.Errorf("%s choice %d must be positive", "AreaScopeOfQMC:", v.Choice)
	}
	isExtension := v.Choice > 4
	if err := aper.EncodeBoolean(bb, isExtension); err != nil {
		return err
	}
	if isExtension {
		return fmt.Errorf("%s extension choice %d not supported", "AreaScopeOfQMC:", v.Choice)
	}
	// arithmetic pattern APER_CHOICE_ROOT_ENCODE: choice index fits the emitted representation; gen/codegen_aper.go:149
	if v.Choice < 1 {
		return fmt.Errorf("choice index outside root")
	}
	if err := aper.EncodeConstrainedWholeNumberAligned(bb, int64(v.Choice-1), 0, 3); err != nil {
		return err
	}
	switch v.Choice {
	case s00.AreaScopeOfQMCChoiceCellBased:
		if v.CellBased == nil {
			return fmt.Errorf("choice alternative cellBased is nil")
		}
		if err := s22.BridgeCellBasedQMCMethodMarshalAPERTo(v.CellBased, bb, len(fresh) != 0 && fresh[0]); err != nil {
			return fmt.Errorf("encoding cellBased: %w", err)
		}
	case s00.AreaScopeOfQMCChoiceTABased:
		if v.TABased == nil {
			return fmt.Errorf("choice alternative tABased is nil")
		}
		if err := s32.BridgeTABasedQMCMethodMarshalAPERTo(v.TABased, bb, len(fresh) != 0 && fresh[0]); err != nil {
			return fmt.Errorf("encoding tABased: %w", err)
		}
	case s00.AreaScopeOfQMCChoiceTAIBased:
		if v.TAIBased == nil {
			return fmt.Errorf("choice alternative tAIBased is nil")
		}
		if err := v.TAIBased.marshalAPERTo(bb, len(fresh) != 0 && fresh[0]); err != nil {
			return fmt.Errorf("encoding tAIBased: %w", err)
		}
	case s00.AreaScopeOfQMCChoicePLMNAreaBased:
		if v.PLMNAreaBased == nil {
			return fmt.Errorf("choice alternative pLMNAreaBased is nil")
		}
		if err := s20.BridgePLMNAreaBasedQMCMethodMarshalAPERTo(v.PLMNAreaBased, bb, len(fresh) != 0 && fresh[0]); err != nil {
			return fmt.Errorf("encoding pLMNAreaBased: %w", err)
		}
	default:
		return fmt.Errorf("unknown AreaScopeOfQMC choice %d", v.Choice)
	}
	return nil
}

// UnmarshalAPER decodes AreaScopeOfQMC from APER format.
func (v *AreaScopeOfQMC) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes AreaScopeOfQMC with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *AreaScopeOfQMC) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "AreaScopeOfQMC")
	}
	bb.EnterComponent("AreaScopeOfQMC")
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "AreaScopeOfQMC")
	}
	padding, err := aper.CaptureFinalBits(bb, "AreaScopeOfQMC")
	if err != nil {
		return runtime.WrapDecodePath(err, "AreaScopeOfQMC")
	}
	v.perPadding = padding.Padding()
	return nil
}
func (v *AreaScopeOfQMC) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = AreaScopeOfQMC{}
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
	idx, err := aper.DecodeConstrainedWholeNumberAligned(bb, 0, 3)
	if err != nil {
		return err
	}
	// arithmetic pattern APER_CHOICE_ROOT_DECODE: choice index fits the emitted representation; gen/codegen_aper.go:236
	if idx < 0 || idx >= int64(^uint(0)>>1) {
		return fmt.Errorf("choice index exceeds host int")
	}
	v.Choice = int(idx) + 1
	switch v.Choice {
	case s00.AreaScopeOfQMCChoiceCellBased:
		toleranceMark_cellbased := bb.EnterComponent("CellBased")
		var dec_cellbased s22.CellBasedQMC
		if err := s22.BridgeCellBasedQMCMethodUnmarshalAPERFrom(&dec_cellbased, bb); err != nil {
			return runtime.WrapDecodePath(err, "CellBased")
		}
		if err := aper.ChargeValue(bb, dec_cellbased); err != nil {
			return err
		}
		v.CellBased = &dec_cellbased
		bb.LeaveComponent(toleranceMark_cellbased)
	case s00.AreaScopeOfQMCChoiceTABased:
		toleranceMark_tabased := bb.EnterComponent("TABased")
		var dec_tabased s32.TABasedQMC
		if err := s32.BridgeTABasedQMCMethodUnmarshalAPERFrom(&dec_tabased, bb); err != nil {
			return runtime.WrapDecodePath(err, "TABased")
		}
		if err := aper.ChargeValue(bb, dec_tabased); err != nil {
			return err
		}
		v.TABased = &dec_tabased
		bb.LeaveComponent(toleranceMark_tabased)
	case s00.AreaScopeOfQMCChoiceTAIBased:
		toleranceMark_taibased := bb.EnterComponent("TAIBased")
		var dec_taibased TAIBasedQMC
		if err := dec_taibased.unmarshalAPERFrom(bb); err != nil {
			return runtime.WrapDecodePath(err, "TAIBased")
		}
		if err := aper.ChargeValue(bb, dec_taibased); err != nil {
			return err
		}
		v.TAIBased = &dec_taibased
		bb.LeaveComponent(toleranceMark_taibased)
	case s00.AreaScopeOfQMCChoicePLMNAreaBased:
		toleranceMark_plmnareabased := bb.EnterComponent("PLMNAreaBased")
		var dec_plmnareabased s20.PLMNAreaBasedQMC
		if err := s20.BridgePLMNAreaBasedQMCMethodUnmarshalAPERFrom(&dec_plmnareabased, bb); err != nil {
			return runtime.WrapDecodePath(err, "PLMNAreaBased")
		}
		if err := aper.ChargeValue(bb, dec_plmnareabased); err != nil {
			return err
		}
		v.PLMNAreaBased = &dec_plmnareabased
		bb.LeaveComponent(toleranceMark_plmnareabased)
	}
	v.stream = bb.CaptureWireSpan(replayStart)

	return nil
}

// MarshalAPER encodes BroadcastCancelledAreaList to APER format.
func (v *BroadcastCancelledAreaList) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.perPadding)
}
func (v *BroadcastCancelledAreaList) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
			return fmt.Errorf("%s known choice %d and unknown extension are both selected", "BroadcastCancelledAreaList:", v.Choice)
		}
		if v.UnknownExtension.Index() < 0 {
			return fmt.Errorf("%s extension index %d must be non-negative", "BroadcastCancelledAreaList:", v.UnknownExtension.Index())
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
		return fmt.Errorf("%s choice %d must be positive", "BroadcastCancelledAreaList:", v.Choice)
	}
	isExtension := v.Choice > 3
	if err := aper.EncodeBoolean(bb, isExtension); err != nil {
		return err
	}
	if isExtension {
		return fmt.Errorf("%s extension choice %d not supported", "BroadcastCancelledAreaList:", v.Choice)
	}
	// arithmetic pattern APER_CHOICE_ROOT_ENCODE: choice index fits the emitted representation; gen/codegen_aper.go:149
	if v.Choice < 1 {
		return fmt.Errorf("choice index outside root")
	}
	if err := aper.EncodeConstrainedWholeNumberAligned(bb, int64(v.Choice-1), 0, 2); err != nil {
		return err
	}
	switch v.Choice {
	case s00.BroadcastCancelledAreaListChoiceCellIDCancelled:
		if err := aper.EncodeCollection(bb, int64(len(v.CellIDCancelled)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_cellidcancelled, fragmentLength_cellidcancelled int64) error {
			// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
			if fragmentOffset_cellidcancelled < 0 || fragmentOffset_cellidcancelled > int64(len(v.CellIDCancelled)) || fragmentLength_cellidcancelled < 0 || fragmentLength_cellidcancelled > int64(len(v.CellIDCancelled[fragmentOffset_cellidcancelled:])) {
				return fmt.Errorf("collection fragment outside value")
			}
			for _, elem := range v.CellIDCancelled[fragmentOffset_cellidcancelled : fragmentOffset_cellidcancelled+fragmentLength_cellidcancelled] {
				if err := s17.BridgeCellIDCancelledItemMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
					return fmt.Errorf("encoding cellID-Cancelled element: %w", err)
				}
			}
			return nil
		}); err != nil {
			return fmt.Errorf("encoding cellID-Cancelled: %w", err)
		}
	case s00.BroadcastCancelledAreaListChoiceTAICancelled:
		if err := aper.EncodeCollection(bb, int64(len(v.TAICancelled)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_taicancelled, fragmentLength_taicancelled int64) error {
			// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
			if fragmentOffset_taicancelled < 0 || fragmentOffset_taicancelled > int64(len(v.TAICancelled)) || fragmentLength_taicancelled < 0 || fragmentLength_taicancelled > int64(len(v.TAICancelled[fragmentOffset_taicancelled:])) {
				return fmt.Errorf("collection fragment outside value")
			}
			for _, elem := range v.TAICancelled[fragmentOffset_taicancelled : fragmentOffset_taicancelled+fragmentLength_taicancelled] {
				if err := s32.BridgeTAICancelledItemMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
					return fmt.Errorf("encoding tAI-Cancelled element: %w", err)
				}
			}
			return nil
		}); err != nil {
			return fmt.Errorf("encoding tAI-Cancelled: %w", err)
		}
	case s00.BroadcastCancelledAreaListChoiceEmergencyAreaIDCancelled:
		if err := aper.EncodeCollection(bb, int64(len(v.EmergencyAreaIDCancelled)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_emergencyareaidcancelled, fragmentLength_emergencyareaidcancelled int64) error {
			// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
			if fragmentOffset_emergencyareaidcancelled < 0 || fragmentOffset_emergencyareaidcancelled > int64(len(v.EmergencyAreaIDCancelled)) || fragmentLength_emergencyareaidcancelled < 0 || fragmentLength_emergencyareaidcancelled > int64(len(v.EmergencyAreaIDCancelled[fragmentOffset_emergencyareaidcancelled:])) {
				return fmt.Errorf("collection fragment outside value")
			}
			for _, elem := range v.EmergencyAreaIDCancelled[fragmentOffset_emergencyareaidcancelled : fragmentOffset_emergencyareaidcancelled+fragmentLength_emergencyareaidcancelled] {
				if err := s22.BridgeEmergencyAreaIDCancelledItemMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
					return fmt.Errorf("encoding emergencyAreaID-Cancelled element: %w", err)
				}
			}
			return nil
		}); err != nil {
			return fmt.Errorf("encoding emergencyAreaID-Cancelled: %w", err)
		}
	default:
		return fmt.Errorf("unknown BroadcastCancelledAreaList choice %d", v.Choice)
	}
	return nil
}

// UnmarshalAPER decodes BroadcastCancelledAreaList from APER format.
func (v *BroadcastCancelledAreaList) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes BroadcastCancelledAreaList with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *BroadcastCancelledAreaList) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "BroadcastCancelledAreaList")
	}
	bb.EnterComponent("BroadcastCancelledAreaList")
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "BroadcastCancelledAreaList")
	}
	padding, err := aper.CaptureFinalBits(bb, "BroadcastCancelledAreaList")
	if err != nil {
		return runtime.WrapDecodePath(err, "BroadcastCancelledAreaList")
	}
	v.perPadding = padding.Padding()
	return nil
}
func (v *BroadcastCancelledAreaList) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = BroadcastCancelledAreaList{}
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
	case s00.BroadcastCancelledAreaListChoiceCellIDCancelled:
		toleranceMark_cellidcancelled := bb.EnterComponent("CellIDCancelled")
		tmp_cellidcancelled := make(s17.CellIDCancelled, 0)
		_, errCollection_cellidcancelled := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_cellidcancelled, fragmentLength_cellidcancelled int64) error {
			// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1128
			if fragmentOffset_cellidcancelled < 0 || fragmentLength_cellidcancelled < 0 || fragmentLength_cellidcancelled > int64(^uint(0)>>1) || fragmentOffset_cellidcancelled > int64(^uint(0)>>1)-fragmentLength_cellidcancelled {
				return fmt.Errorf("collection fragment count out of range")
			}
			for i := int64(0); i < fragmentLength_cellidcancelled; i++ {
				var elem s17.CellIDCancelledItem
				elementMark := bb.EnterIndex(fragmentOffset_cellidcancelled + i)
				if err := s17.BridgeCellIDCancelledItemMethodUnmarshalAPERFrom(&elem, bb); err != nil {
					return runtime.WrapDecodePath(err, fmt.Sprintf("CellIDCancelled[%d]", fragmentOffset_cellidcancelled+i))
				}
				bb.LeaveComponent(elementMark)
				if next, err := aper.AppendValues(bb, tmp_cellidcancelled, elem); err != nil {
					return err
				} else {
					tmp_cellidcancelled = next
				}
			}
			return nil
		})
		if errCollection_cellidcancelled != nil {
			return runtime.WrapDecodePath(errCollection_cellidcancelled, "CellIDCancelled")
		}
		v.CellIDCancelled = tmp_cellidcancelled
		bb.LeaveComponent(toleranceMark_cellidcancelled)
	case s00.BroadcastCancelledAreaListChoiceTAICancelled:
		toleranceMark_taicancelled := bb.EnterComponent("TAICancelled")
		tmp_taicancelled := make(s32.TAICancelled, 0)
		_, errCollection_taicancelled := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_taicancelled, fragmentLength_taicancelled int64) error {
			// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1128
			if fragmentOffset_taicancelled < 0 || fragmentLength_taicancelled < 0 || fragmentLength_taicancelled > int64(^uint(0)>>1) || fragmentOffset_taicancelled > int64(^uint(0)>>1)-fragmentLength_taicancelled {
				return fmt.Errorf("collection fragment count out of range")
			}
			for i := int64(0); i < fragmentLength_taicancelled; i++ {
				var elem s32.TAICancelledItem
				elementMark := bb.EnterIndex(fragmentOffset_taicancelled + i)
				if err := s32.BridgeTAICancelledItemMethodUnmarshalAPERFrom(&elem, bb); err != nil {
					return runtime.WrapDecodePath(err, fmt.Sprintf("TAICancelled[%d]", fragmentOffset_taicancelled+i))
				}
				bb.LeaveComponent(elementMark)
				if next, err := aper.AppendValues(bb, tmp_taicancelled, elem); err != nil {
					return err
				} else {
					tmp_taicancelled = next
				}
			}
			return nil
		})
		if errCollection_taicancelled != nil {
			return runtime.WrapDecodePath(errCollection_taicancelled, "TAICancelled")
		}
		v.TAICancelled = tmp_taicancelled
		bb.LeaveComponent(toleranceMark_taicancelled)
	case s00.BroadcastCancelledAreaListChoiceEmergencyAreaIDCancelled:
		toleranceMark_emergencyareaidcancelled := bb.EnterComponent("EmergencyAreaIDCancelled")
		tmp_emergencyareaidcancelled := make(s22.EmergencyAreaIDCancelled, 0)
		_, errCollection_emergencyareaidcancelled := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_emergencyareaidcancelled, fragmentLength_emergencyareaidcancelled int64) error {
			// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1128
			if fragmentOffset_emergencyareaidcancelled < 0 || fragmentLength_emergencyareaidcancelled < 0 || fragmentLength_emergencyareaidcancelled > int64(^uint(0)>>1) || fragmentOffset_emergencyareaidcancelled > int64(^uint(0)>>1)-fragmentLength_emergencyareaidcancelled {
				return fmt.Errorf("collection fragment count out of range")
			}
			for i := int64(0); i < fragmentLength_emergencyareaidcancelled; i++ {
				var elem s22.EmergencyAreaIDCancelledItem
				elementMark := bb.EnterIndex(fragmentOffset_emergencyareaidcancelled + i)
				if err := s22.BridgeEmergencyAreaIDCancelledItemMethodUnmarshalAPERFrom(&elem, bb); err != nil {
					return runtime.WrapDecodePath(err, fmt.Sprintf("EmergencyAreaIDCancelled[%d]", fragmentOffset_emergencyareaidcancelled+i))
				}
				bb.LeaveComponent(elementMark)
				if next, err := aper.AppendValues(bb, tmp_emergencyareaidcancelled, elem); err != nil {
					return err
				} else {
					tmp_emergencyareaidcancelled = next
				}
			}
			return nil
		})
		if errCollection_emergencyareaidcancelled != nil {
			return runtime.WrapDecodePath(errCollection_emergencyareaidcancelled, "EmergencyAreaIDCancelled")
		}
		v.EmergencyAreaIDCancelled = tmp_emergencyareaidcancelled
		bb.LeaveComponent(toleranceMark_emergencyareaidcancelled)
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
	bb.EnterComponent("RecommendedENBsForPaging")
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
	toleranceMark_recommendedenblist := bb.EnterComponent("RecommendedENBList")
	v.RecommendedENBList = make(s32.RecommendedENBList, 0)
	_, errCollection_recommendedenblist := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 16, HasUpper: true}, true, func(fragmentOffset_recommendedenblist, fragmentLength_recommendedenblist int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1128
		if fragmentOffset_recommendedenblist < 0 || fragmentLength_recommendedenblist < 0 || fragmentLength_recommendedenblist > int64(^uint(0)>>1) || fragmentOffset_recommendedenblist > int64(^uint(0)>>1)-fragmentLength_recommendedenblist {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_recommendedenblist; i++ {
			var elem s32.RecommendedENBItemIEValueProtocolIESingleContainer
			elementMark := bb.EnterIndex(fragmentOffset_recommendedenblist + i)
			if err := s32.BridgeRecommendedENBItemIEFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
				return runtime.WrapDecodePath(err, fmt.Sprintf("RecommendedENBList[%d]", fragmentOffset_recommendedenblist+i))
			}
			bb.LeaveComponent(elementMark)
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
	bb.LeaveComponent(toleranceMark_recommendedenblist)
	if opt_ieextensions {
		toleranceMark_ieextensions := bb.EnterComponent("IEExtensions")
		tmp_ieextensions := make(s11.RecommendedENBsForPagingExtIEsExtContainer, 0)
		_, errCollection_ieextensions := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1128
			if fragmentOffset_ieextensions < 0 || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(^uint(0)>>1) || fragmentOffset_ieextensions > int64(^uint(0)>>1)-fragmentLength_ieextensions {
				return fmt.Errorf("collection fragment count out of range")
			}
			for i := int64(0); i < fragmentLength_ieextensions; i++ {
				var elem s11.RecommendedENBsForPagingExtIEsExtField
				elementMark := bb.EnterIndex(fragmentOffset_ieextensions + i)
				if err := s11.BridgeRecommendedENBsForPagingExtIEsExtFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
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

// MarshalAPER encodes TAIBasedMDT to APER format.
func (v *TAIBasedMDT) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *TAIBasedMDT) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
	if err := aper.EncodeCollection(bb, int64(len(v.TAIListforMDT)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 8, HasUpper: true}, true, func(fragmentOffset_tailistformdt, fragmentLength_tailistformdt int64) error {
		// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
		if fragmentOffset_tailistformdt < 0 || fragmentOffset_tailistformdt > int64(len(v.TAIListforMDT)) || fragmentLength_tailistformdt < 0 || fragmentLength_tailistformdt > int64(len(v.TAIListforMDT[fragmentOffset_tailistformdt:])) {
			return fmt.Errorf("collection fragment outside value")
		}
		for _, elem := range v.TAIListforMDT[fragmentOffset_tailistformdt : fragmentOffset_tailistformdt+fragmentLength_tailistformdt] {
			if err := s32.BridgeTAIMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
				return fmt.Errorf("encoding tAIListforMDT element: %w", err)
			}
		}
		return nil
	}); err != nil {
		return fmt.Errorf("encoding tAIListforMDT: %w", err)
	}
	if v.IEExtensions != nil {
		if err := aper.EncodeCollection(bb, int64(len(v.IEExtensions)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
			if fragmentOffset_ieextensions < 0 || fragmentOffset_ieextensions > int64(len(v.IEExtensions)) || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(len(v.IEExtensions[fragmentOffset_ieextensions:])) {
				return fmt.Errorf("collection fragment outside value")
			}
			for _, elem := range v.IEExtensions[fragmentOffset_ieextensions : fragmentOffset_ieextensions+fragmentLength_ieextensions] {
				if err := s11.BridgeTAIBasedMDTExtIEsExtFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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

// UnmarshalAPER decodes TAIBasedMDT from APER format.
func (v *TAIBasedMDT) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes TAIBasedMDT with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *TAIBasedMDT) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "TAIBasedMDT")
	}
	bb.EnterComponent("TAIBasedMDT")
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "TAIBasedMDT")
	}
	padding, err := aper.CaptureFinalBits(bb, "TAIBasedMDT")
	if err != nil {
		return runtime.WrapDecodePath(err, "TAIBasedMDT")
	}
	v.perPadding = padding.WithRecords(v.perPadding)
	return nil
}
func (v *TAIBasedMDT) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = TAIBasedMDT{}
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
	toleranceMark_tailistformdt := bb.EnterComponent("TAIListforMDT")
	v.TAIListforMDT = make(s32.TAIListforMDT, 0)
	_, errCollection_tailistformdt := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 8, HasUpper: true}, true, func(fragmentOffset_tailistformdt, fragmentLength_tailistformdt int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1128
		if fragmentOffset_tailistformdt < 0 || fragmentLength_tailistformdt < 0 || fragmentLength_tailistformdt > int64(^uint(0)>>1) || fragmentOffset_tailistformdt > int64(^uint(0)>>1)-fragmentLength_tailistformdt {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_tailistformdt; i++ {
			var elem s32.TAI
			elementMark := bb.EnterIndex(fragmentOffset_tailistformdt + i)
			if err := s32.BridgeTAIMethodUnmarshalAPERFrom(&elem, bb); err != nil {
				return runtime.WrapDecodePath(err, fmt.Sprintf("TAIListforMDT[%d]", fragmentOffset_tailistformdt+i))
			}
			bb.LeaveComponent(elementMark)
			if next, err := aper.AppendValues(bb, v.TAIListforMDT, elem); err != nil {
				return err
			} else {
				v.TAIListforMDT = next
			}
		}
		return nil
	})
	if errCollection_tailistformdt != nil {
		return runtime.WrapDecodePath(errCollection_tailistformdt, "TAIListforMDT")
	}
	bb.LeaveComponent(toleranceMark_tailistformdt)
	if opt_ieextensions {
		toleranceMark_ieextensions := bb.EnterComponent("IEExtensions")
		tmp_ieextensions := make(s11.TAIBasedMDTExtIEsExtContainer, 0)
		_, errCollection_ieextensions := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1128
			if fragmentOffset_ieextensions < 0 || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(^uint(0)>>1) || fragmentOffset_ieextensions > int64(^uint(0)>>1)-fragmentLength_ieextensions {
				return fmt.Errorf("collection fragment count out of range")
			}
			for i := int64(0); i < fragmentLength_ieextensions; i++ {
				var elem s11.TAIBasedMDTExtIEsExtField
				elementMark := bb.EnterIndex(fragmentOffset_ieextensions + i)
				if err := s11.BridgeTAIBasedMDTExtIEsExtFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
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
			if err := s32.BridgeTAIMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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
			if err := s32.BridgeTAIMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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

// MarshalAPER encodes TAIBasedQMC to APER format.
func (v *TAIBasedQMC) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *TAIBasedQMC) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
	if err := aper.EncodeCollection(bb, int64(len(v.TAIListforQMC)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 8, HasUpper: true}, true, func(fragmentOffset_tailistforqmc, fragmentLength_tailistforqmc int64) error {
		// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
		if fragmentOffset_tailistforqmc < 0 || fragmentOffset_tailistforqmc > int64(len(v.TAIListforQMC)) || fragmentLength_tailistforqmc < 0 || fragmentLength_tailistforqmc > int64(len(v.TAIListforQMC[fragmentOffset_tailistforqmc:])) {
			return fmt.Errorf("collection fragment outside value")
		}
		for _, elem := range v.TAIListforQMC[fragmentOffset_tailistforqmc : fragmentOffset_tailistforqmc+fragmentLength_tailistforqmc] {
			if err := s32.BridgeTAIMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
				return fmt.Errorf("encoding tAIListforQMC element: %w", err)
			}
		}
		return nil
	}); err != nil {
		return fmt.Errorf("encoding tAIListforQMC: %w", err)
	}
	if v.IEExtensions != nil {
		if err := aper.EncodeCollection(bb, int64(len(v.IEExtensions)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
			if fragmentOffset_ieextensions < 0 || fragmentOffset_ieextensions > int64(len(v.IEExtensions)) || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(len(v.IEExtensions[fragmentOffset_ieextensions:])) {
				return fmt.Errorf("collection fragment outside value")
			}
			for _, elem := range v.IEExtensions[fragmentOffset_ieextensions : fragmentOffset_ieextensions+fragmentLength_ieextensions] {
				if err := s11.BridgeTAIBasedQMCExtIEsExtFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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

// UnmarshalAPER decodes TAIBasedQMC from APER format.
func (v *TAIBasedQMC) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes TAIBasedQMC with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *TAIBasedQMC) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "TAIBasedQMC")
	}
	bb.EnterComponent("TAIBasedQMC")
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "TAIBasedQMC")
	}
	padding, err := aper.CaptureFinalBits(bb, "TAIBasedQMC")
	if err != nil {
		return runtime.WrapDecodePath(err, "TAIBasedQMC")
	}
	v.perPadding = padding.WithRecords(v.perPadding)
	return nil
}
func (v *TAIBasedQMC) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = TAIBasedQMC{}
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
	toleranceMark_tailistforqmc := bb.EnterComponent("TAIListforQMC")
	v.TAIListforQMC = make(s32.TAIListforQMC, 0)
	_, errCollection_tailistforqmc := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 8, HasUpper: true}, true, func(fragmentOffset_tailistforqmc, fragmentLength_tailistforqmc int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1128
		if fragmentOffset_tailistforqmc < 0 || fragmentLength_tailistforqmc < 0 || fragmentLength_tailistforqmc > int64(^uint(0)>>1) || fragmentOffset_tailistforqmc > int64(^uint(0)>>1)-fragmentLength_tailistforqmc {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_tailistforqmc; i++ {
			var elem s32.TAI
			elementMark := bb.EnterIndex(fragmentOffset_tailistforqmc + i)
			if err := s32.BridgeTAIMethodUnmarshalAPERFrom(&elem, bb); err != nil {
				return runtime.WrapDecodePath(err, fmt.Sprintf("TAIListforQMC[%d]", fragmentOffset_tailistforqmc+i))
			}
			bb.LeaveComponent(elementMark)
			if next, err := aper.AppendValues(bb, v.TAIListforQMC, elem); err != nil {
				return err
			} else {
				v.TAIListforQMC = next
			}
		}
		return nil
	})
	if errCollection_tailistforqmc != nil {
		return runtime.WrapDecodePath(errCollection_tailistforqmc, "TAIListforQMC")
	}
	bb.LeaveComponent(toleranceMark_tailistforqmc)
	if opt_ieextensions {
		toleranceMark_ieextensions := bb.EnterComponent("IEExtensions")
		tmp_ieextensions := make(s11.TAIBasedQMCExtIEsExtContainer, 0)
		_, errCollection_ieextensions := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1128
			if fragmentOffset_ieextensions < 0 || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(^uint(0)>>1) || fragmentOffset_ieextensions > int64(^uint(0)>>1)-fragmentLength_ieextensions {
				return fmt.Errorf("collection fragment count out of range")
			}
			for i := int64(0); i < fragmentLength_ieextensions; i++ {
				var elem s11.TAIBasedQMCExtIEsExtField
				elementMark := bb.EnterIndex(fragmentOffset_ieextensions + i)
				if err := s11.BridgeTAIBasedQMCExtIEsExtFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
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
			if err := s32.BridgeTAIMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
				return fmt.Errorf("encoding value element: %w", err)
			}
		}
		return nil
	}); err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
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
			if err := s32.BridgeTAIMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
				return fmt.Errorf("encoding value element: %w", err)
			}
		}
		return nil
	}); err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	return nil
}

// MarshalAPER encodes WarningAreaList to APER format.
func (v *WarningAreaList) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.perPadding)
}
func (v *WarningAreaList) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
			return fmt.Errorf("%s known choice %d and unknown extension are both selected", "WarningAreaList:", v.Choice)
		}
		if v.UnknownExtension.Index() < 0 {
			return fmt.Errorf("%s extension index %d must be non-negative", "WarningAreaList:", v.UnknownExtension.Index())
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
		return fmt.Errorf("%s choice %d must be positive", "WarningAreaList:", v.Choice)
	}
	isExtension := v.Choice > 3
	if err := aper.EncodeBoolean(bb, isExtension); err != nil {
		return err
	}
	if isExtension {
		return fmt.Errorf("%s extension choice %d not supported", "WarningAreaList:", v.Choice)
	}
	// arithmetic pattern APER_CHOICE_ROOT_ENCODE: choice index fits the emitted representation; gen/codegen_aper.go:149
	if v.Choice < 1 {
		return fmt.Errorf("choice index outside root")
	}
	if err := aper.EncodeConstrainedWholeNumberAligned(bb, int64(v.Choice-1), 0, 2); err != nil {
		return err
	}
	switch v.Choice {
	case s00.WarningAreaListChoiceCellIDList:
		if err := aper.EncodeCollection(bb, int64(len(v.CellIDList)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_cellidlist, fragmentLength_cellidlist int64) error {
			// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
			if fragmentOffset_cellidlist < 0 || fragmentOffset_cellidlist > int64(len(v.CellIDList)) || fragmentLength_cellidlist < 0 || fragmentLength_cellidlist > int64(len(v.CellIDList[fragmentOffset_cellidlist:])) {
				return fmt.Errorf("collection fragment outside value")
			}
			for _, elem := range v.CellIDList[fragmentOffset_cellidlist : fragmentOffset_cellidlist+fragmentLength_cellidlist] {
				if err := s17.BridgeEUTRANCGIMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
					return fmt.Errorf("encoding cellIDList element: %w", err)
				}
			}
			return nil
		}); err != nil {
			return fmt.Errorf("encoding cellIDList: %w", err)
		}
	case s00.WarningAreaListChoiceTrackingAreaListforWarning:
		if err := aper.EncodeCollection(bb, int64(len(v.TrackingAreaListforWarning)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_trackingarealistforwarning, fragmentLength_trackingarealistforwarning int64) error {
			// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
			if fragmentOffset_trackingarealistforwarning < 0 || fragmentOffset_trackingarealistforwarning > int64(len(v.TrackingAreaListforWarning)) || fragmentLength_trackingarealistforwarning < 0 || fragmentLength_trackingarealistforwarning > int64(len(v.TrackingAreaListforWarning[fragmentOffset_trackingarealistforwarning:])) {
				return fmt.Errorf("collection fragment outside value")
			}
			for _, elem := range v.TrackingAreaListforWarning[fragmentOffset_trackingarealistforwarning : fragmentOffset_trackingarealistforwarning+fragmentLength_trackingarealistforwarning] {
				if err := s32.BridgeTAIMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
					return fmt.Errorf("encoding trackingAreaListforWarning element: %w", err)
				}
			}
			return nil
		}); err != nil {
			return fmt.Errorf("encoding trackingAreaListforWarning: %w", err)
		}
	case s00.WarningAreaListChoiceEmergencyAreaIDList:
		if err := aper.EncodeCollection(bb, int64(len(v.EmergencyAreaIDList)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_emergencyareaidlist, fragmentLength_emergencyareaidlist int64) error {
			// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
			if fragmentOffset_emergencyareaidlist < 0 || fragmentOffset_emergencyareaidlist > int64(len(v.EmergencyAreaIDList)) || fragmentLength_emergencyareaidlist < 0 || fragmentLength_emergencyareaidlist > int64(len(v.EmergencyAreaIDList[fragmentOffset_emergencyareaidlist:])) {
				return fmt.Errorf("collection fragment outside value")
			}
			for _, elem := range v.EmergencyAreaIDList[fragmentOffset_emergencyareaidlist : fragmentOffset_emergencyareaidlist+fragmentLength_emergencyareaidlist] {
				if err := aper.EncodeOctetStringAligned(bb, []byte(elem), 3, 3, true); err != nil {
					return fmt.Errorf("encoding emergencyAreaIDList element: %w", err)
				}
			}
			return nil
		}); err != nil {
			return fmt.Errorf("encoding emergencyAreaIDList: %w", err)
		}
	default:
		return fmt.Errorf("unknown WarningAreaList choice %d", v.Choice)
	}
	return nil
}

// UnmarshalAPER decodes WarningAreaList from APER format.
func (v *WarningAreaList) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes WarningAreaList with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *WarningAreaList) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "WarningAreaList")
	}
	bb.EnterComponent("WarningAreaList")
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "WarningAreaList")
	}
	padding, err := aper.CaptureFinalBits(bb, "WarningAreaList")
	if err != nil {
		return runtime.WrapDecodePath(err, "WarningAreaList")
	}
	v.perPadding = padding.Padding()
	return nil
}
func (v *WarningAreaList) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = WarningAreaList{}
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
	case s00.WarningAreaListChoiceCellIDList:
		toleranceMark_cellidlist := bb.EnterComponent("CellIDList")
		tmp_cellidlist := make(s17.ECGIList, 0)
		_, errCollection_cellidlist := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_cellidlist, fragmentLength_cellidlist int64) error {
			// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1128
			if fragmentOffset_cellidlist < 0 || fragmentLength_cellidlist < 0 || fragmentLength_cellidlist > int64(^uint(0)>>1) || fragmentOffset_cellidlist > int64(^uint(0)>>1)-fragmentLength_cellidlist {
				return fmt.Errorf("collection fragment count out of range")
			}
			for i := int64(0); i < fragmentLength_cellidlist; i++ {
				var elem s17.EUTRANCGI
				elementMark := bb.EnterIndex(fragmentOffset_cellidlist + i)
				if err := s17.BridgeEUTRANCGIMethodUnmarshalAPERFrom(&elem, bb); err != nil {
					return runtime.WrapDecodePath(err, fmt.Sprintf("CellIDList[%d]", fragmentOffset_cellidlist+i))
				}
				bb.LeaveComponent(elementMark)
				if next, err := aper.AppendValues(bb, tmp_cellidlist, elem); err != nil {
					return err
				} else {
					tmp_cellidlist = next
				}
			}
			return nil
		})
		if errCollection_cellidlist != nil {
			return runtime.WrapDecodePath(errCollection_cellidlist, "CellIDList")
		}
		v.CellIDList = tmp_cellidlist
		bb.LeaveComponent(toleranceMark_cellidlist)
	case s00.WarningAreaListChoiceTrackingAreaListforWarning:
		toleranceMark_trackingarealistforwarning := bb.EnterComponent("TrackingAreaListforWarning")
		tmp_trackingarealistforwarning := make(s32.TAIListforWarning, 0)
		_, errCollection_trackingarealistforwarning := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_trackingarealistforwarning, fragmentLength_trackingarealistforwarning int64) error {
			// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1128
			if fragmentOffset_trackingarealistforwarning < 0 || fragmentLength_trackingarealistforwarning < 0 || fragmentLength_trackingarealistforwarning > int64(^uint(0)>>1) || fragmentOffset_trackingarealistforwarning > int64(^uint(0)>>1)-fragmentLength_trackingarealistforwarning {
				return fmt.Errorf("collection fragment count out of range")
			}
			for i := int64(0); i < fragmentLength_trackingarealistforwarning; i++ {
				var elem s32.TAI
				elementMark := bb.EnterIndex(fragmentOffset_trackingarealistforwarning + i)
				if err := s32.BridgeTAIMethodUnmarshalAPERFrom(&elem, bb); err != nil {
					return runtime.WrapDecodePath(err, fmt.Sprintf("TrackingAreaListforWarning[%d]", fragmentOffset_trackingarealistforwarning+i))
				}
				bb.LeaveComponent(elementMark)
				if next, err := aper.AppendValues(bb, tmp_trackingarealistforwarning, elem); err != nil {
					return err
				} else {
					tmp_trackingarealistforwarning = next
				}
			}
			return nil
		})
		if errCollection_trackingarealistforwarning != nil {
			return runtime.WrapDecodePath(errCollection_trackingarealistforwarning, "TrackingAreaListforWarning")
		}
		v.TrackingAreaListforWarning = tmp_trackingarealistforwarning
		bb.LeaveComponent(toleranceMark_trackingarealistforwarning)
	case s00.WarningAreaListChoiceEmergencyAreaIDList:
		toleranceMark_emergencyareaidlist := bb.EnterComponent("EmergencyAreaIDList")
		tmp_emergencyareaidlist := make(s00.EmergencyAreaIDList, 0)
		_, errCollection_emergencyareaidlist := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_emergencyareaidlist, fragmentLength_emergencyareaidlist int64) error {
			// arithmetic pattern APER_FRAGMENT_LOOP_5: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1191
			if fragmentOffset_emergencyareaidlist < 0 || fragmentLength_emergencyareaidlist < 0 || fragmentLength_emergencyareaidlist > int64(^uint(0)>>1) || fragmentOffset_emergencyareaidlist > int64(^uint(0)>>1)-fragmentLength_emergencyareaidlist {
				return fmt.Errorf("collection fragment count out of range")
			}
			for i := int64(0); i < fragmentLength_emergencyareaidlist; i++ {
				val, err := aper.DecodeOctetStringAligned(bb, 3, 3, true)
				if err != nil {
					return runtime.WrapDecodePath(err, fmt.Sprintf("EmergencyAreaIDList[%d]", fragmentOffset_emergencyareaidlist+i))
				}
				if next, err := aper.AppendValues(bb, tmp_emergencyareaidlist, val); err != nil {
					return err
				} else {
					tmp_emergencyareaidlist = next
				}
			}
			return nil
		})
		if errCollection_emergencyareaidlist != nil {
			return runtime.WrapDecodePath(errCollection_emergencyareaidlist, "EmergencyAreaIDList")
		}
		v.EmergencyAreaIDList = tmp_emergencyareaidlist
		bb.LeaveComponent(toleranceMark_emergencyareaidlist)
	}
	v.stream = bb.CaptureWireSpan(replayStart)

	return nil
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *AreaScopeOfMDT) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s14.BridgeReceivedFormAt(v.received, v.receivedBytes, "AreaScopeOfMDT", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "AreaScopeOfMDT", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v AreaScopeOfMDT) WithoutReplay() AreaScopeOfMDT {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero AreaScopeOfMDT
	v.perPadding = zero.perPadding
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *AreaScopeOfQMC) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s14.BridgeReceivedFormAt(v.received, v.receivedBytes, "AreaScopeOfQMC", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "AreaScopeOfQMC", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v AreaScopeOfQMC) WithoutReplay() AreaScopeOfQMC {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero AreaScopeOfQMC
	v.perPadding = zero.perPadding
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *BroadcastCancelledAreaList) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s14.BridgeReceivedFormAt(v.received, v.receivedBytes, "BroadcastCancelledAreaList", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "BroadcastCancelledAreaList", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v BroadcastCancelledAreaList) WithoutReplay() BroadcastCancelledAreaList {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero BroadcastCancelledAreaList
	v.perPadding = zero.perPadding
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
func (v *TAIBasedMDT) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s14.BridgeReceivedFormAt(v.received, v.receivedBytes, "TAIBasedMDT", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "TAIBasedMDT", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v TAIBasedMDT) WithoutReplay() TAIBasedMDT {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero TAIBasedMDT
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *TAIBasedQMC) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s14.BridgeReceivedFormAt(v.received, v.receivedBytes, "TAIBasedQMC", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "TAIBasedQMC", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v TAIBasedQMC) WithoutReplay() TAIBasedQMC {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero TAIBasedQMC
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *WarningAreaList) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s14.BridgeReceivedFormAt(v.received, v.receivedBytes, "WarningAreaList", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "WarningAreaList", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v WarningAreaList) WithoutReplay() WarningAreaList {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero WarningAreaList
	v.perPadding = zero.perPadding
	return v
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
func (v *TAIBasedMDT) Extensions() []aper.SequenceExtension {
	if v == nil {
		return nil
	}
	views := aper.SequenceExtensionViews(v.extPresent, aper.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *TAIBasedMDT) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("TAIBasedMDT.Extensions[%d]", index))
	}
	if err := aper.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("TAIBasedMDT.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *TAIBasedMDT) RemoveExtension(index uint64) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("TAIBasedMDT.Extensions[%d]", index))
	}
	if err := aper.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("TAIBasedMDT.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// Extensions returns owned unknown sequence additions.
func (v *TAIBasedQMC) Extensions() []aper.SequenceExtension {
	if v == nil {
		return nil
	}
	views := aper.SequenceExtensionViews(v.extPresent, aper.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *TAIBasedQMC) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("TAIBasedQMC.Extensions[%d]", index))
	}
	if err := aper.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("TAIBasedQMC.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *TAIBasedQMC) RemoveExtension(index uint64) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("TAIBasedQMC.Extensions[%d]", index))
	}
	if err := aper.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("TAIBasedQMC.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// MarshalAPER encodes a complete value using one per-call change plan.
func (v *AreaScopeOfMDT) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "AreaScopeOfMDT")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *AreaScopeOfMDT) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "AreaScopeOfMDT")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APAreaScopeOfMDT(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "AreaScopeOfMDT")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "AreaScopeOfMDT")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *AreaScopeOfMDT) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "AreaScopeOfMDT")
}
func (v *AreaScopeOfMDT) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "AreaScopeOfMDT")
}
func (v *AreaScopeOfMDT) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APAreaScopeOfMDT(v, &s)
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
func (v *AreaScopeOfMDT) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *AreaScopeOfMDT) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
func (v *AreaScopeOfQMC) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "AreaScopeOfQMC")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *AreaScopeOfQMC) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "AreaScopeOfQMC")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APAreaScopeOfQMC(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "AreaScopeOfQMC")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "AreaScopeOfQMC")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *AreaScopeOfQMC) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "AreaScopeOfQMC")
}
func (v *AreaScopeOfQMC) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "AreaScopeOfQMC")
}
func (v *AreaScopeOfQMC) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APAreaScopeOfQMC(v, &s)
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
func (v *AreaScopeOfQMC) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *AreaScopeOfQMC) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
func (v *BroadcastCancelledAreaList) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "BroadcastCancelledAreaList")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *BroadcastCancelledAreaList) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "BroadcastCancelledAreaList")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APBroadcastCancelledAreaList(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "BroadcastCancelledAreaList")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "BroadcastCancelledAreaList")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *BroadcastCancelledAreaList) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "BroadcastCancelledAreaList")
}
func (v *BroadcastCancelledAreaList) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "BroadcastCancelledAreaList")
}
func (v *BroadcastCancelledAreaList) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APBroadcastCancelledAreaList(v, &s)
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
func (v *BroadcastCancelledAreaList) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *BroadcastCancelledAreaList) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
func (v *TAIBasedMDT) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "TAIBasedMDT")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *TAIBasedMDT) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "TAIBasedMDT")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APTAIBasedMDT(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "TAIBasedMDT")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "TAIBasedMDT")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *TAIBasedMDT) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "TAIBasedMDT")
}
func (v *TAIBasedMDT) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "TAIBasedMDT")
}
func (v *TAIBasedMDT) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APTAIBasedMDT(v, &s)
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
func (v *TAIBasedMDT) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *TAIBasedMDT) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
func (v *TAIBasedQMC) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "TAIBasedQMC")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *TAIBasedQMC) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "TAIBasedQMC")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APTAIBasedQMC(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "TAIBasedQMC")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "TAIBasedQMC")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *TAIBasedQMC) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "TAIBasedQMC")
}
func (v *TAIBasedQMC) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "TAIBasedQMC")
}
func (v *TAIBasedQMC) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APTAIBasedQMC(v, &s)
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
func (v *TAIBasedQMC) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *TAIBasedQMC) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
func (v *WarningAreaList) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "WarningAreaList")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *WarningAreaList) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "WarningAreaList")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APWarningAreaList(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "WarningAreaList")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "WarningAreaList")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *WarningAreaList) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "WarningAreaList")
}
func (v *WarningAreaList) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "WarningAreaList")
}
func (v *WarningAreaList) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APWarningAreaList(v, &s)
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
func (v *WarningAreaList) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *WarningAreaList) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
func (v *AreaScopeOfMDT) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "AreaScopeOfMDT")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded AreaScopeOfMDT
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APAreaScopeOfMDT(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = AreaScopeOfMDT{}
		return report, aper.OperationError(err, "AreaScopeOfMDT")
	}
	*v = decoded
	return report, aper.OperationError(nil, "AreaScopeOfMDT")
}

// UnmarshalAPER decodes one complete value and returns its report.
func (v *AreaScopeOfQMC) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "AreaScopeOfQMC")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded AreaScopeOfQMC
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APAreaScopeOfQMC(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = AreaScopeOfQMC{}
		return report, aper.OperationError(err, "AreaScopeOfQMC")
	}
	*v = decoded
	return report, aper.OperationError(nil, "AreaScopeOfQMC")
}

// UnmarshalAPER decodes one complete value and returns its report.
func (v *BroadcastCancelledAreaList) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "BroadcastCancelledAreaList")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded BroadcastCancelledAreaList
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APBroadcastCancelledAreaList(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = BroadcastCancelledAreaList{}
		return report, aper.OperationError(err, "BroadcastCancelledAreaList")
	}
	*v = decoded
	return report, aper.OperationError(nil, "BroadcastCancelledAreaList")
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
func (v *TAIBasedMDT) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "TAIBasedMDT")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded TAIBasedMDT
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APTAIBasedMDT(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = TAIBasedMDT{}
		return report, aper.OperationError(err, "TAIBasedMDT")
	}
	*v = decoded
	return report, aper.OperationError(nil, "TAIBasedMDT")
}

// UnmarshalAPER decodes one complete value and returns its report.
func (v *TAIBasedQMC) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "TAIBasedQMC")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded TAIBasedQMC
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APTAIBasedQMC(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = TAIBasedQMC{}
		return report, aper.OperationError(err, "TAIBasedQMC")
	}
	*v = decoded
	return report, aper.OperationError(nil, "TAIBasedQMC")
}

// UnmarshalAPER decodes one complete value and returns its report.
func (v *WarningAreaList) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "WarningAreaList")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded WarningAreaList
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APWarningAreaList(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = WarningAreaList{}
		return report, aper.OperationError(err, "WarningAreaList")
	}
	*v = decoded
	return report, aper.OperationError(nil, "WarningAreaList")
}

// NewAreaScopeOfMDTCellBased constructs a checked complete value.
func NewAreaScopeOfMDTCellBased(v s22.CellBasedMDT, options ...aper.BuildOption) (AreaScopeOfMDT, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return AreaScopeOfMDT{}, aper.OperationError(err, "AreaScopeOfMDTCellBased")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), v); err != nil {
		return AreaScopeOfMDT{}, aper.OperationError(err, "AreaScopeOfMDTCellBased")
	}
	value := BridgeNewAreaScopeOfMDTCellBasedLegacy(v)
	if _, err := (&value).marshalAPERBudget(budget, false); err != nil {
		return AreaScopeOfMDT{}, aper.OperationError(err, "AreaScopeOfMDTCellBased")
	}
	return value, aper.OperationError(nil, "AreaScopeOfMDTCellBased")
}

// NewAreaScopeOfMDTTABased constructs a checked complete value.
func NewAreaScopeOfMDTTABased(v s32.TABasedMDT, options ...aper.BuildOption) (AreaScopeOfMDT, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return AreaScopeOfMDT{}, aper.OperationError(err, "AreaScopeOfMDTTABased")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), v); err != nil {
		return AreaScopeOfMDT{}, aper.OperationError(err, "AreaScopeOfMDTTABased")
	}
	value := BridgeNewAreaScopeOfMDTTABasedLegacy(v)
	if _, err := (&value).marshalAPERBudget(budget, false); err != nil {
		return AreaScopeOfMDT{}, aper.OperationError(err, "AreaScopeOfMDTTABased")
	}
	return value, aper.OperationError(nil, "AreaScopeOfMDTTABased")
}

// NewAreaScopeOfMDTPLMNWide constructs a checked complete value.
func NewAreaScopeOfMDTPLMNWide(v struct{}, options ...aper.BuildOption) (AreaScopeOfMDT, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return AreaScopeOfMDT{}, aper.OperationError(err, "AreaScopeOfMDTPLMNWide")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), v); err != nil {
		return AreaScopeOfMDT{}, aper.OperationError(err, "AreaScopeOfMDTPLMNWide")
	}
	value := BridgeNewAreaScopeOfMDTPLMNWideLegacy(v)
	if _, err := (&value).marshalAPERBudget(budget, false); err != nil {
		return AreaScopeOfMDT{}, aper.OperationError(err, "AreaScopeOfMDTPLMNWide")
	}
	return value, aper.OperationError(nil, "AreaScopeOfMDTPLMNWide")
}

// NewAreaScopeOfMDTTAIBased constructs a checked complete value.
func NewAreaScopeOfMDTTAIBased(v TAIBasedMDT, options ...aper.BuildOption) (AreaScopeOfMDT, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return AreaScopeOfMDT{}, aper.OperationError(err, "AreaScopeOfMDTTAIBased")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), v); err != nil {
		return AreaScopeOfMDT{}, aper.OperationError(err, "AreaScopeOfMDTTAIBased")
	}
	value := BridgeNewAreaScopeOfMDTTAIBasedLegacy(v)
	if _, err := (&value).marshalAPERBudget(budget, false); err != nil {
		return AreaScopeOfMDT{}, aper.OperationError(err, "AreaScopeOfMDTTAIBased")
	}
	return value, aper.OperationError(nil, "AreaScopeOfMDTTAIBased")
}

// NewAreaScopeOfQMCCellBased constructs a checked complete value.
func NewAreaScopeOfQMCCellBased(v s22.CellBasedQMC, options ...aper.BuildOption) (AreaScopeOfQMC, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return AreaScopeOfQMC{}, aper.OperationError(err, "AreaScopeOfQMCCellBased")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), v); err != nil {
		return AreaScopeOfQMC{}, aper.OperationError(err, "AreaScopeOfQMCCellBased")
	}
	value := BridgeNewAreaScopeOfQMCCellBasedLegacy(v)
	if _, err := (&value).marshalAPERBudget(budget, false); err != nil {
		return AreaScopeOfQMC{}, aper.OperationError(err, "AreaScopeOfQMCCellBased")
	}
	return value, aper.OperationError(nil, "AreaScopeOfQMCCellBased")
}

// NewAreaScopeOfQMCTABased constructs a checked complete value.
func NewAreaScopeOfQMCTABased(v s32.TABasedQMC, options ...aper.BuildOption) (AreaScopeOfQMC, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return AreaScopeOfQMC{}, aper.OperationError(err, "AreaScopeOfQMCTABased")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), v); err != nil {
		return AreaScopeOfQMC{}, aper.OperationError(err, "AreaScopeOfQMCTABased")
	}
	value := BridgeNewAreaScopeOfQMCTABasedLegacy(v)
	if _, err := (&value).marshalAPERBudget(budget, false); err != nil {
		return AreaScopeOfQMC{}, aper.OperationError(err, "AreaScopeOfQMCTABased")
	}
	return value, aper.OperationError(nil, "AreaScopeOfQMCTABased")
}

// NewAreaScopeOfQMCTAIBased constructs a checked complete value.
func NewAreaScopeOfQMCTAIBased(v TAIBasedQMC, options ...aper.BuildOption) (AreaScopeOfQMC, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return AreaScopeOfQMC{}, aper.OperationError(err, "AreaScopeOfQMCTAIBased")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), v); err != nil {
		return AreaScopeOfQMC{}, aper.OperationError(err, "AreaScopeOfQMCTAIBased")
	}
	value := BridgeNewAreaScopeOfQMCTAIBasedLegacy(v)
	if _, err := (&value).marshalAPERBudget(budget, false); err != nil {
		return AreaScopeOfQMC{}, aper.OperationError(err, "AreaScopeOfQMCTAIBased")
	}
	return value, aper.OperationError(nil, "AreaScopeOfQMCTAIBased")
}

// NewAreaScopeOfQMCPLMNAreaBased constructs a checked complete value.
func NewAreaScopeOfQMCPLMNAreaBased(v s20.PLMNAreaBasedQMC, options ...aper.BuildOption) (AreaScopeOfQMC, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return AreaScopeOfQMC{}, aper.OperationError(err, "AreaScopeOfQMCPLMNAreaBased")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), v); err != nil {
		return AreaScopeOfQMC{}, aper.OperationError(err, "AreaScopeOfQMCPLMNAreaBased")
	}
	value := BridgeNewAreaScopeOfQMCPLMNAreaBasedLegacy(v)
	if _, err := (&value).marshalAPERBudget(budget, false); err != nil {
		return AreaScopeOfQMC{}, aper.OperationError(err, "AreaScopeOfQMCPLMNAreaBased")
	}
	return value, aper.OperationError(nil, "AreaScopeOfQMCPLMNAreaBased")
}

// NewBroadcastCancelledAreaListCellIDCancelled constructs a checked complete value.
func NewBroadcastCancelledAreaListCellIDCancelled(v s17.CellIDCancelled, options ...aper.BuildOption) (BroadcastCancelledAreaList, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return BroadcastCancelledAreaList{}, aper.OperationError(err, "BroadcastCancelledAreaListCellIDCancelled")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), v); err != nil {
		return BroadcastCancelledAreaList{}, aper.OperationError(err, "BroadcastCancelledAreaListCellIDCancelled")
	}
	value := BridgeNewBroadcastCancelledAreaListCellIDCancelledLegacy(v)
	if _, err := (&value).marshalAPERBudget(budget, false); err != nil {
		return BroadcastCancelledAreaList{}, aper.OperationError(err, "BroadcastCancelledAreaListCellIDCancelled")
	}
	return value, aper.OperationError(nil, "BroadcastCancelledAreaListCellIDCancelled")
}

// NewBroadcastCancelledAreaListTAICancelled constructs a checked complete value.
func NewBroadcastCancelledAreaListTAICancelled(v s32.TAICancelled, options ...aper.BuildOption) (BroadcastCancelledAreaList, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return BroadcastCancelledAreaList{}, aper.OperationError(err, "BroadcastCancelledAreaListTAICancelled")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), v); err != nil {
		return BroadcastCancelledAreaList{}, aper.OperationError(err, "BroadcastCancelledAreaListTAICancelled")
	}
	value := BridgeNewBroadcastCancelledAreaListTAICancelledLegacy(v)
	if _, err := (&value).marshalAPERBudget(budget, false); err != nil {
		return BroadcastCancelledAreaList{}, aper.OperationError(err, "BroadcastCancelledAreaListTAICancelled")
	}
	return value, aper.OperationError(nil, "BroadcastCancelledAreaListTAICancelled")
}

// NewBroadcastCancelledAreaListEmergencyAreaIDCancelled constructs a checked complete value.
func NewBroadcastCancelledAreaListEmergencyAreaIDCancelled(v s22.EmergencyAreaIDCancelled, options ...aper.BuildOption) (BroadcastCancelledAreaList, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return BroadcastCancelledAreaList{}, aper.OperationError(err, "BroadcastCancelledAreaListEmergencyAreaIDCancelled")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), v); err != nil {
		return BroadcastCancelledAreaList{}, aper.OperationError(err, "BroadcastCancelledAreaListEmergencyAreaIDCancelled")
	}
	value := BridgeNewBroadcastCancelledAreaListEmergencyAreaIDCancelledLegacy(v)
	if _, err := (&value).marshalAPERBudget(budget, false); err != nil {
		return BroadcastCancelledAreaList{}, aper.OperationError(err, "BroadcastCancelledAreaListEmergencyAreaIDCancelled")
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
func NewENDCSONTransferTypeRequest(v s32.ENDCTransferTypeRequest, options ...aper.BuildOption) (s32.ENDCSONTransferType, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s32.ENDCSONTransferType{}, aper.OperationError(err, "ENDCSONTransferTypeRequest")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), v); err != nil {
		return s32.ENDCSONTransferType{}, aper.OperationError(err, "ENDCSONTransferTypeRequest")
	}
	value := BridgeNewENDCSONTransferTypeRequestLegacy(v)
	if _, err := s32.BridgeENDCSONTransferTypeMethodMarshalAPERBudget((&value), budget, false); err != nil {
		return s32.ENDCSONTransferType{}, aper.OperationError(err, "ENDCSONTransferTypeRequest")
	}
	return value, aper.OperationError(nil, "ENDCSONTransferTypeRequest")
}

// NewENDCSONTransferTypeReply constructs a checked complete value.
func NewENDCSONTransferTypeReply(v s32.ENDCTransferTypeReply, options ...aper.BuildOption) (s32.ENDCSONTransferType, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s32.ENDCSONTransferType{}, aper.OperationError(err, "ENDCSONTransferTypeReply")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), v); err != nil {
		return s32.ENDCSONTransferType{}, aper.OperationError(err, "ENDCSONTransferTypeReply")
	}
	value := BridgeNewENDCSONTransferTypeReplyLegacy(v)
	if _, err := s32.BridgeENDCSONTransferTypeMethodMarshalAPERBudget((&value), budget, false); err != nil {
		return s32.ENDCSONTransferType{}, aper.OperationError(err, "ENDCSONTransferTypeReply")
	}
	return value, aper.OperationError(nil, "ENDCSONTransferTypeReply")
}

// NewMMEPagingTargetGlobalENBID constructs a checked complete value.
func NewMMEPagingTargetGlobalENBID(v s18.GlobalENBID, options ...aper.BuildOption) (s32.MMEPagingTarget, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s32.MMEPagingTarget{}, aper.OperationError(err, "MMEPagingTargetGlobalENBID")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), v); err != nil {
		return s32.MMEPagingTarget{}, aper.OperationError(err, "MMEPagingTargetGlobalENBID")
	}
	value := BridgeNewMMEPagingTargetGlobalENBIDLegacy(v)
	if _, err := s32.BridgeMMEPagingTargetMethodMarshalAPERBudget((&value), budget, false); err != nil {
		return s32.MMEPagingTarget{}, aper.OperationError(err, "MMEPagingTargetGlobalENBID")
	}
	return value, aper.OperationError(nil, "MMEPagingTargetGlobalENBID")
}

// NewMMEPagingTargetTAI constructs a checked complete value.
func NewMMEPagingTargetTAI(v s32.TAI, options ...aper.BuildOption) (s32.MMEPagingTarget, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s32.MMEPagingTarget{}, aper.OperationError(err, "MMEPagingTargetTAI")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), v); err != nil {
		return s32.MMEPagingTarget{}, aper.OperationError(err, "MMEPagingTargetTAI")
	}
	value := BridgeNewMMEPagingTargetTAILegacy(v)
	if _, err := s32.BridgeMMEPagingTargetMethodMarshalAPERBudget((&value), budget, false); err != nil {
		return s32.MMEPagingTarget{}, aper.OperationError(err, "MMEPagingTargetTAI")
	}
	return value, aper.OperationError(nil, "MMEPagingTargetTAI")
}

// NewWarningAreaListCellIDList constructs a checked complete value.
func NewWarningAreaListCellIDList(v s17.ECGIList, options ...aper.BuildOption) (WarningAreaList, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return WarningAreaList{}, aper.OperationError(err, "WarningAreaListCellIDList")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), v); err != nil {
		return WarningAreaList{}, aper.OperationError(err, "WarningAreaListCellIDList")
	}
	value := BridgeNewWarningAreaListCellIDListLegacy(v)
	if _, err := (&value).marshalAPERBudget(budget, false); err != nil {
		return WarningAreaList{}, aper.OperationError(err, "WarningAreaListCellIDList")
	}
	return value, aper.OperationError(nil, "WarningAreaListCellIDList")
}

// NewWarningAreaListTrackingAreaListforWarning constructs a checked complete value.
func NewWarningAreaListTrackingAreaListforWarning(v s32.TAIListforWarning, options ...aper.BuildOption) (WarningAreaList, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return WarningAreaList{}, aper.OperationError(err, "WarningAreaListTrackingAreaListforWarning")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), v); err != nil {
		return WarningAreaList{}, aper.OperationError(err, "WarningAreaListTrackingAreaListforWarning")
	}
	value := BridgeNewWarningAreaListTrackingAreaListforWarningLegacy(v)
	if _, err := (&value).marshalAPERBudget(budget, false); err != nil {
		return WarningAreaList{}, aper.OperationError(err, "WarningAreaListTrackingAreaListforWarning")
	}
	return value, aper.OperationError(nil, "WarningAreaListTrackingAreaListforWarning")
}

// NewWarningAreaListEmergencyAreaIDList constructs a checked complete value.
func NewWarningAreaListEmergencyAreaIDList(v s00.EmergencyAreaIDList, options ...aper.BuildOption) (WarningAreaList, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return WarningAreaList{}, aper.OperationError(err, "WarningAreaListEmergencyAreaIDList")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), v); err != nil {
		return WarningAreaList{}, aper.OperationError(err, "WarningAreaListEmergencyAreaIDList")
	}
	value := BridgeNewWarningAreaListEmergencyAreaIDListLegacy(v)
	if _, err := (&value).marshalAPERBudget(budget, false); err != nil {
		return WarningAreaList{}, aper.OperationError(err, "WarningAreaListEmergencyAreaIDList")
	}
	return value, aper.OperationError(nil, "WarningAreaListEmergencyAreaIDList")
}

// NewAreaScopeOfMDTUnknownExtension builds a checked, owned unknown CHOICE alternative.
func NewAreaScopeOfMDTUnknownExtension(index uint64, contents []byte, options ...aper.BuildOption) (AreaScopeOfMDT, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return AreaScopeOfMDT{}, aper.OperationError(err, "AreaScopeOfMDTUnknownExtension")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), aper.ChoiceExtension{}); err != nil {
		return AreaScopeOfMDT{}, aper.OperationError(err, "AreaScopeOfMDTUnknownExtension")
	}
	extension, err := aper.BuildChoiceExtension(index, contents, budget)
	if err != nil {
		return AreaScopeOfMDT{}, aper.OperationError(err, "AreaScopeOfMDTUnknownExtension")
	}
	value := AreaScopeOfMDT{UnknownExtension: &extension}
	if _, err := value.marshalAPERBudget(budget, false); err != nil {
		return AreaScopeOfMDT{}, aper.OperationError(err, "AreaScopeOfMDTUnknownExtension")
	}
	return value, aper.OperationError(nil, "AreaScopeOfMDTUnknownExtension")
}

// NewAreaScopeOfQMCUnknownExtension builds a checked, owned unknown CHOICE alternative.
func NewAreaScopeOfQMCUnknownExtension(index uint64, contents []byte, options ...aper.BuildOption) (AreaScopeOfQMC, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return AreaScopeOfQMC{}, aper.OperationError(err, "AreaScopeOfQMCUnknownExtension")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), aper.ChoiceExtension{}); err != nil {
		return AreaScopeOfQMC{}, aper.OperationError(err, "AreaScopeOfQMCUnknownExtension")
	}
	extension, err := aper.BuildChoiceExtension(index, contents, budget)
	if err != nil {
		return AreaScopeOfQMC{}, aper.OperationError(err, "AreaScopeOfQMCUnknownExtension")
	}
	value := AreaScopeOfQMC{UnknownExtension: &extension}
	if _, err := value.marshalAPERBudget(budget, false); err != nil {
		return AreaScopeOfQMC{}, aper.OperationError(err, "AreaScopeOfQMCUnknownExtension")
	}
	return value, aper.OperationError(nil, "AreaScopeOfQMCUnknownExtension")
}

// NewBroadcastCancelledAreaListUnknownExtension builds a checked, owned unknown CHOICE alternative.
func NewBroadcastCancelledAreaListUnknownExtension(index uint64, contents []byte, options ...aper.BuildOption) (BroadcastCancelledAreaList, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return BroadcastCancelledAreaList{}, aper.OperationError(err, "BroadcastCancelledAreaListUnknownExtension")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), aper.ChoiceExtension{}); err != nil {
		return BroadcastCancelledAreaList{}, aper.OperationError(err, "BroadcastCancelledAreaListUnknownExtension")
	}
	extension, err := aper.BuildChoiceExtension(index, contents, budget)
	if err != nil {
		return BroadcastCancelledAreaList{}, aper.OperationError(err, "BroadcastCancelledAreaListUnknownExtension")
	}
	value := BroadcastCancelledAreaList{UnknownExtension: &extension}
	if _, err := value.marshalAPERBudget(budget, false); err != nil {
		return BroadcastCancelledAreaList{}, aper.OperationError(err, "BroadcastCancelledAreaListUnknownExtension")
	}
	return value, aper.OperationError(nil, "BroadcastCancelledAreaListUnknownExtension")
}

// NewWarningAreaListUnknownExtension builds a checked, owned unknown CHOICE alternative.
func NewWarningAreaListUnknownExtension(index uint64, contents []byte, options ...aper.BuildOption) (WarningAreaList, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return WarningAreaList{}, aper.OperationError(err, "WarningAreaListUnknownExtension")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), aper.ChoiceExtension{}); err != nil {
		return WarningAreaList{}, aper.OperationError(err, "WarningAreaListUnknownExtension")
	}
	extension, err := aper.BuildChoiceExtension(index, contents, budget)
	if err != nil {
		return WarningAreaList{}, aper.OperationError(err, "WarningAreaListUnknownExtension")
	}
	value := WarningAreaList{UnknownExtension: &extension}
	if _, err := value.marshalAPERBudget(budget, false); err != nil {
		return WarningAreaList{}, aper.OperationError(err, "WarningAreaListUnknownExtension")
	}
	return value, aper.OperationError(nil, "WarningAreaListUnknownExtension")
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
	ProtocolIEs      s32.LocationReportIEContainer `asn1:"tag:0,context,implicit"`
	protocolIEsIndef bool                          `asn1:"-" json:"-"`
	extCount         int64                         `asn1:"-" json:"-"`
	extPresent       []bool                        `asn1:"-" json:"-"`
	extData          [][]byte                      `asn1:"-" json:"-"`
	perPadding       aper.FinalPadding             `asn1:"-" json:"-"`
	perExtPadding    []aper.CompletePadding        `asn1:"-" json:"-"`
	extOrigin        []aper.OpaqueOrigin
	extWire          []aper.WireSpan
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
	ProtocolIEs      KillRequestIEContainer `asn1:"tag:0,context,implicit"`
	protocolIEsIndef bool                   `asn1:"-" json:"-"`
	extCount         int64                  `asn1:"-" json:"-"`
	extPresent       []bool                 `asn1:"-" json:"-"`
	extData          [][]byte               `asn1:"-" json:"-"`
	perPadding       aper.FinalPadding      `asn1:"-" json:"-"`
	perExtPadding    []aper.CompletePadding `asn1:"-" json:"-"`
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
	ProtocolIEs      KillResponseIEContainer `asn1:"tag:0,context,implicit"`
	protocolIEsIndef bool                    `asn1:"-" json:"-"`
	extCount         int64                   `asn1:"-" json:"-"`
	extPresent       []bool                  `asn1:"-" json:"-"`
	extData          [][]byte                `asn1:"-" json:"-"`
	perPadding       aper.FinalPadding       `asn1:"-" json:"-"`
	perExtPadding    []aper.CompletePadding  `asn1:"-" json:"-"`
	extOrigin        []aper.OpaqueOrigin
	extWire          []aper.WireSpan
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
			if err := s32.BridgeLocationReportIEFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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
	bb.EnterComponent("LocationReport")
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
	toleranceMark_protocolies := bb.EnterComponent("ProtocolIEs")
	v.ProtocolIEs = make(s32.LocationReportIEContainer, 0)
	_, errCollection_protocolies := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1128
		if fragmentOffset_protocolies < 0 || fragmentLength_protocolies < 0 || fragmentLength_protocolies > int64(^uint(0)>>1) || fragmentOffset_protocolies > int64(^uint(0)>>1)-fragmentLength_protocolies {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_protocolies; i++ {
			var elem s32.LocationReportIEField
			elementMark := bb.EnterIndex(fragmentOffset_protocolies + i)
			if err := s32.BridgeLocationReportIEFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
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
	bb.EnterComponent("KillRequest")
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
	toleranceMark_protocolies := bb.EnterComponent("ProtocolIEs")
	v.ProtocolIEs = make(KillRequestIEContainer, 0)
	_, errCollection_protocolies := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1128
		if fragmentOffset_protocolies < 0 || fragmentLength_protocolies < 0 || fragmentLength_protocolies > int64(^uint(0)>>1) || fragmentOffset_protocolies > int64(^uint(0)>>1)-fragmentLength_protocolies {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_protocolies; i++ {
			var elem KillRequestIEField
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
	bb.EnterComponent("KillResponse")
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
	toleranceMark_protocolies := bb.EnterComponent("ProtocolIEs")
	v.ProtocolIEs = make(KillResponseIEContainer, 0)
	_, errCollection_protocolies := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1128
		if fragmentOffset_protocolies < 0 || fragmentLength_protocolies < 0 || fragmentLength_protocolies > int64(^uint(0)>>1) || fragmentOffset_protocolies > int64(^uint(0)>>1)-fragmentLength_protocolies {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_protocolies; i++ {
			var elem KillResponseIEField
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

type KillRequestIEValue struct {
	id                        s00.ProtocolIEID
	received                  aper.WireSpan
	replay                    aper.Snapshot
	opaque                    aper.OpaqueOpenType
	isOpaque                  bool
	rowMessageIdentifier      *s00.MessageIdentifier
	rowSerialNumber           *s00.SerialNumber
	rowWarningAreaList        *WarningAreaList
	rowKillAllWarningMessages *s00.KillAllWarningMessages
}

func (v KillRequestIEValue) matchesID(id s00.ProtocolIEID, _ ...*aper.DecodeBudget) bool {
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
	case s00.ProtocolIEID(191):
		return v.rowKillAllWarningMessages != nil
	}
	return false
}

// Opaque returns the retained opaque open value of KillRequestIEValue and reports whether the opaque alternative is selected.
func (v *KillRequestIEValue) Opaque() (aper.OpaqueOpenType, bool) {
	if v == nil || !v.isOpaque {
		return aper.OpaqueOpenType{}, false
	}
	return v.opaque, true
}
func (KillRequestIEValue) rule() aper.SourceRule {
	return aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "KillRequestIEs"}}
}
func (KillRequestIEValue) reason(id s00.ProtocolIEID) aper.OpaqueReason {
	switch id {
	case s00.ProtocolIEID(111):
		return aper.UnknownSelector
	case s00.ProtocolIEID(112):
		return aper.UnknownSelector
	case s00.ProtocolIEID(113):
		return aper.UnknownSelector
	case s00.ProtocolIEID(191):
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

// AsMessageIdentifier returns the selected MessageIdentifier value of KillRequestIEValue and reports whether that alternative is active.
func (v *KillRequestIEValue) AsMessageIdentifier() (*s00.MessageIdentifier, bool) {
	if v == nil || v.id != s00.ProtocolIEID(111) || v.rowMessageIdentifier == nil {
		return nil, false
	}
	return v.rowMessageIdentifier, true
}

// AsSerialNumber returns the selected SerialNumber value of KillRequestIEValue and reports whether that alternative is active.
func (v *KillRequestIEValue) AsSerialNumber() (*s00.SerialNumber, bool) {
	if v == nil || v.id != s00.ProtocolIEID(112) || v.rowSerialNumber == nil {
		return nil, false
	}
	return v.rowSerialNumber, true
}

// AsWarningAreaList returns the selected WarningAreaList value of KillRequestIEValue and reports whether that alternative is active.
func (v *KillRequestIEValue) AsWarningAreaList() (*WarningAreaList, bool) {
	if v == nil || v.id != s00.ProtocolIEID(113) || v.rowWarningAreaList == nil {
		return nil, false
	}
	return v.rowWarningAreaList, true
}

// AsKillAllWarningMessages returns the selected KillAllWarningMessages value of KillRequestIEValue and reports whether that alternative is active.
func (v *KillRequestIEValue) AsKillAllWarningMessages() (*s00.KillAllWarningMessages, bool) {
	if v == nil || v.id != s00.ProtocolIEID(191) || v.rowKillAllWarningMessages == nil {
		return nil, false
	}
	return v.rowKillAllWarningMessages, true
}
func (v KillRequestIEValue) decode(id s00.ProtocolIEID, raw aper.OpaqueOpenType) (KillRequestIEValue, error) {
	out := KillRequestIEValue{id: id}
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
		var value WarningAreaList
		child := scope
		if err := value.unmarshalAPERFrom(child); err != nil {
			return out, fmt.Errorf("%s %w", "WarningAreaList:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "WarningAreaList")
		if err != nil {
			return out, err
		}
		value.perPadding = padding.Padding()
		value.received = true
		raw.RetainContents(&value.receivedBytes)
		value.receivedLocation = raw.ContentLocation()
		out.rowWarningAreaList = &value
		raw.RetainContents(&out.received)
	case s00.ProtocolIEID(191):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		bb := scope
		decoded, err := aper.DecodeEnumeratedAligned(bb, 1, false, aper.EnumerationSource{KnownExtensions: 0, Path: "KillAllWarningMessages"})
		value := s00.KillAllWarningMessages(decoded)
		if err != nil {
			return out, fmt.Errorf("%s %w", "KillAllWarningMessages:", err)
		}
		if _, err := aper.CompleteOpenTypeValue(bb, value); err != nil {
			return out, err
		}
		out.rowKillAllWarningMessages = &value
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
func (v KillRequestIEValue) encode() ([]byte, error) { return v.encodeFresh(false, nil) }
func (v KillRequestIEValue) encodeFresh(fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
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
			return nil, fmt.Errorf("%s missing value", "KillRequestIEs.id-MessageIdentifier:")
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
			return nil, fmt.Errorf("%s missing value", "KillRequestIEs.id-SerialNumber:")
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
			return nil, fmt.Errorf("%s missing value", "KillRequestIEs.id-WarningAreaList:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		candidate, err := v.rowWarningAreaList.marshalAPERBudget(budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	case s00.ProtocolIEID(191):
		if v.rowKillAllWarningMessages == nil {
			return nil, fmt.Errorf("%s missing value", "KillRequestIEs.id-KillAllWarningMessages:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		encodeBB := aper.NewBudgetBuffer(budget)
		if err := aper.EncodeEnumeratedAligned(encodeBB, int64(*v.rowKillAllWarningMessages), 1, false); err != nil {
			return nil, err
		}
		candidate := encodeBB.CompleteBytes()
		return candidate, nil
	default:
		return nil, fmt.Errorf("%s id %d has no value", "KillRequestIEValue:", v.id)
	}
}

type KillResponseIEValue struct {
	id                            s00.ProtocolIEID
	received                      aper.WireSpan
	replay                        aper.Snapshot
	opaque                        aper.OpaqueOpenType
	isOpaque                      bool
	rowMessageIdentifier          *s00.MessageIdentifier
	rowSerialNumber               *s00.SerialNumber
	rowBroadcastCancelledAreaList *BroadcastCancelledAreaList
	rowCriticalityDiagnostics     *s22.CriticalityDiagnostics
}

func (v KillResponseIEValue) matchesID(id s00.ProtocolIEID, _ ...*aper.DecodeBudget) bool {
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
	case s00.ProtocolIEID(141):
		return v.rowBroadcastCancelledAreaList != nil
	case s00.ProtocolIEID(58):
		return v.rowCriticalityDiagnostics != nil
	}
	return false
}

// Opaque returns the retained opaque open value of KillResponseIEValue and reports whether the opaque alternative is selected.
func (v *KillResponseIEValue) Opaque() (aper.OpaqueOpenType, bool) {
	if v == nil || !v.isOpaque {
		return aper.OpaqueOpenType{}, false
	}
	return v.opaque, true
}
func (KillResponseIEValue) rule() aper.SourceRule {
	return aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "KillResponseIEs"}}
}
func (KillResponseIEValue) reason(id s00.ProtocolIEID) aper.OpaqueReason {
	switch id {
	case s00.ProtocolIEID(111):
		return aper.UnknownSelector
	case s00.ProtocolIEID(112):
		return aper.UnknownSelector
	case s00.ProtocolIEID(141):
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

// AsMessageIdentifier returns the selected MessageIdentifier value of KillResponseIEValue and reports whether that alternative is active.
func (v *KillResponseIEValue) AsMessageIdentifier() (*s00.MessageIdentifier, bool) {
	if v == nil || v.id != s00.ProtocolIEID(111) || v.rowMessageIdentifier == nil {
		return nil, false
	}
	return v.rowMessageIdentifier, true
}

// AsSerialNumber returns the selected SerialNumber value of KillResponseIEValue and reports whether that alternative is active.
func (v *KillResponseIEValue) AsSerialNumber() (*s00.SerialNumber, bool) {
	if v == nil || v.id != s00.ProtocolIEID(112) || v.rowSerialNumber == nil {
		return nil, false
	}
	return v.rowSerialNumber, true
}

// AsBroadcastCancelledAreaList returns the selected BroadcastCancelledAreaList value of KillResponseIEValue and reports whether that alternative is active.
func (v *KillResponseIEValue) AsBroadcastCancelledAreaList() (*BroadcastCancelledAreaList, bool) {
	if v == nil || v.id != s00.ProtocolIEID(141) || v.rowBroadcastCancelledAreaList == nil {
		return nil, false
	}
	return v.rowBroadcastCancelledAreaList, true
}

// AsCriticalityDiagnostics returns the selected CriticalityDiagnostics value of KillResponseIEValue and reports whether that alternative is active.
func (v *KillResponseIEValue) AsCriticalityDiagnostics() (*s22.CriticalityDiagnostics, bool) {
	if v == nil || v.id != s00.ProtocolIEID(58) || v.rowCriticalityDiagnostics == nil {
		return nil, false
	}
	return v.rowCriticalityDiagnostics, true
}
func (v KillResponseIEValue) decode(id s00.ProtocolIEID, raw aper.OpaqueOpenType) (KillResponseIEValue, error) {
	out := KillResponseIEValue{id: id}
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
	case s00.ProtocolIEID(141):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		var value BroadcastCancelledAreaList
		child := scope
		if err := value.unmarshalAPERFrom(child); err != nil {
			return out, fmt.Errorf("%s %w", "BroadcastCancelledAreaList:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "BroadcastCancelledAreaList")
		if err != nil {
			return out, err
		}
		value.perPadding = padding.Padding()
		value.received = true
		raw.RetainContents(&value.receivedBytes)
		value.receivedLocation = raw.ContentLocation()
		out.rowBroadcastCancelledAreaList = &value
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
func (v KillResponseIEValue) encode() ([]byte, error) { return v.encodeFresh(false, nil) }
func (v KillResponseIEValue) encodeFresh(fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
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
			return nil, fmt.Errorf("%s missing value", "KillResponseIEs.id-MessageIdentifier:")
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
			return nil, fmt.Errorf("%s missing value", "KillResponseIEs.id-SerialNumber:")
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
	case s00.ProtocolIEID(141):
		if v.rowBroadcastCancelledAreaList == nil {
			return nil, fmt.Errorf("%s missing value", "KillResponseIEs.id-BroadcastCancelledAreaList:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		candidate, err := v.rowBroadcastCancelledAreaList.marshalAPERBudget(budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	case s00.ProtocolIEID(58):
		if v.rowCriticalityDiagnostics == nil {
			return nil, fmt.Errorf("%s missing value", "KillResponseIEs.id-CriticalityDiagnostics:")
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
		return nil, fmt.Errorf("%s id %d has no value", "KillResponseIEValue:", v.id)
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
	rowWarningAreaList                   *WarningAreaList
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
func (v *WriteReplaceWarningRequestIEValue) AsWarningAreaList() (*WarningAreaList, bool) {
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
		var value WarningAreaList
		child := scope
		if err := value.unmarshalAPERFrom(child); err != nil {
			return out, fmt.Errorf("%s %w", "WarningAreaList:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "WarningAreaList")
		if err != nil {
			return out, err
		}
		value.perPadding = padding.Padding()
		value.received = true
		raw.RetainContents(&value.receivedBytes)
		value.receivedLocation = raw.ContentLocation()
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
		candidate, err := v.rowWarningAreaList.marshalAPERBudget(budget, fresh)
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

type WriteReplaceWarningResponseIEValue struct {
	id                            s00.ProtocolIEID
	received                      aper.WireSpan
	replay                        aper.Snapshot
	opaque                        aper.OpaqueOpenType
	isOpaque                      bool
	rowMessageIdentifier          *s00.MessageIdentifier
	rowSerialNumber               *s00.SerialNumber
	rowBroadcastCompletedAreaList *s32.BroadcastCompletedAreaList
	rowCriticalityDiagnostics     *s22.CriticalityDiagnostics
}

func (v WriteReplaceWarningResponseIEValue) matchesID(id s00.ProtocolIEID, _ ...*aper.DecodeBudget) bool {
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
	case s00.ProtocolIEID(120):
		return v.rowBroadcastCompletedAreaList != nil
	case s00.ProtocolIEID(58):
		return v.rowCriticalityDiagnostics != nil
	}
	return false
}

// Opaque returns the retained opaque open value of WriteReplaceWarningResponseIEValue and reports whether the opaque alternative is selected.
func (v *WriteReplaceWarningResponseIEValue) Opaque() (aper.OpaqueOpenType, bool) {
	if v == nil || !v.isOpaque {
		return aper.OpaqueOpenType{}, false
	}
	return v.opaque, true
}
func (WriteReplaceWarningResponseIEValue) rule() aper.SourceRule {
	return aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "WriteReplaceWarningResponseIEs"}}
}
func (WriteReplaceWarningResponseIEValue) reason(id s00.ProtocolIEID) aper.OpaqueReason {
	switch id {
	case s00.ProtocolIEID(111):
		return aper.UnknownSelector
	case s00.ProtocolIEID(112):
		return aper.UnknownSelector
	case s00.ProtocolIEID(120):
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

// AsMessageIdentifier returns the selected MessageIdentifier value of WriteReplaceWarningResponseIEValue and reports whether that alternative is active.
func (v *WriteReplaceWarningResponseIEValue) AsMessageIdentifier() (*s00.MessageIdentifier, bool) {
	if v == nil || v.id != s00.ProtocolIEID(111) || v.rowMessageIdentifier == nil {
		return nil, false
	}
	return v.rowMessageIdentifier, true
}

// AsSerialNumber returns the selected SerialNumber value of WriteReplaceWarningResponseIEValue and reports whether that alternative is active.
func (v *WriteReplaceWarningResponseIEValue) AsSerialNumber() (*s00.SerialNumber, bool) {
	if v == nil || v.id != s00.ProtocolIEID(112) || v.rowSerialNumber == nil {
		return nil, false
	}
	return v.rowSerialNumber, true
}

// AsBroadcastCompletedAreaList returns the selected BroadcastCompletedAreaList value of WriteReplaceWarningResponseIEValue and reports whether that alternative is active.
func (v *WriteReplaceWarningResponseIEValue) AsBroadcastCompletedAreaList() (*s32.BroadcastCompletedAreaList, bool) {
	if v == nil || v.id != s00.ProtocolIEID(120) || v.rowBroadcastCompletedAreaList == nil {
		return nil, false
	}
	return v.rowBroadcastCompletedAreaList, true
}

// AsCriticalityDiagnostics returns the selected CriticalityDiagnostics value of WriteReplaceWarningResponseIEValue and reports whether that alternative is active.
func (v *WriteReplaceWarningResponseIEValue) AsCriticalityDiagnostics() (*s22.CriticalityDiagnostics, bool) {
	if v == nil || v.id != s00.ProtocolIEID(58) || v.rowCriticalityDiagnostics == nil {
		return nil, false
	}
	return v.rowCriticalityDiagnostics, true
}
func (v WriteReplaceWarningResponseIEValue) decode(id s00.ProtocolIEID, raw aper.OpaqueOpenType) (WriteReplaceWarningResponseIEValue, error) {
	out := WriteReplaceWarningResponseIEValue{id: id}
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
	case s00.ProtocolIEID(120):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		var value s32.BroadcastCompletedAreaList
		child := scope
		if err := s32.BridgeBroadcastCompletedAreaListMethodUnmarshalAPERFrom(&value, child); err != nil {
			return out, fmt.Errorf("%s %w", "BroadcastCompletedAreaList:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "BroadcastCompletedAreaList")
		if err != nil {
			return out, err
		}
		*s32.BridgeBroadcastCompletedAreaListFieldPerPadding(&value) = padding.Padding()
		*s32.BridgeBroadcastCompletedAreaListFieldReceived(&value) = true
		raw.RetainContents(s32.BridgeBroadcastCompletedAreaListFieldReceivedBytes(&value))
		*s32.BridgeBroadcastCompletedAreaListFieldReceivedLocation(&value) = raw.ContentLocation()
		out.rowBroadcastCompletedAreaList = &value
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
func (v WriteReplaceWarningResponseIEValue) encode() ([]byte, error) {
	return v.encodeFresh(false, nil)
}
func (v WriteReplaceWarningResponseIEValue) encodeFresh(fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
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
			return nil, fmt.Errorf("%s missing value", "WriteReplaceWarningResponseIEs.id-MessageIdentifier:")
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
			return nil, fmt.Errorf("%s missing value", "WriteReplaceWarningResponseIEs.id-SerialNumber:")
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
	case s00.ProtocolIEID(120):
		if v.rowBroadcastCompletedAreaList == nil {
			return nil, fmt.Errorf("%s missing value", "WriteReplaceWarningResponseIEs.id-BroadcastCompletedAreaList:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		candidate, err := s32.BridgeBroadcastCompletedAreaListMethodMarshalAPERBudget(v.rowBroadcastCompletedAreaList, budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	case s00.ProtocolIEID(58):
		if v.rowCriticalityDiagnostics == nil {
			return nil, fmt.Errorf("%s missing value", "WriteReplaceWarningResponseIEs.id-CriticalityDiagnostics:")
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
		return nil, fmt.Errorf("%s id %d has no value", "WriteReplaceWarningResponseIEValue:", v.id)
	}
}

type KillRequestIETable struct{}

func KillRequestIEs() KillRequestIETable { return KillRequestIETable{} }

// ID returns the ASN.1 object-set identity of KillRequestIETable.
func (KillRequestIETable) ID() s00.TableID {
	return func() s00.TableID {
		sealed := s00.TableID{}
		*s00.BridgeTableIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "KillRequestIEs"}
		return sealed
	}()
}

// Table returns the ASN.1 object-set table described by KillRequestIETable.
func (KillRequestIETable) Table() s00.KillRequestIEValueIETable {
	return func() s00.KillRequestIEValueIETable {
		sealed := s00.KillRequestIEValueIETable{}
		*s00.BridgeKillRequestIEValueIETableFieldBound(&sealed) = true
		return sealed
	}()
}
func (KillRequestIETable) infoMessageIdentifier() s00.FieldInfo {
	return s00.FieldInfo{Table: KillRequestIEs().ID(), ID: s00.ProtocolIEID(111), Criticality: s00.CriticalityReject, Presence: s00.PresenceMandatory, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "MessageIdentifier"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "KillRequestIEs", Row: "id-MessageIdentifier"}}}
}

// MessageIdentifier returns the typed binding for the MessageIdentifier row of KillRequestIETable.
func (t KillRequestIETable) MessageIdentifier() KillRequestMessageIdentifierIEBinding {
	return KillRequestMessageIdentifierIEBinding{info: t.infoMessageIdentifier(), codec: func() s01.MessageIdentifierValueCodec {
		sealed := s01.MessageIdentifierValueCodec{}
		*s01.BridgeMessageIdentifierValueCodecFieldPath(&sealed) = "MessageIdentifier"
		*s01.BridgeMessageIdentifierValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.MessageIdentifier, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s00.MessageIdentifier
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("MessageIdentifier")
			var zero KillRequestIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(111), raw)
			if err != nil {
				var empty s00.MessageIdentifier
				return empty, runtime.WrapDecodePath(err, "MessageIdentifier")
			}
			value, ok := decoded.AsMessageIdentifier()
			if !ok {
				var empty s00.MessageIdentifier
				return empty, fmt.Errorf("binding KillRequestIEs.id-MessageIdentifier: no selected value")
			}
			return *value, nil
		}
		*s01.BridgeMessageIdentifierValueCodecFieldEncode(&sealed) = func(value s00.MessageIdentifier, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (KillRequestIEValue{id: s00.ProtocolIEID(111), rowMessageIdentifier: &value}).encodeFresh(fresh, budget)
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
		inject: func(value s00.MessageIdentifier) KillRequestIEValue {
			return KillRequestIEValue{id: s00.ProtocolIEID(111), rowMessageIdentifier: &value}
		}, get: func(value *KillRequestIEValue) (*s00.MessageIdentifier, bool) { return value.AsMessageIdentifier() }}
}
func (KillRequestIETable) infoSerialNumber() s00.FieldInfo {
	return s00.FieldInfo{Table: KillRequestIEs().ID(), ID: s00.ProtocolIEID(112), Criticality: s00.CriticalityReject, Presence: s00.PresenceMandatory, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "SerialNumber"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "KillRequestIEs", Row: "id-SerialNumber"}}}
}

// SerialNumber returns the typed binding for the SerialNumber row of KillRequestIETable.
func (t KillRequestIETable) SerialNumber() KillRequestSerialNumberIEBinding {
	return KillRequestSerialNumberIEBinding{info: t.infoSerialNumber(), codec: func() s01.SerialNumberValueCodec {
		sealed := s01.SerialNumberValueCodec{}
		*s01.BridgeSerialNumberValueCodecFieldPath(&sealed) = "SerialNumber"
		*s01.BridgeSerialNumberValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.SerialNumber, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s00.SerialNumber
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("SerialNumber")
			var zero KillRequestIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(112), raw)
			if err != nil {
				var empty s00.SerialNumber
				return empty, runtime.WrapDecodePath(err, "SerialNumber")
			}
			value, ok := decoded.AsSerialNumber()
			if !ok {
				var empty s00.SerialNumber
				return empty, fmt.Errorf("binding KillRequestIEs.id-SerialNumber: no selected value")
			}
			return *value, nil
		}
		*s01.BridgeSerialNumberValueCodecFieldEncode(&sealed) = func(value s00.SerialNumber, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (KillRequestIEValue{id: s00.ProtocolIEID(112), rowSerialNumber: &value}).encodeFresh(fresh, budget)
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
		inject: func(value s00.SerialNumber) KillRequestIEValue {
			return KillRequestIEValue{id: s00.ProtocolIEID(112), rowSerialNumber: &value}
		}, get: func(value *KillRequestIEValue) (*s00.SerialNumber, bool) { return value.AsSerialNumber() }}
}
func (KillRequestIETable) infoWarningAreaList() s00.FieldInfo {
	return s00.FieldInfo{Table: KillRequestIEs().ID(), ID: s00.ProtocolIEID(113), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "WarningAreaList"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "KillRequestIEs", Row: "id-WarningAreaList"}}}
}

// WarningAreaList returns the typed binding for the WarningAreaList row of KillRequestIETable.
func (t KillRequestIETable) WarningAreaList() KillRequestWarningAreaListIEBinding {
	return KillRequestWarningAreaListIEBinding{info: t.infoWarningAreaList(), codec: WarningAreaListValueCodec{path: "WarningAreaList",
		decode: func(data []byte, options aper.DecodeState) (WarningAreaList, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty WarningAreaList
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("WarningAreaList")
			var zero KillRequestIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(113), raw)
			if err != nil {
				var empty WarningAreaList
				return empty, runtime.WrapDecodePath(err, "WarningAreaList")
			}
			value, ok := decoded.AsWarningAreaList()
			if !ok {
				var empty WarningAreaList
				return empty, fmt.Errorf("binding KillRequestIEs.id-WarningAreaList: no selected value")
			}
			return *value, nil
		},
		encode: func(value WarningAreaList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (KillRequestIEValue{id: s00.ProtocolIEID(113), rowWarningAreaList: &value}).encodeFresh(fresh, budget)
		}, capture: func(v WarningAreaList, options aper.DecodeState) (WarningAreaList, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeCaptureS1APWarningAreaList(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}, compare: func(v WarningAreaList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeCompareS1APWarningAreaList(&v, &s)
			s.End(f, root, false)
			return s.
				Plan(), s.BudgetValue()
		}, context: func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:WarningAreaList"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}(),
	}, inject: func(value WarningAreaList) KillRequestIEValue {
		return KillRequestIEValue{id: s00.ProtocolIEID(113), rowWarningAreaList: &value}
	}, get: func(value *KillRequestIEValue) (*WarningAreaList, bool) { return value.AsWarningAreaList() }}
}
func (KillRequestIETable) infoKillAllWarningMessages() s00.FieldInfo {
	return s00.FieldInfo{Table: KillRequestIEs().ID(), ID: s00.ProtocolIEID(191), Criticality: s00.CriticalityReject, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "KillAllWarningMessages"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "KillRequestIEs", Row: "id-KillAllWarningMessages"}}}
}

// KillAllWarningMessages returns the typed binding for the KillAllWarningMessages row of KillRequestIETable.
func (t KillRequestIETable) KillAllWarningMessages() KillRequestKillAllWarningMessagesIEBinding {
	return KillRequestKillAllWarningMessagesIEBinding{info: t.infoKillAllWarningMessages(), codec: func() s01.KillAllWarningMessagesValueCodec {
		sealed := s01.KillAllWarningMessagesValueCodec{}
		*s01.BridgeKillAllWarningMessagesValueCodecFieldPath(&sealed) = "KillAllWarningMessages"
		*s01.BridgeKillAllWarningMessagesValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.KillAllWarningMessages, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s00.KillAllWarningMessages
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("KillAllWarningMessages")
			var zero KillRequestIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(191), raw)
			if err != nil {
				var empty s00.KillAllWarningMessages
				return empty, runtime.WrapDecodePath(err, "KillAllWarningMessages")
			}
			value, ok := decoded.AsKillAllWarningMessages()
			if !ok {
				var empty s00.KillAllWarningMessages
				return empty, fmt.Errorf("binding KillRequestIEs.id-KillAllWarningMessages: no selected value")
			}
			return *value, nil
		}
		*s01.BridgeKillAllWarningMessagesValueCodecFieldEncode(&sealed) = func(value s00.KillAllWarningMessages, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (KillRequestIEValue{id: s00.ProtocolIEID(191), rowKillAllWarningMessages: &value}).encodeFresh(fresh, budget)
		}
		*s01.BridgeKillAllWarningMessagesValueCodecFieldCapture(&sealed) = func(v s00.KillAllWarningMessages, options aper.DecodeState) (s00.KillAllWarningMessages, aper.Snapshot,

		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s00.BridgeCaptureS1APKillAllWarningMessages(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s01.BridgeKillAllWarningMessagesValueCodecFieldCompare(&sealed) = func(v s00.KillAllWarningMessages, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s02.BridgeCompareS1APKillAllWarningMessages(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s01.BridgeKillAllWarningMessagesValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:KillAllWarningMessages"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s00.KillAllWarningMessages) KillRequestIEValue {
			return KillRequestIEValue{id: s00.ProtocolIEID(191), rowKillAllWarningMessages: &value}
		}, get: func(value *KillRequestIEValue) (*s00.KillAllWarningMessages, bool) {
			return value.AsKillAllWarningMessages()
		}}
}

// NewOpaque constructs an owned opaque field for an identifier without a typed row in KillRequestIETable.
func (t KillRequestIETable) NewOpaque(id s00.ProtocolIEID, criticality s00.Criticality, data []byte) (KillRequestIEField, error) {
	if id < 0 || id > 65535 || criticality < 0 || criticality > 2 {
		return KillRequestIEField{}, aper.OperationError(fmt.Errorf("invalid opaque IE selector or criticality"), "Opaque")
	}
	switch id {
	case s00.ProtocolIEID(111):
		return KillRequestIEField{}, aper.OperationError(fmt.Errorf("known IE id-MessageIdentifier requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(112):
		return KillRequestIEField{}, aper.OperationError(fmt.Errorf("known IE id-SerialNumber requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(113):
		return KillRequestIEField{}, aper.OperationError(fmt.Errorf("known IE id-WarningAreaList requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(191):
		return KillRequestIEField{}, aper.OperationError(fmt.Errorf("known IE id-KillAllWarningMessages requires its typed binding"), "Opaque")
	default:
		budget, err := aper.BuildBudget()
		if err != nil {
			return KillRequestIEField{}, aper.OperationError(err, "Opaque")
		}
		opaque, err := aper.BuildOpaqueOpenType(data, budget)
		if err != nil {
			return KillRequestIEField{}, aper.OperationError(err, "Opaque")
		}
		return KillRequestIEField{Id: id, Criticality: criticality, Value: KillRequestIEValue{id: id, opaque: opaque, isOpaque: true}}, aper.OperationError(nil, "Opaque")
	}
}

type KillResponseIETable struct{}

func KillResponseIEs() KillResponseIETable { return KillResponseIETable{} }

// ID returns the ASN.1 object-set identity of KillResponseIETable.
func (KillResponseIETable) ID() s00.TableID {
	return func() s00.TableID {
		sealed := s00.TableID{}
		*s00.BridgeTableIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "KillResponseIEs"}
		return sealed
	}()
}

// Table returns the ASN.1 object-set table described by KillResponseIETable.
func (KillResponseIETable) Table() s00.KillResponseIEValueIETable {
	return func() s00.KillResponseIEValueIETable {
		sealed := s00.KillResponseIEValueIETable{}
		*s00.BridgeKillResponseIEValueIETableFieldBound(&sealed) = true
		return sealed
	}()
}
func (KillResponseIETable) infoMessageIdentifier() s00.FieldInfo {
	return s00.FieldInfo{Table: KillResponseIEs().ID(), ID: s00.ProtocolIEID(111), Criticality: s00.CriticalityReject, Presence: s00.PresenceMandatory, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "MessageIdentifier"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "KillResponseIEs", Row: "id-MessageIdentifier"}}}
}

// MessageIdentifier returns the typed binding for the MessageIdentifier row of KillResponseIETable.
func (t KillResponseIETable) MessageIdentifier() KillResponseMessageIdentifierIEBinding {
	return KillResponseMessageIdentifierIEBinding{info: t.infoMessageIdentifier(), codec: func() s01.MessageIdentifierValueCodec {
		sealed := s01.MessageIdentifierValueCodec{}
		*s01.BridgeMessageIdentifierValueCodecFieldPath(&sealed) = "MessageIdentifier"
		*s01.BridgeMessageIdentifierValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.MessageIdentifier, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s00.MessageIdentifier
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("MessageIdentifier")
			var zero KillResponseIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(111), raw)
			if err != nil {
				var empty s00.MessageIdentifier
				return empty, runtime.WrapDecodePath(err, "MessageIdentifier")
			}
			value, ok := decoded.AsMessageIdentifier()
			if !ok {
				var empty s00.MessageIdentifier
				return empty, fmt.Errorf("binding KillResponseIEs.id-MessageIdentifier: no selected value")
			}
			return *value, nil
		}
		*s01.BridgeMessageIdentifierValueCodecFieldEncode(&sealed) = func(value s00.MessageIdentifier, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (KillResponseIEValue{id: s00.ProtocolIEID(111), rowMessageIdentifier: &value}).encodeFresh(fresh, budget)
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
		inject: func(value s00.MessageIdentifier) KillResponseIEValue {
			return KillResponseIEValue{id: s00.ProtocolIEID(111), rowMessageIdentifier: &value}
		}, get: func(value *KillResponseIEValue) (*s00.MessageIdentifier, bool) { return value.AsMessageIdentifier() }}
}
func (KillResponseIETable) infoSerialNumber() s00.FieldInfo {
	return s00.FieldInfo{Table: KillResponseIEs().ID(), ID: s00.ProtocolIEID(112), Criticality: s00.CriticalityReject, Presence: s00.PresenceMandatory, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "SerialNumber"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "KillResponseIEs", Row: "id-SerialNumber"}}}
}

// SerialNumber returns the typed binding for the SerialNumber row of KillResponseIETable.
func (t KillResponseIETable) SerialNumber() KillResponseSerialNumberIEBinding {
	return KillResponseSerialNumberIEBinding{info: t.infoSerialNumber(), codec: func() s01.SerialNumberValueCodec {
		sealed := s01.SerialNumberValueCodec{}
		*s01.BridgeSerialNumberValueCodecFieldPath(&sealed) = "SerialNumber"
		*s01.BridgeSerialNumberValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.SerialNumber, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s00.SerialNumber
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("SerialNumber")
			var zero KillResponseIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(112), raw)
			if err != nil {
				var empty s00.SerialNumber
				return empty, runtime.WrapDecodePath(err, "SerialNumber")
			}
			value, ok := decoded.AsSerialNumber()
			if !ok {
				var empty s00.SerialNumber
				return empty, fmt.Errorf("binding KillResponseIEs.id-SerialNumber: no selected value")
			}
			return *value, nil
		}
		*s01.BridgeSerialNumberValueCodecFieldEncode(&sealed) = func(value s00.SerialNumber, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (KillResponseIEValue{id: s00.ProtocolIEID(112), rowSerialNumber: &value}).encodeFresh(fresh, budget)
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
		inject: func(value s00.SerialNumber) KillResponseIEValue {
			return KillResponseIEValue{id: s00.ProtocolIEID(112), rowSerialNumber: &value}
		}, get: func(value *KillResponseIEValue) (*s00.SerialNumber, bool) { return value.AsSerialNumber() }}
}
func (KillResponseIETable) infoBroadcastCancelledAreaList() s00.FieldInfo {
	return s00.FieldInfo{Table: KillResponseIEs().ID(), ID: s00.ProtocolIEID(141), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "BroadcastCancelledAreaList"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "KillResponseIEs", Row: "id-BroadcastCancelledAreaList"}}}
}

// BroadcastCancelledAreaList returns the typed binding for the BroadcastCancelledAreaList row of KillResponseIETable.
func (t KillResponseIETable) BroadcastCancelledAreaList() KillResponseBroadcastCancelledAreaListIEBinding {
	return KillResponseBroadcastCancelledAreaListIEBinding{info: t.infoBroadcastCancelledAreaList(), codec: BroadcastCancelledAreaListValueCodec{path: "BroadcastCancelledAreaList",
		decode: func(data []byte, options aper.DecodeState) (BroadcastCancelledAreaList, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty BroadcastCancelledAreaList
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("BroadcastCancelledAreaList")
			var zero KillResponseIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(141), raw)
			if err != nil {
				var empty BroadcastCancelledAreaList
				return empty, runtime.WrapDecodePath(err, "BroadcastCancelledAreaList")
			}
			value, ok := decoded.AsBroadcastCancelledAreaList()
			if !ok {
				var empty BroadcastCancelledAreaList
				return empty, fmt.Errorf("binding KillResponseIEs.id-BroadcastCancelledAreaList: no selected value")
			}
			return *value, nil
		},
		encode: func(value BroadcastCancelledAreaList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (KillResponseIEValue{id: s00.ProtocolIEID(141), rowBroadcastCancelledAreaList: &value}).encodeFresh(fresh, budget)
		}, capture: func(v BroadcastCancelledAreaList, options aper.DecodeState) (BroadcastCancelledAreaList, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeCaptureS1APBroadcastCancelledAreaList(&v, &s)
			var root aper.Snapshot
			s.End(
				f, &root, false)
			return v, root
		}, compare: func(v BroadcastCancelledAreaList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeCompareS1APBroadcastCancelledAreaList(&v, &s)
			s.End(f,
				root,

				false)
			return s.Plan(), s.BudgetValue()
		}, context: func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:BroadcastCancelledAreaList"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}(),
	}, inject: func(value BroadcastCancelledAreaList) KillResponseIEValue {
		return KillResponseIEValue{id: s00.ProtocolIEID(141), rowBroadcastCancelledAreaList: &value}
	}, get: func(value *KillResponseIEValue) (*BroadcastCancelledAreaList, bool) {
		return value.AsBroadcastCancelledAreaList()
	}}
}
func (KillResponseIETable) infoCriticalityDiagnostics() s00.FieldInfo {
	return s00.FieldInfo{Table: KillResponseIEs().ID(), ID: s00.ProtocolIEID(58), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "CriticalityDiagnostics"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "KillResponseIEs", Row: "id-CriticalityDiagnostics"}}}
}

// CriticalityDiagnostics returns the typed binding for the CriticalityDiagnostics row of KillResponseIETable.
func (t KillResponseIETable) CriticalityDiagnostics() KillResponseCriticalityDiagnosticsIEBinding {
	return KillResponseCriticalityDiagnosticsIEBinding{info: t.infoCriticalityDiagnostics(), codec: func() s22.CriticalityDiagnosticsValueCodec {
		sealed := s22.CriticalityDiagnosticsValueCodec{}
		*s22.BridgeCriticalityDiagnosticsValueCodecFieldPath(&sealed) = "CriticalityDiagnostics"
		*s22.BridgeCriticalityDiagnosticsValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s22.CriticalityDiagnostics, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s22.CriticalityDiagnostics
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("CriticalityDiagnostics")
			var zero KillResponseIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(58), raw)
			if err != nil {
				var empty s22.CriticalityDiagnostics
				return empty, runtime.WrapDecodePath(err, "CriticalityDiagnostics")
			}
			value, ok := decoded.AsCriticalityDiagnostics()
			if !ok {
				var empty s22.CriticalityDiagnostics
				return empty, fmt.Errorf("binding KillResponseIEs.id-CriticalityDiagnostics: no selected value")
			}
			return *value, nil
		}
		*s22.BridgeCriticalityDiagnosticsValueCodecFieldEncode(&sealed) = func(value s22.CriticalityDiagnostics, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (KillResponseIEValue{id: s00.ProtocolIEID(58), rowCriticalityDiagnostics: &value}).encodeFresh(fresh, budget)
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
		inject: func(value s22.CriticalityDiagnostics) KillResponseIEValue {
			return KillResponseIEValue{id: s00.ProtocolIEID(58), rowCriticalityDiagnostics: &value}
		}, get: func(value *KillResponseIEValue) (*s22.CriticalityDiagnostics, bool) {
			return value.AsCriticalityDiagnostics()
		}}
}

// NewOpaque constructs an owned opaque field for an identifier without a typed row in KillResponseIETable.
func (t KillResponseIETable) NewOpaque(id s00.ProtocolIEID, criticality s00.Criticality, data []byte) (KillResponseIEField, error) {
	if id < 0 || id > 65535 || criticality < 0 || criticality > 2 {
		return KillResponseIEField{}, aper.OperationError(fmt.Errorf("invalid opaque IE selector or criticality"), "Opaque")
	}
	switch id {
	case s00.ProtocolIEID(111):
		return KillResponseIEField{}, aper.OperationError(fmt.Errorf("known IE id-MessageIdentifier requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(112):
		return KillResponseIEField{}, aper.OperationError(fmt.Errorf("known IE id-SerialNumber requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(141):
		return KillResponseIEField{}, aper.OperationError(fmt.Errorf("known IE id-BroadcastCancelledAreaList requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(58):
		return KillResponseIEField{}, aper.OperationError(fmt.Errorf("known IE id-CriticalityDiagnostics requires its typed binding"), "Opaque")
	default:
		budget, err := aper.BuildBudget()
		if err != nil {
			return KillResponseIEField{}, aper.OperationError(err, "Opaque")
		}
		opaque, err := aper.BuildOpaqueOpenType(data, budget)
		if err != nil {
			return KillResponseIEField{}, aper.OperationError(err, "Opaque")
		}
		return KillResponseIEField{Id: id, Criticality: criticality, Value: KillResponseIEValue{id: id, opaque: opaque, isOpaque: true}}, aper.OperationError(nil, "Opaque")
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
			raw.BudgetBuffer().EnterComponent("MessageIdentifier")
			var zero WriteReplaceWarningRequestIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(111), raw)
			if err != nil {
				var empty s00.MessageIdentifier
				return empty, runtime.WrapDecodePath(err, "MessageIdentifier")
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
			raw.BudgetBuffer().EnterComponent("SerialNumber")
			var zero WriteReplaceWarningRequestIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(112), raw)
			if err != nil {
				var empty s00.SerialNumber
				return empty, runtime.WrapDecodePath(err, "SerialNumber")
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
	return WriteReplaceWarningRequestWarningAreaListIEBinding{info: t.infoWarningAreaList(), codec: WarningAreaListValueCodec{path: "WarningAreaList",
		decode: func(data []byte, options aper.DecodeState) (WarningAreaList, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty WarningAreaList
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("WarningAreaList")
			var zero WriteReplaceWarningRequestIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(113), raw)
			if err != nil {
				var empty WarningAreaList
				return empty, runtime.WrapDecodePath(err, "WarningAreaList")
			}
			value, ok := decoded.AsWarningAreaList()
			if !ok {
				var empty WarningAreaList
				return empty, fmt.Errorf("binding WriteReplaceWarningRequestIEs.id-WarningAreaList: no selected value")
			}
			return *value, nil
		},
		encode: func(value WarningAreaList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (WriteReplaceWarningRequestIEValue{id: s00.ProtocolIEID(113), rowWarningAreaList: &value}).encodeFresh(fresh, budget)
		}, capture: func(v WarningAreaList, options aper.DecodeState) (WarningAreaList, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeCaptureS1APWarningAreaList(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}, compare: func(v WarningAreaList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeCompareS1APWarningAreaList(&v, &s)
			s.End(f, root, false)
			return s.
				Plan(), s.BudgetValue()
		}, context: func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:WarningAreaList"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}(),
	}, inject: func(value WarningAreaList) WriteReplaceWarningRequestIEValue {
		return WriteReplaceWarningRequestIEValue{id: s00.ProtocolIEID(113), rowWarningAreaList: &value}
	}, get: func(value *WriteReplaceWarningRequestIEValue) (*WarningAreaList, bool) {
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
			raw.BudgetBuffer().EnterComponent("RepetitionPeriod")
			var zero WriteReplaceWarningRequestIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(114), raw)
			if err != nil {
				var empty s00.RepetitionPeriod
				return empty, runtime.WrapDecodePath(err, "RepetitionPeriod")
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
			raw.BudgetBuffer().EnterComponent("ExtendedRepetitionPeriod")
			var zero WriteReplaceWarningRequestIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(144), raw)
			if err != nil {
				var empty s00.ExtendedRepetitionPeriod
				return empty, runtime.WrapDecodePath(err, "ExtendedRepetitionPeriod")
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
			raw.BudgetBuffer().EnterComponent("NumberofBroadcastRequest")
			var zero WriteReplaceWarningRequestIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(115), raw)
			if err != nil {
				var empty s00.NumberofBroadcastRequest
				return empty, runtime.WrapDecodePath(err, "NumberofBroadcastRequest")
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
			raw.BudgetBuffer().EnterComponent("WarningType")
			var zero WriteReplaceWarningRequestIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(116), raw)
			if err != nil {
				var empty s00.WarningType
				return empty, runtime.WrapDecodePath(err, "WarningType")
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
			raw.BudgetBuffer().EnterComponent("WarningSecurityInfo")
			var zero WriteReplaceWarningRequestIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(117), raw)
			if err != nil {
				var empty s00.WarningSecurityInfo
				return empty, runtime.WrapDecodePath(err, "WarningSecurityInfo")
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
			raw.BudgetBuffer().EnterComponent("DataCodingScheme")
			var zero WriteReplaceWarningRequestIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(118), raw)
			if err != nil {
				var empty s00.DataCodingScheme
				return empty, runtime.WrapDecodePath(err, "DataCodingScheme")
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
			raw.BudgetBuffer().EnterComponent("WarningMessageContents")
			var zero WriteReplaceWarningRequestIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(119), raw)
			if err != nil {
				var empty s00.WarningMessageContents
				return empty, runtime.WrapDecodePath(err, "WarningMessageContents")
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
			raw.BudgetBuffer().EnterComponent("ConcurrentWarningMessageIndicator")
			var zero WriteReplaceWarningRequestIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(142), raw)
			if err != nil {
				var empty s00.ConcurrentWarningMessageIndicator
				return empty, runtime.WrapDecodePath(err, "ConcurrentWarningMessageIndicator")
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
			raw.BudgetBuffer().EnterComponent("WarningAreaCoordinates")
			var zero WriteReplaceWarningRequestIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(286), raw)
			if err != nil {
				var empty s00.WarningAreaCoordinates
				return empty, runtime.WrapDecodePath(err, "WarningAreaCoordinates")
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

type WriteReplaceWarningResponseIETable struct{}

func WriteReplaceWarningResponseIEs() WriteReplaceWarningResponseIETable {
	return WriteReplaceWarningResponseIETable{}
}

// ID returns the ASN.1 object-set identity of WriteReplaceWarningResponseIETable.
func (WriteReplaceWarningResponseIETable) ID() s00.TableID {
	return func() s00.TableID {
		sealed := s00.TableID{}
		*s00.BridgeTableIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "WriteReplaceWarningResponseIEs"}
		return sealed
	}()
}

// Table returns the ASN.1 object-set table described by WriteReplaceWarningResponseIETable.
func (WriteReplaceWarningResponseIETable) Table() s00.WriteReplaceWarningResponseIEValueIETable {
	return func() s00.WriteReplaceWarningResponseIEValueIETable {
		sealed := s00.WriteReplaceWarningResponseIEValueIETable{}
		*s00.BridgeWriteReplaceWarningResponseIEValueIETableFieldBound(&sealed) = true
		return sealed
	}()
}
func (WriteReplaceWarningResponseIETable) infoMessageIdentifier() s00.FieldInfo {
	return s00.FieldInfo{Table: WriteReplaceWarningResponseIEs().ID(), ID: s00.ProtocolIEID(111), Criticality: s00.CriticalityReject, Presence: s00.PresenceMandatory, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "MessageIdentifier"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "WriteReplaceWarningResponseIEs", Row: "id-MessageIdentifier"}}}
}

// MessageIdentifier returns the typed binding for the MessageIdentifier row of WriteReplaceWarningResponseIETable.
func (t WriteReplaceWarningResponseIETable) MessageIdentifier() WriteReplaceWarningResponseMessageIdentifierIEBinding {
	return WriteReplaceWarningResponseMessageIdentifierIEBinding{info: t.infoMessageIdentifier(), codec: func() s01.MessageIdentifierValueCodec {
		sealed := s01.MessageIdentifierValueCodec{}
		*s01.BridgeMessageIdentifierValueCodecFieldPath(&sealed) = "MessageIdentifier"
		*s01.BridgeMessageIdentifierValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.MessageIdentifier, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s00.MessageIdentifier
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("MessageIdentifier")
			var zero WriteReplaceWarningResponseIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(111), raw)
			if err != nil {
				var empty s00.MessageIdentifier
				return empty, runtime.WrapDecodePath(err, "MessageIdentifier")
			}
			value, ok := decoded.AsMessageIdentifier()
			if !ok {
				var empty s00.MessageIdentifier
				return empty, fmt.Errorf("binding WriteReplaceWarningResponseIEs.id-MessageIdentifier: no selected value")
			}
			return *value, nil
		}
		*s01.BridgeMessageIdentifierValueCodecFieldEncode(&sealed) = func(value s00.MessageIdentifier, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (WriteReplaceWarningResponseIEValue{id: s00.ProtocolIEID(111), rowMessageIdentifier: &value}).encodeFresh(fresh, budget)
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
		inject: func(value s00.MessageIdentifier) WriteReplaceWarningResponseIEValue {
			return WriteReplaceWarningResponseIEValue{id: s00.ProtocolIEID(111), rowMessageIdentifier: &value}
		}, get: func(value *WriteReplaceWarningResponseIEValue) (*s00.MessageIdentifier, bool) {
			return value.AsMessageIdentifier()
		}}
}
func (WriteReplaceWarningResponseIETable) infoSerialNumber() s00.FieldInfo {
	return s00.FieldInfo{Table: WriteReplaceWarningResponseIEs().ID(), ID: s00.ProtocolIEID(112), Criticality: s00.CriticalityReject, Presence: s00.PresenceMandatory, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "SerialNumber"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "WriteReplaceWarningResponseIEs", Row: "id-SerialNumber"}}}
}

// SerialNumber returns the typed binding for the SerialNumber row of WriteReplaceWarningResponseIETable.
func (t WriteReplaceWarningResponseIETable) SerialNumber() WriteReplaceWarningResponseSerialNumberIEBinding {
	return WriteReplaceWarningResponseSerialNumberIEBinding{info: t.infoSerialNumber(), codec: func() s01.SerialNumberValueCodec {
		sealed := s01.SerialNumberValueCodec{}
		*s01.BridgeSerialNumberValueCodecFieldPath(&sealed) = "SerialNumber"
		*s01.BridgeSerialNumberValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.SerialNumber, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s00.SerialNumber
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("SerialNumber")
			var zero WriteReplaceWarningResponseIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(112), raw)
			if err != nil {
				var empty s00.SerialNumber
				return empty, runtime.WrapDecodePath(err, "SerialNumber")
			}
			value, ok := decoded.AsSerialNumber()
			if !ok {
				var empty s00.SerialNumber
				return empty, fmt.Errorf("binding WriteReplaceWarningResponseIEs.id-SerialNumber: no selected value")
			}
			return *value, nil
		}
		*s01.BridgeSerialNumberValueCodecFieldEncode(&sealed) = func(value s00.SerialNumber, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (WriteReplaceWarningResponseIEValue{id: s00.ProtocolIEID(112), rowSerialNumber: &value}).encodeFresh(fresh, budget)
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
		inject: func(value s00.SerialNumber) WriteReplaceWarningResponseIEValue {
			return WriteReplaceWarningResponseIEValue{id: s00.ProtocolIEID(112), rowSerialNumber: &value}
		}, get: func(value *WriteReplaceWarningResponseIEValue) (*s00.SerialNumber, bool) {
			return value.AsSerialNumber()
		}}
}
func (WriteReplaceWarningResponseIETable) infoBroadcastCompletedAreaList() s00.FieldInfo {
	return s00.FieldInfo{Table: WriteReplaceWarningResponseIEs().ID(), ID: s00.ProtocolIEID(120), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "BroadcastCompletedAreaList"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "WriteReplaceWarningResponseIEs", Row: "id-BroadcastCompletedAreaList"}}}
}

// BroadcastCompletedAreaList returns the typed binding for the BroadcastCompletedAreaList row of WriteReplaceWarningResponseIETable.
func (t WriteReplaceWarningResponseIETable) BroadcastCompletedAreaList() WriteReplaceWarningResponseBroadcastCompletedAreaListIEBinding {
	return WriteReplaceWarningResponseBroadcastCompletedAreaListIEBinding{info: t.infoBroadcastCompletedAreaList(), codec: func() s32.BroadcastCompletedAreaListValueCodec {
		sealed := s32.BroadcastCompletedAreaListValueCodec{}
		*s32.BridgeBroadcastCompletedAreaListValueCodecFieldPath(&sealed) = "BroadcastCompletedAreaList"
		*s32.BridgeBroadcastCompletedAreaListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s32.BroadcastCompletedAreaList, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s32.BroadcastCompletedAreaList
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("BroadcastCompletedAreaList")
			var zero WriteReplaceWarningResponseIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(120), raw)
			if err != nil {
				var empty s32.BroadcastCompletedAreaList
				return empty, runtime.WrapDecodePath(err, "BroadcastCompletedAreaList")
			}
			value, ok := decoded.AsBroadcastCompletedAreaList()
			if !ok {
				var empty s32.BroadcastCompletedAreaList
				return empty, fmt.Errorf("binding WriteReplaceWarningResponseIEs.id-BroadcastCompletedAreaList: no selected value")
			}
			return *value, nil
		}
		*s32.BridgeBroadcastCompletedAreaListValueCodecFieldEncode(&sealed) = func(value s32.BroadcastCompletedAreaList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (WriteReplaceWarningResponseIEValue{id: s00.ProtocolIEID(120), rowBroadcastCompletedAreaList: &value}).encodeFresh(fresh, budget)
		}
		*s32.BridgeBroadcastCompletedAreaListValueCodecFieldCapture(&sealed) = func(v s32.BroadcastCompletedAreaList, options aper.DecodeState) (s32.BroadcastCompletedAreaList, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s32.BridgeCaptureS1APBroadcastCompletedAreaList(&v, &s)
			var root aper.Snapshot
			s.End(
				f, &root, false)
			return v, root
		}
		*s32.BridgeBroadcastCompletedAreaListValueCodecFieldCompare(&sealed) = func(v s32.BroadcastCompletedAreaList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s32.BridgeCompareS1APBroadcastCompletedAreaList(&v, &s)
			s.End(f,
				root,

				false)
			return s.Plan(), s.BudgetValue()
		}
		*s32.BridgeBroadcastCompletedAreaListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:BroadcastCompletedAreaList"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s32.BroadcastCompletedAreaList) WriteReplaceWarningResponseIEValue {
			return WriteReplaceWarningResponseIEValue{id: s00.ProtocolIEID(120), rowBroadcastCompletedAreaList: &value}
		}, get: func(value *WriteReplaceWarningResponseIEValue) (*s32.BroadcastCompletedAreaList, bool) {
			return value.AsBroadcastCompletedAreaList()
		}}
}
func (WriteReplaceWarningResponseIETable) infoCriticalityDiagnostics() s00.FieldInfo {
	return s00.FieldInfo{Table: WriteReplaceWarningResponseIEs().ID(), ID: s00.ProtocolIEID(58), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "CriticalityDiagnostics"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "WriteReplaceWarningResponseIEs", Row: "id-CriticalityDiagnostics"}}}
}

// CriticalityDiagnostics returns the typed binding for the CriticalityDiagnostics row of WriteReplaceWarningResponseIETable.
func (t WriteReplaceWarningResponseIETable) CriticalityDiagnostics() WriteReplaceWarningResponseCriticalityDiagnosticsIEBinding {
	return WriteReplaceWarningResponseCriticalityDiagnosticsIEBinding{info: t.infoCriticalityDiagnostics(), codec: func() s22.CriticalityDiagnosticsValueCodec {
		sealed := s22.CriticalityDiagnosticsValueCodec{}
		*s22.BridgeCriticalityDiagnosticsValueCodecFieldPath(&sealed) = "CriticalityDiagnostics"
		*s22.BridgeCriticalityDiagnosticsValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s22.CriticalityDiagnostics, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s22.CriticalityDiagnostics
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("CriticalityDiagnostics")
			var zero WriteReplaceWarningResponseIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(58), raw)
			if err != nil {
				var empty s22.CriticalityDiagnostics
				return empty, runtime.WrapDecodePath(err, "CriticalityDiagnostics")
			}
			value, ok := decoded.AsCriticalityDiagnostics()
			if !ok {
				var empty s22.CriticalityDiagnostics
				return empty, fmt.Errorf("binding WriteReplaceWarningResponseIEs.id-CriticalityDiagnostics: no selected value")
			}
			return *value, nil
		}
		*s22.BridgeCriticalityDiagnosticsValueCodecFieldEncode(&sealed) = func(value s22.CriticalityDiagnostics, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (WriteReplaceWarningResponseIEValue{id: s00.ProtocolIEID(58), rowCriticalityDiagnostics: &value}).encodeFresh(fresh, budget)
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
		inject: func(value s22.CriticalityDiagnostics) WriteReplaceWarningResponseIEValue {
			return WriteReplaceWarningResponseIEValue{id: s00.ProtocolIEID(58), rowCriticalityDiagnostics: &value}
		}, get: func(value *WriteReplaceWarningResponseIEValue) (*s22.CriticalityDiagnostics, bool) {
			return value.AsCriticalityDiagnostics()
		}}
}

// NewOpaque constructs an owned opaque field for an identifier without a typed row in WriteReplaceWarningResponseIETable.
func (t WriteReplaceWarningResponseIETable) NewOpaque(id s00.ProtocolIEID, criticality s00.Criticality, data []byte) (WriteReplaceWarningResponseIEField, error) {
	if id < 0 || id > 65535 || criticality < 0 || criticality > 2 {
		return WriteReplaceWarningResponseIEField{}, aper.OperationError(fmt.Errorf("invalid opaque IE selector or criticality"), "Opaque")
	}
	switch id {
	case s00.ProtocolIEID(111):
		return WriteReplaceWarningResponseIEField{}, aper.OperationError(fmt.Errorf("known IE id-MessageIdentifier requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(112):
		return WriteReplaceWarningResponseIEField{}, aper.OperationError(fmt.Errorf("known IE id-SerialNumber requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(120):
		return WriteReplaceWarningResponseIEField{}, aper.OperationError(fmt.Errorf("known IE id-BroadcastCompletedAreaList requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(58):
		return WriteReplaceWarningResponseIEField{}, aper.OperationError(fmt.Errorf("known IE id-CriticalityDiagnostics requires its typed binding"), "Opaque")
	default:
		budget, err := aper.BuildBudget()
		if err != nil {
			return WriteReplaceWarningResponseIEField{}, aper.OperationError(err, "Opaque")
		}
		opaque, err := aper.BuildOpaqueOpenType(data, budget)
		if err != nil {
			return WriteReplaceWarningResponseIEField{}, aper.OperationError(err, "Opaque")
		}
		return WriteReplaceWarningResponseIEField{Id: id, Criticality: criticality, Value: WriteReplaceWarningResponseIEValue{id: id, opaque: opaque, isOpaque: true}}, aper.OperationError(nil, "Opaque")
	}
}

// AreaScopeOfMDTCodec binds the complete source value type.
func AreaScopeOfMDTCodec() AreaScopeOfMDTValueCodec {
	return AreaScopeOfMDTValueCodec{path: "AreaScopeOfMDT", decode: func(data []byte, options aper.DecodeState) (AreaScopeOfMDT, error) {
		var value AreaScopeOfMDT
		if err := value.unmarshalAPERWithOptions(data, options); err != nil {
			return AreaScopeOfMDT{}, err
		}
		value.received = true
		value.receivedAbsolute = true
		value.receivedBytes = aper.OriginalWire(data)
		return value, nil
	}, encode: func(value AreaScopeOfMDT, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return (&value).marshalAPERBudget(budget, fresh)
	}, capture: func(v AreaScopeOfMDT, options aper.DecodeState) (AreaScopeOfMDT, aper.Snapshot) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeCaptureS1APAreaScopeOfMDT(&v, &s)
		var root aper.Snapshot
		s.End(f, &root, false)
		return v, root
	}, compare: func(v AreaScopeOfMDT, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		BridgeCompareS1APAreaScopeOfMDT(&v, &s)
		s.End(f, root, false)
		return s.Plan(), s.BudgetValue()
	}, context: func() s00.BridgeCodecContext {
		sealed := s00.BridgeCodecContext{}
		*s00.BridgecodecContextFieldSource(&sealed) = "source-value:AreaScopeOfMDT"
		*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
		return sealed
	}(),
	}
}

// AreaScopeOfQMCCodec binds the complete source value type.
func AreaScopeOfQMCCodec() AreaScopeOfQMCValueCodec {
	return AreaScopeOfQMCValueCodec{path: "AreaScopeOfQMC", decode: func(data []byte, options aper.DecodeState) (AreaScopeOfQMC, error) {
		var value AreaScopeOfQMC
		if err := value.unmarshalAPERWithOptions(data, options); err != nil {
			return AreaScopeOfQMC{}, err
		}
		value.received = true
		value.receivedAbsolute = true
		value.receivedBytes = aper.OriginalWire(data)
		return value, nil
	}, encode: func(value AreaScopeOfQMC, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return (&value).marshalAPERBudget(budget, fresh)
	}, capture: func(v AreaScopeOfQMC, options aper.DecodeState) (AreaScopeOfQMC, aper.Snapshot) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeCaptureS1APAreaScopeOfQMC(&v, &s)
		var root aper.Snapshot
		s.End(f, &root, false)
		return v, root
	}, compare: func(v AreaScopeOfQMC, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		BridgeCompareS1APAreaScopeOfQMC(&v, &s)
		s.End(f, root, false)
		return s.Plan(), s.BudgetValue()
	}, context: func() s00.BridgeCodecContext {
		sealed := s00.BridgeCodecContext{}
		*s00.BridgecodecContextFieldSource(&sealed) = "source-value:AreaScopeOfQMC"
		*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
		return sealed
	}(),
	}
}

// BroadcastCancelledAreaListCodec binds the complete APER value type.
func BroadcastCancelledAreaListCodec() BroadcastCancelledAreaListValueCodec {
	return KillResponseIEs().BroadcastCancelledAreaList().Codec()
}

// BroadcastCompletedAreaListCodec binds the complete APER value type.
func BroadcastCompletedAreaListCodec() s32.BroadcastCompletedAreaListValueCodec {
	return WriteReplaceWarningResponseIEs().BroadcastCompletedAreaList().Codec()
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

// KillAllWarningMessagesCodec binds the complete APER value type.
func KillAllWarningMessagesCodec() s01.KillAllWarningMessagesValueCodec {
	return KillRequestIEs().KillAllWarningMessages().Codec()
}

// MessageIdentifierCodec binds the complete APER value type.
func MessageIdentifierCodec() s01.MessageIdentifierValueCodec {
	return KillRequestIEs().MessageIdentifier().Codec()
}

// NumberofBroadcastRequestCodec binds the complete APER value type.
func NumberofBroadcastRequestCodec() s01.NumberofBroadcastRequestValueCodec {
	return WriteReplaceWarningRequestIEs().NumberofBroadcastRequest().Codec()
}

// RepetitionPeriodCodec binds the complete APER value type.
func RepetitionPeriodCodec() s01.RepetitionPeriodValueCodec {
	return WriteReplaceWarningRequestIEs().RepetitionPeriod().Codec()
}

// SerialNumberCodec binds the complete APER value type.
func SerialNumberCodec() s01.SerialNumberValueCodec { return KillRequestIEs().SerialNumber().Codec() }

// TAIBasedMDTCodec binds the complete source value type.
func TAIBasedMDTCodec() TAIBasedMDTValueCodec {
	return TAIBasedMDTValueCodec{path: "TAIBasedMDT", decode: func(data []byte, options aper.DecodeState) (TAIBasedMDT, error) {
		var value TAIBasedMDT
		if err := value.unmarshalAPERWithOptions(data, options); err != nil {
			return TAIBasedMDT{}, err
		}
		value.received = true
		value.receivedAbsolute = true
		value.receivedBytes = aper.OriginalWire(data)
		return value, nil
	}, encode: func(value TAIBasedMDT, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return (&value).marshalAPERBudget(budget, fresh)
	}, capture: func(v TAIBasedMDT, options aper.DecodeState) (TAIBasedMDT, aper.Snapshot) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeCaptureS1APTAIBasedMDT(&v, &s)
		var root aper.Snapshot

		s.End(f, &root, false)
		return v, root
	}, compare: func(v TAIBasedMDT, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		BridgeCompareS1APTAIBasedMDT(&v, &s)
		s.End(f, root, false)
		return s.Plan(), s.
			BudgetValue()
	}, context: func() s00.BridgeCodecContext {
		sealed := s00.BridgeCodecContext{}
		*s00.BridgecodecContextFieldSource(&sealed) = "source-value:TAIBasedMDT"
		*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
		return sealed
	}(),
	}
}

// TAIBasedQMCCodec binds the complete source value type.
func TAIBasedQMCCodec() TAIBasedQMCValueCodec {
	return TAIBasedQMCValueCodec{path: "TAIBasedQMC", decode: func(data []byte, options aper.DecodeState) (TAIBasedQMC, error) {
		var value TAIBasedQMC
		if err := value.unmarshalAPERWithOptions(data, options); err != nil {
			return TAIBasedQMC{}, err
		}
		value.received = true
		value.receivedAbsolute = true
		value.receivedBytes = aper.OriginalWire(data)
		return value, nil
	}, encode: func(value TAIBasedQMC, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return (&value).marshalAPERBudget(budget, fresh)
	}, capture: func(v TAIBasedQMC, options aper.DecodeState) (TAIBasedQMC, aper.Snapshot) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeCaptureS1APTAIBasedQMC(&v, &s)
		var root aper.Snapshot

		s.End(f, &root, false)
		return v, root
	}, compare: func(v TAIBasedQMC, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		BridgeCompareS1APTAIBasedQMC(&v, &s)
		s.End(f, root, false)
		return s.Plan(), s.
			BudgetValue()
	}, context: func() s00.BridgeCodecContext {
		sealed := s00.BridgeCodecContext{}
		*s00.BridgecodecContextFieldSource(&sealed) = "source-value:TAIBasedQMC"
		*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
		return sealed
	}(),
	}
}

// WarningAreaCoordinatesCodec binds the complete APER value type.
func WarningAreaCoordinatesCodec() s02.WarningAreaCoordinatesValueCodec {
	return WriteReplaceWarningRequestIEs().WarningAreaCoordinates().Codec()
}

// WarningAreaListCodec binds the complete APER value type.
func WarningAreaListCodec() WarningAreaListValueCodec {
	return KillRequestIEs().WarningAreaList().Codec()
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
func BridgeAreaScopeOfMDTAPERValueFieldContext(v *AreaScopeOfMDTAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeAreaScopeOfMDTAPERValueFieldReceived(v *AreaScopeOfMDTAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeAreaScopeOfMDTAPERValueFieldReplay(v *AreaScopeOfMDTAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeAreaScopeOfMDTAPERValueFieldWithoutReplay(v *AreaScopeOfMDTAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeAreaScopeOfMDTFieldPerOpenTypePadding(v *AreaScopeOfMDT) *aper.CompletePadding {
	return &v.perOpenTypePadding
}
func BridgeAreaScopeOfMDTFieldPerPadding(v *AreaScopeOfMDT) *aper.CompletePadding {
	return &v.perPadding
}
func BridgeAreaScopeOfMDTFieldReceived(v *AreaScopeOfMDT) *bool         { return &v.received }
func BridgeAreaScopeOfMDTFieldReceivedAbsolute(v *AreaScopeOfMDT) *bool { return &v.receivedAbsolute }
func BridgeAreaScopeOfMDTFieldReceivedBytes(v *AreaScopeOfMDT) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeAreaScopeOfMDTFieldReceivedLocation(v *AreaScopeOfMDT) *aper.Location {
	return &v.receivedLocation
}
func BridgeAreaScopeOfMDTFieldReplay(v *AreaScopeOfMDT) *aper.Snapshot { return &v.replay }
func BridgeAreaScopeOfMDTFieldStream(v *AreaScopeOfMDT) *aper.WireSpan { return &v.stream }
func BridgeAreaScopeOfMDTFieldWithoutReplay(v *AreaScopeOfMDT) *bool   { return &v.withoutReplay }
func BridgeAreaScopeOfMDTMethodMarshalAPERBudget(v *AreaScopeOfMDT, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeAreaScopeOfMDTMethodMarshalAPERBudgetValue(v *AreaScopeOfMDT, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudgetValue(a0, a1)
}
func BridgeAreaScopeOfMDTMethodMarshalAPERChanged(v *AreaScopeOfMDT, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeAreaScopeOfMDTMethodMarshalAPERChangedValue(v *AreaScopeOfMDT, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeAreaScopeOfMDTMethodMarshalAPERLegacy(v *AreaScopeOfMDT) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeAreaScopeOfMDTMethodMarshalAPERNewValue(v *AreaScopeOfMDT, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERNewValue(a0, a1)
}
func BridgeAreaScopeOfMDTMethodMarshalAPERPlanned(v *AreaScopeOfMDT, a0 *aper.DecodeBudget, a1 bool, a2 *aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1, a2)
}
func BridgeAreaScopeOfMDTMethodMarshalAPERTo(v *AreaScopeOfMDT, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeAreaScopeOfMDTMethodUnmarshalAPERFrom(v *AreaScopeOfMDT, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeAreaScopeOfMDTMethodUnmarshalAPERLegacy(v *AreaScopeOfMDT, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeAreaScopeOfMDTMethodUnmarshalAPERWithOptions(v *AreaScopeOfMDT, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeAreaScopeOfMDTValueCodecFieldCapture(v *AreaScopeOfMDTValueCodec) *func(AreaScopeOfMDT, aper.DecodeState) (AreaScopeOfMDT, aper.Snapshot) {
	return &v.capture
}
func BridgeAreaScopeOfMDTValueCodecFieldCompare(v *AreaScopeOfMDTValueCodec) *func(AreaScopeOfMDT, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeAreaScopeOfMDTValueCodecFieldContext(v *AreaScopeOfMDTValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeAreaScopeOfMDTValueCodecFieldDecode(v *AreaScopeOfMDTValueCodec) *func([]byte, aper.DecodeState) (AreaScopeOfMDT, error) {
	return &v.decode
}
func BridgeAreaScopeOfMDTValueCodecFieldEncode(v *AreaScopeOfMDTValueCodec) *func(AreaScopeOfMDT, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeAreaScopeOfMDTValueCodecFieldPath(v *AreaScopeOfMDTValueCodec) *aper.Path { return &v.path }
func BridgeAreaScopeOfMDTValueCodecMethodEncodeBudgetValue(v AreaScopeOfMDTValueCodec, a0 AreaScopeOfMDT, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeAreaScopeOfMDTValueCodecMethodEncodeChanged(v AreaScopeOfMDTValueCodec, a0 AreaScopeOfMDT, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeAreaScopeOfQMCAPERValueFieldContext(v *AreaScopeOfQMCAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeAreaScopeOfQMCAPERValueFieldReceived(v *AreaScopeOfQMCAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeAreaScopeOfQMCAPERValueFieldReplay(v *AreaScopeOfQMCAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeAreaScopeOfQMCAPERValueFieldWithoutReplay(v *AreaScopeOfQMCAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeAreaScopeOfQMCFieldPerOpenTypePadding(v *AreaScopeOfQMC) *aper.CompletePadding {
	return &v.perOpenTypePadding
}
func BridgeAreaScopeOfQMCFieldPerPadding(v *AreaScopeOfQMC) *aper.CompletePadding {
	return &v.perPadding
}
func BridgeAreaScopeOfQMCFieldReceived(v *AreaScopeOfQMC) *bool         { return &v.received }
func BridgeAreaScopeOfQMCFieldReceivedAbsolute(v *AreaScopeOfQMC) *bool { return &v.receivedAbsolute }
func BridgeAreaScopeOfQMCFieldReceivedBytes(v *AreaScopeOfQMC) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeAreaScopeOfQMCFieldReceivedLocation(v *AreaScopeOfQMC) *aper.Location {
	return &v.receivedLocation
}
func BridgeAreaScopeOfQMCFieldReplay(v *AreaScopeOfQMC) *aper.Snapshot { return &v.replay }
func BridgeAreaScopeOfQMCFieldStream(v *AreaScopeOfQMC) *aper.WireSpan { return &v.stream }
func BridgeAreaScopeOfQMCFieldWithoutReplay(v *AreaScopeOfQMC) *bool   { return &v.withoutReplay }
func BridgeAreaScopeOfQMCMethodMarshalAPERBudget(v *AreaScopeOfQMC, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeAreaScopeOfQMCMethodMarshalAPERBudgetValue(v *AreaScopeOfQMC, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudgetValue(a0, a1)
}
func BridgeAreaScopeOfQMCMethodMarshalAPERChanged(v *AreaScopeOfQMC, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeAreaScopeOfQMCMethodMarshalAPERChangedValue(v *AreaScopeOfQMC, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeAreaScopeOfQMCMethodMarshalAPERLegacy(v *AreaScopeOfQMC) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeAreaScopeOfQMCMethodMarshalAPERNewValue(v *AreaScopeOfQMC, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERNewValue(a0, a1)
}
func BridgeAreaScopeOfQMCMethodMarshalAPERPlanned(v *AreaScopeOfQMC, a0 *aper.DecodeBudget, a1 bool, a2 *aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1, a2)
}
func BridgeAreaScopeOfQMCMethodMarshalAPERTo(v *AreaScopeOfQMC, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeAreaScopeOfQMCMethodUnmarshalAPERFrom(v *AreaScopeOfQMC, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeAreaScopeOfQMCMethodUnmarshalAPERLegacy(v *AreaScopeOfQMC, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeAreaScopeOfQMCMethodUnmarshalAPERWithOptions(v *AreaScopeOfQMC, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeAreaScopeOfQMCValueCodecFieldCapture(v *AreaScopeOfQMCValueCodec) *func(AreaScopeOfQMC, aper.DecodeState) (AreaScopeOfQMC, aper.Snapshot) {
	return &v.capture
}
func BridgeAreaScopeOfQMCValueCodecFieldCompare(v *AreaScopeOfQMCValueCodec) *func(AreaScopeOfQMC, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeAreaScopeOfQMCValueCodecFieldContext(v *AreaScopeOfQMCValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeAreaScopeOfQMCValueCodecFieldDecode(v *AreaScopeOfQMCValueCodec) *func([]byte, aper.DecodeState) (AreaScopeOfQMC, error) {
	return &v.decode
}
func BridgeAreaScopeOfQMCValueCodecFieldEncode(v *AreaScopeOfQMCValueCodec) *func(AreaScopeOfQMC, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeAreaScopeOfQMCValueCodecFieldPath(v *AreaScopeOfQMCValueCodec) *aper.Path { return &v.path }
func BridgeAreaScopeOfQMCValueCodecMethodEncodeBudgetValue(v AreaScopeOfQMCValueCodec, a0 AreaScopeOfQMC, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeAreaScopeOfQMCValueCodecMethodEncodeChanged(v AreaScopeOfQMCValueCodec, a0 AreaScopeOfQMC, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeBroadcastCancelledAreaListAPERValueFieldContext(v *BroadcastCancelledAreaListAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeBroadcastCancelledAreaListAPERValueFieldReceived(v *BroadcastCancelledAreaListAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeBroadcastCancelledAreaListAPERValueFieldReplay(v *BroadcastCancelledAreaListAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeBroadcastCancelledAreaListAPERValueFieldWithoutReplay(v *BroadcastCancelledAreaListAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeBroadcastCancelledAreaListFieldPerOpenTypePadding(v *BroadcastCancelledAreaList) *aper.CompletePadding {
	return &v.perOpenTypePadding
}
func BridgeBroadcastCancelledAreaListFieldPerPadding(v *BroadcastCancelledAreaList) *aper.CompletePadding {
	return &v.perPadding
}
func BridgeBroadcastCancelledAreaListFieldReceived(v *BroadcastCancelledAreaList) *bool {
	return &v.received
}
func BridgeBroadcastCancelledAreaListFieldReceivedAbsolute(v *BroadcastCancelledAreaList) *bool {
	return &v.receivedAbsolute
}
func BridgeBroadcastCancelledAreaListFieldReceivedBytes(v *BroadcastCancelledAreaList) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeBroadcastCancelledAreaListFieldReceivedLocation(v *BroadcastCancelledAreaList) *aper.Location {
	return &v.receivedLocation
}
func BridgeBroadcastCancelledAreaListFieldReplay(v *BroadcastCancelledAreaList) *aper.Snapshot {
	return &v.replay
}
func BridgeBroadcastCancelledAreaListFieldStream(v *BroadcastCancelledAreaList) *aper.WireSpan {
	return &v.stream
}
func BridgeBroadcastCancelledAreaListFieldWithoutReplay(v *BroadcastCancelledAreaList) *bool {
	return &v.withoutReplay
}
func BridgeBroadcastCancelledAreaListMethodMarshalAPERBudget(v *BroadcastCancelledAreaList, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeBroadcastCancelledAreaListMethodMarshalAPERBudgetValue(v *BroadcastCancelledAreaList, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudgetValue(a0, a1)
}
func BridgeBroadcastCancelledAreaListMethodMarshalAPERChanged(v *BroadcastCancelledAreaList, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeBroadcastCancelledAreaListMethodMarshalAPERChangedValue(v *BroadcastCancelledAreaList, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeBroadcastCancelledAreaListMethodMarshalAPERLegacy(v *BroadcastCancelledAreaList) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeBroadcastCancelledAreaListMethodMarshalAPERNewValue(v *BroadcastCancelledAreaList, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERNewValue(a0, a1)
}
func BridgeBroadcastCancelledAreaListMethodMarshalAPERPlanned(v *BroadcastCancelledAreaList, a0 *aper.DecodeBudget, a1 bool, a2 *aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1, a2)
}
func BridgeBroadcastCancelledAreaListMethodMarshalAPERTo(v *BroadcastCancelledAreaList, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeBroadcastCancelledAreaListMethodUnmarshalAPERFrom(v *BroadcastCancelledAreaList, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeBroadcastCancelledAreaListMethodUnmarshalAPERLegacy(v *BroadcastCancelledAreaList, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeBroadcastCancelledAreaListMethodUnmarshalAPERWithOptions(v *BroadcastCancelledAreaList, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeBroadcastCancelledAreaListValueCodecFieldCapture(v *BroadcastCancelledAreaListValueCodec) *func(BroadcastCancelledAreaList, aper.DecodeState) (BroadcastCancelledAreaList, aper.Snapshot) {
	return &v.capture
}
func BridgeBroadcastCancelledAreaListValueCodecFieldCompare(v *BroadcastCancelledAreaListValueCodec) *func(BroadcastCancelledAreaList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeBroadcastCancelledAreaListValueCodecFieldContext(v *BroadcastCancelledAreaListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeBroadcastCancelledAreaListValueCodecFieldDecode(v *BroadcastCancelledAreaListValueCodec) *func([]byte, aper.DecodeState) (BroadcastCancelledAreaList, error) {
	return &v.decode
}
func BridgeBroadcastCancelledAreaListValueCodecFieldEncode(v *BroadcastCancelledAreaListValueCodec) *func(BroadcastCancelledAreaList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeBroadcastCancelledAreaListValueCodecFieldPath(v *BroadcastCancelledAreaListValueCodec) *aper.Path {
	return &v.path
}
func BridgeBroadcastCancelledAreaListValueCodecMethodEncodeBudgetValue(v BroadcastCancelledAreaListValueCodec, a0 BroadcastCancelledAreaList, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeBroadcastCancelledAreaListValueCodecMethodEncodeChanged(v BroadcastCancelledAreaListValueCodec, a0 BroadcastCancelledAreaList, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
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
func BridgeKillRequestIEContainerAPERValueFieldContext(v *KillRequestIEContainerAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeKillRequestIEContainerAPERValueFieldReceived(v *KillRequestIEContainerAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeKillRequestIEContainerAPERValueFieldReplay(v *KillRequestIEContainerAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeKillRequestIEContainerAPERValueFieldWithoutReplay(v *KillRequestIEContainerAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeKillRequestIEContainerValueCodecFieldCapture(v *KillRequestIEContainerValueCodec) *func(KillRequestIEContainer, aper.DecodeState) (KillRequestIEContainer, aper.Snapshot) {
	return &v.capture
}
func BridgeKillRequestIEContainerValueCodecFieldCompare(v *KillRequestIEContainerValueCodec) *func(KillRequestIEContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeKillRequestIEContainerValueCodecFieldContext(v *KillRequestIEContainerValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeKillRequestIEContainerValueCodecFieldDecode(v *KillRequestIEContainerValueCodec) *func([]byte, aper.DecodeState) (KillRequestIEContainer, error) {
	return &v.decode
}
func BridgeKillRequestIEContainerValueCodecFieldEncode(v *KillRequestIEContainerValueCodec) *func(KillRequestIEContainer, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeKillRequestIEContainerValueCodecFieldPath(v *KillRequestIEContainerValueCodec) *aper.Path {
	return &v.path
}
func BridgeKillRequestIEContainerValueCodecMethodEncodeBudgetValue(v KillRequestIEContainerValueCodec, a0 KillRequestIEContainer, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeKillRequestIEContainerValueCodecMethodEncodeChanged(v KillRequestIEContainerValueCodec, a0 KillRequestIEContainer, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeKillRequestIEFieldAPERValueFieldContext(v *KillRequestIEFieldAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeKillRequestIEFieldAPERValueFieldReceived(v *KillRequestIEFieldAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeKillRequestIEFieldAPERValueFieldReplay(v *KillRequestIEFieldAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeKillRequestIEFieldAPERValueFieldWithoutReplay(v *KillRequestIEFieldAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeKillRequestIEFieldFieldReceived(v *KillRequestIEField) *aper.CompletePadding {
	return &v.received
}
func BridgeKillRequestIEFieldFieldReplay(v *KillRequestIEField) *aper.Snapshot { return &v.replay }
func BridgeKillRequestIEFieldFieldStream(v *KillRequestIEField) *aper.WireSpan { return &v.stream }
func BridgeKillRequestIEFieldFieldWithoutReplay(v *KillRequestIEField) *bool   { return &v.withoutReplay }
func BridgeKillRequestIEFieldMethodMarshalAPERTo(v *KillRequestIEField, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeKillRequestIEFieldMethodUnmarshalAPERFrom(v *KillRequestIEField, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeKillRequestIEFieldValueCodecFieldCapture(v *KillRequestIEFieldValueCodec) *func(KillRequestIEField, aper.DecodeState) (KillRequestIEField, aper.Snapshot) {
	return &v.capture
}
func BridgeKillRequestIEFieldValueCodecFieldCompare(v *KillRequestIEFieldValueCodec) *func(KillRequestIEField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeKillRequestIEFieldValueCodecFieldContext(v *KillRequestIEFieldValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeKillRequestIEFieldValueCodecFieldDecode(v *KillRequestIEFieldValueCodec) *func([]byte, aper.DecodeState) (KillRequestIEField, error) {
	return &v.decode
}
func BridgeKillRequestIEFieldValueCodecFieldEncode(v *KillRequestIEFieldValueCodec) *func(KillRequestIEField, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeKillRequestIEFieldValueCodecFieldPath(v *KillRequestIEFieldValueCodec) *aper.Path {
	return &v.path
}
func BridgeKillRequestIEFieldValueCodecMethodEncodeBudgetValue(v KillRequestIEFieldValueCodec, a0 KillRequestIEField, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeKillRequestIEFieldValueCodecMethodEncodeChanged(v KillRequestIEFieldValueCodec, a0 KillRequestIEField, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeKillRequestIETableMethodInfoKillAllWarningMessages(v KillRequestIETable) s00.FieldInfo {
	return v.infoKillAllWarningMessages()
}
func BridgeKillRequestIETableMethodInfoMessageIdentifier(v KillRequestIETable) s00.FieldInfo {
	return v.infoMessageIdentifier()
}
func BridgeKillRequestIETableMethodInfoSerialNumber(v KillRequestIETable) s00.FieldInfo {
	return v.infoSerialNumber()
}
func BridgeKillRequestIETableMethodInfoWarningAreaList(v KillRequestIETable) s00.FieldInfo {
	return v.infoWarningAreaList()
}
func BridgeKillRequestIEValueERABIEContainerListAPERValueFieldContext(v *KillRequestIEValueERABIEContainerListAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeKillRequestIEValueERABIEContainerListAPERValueFieldReceived(v *KillRequestIEValueERABIEContainerListAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeKillRequestIEValueERABIEContainerListAPERValueFieldReplay(v *KillRequestIEValueERABIEContainerListAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeKillRequestIEValueERABIEContainerListAPERValueFieldWithoutReplay(v *KillRequestIEValueERABIEContainerListAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeKillRequestIEValueERABIEContainerListValueCodecFieldCapture(v *KillRequestIEValueERABIEContainerListValueCodec) *func(KillRequestIEValueERABIEContainerList, aper.DecodeState) (KillRequestIEValueERABIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgeKillRequestIEValueERABIEContainerListValueCodecFieldCompare(v *KillRequestIEValueERABIEContainerListValueCodec) *func(KillRequestIEValueERABIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeKillRequestIEValueERABIEContainerListValueCodecFieldContext(v *KillRequestIEValueERABIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeKillRequestIEValueERABIEContainerListValueCodecFieldDecode(v *KillRequestIEValueERABIEContainerListValueCodec) *func([]byte, aper.DecodeState) (KillRequestIEValueERABIEContainerList, error) {
	return &v.decode
}
func BridgeKillRequestIEValueERABIEContainerListValueCodecFieldEncode(v *KillRequestIEValueERABIEContainerListValueCodec) *func(KillRequestIEValueERABIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeKillRequestIEValueERABIEContainerListValueCodecFieldPath(v *KillRequestIEValueERABIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgeKillRequestIEValueERABIEContainerListValueCodecMethodEncodeBudgetValue(v KillRequestIEValueERABIEContainerListValueCodec, a0 KillRequestIEValueERABIEContainerList, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeKillRequestIEValueERABIEContainerListValueCodecMethodEncodeChanged(v KillRequestIEValueERABIEContainerListValueCodec, a0 KillRequestIEValueERABIEContainerList, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeKillRequestIEValueFieldId(v *KillRequestIEValue) *s00.ProtocolIEID { return &v.id }
func BridgeKillRequestIEValueFieldIsOpaque(v *KillRequestIEValue) *bool       { return &v.isOpaque }
func BridgeKillRequestIEValueFieldOpaque(v *KillRequestIEValue) *aper.OpaqueOpenType {
	return &v.opaque
}
func BridgeKillRequestIEValueFieldReceived(v *KillRequestIEValue) *aper.WireSpan { return &v.received }
func BridgeKillRequestIEValueFieldReplay(v *KillRequestIEValue) *aper.Snapshot   { return &v.replay }
func BridgeKillRequestIEValueFieldRowKillAllWarningMessages(v *KillRequestIEValue) **s00.KillAllWarningMessages {
	return &v.rowKillAllWarningMessages
}
func BridgeKillRequestIEValueFieldRowMessageIdentifier(v *KillRequestIEValue) **s00.MessageIdentifier {
	return &v.rowMessageIdentifier
}
func BridgeKillRequestIEValueFieldRowSerialNumber(v *KillRequestIEValue) **s00.SerialNumber {
	return &v.rowSerialNumber
}
func BridgeKillRequestIEValueFieldRowWarningAreaList(v *KillRequestIEValue) **WarningAreaList {
	return &v.rowWarningAreaList
}
func BridgeKillRequestIEValueMethodCaptureSemantics(v KillRequestIEValue, a0 aper.SemanticCapture) KillRequestIEValue {
	return v.captureSemantics(a0)
}
func BridgeKillRequestIEValueMethodCompareSemantics(v KillRequestIEValue, a0 aper.SemanticComparison) aper.SemanticComparison {
	return v.compareSemantics(a0)
}
func BridgeKillRequestIEValueMethodDecode(v KillRequestIEValue, a0 s00.ProtocolIEID, a1 aper.OpaqueOpenType) (KillRequestIEValue, error) {
	return v.decode(a0, a1)
}
func BridgeKillRequestIEValueMethodEncode(v KillRequestIEValue) ([]byte, error) { return v.encode() }
func BridgeKillRequestIEValueMethodEncodeFresh(v KillRequestIEValue, a0 bool, a1 *aper.DecodeBudget) ([]byte, error) {
	return v.encodeFresh(a0, a1)
}
func BridgeKillRequestIEValueMethodMatchesID(v KillRequestIEValue, a0 s00.ProtocolIEID, a1 ...*aper.DecodeBudget) bool {
	return v.matchesID(a0, a1...)
}
func BridgeKillRequestIEValueMethodReason(v KillRequestIEValue, a0 s00.ProtocolIEID) aper.OpaqueReason {
	return v.reason(a0)
}
func BridgeKillRequestIEValueMethodRule(v KillRequestIEValue) aper.SourceRule { return v.rule() }
func BridgeKillRequestIEValueProtocolErrorIEContainerListAPERValueFieldContext(v *KillRequestIEValueProtocolErrorIEContainerListAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeKillRequestIEValueProtocolErrorIEContainerListAPERValueFieldReceived(v *KillRequestIEValueProtocolErrorIEContainerListAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeKillRequestIEValueProtocolErrorIEContainerListAPERValueFieldReplay(v *KillRequestIEValueProtocolErrorIEContainerListAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeKillRequestIEValueProtocolErrorIEContainerListAPERValueFieldWithoutReplay(v *KillRequestIEValueProtocolErrorIEContainerListAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeKillRequestIEValueProtocolErrorIEContainerListValueCodecFieldCapture(v *KillRequestIEValueProtocolErrorIEContainerListValueCodec) *func(KillRequestIEValueProtocolErrorIEContainerList, aper.DecodeState) (KillRequestIEValueProtocolErrorIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgeKillRequestIEValueProtocolErrorIEContainerListValueCodecFieldCompare(v *KillRequestIEValueProtocolErrorIEContainerListValueCodec) *func(KillRequestIEValueProtocolErrorIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeKillRequestIEValueProtocolErrorIEContainerListValueCodecFieldContext(v *KillRequestIEValueProtocolErrorIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeKillRequestIEValueProtocolErrorIEContainerListValueCodecFieldDecode(v *KillRequestIEValueProtocolErrorIEContainerListValueCodec) *func([]byte, aper.DecodeState) (KillRequestIEValueProtocolErrorIEContainerList, error) {
	return &v.decode
}
func BridgeKillRequestIEValueProtocolErrorIEContainerListValueCodecFieldEncode(v *KillRequestIEValueProtocolErrorIEContainerListValueCodec) *func(KillRequestIEValueProtocolErrorIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeKillRequestIEValueProtocolErrorIEContainerListValueCodecFieldPath(v *KillRequestIEValueProtocolErrorIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgeKillRequestIEValueProtocolErrorIEContainerListValueCodecMethodEncodeBudgetValue(v KillRequestIEValueProtocolErrorIEContainerListValueCodec, a0 KillRequestIEValueProtocolErrorIEContainerList, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeKillRequestIEValueProtocolErrorIEContainerListValueCodecMethodEncodeChanged(v KillRequestIEValueProtocolErrorIEContainerListValueCodec, a0 KillRequestIEValueProtocolErrorIEContainerList, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeKillRequestIEValueProtocolIEContainerListAPERValueFieldContext(v *KillRequestIEValueProtocolIEContainerListAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeKillRequestIEValueProtocolIEContainerListAPERValueFieldReceived(v *KillRequestIEValueProtocolIEContainerListAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeKillRequestIEValueProtocolIEContainerListAPERValueFieldReplay(v *KillRequestIEValueProtocolIEContainerListAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeKillRequestIEValueProtocolIEContainerListAPERValueFieldWithoutReplay(v *KillRequestIEValueProtocolIEContainerListAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeKillRequestIEValueProtocolIEContainerListValueCodecFieldCapture(v *KillRequestIEValueProtocolIEContainerListValueCodec) *func(KillRequestIEValueProtocolIEContainerList, aper.DecodeState) (KillRequestIEValueProtocolIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgeKillRequestIEValueProtocolIEContainerListValueCodecFieldCompare(v *KillRequestIEValueProtocolIEContainerListValueCodec) *func(KillRequestIEValueProtocolIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeKillRequestIEValueProtocolIEContainerListValueCodecFieldContext(v *KillRequestIEValueProtocolIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeKillRequestIEValueProtocolIEContainerListValueCodecFieldDecode(v *KillRequestIEValueProtocolIEContainerListValueCodec) *func([]byte, aper.DecodeState) (KillRequestIEValueProtocolIEContainerList, error) {
	return &v.decode
}
func BridgeKillRequestIEValueProtocolIEContainerListValueCodecFieldEncode(v *KillRequestIEValueProtocolIEContainerListValueCodec) *func(KillRequestIEValueProtocolIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeKillRequestIEValueProtocolIEContainerListValueCodecFieldPath(v *KillRequestIEValueProtocolIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgeKillRequestIEValueProtocolIEContainerListValueCodecMethodEncodeBudgetValue(v KillRequestIEValueProtocolIEContainerListValueCodec, a0 KillRequestIEValueProtocolIEContainerList, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeKillRequestIEValueProtocolIEContainerListValueCodecMethodEncodeChanged(v KillRequestIEValueProtocolIEContainerListValueCodec, a0 KillRequestIEValueProtocolIEContainerList, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeKillRequestKillAllWarningMessagesIEBindingFieldCodec(v *KillRequestKillAllWarningMessagesIEBinding) *s01.KillAllWarningMessagesValueCodec {
	return &v.codec
}
func BridgeKillRequestKillAllWarningMessagesIEBindingFieldGet(v *KillRequestKillAllWarningMessagesIEBinding) *func(*KillRequestIEValue) (*s00.KillAllWarningMessages, bool) {
	return &v.get
}
func BridgeKillRequestKillAllWarningMessagesIEBindingFieldInfo(v *KillRequestKillAllWarningMessagesIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeKillRequestKillAllWarningMessagesIEBindingFieldInject(v *KillRequestKillAllWarningMessagesIEBinding) *func(s00.KillAllWarningMessages) KillRequestIEValue {
	return &v.inject
}
func BridgeKillRequestMessageIdentifierIEBindingFieldCodec(v *KillRequestMessageIdentifierIEBinding) *s01.MessageIdentifierValueCodec {
	return &v.codec
}
func BridgeKillRequestMessageIdentifierIEBindingFieldGet(v *KillRequestMessageIdentifierIEBinding) *func(*KillRequestIEValue) (*s00.MessageIdentifier, bool) {
	return &v.get
}
func BridgeKillRequestMessageIdentifierIEBindingFieldInfo(v *KillRequestMessageIdentifierIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeKillRequestMessageIdentifierIEBindingFieldInject(v *KillRequestMessageIdentifierIEBinding) *func(s00.MessageIdentifier) KillRequestIEValue {
	return &v.inject
}
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
func BridgeKillRequestSerialNumberIEBindingFieldCodec(v *KillRequestSerialNumberIEBinding) *s01.SerialNumberValueCodec {
	return &v.codec
}
func BridgeKillRequestSerialNumberIEBindingFieldGet(v *KillRequestSerialNumberIEBinding) *func(*KillRequestIEValue) (*s00.SerialNumber, bool) {
	return &v.get
}
func BridgeKillRequestSerialNumberIEBindingFieldInfo(v *KillRequestSerialNumberIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeKillRequestSerialNumberIEBindingFieldInject(v *KillRequestSerialNumberIEBinding) *func(s00.SerialNumber) KillRequestIEValue {
	return &v.inject
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
func BridgeKillRequestWarningAreaListIEBindingFieldCodec(v *KillRequestWarningAreaListIEBinding) *WarningAreaListValueCodec {
	return &v.codec
}
func BridgeKillRequestWarningAreaListIEBindingFieldGet(v *KillRequestWarningAreaListIEBinding) *func(*KillRequestIEValue) (*WarningAreaList, bool) {
	return &v.get
}
func BridgeKillRequestWarningAreaListIEBindingFieldInfo(v *KillRequestWarningAreaListIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeKillRequestWarningAreaListIEBindingFieldInject(v *KillRequestWarningAreaListIEBinding) *func(WarningAreaList) KillRequestIEValue {
	return &v.inject
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
func BridgeKillResponseBroadcastCancelledAreaListIEBindingFieldCodec(v *KillResponseBroadcastCancelledAreaListIEBinding) *BroadcastCancelledAreaListValueCodec {
	return &v.codec
}
func BridgeKillResponseBroadcastCancelledAreaListIEBindingFieldGet(v *KillResponseBroadcastCancelledAreaListIEBinding) *func(*KillResponseIEValue) (*BroadcastCancelledAreaList, bool) {
	return &v.get
}
func BridgeKillResponseBroadcastCancelledAreaListIEBindingFieldInfo(v *KillResponseBroadcastCancelledAreaListIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeKillResponseBroadcastCancelledAreaListIEBindingFieldInject(v *KillResponseBroadcastCancelledAreaListIEBinding) *func(BroadcastCancelledAreaList) KillResponseIEValue {
	return &v.inject
}
func BridgeKillResponseCriticalityDiagnosticsIEBindingFieldCodec(v *KillResponseCriticalityDiagnosticsIEBinding) *s22.CriticalityDiagnosticsValueCodec {
	return &v.codec
}
func BridgeKillResponseCriticalityDiagnosticsIEBindingFieldGet(v *KillResponseCriticalityDiagnosticsIEBinding) *func(*KillResponseIEValue) (*s22.CriticalityDiagnostics, bool) {
	return &v.get
}
func BridgeKillResponseCriticalityDiagnosticsIEBindingFieldInfo(v *KillResponseCriticalityDiagnosticsIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeKillResponseCriticalityDiagnosticsIEBindingFieldInject(v *KillResponseCriticalityDiagnosticsIEBinding) *func(s22.CriticalityDiagnostics) KillResponseIEValue {
	return &v.inject
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
func BridgeKillResponseIEContainerAPERValueFieldContext(v *KillResponseIEContainerAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeKillResponseIEContainerAPERValueFieldReceived(v *KillResponseIEContainerAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeKillResponseIEContainerAPERValueFieldReplay(v *KillResponseIEContainerAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeKillResponseIEContainerAPERValueFieldWithoutReplay(v *KillResponseIEContainerAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeKillResponseIEContainerValueCodecFieldCapture(v *KillResponseIEContainerValueCodec) *func(KillResponseIEContainer, aper.DecodeState) (KillResponseIEContainer, aper.Snapshot) {
	return &v.capture
}
func BridgeKillResponseIEContainerValueCodecFieldCompare(v *KillResponseIEContainerValueCodec) *func(KillResponseIEContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeKillResponseIEContainerValueCodecFieldContext(v *KillResponseIEContainerValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeKillResponseIEContainerValueCodecFieldDecode(v *KillResponseIEContainerValueCodec) *func([]byte, aper.DecodeState) (KillResponseIEContainer, error) {
	return &v.decode
}
func BridgeKillResponseIEContainerValueCodecFieldEncode(v *KillResponseIEContainerValueCodec) *func(KillResponseIEContainer, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeKillResponseIEContainerValueCodecFieldPath(v *KillResponseIEContainerValueCodec) *aper.Path {
	return &v.path
}
func BridgeKillResponseIEContainerValueCodecMethodEncodeBudgetValue(v KillResponseIEContainerValueCodec, a0 KillResponseIEContainer, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeKillResponseIEContainerValueCodecMethodEncodeChanged(v KillResponseIEContainerValueCodec, a0 KillResponseIEContainer, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeKillResponseIEFieldAPERValueFieldContext(v *KillResponseIEFieldAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeKillResponseIEFieldAPERValueFieldReceived(v *KillResponseIEFieldAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeKillResponseIEFieldAPERValueFieldReplay(v *KillResponseIEFieldAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeKillResponseIEFieldAPERValueFieldWithoutReplay(v *KillResponseIEFieldAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeKillResponseIEFieldFieldReceived(v *KillResponseIEField) *aper.CompletePadding {
	return &v.received
}
func BridgeKillResponseIEFieldFieldReplay(v *KillResponseIEField) *aper.Snapshot { return &v.replay }
func BridgeKillResponseIEFieldFieldStream(v *KillResponseIEField) *aper.WireSpan { return &v.stream }
func BridgeKillResponseIEFieldFieldWithoutReplay(v *KillResponseIEField) *bool {
	return &v.withoutReplay
}
func BridgeKillResponseIEFieldMethodMarshalAPERTo(v *KillResponseIEField, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeKillResponseIEFieldMethodUnmarshalAPERFrom(v *KillResponseIEField, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeKillResponseIEFieldValueCodecFieldCapture(v *KillResponseIEFieldValueCodec) *func(KillResponseIEField, aper.DecodeState) (KillResponseIEField, aper.Snapshot) {
	return &v.capture
}
func BridgeKillResponseIEFieldValueCodecFieldCompare(v *KillResponseIEFieldValueCodec) *func(KillResponseIEField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeKillResponseIEFieldValueCodecFieldContext(v *KillResponseIEFieldValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeKillResponseIEFieldValueCodecFieldDecode(v *KillResponseIEFieldValueCodec) *func([]byte, aper.DecodeState) (KillResponseIEField, error) {
	return &v.decode
}
func BridgeKillResponseIEFieldValueCodecFieldEncode(v *KillResponseIEFieldValueCodec) *func(KillResponseIEField, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeKillResponseIEFieldValueCodecFieldPath(v *KillResponseIEFieldValueCodec) *aper.Path {
	return &v.path
}
func BridgeKillResponseIEFieldValueCodecMethodEncodeBudgetValue(v KillResponseIEFieldValueCodec, a0 KillResponseIEField, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeKillResponseIEFieldValueCodecMethodEncodeChanged(v KillResponseIEFieldValueCodec, a0 KillResponseIEField, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeKillResponseIETableMethodInfoBroadcastCancelledAreaList(v KillResponseIETable) s00.FieldInfo {
	return v.infoBroadcastCancelledAreaList()
}
func BridgeKillResponseIETableMethodInfoCriticalityDiagnostics(v KillResponseIETable) s00.FieldInfo {
	return v.infoCriticalityDiagnostics()
}
func BridgeKillResponseIETableMethodInfoMessageIdentifier(v KillResponseIETable) s00.FieldInfo {
	return v.infoMessageIdentifier()
}
func BridgeKillResponseIETableMethodInfoSerialNumber(v KillResponseIETable) s00.FieldInfo {
	return v.infoSerialNumber()
}
func BridgeKillResponseIEValueERABIEContainerListAPERValueFieldContext(v *KillResponseIEValueERABIEContainerListAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeKillResponseIEValueERABIEContainerListAPERValueFieldReceived(v *KillResponseIEValueERABIEContainerListAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeKillResponseIEValueERABIEContainerListAPERValueFieldReplay(v *KillResponseIEValueERABIEContainerListAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeKillResponseIEValueERABIEContainerListAPERValueFieldWithoutReplay(v *KillResponseIEValueERABIEContainerListAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeKillResponseIEValueERABIEContainerListValueCodecFieldCapture(v *KillResponseIEValueERABIEContainerListValueCodec) *func(KillResponseIEValueERABIEContainerList, aper.DecodeState) (KillResponseIEValueERABIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgeKillResponseIEValueERABIEContainerListValueCodecFieldCompare(v *KillResponseIEValueERABIEContainerListValueCodec) *func(KillResponseIEValueERABIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeKillResponseIEValueERABIEContainerListValueCodecFieldContext(v *KillResponseIEValueERABIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeKillResponseIEValueERABIEContainerListValueCodecFieldDecode(v *KillResponseIEValueERABIEContainerListValueCodec) *func([]byte, aper.DecodeState) (KillResponseIEValueERABIEContainerList, error) {
	return &v.decode
}
func BridgeKillResponseIEValueERABIEContainerListValueCodecFieldEncode(v *KillResponseIEValueERABIEContainerListValueCodec) *func(KillResponseIEValueERABIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeKillResponseIEValueERABIEContainerListValueCodecFieldPath(v *KillResponseIEValueERABIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgeKillResponseIEValueERABIEContainerListValueCodecMethodEncodeBudgetValue(v KillResponseIEValueERABIEContainerListValueCodec, a0 KillResponseIEValueERABIEContainerList, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeKillResponseIEValueERABIEContainerListValueCodecMethodEncodeChanged(v KillResponseIEValueERABIEContainerListValueCodec, a0 KillResponseIEValueERABIEContainerList, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeKillResponseIEValueFieldId(v *KillResponseIEValue) *s00.ProtocolIEID { return &v.id }
func BridgeKillResponseIEValueFieldIsOpaque(v *KillResponseIEValue) *bool       { return &v.isOpaque }
func BridgeKillResponseIEValueFieldOpaque(v *KillResponseIEValue) *aper.OpaqueOpenType {
	return &v.opaque
}
func BridgeKillResponseIEValueFieldReceived(v *KillResponseIEValue) *aper.WireSpan {
	return &v.received
}
func BridgeKillResponseIEValueFieldReplay(v *KillResponseIEValue) *aper.Snapshot { return &v.replay }
func BridgeKillResponseIEValueFieldRowBroadcastCancelledAreaList(v *KillResponseIEValue) **BroadcastCancelledAreaList {
	return &v.rowBroadcastCancelledAreaList
}
func BridgeKillResponseIEValueFieldRowCriticalityDiagnostics(v *KillResponseIEValue) **s22.CriticalityDiagnostics {
	return &v.rowCriticalityDiagnostics
}
func BridgeKillResponseIEValueFieldRowMessageIdentifier(v *KillResponseIEValue) **s00.MessageIdentifier {
	return &v.rowMessageIdentifier
}
func BridgeKillResponseIEValueFieldRowSerialNumber(v *KillResponseIEValue) **s00.SerialNumber {
	return &v.rowSerialNumber
}
func BridgeKillResponseIEValueMethodCaptureSemantics(v KillResponseIEValue, a0 aper.SemanticCapture) KillResponseIEValue {
	return v.captureSemantics(a0)
}
func BridgeKillResponseIEValueMethodCompareSemantics(v KillResponseIEValue, a0 aper.SemanticComparison) aper.SemanticComparison {
	return v.compareSemantics(a0)
}
func BridgeKillResponseIEValueMethodDecode(v KillResponseIEValue, a0 s00.ProtocolIEID, a1 aper.OpaqueOpenType) (KillResponseIEValue, error) {
	return v.decode(a0, a1)
}
func BridgeKillResponseIEValueMethodEncode(v KillResponseIEValue) ([]byte, error) { return v.encode() }
func BridgeKillResponseIEValueMethodEncodeFresh(v KillResponseIEValue, a0 bool, a1 *aper.DecodeBudget) ([]byte, error) {
	return v.encodeFresh(a0, a1)
}
func BridgeKillResponseIEValueMethodMatchesID(v KillResponseIEValue, a0 s00.ProtocolIEID, a1 ...*aper.DecodeBudget) bool {
	return v.matchesID(a0, a1...)
}
func BridgeKillResponseIEValueMethodReason(v KillResponseIEValue, a0 s00.ProtocolIEID) aper.OpaqueReason {
	return v.reason(a0)
}
func BridgeKillResponseIEValueMethodRule(v KillResponseIEValue) aper.SourceRule { return v.rule() }
func BridgeKillResponseIEValueProtocolErrorIEContainerListAPERValueFieldContext(v *KillResponseIEValueProtocolErrorIEContainerListAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeKillResponseIEValueProtocolErrorIEContainerListAPERValueFieldReceived(v *KillResponseIEValueProtocolErrorIEContainerListAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeKillResponseIEValueProtocolErrorIEContainerListAPERValueFieldReplay(v *KillResponseIEValueProtocolErrorIEContainerListAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeKillResponseIEValueProtocolErrorIEContainerListAPERValueFieldWithoutReplay(v *KillResponseIEValueProtocolErrorIEContainerListAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeKillResponseIEValueProtocolErrorIEContainerListValueCodecFieldCapture(v *KillResponseIEValueProtocolErrorIEContainerListValueCodec) *func(KillResponseIEValueProtocolErrorIEContainerList, aper.DecodeState) (KillResponseIEValueProtocolErrorIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgeKillResponseIEValueProtocolErrorIEContainerListValueCodecFieldCompare(v *KillResponseIEValueProtocolErrorIEContainerListValueCodec) *func(KillResponseIEValueProtocolErrorIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeKillResponseIEValueProtocolErrorIEContainerListValueCodecFieldContext(v *KillResponseIEValueProtocolErrorIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeKillResponseIEValueProtocolErrorIEContainerListValueCodecFieldDecode(v *KillResponseIEValueProtocolErrorIEContainerListValueCodec) *func([]byte, aper.DecodeState) (KillResponseIEValueProtocolErrorIEContainerList, error) {
	return &v.decode
}
func BridgeKillResponseIEValueProtocolErrorIEContainerListValueCodecFieldEncode(v *KillResponseIEValueProtocolErrorIEContainerListValueCodec) *func(KillResponseIEValueProtocolErrorIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeKillResponseIEValueProtocolErrorIEContainerListValueCodecFieldPath(v *KillResponseIEValueProtocolErrorIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgeKillResponseIEValueProtocolErrorIEContainerListValueCodecMethodEncodeBudgetValue(v KillResponseIEValueProtocolErrorIEContainerListValueCodec, a0 KillResponseIEValueProtocolErrorIEContainerList, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeKillResponseIEValueProtocolErrorIEContainerListValueCodecMethodEncodeChanged(v KillResponseIEValueProtocolErrorIEContainerListValueCodec, a0 KillResponseIEValueProtocolErrorIEContainerList, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeKillResponseIEValueProtocolIEContainerListAPERValueFieldContext(v *KillResponseIEValueProtocolIEContainerListAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeKillResponseIEValueProtocolIEContainerListAPERValueFieldReceived(v *KillResponseIEValueProtocolIEContainerListAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeKillResponseIEValueProtocolIEContainerListAPERValueFieldReplay(v *KillResponseIEValueProtocolIEContainerListAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeKillResponseIEValueProtocolIEContainerListAPERValueFieldWithoutReplay(v *KillResponseIEValueProtocolIEContainerListAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeKillResponseIEValueProtocolIEContainerListValueCodecFieldCapture(v *KillResponseIEValueProtocolIEContainerListValueCodec) *func(KillResponseIEValueProtocolIEContainerList, aper.DecodeState) (KillResponseIEValueProtocolIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgeKillResponseIEValueProtocolIEContainerListValueCodecFieldCompare(v *KillResponseIEValueProtocolIEContainerListValueCodec) *func(KillResponseIEValueProtocolIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeKillResponseIEValueProtocolIEContainerListValueCodecFieldContext(v *KillResponseIEValueProtocolIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeKillResponseIEValueProtocolIEContainerListValueCodecFieldDecode(v *KillResponseIEValueProtocolIEContainerListValueCodec) *func([]byte, aper.DecodeState) (KillResponseIEValueProtocolIEContainerList, error) {
	return &v.decode
}
func BridgeKillResponseIEValueProtocolIEContainerListValueCodecFieldEncode(v *KillResponseIEValueProtocolIEContainerListValueCodec) *func(KillResponseIEValueProtocolIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeKillResponseIEValueProtocolIEContainerListValueCodecFieldPath(v *KillResponseIEValueProtocolIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgeKillResponseIEValueProtocolIEContainerListValueCodecMethodEncodeBudgetValue(v KillResponseIEValueProtocolIEContainerListValueCodec, a0 KillResponseIEValueProtocolIEContainerList, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeKillResponseIEValueProtocolIEContainerListValueCodecMethodEncodeChanged(v KillResponseIEValueProtocolIEContainerListValueCodec, a0 KillResponseIEValueProtocolIEContainerList, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeKillResponseMessageIdentifierIEBindingFieldCodec(v *KillResponseMessageIdentifierIEBinding) *s01.MessageIdentifierValueCodec {
	return &v.codec
}
func BridgeKillResponseMessageIdentifierIEBindingFieldGet(v *KillResponseMessageIdentifierIEBinding) *func(*KillResponseIEValue) (*s00.MessageIdentifier, bool) {
	return &v.get
}
func BridgeKillResponseMessageIdentifierIEBindingFieldInfo(v *KillResponseMessageIdentifierIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeKillResponseMessageIdentifierIEBindingFieldInject(v *KillResponseMessageIdentifierIEBinding) *func(s00.MessageIdentifier) KillResponseIEValue {
	return &v.inject
}
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
func BridgeKillResponseSerialNumberIEBindingFieldCodec(v *KillResponseSerialNumberIEBinding) *s01.SerialNumberValueCodec {
	return &v.codec
}
func BridgeKillResponseSerialNumberIEBindingFieldGet(v *KillResponseSerialNumberIEBinding) *func(*KillResponseIEValue) (*s00.SerialNumber, bool) {
	return &v.get
}
func BridgeKillResponseSerialNumberIEBindingFieldInfo(v *KillResponseSerialNumberIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeKillResponseSerialNumberIEBindingFieldInject(v *KillResponseSerialNumberIEBinding) *func(s00.SerialNumber) KillResponseIEValue {
	return &v.inject
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
func BridgeTAIBasedMDTAPERValueFieldContext(v *TAIBasedMDTAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeTAIBasedMDTAPERValueFieldReceived(v *TAIBasedMDTAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeTAIBasedMDTAPERValueFieldReplay(v *TAIBasedMDTAPERValue) *aper.Snapshot { return &v.replay }
func BridgeTAIBasedMDTAPERValueFieldWithoutReplay(v *TAIBasedMDTAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeTAIBasedMDTFieldExtCount(v *TAIBasedMDT) *int64                { return &v.extCount }
func BridgeTAIBasedMDTFieldExtData(v *TAIBasedMDT) *[][]byte              { return &v.extData }
func BridgeTAIBasedMDTFieldExtOrigin(v *TAIBasedMDT) *[]aper.OpaqueOrigin { return &v.extOrigin }
func BridgeTAIBasedMDTFieldExtPresent(v *TAIBasedMDT) *[]bool             { return &v.extPresent }
func BridgeTAIBasedMDTFieldExtWire(v *TAIBasedMDT) *[]aper.WireSpan       { return &v.extWire }
func BridgeTAIBasedMDTFieldIEExtensionsIndef(v *TAIBasedMDT) *bool        { return &v.iEExtensionsIndef }
func BridgeTAIBasedMDTFieldPerExtPadding(v *TAIBasedMDT) *[]aper.CompletePadding {
	return &v.perExtPadding
}
func BridgeTAIBasedMDTFieldPerPadding(v *TAIBasedMDT) *aper.FinalPadding { return &v.perPadding }
func BridgeTAIBasedMDTFieldReceived(v *TAIBasedMDT) *bool                { return &v.received }
func BridgeTAIBasedMDTFieldReceivedAbsolute(v *TAIBasedMDT) *bool        { return &v.receivedAbsolute }
func BridgeTAIBasedMDTFieldReceivedBytes(v *TAIBasedMDT) *aper.WireSpan  { return &v.receivedBytes }
func BridgeTAIBasedMDTFieldReceivedLocation(v *TAIBasedMDT) *aper.Location {
	return &v.receivedLocation
}
func BridgeTAIBasedMDTFieldReplay(v *TAIBasedMDT) *aper.Snapshot    { return &v.replay }
func BridgeTAIBasedMDTFieldStream(v *TAIBasedMDT) *aper.WireSpan    { return &v.stream }
func BridgeTAIBasedMDTFieldTAIListforMDTIndef(v *TAIBasedMDT) *bool { return &v.tAIListforMDTIndef }
func BridgeTAIBasedMDTFieldWithoutReplay(v *TAIBasedMDT) *bool      { return &v.withoutReplay }
func BridgeTAIBasedMDTMethodMarshalAPERBudget(v *TAIBasedMDT, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeTAIBasedMDTMethodMarshalAPERBudgetValue(v *TAIBasedMDT, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudgetValue(a0, a1)
}
func BridgeTAIBasedMDTMethodMarshalAPERChanged(v *TAIBasedMDT, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeTAIBasedMDTMethodMarshalAPERChangedValue(v *TAIBasedMDT, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeTAIBasedMDTMethodMarshalAPERLegacy(v *TAIBasedMDT) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeTAIBasedMDTMethodMarshalAPERNewValue(v *TAIBasedMDT, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERNewValue(a0, a1)
}
func BridgeTAIBasedMDTMethodMarshalAPERPlanned(v *TAIBasedMDT, a0 *aper.DecodeBudget, a1 bool, a2 *aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1, a2)
}
func BridgeTAIBasedMDTMethodMarshalAPERTo(v *TAIBasedMDT, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeTAIBasedMDTMethodUnmarshalAPERFrom(v *TAIBasedMDT, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeTAIBasedMDTMethodUnmarshalAPERLegacy(v *TAIBasedMDT, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeTAIBasedMDTMethodUnmarshalAPERWithOptions(v *TAIBasedMDT, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeTAIBasedMDTValueCodecFieldCapture(v *TAIBasedMDTValueCodec) *func(TAIBasedMDT, aper.DecodeState) (TAIBasedMDT, aper.Snapshot) {
	return &v.capture
}
func BridgeTAIBasedMDTValueCodecFieldCompare(v *TAIBasedMDTValueCodec) *func(TAIBasedMDT, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeTAIBasedMDTValueCodecFieldContext(v *TAIBasedMDTValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeTAIBasedMDTValueCodecFieldDecode(v *TAIBasedMDTValueCodec) *func([]byte, aper.DecodeState) (TAIBasedMDT, error) {
	return &v.decode
}
func BridgeTAIBasedMDTValueCodecFieldEncode(v *TAIBasedMDTValueCodec) *func(TAIBasedMDT, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeTAIBasedMDTValueCodecFieldPath(v *TAIBasedMDTValueCodec) *aper.Path { return &v.path }
func BridgeTAIBasedMDTValueCodecMethodEncodeBudgetValue(v TAIBasedMDTValueCodec, a0 TAIBasedMDT, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeTAIBasedMDTValueCodecMethodEncodeChanged(v TAIBasedMDTValueCodec, a0 TAIBasedMDT, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeTAIBasedQMCAPERValueFieldContext(v *TAIBasedQMCAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeTAIBasedQMCAPERValueFieldReceived(v *TAIBasedQMCAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeTAIBasedQMCAPERValueFieldReplay(v *TAIBasedQMCAPERValue) *aper.Snapshot { return &v.replay }
func BridgeTAIBasedQMCAPERValueFieldWithoutReplay(v *TAIBasedQMCAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeTAIBasedQMCFieldExtCount(v *TAIBasedQMC) *int64                { return &v.extCount }
func BridgeTAIBasedQMCFieldExtData(v *TAIBasedQMC) *[][]byte              { return &v.extData }
func BridgeTAIBasedQMCFieldExtOrigin(v *TAIBasedQMC) *[]aper.OpaqueOrigin { return &v.extOrigin }
func BridgeTAIBasedQMCFieldExtPresent(v *TAIBasedQMC) *[]bool             { return &v.extPresent }
func BridgeTAIBasedQMCFieldExtWire(v *TAIBasedQMC) *[]aper.WireSpan       { return &v.extWire }
func BridgeTAIBasedQMCFieldIEExtensionsIndef(v *TAIBasedQMC) *bool        { return &v.iEExtensionsIndef }
func BridgeTAIBasedQMCFieldPerExtPadding(v *TAIBasedQMC) *[]aper.CompletePadding {
	return &v.perExtPadding
}
func BridgeTAIBasedQMCFieldPerPadding(v *TAIBasedQMC) *aper.FinalPadding { return &v.perPadding }
func BridgeTAIBasedQMCFieldReceived(v *TAIBasedQMC) *bool                { return &v.received }
func BridgeTAIBasedQMCFieldReceivedAbsolute(v *TAIBasedQMC) *bool        { return &v.receivedAbsolute }
func BridgeTAIBasedQMCFieldReceivedBytes(v *TAIBasedQMC) *aper.WireSpan  { return &v.receivedBytes }
func BridgeTAIBasedQMCFieldReceivedLocation(v *TAIBasedQMC) *aper.Location {
	return &v.receivedLocation
}
func BridgeTAIBasedQMCFieldReplay(v *TAIBasedQMC) *aper.Snapshot    { return &v.replay }
func BridgeTAIBasedQMCFieldStream(v *TAIBasedQMC) *aper.WireSpan    { return &v.stream }
func BridgeTAIBasedQMCFieldTAIListforQMCIndef(v *TAIBasedQMC) *bool { return &v.tAIListforQMCIndef }
func BridgeTAIBasedQMCFieldWithoutReplay(v *TAIBasedQMC) *bool      { return &v.withoutReplay }
func BridgeTAIBasedQMCMethodMarshalAPERBudget(v *TAIBasedQMC, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeTAIBasedQMCMethodMarshalAPERBudgetValue(v *TAIBasedQMC, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudgetValue(a0, a1)
}
func BridgeTAIBasedQMCMethodMarshalAPERChanged(v *TAIBasedQMC, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeTAIBasedQMCMethodMarshalAPERChangedValue(v *TAIBasedQMC, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeTAIBasedQMCMethodMarshalAPERLegacy(v *TAIBasedQMC) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeTAIBasedQMCMethodMarshalAPERNewValue(v *TAIBasedQMC, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERNewValue(a0, a1)
}
func BridgeTAIBasedQMCMethodMarshalAPERPlanned(v *TAIBasedQMC, a0 *aper.DecodeBudget, a1 bool, a2 *aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1, a2)
}
func BridgeTAIBasedQMCMethodMarshalAPERTo(v *TAIBasedQMC, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeTAIBasedQMCMethodUnmarshalAPERFrom(v *TAIBasedQMC, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeTAIBasedQMCMethodUnmarshalAPERLegacy(v *TAIBasedQMC, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeTAIBasedQMCMethodUnmarshalAPERWithOptions(v *TAIBasedQMC, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeTAIBasedQMCValueCodecFieldCapture(v *TAIBasedQMCValueCodec) *func(TAIBasedQMC, aper.DecodeState) (TAIBasedQMC, aper.Snapshot) {
	return &v.capture
}
func BridgeTAIBasedQMCValueCodecFieldCompare(v *TAIBasedQMCValueCodec) *func(TAIBasedQMC, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeTAIBasedQMCValueCodecFieldContext(v *TAIBasedQMCValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeTAIBasedQMCValueCodecFieldDecode(v *TAIBasedQMCValueCodec) *func([]byte, aper.DecodeState) (TAIBasedQMC, error) {
	return &v.decode
}
func BridgeTAIBasedQMCValueCodecFieldEncode(v *TAIBasedQMCValueCodec) *func(TAIBasedQMC, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeTAIBasedQMCValueCodecFieldPath(v *TAIBasedQMCValueCodec) *aper.Path { return &v.path }
func BridgeTAIBasedQMCValueCodecMethodEncodeBudgetValue(v TAIBasedQMCValueCodec, a0 TAIBasedQMC, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeTAIBasedQMCValueCodecMethodEncodeChanged(v TAIBasedQMCValueCodec, a0 TAIBasedQMC, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeWarningAreaListAPERValueFieldContext(v *WarningAreaListAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeWarningAreaListAPERValueFieldReceived(v *WarningAreaListAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeWarningAreaListAPERValueFieldReplay(v *WarningAreaListAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeWarningAreaListAPERValueFieldWithoutReplay(v *WarningAreaListAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeWarningAreaListFieldPerOpenTypePadding(v *WarningAreaList) *aper.CompletePadding {
	return &v.perOpenTypePadding
}
func BridgeWarningAreaListFieldPerPadding(v *WarningAreaList) *aper.CompletePadding {
	return &v.perPadding
}
func BridgeWarningAreaListFieldReceived(v *WarningAreaList) *bool         { return &v.received }
func BridgeWarningAreaListFieldReceivedAbsolute(v *WarningAreaList) *bool { return &v.receivedAbsolute }
func BridgeWarningAreaListFieldReceivedBytes(v *WarningAreaList) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeWarningAreaListFieldReceivedLocation(v *WarningAreaList) *aper.Location {
	return &v.receivedLocation
}
func BridgeWarningAreaListFieldReplay(v *WarningAreaList) *aper.Snapshot { return &v.replay }
func BridgeWarningAreaListFieldStream(v *WarningAreaList) *aper.WireSpan { return &v.stream }
func BridgeWarningAreaListFieldWithoutReplay(v *WarningAreaList) *bool   { return &v.withoutReplay }
func BridgeWarningAreaListMethodMarshalAPERBudget(v *WarningAreaList, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeWarningAreaListMethodMarshalAPERBudgetValue(v *WarningAreaList, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudgetValue(a0, a1)
}
func BridgeWarningAreaListMethodMarshalAPERChanged(v *WarningAreaList, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeWarningAreaListMethodMarshalAPERChangedValue(v *WarningAreaList, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeWarningAreaListMethodMarshalAPERLegacy(v *WarningAreaList) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeWarningAreaListMethodMarshalAPERNewValue(v *WarningAreaList, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERNewValue(a0, a1)
}
func BridgeWarningAreaListMethodMarshalAPERPlanned(v *WarningAreaList, a0 *aper.DecodeBudget, a1 bool, a2 *aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1, a2)
}
func BridgeWarningAreaListMethodMarshalAPERTo(v *WarningAreaList, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeWarningAreaListMethodUnmarshalAPERFrom(v *WarningAreaList, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeWarningAreaListMethodUnmarshalAPERLegacy(v *WarningAreaList, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeWarningAreaListMethodUnmarshalAPERWithOptions(v *WarningAreaList, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeWarningAreaListValueCodecFieldCapture(v *WarningAreaListValueCodec) *func(WarningAreaList, aper.DecodeState) (WarningAreaList, aper.Snapshot) {
	return &v.capture
}
func BridgeWarningAreaListValueCodecFieldCompare(v *WarningAreaListValueCodec) *func(WarningAreaList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeWarningAreaListValueCodecFieldContext(v *WarningAreaListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeWarningAreaListValueCodecFieldDecode(v *WarningAreaListValueCodec) *func([]byte, aper.DecodeState) (WarningAreaList, error) {
	return &v.decode
}
func BridgeWarningAreaListValueCodecFieldEncode(v *WarningAreaListValueCodec) *func(WarningAreaList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeWarningAreaListValueCodecFieldPath(v *WarningAreaListValueCodec) *aper.Path {
	return &v.path
}
func BridgeWarningAreaListValueCodecMethodEncodeBudgetValue(v WarningAreaListValueCodec, a0 WarningAreaList, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeWarningAreaListValueCodecMethodEncodeChanged(v WarningAreaListValueCodec, a0 WarningAreaList, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
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
func BridgeWriteReplaceWarningRequestIEValueFieldRowWarningAreaList(v *WriteReplaceWarningRequestIEValue) **WarningAreaList {
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
func BridgeWriteReplaceWarningRequestWarningAreaListIEBindingFieldCodec(v *WriteReplaceWarningRequestWarningAreaListIEBinding) *WarningAreaListValueCodec {
	return &v.codec
}
func BridgeWriteReplaceWarningRequestWarningAreaListIEBindingFieldGet(v *WriteReplaceWarningRequestWarningAreaListIEBinding) *func(*WriteReplaceWarningRequestIEValue) (*WarningAreaList, bool) {
	return &v.get
}
func BridgeWriteReplaceWarningRequestWarningAreaListIEBindingFieldInfo(v *WriteReplaceWarningRequestWarningAreaListIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeWriteReplaceWarningRequestWarningAreaListIEBindingFieldInject(v *WriteReplaceWarningRequestWarningAreaListIEBinding) *func(WarningAreaList) WriteReplaceWarningRequestIEValue {
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
func BridgeWriteReplaceWarningResponseBroadcastCompletedAreaListIEBindingFieldCodec(v *WriteReplaceWarningResponseBroadcastCompletedAreaListIEBinding) *s32.BroadcastCompletedAreaListValueCodec {
	return &v.codec
}
func BridgeWriteReplaceWarningResponseBroadcastCompletedAreaListIEBindingFieldGet(v *WriteReplaceWarningResponseBroadcastCompletedAreaListIEBinding) *func(*WriteReplaceWarningResponseIEValue) (*s32.BroadcastCompletedAreaList, bool) {
	return &v.get
}
func BridgeWriteReplaceWarningResponseBroadcastCompletedAreaListIEBindingFieldInfo(v *WriteReplaceWarningResponseBroadcastCompletedAreaListIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeWriteReplaceWarningResponseBroadcastCompletedAreaListIEBindingFieldInject(v *WriteReplaceWarningResponseBroadcastCompletedAreaListIEBinding) *func(s32.BroadcastCompletedAreaList) WriteReplaceWarningResponseIEValue {
	return &v.inject
}
func BridgeWriteReplaceWarningResponseCriticalityDiagnosticsIEBindingFieldCodec(v *WriteReplaceWarningResponseCriticalityDiagnosticsIEBinding) *s22.CriticalityDiagnosticsValueCodec {
	return &v.codec
}
func BridgeWriteReplaceWarningResponseCriticalityDiagnosticsIEBindingFieldGet(v *WriteReplaceWarningResponseCriticalityDiagnosticsIEBinding) *func(*WriteReplaceWarningResponseIEValue) (*s22.CriticalityDiagnostics, bool) {
	return &v.get
}
func BridgeWriteReplaceWarningResponseCriticalityDiagnosticsIEBindingFieldInfo(v *WriteReplaceWarningResponseCriticalityDiagnosticsIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeWriteReplaceWarningResponseCriticalityDiagnosticsIEBindingFieldInject(v *WriteReplaceWarningResponseCriticalityDiagnosticsIEBinding) *func(s22.CriticalityDiagnostics) WriteReplaceWarningResponseIEValue {
	return &v.inject
}
func BridgeWriteReplaceWarningResponseIEContainerAPERValueFieldContext(v *WriteReplaceWarningResponseIEContainerAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeWriteReplaceWarningResponseIEContainerAPERValueFieldReceived(v *WriteReplaceWarningResponseIEContainerAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeWriteReplaceWarningResponseIEContainerAPERValueFieldReplay(v *WriteReplaceWarningResponseIEContainerAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeWriteReplaceWarningResponseIEContainerAPERValueFieldWithoutReplay(v *WriteReplaceWarningResponseIEContainerAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeWriteReplaceWarningResponseIEContainerValueCodecFieldCapture(v *WriteReplaceWarningResponseIEContainerValueCodec) *func(WriteReplaceWarningResponseIEContainer, aper.DecodeState) (WriteReplaceWarningResponseIEContainer, aper.Snapshot) {
	return &v.capture
}
func BridgeWriteReplaceWarningResponseIEContainerValueCodecFieldCompare(v *WriteReplaceWarningResponseIEContainerValueCodec) *func(WriteReplaceWarningResponseIEContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeWriteReplaceWarningResponseIEContainerValueCodecFieldContext(v *WriteReplaceWarningResponseIEContainerValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeWriteReplaceWarningResponseIEContainerValueCodecFieldDecode(v *WriteReplaceWarningResponseIEContainerValueCodec) *func([]byte, aper.DecodeState) (WriteReplaceWarningResponseIEContainer, error) {
	return &v.decode
}
func BridgeWriteReplaceWarningResponseIEContainerValueCodecFieldEncode(v *WriteReplaceWarningResponseIEContainerValueCodec) *func(WriteReplaceWarningResponseIEContainer, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeWriteReplaceWarningResponseIEContainerValueCodecFieldPath(v *WriteReplaceWarningResponseIEContainerValueCodec) *aper.Path {
	return &v.path
}
func BridgeWriteReplaceWarningResponseIEContainerValueCodecMethodEncodeBudgetValue(v WriteReplaceWarningResponseIEContainerValueCodec, a0 WriteReplaceWarningResponseIEContainer, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeWriteReplaceWarningResponseIEContainerValueCodecMethodEncodeChanged(v WriteReplaceWarningResponseIEContainerValueCodec, a0 WriteReplaceWarningResponseIEContainer, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeWriteReplaceWarningResponseIEFieldAPERValueFieldContext(v *WriteReplaceWarningResponseIEFieldAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeWriteReplaceWarningResponseIEFieldAPERValueFieldReceived(v *WriteReplaceWarningResponseIEFieldAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeWriteReplaceWarningResponseIEFieldAPERValueFieldReplay(v *WriteReplaceWarningResponseIEFieldAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeWriteReplaceWarningResponseIEFieldAPERValueFieldWithoutReplay(v *WriteReplaceWarningResponseIEFieldAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeWriteReplaceWarningResponseIEFieldFieldReceived(v *WriteReplaceWarningResponseIEField) *aper.CompletePadding {
	return &v.received
}
func BridgeWriteReplaceWarningResponseIEFieldFieldReplay(v *WriteReplaceWarningResponseIEField) *aper.Snapshot {
	return &v.replay
}
func BridgeWriteReplaceWarningResponseIEFieldFieldStream(v *WriteReplaceWarningResponseIEField) *aper.WireSpan {
	return &v.stream
}
func BridgeWriteReplaceWarningResponseIEFieldFieldWithoutReplay(v *WriteReplaceWarningResponseIEField) *bool {
	return &v.withoutReplay
}
func BridgeWriteReplaceWarningResponseIEFieldMethodMarshalAPERTo(v *WriteReplaceWarningResponseIEField, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeWriteReplaceWarningResponseIEFieldMethodUnmarshalAPERFrom(v *WriteReplaceWarningResponseIEField, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeWriteReplaceWarningResponseIEFieldValueCodecFieldCapture(v *WriteReplaceWarningResponseIEFieldValueCodec) *func(WriteReplaceWarningResponseIEField, aper.DecodeState) (WriteReplaceWarningResponseIEField, aper.Snapshot) {
	return &v.capture
}
func BridgeWriteReplaceWarningResponseIEFieldValueCodecFieldCompare(v *WriteReplaceWarningResponseIEFieldValueCodec) *func(WriteReplaceWarningResponseIEField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeWriteReplaceWarningResponseIEFieldValueCodecFieldContext(v *WriteReplaceWarningResponseIEFieldValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeWriteReplaceWarningResponseIEFieldValueCodecFieldDecode(v *WriteReplaceWarningResponseIEFieldValueCodec) *func([]byte, aper.DecodeState) (WriteReplaceWarningResponseIEField, error) {
	return &v.decode
}
func BridgeWriteReplaceWarningResponseIEFieldValueCodecFieldEncode(v *WriteReplaceWarningResponseIEFieldValueCodec) *func(WriteReplaceWarningResponseIEField, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeWriteReplaceWarningResponseIEFieldValueCodecFieldPath(v *WriteReplaceWarningResponseIEFieldValueCodec) *aper.Path {
	return &v.path
}
func BridgeWriteReplaceWarningResponseIEFieldValueCodecMethodEncodeBudgetValue(v WriteReplaceWarningResponseIEFieldValueCodec, a0 WriteReplaceWarningResponseIEField, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeWriteReplaceWarningResponseIEFieldValueCodecMethodEncodeChanged(v WriteReplaceWarningResponseIEFieldValueCodec, a0 WriteReplaceWarningResponseIEField, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeWriteReplaceWarningResponseIETableMethodInfoBroadcastCompletedAreaList(v WriteReplaceWarningResponseIETable) s00.FieldInfo {
	return v.infoBroadcastCompletedAreaList()
}
func BridgeWriteReplaceWarningResponseIETableMethodInfoCriticalityDiagnostics(v WriteReplaceWarningResponseIETable) s00.FieldInfo {
	return v.infoCriticalityDiagnostics()
}
func BridgeWriteReplaceWarningResponseIETableMethodInfoMessageIdentifier(v WriteReplaceWarningResponseIETable) s00.FieldInfo {
	return v.infoMessageIdentifier()
}
func BridgeWriteReplaceWarningResponseIETableMethodInfoSerialNumber(v WriteReplaceWarningResponseIETable) s00.FieldInfo {
	return v.infoSerialNumber()
}
func BridgeWriteReplaceWarningResponseIEValueERABIEContainerListAPERValueFieldContext(v *WriteReplaceWarningResponseIEValueERABIEContainerListAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeWriteReplaceWarningResponseIEValueERABIEContainerListAPERValueFieldReceived(v *WriteReplaceWarningResponseIEValueERABIEContainerListAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeWriteReplaceWarningResponseIEValueERABIEContainerListAPERValueFieldReplay(v *WriteReplaceWarningResponseIEValueERABIEContainerListAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeWriteReplaceWarningResponseIEValueERABIEContainerListAPERValueFieldWithoutReplay(v *WriteReplaceWarningResponseIEValueERABIEContainerListAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeWriteReplaceWarningResponseIEValueERABIEContainerListValueCodecFieldCapture(v *WriteReplaceWarningResponseIEValueERABIEContainerListValueCodec) *func(WriteReplaceWarningResponseIEValueERABIEContainerList, aper.DecodeState) (WriteReplaceWarningResponseIEValueERABIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgeWriteReplaceWarningResponseIEValueERABIEContainerListValueCodecFieldCompare(v *WriteReplaceWarningResponseIEValueERABIEContainerListValueCodec) *func(WriteReplaceWarningResponseIEValueERABIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeWriteReplaceWarningResponseIEValueERABIEContainerListValueCodecFieldContext(v *WriteReplaceWarningResponseIEValueERABIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeWriteReplaceWarningResponseIEValueERABIEContainerListValueCodecFieldDecode(v *WriteReplaceWarningResponseIEValueERABIEContainerListValueCodec) *func([]byte, aper.DecodeState) (WriteReplaceWarningResponseIEValueERABIEContainerList, error) {
	return &v.decode
}
func BridgeWriteReplaceWarningResponseIEValueERABIEContainerListValueCodecFieldEncode(v *WriteReplaceWarningResponseIEValueERABIEContainerListValueCodec) *func(WriteReplaceWarningResponseIEValueERABIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeWriteReplaceWarningResponseIEValueERABIEContainerListValueCodecFieldPath(v *WriteReplaceWarningResponseIEValueERABIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgeWriteReplaceWarningResponseIEValueERABIEContainerListValueCodecMethodEncodeBudgetValue(v WriteReplaceWarningResponseIEValueERABIEContainerListValueCodec, a0 WriteReplaceWarningResponseIEValueERABIEContainerList, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeWriteReplaceWarningResponseIEValueERABIEContainerListValueCodecMethodEncodeChanged(v WriteReplaceWarningResponseIEValueERABIEContainerListValueCodec, a0 WriteReplaceWarningResponseIEValueERABIEContainerList, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeWriteReplaceWarningResponseIEValueFieldId(v *WriteReplaceWarningResponseIEValue) *s00.ProtocolIEID {
	return &v.id
}
func BridgeWriteReplaceWarningResponseIEValueFieldIsOpaque(v *WriteReplaceWarningResponseIEValue) *bool {
	return &v.isOpaque
}
func BridgeWriteReplaceWarningResponseIEValueFieldOpaque(v *WriteReplaceWarningResponseIEValue) *aper.OpaqueOpenType {
	return &v.opaque
}
func BridgeWriteReplaceWarningResponseIEValueFieldReceived(v *WriteReplaceWarningResponseIEValue) *aper.WireSpan {
	return &v.received
}
func BridgeWriteReplaceWarningResponseIEValueFieldReplay(v *WriteReplaceWarningResponseIEValue) *aper.Snapshot {
	return &v.replay
}
func BridgeWriteReplaceWarningResponseIEValueFieldRowBroadcastCompletedAreaList(v *WriteReplaceWarningResponseIEValue) **s32.BroadcastCompletedAreaList {
	return &v.rowBroadcastCompletedAreaList
}
func BridgeWriteReplaceWarningResponseIEValueFieldRowCriticalityDiagnostics(v *WriteReplaceWarningResponseIEValue) **s22.CriticalityDiagnostics {
	return &v.rowCriticalityDiagnostics
}
func BridgeWriteReplaceWarningResponseIEValueFieldRowMessageIdentifier(v *WriteReplaceWarningResponseIEValue) **s00.MessageIdentifier {
	return &v.rowMessageIdentifier
}
func BridgeWriteReplaceWarningResponseIEValueFieldRowSerialNumber(v *WriteReplaceWarningResponseIEValue) **s00.SerialNumber {
	return &v.rowSerialNumber
}
func BridgeWriteReplaceWarningResponseIEValueMethodCaptureSemantics(v WriteReplaceWarningResponseIEValue, a0 aper.SemanticCapture) WriteReplaceWarningResponseIEValue {
	return v.captureSemantics(a0)
}
func BridgeWriteReplaceWarningResponseIEValueMethodCompareSemantics(v WriteReplaceWarningResponseIEValue, a0 aper.SemanticComparison) aper.SemanticComparison {
	return v.compareSemantics(a0)
}
func BridgeWriteReplaceWarningResponseIEValueMethodDecode(v WriteReplaceWarningResponseIEValue, a0 s00.ProtocolIEID, a1 aper.OpaqueOpenType) (WriteReplaceWarningResponseIEValue, error) {
	return v.decode(a0, a1)
}
func BridgeWriteReplaceWarningResponseIEValueMethodEncode(v WriteReplaceWarningResponseIEValue) ([]byte, error) {
	return v.encode()
}
func BridgeWriteReplaceWarningResponseIEValueMethodEncodeFresh(v WriteReplaceWarningResponseIEValue, a0 bool, a1 *aper.DecodeBudget) ([]byte, error) {
	return v.encodeFresh(a0, a1)
}
func BridgeWriteReplaceWarningResponseIEValueMethodMatchesID(v WriteReplaceWarningResponseIEValue, a0 s00.ProtocolIEID, a1 ...*aper.DecodeBudget) bool {
	return v.matchesID(a0, a1...)
}
func BridgeWriteReplaceWarningResponseIEValueMethodReason(v WriteReplaceWarningResponseIEValue, a0 s00.ProtocolIEID) aper.OpaqueReason {
	return v.reason(a0)
}
func BridgeWriteReplaceWarningResponseIEValueMethodRule(v WriteReplaceWarningResponseIEValue) aper.SourceRule {
	return v.rule()
}
func BridgeWriteReplaceWarningResponseIEValueProtocolErrorIEContainerListAPERValueFieldContext(v *WriteReplaceWarningResponseIEValueProtocolErrorIEContainerListAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeWriteReplaceWarningResponseIEValueProtocolErrorIEContainerListAPERValueFieldReceived(v *WriteReplaceWarningResponseIEValueProtocolErrorIEContainerListAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeWriteReplaceWarningResponseIEValueProtocolErrorIEContainerListAPERValueFieldReplay(v *WriteReplaceWarningResponseIEValueProtocolErrorIEContainerListAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeWriteReplaceWarningResponseIEValueProtocolErrorIEContainerListAPERValueFieldWithoutReplay(v *WriteReplaceWarningResponseIEValueProtocolErrorIEContainerListAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeWriteReplaceWarningResponseIEValueProtocolErrorIEContainerListValueCodecFieldCapture(v *WriteReplaceWarningResponseIEValueProtocolErrorIEContainerListValueCodec) *func(WriteReplaceWarningResponseIEValueProtocolErrorIEContainerList, aper.DecodeState) (WriteReplaceWarningResponseIEValueProtocolErrorIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgeWriteReplaceWarningResponseIEValueProtocolErrorIEContainerListValueCodecFieldCompare(v *WriteReplaceWarningResponseIEValueProtocolErrorIEContainerListValueCodec) *func(WriteReplaceWarningResponseIEValueProtocolErrorIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeWriteReplaceWarningResponseIEValueProtocolErrorIEContainerListValueCodecFieldContext(v *WriteReplaceWarningResponseIEValueProtocolErrorIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeWriteReplaceWarningResponseIEValueProtocolErrorIEContainerListValueCodecFieldDecode(v *WriteReplaceWarningResponseIEValueProtocolErrorIEContainerListValueCodec) *func([]byte, aper.DecodeState) (WriteReplaceWarningResponseIEValueProtocolErrorIEContainerList, error) {
	return &v.decode
}
func BridgeWriteReplaceWarningResponseIEValueProtocolErrorIEContainerListValueCodecFieldEncode(v *WriteReplaceWarningResponseIEValueProtocolErrorIEContainerListValueCodec) *func(WriteReplaceWarningResponseIEValueProtocolErrorIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeWriteReplaceWarningResponseIEValueProtocolErrorIEContainerListValueCodecFieldPath(v *WriteReplaceWarningResponseIEValueProtocolErrorIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgeWriteReplaceWarningResponseIEValueProtocolErrorIEContainerListValueCodecMethodEncodeBudgetValue(v WriteReplaceWarningResponseIEValueProtocolErrorIEContainerListValueCodec, a0 WriteReplaceWarningResponseIEValueProtocolErrorIEContainerList, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeWriteReplaceWarningResponseIEValueProtocolErrorIEContainerListValueCodecMethodEncodeChanged(v WriteReplaceWarningResponseIEValueProtocolErrorIEContainerListValueCodec, a0 WriteReplaceWarningResponseIEValueProtocolErrorIEContainerList, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeWriteReplaceWarningResponseIEValueProtocolIEContainerListAPERValueFieldContext(v *WriteReplaceWarningResponseIEValueProtocolIEContainerListAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeWriteReplaceWarningResponseIEValueProtocolIEContainerListAPERValueFieldReceived(v *WriteReplaceWarningResponseIEValueProtocolIEContainerListAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeWriteReplaceWarningResponseIEValueProtocolIEContainerListAPERValueFieldReplay(v *WriteReplaceWarningResponseIEValueProtocolIEContainerListAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeWriteReplaceWarningResponseIEValueProtocolIEContainerListAPERValueFieldWithoutReplay(v *WriteReplaceWarningResponseIEValueProtocolIEContainerListAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeWriteReplaceWarningResponseIEValueProtocolIEContainerListValueCodecFieldCapture(v *WriteReplaceWarningResponseIEValueProtocolIEContainerListValueCodec) *func(WriteReplaceWarningResponseIEValueProtocolIEContainerList, aper.DecodeState) (WriteReplaceWarningResponseIEValueProtocolIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgeWriteReplaceWarningResponseIEValueProtocolIEContainerListValueCodecFieldCompare(v *WriteReplaceWarningResponseIEValueProtocolIEContainerListValueCodec) *func(WriteReplaceWarningResponseIEValueProtocolIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeWriteReplaceWarningResponseIEValueProtocolIEContainerListValueCodecFieldContext(v *WriteReplaceWarningResponseIEValueProtocolIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeWriteReplaceWarningResponseIEValueProtocolIEContainerListValueCodecFieldDecode(v *WriteReplaceWarningResponseIEValueProtocolIEContainerListValueCodec) *func([]byte, aper.DecodeState) (WriteReplaceWarningResponseIEValueProtocolIEContainerList, error) {
	return &v.decode
}
func BridgeWriteReplaceWarningResponseIEValueProtocolIEContainerListValueCodecFieldEncode(v *WriteReplaceWarningResponseIEValueProtocolIEContainerListValueCodec) *func(WriteReplaceWarningResponseIEValueProtocolIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeWriteReplaceWarningResponseIEValueProtocolIEContainerListValueCodecFieldPath(v *WriteReplaceWarningResponseIEValueProtocolIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgeWriteReplaceWarningResponseIEValueProtocolIEContainerListValueCodecMethodEncodeBudgetValue(v WriteReplaceWarningResponseIEValueProtocolIEContainerListValueCodec, a0 WriteReplaceWarningResponseIEValueProtocolIEContainerList, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeWriteReplaceWarningResponseIEValueProtocolIEContainerListValueCodecMethodEncodeChanged(v WriteReplaceWarningResponseIEValueProtocolIEContainerListValueCodec, a0 WriteReplaceWarningResponseIEValueProtocolIEContainerList, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeWriteReplaceWarningResponseMessageIdentifierIEBindingFieldCodec(v *WriteReplaceWarningResponseMessageIdentifierIEBinding) *s01.MessageIdentifierValueCodec {
	return &v.codec
}
func BridgeWriteReplaceWarningResponseMessageIdentifierIEBindingFieldGet(v *WriteReplaceWarningResponseMessageIdentifierIEBinding) *func(*WriteReplaceWarningResponseIEValue) (*s00.MessageIdentifier, bool) {
	return &v.get
}
func BridgeWriteReplaceWarningResponseMessageIdentifierIEBindingFieldInfo(v *WriteReplaceWarningResponseMessageIdentifierIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeWriteReplaceWarningResponseMessageIdentifierIEBindingFieldInject(v *WriteReplaceWarningResponseMessageIdentifierIEBinding) *func(s00.MessageIdentifier) WriteReplaceWarningResponseIEValue {
	return &v.inject
}
func BridgeWriteReplaceWarningResponseSerialNumberIEBindingFieldCodec(v *WriteReplaceWarningResponseSerialNumberIEBinding) *s01.SerialNumberValueCodec {
	return &v.codec
}
func BridgeWriteReplaceWarningResponseSerialNumberIEBindingFieldGet(v *WriteReplaceWarningResponseSerialNumberIEBinding) *func(*WriteReplaceWarningResponseIEValue) (*s00.SerialNumber, bool) {
	return &v.get
}
func BridgeWriteReplaceWarningResponseSerialNumberIEBindingFieldInfo(v *WriteReplaceWarningResponseSerialNumberIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeWriteReplaceWarningResponseSerialNumberIEBindingFieldInject(v *WriteReplaceWarningResponseSerialNumberIEBinding) *func(s00.SerialNumber) WriteReplaceWarningResponseIEValue {
	return &v.inject
}

// Selected returns the decoded value of the active alternative, as the matching As method returns it, or false when the value is opaque or empty.
// The field's Id distinguishes alternatives with the same Go type.
func (v *KillRequestIEValue) Selected() (any, bool) {
	if v == nil || v.isOpaque {
		return nil, false
	}
	switch v.id {
	case 111:
		if value, ok := v.AsMessageIdentifier(); ok {
			return value, true
		}
	case 112:
		if value, ok := v.AsSerialNumber(); ok {
			return value, true
		}
	case 113:
		if value, ok := v.AsWarningAreaList(); ok {
			return value, true
		}
	case 191:
		if value, ok := v.AsKillAllWarningMessages(); ok {
			return value, true
		}
	}
	return nil, false
}

// Selected returns the decoded value of the active alternative, as the matching As method returns it, or false when the value is opaque or empty.
// The field's Id distinguishes alternatives with the same Go type.
func (v *KillResponseIEValue) Selected() (any, bool) {
	if v == nil || v.isOpaque {
		return nil, false
	}
	switch v.id {
	case 111:
		if value, ok := v.AsMessageIdentifier(); ok {
			return value, true
		}
	case 112:
		if value, ok := v.AsSerialNumber(); ok {
			return value, true
		}
	case 141:
		if value, ok := v.AsBroadcastCancelledAreaList(); ok {
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
// The field's Id distinguishes alternatives with the same Go type.
func (v *WriteReplaceWarningRequestIEValue) Selected() (any, bool) {
	if v == nil || v.isOpaque {
		return nil, false
	}
	switch v.id {
	case 111:
		if value, ok := v.AsMessageIdentifier(); ok {
			return value, true
		}
	case 112:
		if value, ok := v.AsSerialNumber(); ok {
			return value, true
		}
	case 113:
		if value, ok := v.AsWarningAreaList(); ok {
			return value, true
		}
	case 114:
		if value, ok := v.AsRepetitionPeriod(); ok {
			return value, true
		}
	case 144:
		if value, ok := v.AsExtendedRepetitionPeriod(); ok {
			return value, true
		}
	case 115:
		if value, ok := v.AsNumberofBroadcastRequest(); ok {
			return value, true
		}
	case 116:
		if value, ok := v.AsWarningType(); ok {
			return value, true
		}
	case 117:
		if value, ok := v.AsWarningSecurityInfo(); ok {
			return value, true
		}
	case 118:
		if value, ok := v.AsDataCodingScheme(); ok {
			return value, true
		}
	case 119:
		if value, ok := v.AsWarningMessageContents(); ok {
			return value, true
		}
	case 142:
		if value, ok := v.AsConcurrentWarningMessageIndicator(); ok {
			return value, true
		}
	case 286:
		if value, ok := v.AsWarningAreaCoordinates(); ok {
			return value, true
		}
	}
	return nil, false
}

// Selected returns the decoded value of the active alternative, as the matching As method returns it, or false when the value is opaque or empty.
// The field's Id distinguishes alternatives with the same Go type.
func (v *WriteReplaceWarningResponseIEValue) Selected() (any, bool) {
	if v == nil || v.isOpaque {
		return nil, false
	}
	switch v.id {
	case 111:
		if value, ok := v.AsMessageIdentifier(); ok {
			return value, true
		}
	case 112:
		if value, ok := v.AsSerialNumber(); ok {
			return value, true
		}
	case 120:
		if value, ok := v.AsBroadcastCompletedAreaList(); ok {
			return value, true
		}
	case 58:
		if value, ok := v.AsCriticalityDiagnostics(); ok {
			return value, true
		}
	}
	return nil, false
}
