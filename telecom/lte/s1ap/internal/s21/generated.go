// Code generated from the pinned S1AP source closure. DO NOT EDIT.

// Package s21 implements the github.com/gomaja/go-asn1/telecom/lte/s1ap root package.
package s21

import (
	fmt "fmt"
	s00 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s00"
	s01 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s01"
	s02 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s02"
	s06 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s06"
	s07 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s07"
	s08 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s08"
	s13 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s13"
	s14 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s14"
	s15 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s15"
	s16 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s16"
	s17 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s17"
	s18 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s18"
	s19 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s19"
	s20 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s20"
	runtime "github.com/gomaja/go-asn1/telecom/lte/s1ap/runtime"
	aper "github.com/gomaja/go-asn1/telecom/lte/s1ap/runtime/aper"
)

type BuildError struct{ Issues []ValidationIssue }

// Unwrap returns the invalid-value error associated with the failed S1AP build.
func (e *BuildError) Unwrap() error { return aper.ErrInvalidValue }

// Error describes the first reported S1AP message-structure issue, or a generic build failure when no issue is available.
func (e *BuildError) Error() string {
	if e == nil || len(e.Issues) == 0 {
		return "S1AP build failed"
	}
	return fmt.Sprintf("S1AP build at %s: structural issue %d (IE %d)", e.Issues[0].Location.Path, e.Issues[0].Code, e.Issues[0].IEID)
}
func BridgeBuildBlockingIssues(report ValidationReport) []ValidationIssue {
	blocking := report.Issues[:0]
	for _, issue := range report.Issues {
		if report.budget != nil {
			if err := aper.NewBudgetBuffer(report.budget).ChargeWork(1); err != nil {
				return nil
			}
		}
		if issue.Severity == s00.ValidationSeverityError {
			blocking = append(blocking, issue)
		}
	}
	return blocking
}

// UplinkS1cdma2000tunnellingIEContainer is the concrete ProtocolIEContainer[UplinkS1cdma2000tunnellingIEValue].
type UplinkS1cdma2000tunnellingIEContainer []UplinkS1cdma2000tunnellingIEField

// UplinkS1cdma2000tunnellingIEField is the concrete ProtocolIEField[UplinkS1cdma2000tunnellingIEValue].
type UplinkS1cdma2000tunnellingIEField struct {
	withoutReplay bool
	replay        aper.Snapshot
	stream        aper.WireSpan
	Id            s00.ProtocolIEID
	Criticality   s00.Criticality
	Value         UplinkS1cdma2000tunnellingIEValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v UplinkS1cdma2000tunnellingIEField) WithoutReplay() UplinkS1cdma2000tunnellingIEField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *UplinkS1cdma2000tunnellingIEField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *UplinkS1cdma2000tunnellingIEField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
func (v *UplinkS1cdma2000tunnellingIEField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolIEField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = UplinkS1cdma2000tunnellingIEField{}
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
	var zero UplinkS1cdma2000tunnellingIEValue

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

// ENBStatusTransferIEContainer is the concrete ProtocolIEContainer[ENBStatusTransferIEValue].
type ENBStatusTransferIEContainer []ENBStatusTransferIEField

// ENBStatusTransferIEField is the concrete ProtocolIEField[ENBStatusTransferIEValue].
type ENBStatusTransferIEField struct {
	withoutReplay bool
	replay        aper.Snapshot
	stream        aper.WireSpan
	Id            s00.ProtocolIEID
	Criticality   s00.Criticality
	Value         ENBStatusTransferIEValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ENBStatusTransferIEField) WithoutReplay() ENBStatusTransferIEField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *ENBStatusTransferIEField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *ENBStatusTransferIEField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
func (v *ENBStatusTransferIEField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolIEField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = ENBStatusTransferIEField{}
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
	var zero ENBStatusTransferIEValue

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

// MMEStatusTransferIEContainer is the concrete ProtocolIEContainer[MMEStatusTransferIEValue].
type MMEStatusTransferIEContainer []MMEStatusTransferIEField

// MMEStatusTransferIEField is the concrete ProtocolIEField[MMEStatusTransferIEValue].
type MMEStatusTransferIEField struct {
	withoutReplay bool
	replay        aper.Snapshot
	stream        aper.WireSpan
	Id            s00.ProtocolIEID
	Criticality   s00.Criticality
	Value         MMEStatusTransferIEValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v MMEStatusTransferIEField) WithoutReplay() MMEStatusTransferIEField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *MMEStatusTransferIEField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *MMEStatusTransferIEField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
func (v *MMEStatusTransferIEField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolIEField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = MMEStatusTransferIEField{}
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
	var zero MMEStatusTransferIEValue

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

// UEContextModificationIndicationIEContainer is the concrete ProtocolIEContainer[UEContextModificationIndicationIEValue].
type UEContextModificationIndicationIEContainer []UEContextModificationIndicationIEField

// UEContextModificationIndicationIEField is the concrete ProtocolIEField[UEContextModificationIndicationIEValue].
type UEContextModificationIndicationIEField struct {
	withoutReplay bool
	replay        aper.Snapshot
	stream        aper.WireSpan
	Id            s00.ProtocolIEID
	Criticality   s00.Criticality
	Value         UEContextModificationIndicationIEValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v UEContextModificationIndicationIEField) WithoutReplay() UEContextModificationIndicationIEField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *UEContextModificationIndicationIEField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *UEContextModificationIndicationIEField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
func (v *UEContextModificationIndicationIEField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolIEField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = UEContextModificationIndicationIEField{}
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
	var zero UEContextModificationIndicationIEValue

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
func BridgeBearersSubjectToDLDiscardingItemIEValueCaptureS1APProtocolIESingleContainer(v *s15.BearersSubjectToDLDiscardingItemIEValueProtocolIESingleContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeBearersSubjectToDLDiscardingItemIEValueCaptureS1APProtocolIEField(v, s)
	s.End(f, nil, false)
}
func BridgeBearersSubjectToDLDiscardingItemIEValueCompareS1APProtocolIESingleContainer(v *s15.BearersSubjectToDLDiscardingItemIEValueProtocolIESingleContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeBearersSubjectToDLDiscardingItemIEValueCompareS1APProtocolIEField(v, s)
	s.End(f, aper.Snapshot{}, false)
}
func BridgeBearersSubjectToEarlyStatusTransferItemIEValueCaptureS1APProtocolIESingleContainer(v *s15.BearersSubjectToEarlyStatusTransferItemIEValueProtocolIESingleContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeBearersSubjectToEarlyStatusTransferItemIEValueCaptureS1APProtocolIEField(v, s)
	s.End(f, nil, false)
}
func BridgeBearersSubjectToEarlyStatusTransferItemIEValueCompareS1APProtocolIESingleContainer(v *s15.BearersSubjectToEarlyStatusTransferItemIEValueProtocolIESingleContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeBearersSubjectToEarlyStatusTransferItemIEValueCompareS1APProtocolIEField(v, s)
	s.End(f, aper.Snapshot{}, false)
}
func BridgeBearersSubjectToStatusTransferItemExtIEsValueCaptureS1APProtocolExtensionContainer(v *s14.BearersSubjectToStatusTransferItemExtIEsExtContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeBearersSubjectToStatusTransferItemExtIEsValueCaptureS1APProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeBearersSubjectToStatusTransferItemExtIEsValueCompareS1APProtocolExtensionContainer(v *s14.BearersSubjectToStatusTransferItemExtIEsExtContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeBearersSubjectToStatusTransferItemExtIEsValueCompareS1APProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeBearersSubjectToStatusTransferItemIEValueCaptureS1APProtocolIESingleContainer(v *BearersSubjectToStatusTransferItemIEValueProtocolIESingleContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeBearersSubjectToStatusTransferItemIEValueCaptureS1APProtocolIEField(v, s)
	s.End(f, nil, false)
}
func BridgeBearersSubjectToStatusTransferItemIEValueCompareS1APProtocolIESingleContainer(v *BearersSubjectToStatusTransferItemIEValueProtocolIESingleContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeBearersSubjectToStatusTransferItemIEValueCompareS1APProtocolIEField(v, s)
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCellTrafficTraceIEValueCaptureS1APProtocolIEContainer(v *s17.CellTrafficTraceIEContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeCellTrafficTraceIEValueCaptureS1APProtocolIEField(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeCellTrafficTraceIEValueCompareS1APProtocolIEContainer(v *s17.CellTrafficTraceIEContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeCellTrafficTraceIEValueCompareS1APProtocolIEField(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}

// BearersSubjectToStatusTransferItemIEValueProtocolIESingleContainer is the concrete ProtocolIESingleContainer[BearersSubjectToStatusTransferItemIEValue].
type BearersSubjectToStatusTransferItemIEValueProtocolIESingleContainer = BearersSubjectToStatusTransferItemIEField

// UserLocationInformationExtIEsExtContainer is the concrete ProtocolExtensionContainer[UserLocationInformationExtIEsValue].
type UserLocationInformationExtIEsExtContainer []UserLocationInformationExtIEsExtField

// UserLocationInformationExtIEsExtField is the concrete ProtocolExtensionField[UserLocationInformationExtIEsValue].
type UserLocationInformationExtIEsExtField struct {
	withoutReplay  bool
	replay         aper.Snapshot
	stream         aper.WireSpan
	Id             s00.ProtocolExtensionID
	Criticality    s00.Criticality
	ExtensionValue UserLocationInformationExtIEsValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v UserLocationInformationExtIEsExtField) WithoutReplay() UserLocationInformationExtIEsExtField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *UserLocationInformationExtIEsExtField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *UserLocationInformationExtIEsExtField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
func (v *UserLocationInformationExtIEsExtField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolExtensionField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = UserLocationInformationExtIEsExtField{}
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
	var zero UserLocationInformationExtIEsValue

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

// ERABToBeModifyItemBearerModReqExtIEsExtContainer is the concrete ProtocolExtensionContainer[ERABToBeModifyItemBearerModReqExtIEsValue].
type ERABToBeModifyItemBearerModReqExtIEsExtContainer []ERABToBeModifyItemBearerModReqExtIEsExtField

// ERABToBeModifyItemBearerModReqExtIEsExtField is the concrete ProtocolExtensionField[ERABToBeModifyItemBearerModReqExtIEsValue].
type ERABToBeModifyItemBearerModReqExtIEsExtField struct {
	withoutReplay  bool
	replay         aper.Snapshot
	stream         aper.WireSpan
	Id             s00.ProtocolExtensionID
	Criticality    s00.Criticality
	ExtensionValue ERABToBeModifyItemBearerModReqExtIEsValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ERABToBeModifyItemBearerModReqExtIEsExtField) WithoutReplay() ERABToBeModifyItemBearerModReqExtIEsExtField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *ERABToBeModifyItemBearerModReqExtIEsExtField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *ERABToBeModifyItemBearerModReqExtIEsExtField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
func (v *ERABToBeModifyItemBearerModReqExtIEsExtField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolExtensionField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = ERABToBeModifyItemBearerModReqExtIEsExtField{}
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
	var zero ERABToBeModifyItemBearerModReqExtIEsValue

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

// BearersSubjectToStatusTransferItemBearersSubjectToStatusTransferItemIEBinding is the concrete IEBinding[BearersSubjectToStatusTransferItem, BearersSubjectToStatusTransferItemIEValue].
type BearersSubjectToStatusTransferItemBearersSubjectToStatusTransferItemIEBinding struct {
	info   s00.FieldInfo
	codec  BearersSubjectToStatusTransferItemValueCodec
	inject func(BearersSubjectToStatusTransferItem,

	) BearersSubjectToStatusTransferItemIEValue

	get func(*BearersSubjectToStatusTransferItemIEValue,

	) (*BearersSubjectToStatusTransferItem,

		bool)
}

// Info returns the source descriptor for this binding.
func (b BearersSubjectToStatusTransferItemBearersSubjectToStatusTransferItemIEBinding) Info() s00.FieldInfo {
	return b.info
}

// Codec returns the complete value codec for this binding.
func (b BearersSubjectToStatusTransferItemBearersSubjectToStatusTransferItemIEBinding) Codec() BearersSubjectToStatusTransferItemValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b BearersSubjectToStatusTransferItemBearersSubjectToStatusTransferItemIEBinding) New(value BearersSubjectToStatusTransferItem,

) (BearersSubjectToStatusTransferItemIEField, error) {
	if b.inject == nil {
		return BearersSubjectToStatusTransferItemIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return BearersSubjectToStatusTransferItemIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := b.codec.encode(value, false, budget); err != nil {
		return BearersSubjectToStatusTransferItemIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return BearersSubjectToStatusTransferItemIEField{}, aper.OperationError(err, "Value.New")
	}
	return BearersSubjectToStatusTransferItemIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b BearersSubjectToStatusTransferItemBearersSubjectToStatusTransferItemIEBinding) Get(field *BearersSubjectToStatusTransferItemIEField) (*BearersSubjectToStatusTransferItem,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// BearersSubjectToStatusTransferItemValueCodec is the concrete ValueCodec[BearersSubjectToStatusTransferItem].
type BearersSubjectToStatusTransferItemValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (BearersSubjectToStatusTransferItem,

		error)
	encode func(BearersSubjectToStatusTransferItem,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(BearersSubjectToStatusTransferItem, aper.DecodeState,

	) (BearersSubjectToStatusTransferItem, aper.Snapshot,

	)
	compare func(BearersSubjectToStatusTransferItem, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c BearersSubjectToStatusTransferItemValueCodec) New(value BearersSubjectToStatusTransferItem,

) (BearersSubjectToStatusTransferItemAPERValue, error) {
	if c.encode == nil {
		return BearersSubjectToStatusTransferItemAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return BearersSubjectToStatusTransferItemAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return BearersSubjectToStatusTransferItemAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return BearersSubjectToStatusTransferItemAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c BearersSubjectToStatusTransferItemValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (BearersSubjectToStatusTransferItemAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return BearersSubjectToStatusTransferItemAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return BearersSubjectToStatusTransferItemAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return BearersSubjectToStatusTransferItemAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return BearersSubjectToStatusTransferItemAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c BearersSubjectToStatusTransferItemValueCodec) EncodeAPER(value BearersSubjectToStatusTransferItemAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c BearersSubjectToStatusTransferItemValueCodec) encodeBudgetValue(value BearersSubjectToStatusTransferItem,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c BearersSubjectToStatusTransferItemValueCodec) encodeChanged(value BearersSubjectToStatusTransferItem,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// BearersSubjectToStatusTransferItemIEField is the concrete ProtocolIEField[BearersSubjectToStatusTransferItemIEValue].
type BearersSubjectToStatusTransferItemIEField struct {
	withoutReplay bool
	replay        aper.Snapshot
	stream        aper.WireSpan
	Id            s00.ProtocolIEID
	Criticality   s00.Criticality
	Value         BearersSubjectToStatusTransferItemIEValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v BearersSubjectToStatusTransferItemIEField) WithoutReplay() BearersSubjectToStatusTransferItemIEField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *BearersSubjectToStatusTransferItemIEField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *BearersSubjectToStatusTransferItemIEField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
func (v *BearersSubjectToStatusTransferItemIEField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolIEField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = BearersSubjectToStatusTransferItemIEField{}
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
	var zero BearersSubjectToStatusTransferItemIEValue

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

// UserLocationInformationExtIEsPSCellInformationExtBinding is the concrete ExtensionBinding[PSCellInformation, UserLocationInformationExtIEsValue].
type UserLocationInformationExtIEsPSCellInformationExtBinding struct {
	info   s00.ExtensionInfo
	codec  s20.PSCellInformationValueCodec
	inject func(s20.PSCellInformation,

	) UserLocationInformationExtIEsValue

	get func(*UserLocationInformationExtIEsValue,

	) (*s20.PSCellInformation,

		bool)
}

// Info returns the source descriptor for this binding.
func (b UserLocationInformationExtIEsPSCellInformationExtBinding) Info() s00.ExtensionInfo {
	return b.info
}

// Codec returns the complete value codec for this binding.
func (b UserLocationInformationExtIEsPSCellInformationExtBinding) Codec() s20.PSCellInformationValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b UserLocationInformationExtIEsPSCellInformationExtBinding) New(value s20.PSCellInformation,

) (UserLocationInformationExtIEsExtField, error) {
	if b.inject == nil {
		return UserLocationInformationExtIEsExtField{}, aper.OperationError(fmt.Errorf("unbound extension binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return UserLocationInformationExtIEsExtField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s20.BridgePSCellInformationValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return UserLocationInformationExtIEsExtField{}, aper.OperationError(fmt.Errorf("extension %d: %w", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return UserLocationInformationExtIEsExtField{}, aper.OperationError(err, "Value.New")
	}
	return UserLocationInformationExtIEsExtField{Id: b.info.ID, Criticality: b.info.Criticality, ExtensionValue: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b UserLocationInformationExtIEsPSCellInformationExtBinding) Get(field *UserLocationInformationExtIEsExtField) (*s20.PSCellInformation,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.ExtensionValue)
}

// UserLocationInformationExtIEsLTENTNTAIInformationExtBinding is the concrete ExtensionBinding[LTENTNTAIInformation, UserLocationInformationExtIEsValue].
type UserLocationInformationExtIEsLTENTNTAIInformationExtBinding struct {
	info   s00.ExtensionInfo
	codec  s18.LTENTNTAIInformationValueCodec
	inject func(s18.LTENTNTAIInformation,

	) UserLocationInformationExtIEsValue

	get func(*UserLocationInformationExtIEsValue,

	) (*s18.LTENTNTAIInformation,

		bool)
}

// Info returns the source descriptor for this binding.
func (b UserLocationInformationExtIEsLTENTNTAIInformationExtBinding) Info() s00.ExtensionInfo {
	return b.info
}

// Codec returns the complete value codec for this binding.
func (b UserLocationInformationExtIEsLTENTNTAIInformationExtBinding) Codec() s18.LTENTNTAIInformationValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b UserLocationInformationExtIEsLTENTNTAIInformationExtBinding) New(value s18.LTENTNTAIInformation,

) (UserLocationInformationExtIEsExtField, error) {
	if b.inject == nil {
		return UserLocationInformationExtIEsExtField{}, aper.OperationError(fmt.Errorf("unbound extension binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return UserLocationInformationExtIEsExtField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s18.BridgeLTENTNTAIInformationValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return UserLocationInformationExtIEsExtField{}, aper.OperationError(fmt.Errorf("extension %d: %w", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return UserLocationInformationExtIEsExtField{}, aper.OperationError(err, "Value.New")
	}
	return UserLocationInformationExtIEsExtField{Id: b.info.ID, Criticality: b.info.Criticality, ExtensionValue: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b UserLocationInformationExtIEsLTENTNTAIInformationExtBinding) Get(field *UserLocationInformationExtIEsExtField) (*s18.LTENTNTAIInformation,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.ExtensionValue)
}

// ERABToBeModifyItemBearerModReqExtIEsTransportInformationExtBinding is the concrete ExtensionBinding[TransportInformation, ERABToBeModifyItemBearerModReqExtIEsValue].
type ERABToBeModifyItemBearerModReqExtIEsTransportInformationExtBinding struct {
	info   s00.ExtensionInfo
	codec  TransportInformationValueCodec
	inject func(TransportInformation,

	) ERABToBeModifyItemBearerModReqExtIEsValue

	get func(*ERABToBeModifyItemBearerModReqExtIEsValue,

	) (*TransportInformation,

		bool)
}

// Info returns the source descriptor for this binding.
func (b ERABToBeModifyItemBearerModReqExtIEsTransportInformationExtBinding) Info() s00.ExtensionInfo {
	return b.info
}

// Codec returns the complete value codec for this binding.
func (b ERABToBeModifyItemBearerModReqExtIEsTransportInformationExtBinding) Codec() TransportInformationValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b ERABToBeModifyItemBearerModReqExtIEsTransportInformationExtBinding) New(value TransportInformation,

) (ERABToBeModifyItemBearerModReqExtIEsExtField, error) {
	if b.inject == nil {
		return ERABToBeModifyItemBearerModReqExtIEsExtField{}, aper.OperationError(fmt.Errorf("unbound extension binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ERABToBeModifyItemBearerModReqExtIEsExtField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := b.codec.encode(value, false, budget); err != nil {
		return ERABToBeModifyItemBearerModReqExtIEsExtField{}, aper.OperationError(fmt.Errorf("extension %d: %w", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return ERABToBeModifyItemBearerModReqExtIEsExtField{}, aper.OperationError(err, "Value.New")
	}
	return ERABToBeModifyItemBearerModReqExtIEsExtField{Id: b.info.ID, Criticality: b.info.Criticality, ExtensionValue: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b ERABToBeModifyItemBearerModReqExtIEsTransportInformationExtBinding) Get(field *ERABToBeModifyItemBearerModReqExtIEsExtField) (*TransportInformation,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.ExtensionValue)
}

// TransportInformationValueCodec is the concrete ValueCodec[TransportInformation].
type TransportInformationValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (TransportInformation,

		error)
	encode func(TransportInformation,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(TransportInformation, aper.DecodeState,

	) (TransportInformation, aper.Snapshot,

	)
	compare func(TransportInformation, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c TransportInformationValueCodec) New(value TransportInformation,

) (TransportInformationAPERValue, error) {
	if c.encode == nil {
		return TransportInformationAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return TransportInformationAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return TransportInformationAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return TransportInformationAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c TransportInformationValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (TransportInformationAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return TransportInformationAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return TransportInformationAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return TransportInformationAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return TransportInformationAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c TransportInformationValueCodec) EncodeAPER(value TransportInformationAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c TransportInformationValueCodec) encodeBudgetValue(value TransportInformation,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c TransportInformationValueCodec) encodeChanged(value TransportInformation,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ENBStatusTransferMMEUES1APIDIEBinding is the concrete IEBinding[MMEUES1APID, ENBStatusTransferIEValue].
type ENBStatusTransferMMEUES1APIDIEBinding struct {
	info   s00.FieldInfo
	codec  s01.MMEUES1APIDValueCodec
	inject func(s00.MMEUES1APID,

	) ENBStatusTransferIEValue

	get func(*ENBStatusTransferIEValue,

	) (*s00.MMEUES1APID,

		bool)
}

// Info returns the source descriptor for this binding.
func (b ENBStatusTransferMMEUES1APIDIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b ENBStatusTransferMMEUES1APIDIEBinding) Codec() s01.MMEUES1APIDValueCodec { return b.codec }

// New validates a source value and constructs its bound field.
func (b ENBStatusTransferMMEUES1APIDIEBinding) New(value s00.MMEUES1APID,

) (ENBStatusTransferIEField, error) {
	if b.inject == nil {
		return ENBStatusTransferIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ENBStatusTransferIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s01.BridgeMMEUES1APIDValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return ENBStatusTransferIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return ENBStatusTransferIEField{}, aper.OperationError(err, "Value.New")
	}
	return ENBStatusTransferIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b ENBStatusTransferMMEUES1APIDIEBinding) Get(field *ENBStatusTransferIEField) (*s00.MMEUES1APID,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// ENBStatusTransferENBUES1APIDIEBinding is the concrete IEBinding[ENBUES1APID, ENBStatusTransferIEValue].
type ENBStatusTransferENBUES1APIDIEBinding struct {
	info   s00.FieldInfo
	codec  s00.ENBUES1APIDValueCodec
	inject func(s00.ENBUES1APID,

	) ENBStatusTransferIEValue

	get func(*ENBStatusTransferIEValue,

	) (*s00.ENBUES1APID,

		bool)
}

// Info returns the source descriptor for this binding.
func (b ENBStatusTransferENBUES1APIDIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b ENBStatusTransferENBUES1APIDIEBinding) Codec() s00.ENBUES1APIDValueCodec { return b.codec }

// New validates a source value and constructs its bound field.
func (b ENBStatusTransferENBUES1APIDIEBinding) New(value s00.ENBUES1APID,

) (ENBStatusTransferIEField, error) {
	if b.inject == nil {
		return ENBStatusTransferIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ENBStatusTransferIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s00.BridgeENBUES1APIDValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return ENBStatusTransferIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return ENBStatusTransferIEField{}, aper.OperationError(err, "Value.New")
	}
	return ENBStatusTransferIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b ENBStatusTransferENBUES1APIDIEBinding) Get(field *ENBStatusTransferIEField) (*s00.ENBUES1APID,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// ENBStatusTransferENBStatusTransferTransparentContainerIEBinding is the concrete IEBinding[ENBStatusTransferTransparentContainer, ENBStatusTransferIEValue].
type ENBStatusTransferENBStatusTransferTransparentContainerIEBinding struct {
	info   s00.FieldInfo
	codec  ENBStatusTransferTransparentContainerValueCodec
	inject func(ENBStatusTransferTransparentContainer,

	) ENBStatusTransferIEValue

	get func(*ENBStatusTransferIEValue,

	) (*ENBStatusTransferTransparentContainer,

		bool)
}

// Info returns the source descriptor for this binding.
func (b ENBStatusTransferENBStatusTransferTransparentContainerIEBinding) Info() s00.FieldInfo {
	return b.info
}

// Codec returns the complete value codec for this binding.
func (b ENBStatusTransferENBStatusTransferTransparentContainerIEBinding) Codec() ENBStatusTransferTransparentContainerValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b ENBStatusTransferENBStatusTransferTransparentContainerIEBinding) New(value ENBStatusTransferTransparentContainer,

) (ENBStatusTransferIEField, error) {
	if b.inject == nil {
		return ENBStatusTransferIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ENBStatusTransferIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := b.codec.encode(value, false, budget); err != nil {
		return ENBStatusTransferIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return ENBStatusTransferIEField{}, aper.OperationError(err, "Value.New")
	}
	return ENBStatusTransferIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b ENBStatusTransferENBStatusTransferTransparentContainerIEBinding) Get(field *ENBStatusTransferIEField) (*ENBStatusTransferTransparentContainer,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// ENBStatusTransferTransparentContainerValueCodec is the concrete ValueCodec[ENBStatusTransferTransparentContainer].
type ENBStatusTransferTransparentContainerValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ENBStatusTransferTransparentContainer,

		error)
	encode func(ENBStatusTransferTransparentContainer,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ENBStatusTransferTransparentContainer, aper.DecodeState,

	) (ENBStatusTransferTransparentContainer, aper.Snapshot,

	)
	compare func(ENBStatusTransferTransparentContainer, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ENBStatusTransferTransparentContainerValueCodec) New(value ENBStatusTransferTransparentContainer,

) (ENBStatusTransferTransparentContainerAPERValue, error) {
	if c.encode == nil {
		return ENBStatusTransferTransparentContainerAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ENBStatusTransferTransparentContainerAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ENBStatusTransferTransparentContainerAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ENBStatusTransferTransparentContainerAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ENBStatusTransferTransparentContainerValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ENBStatusTransferTransparentContainerAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ENBStatusTransferTransparentContainerAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ENBStatusTransferTransparentContainerAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ENBStatusTransferTransparentContainerAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ENBStatusTransferTransparentContainerAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ENBStatusTransferTransparentContainerValueCodec) EncodeAPER(value ENBStatusTransferTransparentContainerAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c ENBStatusTransferTransparentContainerValueCodec) encodeBudgetValue(value ENBStatusTransferTransparentContainer,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ENBStatusTransferTransparentContainerValueCodec) encodeChanged(value ENBStatusTransferTransparentContainer,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// MMEStatusTransferENBUES1APIDIEBinding is the concrete IEBinding[ENBUES1APID, MMEStatusTransferIEValue].
type MMEStatusTransferENBUES1APIDIEBinding struct {
	info   s00.FieldInfo
	codec  s00.ENBUES1APIDValueCodec
	inject func(s00.ENBUES1APID,

	) MMEStatusTransferIEValue

	get func(*MMEStatusTransferIEValue,

	) (*s00.ENBUES1APID,

		bool)
}

// Info returns the source descriptor for this binding.
func (b MMEStatusTransferENBUES1APIDIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b MMEStatusTransferENBUES1APIDIEBinding) Codec() s00.ENBUES1APIDValueCodec { return b.codec }

// New validates a source value and constructs its bound field.
func (b MMEStatusTransferENBUES1APIDIEBinding) New(value s00.ENBUES1APID,

) (MMEStatusTransferIEField, error) {
	if b.inject == nil {
		return MMEStatusTransferIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return MMEStatusTransferIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s00.BridgeENBUES1APIDValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return MMEStatusTransferIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return MMEStatusTransferIEField{}, aper.OperationError(err, "Value.New")
	}
	return MMEStatusTransferIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b MMEStatusTransferENBUES1APIDIEBinding) Get(field *MMEStatusTransferIEField) (*s00.ENBUES1APID,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// MMEStatusTransferENBStatusTransferTransparentContainerIEBinding is the concrete IEBinding[ENBStatusTransferTransparentContainer, MMEStatusTransferIEValue].
type MMEStatusTransferENBStatusTransferTransparentContainerIEBinding struct {
	info   s00.FieldInfo
	codec  ENBStatusTransferTransparentContainerValueCodec
	inject func(ENBStatusTransferTransparentContainer,

	) MMEStatusTransferIEValue

	get func(*MMEStatusTransferIEValue,

	) (*ENBStatusTransferTransparentContainer,

		bool)
}

// Info returns the source descriptor for this binding.
func (b MMEStatusTransferENBStatusTransferTransparentContainerIEBinding) Info() s00.FieldInfo {
	return b.info
}

// Codec returns the complete value codec for this binding.
func (b MMEStatusTransferENBStatusTransferTransparentContainerIEBinding) Codec() ENBStatusTransferTransparentContainerValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b MMEStatusTransferENBStatusTransferTransparentContainerIEBinding) New(value ENBStatusTransferTransparentContainer,

) (MMEStatusTransferIEField, error) {
	if b.inject == nil {
		return MMEStatusTransferIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return MMEStatusTransferIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := b.codec.encode(value, false, budget); err != nil {
		return MMEStatusTransferIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return MMEStatusTransferIEField{}, aper.OperationError(err, "Value.New")
	}
	return MMEStatusTransferIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b MMEStatusTransferENBStatusTransferTransparentContainerIEBinding) Get(field *MMEStatusTransferIEField) (*ENBStatusTransferTransparentContainer,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// TraceFailureIndicationMMEUES1APIDIEBinding is the concrete IEBinding[MMEUES1APID, TraceFailureIndicationIEValue].
type TraceFailureIndicationMMEUES1APIDIEBinding struct {
	info   s00.FieldInfo
	codec  s01.MMEUES1APIDValueCodec
	inject func(s00.MMEUES1APID,

	) s20.TraceFailureIndicationIEValue

	get func(*s20.TraceFailureIndicationIEValue,

	) (*s00.MMEUES1APID,

		bool)
}

// Info returns the source descriptor for this binding.
func (b TraceFailureIndicationMMEUES1APIDIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b TraceFailureIndicationMMEUES1APIDIEBinding) Codec() s01.MMEUES1APIDValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b TraceFailureIndicationMMEUES1APIDIEBinding) New(value s00.MMEUES1APID,

) (s20.TraceFailureIndicationIEField, error) {
	if b.inject == nil {
		return s20.TraceFailureIndicationIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return s20.TraceFailureIndicationIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s01.BridgeMMEUES1APIDValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return s20.TraceFailureIndicationIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return s20.TraceFailureIndicationIEField{}, aper.OperationError(err, "Value.New")
	}
	return s20.TraceFailureIndicationIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b TraceFailureIndicationMMEUES1APIDIEBinding) Get(field *s20.TraceFailureIndicationIEField) (*s00.MMEUES1APID,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// UEContextModificationIndicationMMEUES1APIDIEBinding is the concrete IEBinding[MMEUES1APID, UEContextModificationIndicationIEValue].
type UEContextModificationIndicationMMEUES1APIDIEBinding struct {
	info   s00.FieldInfo
	codec  s01.MMEUES1APIDValueCodec
	inject func(s00.MMEUES1APID,

	) UEContextModificationIndicationIEValue

	get func(*UEContextModificationIndicationIEValue,

	) (*s00.MMEUES1APID,

		bool)
}

// Info returns the source descriptor for this binding.
func (b UEContextModificationIndicationMMEUES1APIDIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b UEContextModificationIndicationMMEUES1APIDIEBinding) Codec() s01.MMEUES1APIDValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b UEContextModificationIndicationMMEUES1APIDIEBinding) New(value s00.MMEUES1APID,

) (UEContextModificationIndicationIEField, error) {
	if b.inject == nil {
		return UEContextModificationIndicationIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return UEContextModificationIndicationIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s01.BridgeMMEUES1APIDValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return UEContextModificationIndicationIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return UEContextModificationIndicationIEField{}, aper.OperationError(err, "Value.New")
	}
	return UEContextModificationIndicationIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b UEContextModificationIndicationMMEUES1APIDIEBinding) Get(field *UEContextModificationIndicationIEField) (*s00.MMEUES1APID,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// UEContextModificationIndicationENBUES1APIDIEBinding is the concrete IEBinding[ENBUES1APID, UEContextModificationIndicationIEValue].
type UEContextModificationIndicationENBUES1APIDIEBinding struct {
	info   s00.FieldInfo
	codec  s00.ENBUES1APIDValueCodec
	inject func(s00.ENBUES1APID,

	) UEContextModificationIndicationIEValue

	get func(*UEContextModificationIndicationIEValue,

	) (*s00.ENBUES1APID,

		bool)
}

// Info returns the source descriptor for this binding.
func (b UEContextModificationIndicationENBUES1APIDIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b UEContextModificationIndicationENBUES1APIDIEBinding) Codec() s00.ENBUES1APIDValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b UEContextModificationIndicationENBUES1APIDIEBinding) New(value s00.ENBUES1APID,

) (UEContextModificationIndicationIEField, error) {
	if b.inject == nil {
		return UEContextModificationIndicationIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return UEContextModificationIndicationIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s00.BridgeENBUES1APIDValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return UEContextModificationIndicationIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return UEContextModificationIndicationIEField{}, aper.OperationError(err, "Value.New")
	}
	return UEContextModificationIndicationIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b UEContextModificationIndicationENBUES1APIDIEBinding) Get(field *UEContextModificationIndicationIEField) (*s00.ENBUES1APID,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// UEContextModificationIndicationCSGMembershipInfoIEBinding is the concrete IEBinding[CSGMembershipInfo, UEContextModificationIndicationIEValue].
type UEContextModificationIndicationCSGMembershipInfoIEBinding struct {
	info   s00.FieldInfo
	codec  s14.CSGMembershipInfoValueCodec
	inject func(s14.CSGMembershipInfo,

	) UEContextModificationIndicationIEValue

	get func(*UEContextModificationIndicationIEValue,

	) (*s14.CSGMembershipInfo,

		bool)
}

// Info returns the source descriptor for this binding.
func (b UEContextModificationIndicationCSGMembershipInfoIEBinding) Info() s00.FieldInfo {
	return b.info
}

// Codec returns the complete value codec for this binding.
func (b UEContextModificationIndicationCSGMembershipInfoIEBinding) Codec() s14.CSGMembershipInfoValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b UEContextModificationIndicationCSGMembershipInfoIEBinding) New(value s14.CSGMembershipInfo,

) (UEContextModificationIndicationIEField, error) {
	if b.inject == nil {
		return UEContextModificationIndicationIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return UEContextModificationIndicationIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s14.BridgeCSGMembershipInfoValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return UEContextModificationIndicationIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return UEContextModificationIndicationIEField{}, aper.OperationError(err, "Value.New")
	}
	return UEContextModificationIndicationIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b UEContextModificationIndicationCSGMembershipInfoIEBinding) Get(field *UEContextModificationIndicationIEField) (*s14.CSGMembershipInfo,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// UplinkS1cdma2000tunnellingMMEUES1APIDIEBinding is the concrete IEBinding[MMEUES1APID, UplinkS1cdma2000tunnellingIEValue].
type UplinkS1cdma2000tunnellingMMEUES1APIDIEBinding struct {
	info   s00.FieldInfo
	codec  s01.MMEUES1APIDValueCodec
	inject func(s00.MMEUES1APID,

	) UplinkS1cdma2000tunnellingIEValue

	get func(*UplinkS1cdma2000tunnellingIEValue,

	) (*s00.MMEUES1APID,

		bool)
}

// Info returns the source descriptor for this binding.
func (b UplinkS1cdma2000tunnellingMMEUES1APIDIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b UplinkS1cdma2000tunnellingMMEUES1APIDIEBinding) Codec() s01.MMEUES1APIDValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b UplinkS1cdma2000tunnellingMMEUES1APIDIEBinding) New(value s00.MMEUES1APID,

) (UplinkS1cdma2000tunnellingIEField, error) {
	if b.inject == nil {
		return UplinkS1cdma2000tunnellingIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return UplinkS1cdma2000tunnellingIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s01.BridgeMMEUES1APIDValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return UplinkS1cdma2000tunnellingIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return UplinkS1cdma2000tunnellingIEField{}, aper.OperationError(err, "Value.New")
	}
	return UplinkS1cdma2000tunnellingIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b UplinkS1cdma2000tunnellingMMEUES1APIDIEBinding) Get(field *UplinkS1cdma2000tunnellingIEField) (*s00.MMEUES1APID,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// UplinkS1cdma2000tunnellingENBUES1APIDIEBinding is the concrete IEBinding[ENBUES1APID, UplinkS1cdma2000tunnellingIEValue].
type UplinkS1cdma2000tunnellingENBUES1APIDIEBinding struct {
	info   s00.FieldInfo
	codec  s00.ENBUES1APIDValueCodec
	inject func(s00.ENBUES1APID,

	) UplinkS1cdma2000tunnellingIEValue

	get func(*UplinkS1cdma2000tunnellingIEValue,

	) (*s00.ENBUES1APID,

		bool)
}

// Info returns the source descriptor for this binding.
func (b UplinkS1cdma2000tunnellingENBUES1APIDIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b UplinkS1cdma2000tunnellingENBUES1APIDIEBinding) Codec() s00.ENBUES1APIDValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b UplinkS1cdma2000tunnellingENBUES1APIDIEBinding) New(value s00.ENBUES1APID,

) (UplinkS1cdma2000tunnellingIEField, error) {
	if b.inject == nil {
		return UplinkS1cdma2000tunnellingIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return UplinkS1cdma2000tunnellingIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s00.BridgeENBUES1APIDValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return UplinkS1cdma2000tunnellingIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return UplinkS1cdma2000tunnellingIEField{}, aper.OperationError(err, "Value.New")
	}
	return UplinkS1cdma2000tunnellingIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b UplinkS1cdma2000tunnellingENBUES1APIDIEBinding) Get(field *UplinkS1cdma2000tunnellingIEField) (*s00.ENBUES1APID,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// UplinkS1cdma2000tunnellingCdma2000RATTypeIEBinding is the concrete IEBinding[Cdma2000RATType, UplinkS1cdma2000tunnellingIEValue].
type UplinkS1cdma2000tunnellingCdma2000RATTypeIEBinding struct {
	info   s00.FieldInfo
	codec  s00.Cdma2000RATTypeValueCodec
	inject func(s00.Cdma2000RATType,

	) UplinkS1cdma2000tunnellingIEValue

	get func(*UplinkS1cdma2000tunnellingIEValue,

	) (*s00.Cdma2000RATType,

		bool)
}

// Info returns the source descriptor for this binding.
func (b UplinkS1cdma2000tunnellingCdma2000RATTypeIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b UplinkS1cdma2000tunnellingCdma2000RATTypeIEBinding) Codec() s00.Cdma2000RATTypeValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b UplinkS1cdma2000tunnellingCdma2000RATTypeIEBinding) New(value s00.Cdma2000RATType,

) (UplinkS1cdma2000tunnellingIEField, error) {
	if b.inject == nil {
		return UplinkS1cdma2000tunnellingIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return UplinkS1cdma2000tunnellingIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s00.BridgeCdma2000RATTypeValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return UplinkS1cdma2000tunnellingIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return UplinkS1cdma2000tunnellingIEField{}, aper.OperationError(err, "Value.New")
	}
	return UplinkS1cdma2000tunnellingIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b UplinkS1cdma2000tunnellingCdma2000RATTypeIEBinding) Get(field *UplinkS1cdma2000tunnellingIEField) (*s00.Cdma2000RATType,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// UplinkS1cdma2000tunnellingCdma2000SectorIDIEBinding is the concrete IEBinding[Cdma2000SectorID, UplinkS1cdma2000tunnellingIEValue].
type UplinkS1cdma2000tunnellingCdma2000SectorIDIEBinding struct {
	info   s00.FieldInfo
	codec  s00.Cdma2000SectorIDValueCodec
	inject func(s00.Cdma2000SectorID,

	) UplinkS1cdma2000tunnellingIEValue

	get func(*UplinkS1cdma2000tunnellingIEValue,

	) (*s00.Cdma2000SectorID,

		bool)
}

// Info returns the source descriptor for this binding.
func (b UplinkS1cdma2000tunnellingCdma2000SectorIDIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b UplinkS1cdma2000tunnellingCdma2000SectorIDIEBinding) Codec() s00.Cdma2000SectorIDValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b UplinkS1cdma2000tunnellingCdma2000SectorIDIEBinding) New(value s00.Cdma2000SectorID,

) (UplinkS1cdma2000tunnellingIEField, error) {
	if b.inject == nil {
		return UplinkS1cdma2000tunnellingIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return UplinkS1cdma2000tunnellingIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s00.BridgeCdma2000SectorIDValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return UplinkS1cdma2000tunnellingIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return UplinkS1cdma2000tunnellingIEField{}, aper.OperationError(err, "Value.New")
	}
	return UplinkS1cdma2000tunnellingIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b UplinkS1cdma2000tunnellingCdma2000SectorIDIEBinding) Get(field *UplinkS1cdma2000tunnellingIEField) (*s00.Cdma2000SectorID,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// UplinkS1cdma2000tunnellingCdma2000HORequiredIndicationIEBinding is the concrete IEBinding[Cdma2000HORequiredIndication, UplinkS1cdma2000tunnellingIEValue].
type UplinkS1cdma2000tunnellingCdma2000HORequiredIndicationIEBinding struct {
	info   s00.FieldInfo
	codec  s00.Cdma2000HORequiredIndicationValueCodec
	inject func(s00.Cdma2000HORequiredIndication,

	) UplinkS1cdma2000tunnellingIEValue

	get func(*UplinkS1cdma2000tunnellingIEValue,

	) (*s00.Cdma2000HORequiredIndication,

		bool)
}

// Info returns the source descriptor for this binding.
func (b UplinkS1cdma2000tunnellingCdma2000HORequiredIndicationIEBinding) Info() s00.FieldInfo {
	return b.info
}

// Codec returns the complete value codec for this binding.
func (b UplinkS1cdma2000tunnellingCdma2000HORequiredIndicationIEBinding) Codec() s00.Cdma2000HORequiredIndicationValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b UplinkS1cdma2000tunnellingCdma2000HORequiredIndicationIEBinding) New(value s00.Cdma2000HORequiredIndication,

) (UplinkS1cdma2000tunnellingIEField, error) {
	if b.inject == nil {
		return UplinkS1cdma2000tunnellingIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return UplinkS1cdma2000tunnellingIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s00.BridgeCdma2000HORequiredIndicationValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return UplinkS1cdma2000tunnellingIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return UplinkS1cdma2000tunnellingIEField{}, aper.OperationError(err, "Value.New")
	}
	return UplinkS1cdma2000tunnellingIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b UplinkS1cdma2000tunnellingCdma2000HORequiredIndicationIEBinding) Get(field *UplinkS1cdma2000tunnellingIEField) (*s00.Cdma2000HORequiredIndication,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// UplinkS1cdma2000tunnellingCdma2000OneXSRVCCInfoIEBinding is the concrete IEBinding[Cdma2000OneXSRVCCInfo, UplinkS1cdma2000tunnellingIEValue].
type UplinkS1cdma2000tunnellingCdma2000OneXSRVCCInfoIEBinding struct {
	info   s00.FieldInfo
	codec  s14.Cdma2000OneXSRVCCInfoValueCodec
	inject func(s14.Cdma2000OneXSRVCCInfo,

	) UplinkS1cdma2000tunnellingIEValue

	get func(*UplinkS1cdma2000tunnellingIEValue,

	) (*s14.Cdma2000OneXSRVCCInfo,

		bool)
}

// Info returns the source descriptor for this binding.
func (b UplinkS1cdma2000tunnellingCdma2000OneXSRVCCInfoIEBinding) Info() s00.FieldInfo {
	return b.info
}

// Codec returns the complete value codec for this binding.
func (b UplinkS1cdma2000tunnellingCdma2000OneXSRVCCInfoIEBinding) Codec() s14.Cdma2000OneXSRVCCInfoValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b UplinkS1cdma2000tunnellingCdma2000OneXSRVCCInfoIEBinding) New(value s14.Cdma2000OneXSRVCCInfo,

) (UplinkS1cdma2000tunnellingIEField, error) {
	if b.inject == nil {
		return UplinkS1cdma2000tunnellingIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return UplinkS1cdma2000tunnellingIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s14.BridgeCdma2000OneXSRVCCInfoValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return UplinkS1cdma2000tunnellingIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return UplinkS1cdma2000tunnellingIEField{}, aper.OperationError(err, "Value.New")
	}
	return UplinkS1cdma2000tunnellingIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b UplinkS1cdma2000tunnellingCdma2000OneXSRVCCInfoIEBinding) Get(field *UplinkS1cdma2000tunnellingIEField) (*s14.Cdma2000OneXSRVCCInfo,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// UplinkS1cdma2000tunnellingCdma2000OneXRANDIEBinding is the concrete IEBinding[Cdma2000OneXRAND, UplinkS1cdma2000tunnellingIEValue].
type UplinkS1cdma2000tunnellingCdma2000OneXRANDIEBinding struct {
	info   s00.FieldInfo
	codec  s00.Cdma2000OneXRANDValueCodec
	inject func(s00.Cdma2000OneXRAND,

	) UplinkS1cdma2000tunnellingIEValue

	get func(*UplinkS1cdma2000tunnellingIEValue,

	) (*s00.Cdma2000OneXRAND,

		bool)
}

// Info returns the source descriptor for this binding.
func (b UplinkS1cdma2000tunnellingCdma2000OneXRANDIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b UplinkS1cdma2000tunnellingCdma2000OneXRANDIEBinding) Codec() s00.Cdma2000OneXRANDValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b UplinkS1cdma2000tunnellingCdma2000OneXRANDIEBinding) New(value s00.Cdma2000OneXRAND,

) (UplinkS1cdma2000tunnellingIEField, error) {
	if b.inject == nil {
		return UplinkS1cdma2000tunnellingIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return UplinkS1cdma2000tunnellingIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s00.BridgeCdma2000OneXRANDValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return UplinkS1cdma2000tunnellingIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return UplinkS1cdma2000tunnellingIEField{}, aper.OperationError(err, "Value.New")
	}
	return UplinkS1cdma2000tunnellingIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b UplinkS1cdma2000tunnellingCdma2000OneXRANDIEBinding) Get(field *UplinkS1cdma2000tunnellingIEField) (*s00.Cdma2000OneXRAND,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// UplinkS1cdma2000tunnellingCdma2000PDUIEBinding is the concrete IEBinding[Cdma2000PDU, UplinkS1cdma2000tunnellingIEValue].
type UplinkS1cdma2000tunnellingCdma2000PDUIEBinding struct {
	info   s00.FieldInfo
	codec  s00.Cdma2000PDUValueCodec
	inject func(s00.Cdma2000PDU,

	) UplinkS1cdma2000tunnellingIEValue

	get func(*UplinkS1cdma2000tunnellingIEValue,

	) (*s00.Cdma2000PDU,

		bool)
}

// Info returns the source descriptor for this binding.
func (b UplinkS1cdma2000tunnellingCdma2000PDUIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b UplinkS1cdma2000tunnellingCdma2000PDUIEBinding) Codec() s00.Cdma2000PDUValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b UplinkS1cdma2000tunnellingCdma2000PDUIEBinding) New(value s00.Cdma2000PDU,

) (UplinkS1cdma2000tunnellingIEField, error) {
	if b.inject == nil {
		return UplinkS1cdma2000tunnellingIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return UplinkS1cdma2000tunnellingIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s00.BridgeCdma2000PDUValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return UplinkS1cdma2000tunnellingIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return UplinkS1cdma2000tunnellingIEField{}, aper.OperationError(err, "Value.New")
	}
	return UplinkS1cdma2000tunnellingIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b UplinkS1cdma2000tunnellingCdma2000PDUIEBinding) Get(field *UplinkS1cdma2000tunnellingIEField) (*s00.Cdma2000PDU,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// UplinkS1cdma2000tunnellingEUTRANRoundTripDelayEstimationInfoIEBinding is the concrete IEBinding[EUTRANRoundTripDelayEstimationInfo, UplinkS1cdma2000tunnellingIEValue].
type UplinkS1cdma2000tunnellingEUTRANRoundTripDelayEstimationInfoIEBinding struct {
	info   s00.FieldInfo
	codec  s00.EUTRANRoundTripDelayEstimationInfoValueCodec
	inject func(s00.EUTRANRoundTripDelayEstimationInfo,

	) UplinkS1cdma2000tunnellingIEValue

	get func(*UplinkS1cdma2000tunnellingIEValue,

	) (*s00.EUTRANRoundTripDelayEstimationInfo,

		bool)
}

// Info returns the source descriptor for this binding.
func (b UplinkS1cdma2000tunnellingEUTRANRoundTripDelayEstimationInfoIEBinding) Info() s00.FieldInfo {
	return b.info
}

// Codec returns the complete value codec for this binding.
func (b UplinkS1cdma2000tunnellingEUTRANRoundTripDelayEstimationInfoIEBinding) Codec() s00.EUTRANRoundTripDelayEstimationInfoValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b UplinkS1cdma2000tunnellingEUTRANRoundTripDelayEstimationInfoIEBinding) New(value s00.EUTRANRoundTripDelayEstimationInfo,

) (UplinkS1cdma2000tunnellingIEField, error) {
	if b.inject == nil {
		return UplinkS1cdma2000tunnellingIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return UplinkS1cdma2000tunnellingIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s00.BridgeEUTRANRoundTripDelayEstimationInfoValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return UplinkS1cdma2000tunnellingIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return UplinkS1cdma2000tunnellingIEField{}, aper.OperationError(err, "Value.New")
	}
	return UplinkS1cdma2000tunnellingIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b UplinkS1cdma2000tunnellingEUTRANRoundTripDelayEstimationInfoIEBinding) Get(field *UplinkS1cdma2000tunnellingIEField) (*s00.EUTRANRoundTripDelayEstimationInfo,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// BearersSubjectToStatusTransferListValueCodec is the concrete ValueCodec[BearersSubjectToStatusTransferList].
type BearersSubjectToStatusTransferListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (BearersSubjectToStatusTransferList,

		error)
	encode func(BearersSubjectToStatusTransferList,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(BearersSubjectToStatusTransferList, aper.DecodeState,

	) (BearersSubjectToStatusTransferList, aper.Snapshot,

	)
	compare func(BearersSubjectToStatusTransferList, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c BearersSubjectToStatusTransferListValueCodec) New(value BearersSubjectToStatusTransferList,

) (BearersSubjectToStatusTransferListAPERValue, error) {
	if c.encode == nil {
		return BearersSubjectToStatusTransferListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return BearersSubjectToStatusTransferListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return BearersSubjectToStatusTransferListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return BearersSubjectToStatusTransferListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c BearersSubjectToStatusTransferListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (BearersSubjectToStatusTransferListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return BearersSubjectToStatusTransferListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return BearersSubjectToStatusTransferListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return BearersSubjectToStatusTransferListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return BearersSubjectToStatusTransferListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c BearersSubjectToStatusTransferListValueCodec) EncodeAPER(value BearersSubjectToStatusTransferListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c BearersSubjectToStatusTransferListValueCodec) encodeBudgetValue(value BearersSubjectToStatusTransferList,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c BearersSubjectToStatusTransferListValueCodec) encodeChanged(value BearersSubjectToStatusTransferList,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// CellActivationResponseValueCodec is the concrete ValueCodec[CellActivationResponse].
type CellActivationResponseValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (CellActivationResponse,

		error)
	encode func(CellActivationResponse,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(CellActivationResponse, aper.DecodeState,

	) (CellActivationResponse, aper.Snapshot,

	)
	compare func(CellActivationResponse, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c CellActivationResponseValueCodec) New(value CellActivationResponse,

) (CellActivationResponseAPERValue, error) {
	if c.encode == nil {
		return CellActivationResponseAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return CellActivationResponseAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return CellActivationResponseAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return CellActivationResponseAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c CellActivationResponseValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (CellActivationResponseAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return CellActivationResponseAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return CellActivationResponseAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return CellActivationResponseAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return CellActivationResponseAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c CellActivationResponseValueCodec) EncodeAPER(value CellActivationResponseAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c CellActivationResponseValueCodec) encodeBudgetValue(value CellActivationResponse,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c CellActivationResponseValueCodec) encodeChanged(value CellActivationResponse,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// CellTrafficTraceValueCodec is the concrete ValueCodec[CellTrafficTrace].
type CellTrafficTraceValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (CellTrafficTrace,

		error)
	encode func(CellTrafficTrace,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(CellTrafficTrace, aper.DecodeState,

	) (CellTrafficTrace, aper.Snapshot,

	)
	compare func(CellTrafficTrace, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c CellTrafficTraceValueCodec) New(value CellTrafficTrace,

) (CellTrafficTraceAPERValue, error) {
	if c.encode == nil {
		return CellTrafficTraceAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return CellTrafficTraceAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return CellTrafficTraceAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return CellTrafficTraceAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c CellTrafficTraceValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (CellTrafficTraceAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return CellTrafficTraceAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return CellTrafficTraceAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return CellTrafficTraceAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return CellTrafficTraceAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c CellTrafficTraceValueCodec) EncodeAPER(value CellTrafficTraceAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c CellTrafficTraceValueCodec) encodeBudgetValue(value CellTrafficTrace,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c CellTrafficTraceValueCodec) encodeChanged(value CellTrafficTrace,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// BearersSubjectToStatusTransferItemIEContainer is the concrete ProtocolIEContainer[BearersSubjectToStatusTransferItemIEValue].
type BearersSubjectToStatusTransferItemIEContainer []BearersSubjectToStatusTransferItemIEField

func BearersSubjectToDLDiscardingItemIEValueERABIEContainerListCodec(table s00.BearersSubjectToDLDiscardingItemIEValueIETable) s15.BearersSubjectToDLDiscardingItemIEValueERABIEContainerListValueCodec {
	codec := BearersSubjectToDLDiscardingItemIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if *s15.BridgeBearersSubjectToDLDiscardingItemIEContainerValueCodecFieldDecode(&codec) == nil {
		return s15.BearersSubjectToDLDiscardingItemIEValueERABIEContainerListValueCodec{}
	}
	return func() s15.BearersSubjectToDLDiscardingItemIEValueERABIEContainerListValueCodec {
		sealed := s15.BearersSubjectToDLDiscardingItemIEValueERABIEContainerListValueCodec{}
		*s15.BridgeBearersSubjectToDLDiscardingItemIEValueERABIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s15.BearersSubjectToDLDiscardingItemIEValueERABIEContainerList, error) {
			value, err := (*s15.BridgeBearersSubjectToDLDiscardingItemIEContainerValueCodecFieldDecode(&codec))(data, options)
			return s15.BearersSubjectToDLDiscardingItemIEValueERABIEContainerList(value), err
		}
		*s15.BridgeBearersSubjectToDLDiscardingItemIEValueERABIEContainerListValueCodecFieldEncode(&sealed) = func(value s15.BearersSubjectToDLDiscardingItemIEValueERABIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s15.BridgeBearersSubjectToDLDiscardingItemIEContainerValueCodecFieldEncode(&codec))(s15.BearersSubjectToDLDiscardingItemIEContainer(value), fresh, budget)
		}
		*s15.BridgeBearersSubjectToDLDiscardingItemIEValueERABIEContainerListValueCodecFieldCapture(&sealed) = func(v s15.BearersSubjectToDLDiscardingItemIEValueERABIEContainerList, options aper.DecodeState) (s15.BearersSubjectToDLDiscardingItemIEValueERABIEContainerList, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeBearersSubjectToDLDiscardingItemIEValueCaptureS1APERABIEContainerList(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s15.BridgeBearersSubjectToDLDiscardingItemIEValueERABIEContainerListValueCodecFieldCompare(&sealed) = func(v s15.BearersSubjectToDLDiscardingItemIEValueERABIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeBearersSubjectToDLDiscardingItemIEValueCompareS1APERABIEContainerList(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s15.BridgeBearersSubjectToDLDiscardingItemIEValueERABIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ERABIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}
func BearersSubjectToEarlyStatusTransferItemIEValueERABIEContainerListCodec(table s00.BearersSubjectToEarlyStatusTransferItemIEValueIETable) s15.BearersSubjectToEarlyStatusTransferItemIEValueERABIEContainerListValueCodec {
	codec := BearersSubjectToEarlyStatusTransferItemIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if *s15.BridgeBearersSubjectToEarlyStatusTransferItemIEContainerValueCodecFieldDecode(&codec) == nil {
		return s15.BearersSubjectToEarlyStatusTransferItemIEValueERABIEContainerListValueCodec{}
	}
	return func() s15.BearersSubjectToEarlyStatusTransferItemIEValueERABIEContainerListValueCodec {
		sealed := s15.BearersSubjectToEarlyStatusTransferItemIEValueERABIEContainerListValueCodec{}
		*s15.BridgeBearersSubjectToEarlyStatusTransferItemIEValueERABIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s15.BearersSubjectToEarlyStatusTransferItemIEValueERABIEContainerList, error) {
			value, err := (*s15.BridgeBearersSubjectToEarlyStatusTransferItemIEContainerValueCodecFieldDecode(&codec))(data, options)
			return s15.BearersSubjectToEarlyStatusTransferItemIEValueERABIEContainerList(value), err
		}
		*s15.BridgeBearersSubjectToEarlyStatusTransferItemIEValueERABIEContainerListValueCodecFieldEncode(&sealed) = func(value s15.BearersSubjectToEarlyStatusTransferItemIEValueERABIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s15.BridgeBearersSubjectToEarlyStatusTransferItemIEContainerValueCodecFieldEncode(&codec))(s15.BearersSubjectToEarlyStatusTransferItemIEContainer(value), fresh, budget)
		}
		*s15.BridgeBearersSubjectToEarlyStatusTransferItemIEValueERABIEContainerListValueCodecFieldCapture(&sealed) = func(v s15.BearersSubjectToEarlyStatusTransferItemIEValueERABIEContainerList, options aper.DecodeState) (s15.BearersSubjectToEarlyStatusTransferItemIEValueERABIEContainerList, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeBearersSubjectToEarlyStatusTransferItemIEValueCaptureS1APERABIEContainerList(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s15.BridgeBearersSubjectToEarlyStatusTransferItemIEValueERABIEContainerListValueCodecFieldCompare(&sealed) = func(v s15.BearersSubjectToEarlyStatusTransferItemIEValueERABIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeBearersSubjectToEarlyStatusTransferItemIEValueCompareS1APERABIEContainerList(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s15.BridgeBearersSubjectToEarlyStatusTransferItemIEValueERABIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ERABIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}
func BearersSubjectToStatusTransferItemIEValueERABIEContainerListCodec(table s00.BearersSubjectToStatusTransferItemIEValueIETable) BearersSubjectToStatusTransferItemIEValueERABIEContainerListValueCodec {
	codec := BearersSubjectToStatusTransferItemIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if codec.decode == nil {
		return BearersSubjectToStatusTransferItemIEValueERABIEContainerListValueCodec{}
	}
	return BearersSubjectToStatusTransferItemIEValueERABIEContainerListValueCodec{decode: func(data []byte, options aper.DecodeState) (BearersSubjectToStatusTransferItemIEValueERABIEContainerList, error) {
		value, err := codec.decode(data, options)
		return BearersSubjectToStatusTransferItemIEValueERABIEContainerList(value), err
	}, encode: func(value BearersSubjectToStatusTransferItemIEValueERABIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return codec.encode(BearersSubjectToStatusTransferItemIEContainer(value), fresh, budget)
	}, capture: func(v BearersSubjectToStatusTransferItemIEValueERABIEContainerList, options aper.DecodeState) (BearersSubjectToStatusTransferItemIEValueERABIEContainerList, aper.Snapshot) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeBearersSubjectToStatusTransferItemIEValueCaptureS1APERABIEContainerList(&v, &s)
		var root aper.Snapshot
		s.End(f, &root, false)
		return v, root
	}, compare: func(v BearersSubjectToStatusTransferItemIEValueERABIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
	) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		BridgeBearersSubjectToStatusTransferItemIEValueCompareS1APERABIEContainerList(&v, &s)
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
func CellTrafficTraceIEValueERABIEContainerListCodec(table s00.CellTrafficTraceIEValueIETable) s17.CellTrafficTraceIEValueERABIEContainerListValueCodec {
	codec := CellTrafficTraceIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if *s17.BridgeCellTrafficTraceIEContainerValueCodecFieldDecode(&codec) == nil {
		return s17.CellTrafficTraceIEValueERABIEContainerListValueCodec{}
	}
	return func() s17.CellTrafficTraceIEValueERABIEContainerListValueCodec {
		sealed := s17.CellTrafficTraceIEValueERABIEContainerListValueCodec{}
		*s17.BridgeCellTrafficTraceIEValueERABIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s17.CellTrafficTraceIEValueERABIEContainerList, error) {
			value, err := (*s17.BridgeCellTrafficTraceIEContainerValueCodecFieldDecode(&codec))(data, options)
			return s17.CellTrafficTraceIEValueERABIEContainerList(value), err
		}
		*s17.BridgeCellTrafficTraceIEValueERABIEContainerListValueCodecFieldEncode(&sealed) = func(value s17.CellTrafficTraceIEValueERABIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s17.BridgeCellTrafficTraceIEContainerValueCodecFieldEncode(&codec))(s17.CellTrafficTraceIEContainer(value), fresh, budget)
		}
		*s17.BridgeCellTrafficTraceIEValueERABIEContainerListValueCodecFieldCapture(&sealed) = func(v s17.CellTrafficTraceIEValueERABIEContainerList, options aper.DecodeState) (s17.CellTrafficTraceIEValueERABIEContainerList, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeCellTrafficTraceIEValueCaptureS1APERABIEContainerList(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s17.BridgeCellTrafficTraceIEValueERABIEContainerListValueCodecFieldCompare(&sealed) = func(v s17.CellTrafficTraceIEValueERABIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeCellTrafficTraceIEValueCompareS1APERABIEContainerList(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s17.BridgeCellTrafficTraceIEValueERABIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ERABIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}
func BearersSubjectToStatusTransferItemExtIEsValueExtensionFieldTableCodec(table s00.BearersSubjectToStatusTransferItemExtIEsValueExtensionTable) s14.BearersSubjectToStatusTransferItemExtIEsExtFieldValueCodec {
	if !*s00.BridgeBearersSubjectToStatusTransferItemExtIEsValueExtensionTableFieldBound(&table) {
		return s14.BearersSubjectToStatusTransferItemExtIEsExtFieldValueCodec{}
	}
	return func() s14.BearersSubjectToStatusTransferItemExtIEsExtFieldValueCodec {
		sealed := s14.BearersSubjectToStatusTransferItemExtIEsExtFieldValueCodec{}
		*s14.BridgeBearersSubjectToStatusTransferItemExtIEsExtFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s14.BearersSubjectToStatusTransferItemExtIEsExtField, error) {
			var field s14.BearersSubjectToStatusTransferItemExtIEsExtField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s14.BridgeBearersSubjectToStatusTransferItemExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, err
			}
			if _, err := aper.CaptureFinalBits(bb, "ProtocolExtensionField"); err != nil {
				return field, err
			}
			return field, nil
		}
		*s14.BridgeBearersSubjectToStatusTransferItemExtIEsExtFieldValueCodecFieldEncode(&sealed) = func(field s14.BearersSubjectToStatusTransferItemExtIEsExtField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s14.BridgeBearersSubjectToStatusTransferItemExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s14.BridgeBearersSubjectToStatusTransferItemExtIEsExtFieldValueCodecFieldCapture(&sealed) = func(v s14.BearersSubjectToStatusTransferItemExtIEsExtField, options aper.DecodeState) (s14.BearersSubjectToStatusTransferItemExtIEsExtField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeBearersSubjectToStatusTransferItemExtIEsValueCaptureS1APProtocolExtensionField(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,
				false)
			return v, root
		}
		*s14.BridgeBearersSubjectToStatusTransferItemExtIEsExtFieldValueCodecFieldCompare(&sealed) = func(v s14.BearersSubjectToStatusTransferItemExtIEsExtField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeBearersSubjectToStatusTransferItemExtIEsValueCompareS1APProtocolExtensionField(&v, &s)
			s.End(f, root,

				false)
			return s.Plan(), s.BudgetValue()
		}
		*s14.BridgeBearersSubjectToStatusTransferItemExtIEsExtFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}
func BearersSubjectToStatusTransferItemExtIEsValueExtensionTableCodec(table s00.BearersSubjectToStatusTransferItemExtIEsValueExtensionTable, bounds aper.ListBounds) s14.BearersSubjectToStatusTransferItemExtIEsExtContainerValueCodec {
	if !*s00.BridgeBearersSubjectToStatusTransferItemExtIEsValueExtensionTableFieldBound(&table) {
		return s14.BearersSubjectToStatusTransferItemExtIEsExtContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s14.BearersSubjectToStatusTransferItemExtIEsExtContainerValueCodec {
		sealed := s14.BearersSubjectToStatusTransferItemExtIEsExtContainerValueCodec{}
		*s14.BridgeBearersSubjectToStatusTransferItemExtIEsExtContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s14.BearersSubjectToStatusTransferItemExtIEsExtContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s14.BearersSubjectToStatusTransferItemExtIEsExtContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s14.BearersSubjectToStatusTransferItemExtIEsExtField
					if err := s14.BridgeBearersSubjectToStatusTransferItemExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
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
		*s14.BridgeBearersSubjectToStatusTransferItemExtIEsExtContainerValueCodecFieldEncode(&sealed) = func(fields s14.BearersSubjectToStatusTransferItemExtIEsExtContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s14.BridgeBearersSubjectToStatusTransferItemExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
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
		*s14.BridgeBearersSubjectToStatusTransferItemExtIEsExtContainerValueCodecFieldCapture(&sealed) = func(v s14.BearersSubjectToStatusTransferItemExtIEsExtContainer, options aper.DecodeState) (s14.BearersSubjectToStatusTransferItemExtIEsExtContainer, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeBearersSubjectToStatusTransferItemExtIEsValueCaptureS1APProtocolExtensionContainer(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s14.BridgeBearersSubjectToStatusTransferItemExtIEsExtContainerValueCodecFieldCompare(&sealed) = func(v s14.BearersSubjectToStatusTransferItemExtIEsExtContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.
				Begin()
			BridgeBearersSubjectToStatusTransferItemExtIEsValueCompareS1APProtocolExtensionContainer(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s14.BridgeBearersSubjectToStatusTransferItemExtIEsExtContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}
func BearersSubjectToDLDiscardingItemIEValueIEFieldTableCodec(table s00.BearersSubjectToDLDiscardingItemIEValueIETable) s15.BearersSubjectToDLDiscardingItemIEFieldValueCodec {
	if !*s00.BridgeBearersSubjectToDLDiscardingItemIEValueIETableFieldBound(&table) {
		return s15.BearersSubjectToDLDiscardingItemIEFieldValueCodec{}
	}
	return func() s15.BearersSubjectToDLDiscardingItemIEFieldValueCodec {
		sealed := s15.BearersSubjectToDLDiscardingItemIEFieldValueCodec{}
		*s15.BridgeBearersSubjectToDLDiscardingItemIEFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s15.BearersSubjectToDLDiscardingItemIEField, error) {
			var field s15.BearersSubjectToDLDiscardingItemIEField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s15.BridgeBearersSubjectToDLDiscardingItemIEFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, err
			}
			if _, err := aper.CaptureFinalBits(bb, "ProtocolIEField"); err != nil {
				return field, err
			}
			return field, nil
		}
		*s15.BridgeBearersSubjectToDLDiscardingItemIEFieldValueCodecFieldEncode(&sealed) = func(field s15.BearersSubjectToDLDiscardingItemIEField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s15.BridgeBearersSubjectToDLDiscardingItemIEFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s15.BridgeBearersSubjectToDLDiscardingItemIEFieldValueCodecFieldCapture(&sealed) = func(v s15.BearersSubjectToDLDiscardingItemIEField, options aper.DecodeState) (s15.BearersSubjectToDLDiscardingItemIEField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeBearersSubjectToDLDiscardingItemIEValueCaptureS1APProtocolIEField(&v,
				&s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v,
				root
		}
		*s15.BridgeBearersSubjectToDLDiscardingItemIEFieldValueCodecFieldCompare(&sealed) = func(v s15.BearersSubjectToDLDiscardingItemIEField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeBearersSubjectToDLDiscardingItemIEValueCompareS1APProtocolIEField(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s15.BridgeBearersSubjectToDLDiscardingItemIEFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}
func BearersSubjectToEarlyStatusTransferItemIEValueIEFieldTableCodec(table s00.BearersSubjectToEarlyStatusTransferItemIEValueIETable) s15.BearersSubjectToEarlyStatusTransferItemIEFieldValueCodec {
	if !*s00.BridgeBearersSubjectToEarlyStatusTransferItemIEValueIETableFieldBound(&table) {
		return s15.BearersSubjectToEarlyStatusTransferItemIEFieldValueCodec{}
	}
	return func() s15.BearersSubjectToEarlyStatusTransferItemIEFieldValueCodec {
		sealed := s15.BearersSubjectToEarlyStatusTransferItemIEFieldValueCodec{}
		*s15.BridgeBearersSubjectToEarlyStatusTransferItemIEFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s15.BearersSubjectToEarlyStatusTransferItemIEField, error) {
			var field s15.BearersSubjectToEarlyStatusTransferItemIEField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s15.BridgeBearersSubjectToEarlyStatusTransferItemIEFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, err
			}
			if _, err := aper.CaptureFinalBits(bb, "ProtocolIEField"); err != nil {
				return field, err
			}
			return field, nil
		}
		*s15.BridgeBearersSubjectToEarlyStatusTransferItemIEFieldValueCodecFieldEncode(&sealed) = func(field s15.BearersSubjectToEarlyStatusTransferItemIEField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s15.BridgeBearersSubjectToEarlyStatusTransferItemIEFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s15.BridgeBearersSubjectToEarlyStatusTransferItemIEFieldValueCodecFieldCapture(&sealed) = func(v s15.BearersSubjectToEarlyStatusTransferItemIEField, options aper.DecodeState) (s15.BearersSubjectToEarlyStatusTransferItemIEField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeBearersSubjectToEarlyStatusTransferItemIEValueCaptureS1APProtocolIEField(&v,
				&s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v,
				root
		}
		*s15.BridgeBearersSubjectToEarlyStatusTransferItemIEFieldValueCodecFieldCompare(&sealed) = func(v s15.BearersSubjectToEarlyStatusTransferItemIEField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeBearersSubjectToEarlyStatusTransferItemIEValueCompareS1APProtocolIEField(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s15.BridgeBearersSubjectToEarlyStatusTransferItemIEFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}
func BearersSubjectToStatusTransferItemIEValueIEFieldTableCodec(table s00.BearersSubjectToStatusTransferItemIEValueIETable) BearersSubjectToStatusTransferItemIEFieldValueCodec {
	if !*s00.BridgeBearersSubjectToStatusTransferItemIEValueIETableFieldBound(&table) {
		return BearersSubjectToStatusTransferItemIEFieldValueCodec{}
	}
	return BearersSubjectToStatusTransferItemIEFieldValueCodec{decode: func(data []byte, options aper.DecodeState) (BearersSubjectToStatusTransferItemIEField, error) {
		var field BearersSubjectToStatusTransferItemIEField
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
	}, encode: func(field BearersSubjectToStatusTransferItemIEField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		bb := aper.NewBudgetBuffer(budget)
		if err := field.marshalAPERTo(bb, fresh); err != nil {
			return nil, err
		}
		return bb.CompleteBytes(), nil
	}, capture: func(v BearersSubjectToStatusTransferItemIEField, options aper.DecodeState) (BearersSubjectToStatusTransferItemIEField, aper.Snapshot,
	) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeBearersSubjectToStatusTransferItemIEValueCaptureS1APProtocolIEField(&v,
			&s)
		var root aper.Snapshot
		s.End(f, &root, false)
		return v,
			root
	}, compare: func(v BearersSubjectToStatusTransferItemIEField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

	) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		BridgeBearersSubjectToStatusTransferItemIEValueCompareS1APProtocolIEField(&v, &s)
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
func CellTrafficTraceIEValueIEFieldTableCodec(table s00.CellTrafficTraceIEValueIETable) s17.CellTrafficTraceIEFieldValueCodec {
	if !*s00.BridgeCellTrafficTraceIEValueIETableFieldBound(&table) {
		return s17.CellTrafficTraceIEFieldValueCodec{}
	}
	return func() s17.CellTrafficTraceIEFieldValueCodec {
		sealed := s17.CellTrafficTraceIEFieldValueCodec{}
		*s17.BridgeCellTrafficTraceIEFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s17.CellTrafficTraceIEField, error) {
			var field s17.CellTrafficTraceIEField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s17.BridgeCellTrafficTraceIEFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, err
			}
			if _, err := aper.CaptureFinalBits(bb, "ProtocolIEField"); err != nil {
				return field, err
			}
			return field, nil
		}
		*s17.BridgeCellTrafficTraceIEFieldValueCodecFieldEncode(&sealed) = func(field s17.CellTrafficTraceIEField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s17.BridgeCellTrafficTraceIEFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s17.BridgeCellTrafficTraceIEFieldValueCodecFieldCapture(&sealed) = func(v s17.CellTrafficTraceIEField, options aper.DecodeState) (s17.CellTrafficTraceIEField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeCellTrafficTraceIEValueCaptureS1APProtocolIEField(&v,
				&s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v,
				root
		}
		*s17.BridgeCellTrafficTraceIEFieldValueCodecFieldCompare(&sealed) = func(v s17.CellTrafficTraceIEField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeCellTrafficTraceIEValueCompareS1APProtocolIEField(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s17.BridgeCellTrafficTraceIEFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}
func BearersSubjectToDLDiscardingItemIEValueIETableCodec(table s00.BearersSubjectToDLDiscardingItemIEValueIETable, bounds aper.ListBounds) s15.BearersSubjectToDLDiscardingItemIEContainerValueCodec {
	if !*s00.BridgeBearersSubjectToDLDiscardingItemIEValueIETableFieldBound(&table) {
		return s15.BearersSubjectToDLDiscardingItemIEContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s15.BearersSubjectToDLDiscardingItemIEContainerValueCodec {
		sealed := s15.BearersSubjectToDLDiscardingItemIEContainerValueCodec{}
		*s15.BridgeBearersSubjectToDLDiscardingItemIEContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s15.BearersSubjectToDLDiscardingItemIEContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s15.BearersSubjectToDLDiscardingItemIEContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s15.BearersSubjectToDLDiscardingItemIEField
					if err := s15.BridgeBearersSubjectToDLDiscardingItemIEFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
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
		*s15.BridgeBearersSubjectToDLDiscardingItemIEContainerValueCodecFieldEncode(&sealed) = func(fields s15.BearersSubjectToDLDiscardingItemIEContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s15.BridgeBearersSubjectToDLDiscardingItemIEFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
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
		*s15.BridgeBearersSubjectToDLDiscardingItemIEContainerValueCodecFieldCapture(&sealed) = func(v s15.BearersSubjectToDLDiscardingItemIEContainer, options aper.DecodeState) (s15.BearersSubjectToDLDiscardingItemIEContainer, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeBearersSubjectToDLDiscardingItemIEValueCaptureS1APProtocolIEContainer(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s15.BridgeBearersSubjectToDLDiscardingItemIEContainerValueCodecFieldCompare(&sealed) = func(v s15.BearersSubjectToDLDiscardingItemIEContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeBearersSubjectToDLDiscardingItemIEValueCompareS1APProtocolIEContainer(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s15.BridgeBearersSubjectToDLDiscardingItemIEContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}
func BearersSubjectToEarlyStatusTransferItemIEValueIETableCodec(table s00.BearersSubjectToEarlyStatusTransferItemIEValueIETable, bounds aper.ListBounds) s15.BearersSubjectToEarlyStatusTransferItemIEContainerValueCodec {
	if !*s00.BridgeBearersSubjectToEarlyStatusTransferItemIEValueIETableFieldBound(&table) {
		return s15.BearersSubjectToEarlyStatusTransferItemIEContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s15.BearersSubjectToEarlyStatusTransferItemIEContainerValueCodec {
		sealed := s15.BearersSubjectToEarlyStatusTransferItemIEContainerValueCodec{}
		*s15.BridgeBearersSubjectToEarlyStatusTransferItemIEContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s15.BearersSubjectToEarlyStatusTransferItemIEContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s15.BearersSubjectToEarlyStatusTransferItemIEContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s15.BearersSubjectToEarlyStatusTransferItemIEField
					if err := s15.BridgeBearersSubjectToEarlyStatusTransferItemIEFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
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
		*s15.BridgeBearersSubjectToEarlyStatusTransferItemIEContainerValueCodecFieldEncode(&sealed) = func(fields s15.BearersSubjectToEarlyStatusTransferItemIEContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s15.BridgeBearersSubjectToEarlyStatusTransferItemIEFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
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
		*s15.BridgeBearersSubjectToEarlyStatusTransferItemIEContainerValueCodecFieldCapture(&sealed) = func(v s15.BearersSubjectToEarlyStatusTransferItemIEContainer, options aper.DecodeState) (s15.BearersSubjectToEarlyStatusTransferItemIEContainer, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeBearersSubjectToEarlyStatusTransferItemIEValueCaptureS1APProtocolIEContainer(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s15.BridgeBearersSubjectToEarlyStatusTransferItemIEContainerValueCodecFieldCompare(&sealed) = func(v s15.BearersSubjectToEarlyStatusTransferItemIEContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeBearersSubjectToEarlyStatusTransferItemIEValueCompareS1APProtocolIEContainer(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s15.BridgeBearersSubjectToEarlyStatusTransferItemIEContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}
func BearersSubjectToStatusTransferItemIEValueIETableCodec(table s00.BearersSubjectToStatusTransferItemIEValueIETable, bounds aper.ListBounds) BearersSubjectToStatusTransferItemIEContainerValueCodec {
	if !*s00.BridgeBearersSubjectToStatusTransferItemIEValueIETableFieldBound(&table) {
		return BearersSubjectToStatusTransferItemIEContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return BearersSubjectToStatusTransferItemIEContainerValueCodec{decode: func(data []byte, options aper.DecodeState) (BearersSubjectToStatusTransferItemIEContainer, error) {
		bb := aper.NewCompleteDecodeBuffer(data, options)
		if err := bb.SetDecodeOptionsAligned(options); err != nil {
			return nil, err
		}
		var fields BearersSubjectToStatusTransferItemIEContainer
		_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
			for i := int64(0); i < length; i++ {
				var field BearersSubjectToStatusTransferItemIEField
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
		encode: func(fields BearersSubjectToStatusTransferItemIEContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
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
		}, capture: func(v BearersSubjectToStatusTransferItemIEContainer, options aper.DecodeState) (BearersSubjectToStatusTransferItemIEContainer, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeBearersSubjectToStatusTransferItemIEValueCaptureS1APProtocolIEContainer(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}, compare: func(v BearersSubjectToStatusTransferItemIEContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeBearersSubjectToStatusTransferItemIEValueCompareS1APProtocolIEContainer(&v, &s)
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
func CellTrafficTraceIEValueIETableCodec(table s00.CellTrafficTraceIEValueIETable, bounds aper.ListBounds) s17.CellTrafficTraceIEContainerValueCodec {
	if !*s00.BridgeCellTrafficTraceIEValueIETableFieldBound(&table) {
		return s17.CellTrafficTraceIEContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s17.CellTrafficTraceIEContainerValueCodec {
		sealed := s17.CellTrafficTraceIEContainerValueCodec{}
		*s17.BridgeCellTrafficTraceIEContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s17.CellTrafficTraceIEContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s17.CellTrafficTraceIEContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s17.CellTrafficTraceIEField
					if err := s17.BridgeCellTrafficTraceIEFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
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
		*s17.BridgeCellTrafficTraceIEContainerValueCodecFieldEncode(&sealed) = func(fields s17.CellTrafficTraceIEContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s17.BridgeCellTrafficTraceIEFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
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
		*s17.BridgeCellTrafficTraceIEContainerValueCodecFieldCapture(&sealed) = func(v s17.CellTrafficTraceIEContainer, options aper.DecodeState) (s17.CellTrafficTraceIEContainer, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeCellTrafficTraceIEValueCaptureS1APProtocolIEContainer(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s17.BridgeCellTrafficTraceIEContainerValueCodecFieldCompare(&sealed) = func(v s17.CellTrafficTraceIEContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeCellTrafficTraceIEValueCompareS1APProtocolIEContainer(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s17.BridgeCellTrafficTraceIEContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}
func BearersSubjectToDLDiscardingItemIEValueProtocolErrorIEContainerListCodec(table s00.BearersSubjectToDLDiscardingItemIEValueIETable) s15.BearersSubjectToDLDiscardingItemIEValueProtocolErrorIEContainerListValueCodec {
	codec := BearersSubjectToDLDiscardingItemIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if *s15.BridgeBearersSubjectToDLDiscardingItemIEContainerValueCodecFieldDecode(&codec) == nil {
		return s15.BearersSubjectToDLDiscardingItemIEValueProtocolErrorIEContainerListValueCodec{}
	}
	return func() s15.BearersSubjectToDLDiscardingItemIEValueProtocolErrorIEContainerListValueCodec {
		sealed := s15.BearersSubjectToDLDiscardingItemIEValueProtocolErrorIEContainerListValueCodec{}
		*s15.BridgeBearersSubjectToDLDiscardingItemIEValueProtocolErrorIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s15.BearersSubjectToDLDiscardingItemIEValueProtocolErrorIEContainerList, error) {
			value, err := (*s15.BridgeBearersSubjectToDLDiscardingItemIEContainerValueCodecFieldDecode(&codec))(data, options)
			return s15.BearersSubjectToDLDiscardingItemIEValueProtocolErrorIEContainerList(value), err
		}
		*s15.BridgeBearersSubjectToDLDiscardingItemIEValueProtocolErrorIEContainerListValueCodecFieldEncode(&sealed) = func(value s15.BearersSubjectToDLDiscardingItemIEValueProtocolErrorIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s15.BridgeBearersSubjectToDLDiscardingItemIEContainerValueCodecFieldEncode(&codec))(s15.BearersSubjectToDLDiscardingItemIEContainer(value), fresh, budget)
		}
		*s15.BridgeBearersSubjectToDLDiscardingItemIEValueProtocolErrorIEContainerListValueCodecFieldCapture(&sealed) = func(v s15.BearersSubjectToDLDiscardingItemIEValueProtocolErrorIEContainerList, options aper.DecodeState) (s15.BearersSubjectToDLDiscardingItemIEValueProtocolErrorIEContainerList, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeBearersSubjectToDLDiscardingItemIEValueCaptureS1APProtocolErrorIEContainerList(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s15.BridgeBearersSubjectToDLDiscardingItemIEValueProtocolErrorIEContainerListValueCodecFieldCompare(&sealed) = func(v s15.BearersSubjectToDLDiscardingItemIEValueProtocolErrorIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f :=
				s.
					Begin()
			BridgeBearersSubjectToDLDiscardingItemIEValueCompareS1APProtocolErrorIEContainerList(&v, &s)
			s.
				End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s15.BridgeBearersSubjectToDLDiscardingItemIEValueProtocolErrorIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolErrorIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}
func BearersSubjectToEarlyStatusTransferItemIEValueProtocolErrorIEContainerListCodec(table s00.BearersSubjectToEarlyStatusTransferItemIEValueIETable) s15.BearersSubjectToEarlyStatusTransferItemIEValueProtocolErrorIEContainerListValueCodec {
	codec := BearersSubjectToEarlyStatusTransferItemIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if *s15.BridgeBearersSubjectToEarlyStatusTransferItemIEContainerValueCodecFieldDecode(&codec) == nil {
		return s15.BearersSubjectToEarlyStatusTransferItemIEValueProtocolErrorIEContainerListValueCodec{}
	}
	return func() s15.BearersSubjectToEarlyStatusTransferItemIEValueProtocolErrorIEContainerListValueCodec {
		sealed := s15.BearersSubjectToEarlyStatusTransferItemIEValueProtocolErrorIEContainerListValueCodec{}
		*s15.BridgeBearersSubjectToEarlyStatusTransferItemIEValueProtocolErrorIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s15.BearersSubjectToEarlyStatusTransferItemIEValueProtocolErrorIEContainerList, error) {
			value, err := (*s15.BridgeBearersSubjectToEarlyStatusTransferItemIEContainerValueCodecFieldDecode(&codec))(data, options)
			return s15.BearersSubjectToEarlyStatusTransferItemIEValueProtocolErrorIEContainerList(value), err
		}
		*s15.BridgeBearersSubjectToEarlyStatusTransferItemIEValueProtocolErrorIEContainerListValueCodecFieldEncode(&sealed) = func(value s15.BearersSubjectToEarlyStatusTransferItemIEValueProtocolErrorIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s15.BridgeBearersSubjectToEarlyStatusTransferItemIEContainerValueCodecFieldEncode(&codec))(s15.BearersSubjectToEarlyStatusTransferItemIEContainer(value), fresh, budget)
		}
		*s15.BridgeBearersSubjectToEarlyStatusTransferItemIEValueProtocolErrorIEContainerListValueCodecFieldCapture(&sealed) = func(v s15.BearersSubjectToEarlyStatusTransferItemIEValueProtocolErrorIEContainerList, options aper.DecodeState) (s15.BearersSubjectToEarlyStatusTransferItemIEValueProtocolErrorIEContainerList, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeBearersSubjectToEarlyStatusTransferItemIEValueCaptureS1APProtocolErrorIEContainerList(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s15.BridgeBearersSubjectToEarlyStatusTransferItemIEValueProtocolErrorIEContainerListValueCodecFieldCompare(&sealed) = func(v s15.BearersSubjectToEarlyStatusTransferItemIEValueProtocolErrorIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f :=
				s.
					Begin()
			BridgeBearersSubjectToEarlyStatusTransferItemIEValueCompareS1APProtocolErrorIEContainerList(&v, &s)
			s.
				End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s15.BridgeBearersSubjectToEarlyStatusTransferItemIEValueProtocolErrorIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolErrorIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}
func BearersSubjectToStatusTransferItemIEValueProtocolErrorIEContainerListCodec(table s00.BearersSubjectToStatusTransferItemIEValueIETable) BearersSubjectToStatusTransferItemIEValueProtocolErrorIEContainerListValueCodec {
	codec := BearersSubjectToStatusTransferItemIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if codec.decode == nil {
		return BearersSubjectToStatusTransferItemIEValueProtocolErrorIEContainerListValueCodec{}
	}
	return BearersSubjectToStatusTransferItemIEValueProtocolErrorIEContainerListValueCodec{decode: func(data []byte, options aper.DecodeState) (BearersSubjectToStatusTransferItemIEValueProtocolErrorIEContainerList, error) {
		value, err := codec.decode(data, options)
		return BearersSubjectToStatusTransferItemIEValueProtocolErrorIEContainerList(value), err
	}, encode: func(value BearersSubjectToStatusTransferItemIEValueProtocolErrorIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return codec.encode(BearersSubjectToStatusTransferItemIEContainer(value), fresh, budget)
	}, capture: func(v BearersSubjectToStatusTransferItemIEValueProtocolErrorIEContainerList, options aper.DecodeState) (BearersSubjectToStatusTransferItemIEValueProtocolErrorIEContainerList, aper.Snapshot,
	) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeBearersSubjectToStatusTransferItemIEValueCaptureS1APProtocolErrorIEContainerList(&v, &s)
		var root aper.Snapshot

		s.End(f, &root, false)
		return v, root
	}, compare: func(v BearersSubjectToStatusTransferItemIEValueProtocolErrorIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

	) {
		s := aper.NewSemanticComparison(root, budget)
		f :=
			s.
				Begin()
		BridgeBearersSubjectToStatusTransferItemIEValueCompareS1APProtocolErrorIEContainerList(&v, &s)
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
func CellTrafficTraceIEValueProtocolErrorIEContainerListCodec(table s00.CellTrafficTraceIEValueIETable) s17.CellTrafficTraceIEValueProtocolErrorIEContainerListValueCodec {
	codec := CellTrafficTraceIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if *s17.BridgeCellTrafficTraceIEContainerValueCodecFieldDecode(&codec) == nil {
		return s17.CellTrafficTraceIEValueProtocolErrorIEContainerListValueCodec{}
	}
	return func() s17.CellTrafficTraceIEValueProtocolErrorIEContainerListValueCodec {
		sealed := s17.CellTrafficTraceIEValueProtocolErrorIEContainerListValueCodec{}
		*s17.BridgeCellTrafficTraceIEValueProtocolErrorIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s17.CellTrafficTraceIEValueProtocolErrorIEContainerList, error) {
			value, err := (*s17.BridgeCellTrafficTraceIEContainerValueCodecFieldDecode(&codec))(data, options)
			return s17.CellTrafficTraceIEValueProtocolErrorIEContainerList(value), err
		}
		*s17.BridgeCellTrafficTraceIEValueProtocolErrorIEContainerListValueCodecFieldEncode(&sealed) = func(value s17.CellTrafficTraceIEValueProtocolErrorIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s17.BridgeCellTrafficTraceIEContainerValueCodecFieldEncode(&codec))(s17.CellTrafficTraceIEContainer(value), fresh, budget)
		}
		*s17.BridgeCellTrafficTraceIEValueProtocolErrorIEContainerListValueCodecFieldCapture(&sealed) = func(v s17.CellTrafficTraceIEValueProtocolErrorIEContainerList, options aper.DecodeState) (s17.CellTrafficTraceIEValueProtocolErrorIEContainerList, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeCellTrafficTraceIEValueCaptureS1APProtocolErrorIEContainerList(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s17.BridgeCellTrafficTraceIEValueProtocolErrorIEContainerListValueCodecFieldCompare(&sealed) = func(v s17.CellTrafficTraceIEValueProtocolErrorIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f :=
				s.
					Begin()
			BridgeCellTrafficTraceIEValueCompareS1APProtocolErrorIEContainerList(&v, &s)
			s.
				End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s17.BridgeCellTrafficTraceIEValueProtocolErrorIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolErrorIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}
func BearersSubjectToDLDiscardingItemIEValueProtocolIEContainerListCodec(table s00.BearersSubjectToDLDiscardingItemIEValueIETable, bounds aper.ListBounds) s15.BearersSubjectToDLDiscardingItemIEValueProtocolIEContainerListValueCodec {
	codec := BearersSubjectToDLDiscardingItemIEValueIETableCodec(table, bounds)
	if *s15.BridgeBearersSubjectToDLDiscardingItemIEContainerValueCodecFieldDecode(&codec) == nil {
		return s15.BearersSubjectToDLDiscardingItemIEValueProtocolIEContainerListValueCodec{}
	}
	return func() s15.BearersSubjectToDLDiscardingItemIEValueProtocolIEContainerListValueCodec {
		sealed := s15.BearersSubjectToDLDiscardingItemIEValueProtocolIEContainerListValueCodec{}
		*s15.BridgeBearersSubjectToDLDiscardingItemIEValueProtocolIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s15.BearersSubjectToDLDiscardingItemIEValueProtocolIEContainerList, error) {
			value, err := (*s15.BridgeBearersSubjectToDLDiscardingItemIEContainerValueCodecFieldDecode(&codec))(data, options)
			return s15.BearersSubjectToDLDiscardingItemIEValueProtocolIEContainerList(value), err
		}
		*s15.BridgeBearersSubjectToDLDiscardingItemIEValueProtocolIEContainerListValueCodecFieldEncode(&sealed) = func(value s15.BearersSubjectToDLDiscardingItemIEValueProtocolIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s15.BridgeBearersSubjectToDLDiscardingItemIEContainerValueCodecFieldEncode(&codec))(s15.BearersSubjectToDLDiscardingItemIEContainer(value), fresh, budget)
		}
		*s15.BridgeBearersSubjectToDLDiscardingItemIEValueProtocolIEContainerListValueCodecFieldCapture(&sealed) = func(v s15.BearersSubjectToDLDiscardingItemIEValueProtocolIEContainerList, options aper.DecodeState) (s15.BearersSubjectToDLDiscardingItemIEValueProtocolIEContainerList, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeBearersSubjectToDLDiscardingItemIEValueCaptureS1APProtocolIEContainerList(&v, &s)
			var root aper.Snapshot
			s.End(
				f,
				&root, false)
			return v, root
		}
		*s15.BridgeBearersSubjectToDLDiscardingItemIEValueProtocolIEContainerListValueCodecFieldCompare(&sealed) = func(v s15.BearersSubjectToDLDiscardingItemIEValueProtocolIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeBearersSubjectToDLDiscardingItemIEValueCompareS1APProtocolIEContainerList(&v, &s)
			s.End(f, root,

				false)
			return s.Plan(), s.BudgetValue()
		}
		*s15.BridgeBearersSubjectToDLDiscardingItemIEValueProtocolIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}
func BearersSubjectToEarlyStatusTransferItemIEValueProtocolIEContainerListCodec(table s00.BearersSubjectToEarlyStatusTransferItemIEValueIETable, bounds aper.ListBounds) s15.BearersSubjectToEarlyStatusTransferItemIEValueProtocolIEContainerListValueCodec {
	codec := BearersSubjectToEarlyStatusTransferItemIEValueIETableCodec(table, bounds)
	if *s15.BridgeBearersSubjectToEarlyStatusTransferItemIEContainerValueCodecFieldDecode(&codec) == nil {
		return s15.BearersSubjectToEarlyStatusTransferItemIEValueProtocolIEContainerListValueCodec{}
	}
	return func() s15.BearersSubjectToEarlyStatusTransferItemIEValueProtocolIEContainerListValueCodec {
		sealed := s15.BearersSubjectToEarlyStatusTransferItemIEValueProtocolIEContainerListValueCodec{}
		*s15.BridgeBearersSubjectToEarlyStatusTransferItemIEValueProtocolIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s15.BearersSubjectToEarlyStatusTransferItemIEValueProtocolIEContainerList, error) {
			value, err := (*s15.BridgeBearersSubjectToEarlyStatusTransferItemIEContainerValueCodecFieldDecode(&codec))(data, options)
			return s15.BearersSubjectToEarlyStatusTransferItemIEValueProtocolIEContainerList(value), err
		}
		*s15.BridgeBearersSubjectToEarlyStatusTransferItemIEValueProtocolIEContainerListValueCodecFieldEncode(&sealed) = func(value s15.BearersSubjectToEarlyStatusTransferItemIEValueProtocolIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s15.BridgeBearersSubjectToEarlyStatusTransferItemIEContainerValueCodecFieldEncode(&codec))(s15.BearersSubjectToEarlyStatusTransferItemIEContainer(value), fresh, budget)
		}
		*s15.BridgeBearersSubjectToEarlyStatusTransferItemIEValueProtocolIEContainerListValueCodecFieldCapture(&sealed) = func(v s15.BearersSubjectToEarlyStatusTransferItemIEValueProtocolIEContainerList, options aper.DecodeState) (s15.BearersSubjectToEarlyStatusTransferItemIEValueProtocolIEContainerList, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeBearersSubjectToEarlyStatusTransferItemIEValueCaptureS1APProtocolIEContainerList(&v, &s)
			var root aper.Snapshot
			s.End(
				f,
				&root, false)
			return v, root
		}
		*s15.BridgeBearersSubjectToEarlyStatusTransferItemIEValueProtocolIEContainerListValueCodecFieldCompare(&sealed) = func(v s15.BearersSubjectToEarlyStatusTransferItemIEValueProtocolIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeBearersSubjectToEarlyStatusTransferItemIEValueCompareS1APProtocolIEContainerList(&v, &s)
			s.End(f, root,

				false)
			return s.Plan(), s.BudgetValue()
		}
		*s15.BridgeBearersSubjectToEarlyStatusTransferItemIEValueProtocolIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}
func BearersSubjectToStatusTransferItemIEValueProtocolIEContainerListCodec(table s00.BearersSubjectToStatusTransferItemIEValueIETable, bounds aper.ListBounds) BearersSubjectToStatusTransferItemIEValueProtocolIEContainerListValueCodec {
	codec := BearersSubjectToStatusTransferItemIEValueIETableCodec(table, bounds)
	if codec.decode == nil {
		return BearersSubjectToStatusTransferItemIEValueProtocolIEContainerListValueCodec{}
	}
	return BearersSubjectToStatusTransferItemIEValueProtocolIEContainerListValueCodec{decode: func(data []byte, options aper.DecodeState) (BearersSubjectToStatusTransferItemIEValueProtocolIEContainerList, error) {
		value, err := codec.decode(data, options)
		return BearersSubjectToStatusTransferItemIEValueProtocolIEContainerList(value), err
	}, encode: func(value BearersSubjectToStatusTransferItemIEValueProtocolIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return codec.encode(BearersSubjectToStatusTransferItemIEContainer(value), fresh, budget)
	}, capture: func(v BearersSubjectToStatusTransferItemIEValueProtocolIEContainerList, options aper.DecodeState) (BearersSubjectToStatusTransferItemIEValueProtocolIEContainerList, aper.Snapshot,
	) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeBearersSubjectToStatusTransferItemIEValueCaptureS1APProtocolIEContainerList(&v, &s)
		var root aper.Snapshot
		s.End(
			f,
			&root, false)
		return v, root
	}, compare: func(v BearersSubjectToStatusTransferItemIEValueProtocolIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
	) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		BridgeBearersSubjectToStatusTransferItemIEValueCompareS1APProtocolIEContainerList(&v, &s)
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
func CellTrafficTraceIEValueProtocolIEContainerListCodec(table s00.CellTrafficTraceIEValueIETable, bounds aper.ListBounds) s17.CellTrafficTraceIEValueProtocolIEContainerListValueCodec {
	codec := CellTrafficTraceIEValueIETableCodec(table, bounds)
	if *s17.BridgeCellTrafficTraceIEContainerValueCodecFieldDecode(&codec) == nil {
		return s17.CellTrafficTraceIEValueProtocolIEContainerListValueCodec{}
	}
	return func() s17.CellTrafficTraceIEValueProtocolIEContainerListValueCodec {
		sealed := s17.CellTrafficTraceIEValueProtocolIEContainerListValueCodec{}
		*s17.BridgeCellTrafficTraceIEValueProtocolIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s17.CellTrafficTraceIEValueProtocolIEContainerList, error) {
			value, err := (*s17.BridgeCellTrafficTraceIEContainerValueCodecFieldDecode(&codec))(data, options)
			return s17.CellTrafficTraceIEValueProtocolIEContainerList(value), err
		}
		*s17.BridgeCellTrafficTraceIEValueProtocolIEContainerListValueCodecFieldEncode(&sealed) = func(value s17.CellTrafficTraceIEValueProtocolIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s17.BridgeCellTrafficTraceIEContainerValueCodecFieldEncode(&codec))(s17.CellTrafficTraceIEContainer(value), fresh, budget)
		}
		*s17.BridgeCellTrafficTraceIEValueProtocolIEContainerListValueCodecFieldCapture(&sealed) = func(v s17.CellTrafficTraceIEValueProtocolIEContainerList, options aper.DecodeState) (s17.CellTrafficTraceIEValueProtocolIEContainerList, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeCellTrafficTraceIEValueCaptureS1APProtocolIEContainerList(&v, &s)
			var root aper.Snapshot
			s.End(
				f,
				&root, false)
			return v, root
		}
		*s17.BridgeCellTrafficTraceIEValueProtocolIEContainerListValueCodecFieldCompare(&sealed) = func(v s17.CellTrafficTraceIEValueProtocolIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeCellTrafficTraceIEValueCompareS1APProtocolIEContainerList(&v, &s)
			s.End(f, root,

				false)
			return s.Plan(), s.BudgetValue()
		}
		*s17.BridgeCellTrafficTraceIEValueProtocolIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}

// bearersSubjectToDLDiscardingItemIEValueProtocolOpenValue is the concrete protocolOpenValue[BearersSubjectToDLDiscardingItemIEValue].
type BearersSubjectToDLDiscardingItemIEValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) s15.BearersSubjectToDLDiscardingItemIEValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (s15.BearersSubjectToDLDiscardingItemIEValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

func BridgeBearersSubjectToDLDiscardingItemIEValueCaptureS1APProtocolIEField(v *s15.BearersSubjectToDLDiscardingItemIEField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolIEID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.Value = s15.BridgeBearersSubjectToDLDiscardingItemIEValueMethodCaptureSemantics(v.Value, *s)
	s.End(f, s15.BridgeBearersSubjectToDLDiscardingItemIEFieldFieldReplay(v), *s15.BridgeBearersSubjectToDLDiscardingItemIEFieldFieldWithoutReplay(v))
}
func BridgeBearersSubjectToDLDiscardingItemIEValueCompareS1APProtocolIEField(v *s15.BearersSubjectToDLDiscardingItemIEField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s02.BridgeCompareS1APProtocolIEID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s15.BridgeBearersSubjectToDLDiscardingItemIEValueMethodCompareSemantics(v.Value, *s)
	s.End(f, *s15.BridgeBearersSubjectToDLDiscardingItemIEFieldFieldReplay(v), *s15.BridgeBearersSubjectToDLDiscardingItemIEFieldFieldWithoutReplay(v))
}

// bearersSubjectToEarlyStatusTransferItemIEValueProtocolOpenValue is the concrete protocolOpenValue[BearersSubjectToEarlyStatusTransferItemIEValue].
type BearersSubjectToEarlyStatusTransferItemIEValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) s15.BearersSubjectToEarlyStatusTransferItemIEValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (s15.BearersSubjectToEarlyStatusTransferItemIEValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

func BridgeBearersSubjectToEarlyStatusTransferItemIEValueCaptureS1APProtocolIEField(v *s15.BearersSubjectToEarlyStatusTransferItemIEField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolIEID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.Value = s15.BridgeBearersSubjectToEarlyStatusTransferItemIEValueMethodCaptureSemantics(v.Value, *s)
	s.End(f, s15.BridgeBearersSubjectToEarlyStatusTransferItemIEFieldFieldReplay(v), *s15.BridgeBearersSubjectToEarlyStatusTransferItemIEFieldFieldWithoutReplay(v))
}
func BridgeBearersSubjectToEarlyStatusTransferItemIEValueCompareS1APProtocolIEField(v *s15.BearersSubjectToEarlyStatusTransferItemIEField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s02.BridgeCompareS1APProtocolIEID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s15.BridgeBearersSubjectToEarlyStatusTransferItemIEValueMethodCompareSemantics(v.Value, *s)
	s.End(f, *s15.BridgeBearersSubjectToEarlyStatusTransferItemIEFieldFieldReplay(v), *s15.BridgeBearersSubjectToEarlyStatusTransferItemIEFieldFieldWithoutReplay(v))
}

// bearersSubjectToStatusTransferItemExtIEsValueProtocolOpenValue is the concrete protocolOpenValue[BearersSubjectToStatusTransferItemExtIEsValue].
type BearersSubjectToStatusTransferItemExtIEsValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) s14.BearersSubjectToStatusTransferItemExtIEsValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (s14.BearersSubjectToStatusTransferItemExtIEsValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

func BridgeBearersSubjectToStatusTransferItemExtIEsValueCaptureS1APProtocolExtensionField(v *s14.BearersSubjectToStatusTransferItemExtIEsExtField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolExtensionID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.ExtensionValue = s14.BridgeBearersSubjectToStatusTransferItemExtIEsValueMethodCaptureSemantics(v.ExtensionValue, *s)
	s.End(f, s14.BridgeBearersSubjectToStatusTransferItemExtIEsExtFieldFieldReplay(v), *s14.BridgeBearersSubjectToStatusTransferItemExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeBearersSubjectToStatusTransferItemExtIEsValueCompareS1APProtocolExtensionField(v *s14.BearersSubjectToStatusTransferItemExtIEsExtField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s02.BridgeCompareS1APProtocolExtensionID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s14.BridgeBearersSubjectToStatusTransferItemExtIEsValueMethodCompareSemantics(v.ExtensionValue, *s)
	s.End(f, *s14.BridgeBearersSubjectToStatusTransferItemExtIEsExtFieldFieldReplay(v), *s14.BridgeBearersSubjectToStatusTransferItemExtIEsExtFieldFieldWithoutReplay(v))
}

// bearersSubjectToStatusTransferItemIEValueProtocolOpenValue is the concrete protocolOpenValue[BearersSubjectToStatusTransferItemIEValue].
type BearersSubjectToStatusTransferItemIEValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) BearersSubjectToStatusTransferItemIEValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (BearersSubjectToStatusTransferItemIEValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

func BridgeBearersSubjectToStatusTransferItemIEValueCaptureS1APProtocolIEField(v *BearersSubjectToStatusTransferItemIEField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolIEID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.Value = v.Value.captureSemantics(*s)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeBearersSubjectToStatusTransferItemIEValueCompareS1APProtocolIEField(v *BearersSubjectToStatusTransferItemIEField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s02.BridgeCompareS1APProtocolIEID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = v.Value.compareSemantics(*s)
	s.End(f, v.replay, v.withoutReplay)
}

// cellTrafficTraceIEValueProtocolOpenValue is the concrete protocolOpenValue[CellTrafficTraceIEValue].
type CellTrafficTraceIEValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) s17.CellTrafficTraceIEValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (s17.CellTrafficTraceIEValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

func BridgeCellTrafficTraceIEValueCaptureS1APProtocolIEField(v *s17.CellTrafficTraceIEField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolIEID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.Value = s17.BridgeCellTrafficTraceIEValueMethodCaptureSemantics(v.Value, *s)
	s.End(f, s17.BridgeCellTrafficTraceIEFieldFieldReplay(v), *s17.BridgeCellTrafficTraceIEFieldFieldWithoutReplay(v))
}
func BridgeCellTrafficTraceIEValueCompareS1APProtocolIEField(v *s17.CellTrafficTraceIEField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s02.BridgeCompareS1APProtocolIEID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s17.BridgeCellTrafficTraceIEValueMethodCompareSemantics(v.Value, *s)
	s.End(f, *s17.BridgeCellTrafficTraceIEFieldFieldReplay(v), *s17.BridgeCellTrafficTraceIEFieldFieldWithoutReplay(v))
}

// BearersSubjectToStatusTransferItemAPERValue is the concrete APERValue[BearersSubjectToStatusTransferItem].
type BearersSubjectToStatusTransferItemAPERValue struct {
	context s00.BridgeCodecContext
	Value   BearersSubjectToStatusTransferItem

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v BearersSubjectToStatusTransferItemAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v BearersSubjectToStatusTransferItemAPERValue) WithoutReplay() BearersSubjectToStatusTransferItemAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// TransportInformationAPERValue is the concrete APERValue[TransportInformation].
type TransportInformationAPERValue struct {
	context s00.BridgeCodecContext
	Value   TransportInformation

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v TransportInformationAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v TransportInformationAPERValue) WithoutReplay() TransportInformationAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ENBStatusTransferTransparentContainerAPERValue is the concrete APERValue[ENBStatusTransferTransparentContainer].
type ENBStatusTransferTransparentContainerAPERValue struct {
	context s00.BridgeCodecContext
	Value   ENBStatusTransferTransparentContainer

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ENBStatusTransferTransparentContainerAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ENBStatusTransferTransparentContainerAPERValue) WithoutReplay() ENBStatusTransferTransparentContainerAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// BearersSubjectToStatusTransferListAPERValue is the concrete APERValue[BearersSubjectToStatusTransferList].
type BearersSubjectToStatusTransferListAPERValue struct {
	context s00.BridgeCodecContext
	Value   BearersSubjectToStatusTransferList

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v BearersSubjectToStatusTransferListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v BearersSubjectToStatusTransferListAPERValue) WithoutReplay() BearersSubjectToStatusTransferListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// CellActivationResponseAPERValue is the concrete APERValue[CellActivationResponse].
type CellActivationResponseAPERValue struct {
	context s00.BridgeCodecContext
	Value   CellActivationResponse

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v CellActivationResponseAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v CellActivationResponseAPERValue) WithoutReplay() CellActivationResponseAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// CellTrafficTraceAPERValue is the concrete APERValue[CellTrafficTrace].
type CellTrafficTraceAPERValue struct {
	context s00.BridgeCodecContext
	Value   CellTrafficTrace

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v CellTrafficTraceAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v CellTrafficTraceAPERValue) WithoutReplay() CellTrafficTraceAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ERABToBeModifyItemBearerModReqExtIEsIEField is the concrete ProtocolIEField[ERABToBeModifyItemBearerModReqExtIEsValue].
type ERABToBeModifyItemBearerModReqExtIEsIEField struct {
	withoutReplay bool
	replay        aper.Snapshot
	stream        aper.WireSpan
	Id            s00.ProtocolIEID
	Criticality   s00.Criticality
	Value         ERABToBeModifyItemBearerModReqExtIEsValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ERABToBeModifyItemBearerModReqExtIEsIEField) WithoutReplay() ERABToBeModifyItemBearerModReqExtIEsIEField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *ERABToBeModifyItemBearerModReqExtIEsIEField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *ERABToBeModifyItemBearerModReqExtIEsIEField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
func (v *ERABToBeModifyItemBearerModReqExtIEsIEField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolIEField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = ERABToBeModifyItemBearerModReqExtIEsIEField{}
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
	var zero ERABToBeModifyItemBearerModReqExtIEsValue

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

// ERABToBeModifyItemBearerModReqExtIEsIEContainer is the concrete ProtocolIEContainer[ERABToBeModifyItemBearerModReqExtIEsValue].
type ERABToBeModifyItemBearerModReqExtIEsIEContainer []ERABToBeModifyItemBearerModReqExtIEsIEField

// UserLocationInformationExtIEsIEField is the concrete ProtocolIEField[UserLocationInformationExtIEsValue].
type UserLocationInformationExtIEsIEField struct {
	withoutReplay bool
	replay        aper.Snapshot
	stream        aper.WireSpan
	Id            s00.ProtocolIEID
	Criticality   s00.Criticality
	Value         UserLocationInformationExtIEsValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v UserLocationInformationExtIEsIEField) WithoutReplay() UserLocationInformationExtIEsIEField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *UserLocationInformationExtIEsIEField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *UserLocationInformationExtIEsIEField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
func (v *UserLocationInformationExtIEsIEField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolIEField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = UserLocationInformationExtIEsIEField{}
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
	var zero UserLocationInformationExtIEsValue

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

// UserLocationInformationExtIEsIEContainer is the concrete ProtocolIEContainer[UserLocationInformationExtIEsValue].
type UserLocationInformationExtIEsIEContainer []UserLocationInformationExtIEsIEField

func BridgeBearersSubjectToDLDiscardingItemIEValueCaptureS1APERABIEContainerList(v *s15.BearersSubjectToDLDiscardingItemIEValueERABIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeBearersSubjectToDLDiscardingItemIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeBearersSubjectToDLDiscardingItemIEValueCompareS1APERABIEContainerList(v *s15.BearersSubjectToDLDiscardingItemIEValueERABIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeBearersSubjectToDLDiscardingItemIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeBearersSubjectToEarlyStatusTransferItemIEValueCaptureS1APERABIEContainerList(v *s15.BearersSubjectToEarlyStatusTransferItemIEValueERABIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeBearersSubjectToEarlyStatusTransferItemIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeBearersSubjectToEarlyStatusTransferItemIEValueCompareS1APERABIEContainerList(v *s15.BearersSubjectToEarlyStatusTransferItemIEValueERABIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeBearersSubjectToEarlyStatusTransferItemIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}

// BearersSubjectToStatusTransferItemIEValueERABIEContainerListValueCodec is the concrete ValueCodec[ERABIEContainerList[BearersSubjectToStatusTransferItemIEValue]].
type BearersSubjectToStatusTransferItemIEValueERABIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (BearersSubjectToStatusTransferItemIEValueERABIEContainerList, error)
	encode  func(BearersSubjectToStatusTransferItemIEValueERABIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(BearersSubjectToStatusTransferItemIEValueERABIEContainerList, aper.DecodeState) (BearersSubjectToStatusTransferItemIEValueERABIEContainerList, aper.Snapshot)
	compare func(BearersSubjectToStatusTransferItemIEValueERABIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c BearersSubjectToStatusTransferItemIEValueERABIEContainerListValueCodec) New(value BearersSubjectToStatusTransferItemIEValueERABIEContainerList) (BearersSubjectToStatusTransferItemIEValueERABIEContainerListAPERValue, error) {
	if c.encode == nil {
		return BearersSubjectToStatusTransferItemIEValueERABIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return BearersSubjectToStatusTransferItemIEValueERABIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return BearersSubjectToStatusTransferItemIEValueERABIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return BearersSubjectToStatusTransferItemIEValueERABIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c BearersSubjectToStatusTransferItemIEValueERABIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (BearersSubjectToStatusTransferItemIEValueERABIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return BearersSubjectToStatusTransferItemIEValueERABIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return BearersSubjectToStatusTransferItemIEValueERABIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return BearersSubjectToStatusTransferItemIEValueERABIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return BearersSubjectToStatusTransferItemIEValueERABIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c BearersSubjectToStatusTransferItemIEValueERABIEContainerListValueCodec) EncodeAPER(value BearersSubjectToStatusTransferItemIEValueERABIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c BearersSubjectToStatusTransferItemIEValueERABIEContainerListValueCodec) encodeBudgetValue(value BearersSubjectToStatusTransferItemIEValueERABIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c BearersSubjectToStatusTransferItemIEValueERABIEContainerListValueCodec) encodeChanged(value BearersSubjectToStatusTransferItemIEValueERABIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// BearersSubjectToStatusTransferItemIEValueERABIEContainerList is the concrete ERABIEContainerList[BearersSubjectToStatusTransferItemIEValue].
type BearersSubjectToStatusTransferItemIEValueERABIEContainerList []BearersSubjectToStatusTransferItemIEValueProtocolIESingleContainer

func BridgeBearersSubjectToStatusTransferItemIEValueCaptureS1APERABIEContainerList(v *BearersSubjectToStatusTransferItemIEValueERABIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeBearersSubjectToStatusTransferItemIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeBearersSubjectToStatusTransferItemIEValueCompareS1APERABIEContainerList(v *BearersSubjectToStatusTransferItemIEValueERABIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeBearersSubjectToStatusTransferItemIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCellTrafficTraceIEValueCaptureS1APERABIEContainerList(v *s17.CellTrafficTraceIEValueERABIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeCellTrafficTraceIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeCellTrafficTraceIEValueCompareS1APERABIEContainerList(v *s17.CellTrafficTraceIEValueERABIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeCellTrafficTraceIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}

// ENBStatusTransferIEValueERABIEContainerListValueCodec is the concrete ValueCodec[ERABIEContainerList[ENBStatusTransferIEValue]].
type ENBStatusTransferIEValueERABIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ENBStatusTransferIEValueERABIEContainerList, error)
	encode  func(ENBStatusTransferIEValueERABIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ENBStatusTransferIEValueERABIEContainerList, aper.DecodeState) (ENBStatusTransferIEValueERABIEContainerList, aper.Snapshot)
	compare func(ENBStatusTransferIEValueERABIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ENBStatusTransferIEValueERABIEContainerListValueCodec) New(value ENBStatusTransferIEValueERABIEContainerList) (ENBStatusTransferIEValueERABIEContainerListAPERValue, error) {
	if c.encode == nil {
		return ENBStatusTransferIEValueERABIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ENBStatusTransferIEValueERABIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ENBStatusTransferIEValueERABIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ENBStatusTransferIEValueERABIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ENBStatusTransferIEValueERABIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ENBStatusTransferIEValueERABIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ENBStatusTransferIEValueERABIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ENBStatusTransferIEValueERABIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ENBStatusTransferIEValueERABIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ENBStatusTransferIEValueERABIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ENBStatusTransferIEValueERABIEContainerListValueCodec) EncodeAPER(value ENBStatusTransferIEValueERABIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c ENBStatusTransferIEValueERABIEContainerListValueCodec) encodeBudgetValue(value ENBStatusTransferIEValueERABIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ENBStatusTransferIEValueERABIEContainerListValueCodec) encodeChanged(value ENBStatusTransferIEValueERABIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ENBStatusTransferIEValueERABIEContainerList is the concrete ERABIEContainerList[ENBStatusTransferIEValue].
type ENBStatusTransferIEValueERABIEContainerList []ENBStatusTransferIEValueProtocolIESingleContainer

// MMEStatusTransferIEValueERABIEContainerListValueCodec is the concrete ValueCodec[ERABIEContainerList[MMEStatusTransferIEValue]].
type MMEStatusTransferIEValueERABIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (MMEStatusTransferIEValueERABIEContainerList, error)
	encode  func(MMEStatusTransferIEValueERABIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(MMEStatusTransferIEValueERABIEContainerList, aper.DecodeState) (MMEStatusTransferIEValueERABIEContainerList, aper.Snapshot)
	compare func(MMEStatusTransferIEValueERABIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c MMEStatusTransferIEValueERABIEContainerListValueCodec) New(value MMEStatusTransferIEValueERABIEContainerList) (MMEStatusTransferIEValueERABIEContainerListAPERValue, error) {
	if c.encode == nil {
		return MMEStatusTransferIEValueERABIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return MMEStatusTransferIEValueERABIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return MMEStatusTransferIEValueERABIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return MMEStatusTransferIEValueERABIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c MMEStatusTransferIEValueERABIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (MMEStatusTransferIEValueERABIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return MMEStatusTransferIEValueERABIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return MMEStatusTransferIEValueERABIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return MMEStatusTransferIEValueERABIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return MMEStatusTransferIEValueERABIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c MMEStatusTransferIEValueERABIEContainerListValueCodec) EncodeAPER(value MMEStatusTransferIEValueERABIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c MMEStatusTransferIEValueERABIEContainerListValueCodec) encodeBudgetValue(value MMEStatusTransferIEValueERABIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c MMEStatusTransferIEValueERABIEContainerListValueCodec) encodeChanged(value MMEStatusTransferIEValueERABIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// MMEStatusTransferIEValueERABIEContainerList is the concrete ERABIEContainerList[MMEStatusTransferIEValue].
type MMEStatusTransferIEValueERABIEContainerList []MMEStatusTransferIEValueProtocolIESingleContainer

// UEContextModificationIndicationIEValueERABIEContainerListValueCodec is the concrete ValueCodec[ERABIEContainerList[UEContextModificationIndicationIEValue]].
type UEContextModificationIndicationIEValueERABIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (UEContextModificationIndicationIEValueERABIEContainerList, error)
	encode  func(UEContextModificationIndicationIEValueERABIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(UEContextModificationIndicationIEValueERABIEContainerList, aper.DecodeState) (UEContextModificationIndicationIEValueERABIEContainerList, aper.Snapshot)
	compare func(UEContextModificationIndicationIEValueERABIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c UEContextModificationIndicationIEValueERABIEContainerListValueCodec) New(value UEContextModificationIndicationIEValueERABIEContainerList) (UEContextModificationIndicationIEValueERABIEContainerListAPERValue, error) {
	if c.encode == nil {
		return UEContextModificationIndicationIEValueERABIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return UEContextModificationIndicationIEValueERABIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return UEContextModificationIndicationIEValueERABIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return UEContextModificationIndicationIEValueERABIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c UEContextModificationIndicationIEValueERABIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (UEContextModificationIndicationIEValueERABIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return UEContextModificationIndicationIEValueERABIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return UEContextModificationIndicationIEValueERABIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return UEContextModificationIndicationIEValueERABIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return UEContextModificationIndicationIEValueERABIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c UEContextModificationIndicationIEValueERABIEContainerListValueCodec) EncodeAPER(value UEContextModificationIndicationIEValueERABIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c UEContextModificationIndicationIEValueERABIEContainerListValueCodec) encodeBudgetValue(value UEContextModificationIndicationIEValueERABIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c UEContextModificationIndicationIEValueERABIEContainerListValueCodec) encodeChanged(value UEContextModificationIndicationIEValueERABIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// UEContextModificationIndicationIEValueERABIEContainerList is the concrete ERABIEContainerList[UEContextModificationIndicationIEValue].
type UEContextModificationIndicationIEValueERABIEContainerList []UEContextModificationIndicationIEValueProtocolIESingleContainer

// UplinkS1cdma2000tunnellingIEValueERABIEContainerListValueCodec is the concrete ValueCodec[ERABIEContainerList[UplinkS1cdma2000tunnellingIEValue]].
type UplinkS1cdma2000tunnellingIEValueERABIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (UplinkS1cdma2000tunnellingIEValueERABIEContainerList, error)
	encode  func(UplinkS1cdma2000tunnellingIEValueERABIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(UplinkS1cdma2000tunnellingIEValueERABIEContainerList, aper.DecodeState) (UplinkS1cdma2000tunnellingIEValueERABIEContainerList, aper.Snapshot)
	compare func(UplinkS1cdma2000tunnellingIEValueERABIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c UplinkS1cdma2000tunnellingIEValueERABIEContainerListValueCodec) New(value UplinkS1cdma2000tunnellingIEValueERABIEContainerList) (UplinkS1cdma2000tunnellingIEValueERABIEContainerListAPERValue, error) {
	if c.encode == nil {
		return UplinkS1cdma2000tunnellingIEValueERABIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return UplinkS1cdma2000tunnellingIEValueERABIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return UplinkS1cdma2000tunnellingIEValueERABIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return UplinkS1cdma2000tunnellingIEValueERABIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c UplinkS1cdma2000tunnellingIEValueERABIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (UplinkS1cdma2000tunnellingIEValueERABIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return UplinkS1cdma2000tunnellingIEValueERABIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return UplinkS1cdma2000tunnellingIEValueERABIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return UplinkS1cdma2000tunnellingIEValueERABIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return UplinkS1cdma2000tunnellingIEValueERABIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c UplinkS1cdma2000tunnellingIEValueERABIEContainerListValueCodec) EncodeAPER(value UplinkS1cdma2000tunnellingIEValueERABIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c UplinkS1cdma2000tunnellingIEValueERABIEContainerListValueCodec) encodeBudgetValue(value UplinkS1cdma2000tunnellingIEValueERABIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c UplinkS1cdma2000tunnellingIEValueERABIEContainerListValueCodec) encodeChanged(value UplinkS1cdma2000tunnellingIEValueERABIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// UplinkS1cdma2000tunnellingIEValueERABIEContainerList is the concrete ERABIEContainerList[UplinkS1cdma2000tunnellingIEValue].
type UplinkS1cdma2000tunnellingIEValueERABIEContainerList []UplinkS1cdma2000tunnellingIEValueProtocolIESingleContainer

// ERABToBeModifyItemBearerModReqExtIEsExtFieldValueCodec is the concrete ValueCodec[ProtocolExtensionField[ERABToBeModifyItemBearerModReqExtIEsValue]].
type ERABToBeModifyItemBearerModReqExtIEsExtFieldValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ERABToBeModifyItemBearerModReqExtIEsExtField, error)
	encode  func(ERABToBeModifyItemBearerModReqExtIEsExtField, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ERABToBeModifyItemBearerModReqExtIEsExtField, aper.DecodeState) (ERABToBeModifyItemBearerModReqExtIEsExtField, aper.Snapshot)
	compare func(ERABToBeModifyItemBearerModReqExtIEsExtField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ERABToBeModifyItemBearerModReqExtIEsExtFieldValueCodec) New(value ERABToBeModifyItemBearerModReqExtIEsExtField) (ERABToBeModifyItemBearerModReqExtIEsExtFieldAPERValue, error) {
	if c.encode == nil {
		return ERABToBeModifyItemBearerModReqExtIEsExtFieldAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ERABToBeModifyItemBearerModReqExtIEsExtFieldAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ERABToBeModifyItemBearerModReqExtIEsExtFieldAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ERABToBeModifyItemBearerModReqExtIEsExtFieldAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ERABToBeModifyItemBearerModReqExtIEsExtFieldValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ERABToBeModifyItemBearerModReqExtIEsExtFieldAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ERABToBeModifyItemBearerModReqExtIEsExtFieldAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ERABToBeModifyItemBearerModReqExtIEsExtFieldAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ERABToBeModifyItemBearerModReqExtIEsExtFieldAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ERABToBeModifyItemBearerModReqExtIEsExtFieldAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ERABToBeModifyItemBearerModReqExtIEsExtFieldValueCodec) EncodeAPER(value ERABToBeModifyItemBearerModReqExtIEsExtFieldAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c ERABToBeModifyItemBearerModReqExtIEsExtFieldValueCodec) encodeBudgetValue(value ERABToBeModifyItemBearerModReqExtIEsExtField, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ERABToBeModifyItemBearerModReqExtIEsExtFieldValueCodec) encodeChanged(value ERABToBeModifyItemBearerModReqExtIEsExtField, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// UserLocationInformationExtIEsExtFieldValueCodec is the concrete ValueCodec[ProtocolExtensionField[UserLocationInformationExtIEsValue]].
type UserLocationInformationExtIEsExtFieldValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (UserLocationInformationExtIEsExtField, error)
	encode  func(UserLocationInformationExtIEsExtField, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(UserLocationInformationExtIEsExtField, aper.DecodeState) (UserLocationInformationExtIEsExtField, aper.Snapshot)
	compare func(UserLocationInformationExtIEsExtField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c UserLocationInformationExtIEsExtFieldValueCodec) New(value UserLocationInformationExtIEsExtField) (UserLocationInformationExtIEsExtFieldAPERValue, error) {
	if c.encode == nil {
		return UserLocationInformationExtIEsExtFieldAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return UserLocationInformationExtIEsExtFieldAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return UserLocationInformationExtIEsExtFieldAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return UserLocationInformationExtIEsExtFieldAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c UserLocationInformationExtIEsExtFieldValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (UserLocationInformationExtIEsExtFieldAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return UserLocationInformationExtIEsExtFieldAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return UserLocationInformationExtIEsExtFieldAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return UserLocationInformationExtIEsExtFieldAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return UserLocationInformationExtIEsExtFieldAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c UserLocationInformationExtIEsExtFieldValueCodec) EncodeAPER(value UserLocationInformationExtIEsExtFieldAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c UserLocationInformationExtIEsExtFieldValueCodec) encodeBudgetValue(value UserLocationInformationExtIEsExtField, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c UserLocationInformationExtIEsExtFieldValueCodec) encodeChanged(value UserLocationInformationExtIEsExtField, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ERABToBeModifyItemBearerModReqExtIEsExtContainerValueCodec is the concrete ValueCodec[ProtocolExtensionContainer[ERABToBeModifyItemBearerModReqExtIEsValue]].
type ERABToBeModifyItemBearerModReqExtIEsExtContainerValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ERABToBeModifyItemBearerModReqExtIEsExtContainer, error)
	encode  func(ERABToBeModifyItemBearerModReqExtIEsExtContainer, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ERABToBeModifyItemBearerModReqExtIEsExtContainer, aper.DecodeState) (ERABToBeModifyItemBearerModReqExtIEsExtContainer, aper.Snapshot)
	compare func(ERABToBeModifyItemBearerModReqExtIEsExtContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ERABToBeModifyItemBearerModReqExtIEsExtContainerValueCodec) New(value ERABToBeModifyItemBearerModReqExtIEsExtContainer) (ERABToBeModifyItemBearerModReqExtIEsExtContainerAPERValue, error) {
	if c.encode == nil {
		return ERABToBeModifyItemBearerModReqExtIEsExtContainerAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ERABToBeModifyItemBearerModReqExtIEsExtContainerAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ERABToBeModifyItemBearerModReqExtIEsExtContainerAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ERABToBeModifyItemBearerModReqExtIEsExtContainerAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ERABToBeModifyItemBearerModReqExtIEsExtContainerValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ERABToBeModifyItemBearerModReqExtIEsExtContainerAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ERABToBeModifyItemBearerModReqExtIEsExtContainerAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ERABToBeModifyItemBearerModReqExtIEsExtContainerAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ERABToBeModifyItemBearerModReqExtIEsExtContainerAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ERABToBeModifyItemBearerModReqExtIEsExtContainerAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ERABToBeModifyItemBearerModReqExtIEsExtContainerValueCodec) EncodeAPER(value ERABToBeModifyItemBearerModReqExtIEsExtContainerAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c ERABToBeModifyItemBearerModReqExtIEsExtContainerValueCodec) encodeBudgetValue(value ERABToBeModifyItemBearerModReqExtIEsExtContainer, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ERABToBeModifyItemBearerModReqExtIEsExtContainerValueCodec) encodeChanged(value ERABToBeModifyItemBearerModReqExtIEsExtContainer, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// UserLocationInformationExtIEsExtContainerValueCodec is the concrete ValueCodec[ProtocolExtensionContainer[UserLocationInformationExtIEsValue]].
type UserLocationInformationExtIEsExtContainerValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (UserLocationInformationExtIEsExtContainer, error)
	encode  func(UserLocationInformationExtIEsExtContainer, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(UserLocationInformationExtIEsExtContainer, aper.DecodeState) (UserLocationInformationExtIEsExtContainer, aper.Snapshot)
	compare func(UserLocationInformationExtIEsExtContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c UserLocationInformationExtIEsExtContainerValueCodec) New(value UserLocationInformationExtIEsExtContainer) (UserLocationInformationExtIEsExtContainerAPERValue, error) {
	if c.encode == nil {
		return UserLocationInformationExtIEsExtContainerAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return UserLocationInformationExtIEsExtContainerAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return UserLocationInformationExtIEsExtContainerAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return UserLocationInformationExtIEsExtContainerAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c UserLocationInformationExtIEsExtContainerValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (UserLocationInformationExtIEsExtContainerAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return UserLocationInformationExtIEsExtContainerAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return UserLocationInformationExtIEsExtContainerAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return UserLocationInformationExtIEsExtContainerAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return UserLocationInformationExtIEsExtContainerAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c UserLocationInformationExtIEsExtContainerValueCodec) EncodeAPER(value UserLocationInformationExtIEsExtContainerAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c UserLocationInformationExtIEsExtContainerValueCodec) encodeBudgetValue(value UserLocationInformationExtIEsExtContainer, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c UserLocationInformationExtIEsExtContainerValueCodec) encodeChanged(value UserLocationInformationExtIEsExtContainer, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// BearersSubjectToStatusTransferItemIEFieldValueCodec is the concrete ValueCodec[ProtocolIEField[BearersSubjectToStatusTransferItemIEValue]].
type BearersSubjectToStatusTransferItemIEFieldValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (BearersSubjectToStatusTransferItemIEField, error)
	encode  func(BearersSubjectToStatusTransferItemIEField, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(BearersSubjectToStatusTransferItemIEField, aper.DecodeState) (BearersSubjectToStatusTransferItemIEField, aper.Snapshot)
	compare func(BearersSubjectToStatusTransferItemIEField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c BearersSubjectToStatusTransferItemIEFieldValueCodec) New(value BearersSubjectToStatusTransferItemIEField) (BearersSubjectToStatusTransferItemIEFieldAPERValue, error) {
	if c.encode == nil {
		return BearersSubjectToStatusTransferItemIEFieldAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return BearersSubjectToStatusTransferItemIEFieldAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return BearersSubjectToStatusTransferItemIEFieldAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return BearersSubjectToStatusTransferItemIEFieldAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c BearersSubjectToStatusTransferItemIEFieldValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (BearersSubjectToStatusTransferItemIEFieldAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return BearersSubjectToStatusTransferItemIEFieldAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return BearersSubjectToStatusTransferItemIEFieldAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return BearersSubjectToStatusTransferItemIEFieldAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return BearersSubjectToStatusTransferItemIEFieldAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c BearersSubjectToStatusTransferItemIEFieldValueCodec) EncodeAPER(value BearersSubjectToStatusTransferItemIEFieldAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c BearersSubjectToStatusTransferItemIEFieldValueCodec) encodeBudgetValue(value BearersSubjectToStatusTransferItemIEField, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c BearersSubjectToStatusTransferItemIEFieldValueCodec) encodeChanged(value BearersSubjectToStatusTransferItemIEField, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ENBStatusTransferIEFieldValueCodec is the concrete ValueCodec[ProtocolIEField[ENBStatusTransferIEValue]].
type ENBStatusTransferIEFieldValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ENBStatusTransferIEField, error)
	encode  func(ENBStatusTransferIEField, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ENBStatusTransferIEField, aper.DecodeState) (ENBStatusTransferIEField, aper.Snapshot)
	compare func(ENBStatusTransferIEField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ENBStatusTransferIEFieldValueCodec) New(value ENBStatusTransferIEField) (ENBStatusTransferIEFieldAPERValue, error) {
	if c.encode == nil {
		return ENBStatusTransferIEFieldAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ENBStatusTransferIEFieldAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ENBStatusTransferIEFieldAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ENBStatusTransferIEFieldAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ENBStatusTransferIEFieldValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ENBStatusTransferIEFieldAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ENBStatusTransferIEFieldAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ENBStatusTransferIEFieldAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ENBStatusTransferIEFieldAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ENBStatusTransferIEFieldAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ENBStatusTransferIEFieldValueCodec) EncodeAPER(value ENBStatusTransferIEFieldAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c ENBStatusTransferIEFieldValueCodec) encodeBudgetValue(value ENBStatusTransferIEField, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ENBStatusTransferIEFieldValueCodec) encodeChanged(value ENBStatusTransferIEField, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// MMEStatusTransferIEFieldValueCodec is the concrete ValueCodec[ProtocolIEField[MMEStatusTransferIEValue]].
type MMEStatusTransferIEFieldValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (MMEStatusTransferIEField, error)
	encode  func(MMEStatusTransferIEField, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(MMEStatusTransferIEField, aper.DecodeState) (MMEStatusTransferIEField, aper.Snapshot)
	compare func(MMEStatusTransferIEField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c MMEStatusTransferIEFieldValueCodec) New(value MMEStatusTransferIEField) (MMEStatusTransferIEFieldAPERValue, error) {
	if c.encode == nil {
		return MMEStatusTransferIEFieldAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return MMEStatusTransferIEFieldAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return MMEStatusTransferIEFieldAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return MMEStatusTransferIEFieldAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c MMEStatusTransferIEFieldValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (MMEStatusTransferIEFieldAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return MMEStatusTransferIEFieldAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return MMEStatusTransferIEFieldAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return MMEStatusTransferIEFieldAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return MMEStatusTransferIEFieldAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c MMEStatusTransferIEFieldValueCodec) EncodeAPER(value MMEStatusTransferIEFieldAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c MMEStatusTransferIEFieldValueCodec) encodeBudgetValue(value MMEStatusTransferIEField, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c MMEStatusTransferIEFieldValueCodec) encodeChanged(value MMEStatusTransferIEField, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// UEContextModificationIndicationIEFieldValueCodec is the concrete ValueCodec[ProtocolIEField[UEContextModificationIndicationIEValue]].
type UEContextModificationIndicationIEFieldValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (UEContextModificationIndicationIEField, error)
	encode  func(UEContextModificationIndicationIEField, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(UEContextModificationIndicationIEField, aper.DecodeState) (UEContextModificationIndicationIEField, aper.Snapshot)
	compare func(UEContextModificationIndicationIEField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c UEContextModificationIndicationIEFieldValueCodec) New(value UEContextModificationIndicationIEField) (UEContextModificationIndicationIEFieldAPERValue, error) {
	if c.encode == nil {
		return UEContextModificationIndicationIEFieldAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return UEContextModificationIndicationIEFieldAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return UEContextModificationIndicationIEFieldAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return UEContextModificationIndicationIEFieldAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c UEContextModificationIndicationIEFieldValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (UEContextModificationIndicationIEFieldAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return UEContextModificationIndicationIEFieldAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return UEContextModificationIndicationIEFieldAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return UEContextModificationIndicationIEFieldAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return UEContextModificationIndicationIEFieldAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c UEContextModificationIndicationIEFieldValueCodec) EncodeAPER(value UEContextModificationIndicationIEFieldAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c UEContextModificationIndicationIEFieldValueCodec) encodeBudgetValue(value UEContextModificationIndicationIEField, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c UEContextModificationIndicationIEFieldValueCodec) encodeChanged(value UEContextModificationIndicationIEField, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// UplinkS1cdma2000tunnellingIEFieldValueCodec is the concrete ValueCodec[ProtocolIEField[UplinkS1cdma2000tunnellingIEValue]].
type UplinkS1cdma2000tunnellingIEFieldValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (UplinkS1cdma2000tunnellingIEField, error)
	encode  func(UplinkS1cdma2000tunnellingIEField, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(UplinkS1cdma2000tunnellingIEField, aper.DecodeState) (UplinkS1cdma2000tunnellingIEField, aper.Snapshot)
	compare func(UplinkS1cdma2000tunnellingIEField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c UplinkS1cdma2000tunnellingIEFieldValueCodec) New(value UplinkS1cdma2000tunnellingIEField) (UplinkS1cdma2000tunnellingIEFieldAPERValue, error) {
	if c.encode == nil {
		return UplinkS1cdma2000tunnellingIEFieldAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return UplinkS1cdma2000tunnellingIEFieldAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return UplinkS1cdma2000tunnellingIEFieldAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return UplinkS1cdma2000tunnellingIEFieldAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c UplinkS1cdma2000tunnellingIEFieldValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (UplinkS1cdma2000tunnellingIEFieldAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return UplinkS1cdma2000tunnellingIEFieldAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return UplinkS1cdma2000tunnellingIEFieldAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return UplinkS1cdma2000tunnellingIEFieldAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return UplinkS1cdma2000tunnellingIEFieldAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c UplinkS1cdma2000tunnellingIEFieldValueCodec) EncodeAPER(value UplinkS1cdma2000tunnellingIEFieldAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c UplinkS1cdma2000tunnellingIEFieldValueCodec) encodeBudgetValue(value UplinkS1cdma2000tunnellingIEField, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c UplinkS1cdma2000tunnellingIEFieldValueCodec) encodeChanged(value UplinkS1cdma2000tunnellingIEField, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func BridgeBearersSubjectToDLDiscardingItemIEValueCaptureS1APProtocolIEContainer(v *s15.BearersSubjectToDLDiscardingItemIEContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeBearersSubjectToDLDiscardingItemIEValueCaptureS1APProtocolIEField(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeBearersSubjectToDLDiscardingItemIEValueCompareS1APProtocolIEContainer(v *s15.BearersSubjectToDLDiscardingItemIEContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeBearersSubjectToDLDiscardingItemIEValueCompareS1APProtocolIEField(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeBearersSubjectToEarlyStatusTransferItemIEValueCaptureS1APProtocolIEContainer(v *s15.BearersSubjectToEarlyStatusTransferItemIEContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeBearersSubjectToEarlyStatusTransferItemIEValueCaptureS1APProtocolIEField(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeBearersSubjectToEarlyStatusTransferItemIEValueCompareS1APProtocolIEContainer(v *s15.BearersSubjectToEarlyStatusTransferItemIEContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeBearersSubjectToEarlyStatusTransferItemIEValueCompareS1APProtocolIEField(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}

// BearersSubjectToStatusTransferItemIEContainerValueCodec is the concrete ValueCodec[ProtocolIEContainer[BearersSubjectToStatusTransferItemIEValue]].
type BearersSubjectToStatusTransferItemIEContainerValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (BearersSubjectToStatusTransferItemIEContainer, error)
	encode  func(BearersSubjectToStatusTransferItemIEContainer, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(BearersSubjectToStatusTransferItemIEContainer, aper.DecodeState) (BearersSubjectToStatusTransferItemIEContainer, aper.Snapshot)
	compare func(BearersSubjectToStatusTransferItemIEContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c BearersSubjectToStatusTransferItemIEContainerValueCodec) New(value BearersSubjectToStatusTransferItemIEContainer) (BearersSubjectToStatusTransferItemIEContainerAPERValue, error) {
	if c.encode == nil {
		return BearersSubjectToStatusTransferItemIEContainerAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return BearersSubjectToStatusTransferItemIEContainerAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return BearersSubjectToStatusTransferItemIEContainerAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return BearersSubjectToStatusTransferItemIEContainerAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c BearersSubjectToStatusTransferItemIEContainerValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (BearersSubjectToStatusTransferItemIEContainerAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return BearersSubjectToStatusTransferItemIEContainerAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return BearersSubjectToStatusTransferItemIEContainerAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return BearersSubjectToStatusTransferItemIEContainerAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return BearersSubjectToStatusTransferItemIEContainerAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c BearersSubjectToStatusTransferItemIEContainerValueCodec) EncodeAPER(value BearersSubjectToStatusTransferItemIEContainerAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c BearersSubjectToStatusTransferItemIEContainerValueCodec) encodeBudgetValue(value BearersSubjectToStatusTransferItemIEContainer, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c BearersSubjectToStatusTransferItemIEContainerValueCodec) encodeChanged(value BearersSubjectToStatusTransferItemIEContainer, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func BridgeBearersSubjectToStatusTransferItemIEValueCaptureS1APProtocolIEContainer(v *BearersSubjectToStatusTransferItemIEContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeBearersSubjectToStatusTransferItemIEValueCaptureS1APProtocolIEField(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeBearersSubjectToStatusTransferItemIEValueCompareS1APProtocolIEContainer(v *BearersSubjectToStatusTransferItemIEContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeBearersSubjectToStatusTransferItemIEValueCompareS1APProtocolIEField(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}

// ENBStatusTransferIEContainerValueCodec is the concrete ValueCodec[ProtocolIEContainer[ENBStatusTransferIEValue]].
type ENBStatusTransferIEContainerValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ENBStatusTransferIEContainer, error)
	encode  func(ENBStatusTransferIEContainer, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ENBStatusTransferIEContainer, aper.DecodeState) (ENBStatusTransferIEContainer, aper.Snapshot)
	compare func(ENBStatusTransferIEContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ENBStatusTransferIEContainerValueCodec) New(value ENBStatusTransferIEContainer) (ENBStatusTransferIEContainerAPERValue, error) {
	if c.encode == nil {
		return ENBStatusTransferIEContainerAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ENBStatusTransferIEContainerAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ENBStatusTransferIEContainerAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ENBStatusTransferIEContainerAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ENBStatusTransferIEContainerValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ENBStatusTransferIEContainerAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ENBStatusTransferIEContainerAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ENBStatusTransferIEContainerAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ENBStatusTransferIEContainerAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ENBStatusTransferIEContainerAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ENBStatusTransferIEContainerValueCodec) EncodeAPER(value ENBStatusTransferIEContainerAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c ENBStatusTransferIEContainerValueCodec) encodeBudgetValue(value ENBStatusTransferIEContainer, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ENBStatusTransferIEContainerValueCodec) encodeChanged(value ENBStatusTransferIEContainer, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// MMEStatusTransferIEContainerValueCodec is the concrete ValueCodec[ProtocolIEContainer[MMEStatusTransferIEValue]].
type MMEStatusTransferIEContainerValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (MMEStatusTransferIEContainer, error)
	encode  func(MMEStatusTransferIEContainer, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(MMEStatusTransferIEContainer, aper.DecodeState) (MMEStatusTransferIEContainer, aper.Snapshot)
	compare func(MMEStatusTransferIEContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c MMEStatusTransferIEContainerValueCodec) New(value MMEStatusTransferIEContainer) (MMEStatusTransferIEContainerAPERValue, error) {
	if c.encode == nil {
		return MMEStatusTransferIEContainerAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return MMEStatusTransferIEContainerAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return MMEStatusTransferIEContainerAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return MMEStatusTransferIEContainerAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c MMEStatusTransferIEContainerValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (MMEStatusTransferIEContainerAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return MMEStatusTransferIEContainerAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return MMEStatusTransferIEContainerAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return MMEStatusTransferIEContainerAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return MMEStatusTransferIEContainerAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c MMEStatusTransferIEContainerValueCodec) EncodeAPER(value MMEStatusTransferIEContainerAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c MMEStatusTransferIEContainerValueCodec) encodeBudgetValue(value MMEStatusTransferIEContainer, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c MMEStatusTransferIEContainerValueCodec) encodeChanged(value MMEStatusTransferIEContainer, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// UEContextModificationIndicationIEContainerValueCodec is the concrete ValueCodec[ProtocolIEContainer[UEContextModificationIndicationIEValue]].
type UEContextModificationIndicationIEContainerValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (UEContextModificationIndicationIEContainer, error)
	encode  func(UEContextModificationIndicationIEContainer, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(UEContextModificationIndicationIEContainer, aper.DecodeState) (UEContextModificationIndicationIEContainer, aper.Snapshot)
	compare func(UEContextModificationIndicationIEContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c UEContextModificationIndicationIEContainerValueCodec) New(value UEContextModificationIndicationIEContainer) (UEContextModificationIndicationIEContainerAPERValue, error) {
	if c.encode == nil {
		return UEContextModificationIndicationIEContainerAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return UEContextModificationIndicationIEContainerAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return UEContextModificationIndicationIEContainerAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return UEContextModificationIndicationIEContainerAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c UEContextModificationIndicationIEContainerValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (UEContextModificationIndicationIEContainerAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return UEContextModificationIndicationIEContainerAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return UEContextModificationIndicationIEContainerAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return UEContextModificationIndicationIEContainerAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return UEContextModificationIndicationIEContainerAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c UEContextModificationIndicationIEContainerValueCodec) EncodeAPER(value UEContextModificationIndicationIEContainerAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c UEContextModificationIndicationIEContainerValueCodec) encodeBudgetValue(value UEContextModificationIndicationIEContainer, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c UEContextModificationIndicationIEContainerValueCodec) encodeChanged(value UEContextModificationIndicationIEContainer, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// UplinkS1cdma2000tunnellingIEContainerValueCodec is the concrete ValueCodec[ProtocolIEContainer[UplinkS1cdma2000tunnellingIEValue]].
type UplinkS1cdma2000tunnellingIEContainerValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (UplinkS1cdma2000tunnellingIEContainer, error)
	encode  func(UplinkS1cdma2000tunnellingIEContainer, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(UplinkS1cdma2000tunnellingIEContainer, aper.DecodeState) (UplinkS1cdma2000tunnellingIEContainer, aper.Snapshot)
	compare func(UplinkS1cdma2000tunnellingIEContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c UplinkS1cdma2000tunnellingIEContainerValueCodec) New(value UplinkS1cdma2000tunnellingIEContainer) (UplinkS1cdma2000tunnellingIEContainerAPERValue, error) {
	if c.encode == nil {
		return UplinkS1cdma2000tunnellingIEContainerAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return UplinkS1cdma2000tunnellingIEContainerAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return UplinkS1cdma2000tunnellingIEContainerAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return UplinkS1cdma2000tunnellingIEContainerAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c UplinkS1cdma2000tunnellingIEContainerValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (UplinkS1cdma2000tunnellingIEContainerAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return UplinkS1cdma2000tunnellingIEContainerAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return UplinkS1cdma2000tunnellingIEContainerAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return UplinkS1cdma2000tunnellingIEContainerAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return UplinkS1cdma2000tunnellingIEContainerAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c UplinkS1cdma2000tunnellingIEContainerValueCodec) EncodeAPER(value UplinkS1cdma2000tunnellingIEContainerAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c UplinkS1cdma2000tunnellingIEContainerValueCodec) encodeBudgetValue(value UplinkS1cdma2000tunnellingIEContainer, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c UplinkS1cdma2000tunnellingIEContainerValueCodec) encodeChanged(value UplinkS1cdma2000tunnellingIEContainer, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func BridgeBearersSubjectToDLDiscardingItemIEValueCaptureS1APProtocolErrorIEContainerList(v *s15.BearersSubjectToDLDiscardingItemIEValueProtocolErrorIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeBearersSubjectToDLDiscardingItemIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeBearersSubjectToDLDiscardingItemIEValueCompareS1APProtocolErrorIEContainerList(v *s15.BearersSubjectToDLDiscardingItemIEValueProtocolErrorIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeBearersSubjectToDLDiscardingItemIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeBearersSubjectToEarlyStatusTransferItemIEValueCaptureS1APProtocolErrorIEContainerList(v *s15.BearersSubjectToEarlyStatusTransferItemIEValueProtocolErrorIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeBearersSubjectToEarlyStatusTransferItemIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeBearersSubjectToEarlyStatusTransferItemIEValueCompareS1APProtocolErrorIEContainerList(v *s15.BearersSubjectToEarlyStatusTransferItemIEValueProtocolErrorIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeBearersSubjectToEarlyStatusTransferItemIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}

// BearersSubjectToStatusTransferItemIEValueProtocolErrorIEContainerListValueCodec is the concrete ValueCodec[ProtocolErrorIEContainerList[BearersSubjectToStatusTransferItemIEValue]].
type BearersSubjectToStatusTransferItemIEValueProtocolErrorIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (BearersSubjectToStatusTransferItemIEValueProtocolErrorIEContainerList, error)
	encode  func(BearersSubjectToStatusTransferItemIEValueProtocolErrorIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(BearersSubjectToStatusTransferItemIEValueProtocolErrorIEContainerList, aper.DecodeState) (BearersSubjectToStatusTransferItemIEValueProtocolErrorIEContainerList, aper.Snapshot)
	compare func(BearersSubjectToStatusTransferItemIEValueProtocolErrorIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c BearersSubjectToStatusTransferItemIEValueProtocolErrorIEContainerListValueCodec) New(value BearersSubjectToStatusTransferItemIEValueProtocolErrorIEContainerList) (BearersSubjectToStatusTransferItemIEValueProtocolErrorIEContainerListAPERValue, error) {
	if c.encode == nil {
		return BearersSubjectToStatusTransferItemIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return BearersSubjectToStatusTransferItemIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return BearersSubjectToStatusTransferItemIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return BearersSubjectToStatusTransferItemIEValueProtocolErrorIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c BearersSubjectToStatusTransferItemIEValueProtocolErrorIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (BearersSubjectToStatusTransferItemIEValueProtocolErrorIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return BearersSubjectToStatusTransferItemIEValueProtocolErrorIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return BearersSubjectToStatusTransferItemIEValueProtocolErrorIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return BearersSubjectToStatusTransferItemIEValueProtocolErrorIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return BearersSubjectToStatusTransferItemIEValueProtocolErrorIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c BearersSubjectToStatusTransferItemIEValueProtocolErrorIEContainerListValueCodec) EncodeAPER(value BearersSubjectToStatusTransferItemIEValueProtocolErrorIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c BearersSubjectToStatusTransferItemIEValueProtocolErrorIEContainerListValueCodec) encodeBudgetValue(value BearersSubjectToStatusTransferItemIEValueProtocolErrorIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c BearersSubjectToStatusTransferItemIEValueProtocolErrorIEContainerListValueCodec) encodeChanged(value BearersSubjectToStatusTransferItemIEValueProtocolErrorIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// BearersSubjectToStatusTransferItemIEValueProtocolErrorIEContainerList is the concrete ProtocolErrorIEContainerList[BearersSubjectToStatusTransferItemIEValue].
type BearersSubjectToStatusTransferItemIEValueProtocolErrorIEContainerList []BearersSubjectToStatusTransferItemIEValueProtocolIESingleContainer

func BridgeBearersSubjectToStatusTransferItemIEValueCaptureS1APProtocolErrorIEContainerList(v *BearersSubjectToStatusTransferItemIEValueProtocolErrorIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeBearersSubjectToStatusTransferItemIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeBearersSubjectToStatusTransferItemIEValueCompareS1APProtocolErrorIEContainerList(v *BearersSubjectToStatusTransferItemIEValueProtocolErrorIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeBearersSubjectToStatusTransferItemIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCellTrafficTraceIEValueCaptureS1APProtocolErrorIEContainerList(v *s17.CellTrafficTraceIEValueProtocolErrorIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeCellTrafficTraceIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeCellTrafficTraceIEValueCompareS1APProtocolErrorIEContainerList(v *s17.CellTrafficTraceIEValueProtocolErrorIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeCellTrafficTraceIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}

// ENBStatusTransferIEValueProtocolErrorIEContainerListValueCodec is the concrete ValueCodec[ProtocolErrorIEContainerList[ENBStatusTransferIEValue]].
type ENBStatusTransferIEValueProtocolErrorIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ENBStatusTransferIEValueProtocolErrorIEContainerList, error)
	encode  func(ENBStatusTransferIEValueProtocolErrorIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ENBStatusTransferIEValueProtocolErrorIEContainerList, aper.DecodeState) (ENBStatusTransferIEValueProtocolErrorIEContainerList, aper.Snapshot)
	compare func(ENBStatusTransferIEValueProtocolErrorIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ENBStatusTransferIEValueProtocolErrorIEContainerListValueCodec) New(value ENBStatusTransferIEValueProtocolErrorIEContainerList) (ENBStatusTransferIEValueProtocolErrorIEContainerListAPERValue, error) {
	if c.encode == nil {
		return ENBStatusTransferIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ENBStatusTransferIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ENBStatusTransferIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ENBStatusTransferIEValueProtocolErrorIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ENBStatusTransferIEValueProtocolErrorIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ENBStatusTransferIEValueProtocolErrorIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ENBStatusTransferIEValueProtocolErrorIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ENBStatusTransferIEValueProtocolErrorIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ENBStatusTransferIEValueProtocolErrorIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ENBStatusTransferIEValueProtocolErrorIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ENBStatusTransferIEValueProtocolErrorIEContainerListValueCodec) EncodeAPER(value ENBStatusTransferIEValueProtocolErrorIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c ENBStatusTransferIEValueProtocolErrorIEContainerListValueCodec) encodeBudgetValue(value ENBStatusTransferIEValueProtocolErrorIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ENBStatusTransferIEValueProtocolErrorIEContainerListValueCodec) encodeChanged(value ENBStatusTransferIEValueProtocolErrorIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ENBStatusTransferIEValueProtocolErrorIEContainerList is the concrete ProtocolErrorIEContainerList[ENBStatusTransferIEValue].
type ENBStatusTransferIEValueProtocolErrorIEContainerList []ENBStatusTransferIEValueProtocolIESingleContainer

// MMEStatusTransferIEValueProtocolErrorIEContainerListValueCodec is the concrete ValueCodec[ProtocolErrorIEContainerList[MMEStatusTransferIEValue]].
type MMEStatusTransferIEValueProtocolErrorIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (MMEStatusTransferIEValueProtocolErrorIEContainerList, error)
	encode  func(MMEStatusTransferIEValueProtocolErrorIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(MMEStatusTransferIEValueProtocolErrorIEContainerList, aper.DecodeState) (MMEStatusTransferIEValueProtocolErrorIEContainerList, aper.Snapshot)
	compare func(MMEStatusTransferIEValueProtocolErrorIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c MMEStatusTransferIEValueProtocolErrorIEContainerListValueCodec) New(value MMEStatusTransferIEValueProtocolErrorIEContainerList) (MMEStatusTransferIEValueProtocolErrorIEContainerListAPERValue, error) {
	if c.encode == nil {
		return MMEStatusTransferIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return MMEStatusTransferIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return MMEStatusTransferIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return MMEStatusTransferIEValueProtocolErrorIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c MMEStatusTransferIEValueProtocolErrorIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (MMEStatusTransferIEValueProtocolErrorIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return MMEStatusTransferIEValueProtocolErrorIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return MMEStatusTransferIEValueProtocolErrorIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return MMEStatusTransferIEValueProtocolErrorIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return MMEStatusTransferIEValueProtocolErrorIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c MMEStatusTransferIEValueProtocolErrorIEContainerListValueCodec) EncodeAPER(value MMEStatusTransferIEValueProtocolErrorIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c MMEStatusTransferIEValueProtocolErrorIEContainerListValueCodec) encodeBudgetValue(value MMEStatusTransferIEValueProtocolErrorIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c MMEStatusTransferIEValueProtocolErrorIEContainerListValueCodec) encodeChanged(value MMEStatusTransferIEValueProtocolErrorIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// MMEStatusTransferIEValueProtocolErrorIEContainerList is the concrete ProtocolErrorIEContainerList[MMEStatusTransferIEValue].
type MMEStatusTransferIEValueProtocolErrorIEContainerList []MMEStatusTransferIEValueProtocolIESingleContainer

// UEContextModificationIndicationIEValueProtocolErrorIEContainerListValueCodec is the concrete ValueCodec[ProtocolErrorIEContainerList[UEContextModificationIndicationIEValue]].
type UEContextModificationIndicationIEValueProtocolErrorIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (UEContextModificationIndicationIEValueProtocolErrorIEContainerList, error)
	encode  func(UEContextModificationIndicationIEValueProtocolErrorIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(UEContextModificationIndicationIEValueProtocolErrorIEContainerList, aper.DecodeState) (UEContextModificationIndicationIEValueProtocolErrorIEContainerList, aper.Snapshot)
	compare func(UEContextModificationIndicationIEValueProtocolErrorIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c UEContextModificationIndicationIEValueProtocolErrorIEContainerListValueCodec) New(value UEContextModificationIndicationIEValueProtocolErrorIEContainerList) (UEContextModificationIndicationIEValueProtocolErrorIEContainerListAPERValue, error) {
	if c.encode == nil {
		return UEContextModificationIndicationIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return UEContextModificationIndicationIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return UEContextModificationIndicationIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return UEContextModificationIndicationIEValueProtocolErrorIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c UEContextModificationIndicationIEValueProtocolErrorIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (UEContextModificationIndicationIEValueProtocolErrorIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return UEContextModificationIndicationIEValueProtocolErrorIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return UEContextModificationIndicationIEValueProtocolErrorIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return UEContextModificationIndicationIEValueProtocolErrorIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return UEContextModificationIndicationIEValueProtocolErrorIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c UEContextModificationIndicationIEValueProtocolErrorIEContainerListValueCodec) EncodeAPER(value UEContextModificationIndicationIEValueProtocolErrorIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c UEContextModificationIndicationIEValueProtocolErrorIEContainerListValueCodec) encodeBudgetValue(value UEContextModificationIndicationIEValueProtocolErrorIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c UEContextModificationIndicationIEValueProtocolErrorIEContainerListValueCodec) encodeChanged(value UEContextModificationIndicationIEValueProtocolErrorIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// UEContextModificationIndicationIEValueProtocolErrorIEContainerList is the concrete ProtocolErrorIEContainerList[UEContextModificationIndicationIEValue].
type UEContextModificationIndicationIEValueProtocolErrorIEContainerList []UEContextModificationIndicationIEValueProtocolIESingleContainer

// UplinkS1cdma2000tunnellingIEValueProtocolErrorIEContainerListValueCodec is the concrete ValueCodec[ProtocolErrorIEContainerList[UplinkS1cdma2000tunnellingIEValue]].
type UplinkS1cdma2000tunnellingIEValueProtocolErrorIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (UplinkS1cdma2000tunnellingIEValueProtocolErrorIEContainerList, error)
	encode  func(UplinkS1cdma2000tunnellingIEValueProtocolErrorIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(UplinkS1cdma2000tunnellingIEValueProtocolErrorIEContainerList, aper.DecodeState) (UplinkS1cdma2000tunnellingIEValueProtocolErrorIEContainerList, aper.Snapshot)
	compare func(UplinkS1cdma2000tunnellingIEValueProtocolErrorIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c UplinkS1cdma2000tunnellingIEValueProtocolErrorIEContainerListValueCodec) New(value UplinkS1cdma2000tunnellingIEValueProtocolErrorIEContainerList) (UplinkS1cdma2000tunnellingIEValueProtocolErrorIEContainerListAPERValue, error) {
	if c.encode == nil {
		return UplinkS1cdma2000tunnellingIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return UplinkS1cdma2000tunnellingIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return UplinkS1cdma2000tunnellingIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return UplinkS1cdma2000tunnellingIEValueProtocolErrorIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c UplinkS1cdma2000tunnellingIEValueProtocolErrorIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (UplinkS1cdma2000tunnellingIEValueProtocolErrorIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return UplinkS1cdma2000tunnellingIEValueProtocolErrorIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return UplinkS1cdma2000tunnellingIEValueProtocolErrorIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return UplinkS1cdma2000tunnellingIEValueProtocolErrorIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return UplinkS1cdma2000tunnellingIEValueProtocolErrorIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c UplinkS1cdma2000tunnellingIEValueProtocolErrorIEContainerListValueCodec) EncodeAPER(value UplinkS1cdma2000tunnellingIEValueProtocolErrorIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c UplinkS1cdma2000tunnellingIEValueProtocolErrorIEContainerListValueCodec) encodeBudgetValue(value UplinkS1cdma2000tunnellingIEValueProtocolErrorIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c UplinkS1cdma2000tunnellingIEValueProtocolErrorIEContainerListValueCodec) encodeChanged(value UplinkS1cdma2000tunnellingIEValueProtocolErrorIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// UplinkS1cdma2000tunnellingIEValueProtocolErrorIEContainerList is the concrete ProtocolErrorIEContainerList[UplinkS1cdma2000tunnellingIEValue].
type UplinkS1cdma2000tunnellingIEValueProtocolErrorIEContainerList []UplinkS1cdma2000tunnellingIEValueProtocolIESingleContainer

func BridgeBearersSubjectToDLDiscardingItemIEValueCaptureS1APProtocolIEContainerList(v *s15.BearersSubjectToDLDiscardingItemIEValueProtocolIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeBearersSubjectToDLDiscardingItemIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeBearersSubjectToDLDiscardingItemIEValueCompareS1APProtocolIEContainerList(v *s15.BearersSubjectToDLDiscardingItemIEValueProtocolIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeBearersSubjectToDLDiscardingItemIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeBearersSubjectToEarlyStatusTransferItemIEValueCaptureS1APProtocolIEContainerList(v *s15.BearersSubjectToEarlyStatusTransferItemIEValueProtocolIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeBearersSubjectToEarlyStatusTransferItemIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeBearersSubjectToEarlyStatusTransferItemIEValueCompareS1APProtocolIEContainerList(v *s15.BearersSubjectToEarlyStatusTransferItemIEValueProtocolIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeBearersSubjectToEarlyStatusTransferItemIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}

// BearersSubjectToStatusTransferItemIEValueProtocolIEContainerListValueCodec is the concrete ValueCodec[ProtocolIEContainerList[BearersSubjectToStatusTransferItemIEValue]].
type BearersSubjectToStatusTransferItemIEValueProtocolIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (BearersSubjectToStatusTransferItemIEValueProtocolIEContainerList, error)
	encode  func(BearersSubjectToStatusTransferItemIEValueProtocolIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(BearersSubjectToStatusTransferItemIEValueProtocolIEContainerList, aper.DecodeState) (BearersSubjectToStatusTransferItemIEValueProtocolIEContainerList, aper.Snapshot)
	compare func(BearersSubjectToStatusTransferItemIEValueProtocolIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c BearersSubjectToStatusTransferItemIEValueProtocolIEContainerListValueCodec) New(value BearersSubjectToStatusTransferItemIEValueProtocolIEContainerList) (BearersSubjectToStatusTransferItemIEValueProtocolIEContainerListAPERValue, error) {
	if c.encode == nil {
		return BearersSubjectToStatusTransferItemIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return BearersSubjectToStatusTransferItemIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return BearersSubjectToStatusTransferItemIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return BearersSubjectToStatusTransferItemIEValueProtocolIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c BearersSubjectToStatusTransferItemIEValueProtocolIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (BearersSubjectToStatusTransferItemIEValueProtocolIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return BearersSubjectToStatusTransferItemIEValueProtocolIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return BearersSubjectToStatusTransferItemIEValueProtocolIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return BearersSubjectToStatusTransferItemIEValueProtocolIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return BearersSubjectToStatusTransferItemIEValueProtocolIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c BearersSubjectToStatusTransferItemIEValueProtocolIEContainerListValueCodec) EncodeAPER(value BearersSubjectToStatusTransferItemIEValueProtocolIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c BearersSubjectToStatusTransferItemIEValueProtocolIEContainerListValueCodec) encodeBudgetValue(value BearersSubjectToStatusTransferItemIEValueProtocolIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c BearersSubjectToStatusTransferItemIEValueProtocolIEContainerListValueCodec) encodeChanged(value BearersSubjectToStatusTransferItemIEValueProtocolIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// BearersSubjectToStatusTransferItemIEValueProtocolIEContainerList is the concrete ProtocolIEContainerList[BearersSubjectToStatusTransferItemIEValue].
type BearersSubjectToStatusTransferItemIEValueProtocolIEContainerList []BearersSubjectToStatusTransferItemIEValueProtocolIESingleContainer

func BridgeBearersSubjectToStatusTransferItemIEValueCaptureS1APProtocolIEContainerList(v *BearersSubjectToStatusTransferItemIEValueProtocolIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeBearersSubjectToStatusTransferItemIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeBearersSubjectToStatusTransferItemIEValueCompareS1APProtocolIEContainerList(v *BearersSubjectToStatusTransferItemIEValueProtocolIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeBearersSubjectToStatusTransferItemIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCellTrafficTraceIEValueCaptureS1APProtocolIEContainerList(v *s17.CellTrafficTraceIEValueProtocolIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeCellTrafficTraceIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeCellTrafficTraceIEValueCompareS1APProtocolIEContainerList(v *s17.CellTrafficTraceIEValueProtocolIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeCellTrafficTraceIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}

// ENBStatusTransferIEValueProtocolIEContainerListValueCodec is the concrete ValueCodec[ProtocolIEContainerList[ENBStatusTransferIEValue]].
type ENBStatusTransferIEValueProtocolIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ENBStatusTransferIEValueProtocolIEContainerList, error)
	encode  func(ENBStatusTransferIEValueProtocolIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ENBStatusTransferIEValueProtocolIEContainerList, aper.DecodeState) (ENBStatusTransferIEValueProtocolIEContainerList, aper.Snapshot)
	compare func(ENBStatusTransferIEValueProtocolIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ENBStatusTransferIEValueProtocolIEContainerListValueCodec) New(value ENBStatusTransferIEValueProtocolIEContainerList) (ENBStatusTransferIEValueProtocolIEContainerListAPERValue, error) {
	if c.encode == nil {
		return ENBStatusTransferIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ENBStatusTransferIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ENBStatusTransferIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ENBStatusTransferIEValueProtocolIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ENBStatusTransferIEValueProtocolIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ENBStatusTransferIEValueProtocolIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ENBStatusTransferIEValueProtocolIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ENBStatusTransferIEValueProtocolIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ENBStatusTransferIEValueProtocolIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ENBStatusTransferIEValueProtocolIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ENBStatusTransferIEValueProtocolIEContainerListValueCodec) EncodeAPER(value ENBStatusTransferIEValueProtocolIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c ENBStatusTransferIEValueProtocolIEContainerListValueCodec) encodeBudgetValue(value ENBStatusTransferIEValueProtocolIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ENBStatusTransferIEValueProtocolIEContainerListValueCodec) encodeChanged(value ENBStatusTransferIEValueProtocolIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ENBStatusTransferIEValueProtocolIEContainerList is the concrete ProtocolIEContainerList[ENBStatusTransferIEValue].
type ENBStatusTransferIEValueProtocolIEContainerList []ENBStatusTransferIEValueProtocolIESingleContainer

// MMEStatusTransferIEValueProtocolIEContainerList is the concrete ProtocolIEContainerList[MMEStatusTransferIEValue].
type MMEStatusTransferIEValueProtocolIEContainerList []MMEStatusTransferIEValueProtocolIESingleContainer

// TraceFailureIndicationIEValueProtocolIEContainerListValueCodec is the concrete ValueCodec[ProtocolIEContainerList[TraceFailureIndicationIEValue]].
type TraceFailureIndicationIEValueProtocolIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (s20.TraceFailureIndicationIEValueProtocolIEContainerList, error)
	encode  func(s20.TraceFailureIndicationIEValueProtocolIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(s20.TraceFailureIndicationIEValueProtocolIEContainerList, aper.DecodeState) (s20.TraceFailureIndicationIEValueProtocolIEContainerList, aper.Snapshot)
	compare func(s20.TraceFailureIndicationIEValueProtocolIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c TraceFailureIndicationIEValueProtocolIEContainerListValueCodec) New(value s20.TraceFailureIndicationIEValueProtocolIEContainerList) (s20.TraceFailureIndicationIEValueProtocolIEContainerListAPERValue, error) {
	if c.encode == nil {
		return s20.TraceFailureIndicationIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return s20.TraceFailureIndicationIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return s20.TraceFailureIndicationIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return s20.TraceFailureIndicationIEValueProtocolIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c TraceFailureIndicationIEValueProtocolIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (s20.TraceFailureIndicationIEValueProtocolIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return s20.TraceFailureIndicationIEValueProtocolIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return s20.TraceFailureIndicationIEValueProtocolIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return func() s20.TraceFailureIndicationIEValueProtocolIEContainerListAPERValue {
			sealed := s20.TraceFailureIndicationIEValueProtocolIEContainerListAPERValue{Value: value}
			*s20.BridgeTraceFailureIndicationIEValueProtocolIEContainerListAPERValueFieldReceived(&sealed) = aper.OriginalWire(data)
			*s20.BridgeTraceFailureIndicationIEValueProtocolIEContainerListAPERValueFieldReplay(&sealed) = replay
			*s20.BridgeTraceFailureIndicationIEValueProtocolIEContainerListAPERValueFieldContext(&sealed) = c.context
			return sealed
		}(), report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return s20.TraceFailureIndicationIEValueProtocolIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c TraceFailureIndicationIEValueProtocolIEContainerListValueCodec) EncodeAPER(value s20.TraceFailureIndicationIEValueProtocolIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := *s20.BridgeTraceFailureIndicationIEValueProtocolIEContainerListAPERValueFieldWithoutReplay(&value) || aper.EncodeWithoutReplay(options...)
	if *s20.BridgeTraceFailureIndicationIEValueProtocolIEContainerListAPERValueFieldContext(&value) == c.context && !fresh && (*s20.BridgeTraceFailureIndicationIEValueProtocolIEContainerListAPERValueFieldReplay(&value)).Present() {
		plan, next := c.compare(value.Value, *s20.BridgeTraceFailureIndicationIEValueProtocolIEContainerListAPERValueFieldReplay(&value), budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(*s20.BridgeTraceFailureIndicationIEValueProtocolIEContainerListAPERValueFieldReplay(&value)) {
			out, err := aper.CopyReplay(*s20.BridgeTraceFailureIndicationIEValueProtocolIEContainerListAPERValueFieldReceived(&value), &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c TraceFailureIndicationIEValueProtocolIEContainerListValueCodec) encodeBudgetValue(value s20.TraceFailureIndicationIEValueProtocolIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c TraceFailureIndicationIEValueProtocolIEContainerListValueCodec) encodeChanged(value s20.TraceFailureIndicationIEValueProtocolIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// UEContextModificationIndicationIEValueProtocolIEContainerListValueCodec is the concrete ValueCodec[ProtocolIEContainerList[UEContextModificationIndicationIEValue]].
type UEContextModificationIndicationIEValueProtocolIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (UEContextModificationIndicationIEValueProtocolIEContainerList, error)
	encode  func(UEContextModificationIndicationIEValueProtocolIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(UEContextModificationIndicationIEValueProtocolIEContainerList, aper.DecodeState) (UEContextModificationIndicationIEValueProtocolIEContainerList, aper.Snapshot)
	compare func(UEContextModificationIndicationIEValueProtocolIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c UEContextModificationIndicationIEValueProtocolIEContainerListValueCodec) New(value UEContextModificationIndicationIEValueProtocolIEContainerList) (UEContextModificationIndicationIEValueProtocolIEContainerListAPERValue, error) {
	if c.encode == nil {
		return UEContextModificationIndicationIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return UEContextModificationIndicationIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return UEContextModificationIndicationIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return UEContextModificationIndicationIEValueProtocolIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c UEContextModificationIndicationIEValueProtocolIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (UEContextModificationIndicationIEValueProtocolIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return UEContextModificationIndicationIEValueProtocolIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return UEContextModificationIndicationIEValueProtocolIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return UEContextModificationIndicationIEValueProtocolIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return UEContextModificationIndicationIEValueProtocolIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c UEContextModificationIndicationIEValueProtocolIEContainerListValueCodec) EncodeAPER(value UEContextModificationIndicationIEValueProtocolIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c UEContextModificationIndicationIEValueProtocolIEContainerListValueCodec) encodeBudgetValue(value UEContextModificationIndicationIEValueProtocolIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c UEContextModificationIndicationIEValueProtocolIEContainerListValueCodec) encodeChanged(value UEContextModificationIndicationIEValueProtocolIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// UEContextModificationIndicationIEValueProtocolIEContainerList is the concrete ProtocolIEContainerList[UEContextModificationIndicationIEValue].
type UEContextModificationIndicationIEValueProtocolIEContainerList []UEContextModificationIndicationIEValueProtocolIESingleContainer

// UplinkS1cdma2000tunnellingIEValueProtocolIEContainerListValueCodec is the concrete ValueCodec[ProtocolIEContainerList[UplinkS1cdma2000tunnellingIEValue]].
type UplinkS1cdma2000tunnellingIEValueProtocolIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (UplinkS1cdma2000tunnellingIEValueProtocolIEContainerList, error)
	encode  func(UplinkS1cdma2000tunnellingIEValueProtocolIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(UplinkS1cdma2000tunnellingIEValueProtocolIEContainerList, aper.DecodeState) (UplinkS1cdma2000tunnellingIEValueProtocolIEContainerList, aper.Snapshot)
	compare func(UplinkS1cdma2000tunnellingIEValueProtocolIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c UplinkS1cdma2000tunnellingIEValueProtocolIEContainerListValueCodec) New(value UplinkS1cdma2000tunnellingIEValueProtocolIEContainerList) (UplinkS1cdma2000tunnellingIEValueProtocolIEContainerListAPERValue, error) {
	if c.encode == nil {
		return UplinkS1cdma2000tunnellingIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return UplinkS1cdma2000tunnellingIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return UplinkS1cdma2000tunnellingIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return UplinkS1cdma2000tunnellingIEValueProtocolIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c UplinkS1cdma2000tunnellingIEValueProtocolIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (UplinkS1cdma2000tunnellingIEValueProtocolIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return UplinkS1cdma2000tunnellingIEValueProtocolIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return UplinkS1cdma2000tunnellingIEValueProtocolIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return UplinkS1cdma2000tunnellingIEValueProtocolIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return UplinkS1cdma2000tunnellingIEValueProtocolIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c UplinkS1cdma2000tunnellingIEValueProtocolIEContainerListValueCodec) EncodeAPER(value UplinkS1cdma2000tunnellingIEValueProtocolIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c UplinkS1cdma2000tunnellingIEValueProtocolIEContainerListValueCodec) encodeBudgetValue(value UplinkS1cdma2000tunnellingIEValueProtocolIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c UplinkS1cdma2000tunnellingIEValueProtocolIEContainerListValueCodec) encodeChanged(value UplinkS1cdma2000tunnellingIEValueProtocolIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// UplinkS1cdma2000tunnellingIEValueProtocolIEContainerList is the concrete ProtocolIEContainerList[UplinkS1cdma2000tunnellingIEValue].
type UplinkS1cdma2000tunnellingIEValueProtocolIEContainerList []UplinkS1cdma2000tunnellingIEValueProtocolIESingleContainer

// BearersSubjectToStatusTransferItemIEValueERABIEContainerListAPERValue is the concrete APERValue[ERABIEContainerList[BearersSubjectToStatusTransferItemIEValue]].
type BearersSubjectToStatusTransferItemIEValueERABIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         BearersSubjectToStatusTransferItemIEValueERABIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v BearersSubjectToStatusTransferItemIEValueERABIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v BearersSubjectToStatusTransferItemIEValueERABIEContainerListAPERValue) WithoutReplay() BearersSubjectToStatusTransferItemIEValueERABIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}
func BridgeCellTrafficTraceIEValueCaptureS1APProtocolIESingleContainer(v *s17.CellTrafficTraceIEValueProtocolIESingleContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeCellTrafficTraceIEValueCaptureS1APProtocolIEField(v, s)
	s.End(f, nil, false)
}
func BridgeCellTrafficTraceIEValueCompareS1APProtocolIESingleContainer(v *s17.CellTrafficTraceIEValueProtocolIESingleContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeCellTrafficTraceIEValueCompareS1APProtocolIEField(v, s)
	s.End(f, aper.Snapshot{}, false)
}

// ENBStatusTransferIEValueERABIEContainerListAPERValue is the concrete APERValue[ERABIEContainerList[ENBStatusTransferIEValue]].
type ENBStatusTransferIEValueERABIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         ENBStatusTransferIEValueERABIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ENBStatusTransferIEValueERABIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ENBStatusTransferIEValueERABIEContainerListAPERValue) WithoutReplay() ENBStatusTransferIEValueERABIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ENBStatusTransferIEValueProtocolIESingleContainer is the concrete ProtocolIESingleContainer[ENBStatusTransferIEValue].
type ENBStatusTransferIEValueProtocolIESingleContainer = ENBStatusTransferIEField

// MMEStatusTransferIEValueERABIEContainerListAPERValue is the concrete APERValue[ERABIEContainerList[MMEStatusTransferIEValue]].
type MMEStatusTransferIEValueERABIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         MMEStatusTransferIEValueERABIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v MMEStatusTransferIEValueERABIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v MMEStatusTransferIEValueERABIEContainerListAPERValue) WithoutReplay() MMEStatusTransferIEValueERABIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// MMEStatusTransferIEValueProtocolIESingleContainer is the concrete ProtocolIESingleContainer[MMEStatusTransferIEValue].
type MMEStatusTransferIEValueProtocolIESingleContainer = MMEStatusTransferIEField

// UEContextModificationIndicationIEValueERABIEContainerListAPERValue is the concrete APERValue[ERABIEContainerList[UEContextModificationIndicationIEValue]].
type UEContextModificationIndicationIEValueERABIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         UEContextModificationIndicationIEValueERABIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v UEContextModificationIndicationIEValueERABIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v UEContextModificationIndicationIEValueERABIEContainerListAPERValue) WithoutReplay() UEContextModificationIndicationIEValueERABIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// UEContextModificationIndicationIEValueProtocolIESingleContainer is the concrete ProtocolIESingleContainer[UEContextModificationIndicationIEValue].
type UEContextModificationIndicationIEValueProtocolIESingleContainer = UEContextModificationIndicationIEField

// UplinkS1cdma2000tunnellingIEValueERABIEContainerListAPERValue is the concrete APERValue[ERABIEContainerList[UplinkS1cdma2000tunnellingIEValue]].
type UplinkS1cdma2000tunnellingIEValueERABIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         UplinkS1cdma2000tunnellingIEValueERABIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v UplinkS1cdma2000tunnellingIEValueERABIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v UplinkS1cdma2000tunnellingIEValueERABIEContainerListAPERValue) WithoutReplay() UplinkS1cdma2000tunnellingIEValueERABIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// UplinkS1cdma2000tunnellingIEValueProtocolIESingleContainer is the concrete ProtocolIESingleContainer[UplinkS1cdma2000tunnellingIEValue].
type UplinkS1cdma2000tunnellingIEValueProtocolIESingleContainer = UplinkS1cdma2000tunnellingIEField

// ERABToBeModifyItemBearerModReqExtIEsExtFieldAPERValue is the concrete APERValue[ProtocolExtensionField[ERABToBeModifyItemBearerModReqExtIEsValue]].
type ERABToBeModifyItemBearerModReqExtIEsExtFieldAPERValue struct {
	context       s00.BridgeCodecContext
	Value         ERABToBeModifyItemBearerModReqExtIEsExtField
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ERABToBeModifyItemBearerModReqExtIEsExtFieldAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ERABToBeModifyItemBearerModReqExtIEsExtFieldAPERValue) WithoutReplay() ERABToBeModifyItemBearerModReqExtIEsExtFieldAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// UserLocationInformationExtIEsExtFieldAPERValue is the concrete APERValue[ProtocolExtensionField[UserLocationInformationExtIEsValue]].
type UserLocationInformationExtIEsExtFieldAPERValue struct {
	context       s00.BridgeCodecContext
	Value         UserLocationInformationExtIEsExtField
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v UserLocationInformationExtIEsExtFieldAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v UserLocationInformationExtIEsExtFieldAPERValue) WithoutReplay() UserLocationInformationExtIEsExtFieldAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ERABToBeModifyItemBearerModReqExtIEsExtContainerAPERValue is the concrete APERValue[ProtocolExtensionContainer[ERABToBeModifyItemBearerModReqExtIEsValue]].
type ERABToBeModifyItemBearerModReqExtIEsExtContainerAPERValue struct {
	context       s00.BridgeCodecContext
	Value         ERABToBeModifyItemBearerModReqExtIEsExtContainer
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ERABToBeModifyItemBearerModReqExtIEsExtContainerAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ERABToBeModifyItemBearerModReqExtIEsExtContainerAPERValue) WithoutReplay() ERABToBeModifyItemBearerModReqExtIEsExtContainerAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// UserLocationInformationExtIEsExtContainerAPERValue is the concrete APERValue[ProtocolExtensionContainer[UserLocationInformationExtIEsValue]].
type UserLocationInformationExtIEsExtContainerAPERValue struct {
	context       s00.BridgeCodecContext
	Value         UserLocationInformationExtIEsExtContainer
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v UserLocationInformationExtIEsExtContainerAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v UserLocationInformationExtIEsExtContainerAPERValue) WithoutReplay() UserLocationInformationExtIEsExtContainerAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// BearersSubjectToStatusTransferItemIEFieldAPERValue is the concrete APERValue[ProtocolIEField[BearersSubjectToStatusTransferItemIEValue]].
type BearersSubjectToStatusTransferItemIEFieldAPERValue struct {
	context       s00.BridgeCodecContext
	Value         BearersSubjectToStatusTransferItemIEField
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v BearersSubjectToStatusTransferItemIEFieldAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v BearersSubjectToStatusTransferItemIEFieldAPERValue) WithoutReplay() BearersSubjectToStatusTransferItemIEFieldAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ENBStatusTransferIEFieldAPERValue is the concrete APERValue[ProtocolIEField[ENBStatusTransferIEValue]].
type ENBStatusTransferIEFieldAPERValue struct {
	context       s00.BridgeCodecContext
	Value         ENBStatusTransferIEField
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ENBStatusTransferIEFieldAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ENBStatusTransferIEFieldAPERValue) WithoutReplay() ENBStatusTransferIEFieldAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// MMEStatusTransferIEFieldAPERValue is the concrete APERValue[ProtocolIEField[MMEStatusTransferIEValue]].
type MMEStatusTransferIEFieldAPERValue struct {
	context       s00.BridgeCodecContext
	Value         MMEStatusTransferIEField
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v MMEStatusTransferIEFieldAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v MMEStatusTransferIEFieldAPERValue) WithoutReplay() MMEStatusTransferIEFieldAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// UEContextModificationIndicationIEFieldAPERValue is the concrete APERValue[ProtocolIEField[UEContextModificationIndicationIEValue]].
type UEContextModificationIndicationIEFieldAPERValue struct {
	context       s00.BridgeCodecContext
	Value         UEContextModificationIndicationIEField
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v UEContextModificationIndicationIEFieldAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v UEContextModificationIndicationIEFieldAPERValue) WithoutReplay() UEContextModificationIndicationIEFieldAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// UplinkS1cdma2000tunnellingIEFieldAPERValue is the concrete APERValue[ProtocolIEField[UplinkS1cdma2000tunnellingIEValue]].
type UplinkS1cdma2000tunnellingIEFieldAPERValue struct {
	context       s00.BridgeCodecContext
	Value         UplinkS1cdma2000tunnellingIEField
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v UplinkS1cdma2000tunnellingIEFieldAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v UplinkS1cdma2000tunnellingIEFieldAPERValue) WithoutReplay() UplinkS1cdma2000tunnellingIEFieldAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// BearersSubjectToStatusTransferItemIEContainerAPERValue is the concrete APERValue[ProtocolIEContainer[BearersSubjectToStatusTransferItemIEValue]].
type BearersSubjectToStatusTransferItemIEContainerAPERValue struct {
	context       s00.BridgeCodecContext
	Value         BearersSubjectToStatusTransferItemIEContainer
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v BearersSubjectToStatusTransferItemIEContainerAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v BearersSubjectToStatusTransferItemIEContainerAPERValue) WithoutReplay() BearersSubjectToStatusTransferItemIEContainerAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ENBStatusTransferIEContainerAPERValue is the concrete APERValue[ProtocolIEContainer[ENBStatusTransferIEValue]].
type ENBStatusTransferIEContainerAPERValue struct {
	context       s00.BridgeCodecContext
	Value         ENBStatusTransferIEContainer
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ENBStatusTransferIEContainerAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ENBStatusTransferIEContainerAPERValue) WithoutReplay() ENBStatusTransferIEContainerAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// MMEStatusTransferIEContainerAPERValue is the concrete APERValue[ProtocolIEContainer[MMEStatusTransferIEValue]].
type MMEStatusTransferIEContainerAPERValue struct {
	context       s00.BridgeCodecContext
	Value         MMEStatusTransferIEContainer
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v MMEStatusTransferIEContainerAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v MMEStatusTransferIEContainerAPERValue) WithoutReplay() MMEStatusTransferIEContainerAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// UEContextModificationIndicationIEContainerAPERValue is the concrete APERValue[ProtocolIEContainer[UEContextModificationIndicationIEValue]].
type UEContextModificationIndicationIEContainerAPERValue struct {
	context       s00.BridgeCodecContext
	Value         UEContextModificationIndicationIEContainer
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v UEContextModificationIndicationIEContainerAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v UEContextModificationIndicationIEContainerAPERValue) WithoutReplay() UEContextModificationIndicationIEContainerAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// UplinkS1cdma2000tunnellingIEContainerAPERValue is the concrete APERValue[ProtocolIEContainer[UplinkS1cdma2000tunnellingIEValue]].
type UplinkS1cdma2000tunnellingIEContainerAPERValue struct {
	context       s00.BridgeCodecContext
	Value         UplinkS1cdma2000tunnellingIEContainer
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v UplinkS1cdma2000tunnellingIEContainerAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v UplinkS1cdma2000tunnellingIEContainerAPERValue) WithoutReplay() UplinkS1cdma2000tunnellingIEContainerAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// BearersSubjectToStatusTransferItemIEValueProtocolErrorIEContainerListAPERValue is the concrete APERValue[ProtocolErrorIEContainerList[BearersSubjectToStatusTransferItemIEValue]].
type BearersSubjectToStatusTransferItemIEValueProtocolErrorIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         BearersSubjectToStatusTransferItemIEValueProtocolErrorIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v BearersSubjectToStatusTransferItemIEValueProtocolErrorIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v BearersSubjectToStatusTransferItemIEValueProtocolErrorIEContainerListAPERValue) WithoutReplay() BearersSubjectToStatusTransferItemIEValueProtocolErrorIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ENBStatusTransferIEValueProtocolErrorIEContainerListAPERValue is the concrete APERValue[ProtocolErrorIEContainerList[ENBStatusTransferIEValue]].
type ENBStatusTransferIEValueProtocolErrorIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         ENBStatusTransferIEValueProtocolErrorIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ENBStatusTransferIEValueProtocolErrorIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ENBStatusTransferIEValueProtocolErrorIEContainerListAPERValue) WithoutReplay() ENBStatusTransferIEValueProtocolErrorIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// MMEStatusTransferIEValueProtocolErrorIEContainerListAPERValue is the concrete APERValue[ProtocolErrorIEContainerList[MMEStatusTransferIEValue]].
type MMEStatusTransferIEValueProtocolErrorIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         MMEStatusTransferIEValueProtocolErrorIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v MMEStatusTransferIEValueProtocolErrorIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v MMEStatusTransferIEValueProtocolErrorIEContainerListAPERValue) WithoutReplay() MMEStatusTransferIEValueProtocolErrorIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// UEContextModificationIndicationIEValueProtocolErrorIEContainerListAPERValue is the concrete APERValue[ProtocolErrorIEContainerList[UEContextModificationIndicationIEValue]].
type UEContextModificationIndicationIEValueProtocolErrorIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         UEContextModificationIndicationIEValueProtocolErrorIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v UEContextModificationIndicationIEValueProtocolErrorIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v UEContextModificationIndicationIEValueProtocolErrorIEContainerListAPERValue) WithoutReplay() UEContextModificationIndicationIEValueProtocolErrorIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// UplinkS1cdma2000tunnellingIEValueProtocolErrorIEContainerListAPERValue is the concrete APERValue[ProtocolErrorIEContainerList[UplinkS1cdma2000tunnellingIEValue]].
type UplinkS1cdma2000tunnellingIEValueProtocolErrorIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         UplinkS1cdma2000tunnellingIEValueProtocolErrorIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v UplinkS1cdma2000tunnellingIEValueProtocolErrorIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v UplinkS1cdma2000tunnellingIEValueProtocolErrorIEContainerListAPERValue) WithoutReplay() UplinkS1cdma2000tunnellingIEValueProtocolErrorIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// BearersSubjectToStatusTransferItemIEValueProtocolIEContainerListAPERValue is the concrete APERValue[ProtocolIEContainerList[BearersSubjectToStatusTransferItemIEValue]].
type BearersSubjectToStatusTransferItemIEValueProtocolIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         BearersSubjectToStatusTransferItemIEValueProtocolIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v BearersSubjectToStatusTransferItemIEValueProtocolIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v BearersSubjectToStatusTransferItemIEValueProtocolIEContainerListAPERValue) WithoutReplay() BearersSubjectToStatusTransferItemIEValueProtocolIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ENBStatusTransferIEValueProtocolIEContainerListAPERValue is the concrete APERValue[ProtocolIEContainerList[ENBStatusTransferIEValue]].
type ENBStatusTransferIEValueProtocolIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         ENBStatusTransferIEValueProtocolIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ENBStatusTransferIEValueProtocolIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ENBStatusTransferIEValueProtocolIEContainerListAPERValue) WithoutReplay() ENBStatusTransferIEValueProtocolIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// UEContextModificationIndicationIEValueProtocolIEContainerListAPERValue is the concrete APERValue[ProtocolIEContainerList[UEContextModificationIndicationIEValue]].
type UEContextModificationIndicationIEValueProtocolIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         UEContextModificationIndicationIEValueProtocolIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v UEContextModificationIndicationIEValueProtocolIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v UEContextModificationIndicationIEValueProtocolIEContainerListAPERValue) WithoutReplay() UEContextModificationIndicationIEValueProtocolIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// UplinkS1cdma2000tunnellingIEValueProtocolIEContainerListAPERValue is the concrete APERValue[ProtocolIEContainerList[UplinkS1cdma2000tunnellingIEValue]].
type UplinkS1cdma2000tunnellingIEValueProtocolIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         UplinkS1cdma2000tunnellingIEValueProtocolIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v UplinkS1cdma2000tunnellingIEValueProtocolIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v UplinkS1cdma2000tunnellingIEValueProtocolIEContainerListAPERValue) WithoutReplay() UplinkS1cdma2000tunnellingIEValueProtocolIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}
func BridgeCaptureS1APActivatedCellsList(v *s14.ActivatedCellsList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			s14.BridgeCaptureS1APActivatedCellsListItem(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeCompareS1APActivatedCellsList(v *s14.ActivatedCellsList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			s14.BridgeCompareS1APActivatedCellsListItem(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCaptureS1APBearersSubjectToDLDiscardingList(v *s15.BearersSubjectToDLDiscardingList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeBearersSubjectToDLDiscardingItemIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeCompareS1APBearersSubjectToDLDiscardingList(v *s15.BearersSubjectToDLDiscardingList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeBearersSubjectToDLDiscardingItemIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCaptureS1APBearersSubjectToEarlyStatusTransferList(v *s15.BearersSubjectToEarlyStatusTransferList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeBearersSubjectToEarlyStatusTransferItemIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeCompareS1APBearersSubjectToEarlyStatusTransferList(v *s15.BearersSubjectToEarlyStatusTransferList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeBearersSubjectToEarlyStatusTransferItemIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCaptureS1APBearersSubjectToStatusTransferItem(v *BearersSubjectToStatusTransferItem, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APERABID(&v.ERABID, s)
	s14.BridgeCaptureS1APCOUNTvalue(&v.ULCOUNTvalue, s)
	s14.BridgeCaptureS1APCOUNTvalue(&v.DLCOUNTvalue, s)
	{
		f := s.Begin()
		s.Bool(v.ReceiveStatusofULPDCPSDUs == nil)
		if v.ReceiveStatusofULPDCPSDUs != nil {
			s00.BridgeCaptureS1APReceiveStatusofULPDCPSDUs(v.ReceiveStatusofULPDCPSDUs, s)
		}
		s.End(f, nil, false)
	}
	s.Bool(v.IEExtensions == nil)
	BridgeBearersSubjectToStatusTransferItemExtIEsValueCaptureS1APProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APBearersSubjectToStatusTransferItem(v *BearersSubjectToStatusTransferItem, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s02.BridgeCompareS1APERABID(&v.ERABID, s)
	s14.BridgeCompareS1APCOUNTvalue(&v.ULCOUNTvalue, s)
	s14.BridgeCompareS1APCOUNTvalue(&v.DLCOUNTvalue, s)
	{
		f := s.Begin()
		s.Bool(v.ReceiveStatusofULPDCPSDUs == nil)
		if v.ReceiveStatusofULPDCPSDUs != nil {
			s06.BridgeCompareS1APReceiveStatusofULPDCPSDUs(v.ReceiveStatusofULPDCPSDUs, s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.Bool(v.IEExtensions == nil)
	BridgeBearersSubjectToStatusTransferItemExtIEsValueCompareS1APProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APBearersSubjectToStatusTransferItemIEValue(v *BearersSubjectToStatusTransferItemIEValue, s *aper.SemanticCapture) {
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
		case s00.ProtocolIEID(89):
			{
				f := s.Begin()
				s.Bool(v.rowBearersSubjectToStatusTransferItem == nil)
				if v.rowBearersSubjectToStatusTransferItem != nil {
					BridgeCaptureS1APBearersSubjectToStatusTransferItem(v.rowBearersSubjectToStatusTransferItem, s)
				}
				s.End(f, nil, false)
			}
		}
	}
	s.End(f, &v.replay, false)
	s.CheckReceived(v.replay, v.received)
}
func (v BearersSubjectToStatusTransferItemIEValue) captureSemantics(s aper.SemanticCapture) BearersSubjectToStatusTransferItemIEValue {
	BridgeCaptureS1APBearersSubjectToStatusTransferItemIEValue(&v, &s)
	return v
}
func BridgeCompareS1APBearersSubjectToStatusTransferItemIEValue(v *BearersSubjectToStatusTransferItemIEValue, s *aper.SemanticComparison) {
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
		case s00.ProtocolIEID(89):
			{
				f := s.Begin()
				s.Bool(v.rowBearersSubjectToStatusTransferItem == nil)
				if v.rowBearersSubjectToStatusTransferItem != nil {
					BridgeCompareS1APBearersSubjectToStatusTransferItem(v.rowBearersSubjectToStatusTransferItem, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		}
	}
	s.End(f, v.replay, false)
	s.CheckReceived(v.replay, v.received)
}
func (v BearersSubjectToStatusTransferItemIEValue) compareSemantics(s aper.SemanticComparison) aper.SemanticComparison {
	BridgeCompareS1APBearersSubjectToStatusTransferItemIEValue(&v, &s)
	return s
}
func BridgeCaptureS1APBearersSubjectToStatusTransferList(v *BearersSubjectToStatusTransferList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeBearersSubjectToStatusTransferItemIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeCompareS1APBearersSubjectToStatusTransferList(v *BearersSubjectToStatusTransferList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeBearersSubjectToStatusTransferItemIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCaptureS1APCNTypeRestrictions(v *s14.CNTypeRestrictions, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			s14.BridgeCaptureS1APCNTypeRestrictionsItem(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeCaptureS1APCSGIdList(v *s14.CSGIdList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			s14.BridgeCaptureS1APCSGIdListItem(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeCaptureS1APCancelledCellinEAI(v *s17.CancelledCellinEAI, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			s17.BridgeCaptureS1APCancelledCellinEAIItem(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeCaptureS1APCancelledCellinTAI(v *s17.CancelledCellinTAI, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			s17.BridgeCaptureS1APCancelledCellinTAIItem(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeCaptureS1APCandidateCellList(v *s18.CandidateCellList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			s18.BridgeCaptureS1APIRATCellID(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeCaptureS1APCandidatePCIList(v *s14.CandidatePCIList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			s14.BridgeCaptureS1APCandidatePCI(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeCaptureS1APCellActivationResponse(v *CellActivationResponse, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeCaptureS1APActivatedCellsList(&v.ActivatedCellsList, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APCellActivationResponse(v *CellActivationResponse, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeCompareS1APActivatedCellsList(&v.ActivatedCellsList, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APCellIDBroadcast(v *s17.CellIDBroadcast, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			s17.BridgeCaptureS1APCellIDBroadcastItem(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeCaptureS1APCellIDCancelled(v *s17.CellIDCancelled, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			s17.BridgeCaptureS1APCellIDCancelledItem(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeCaptureS1APCellIdListforMDT(v *s17.CellIdListforMDT, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			s17.BridgeCaptureS1APEUTRANCGI(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeCaptureS1APCellIdListforQMC(v *s17.CellIdListforQMC, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			s17.BridgeCaptureS1APEUTRANCGI(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeCaptureS1APCellTrafficTrace(v *CellTrafficTrace, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeCellTrafficTraceIEValueCaptureS1APProtocolIEContainer(&v.ProtocolIEs, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APCellTrafficTrace(v *CellTrafficTrace, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeCellTrafficTraceIEValueCompareS1APProtocolIEContainer(&v.ProtocolIEs, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APCellsToActivateList(v *s14.CellsToActivateList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			s14.BridgeCaptureS1APCellsToActivateListItem(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeCaptureS1APCompletedCellinEAI(v *s17.CompletedCellinEAI, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			s17.BridgeCaptureS1APCompletedCellinEAIItem(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeCaptureS1APCompletedCellinTAI(v *s17.CompletedCellinTAI, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			s17.BridgeCaptureS1APCompletedCellinTAIItem(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeCaptureS1APCriticalityDiagnosticsIEList(v *s14.CriticalityDiagnosticsIEList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			s14.BridgeCaptureS1APCriticalityDiagnosticsIEItem(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeCaptureS1APECGIList(v *s17.ECGIList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			s17.BridgeCaptureS1APEUTRANCGI(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeCaptureS1APECGIListForRestart(v *s17.ECGIListForRestart, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			s17.BridgeCaptureS1APEUTRANCGI(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeCaptureS1APENBStatusTransferIEValue(v *ENBStatusTransferIEValue, s *aper.SemanticCapture) {
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
		case s00.ProtocolIEID(90):
			{
				f := s.Begin()
				s.Bool(v.rowENBStatusTransferTransparentContainer == nil)
				if v.rowENBStatusTransferTransparentContainer != nil {
					BridgeCaptureS1APENBStatusTransferTransparentContainer(v.rowENBStatusTransferTransparentContainer, s)
				}
				s.End(f, nil, false)
			}
		}
	}
	s.End(f, &v.replay, false)
	s.CheckReceived(v.replay, v.received)
}
func (v ENBStatusTransferIEValue) captureSemantics(s aper.SemanticCapture) ENBStatusTransferIEValue {
	BridgeCaptureS1APENBStatusTransferIEValue(&v, &s)
	return v
}
func BridgeCompareS1APENBStatusTransferIEValue(v *ENBStatusTransferIEValue, s *aper.SemanticComparison) {
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
		case s00.ProtocolIEID(90):
			{
				f := s.Begin()
				s.Bool(v.rowENBStatusTransferTransparentContainer == nil)
				if v.rowENBStatusTransferTransparentContainer != nil {
					BridgeCompareS1APENBStatusTransferTransparentContainer(v.rowENBStatusTransferTransparentContainer, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		}
	}
	s.End(f, v.replay, false)
	s.CheckReceived(v.replay, v.received)
}
func (v ENBStatusTransferIEValue) compareSemantics(s aper.SemanticComparison) aper.SemanticComparison {
	BridgeCompareS1APENBStatusTransferIEValue(&v, &s)
	return s
}
func BridgeCaptureS1APENBStatusTransferTransparentContainer(v *ENBStatusTransferTransparentContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeCaptureS1APBearersSubjectToStatusTransferList(&v.BearersSubjectToStatusTransferList, s)
	s.Bool(v.IEExtensions == nil)
	s13.BridgeENBStatusTransferTransparentContainerExtIEsValueCaptureS1APProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APENBStatusTransferTransparentContainer(v *ENBStatusTransferTransparentContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeCompareS1APBearersSubjectToStatusTransferList(&v.BearersSubjectToStatusTransferList, s)
	s.Bool(v.IEExtensions == nil)
	s13.BridgeENBStatusTransferTransparentContainerExtIEsValueCompareS1APProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APENBX2ExtTLAs(v *s15.ENBX2ExtTLAs, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			s15.BridgeCaptureS1APENBX2ExtTLA(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeCaptureS1APERABToBeModifyItemBearerModReqExtIEsValue(v *ERABToBeModifyItemBearerModReqExtIEsValue, s *aper.SemanticCapture) {
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
		case s00.ProtocolIEID(185):
			{
				f := s.Begin()
				s.Bool(v.rowTransportInformation == nil)
				if v.rowTransportInformation != nil {
					BridgeCaptureS1APTransportInformation(v.rowTransportInformation, s)
				}
				s.End(f, nil, false)
			}
		}
	}
	s.End(f, &v.replay, false)
	s.CheckReceived(v.replay, v.received)
}
func (v ERABToBeModifyItemBearerModReqExtIEsValue) captureSemantics(s aper.SemanticCapture) ERABToBeModifyItemBearerModReqExtIEsValue {
	BridgeCaptureS1APERABToBeModifyItemBearerModReqExtIEsValue(&v, &s)
	return v
}
func BridgeCompareS1APERABToBeModifyItemBearerModReqExtIEsValue(v *ERABToBeModifyItemBearerModReqExtIEsValue, s *aper.SemanticComparison) {
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
		case s00.ProtocolIEID(185):
			{
				f := s.Begin()
				s.Bool(v.rowTransportInformation == nil)
				if v.rowTransportInformation != nil {
					BridgeCompareS1APTransportInformation(v.rowTransportInformation, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		}
	}
	s.End(f, v.replay, false)
	s.CheckReceived(v.replay, v.received)
}
func (v ERABToBeModifyItemBearerModReqExtIEsValue) compareSemantics(s aper.SemanticComparison) aper.SemanticComparison {
	BridgeCompareS1APERABToBeModifyItemBearerModReqExtIEsValue(&v, &s)
	return s
}
func BridgeCaptureS1APForbiddenLAs(v *s18.ForbiddenLAs, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			s18.BridgeCaptureS1APForbiddenLAsItem(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeCaptureS1APForbiddenTAs(v *s18.ForbiddenTAs, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			s18.BridgeCaptureS1APForbiddenTAsItem(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeCaptureS1APGUMMEIList(v *s18.GUMMEIList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			s18.BridgeCaptureS1APGUMMEI(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeCaptureS1APIEsECGIList(v *s18.IEsECGIList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			s17.BridgeCaptureS1APEUTRANCGI(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeCaptureS1APInterSystemMeasurementList(v *s18.InterSystemMeasurementList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			s18.BridgeCaptureS1APInterSystemMeasurementItem(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeCaptureS1APLastVisitedPSCellList(v *s20.LastVisitedPSCellList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			s20.BridgeCaptureS1APLastVisitedPSCellInformation(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeCaptureS1APMBSFNResultToLog(v *s19.MBSFNResultToLog, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			s19.BridgeCaptureS1APMBSFNResultToLogInfo(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeCaptureS1APMMEStatusTransferIEValue(v *MMEStatusTransferIEValue, s *aper.SemanticCapture) {
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
		case s00.ProtocolIEID(90):
			{
				f := s.Begin()
				s.Bool(v.rowENBStatusTransferTransparentContainer == nil)
				if v.rowENBStatusTransferTransparentContainer != nil {
					BridgeCaptureS1APENBStatusTransferTransparentContainer(v.rowENBStatusTransferTransparentContainer, s)
				}
				s.End(f, nil, false)
			}
		}
	}
	s.End(f, &v.replay, false)
	s.CheckReceived(v.replay, v.received)
}
func (v MMEStatusTransferIEValue) captureSemantics(s aper.SemanticCapture) MMEStatusTransferIEValue {
	BridgeCaptureS1APMMEStatusTransferIEValue(&v, &s)
	return v
}
func BridgeCompareS1APMMEStatusTransferIEValue(v *MMEStatusTransferIEValue, s *aper.SemanticComparison) {
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
		case s00.ProtocolIEID(90):
			{
				f := s.Begin()
				s.Bool(v.rowENBStatusTransferTransparentContainer == nil)
				if v.rowENBStatusTransferTransparentContainer != nil {
					BridgeCompareS1APENBStatusTransferTransparentContainer(v.rowENBStatusTransferTransparentContainer, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		}
	}
	s.End(f, v.replay, false)
	s.CheckReceived(v.replay, v.received)
}
func (v MMEStatusTransferIEValue) compareSemantics(s aper.SemanticComparison) aper.SemanticComparison {
	BridgeCompareS1APMMEStatusTransferIEValue(&v, &s)
	return s
}
func BridgeCaptureS1APMultiCellLoadReportingResponse(v *s19.MultiCellLoadReportingResponse, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			s19.BridgeCaptureS1APMultiCellLoadReportingResponseItem(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeCaptureS1APNotificationCellList(v *s19.NotificationCellList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			s19.BridgeCaptureS1APNotificationCellListItem(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeCaptureS1APPC5QoSFlowList(v *s20.PC5QoSFlowList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			s20.BridgeCaptureS1APPC5QoSFlowItem(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeCaptureS1APPWSfailedECGIList(v *s20.PWSfailedECGIList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			s17.BridgeCaptureS1APEUTRANCGI(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeCaptureS1APRATRestrictions(v *s20.RATRestrictions, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			s20.BridgeCaptureS1APRATRestrictionsItem(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeCaptureS1APReportingCellList(v *s20.ReportingCellList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			s20.BridgeCaptureS1APReportingCellListItem(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeCaptureS1APRequestedCellList(v *s20.RequestedCellList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			s18.BridgeCaptureS1APIRATCellID(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeCaptureS1APTransportInformation(v *TransportInformation, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APTransportLayerAddress(&v.TransportLayerAddress, s)
	s00.BridgeCaptureS1APGTPTEID(&v.ULGTPTEID, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APTransportInformation(v *TransportInformation, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s07.BridgeCompareS1APTransportLayerAddress(&v.TransportLayerAddress, s)
	s02.BridgeCompareS1APGTPTEID(&v.ULGTPTEID, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APUEContextModificationIndicationIEValue(v *UEContextModificationIndicationIEValue, s *aper.SemanticCapture) {
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
		case s00.ProtocolIEID(226):
			{
				f := s.Begin()
				s.Bool(v.rowCSGMembershipInfo == nil)
				if v.rowCSGMembershipInfo != nil {
					s14.BridgeCaptureS1APCSGMembershipInfo(v.rowCSGMembershipInfo, s)
				}
				s.End(f, nil, false)
			}
		}
	}
	s.End(f, &v.replay, false)
	s.CheckReceived(v.replay, v.received)
}
func (v UEContextModificationIndicationIEValue) captureSemantics(s aper.SemanticCapture) UEContextModificationIndicationIEValue {
	BridgeCaptureS1APUEContextModificationIndicationIEValue(&v, &s)
	return v
}
func BridgeCompareS1APUEContextModificationIndicationIEValue(v *UEContextModificationIndicationIEValue, s *aper.SemanticComparison) {
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
		case s00.ProtocolIEID(226):
			{
				f := s.Begin()
				s.Bool(v.rowCSGMembershipInfo == nil)
				if v.rowCSGMembershipInfo != nil {
					s14.BridgeCompareS1APCSGMembershipInfo(v.rowCSGMembershipInfo, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		}
	}
	s.End(f, v.replay, false)
	s.CheckReceived(v.replay, v.received)
}
func (v UEContextModificationIndicationIEValue) compareSemantics(s aper.SemanticComparison) aper.SemanticComparison {
	BridgeCompareS1APUEContextModificationIndicationIEValue(&v, &s)
	return s
}
func BridgeCaptureS1APUplinkS1cdma2000tunnellingIEValue(v *UplinkS1cdma2000tunnellingIEValue, s *aper.SemanticCapture) {
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
		case s00.ProtocolIEID(71):
			{
				f := s.Begin()
				s.Bool(v.rowCdma2000RATType == nil)
				if v.rowCdma2000RATType != nil {
					s00.BridgeCaptureS1APCdma2000RATType(v.rowCdma2000RATType, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(72):
			{
				f := s.Begin()
				s.Bool(v.rowCdma2000SectorID == nil)
				if v.rowCdma2000SectorID != nil {
					s00.BridgeCaptureS1APCdma2000SectorID(v.rowCdma2000SectorID, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(84):
			{
				f := s.Begin()
				s.Bool(v.rowCdma2000HORequiredIndication == nil)
				if v.rowCdma2000HORequiredIndication != nil {
					s00.BridgeCaptureS1APCdma2000HORequiredIndication(v.rowCdma2000HORequiredIndication, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(102):
			{
				f := s.Begin()
				s.Bool(v.rowCdma2000OneXSRVCCInfo == nil)
				if v.rowCdma2000OneXSRVCCInfo != nil {
					s14.BridgeCaptureS1APCdma2000OneXSRVCCInfo(v.rowCdma2000OneXSRVCCInfo, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(97):
			{
				f := s.Begin()
				s.Bool(v.rowCdma2000OneXRAND == nil)
				if v.rowCdma2000OneXRAND != nil {
					s00.BridgeCaptureS1APCdma2000OneXRAND(v.rowCdma2000OneXRAND, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(70):
			{
				f := s.Begin()
				s.Bool(v.rowCdma2000PDU == nil)
				if v.rowCdma2000PDU != nil {
					s00.BridgeCaptureS1APCdma2000PDU(v.rowCdma2000PDU, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(140):
			{
				f := s.Begin()
				s.Bool(v.rowEUTRANRoundTripDelayEstimationInfo == nil)
				if v.rowEUTRANRoundTripDelayEstimationInfo != nil {
					s00.BridgeCaptureS1APEUTRANRoundTripDelayEstimationInfo(v.rowEUTRANRoundTripDelayEstimationInfo, s)
				}
				s.End(f, nil, false)
			}
		}
	}
	s.End(f, &v.replay, false)
	s.CheckReceived(v.replay, v.received)
}
func (v UplinkS1cdma2000tunnellingIEValue) captureSemantics(s aper.SemanticCapture) UplinkS1cdma2000tunnellingIEValue {
	BridgeCaptureS1APUplinkS1cdma2000tunnellingIEValue(&v, &s)
	return v
}
func BridgeCompareS1APUplinkS1cdma2000tunnellingIEValue(v *UplinkS1cdma2000tunnellingIEValue, s *aper.SemanticComparison) {
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
		case s00.ProtocolIEID(71):
			{
				f := s.Begin()
				s.Bool(v.rowCdma2000RATType == nil)
				if v.rowCdma2000RATType != nil {
					s02.BridgeCompareS1APCdma2000RATType(v.rowCdma2000RATType, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(72):
			{
				f := s.Begin()
				s.Bool(v.rowCdma2000SectorID == nil)
				if v.rowCdma2000SectorID != nil {
					s02.BridgeCompareS1APCdma2000SectorID(v.rowCdma2000SectorID, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(84):
			{
				f := s.Begin()
				s.Bool(v.rowCdma2000HORequiredIndication == nil)
				if v.rowCdma2000HORequiredIndication != nil {
					s02.BridgeCompareS1APCdma2000HORequiredIndication(v.rowCdma2000HORequiredIndication, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(102):
			{
				f := s.Begin()
				s.Bool(v.rowCdma2000OneXSRVCCInfo == nil)
				if v.rowCdma2000OneXSRVCCInfo != nil {
					s14.BridgeCompareS1APCdma2000OneXSRVCCInfo(v.rowCdma2000OneXSRVCCInfo, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(97):
			{
				f := s.Begin()
				s.Bool(v.rowCdma2000OneXRAND == nil)
				if v.rowCdma2000OneXRAND != nil {
					s02.BridgeCompareS1APCdma2000OneXRAND(v.rowCdma2000OneXRAND, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(70):
			{
				f := s.Begin()
				s.Bool(v.rowCdma2000PDU == nil)
				if v.rowCdma2000PDU != nil {
					s02.BridgeCompareS1APCdma2000PDU(v.rowCdma2000PDU, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(140):
			{
				f := s.Begin()
				s.Bool(v.rowEUTRANRoundTripDelayEstimationInfo == nil)
				if v.rowEUTRANRoundTripDelayEstimationInfo != nil {
					s02.BridgeCompareS1APEUTRANRoundTripDelayEstimationInfo(v.rowEUTRANRoundTripDelayEstimationInfo, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		}
	}
	s.End(f, v.replay, false)
	s.CheckReceived(v.replay, v.received)
}
func (v UplinkS1cdma2000tunnellingIEValue) compareSemantics(s aper.SemanticComparison) aper.SemanticComparison {
	BridgeCompareS1APUplinkS1cdma2000tunnellingIEValue(&v, &s)
	return s
}
func BridgeCaptureS1APUserLocationInformationExtIEsValue(v *UserLocationInformationExtIEsValue, s *aper.SemanticCapture) {
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
func (v UserLocationInformationExtIEsValue) captureSemantics(s aper.SemanticCapture) UserLocationInformationExtIEsValue {
	BridgeCaptureS1APUserLocationInformationExtIEsValue(&v, &s)
	return v
}
func BridgeCompareS1APUserLocationInformationExtIEsValue(v *UserLocationInformationExtIEsValue, s *aper.SemanticComparison) {
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
func (v UserLocationInformationExtIEsValue) compareSemantics(s aper.SemanticComparison) aper.SemanticComparison {
	BridgeCompareS1APUserLocationInformationExtIEsValue(&v, &s)
	return s
}

type BearersSubjectToStatusTransferList = []BearersSubjectToStatusTransferItemIEValueProtocolIESingleContainer

// BearersSubjectToStatusTransferItem represents the ASN.1 type Bearers-SubjectToStatusTransfer-Item (SEQUENCE).
type BearersSubjectToStatusTransferItem struct {
	replay                    aper.Snapshot
	stream                    aper.WireSpan
	received                  bool
	withoutReplay             bool
	receivedAbsolute          bool
	receivedBytes             aper.WireSpan
	receivedLocation          aper.Location
	ERABID                    s00.ERABID                                               `asn1:"tag:0,context,implicit"`
	ULCOUNTvalue              s14.COUNTvalue                                           `asn1:"tag:1,context,implicit"`
	DLCOUNTvalue              s14.COUNTvalue                                           `asn1:"tag:2,context,implicit"`
	ReceiveStatusofULPDCPSDUs *s00.ReceiveStatusofULPDCPSDUs                           `asn1:"tag:3,context,implicit,optional" json:"ReceiveStatusofULPDCPSDUs,omitempty"`
	IEExtensions              s14.BearersSubjectToStatusTransferItemExtIEsExtContainer `asn1:"tag:4,context,implicit,optional" json:"IEExtensions,omitzero"`
	iEExtensionsIndef         bool                                                     `asn1:"-" json:"-"`
	extCount                  int64                                                    `asn1:"-" json:"-"`
	extPresent                []bool                                                   `asn1:"-" json:"-"`
	extData                   [][]byte                                                 `asn1:"-" json:"-"`
	perPadding                aper.FinalPadding                                        `asn1:"-" json:"-"`
	perExtPadding             []aper.CompletePadding                                   `asn1:"-" json:"-"`
	extOrigin                 []aper.OpaqueOrigin
	extWire                   []aper.WireSpan
}

// ENBStatusTransferTransparentContainer represents the ASN.1 type ENB-StatusTransfer-TransparentContainer (SEQUENCE).
type ENBStatusTransferTransparentContainer struct {
	replay                                  aper.Snapshot
	stream                                  aper.WireSpan
	received                                bool
	withoutReplay                           bool
	receivedAbsolute                        bool
	receivedBytes                           aper.WireSpan
	receivedLocation                        aper.Location
	BearersSubjectToStatusTransferList      BearersSubjectToStatusTransferList                          `asn1:"tag:0,context,implicit"`
	bearersSubjectToStatusTransferListIndef bool                                                        `asn1:"-" json:"-"`
	IEExtensions                            s08.ENBStatusTransferTransparentContainerExtIEsExtContainer `asn1:"tag:1,context,implicit,optional" json:"IEExtensions,omitzero"`
	iEExtensionsIndef                       bool                                                        `asn1:"-" json:"-"`
	extCount                                int64                                                       `asn1:"-" json:"-"`
	extPresent                              []bool                                                      `asn1:"-" json:"-"`
	extData                                 [][]byte                                                    `asn1:"-" json:"-"`
	perPadding                              aper.FinalPadding                                           `asn1:"-" json:"-"`
	perExtPadding                           []aper.CompletePadding                                      `asn1:"-" json:"-"`
	extOrigin                               []aper.OpaqueOrigin
	extWire                                 []aper.WireSpan
}

// TransportInformation represents the ASN.1 type TransportInformation (SEQUENCE).
type TransportInformation struct {
	replay                aper.Snapshot
	stream                aper.WireSpan
	received              bool
	withoutReplay         bool
	receivedAbsolute      bool
	receivedBytes         aper.WireSpan
	receivedLocation      aper.Location
	TransportLayerAddress s00.TransportLayerAddress `asn1:"tag:0,context,implicit"`
	ULGTPTEID             s00.GTPTEID               `asn1:"tag:1,context,implicit"`
	extCount              int64                     `asn1:"-" json:"-"`
	extPresent            []bool                    `asn1:"-" json:"-"`
	extData               [][]byte                  `asn1:"-" json:"-"`
	perPadding            aper.FinalPadding         `asn1:"-" json:"-"`
	perExtPadding         []aper.CompletePadding    `asn1:"-" json:"-"`
	extOrigin             []aper.OpaqueOrigin
	extWire               []aper.WireSpan
}
type BridgeAsn1cAPERBearersSubjectToStatusTransferListListValue struct {
	Value BearersSubjectToStatusTransferList
}

// MarshalAPER encodes BearersSubjectToStatusTransferItem to APER format.
func (v *BearersSubjectToStatusTransferItem) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *BearersSubjectToStatusTransferItem) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
	if err := aper.EncodeBoolean(bb, v.ReceiveStatusofULPDCPSDUs != nil); err != nil {
		return err
	}
	if err := aper.EncodeBoolean(bb, v.IEExtensions != nil); err != nil {
		return err
	}
	if err := aper.EncodeIntegerBigBoundsAligned(bb, v.ERABID, s00.BridgeAsn1IntegerBound0, s00.BridgeAsn1IntegerBound5, true); err != nil {
		return fmt.Errorf("encoding e-RAB-ID: %w", err)
	}
	if err := s14.BridgeCOUNTvalueMethodMarshalAPERTo(&v.ULCOUNTvalue, bb, len(fresh) != 0 && fresh[0]); err != nil {
		return fmt.Errorf("encoding uL-COUNTvalue: %w", err)
	}
	if err := s14.BridgeCOUNTvalueMethodMarshalAPERTo(&v.DLCOUNTvalue, bb, len(fresh) != 0 && fresh[0]); err != nil {
		return fmt.Errorf("encoding dL-COUNTvalue: %w", err)
	}
	if v.ReceiveStatusofULPDCPSDUs != nil {
		if err := aper.EncodeBitStringAligned(bb, v.ReceiveStatusofULPDCPSDUs.Bytes, v.ReceiveStatusofULPDCPSDUs.BitLength, 4096, 4096, true); err != nil {
			return fmt.Errorf("encoding receiveStatusofULPDCPSDUs: %w", err)
		}
	}
	if v.IEExtensions != nil {
		if err := aper.EncodeCollection(bb, int64(len(v.IEExtensions)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
			if fragmentOffset_ieextensions < 0 || fragmentOffset_ieextensions > int64(len(v.IEExtensions)) || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(len(v.IEExtensions[fragmentOffset_ieextensions:])) {
				return fmt.Errorf("collection fragment outside value")
			}
			for _, elem := range v.IEExtensions[fragmentOffset_ieextensions : fragmentOffset_ieextensions+fragmentLength_ieextensions] {
				if err := s14.BridgeBearersSubjectToStatusTransferItemExtIEsExtFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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

// UnmarshalAPER decodes BearersSubjectToStatusTransferItem from APER format.
func (v *BearersSubjectToStatusTransferItem) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes BearersSubjectToStatusTransferItem with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *BearersSubjectToStatusTransferItem) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "BearersSubjectToStatusTransferItem")
	}
	bb.EnterComponent("BearersSubjectToStatusTransferItem")
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "BearersSubjectToStatusTransferItem")
	}
	padding, err := aper.CaptureFinalBits(bb, "BearersSubjectToStatusTransferItem")
	if err != nil {
		return runtime.WrapDecodePath(err, "BearersSubjectToStatusTransferItem")
	}
	v.perPadding = padding.WithRecords(v.perPadding)
	return nil
}
func (v *BearersSubjectToStatusTransferItem) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = BearersSubjectToStatusTransferItem{}
	extAdditions := aper.BeginExtensionAdditions(bb)
	hasExtensions, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	// Read preamble bitmap for optional root fields
	opt_receivestatusofulpdcpsdus, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	opt_ieextensions, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	val_erabid, err := aper.DecodeIntegerBigBoundsAligned(bb, s00.BridgeAsn1IntegerBound0, s00.BridgeAsn1IntegerBound5, true)
	if err != nil {
		return runtime.WrapDecodePath(err, "ERABID")
	}
	v.ERABID = val_erabid
	toleranceMark_ulcountvalue := bb.EnterComponent("ULCOUNTvalue")
	if err := s14.BridgeCOUNTvalueMethodUnmarshalAPERFrom(&v.ULCOUNTvalue, bb); err != nil {
		return runtime.WrapDecodePath(err, "ULCOUNTvalue")
	}
	bb.LeaveComponent(toleranceMark_ulcountvalue)
	toleranceMark_dlcountvalue := bb.EnterComponent("DLCOUNTvalue")
	if err := s14.BridgeCOUNTvalueMethodUnmarshalAPERFrom(&v.DLCOUNTvalue, bb); err != nil {
		return runtime.WrapDecodePath(err, "DLCOUNTvalue")
	}
	bb.LeaveComponent(toleranceMark_dlcountvalue)
	if opt_receivestatusofulpdcpsdus {
		bsBytes_receivestatusofulpdcpsdus, bsBitLen_receivestatusofulpdcpsdus, err := aper.DecodeBitStringAligned(bb, 4096, 4096, true)
		if err != nil {
			return runtime.WrapDecodePath(err, "ReceiveStatusofULPDCPSDUs")
		}
		tmp_receivestatusofulpdcpsdus := runtime.BitString{Bytes: bsBytes_receivestatusofulpdcpsdus, BitLength: bsBitLen_receivestatusofulpdcpsdus}
		if err := aper.ChargeValue(bb, tmp_receivestatusofulpdcpsdus); err != nil {
			return err
		}
		v.ReceiveStatusofULPDCPSDUs = &tmp_receivestatusofulpdcpsdus
	}
	if opt_ieextensions {
		toleranceMark_ieextensions := bb.EnterComponent("IEExtensions")
		tmp_ieextensions := make(s14.BearersSubjectToStatusTransferItemExtIEsExtContainer, 0)
		_, errCollection_ieextensions := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1128
			if fragmentOffset_ieextensions < 0 || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(^uint(0)>>1) || fragmentOffset_ieextensions > int64(^uint(0)>>1)-fragmentLength_ieextensions {
				return fmt.Errorf("collection fragment count out of range")
			}
			for i := int64(0); i < fragmentLength_ieextensions; i++ {
				var elem s14.BearersSubjectToStatusTransferItemExtIEsExtField
				elementMark := bb.EnterIndex(fragmentOffset_ieextensions + i)
				if err := s14.BridgeBearersSubjectToStatusTransferItemExtIEsExtFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
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

type BridgeAsn1cAPERBearersSubjectToEarlyStatusTransferListListValue struct {
	Value s15.BearersSubjectToEarlyStatusTransferList
}
type BridgeAsn1cAPERBearersSubjectToDLDiscardingListListValue struct {
	Value s15.BearersSubjectToDLDiscardingList
}
type BridgeAsn1cAPERCancelledCellinEAIListValue struct{ Value s17.CancelledCellinEAI }
type BridgeAsn1cAPERCancelledCellinTAIListValue struct{ Value s17.CancelledCellinTAI }
type BridgeAsn1cAPERCellIDBroadcastListValue struct{ Value s17.CellIDBroadcast }
type BridgeAsn1cAPERCellIDCancelledListValue struct{ Value s17.CellIDCancelled }
type BridgeAsn1cAPERCellIdListforMDTListValue struct{ Value s17.CellIdListforMDT }
type BridgeAsn1cAPERCellIdListforQMCListValue struct{ Value s17.CellIdListforQMC }
type BridgeAsn1cAPERCNTypeRestrictionsListValue struct{ Value s14.CNTypeRestrictions }
type BridgeAsn1cAPERCSGIdListListValue struct{ Value s14.CSGIdList }
type BridgeAsn1cAPERCriticalityDiagnosticsIEListListValue struct {
	Value s14.CriticalityDiagnosticsIEList
}
type BridgeAsn1cAPERDAPSResponseInfoListListValue struct{ Value s14.DAPSResponseInfoList }
type BridgeAsn1cAPERECGIListListValue struct{ Value s17.ECGIList }
type BridgeAsn1cAPERPWSfailedECGIListListValue struct{ Value s20.PWSfailedECGIList }
type BridgeAsn1cAPERCompletedCellinEAIListValue struct{ Value s17.CompletedCellinEAI }
type BridgeAsn1cAPERIEsECGIListListValue struct{ Value s18.IEsECGIList }
type BridgeAsn1cAPERGUMMEIListListValue struct{ Value s18.GUMMEIList }

// MarshalAPER encodes ENBStatusTransferTransparentContainer to APER format.
func (v *ENBStatusTransferTransparentContainer) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *ENBStatusTransferTransparentContainer) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
	if err := aper.EncodeCollection(bb, int64(len(v.BearersSubjectToStatusTransferList)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 256, HasUpper: true}, true, func(fragmentOffset_bearerssubjecttostatustransferlist, fragmentLength_bearerssubjecttostatustransferlist int64) error {
		// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
		if fragmentOffset_bearerssubjecttostatustransferlist < 0 || fragmentOffset_bearerssubjecttostatustransferlist > int64(len(v.BearersSubjectToStatusTransferList)) || fragmentLength_bearerssubjecttostatustransferlist < 0 || fragmentLength_bearerssubjecttostatustransferlist > int64(len(v.BearersSubjectToStatusTransferList[fragmentOffset_bearerssubjecttostatustransferlist:])) {
			return fmt.Errorf("collection fragment outside value")
		}
		for _, elem := range v.BearersSubjectToStatusTransferList[fragmentOffset_bearerssubjecttostatustransferlist : fragmentOffset_bearerssubjecttostatustransferlist+fragmentLength_bearerssubjecttostatustransferlist] {
			if err := elem.marshalAPERTo(bb, len(fresh) != 0 && fresh[0]); err != nil {
				return fmt.Errorf("encoding bearers-SubjectToStatusTransferList element: %w", err)
			}
		}
		return nil
	}); err != nil {
		return fmt.Errorf("encoding bearers-SubjectToStatusTransferList: %w", err)
	}
	if v.IEExtensions != nil {
		if err := aper.EncodeCollection(bb, int64(len(v.IEExtensions)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
			if fragmentOffset_ieextensions < 0 || fragmentOffset_ieextensions > int64(len(v.IEExtensions)) || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(len(v.IEExtensions[fragmentOffset_ieextensions:])) {
				return fmt.Errorf("collection fragment outside value")
			}
			for _, elem := range v.IEExtensions[fragmentOffset_ieextensions : fragmentOffset_ieextensions+fragmentLength_ieextensions] {
				if err := s08.BridgeENBStatusTransferTransparentContainerExtIEsExtFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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

// UnmarshalAPER decodes ENBStatusTransferTransparentContainer from APER format.
func (v *ENBStatusTransferTransparentContainer) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes ENBStatusTransferTransparentContainer with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *ENBStatusTransferTransparentContainer) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "ENBStatusTransferTransparentContainer")
	}
	bb.EnterComponent("ENBStatusTransferTransparentContainer")
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "ENBStatusTransferTransparentContainer")
	}
	padding, err := aper.CaptureFinalBits(bb, "ENBStatusTransferTransparentContainer")
	if err != nil {
		return runtime.WrapDecodePath(err, "ENBStatusTransferTransparentContainer")
	}
	v.perPadding = padding.WithRecords(v.perPadding)
	return nil
}
func (v *ENBStatusTransferTransparentContainer) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = ENBStatusTransferTransparentContainer{}
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
	toleranceMark_bearerssubjecttostatustransferlist := bb.EnterComponent("BearersSubjectToStatusTransferList")
	v.BearersSubjectToStatusTransferList = make(BearersSubjectToStatusTransferList, 0)
	_, errCollection_bearerssubjecttostatustransferlist := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 256, HasUpper: true}, true, func(fragmentOffset_bearerssubjecttostatustransferlist, fragmentLength_bearerssubjecttostatustransferlist int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1128
		if fragmentOffset_bearerssubjecttostatustransferlist < 0 || fragmentLength_bearerssubjecttostatustransferlist < 0 || fragmentLength_bearerssubjecttostatustransferlist > int64(^uint(0)>>1) || fragmentOffset_bearerssubjecttostatustransferlist > int64(^uint(0)>>1)-fragmentLength_bearerssubjecttostatustransferlist {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_bearerssubjecttostatustransferlist; i++ {
			var elem BearersSubjectToStatusTransferItemIEValueProtocolIESingleContainer
			elementMark := bb.EnterIndex(fragmentOffset_bearerssubjecttostatustransferlist + i)
			if err := elem.unmarshalAPERFrom(bb); err != nil {
				return runtime.WrapDecodePath(err, fmt.Sprintf("BearersSubjectToStatusTransferList[%d]", fragmentOffset_bearerssubjecttostatustransferlist+i))
			}
			bb.LeaveComponent(elementMark)
			if next, err := aper.AppendValues(bb, v.BearersSubjectToStatusTransferList, elem); err != nil {
				return err
			} else {
				v.BearersSubjectToStatusTransferList = next
			}
		}
		return nil
	})
	if errCollection_bearerssubjecttostatustransferlist != nil {
		return runtime.WrapDecodePath(errCollection_bearerssubjecttostatustransferlist, "BearersSubjectToStatusTransferList")
	}
	bb.LeaveComponent(toleranceMark_bearerssubjecttostatustransferlist)
	if opt_ieextensions {
		toleranceMark_ieextensions := bb.EnterComponent("IEExtensions")
		tmp_ieextensions := make(s08.ENBStatusTransferTransparentContainerExtIEsExtContainer, 0)
		_, errCollection_ieextensions := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1128
			if fragmentOffset_ieextensions < 0 || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(^uint(0)>>1) || fragmentOffset_ieextensions > int64(^uint(0)>>1)-fragmentLength_ieextensions {
				return fmt.Errorf("collection fragment count out of range")
			}
			for i := int64(0); i < fragmentLength_ieextensions; i++ {
				var elem s08.ENBStatusTransferTransparentContainerExtIEsExtField
				elementMark := bb.EnterIndex(fragmentOffset_ieextensions + i)
				if err := s08.BridgeENBStatusTransferTransparentContainerExtIEsExtFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
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

type BridgeAsn1cAPERERABListListValue struct{ Value s16.ERABList }
type BridgeAsn1cAPERERABUsageReportListListValue struct{ Value s17.ERABUsageReportList }
type BridgeAsn1cAPERForbiddenTAsListValue struct{ Value s18.ForbiddenTAs }
type BridgeAsn1cAPERForbiddenLAsListValue struct{ Value s18.ForbiddenLAs }
type BridgeAsn1cAPERInterSystemMeasurementListListValue struct {
	Value s18.InterSystemMeasurementList
}
type BridgeAsn1cAPERLastVisitedPSCellListListValue struct{ Value s20.LastVisitedPSCellList }
type BridgeAsn1cAPERMBSFNResultToLogListValue struct{ Value s19.MBSFNResultToLog }
type BridgeAsn1cAPERPC5QoSFlowListListValue struct{ Value s20.PC5QoSFlowList }
type BridgeAsn1cAPERRATRestrictionsListValue struct{ Value s20.RATRestrictions }
type BridgeAsn1cAPERECGIListForRestartListValue struct{ Value s17.ECGIListForRestart }
type BridgeAsn1cAPERCompletedCellinTAIListValue struct{ Value s17.CompletedCellinTAI }

// MarshalAPER encodes TransportInformation to APER format.
func (v *TransportInformation) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *TransportInformation) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
	if err := aper.EncodeBitStringAlignedExt(bb, v.TransportLayerAddress.Bytes, v.TransportLayerAddress.BitLength, 1, 160, true, true); err != nil {
		return fmt.Errorf("encoding transportLayerAddress: %w", err)
	}
	if err := aper.EncodeOctetStringAligned(bb, []byte(v.ULGTPTEID), 4, 4, true); err != nil {
		return fmt.Errorf("encoding uL-GTP-TEID: %w", err)
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

// UnmarshalAPER decodes TransportInformation from APER format.
func (v *TransportInformation) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes TransportInformation with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *TransportInformation) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "TransportInformation")
	}
	bb.EnterComponent("TransportInformation")
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "TransportInformation")
	}
	padding, err := aper.CaptureFinalBits(bb, "TransportInformation")
	if err != nil {
		return runtime.WrapDecodePath(err, "TransportInformation")
	}
	v.perPadding = padding.WithRecords(v.perPadding)
	return nil
}
func (v *TransportInformation) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = TransportInformation{}
	extAdditions := aper.BeginExtensionAdditions(bb)
	hasExtensions, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	bsBytes_transportlayeraddress, bsBitLen_transportlayeraddress, err := aper.DecodeBitStringAlignedExt(bb, 1, 160, true, true)
	if err != nil {
		return runtime.WrapDecodePath(err, "TransportLayerAddress")
	}
	v.TransportLayerAddress = runtime.BitString{Bytes: bsBytes_transportlayeraddress, BitLength: bsBitLen_transportlayeraddress}
	val_ulgtpteid, err := aper.DecodeOctetStringAligned(bb, 4, 4, true)
	if err != nil {
		return runtime.WrapDecodePath(err, "ULGTPTEID")
	}
	v.ULGTPTEID = s00.GTPTEID(val_ulgtpteid)
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

type BridgeAsn1cAPERENBX2ExtTLAsListValue struct{ Value s15.ENBX2ExtTLAs }

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *BearersSubjectToStatusTransferItem) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s14.BridgeReceivedFormAt(v.received, v.receivedBytes, "BearersSubjectToStatusTransferItem", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "BearersSubjectToStatusTransferItem", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v BearersSubjectToStatusTransferItem) WithoutReplay() BearersSubjectToStatusTransferItem {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero BearersSubjectToStatusTransferItem
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *ENBStatusTransferTransparentContainer) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s14.BridgeReceivedFormAt(v.received, v.receivedBytes, "ENBStatusTransferTransparentContainer", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "ENBStatusTransferTransparentContainer", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v ENBStatusTransferTransparentContainer) WithoutReplay() ENBStatusTransferTransparentContainer {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero ENBStatusTransferTransparentContainer
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *TransportInformation) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s14.BridgeReceivedFormAt(v.received, v.receivedBytes, "TransportInformation", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "TransportInformation", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v TransportInformation) WithoutReplay() TransportInformation {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero TransportInformation
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// Extensions returns owned unknown sequence additions.
func (v *BearersSubjectToStatusTransferItem) Extensions() []aper.SequenceExtension {
	if v == nil {
		return nil
	}
	views := aper.SequenceExtensionViews(v.extPresent, aper.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *BearersSubjectToStatusTransferItem) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("BearersSubjectToStatusTransferItem.Extensions[%d]", index))
	}
	if err := aper.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("BearersSubjectToStatusTransferItem.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *BearersSubjectToStatusTransferItem) RemoveExtension(index uint64) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("BearersSubjectToStatusTransferItem.Extensions[%d]", index))
	}
	if err := aper.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("BearersSubjectToStatusTransferItem.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// Extensions returns owned unknown sequence additions.
func (v *ENBStatusTransferTransparentContainer) Extensions() []aper.SequenceExtension {
	if v == nil {
		return nil
	}
	views := aper.SequenceExtensionViews(v.extPresent, aper.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *ENBStatusTransferTransparentContainer) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("ENBStatusTransferTransparentContainer.Extensions[%d]", index))
	}
	if err := aper.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("ENBStatusTransferTransparentContainer.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *ENBStatusTransferTransparentContainer) RemoveExtension(index uint64) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("ENBStatusTransferTransparentContainer.Extensions[%d]", index))
	}
	if err := aper.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("ENBStatusTransferTransparentContainer.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// Extensions returns owned unknown sequence additions.
func (v *TransportInformation) Extensions() []aper.SequenceExtension {
	if v == nil {
		return nil
	}
	views := aper.SequenceExtensionViews(v.extPresent, aper.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *TransportInformation) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("TransportInformation.Extensions[%d]", index))
	}
	if err := aper.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("TransportInformation.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *TransportInformation) RemoveExtension(index uint64) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("TransportInformation.Extensions[%d]", index))
	}
	if err := aper.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("TransportInformation.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// MarshalAPER encodes a complete value using one per-call change plan.
func (v *BearersSubjectToStatusTransferItem) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "BearersSubjectToStatusTransferItem")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *BearersSubjectToStatusTransferItem) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "BearersSubjectToStatusTransferItem")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APBearersSubjectToStatusTransferItem(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "BearersSubjectToStatusTransferItem")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "BearersSubjectToStatusTransferItem")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *BearersSubjectToStatusTransferItem) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "BearersSubjectToStatusTransferItem")
}
func (v *BearersSubjectToStatusTransferItem) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "BearersSubjectToStatusTransferItem")
}
func (v *BearersSubjectToStatusTransferItem) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APBearersSubjectToStatusTransferItem(v, &s)
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
func (v *BearersSubjectToStatusTransferItem) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *BearersSubjectToStatusTransferItem) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
func (v *ENBStatusTransferTransparentContainer) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "ENBStatusTransferTransparentContainer")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *ENBStatusTransferTransparentContainer) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "ENBStatusTransferTransparentContainer")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APENBStatusTransferTransparentContainer(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "ENBStatusTransferTransparentContainer")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "ENBStatusTransferTransparentContainer")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *ENBStatusTransferTransparentContainer) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "ENBStatusTransferTransparentContainer")
}
func (v *ENBStatusTransferTransparentContainer) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "ENBStatusTransferTransparentContainer")
}
func (v *ENBStatusTransferTransparentContainer) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APENBStatusTransferTransparentContainer(v, &s)
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
func (v *ENBStatusTransferTransparentContainer) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *ENBStatusTransferTransparentContainer) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
func (v *TransportInformation) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "TransportInformation")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *TransportInformation) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "TransportInformation")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APTransportInformation(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "TransportInformation")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "TransportInformation")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *TransportInformation) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "TransportInformation")
}
func (v *TransportInformation) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "TransportInformation")
}
func (v *TransportInformation) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APTransportInformation(v, &s)
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
func (v *TransportInformation) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *TransportInformation) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
func (v *BearersSubjectToStatusTransferItem) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "BearersSubjectToStatusTransferItem")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded BearersSubjectToStatusTransferItem
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APBearersSubjectToStatusTransferItem(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = BearersSubjectToStatusTransferItem{}
		return report, aper.OperationError(err, "BearersSubjectToStatusTransferItem")
	}
	*v = decoded
	return report, aper.OperationError(nil, "BearersSubjectToStatusTransferItem")
}

// UnmarshalAPER decodes one complete value and returns its report.
func (v *ENBStatusTransferTransparentContainer) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "ENBStatusTransferTransparentContainer")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded ENBStatusTransferTransparentContainer
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APENBStatusTransferTransparentContainer(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = ENBStatusTransferTransparentContainer{}
		return report, aper.OperationError(err, "ENBStatusTransferTransparentContainer")
	}
	*v = decoded
	return report, aper.OperationError(nil, "ENBStatusTransferTransparentContainer")
}

// UnmarshalAPER decodes one complete value and returns its report.
func (v *TransportInformation) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "TransportInformation")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded TransportInformation
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APTransportInformation(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = TransportInformation{}
		return report, aper.OperationError(err, "TransportInformation")
	}
	*v = decoded
	return report, aper.OperationError(nil, "TransportInformation")
}

// CellTrafficTrace represents the ASN.1 type CellTrafficTrace (SEQUENCE).
type CellTrafficTrace struct {
	replay           aper.Snapshot
	stream           aper.WireSpan
	received         bool
	withoutReplay    bool
	receivedAbsolute bool
	receivedBytes    aper.WireSpan
	receivedLocation aper.Location
	ProtocolIEs      s17.CellTrafficTraceIEContainer `asn1:"tag:0,context,implicit"`
	protocolIEsIndef bool                            `asn1:"-" json:"-"`
	extCount         int64                           `asn1:"-" json:"-"`
	extPresent       []bool                          `asn1:"-" json:"-"`
	extData          [][]byte                        `asn1:"-" json:"-"`
	perPadding       aper.FinalPadding               `asn1:"-" json:"-"`
	perExtPadding    []aper.CompletePadding          `asn1:"-" json:"-"`
	extOrigin        []aper.OpaqueOrigin
	extWire          []aper.WireSpan
}
type BridgeAsn1cAPERERABSubjecttoDataForwardingListListValue struct {
	Value s17.ERABSubjecttoDataForwardingList
}
type BridgeAsn1cAPERERABAdmittedListListValue struct{ Value s15.ERABAdmittedList }
type BridgeAsn1cAPERERABFailedtoSetupListHOReqAckListValue struct {
	Value s16.ERABFailedtoSetupListHOReqAck
}
type BridgeAsn1cAPERERABToBeSwitchedULListListValue struct{ Value s17.ERABToBeSwitchedULList }
type BridgeAsn1cAPERERABSetupListBearerSUResListValue struct{ Value s17.ERABSetupListBearerSURes }
type BridgeAsn1cAPERERABModifyListBearerModResListValue struct {
	Value s16.ERABModifyListBearerModRes
}
type BridgeAsn1cAPERERABReleaseListBearerRelCompListValue struct {
	Value s16.ERABReleaseListBearerRelComp
}
type BridgeAsn1cAPERERABSetupListCtxtSUResListValue struct{ Value s17.ERABSetupListCtxtSURes }

// MarshalAPER encodes CellTrafficTrace to APER format.
func (v *CellTrafficTrace) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *CellTrafficTrace) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
			if err := s17.BridgeCellTrafficTraceIEFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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

// UnmarshalAPER decodes CellTrafficTrace from APER format.
func (v *CellTrafficTrace) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes CellTrafficTrace with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *CellTrafficTrace) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "CellTrafficTrace")
	}
	bb.EnterComponent("CellTrafficTrace")
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "CellTrafficTrace")
	}
	padding, err := aper.CaptureFinalBits(bb, "CellTrafficTrace")
	if err != nil {
		return runtime.WrapDecodePath(err, "CellTrafficTrace")
	}
	v.perPadding = padding.WithRecords(v.perPadding)
	return nil
}
func (v *CellTrafficTrace) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = CellTrafficTrace{}
	extAdditions := aper.BeginExtensionAdditions(bb)
	hasExtensions, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	toleranceMark_protocolies := bb.EnterComponent("ProtocolIEs")
	v.ProtocolIEs = make(s17.CellTrafficTraceIEContainer, 0)
	_, errCollection_protocolies := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1128
		if fragmentOffset_protocolies < 0 || fragmentLength_protocolies < 0 || fragmentLength_protocolies > int64(^uint(0)>>1) || fragmentOffset_protocolies > int64(^uint(0)>>1)-fragmentLength_protocolies {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_protocolies; i++ {
			var elem s17.CellTrafficTraceIEField
			elementMark := bb.EnterIndex(fragmentOffset_protocolies + i)
			if err := s17.BridgeCellTrafficTraceIEFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
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

type BridgeAsn1cAPERERABToBeModifiedListBearerModIndListValue struct {
	Value s17.ERABToBeModifiedListBearerModInd
}
type BridgeAsn1cAPERERABNotToBeModifiedListBearerModIndListValue struct {
	Value s16.ERABNotToBeModifiedListBearerModInd
}
type BridgeAsn1cAPERERABModifyListBearerModConfListValue struct {
	Value s16.ERABModifyListBearerModConf
}
type BridgeAsn1cAPERERABFailedToResumeListResumeReqListValue struct {
	Value s16.ERABFailedToResumeListResumeReq
}
type BridgeAsn1cAPERERABFailedToResumeListResumeResListValue struct {
	Value s16.ERABFailedToResumeListResumeRes
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *CellTrafficTrace) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s14.BridgeReceivedFormAt(v.received, v.receivedBytes, "CellTrafficTrace", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "CellTrafficTrace", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v CellTrafficTrace) WithoutReplay() CellTrafficTrace {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero CellTrafficTrace
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// Extensions returns owned unknown sequence additions.
func (v *CellTrafficTrace) Extensions() []aper.SequenceExtension {
	if v == nil {
		return nil
	}
	views := aper.SequenceExtensionViews(v.extPresent, aper.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *CellTrafficTrace) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("CellTrafficTrace.Extensions[%d]", index))
	}
	if err := aper.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("CellTrafficTrace.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *CellTrafficTrace) RemoveExtension(index uint64) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("CellTrafficTrace.Extensions[%d]", index))
	}
	if err := aper.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("CellTrafficTrace.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// MarshalAPER encodes a complete value using one per-call change plan.
func (v *CellTrafficTrace) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "CellTrafficTrace")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *CellTrafficTrace) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "CellTrafficTrace")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APCellTrafficTrace(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "CellTrafficTrace")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "CellTrafficTrace")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *CellTrafficTrace) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "CellTrafficTrace")
}
func (v *CellTrafficTrace) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "CellTrafficTrace")
}
func (v *CellTrafficTrace) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APCellTrafficTrace(v, &s)
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
func (v *CellTrafficTrace) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *CellTrafficTrace) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
func (v *CellTrafficTrace) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "CellTrafficTrace")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded CellTrafficTrace
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APCellTrafficTrace(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = CellTrafficTrace{}
		return report, aper.OperationError(err, "CellTrafficTrace")
	}
	*v = decoded
	return report, aper.OperationError(nil, "CellTrafficTrace")
}

// CellActivationResponse represents the ASN.1 type CellActivationResponse (SEQUENCE).
type CellActivationResponse struct {
	replay                  aper.Snapshot
	stream                  aper.WireSpan
	received                bool
	withoutReplay           bool
	receivedAbsolute        bool
	receivedBytes           aper.WireSpan
	receivedLocation        aper.Location
	ActivatedCellsList      s14.ActivatedCellsList `asn1:"tag:0,context,implicit"`
	activatedCellsListIndef bool                   `asn1:"-" json:"-"`
	extCount                int64                  `asn1:"-" json:"-"`
	extPresent              []bool                 `asn1:"-" json:"-"`
	extData                 [][]byte               `asn1:"-" json:"-"`
	perPadding              aper.FinalPadding      `asn1:"-" json:"-"`
	perExtPadding           []aper.CompletePadding `asn1:"-" json:"-"`
	extOrigin               []aper.OpaqueOrigin
	extWire                 []aper.WireSpan
}
type BridgeAsn1cAPERRequestedCellListListValue struct{ Value s20.RequestedCellList }
type BridgeAsn1cAPERReportingCellListListValue struct{ Value s20.ReportingCellList }
type BridgeAsn1cAPERMultiCellLoadReportingResponseListValue struct {
	Value s19.MultiCellLoadReportingResponse
}
type BridgeAsn1cAPERCandidateCellListListValue struct{ Value s18.CandidateCellList }
type BridgeAsn1cAPERCandidatePCIListListValue struct{ Value s14.CandidatePCIList }
type BridgeAsn1cAPERCellsToActivateListListValue struct{ Value s14.CellsToActivateList }

// MarshalAPER encodes CellActivationResponse to APER format.
func (v *CellActivationResponse) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *CellActivationResponse) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
	if v.withoutReplay {
		fresh = []bool{true}
	}
	if len(fresh) > 0 && fresh[0] {
		previous := bb.SuspendReplayPlan()
		defer bb.RestoreReplayPlan(previous)
	}
	if v != nil && bb.ReplayPlan() != nil && bb.ReplayPlan().Unchanged(v.replay) && !v.withoutReplay {
		if ok, err := v.stream.ReplayTo(bb); ok || err != nil {
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
	if err := aper.EncodeCollection(bb, int64(len(v.ActivatedCellsList)), aper.SizeConstraint{Lower: 0, HasLower: true, Upper: 256, HasUpper: true}, true, func(fragmentOffset_activatedcellslist, fragmentLength_activatedcellslist int64) error {
		// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
		if fragmentOffset_activatedcellslist < 0 || fragmentOffset_activatedcellslist > int64(len(v.ActivatedCellsList)) || fragmentLength_activatedcellslist < 0 || fragmentLength_activatedcellslist > int64(len(v.ActivatedCellsList[fragmentOffset_activatedcellslist:])) {
			return fmt.Errorf("collection fragment outside value")
		}
		for _, elem := range v.ActivatedCellsList[fragmentOffset_activatedcellslist : fragmentOffset_activatedcellslist+fragmentLength_activatedcellslist] {
			if err := s14.BridgeActivatedCellsListItemMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
				return fmt.Errorf("encoding activatedCellsList element: %w", err)
			}
		}
		return nil
	}); err != nil {
		return fmt.Errorf("encoding activatedCellsList: %w", err)
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

// UnmarshalAPER decodes CellActivationResponse from APER format.
func (v *CellActivationResponse) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes CellActivationResponse with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *CellActivationResponse) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "CellActivationResponse")
	}
	bb.EnterComponent("CellActivationResponse")
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "CellActivationResponse")
	}
	padding, err := aper.CaptureFinalBits(bb, "CellActivationResponse")
	if err != nil {
		return runtime.WrapDecodePath(err, "CellActivationResponse")
	}
	v.perPadding = padding.WithRecords(v.perPadding)
	return nil
}
func (v *CellActivationResponse) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = CellActivationResponse{}
	extAdditions := aper.BeginExtensionAdditions(bb)
	hasExtensions, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	toleranceMark_activatedcellslist := bb.EnterComponent("ActivatedCellsList")
	v.ActivatedCellsList = make(s14.ActivatedCellsList, 0)
	_, errCollection_activatedcellslist := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 0, HasLower: true, Upper: 256, HasUpper: true}, true, func(fragmentOffset_activatedcellslist, fragmentLength_activatedcellslist int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1128
		if fragmentOffset_activatedcellslist < 0 || fragmentLength_activatedcellslist < 0 || fragmentLength_activatedcellslist > int64(^uint(0)>>1) || fragmentOffset_activatedcellslist > int64(^uint(0)>>1)-fragmentLength_activatedcellslist {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_activatedcellslist; i++ {
			var elem s14.ActivatedCellsListItem
			elementMark := bb.EnterIndex(fragmentOffset_activatedcellslist + i)
			if err := s14.BridgeActivatedCellsListItemMethodUnmarshalAPERFrom(&elem, bb); err != nil {
				return runtime.WrapDecodePath(err, fmt.Sprintf("ActivatedCellsList[%d]", fragmentOffset_activatedcellslist+i))
			}
			bb.LeaveComponent(elementMark)
			if next, err := aper.AppendValues(bb, v.ActivatedCellsList, elem); err != nil {
				return err
			} else {
				v.ActivatedCellsList = next
			}
		}
		return nil
	})
	if errCollection_activatedcellslist != nil {
		return runtime.WrapDecodePath(errCollection_activatedcellslist, "ActivatedCellsList")
	}
	bb.LeaveComponent(toleranceMark_activatedcellslist)
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
				opaque, err := aper.DecodeOpaqueOpenTypeAligned(bb, aper.UnknownSelector, aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "Annex B.2"})
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

type BridgeAsn1cAPERActivatedCellsListListValue struct{ Value s14.ActivatedCellsList }
type BridgeAsn1cAPERNotificationCellListListValue struct{ Value s19.NotificationCellList }

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *CellActivationResponse) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s14.BridgeReceivedFormAt(v.received, v.receivedBytes, "CellActivationResponse", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "CellActivationResponse", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v CellActivationResponse) WithoutReplay() CellActivationResponse {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero CellActivationResponse
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// Extensions returns owned unknown sequence additions.
func (v *CellActivationResponse) Extensions() []aper.SequenceExtension {
	if v == nil {
		return nil
	}
	views := aper.SequenceExtensionViews(v.extPresent, aper.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *CellActivationResponse) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("CellActivationResponse.Extensions[%d]", index))
	}
	if err := aper.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("CellActivationResponse.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *CellActivationResponse) RemoveExtension(index uint64) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("CellActivationResponse.Extensions[%d]", index))
	}
	if err := aper.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("CellActivationResponse.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// MarshalAPER encodes a complete value using one per-call change plan.
func (v *CellActivationResponse) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "CellActivationResponse")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *CellActivationResponse) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "CellActivationResponse")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APCellActivationResponse(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "CellActivationResponse")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "CellActivationResponse")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *CellActivationResponse) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "CellActivationResponse")
}
func (v *CellActivationResponse) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "CellActivationResponse")
}
func (v *CellActivationResponse) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APCellActivationResponse(v, &s)
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
func (v *CellActivationResponse) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *CellActivationResponse) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
func (v *CellActivationResponse) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "CellActivationResponse")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded CellActivationResponse
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APCellActivationResponse(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = CellActivationResponse{}
		return report, aper.OperationError(err, "CellActivationResponse")
	}
	*v = decoded
	return report, aper.OperationError(nil, "CellActivationResponse")
}

type BearersSubjectToStatusTransferItemIEValue struct {
	id                                    s00.ProtocolIEID
	received                              aper.WireSpan
	replay                                aper.Snapshot
	opaque                                aper.OpaqueOpenType
	isOpaque                              bool
	rowBearersSubjectToStatusTransferItem *BearersSubjectToStatusTransferItem
}

func (v BearersSubjectToStatusTransferItemIEValue) matchesID(id s00.ProtocolIEID, _ ...*aper.DecodeBudget) bool {
	if v.id != id {
		return false
	}
	if v.isOpaque {
		return true
	}
	switch id {
	case s00.ProtocolIEID(89):
		return v.rowBearersSubjectToStatusTransferItem != nil
	}
	return false
}

// Opaque returns the retained opaque open value of BearersSubjectToStatusTransferItemIEValue and reports whether the opaque alternative is selected.
func (v *BearersSubjectToStatusTransferItemIEValue) Opaque() (aper.OpaqueOpenType, bool) {
	if v == nil || !v.isOpaque {
		return aper.OpaqueOpenType{}, false
	}
	return v.opaque, true
}
func (BearersSubjectToStatusTransferItemIEValue) rule() aper.SourceRule {
	return aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.4", Assignment: aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "Bearers-SubjectToStatusTransfer-ItemIEs"}}
}
func (BearersSubjectToStatusTransferItemIEValue) reason(id s00.ProtocolIEID) aper.OpaqueReason {
	switch id {
	case s00.ProtocolIEID(89):
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

// AsBearersSubjectToStatusTransferItem returns the selected BearersSubjectToStatusTransferItem value of BearersSubjectToStatusTransferItemIEValue and reports whether that alternative is active.
func (v *BearersSubjectToStatusTransferItemIEValue) AsBearersSubjectToStatusTransferItem() (*BearersSubjectToStatusTransferItem, bool) {
	if v == nil || v.id != s00.ProtocolIEID(89) || v.rowBearersSubjectToStatusTransferItem == nil {
		return nil, false
	}
	return v.rowBearersSubjectToStatusTransferItem, true
}
func (v BearersSubjectToStatusTransferItemIEValue) decode(id s00.ProtocolIEID, raw aper.OpaqueOpenType) (BearersSubjectToStatusTransferItemIEValue, error) {
	out := BearersSubjectToStatusTransferItemIEValue{id: id}
	switch id {
	case s00.ProtocolIEID(89):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		var value BearersSubjectToStatusTransferItem
		child := scope
		if err := value.unmarshalAPERFrom(child); err != nil {
			return out, fmt.Errorf("%s %w", "BearersSubjectToStatusTransferItem:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "BearersSubjectToStatusTransferItem")
		if err != nil {
			return out, err
		}
		value.perPadding = padding
		value.received = true
		raw.RetainContents(&value.receivedBytes)
		value.receivedLocation = raw.ContentLocation()
		out.rowBearersSubjectToStatusTransferItem = &value
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
func (v BearersSubjectToStatusTransferItemIEValue) encode() ([]byte, error) {
	return v.encodeFresh(false, nil)
}
func (v BearersSubjectToStatusTransferItemIEValue) encodeFresh(fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
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
	case s00.ProtocolIEID(89):
		if v.rowBearersSubjectToStatusTransferItem == nil {
			return nil, fmt.Errorf("%s missing value", "Bearers-SubjectToStatusTransfer-ItemIEs.id-Bearers-SubjectToStatusTransfer-Item:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		candidate, err := v.rowBearersSubjectToStatusTransferItem.marshalAPERBudget(budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	default:
		return nil, fmt.Errorf("%s id %d has no value", "BearersSubjectToStatusTransferItemIEValue:", v.id)
	}
}

type UserLocationInformationExtIEsValue struct {
	id                      s00.ProtocolIEID
	received                aper.WireSpan
	replay                  aper.Snapshot
	opaque                  aper.OpaqueOpenType
	isOpaque                bool
	rowPSCellInformation    *s20.PSCellInformation
	rowLTENTNTAIInformation *s18.LTENTNTAIInformation
}

func (v UserLocationInformationExtIEsValue) matchesID(id s00.ProtocolIEID, _ ...*aper.DecodeBudget) bool {
	if v.id != id {
		return false
	}
	if v.isOpaque {
		return true
	}
	switch id {
	case s00.ProtocolIEID(288):
		return v.rowPSCellInformation != nil
	case s00.ProtocolIEID(339):
		return v.rowLTENTNTAIInformation != nil
	}
	return false
}

// Opaque returns the retained opaque open value of UserLocationInformationExtIEsValue and reports whether the opaque alternative is selected.
func (v *UserLocationInformationExtIEsValue) Opaque() (aper.OpaqueOpenType, bool) {
	if v == nil || !v.isOpaque {
		return aper.OpaqueOpenType{}, false
	}
	return v.opaque, true
}
func (UserLocationInformationExtIEsValue) rule() aper.SourceRule {
	return aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.4", Assignment: aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "UserLocationInformation-ExtIEs"}}
}
func (UserLocationInformationExtIEsValue) reason(id s00.ProtocolIEID) aper.OpaqueReason {
	switch id {
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

// AsPSCellInformation returns the selected PSCellInformation value of UserLocationInformationExtIEsValue and reports whether that alternative is active.
func (v *UserLocationInformationExtIEsValue) AsPSCellInformation() (*s20.PSCellInformation, bool) {
	if v == nil || v.id != s00.ProtocolIEID(288) || v.rowPSCellInformation == nil {
		return nil, false
	}
	return v.rowPSCellInformation, true
}

// AsLTENTNTAIInformation returns the selected LTENTNTAIInformation value of UserLocationInformationExtIEsValue and reports whether that alternative is active.
func (v *UserLocationInformationExtIEsValue) AsLTENTNTAIInformation() (*s18.LTENTNTAIInformation, bool) {
	if v == nil || v.id != s00.ProtocolIEID(339) || v.rowLTENTNTAIInformation == nil {
		return nil, false
	}
	return v.rowLTENTNTAIInformation, true
}
func (v UserLocationInformationExtIEsValue) decode(id s00.ProtocolIEID, raw aper.OpaqueOpenType) (UserLocationInformationExtIEsValue, error) {
	out := UserLocationInformationExtIEsValue{id: id}
	switch id {
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
func (v UserLocationInformationExtIEsValue) encode() ([]byte, error) {
	return v.encodeFresh(false, nil)
}
func (v UserLocationInformationExtIEsValue) encodeFresh(fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
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
	case s00.ProtocolIEID(288):
		if v.rowPSCellInformation == nil {
			return nil, fmt.Errorf("%s missing value", "UserLocationInformation-ExtIEs.id-PSCellInformation:")
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
			return nil, fmt.Errorf("%s missing value", "UserLocationInformation-ExtIEs.id-LTE-NTN-TAI-Information:")
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
		return nil, fmt.Errorf("%s id %d has no value", "UserLocationInformationExtIEsValue:", v.id)
	}
}

type ERABToBeModifyItemBearerModReqExtIEsValue struct {
	id                      s00.ProtocolIEID
	received                aper.WireSpan
	replay                  aper.Snapshot
	opaque                  aper.OpaqueOpenType
	isOpaque                bool
	rowTransportInformation *TransportInformation
}

func (v ERABToBeModifyItemBearerModReqExtIEsValue) matchesID(id s00.ProtocolIEID, _ ...*aper.DecodeBudget) bool {
	if v.id != id {
		return false
	}
	if v.isOpaque {
		return true
	}
	switch id {
	case s00.ProtocolIEID(185):
		return v.rowTransportInformation != nil
	}
	return false
}

// Opaque returns the retained opaque open value of ERABToBeModifyItemBearerModReqExtIEsValue and reports whether the opaque alternative is selected.
func (v *ERABToBeModifyItemBearerModReqExtIEsValue) Opaque() (aper.OpaqueOpenType, bool) {
	if v == nil || !v.isOpaque {
		return aper.OpaqueOpenType{}, false
	}
	return v.opaque, true
}
func (ERABToBeModifyItemBearerModReqExtIEsValue) rule() aper.SourceRule {
	return aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "E-RABToBeModifyItemBearerModReqExtIEs"}}
}
func (ERABToBeModifyItemBearerModReqExtIEsValue) reason(id s00.ProtocolIEID) aper.OpaqueReason {
	switch id {
	case s00.ProtocolIEID(185):
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

// AsTransportInformation returns the selected TransportInformation value of ERABToBeModifyItemBearerModReqExtIEsValue and reports whether that alternative is active.
func (v *ERABToBeModifyItemBearerModReqExtIEsValue) AsTransportInformation() (*TransportInformation, bool) {
	if v == nil || v.id != s00.ProtocolIEID(185) || v.rowTransportInformation == nil {
		return nil, false
	}
	return v.rowTransportInformation, true
}
func (v ERABToBeModifyItemBearerModReqExtIEsValue) decode(id s00.ProtocolIEID, raw aper.OpaqueOpenType) (ERABToBeModifyItemBearerModReqExtIEsValue, error) {
	out := ERABToBeModifyItemBearerModReqExtIEsValue{id: id}
	switch id {
	case s00.ProtocolIEID(185):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		var value TransportInformation
		child := scope
		if err := value.unmarshalAPERFrom(child); err != nil {
			return out, fmt.Errorf("%s %w", "TransportInformation:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "TransportInformation")
		if err != nil {
			return out, err
		}
		value.perPadding = padding
		value.received = true
		raw.RetainContents(&value.receivedBytes)
		value.receivedLocation = raw.ContentLocation()
		out.rowTransportInformation = &value
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
func (v ERABToBeModifyItemBearerModReqExtIEsValue) encode() ([]byte, error) {
	return v.encodeFresh(false, nil)
}
func (v ERABToBeModifyItemBearerModReqExtIEsValue) encodeFresh(fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
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
	case s00.ProtocolIEID(185):
		if v.rowTransportInformation == nil {
			return nil, fmt.Errorf("%s missing value", "E-RABToBeModifyItemBearerModReqExtIEs.id-TransportInformation:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		candidate, err := v.rowTransportInformation.marshalAPERBudget(budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	default:
		return nil, fmt.Errorf("%s id %d has no value", "ERABToBeModifyItemBearerModReqExtIEsValue:", v.id)
	}
}

type ENBStatusTransferIEValue struct {
	id                                       s00.ProtocolIEID
	received                                 aper.WireSpan
	replay                                   aper.Snapshot
	opaque                                   aper.OpaqueOpenType
	isOpaque                                 bool
	rowMMEUES1APID                           *s00.MMEUES1APID
	rowENBUES1APID                           *s00.ENBUES1APID
	rowENBStatusTransferTransparentContainer *ENBStatusTransferTransparentContainer
}

func (v ENBStatusTransferIEValue) matchesID(id s00.ProtocolIEID, _ ...*aper.DecodeBudget) bool {
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
	case s00.ProtocolIEID(90):
		return v.rowENBStatusTransferTransparentContainer != nil
	}
	return false
}

// Opaque returns the retained opaque open value of ENBStatusTransferIEValue and reports whether the opaque alternative is selected.
func (v *ENBStatusTransferIEValue) Opaque() (aper.OpaqueOpenType, bool) {
	if v == nil || !v.isOpaque {
		return aper.OpaqueOpenType{}, false
	}
	return v.opaque, true
}
func (ENBStatusTransferIEValue) rule() aper.SourceRule {
	return aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "ENBStatusTransferIEs"}}
}
func (ENBStatusTransferIEValue) reason(id s00.ProtocolIEID) aper.OpaqueReason {
	switch id {
	case s00.ProtocolIEID(0):
		return aper.UnknownSelector
	case s00.ProtocolIEID(8):
		return aper.UnknownSelector
	case s00.ProtocolIEID(90):
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

// AsMMEUES1APID returns the selected MMEUES1APID value of ENBStatusTransferIEValue and reports whether that alternative is active.
func (v *ENBStatusTransferIEValue) AsMMEUES1APID() (*s00.MMEUES1APID, bool) {
	if v == nil || v.id != s00.ProtocolIEID(0) || v.rowMMEUES1APID == nil {
		return nil, false
	}
	return v.rowMMEUES1APID, true
}

// AsENBUES1APID returns the selected ENBUES1APID value of ENBStatusTransferIEValue and reports whether that alternative is active.
func (v *ENBStatusTransferIEValue) AsENBUES1APID() (*s00.ENBUES1APID, bool) {
	if v == nil || v.id != s00.ProtocolIEID(8) || v.rowENBUES1APID == nil {
		return nil, false
	}
	return v.rowENBUES1APID, true
}

// AsENBStatusTransferTransparentContainer returns the selected ENBStatusTransferTransparentContainer value of ENBStatusTransferIEValue and reports whether that alternative is active.
func (v *ENBStatusTransferIEValue) AsENBStatusTransferTransparentContainer() (*ENBStatusTransferTransparentContainer, bool) {
	if v == nil || v.id != s00.ProtocolIEID(90) || v.rowENBStatusTransferTransparentContainer == nil {
		return nil, false
	}
	return v.rowENBStatusTransferTransparentContainer, true
}
func (v ENBStatusTransferIEValue) decode(id s00.ProtocolIEID, raw aper.OpaqueOpenType) (ENBStatusTransferIEValue, error) {
	out := ENBStatusTransferIEValue{id: id}
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
	case s00.ProtocolIEID(90):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		var value ENBStatusTransferTransparentContainer
		child := scope
		if err := value.unmarshalAPERFrom(child); err != nil {
			return out, fmt.Errorf("%s %w", "ENBStatusTransferTransparentContainer:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "ENBStatusTransferTransparentContainer")
		if err != nil {
			return out, err
		}
		value.perPadding = padding
		value.received = true
		raw.RetainContents(&value.receivedBytes)
		value.receivedLocation = raw.ContentLocation()
		out.rowENBStatusTransferTransparentContainer = &value
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
func (v ENBStatusTransferIEValue) encode() ([]byte, error) { return v.encodeFresh(false, nil) }
func (v ENBStatusTransferIEValue) encodeFresh(fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
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
			return nil, fmt.Errorf("%s missing value", "ENBStatusTransferIEs.id-MME-UE-S1AP-ID:")
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
			return nil, fmt.Errorf("%s missing value", "ENBStatusTransferIEs.id-eNB-UE-S1AP-ID:")
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
	case s00.ProtocolIEID(90):
		if v.rowENBStatusTransferTransparentContainer == nil {
			return nil, fmt.Errorf("%s missing value", "ENBStatusTransferIEs.id-eNB-StatusTransfer-TransparentContainer:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		candidate, err := v.rowENBStatusTransferTransparentContainer.marshalAPERBudget(budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	default:
		return nil, fmt.Errorf("%s id %d has no value", "ENBStatusTransferIEValue:", v.id)
	}
}

type MMEStatusTransferIEValue struct {
	id                                       s00.ProtocolIEID
	received                                 aper.WireSpan
	replay                                   aper.Snapshot
	opaque                                   aper.OpaqueOpenType
	isOpaque                                 bool
	rowMMEUES1APID                           *s00.MMEUES1APID
	rowENBUES1APID                           *s00.ENBUES1APID
	rowENBStatusTransferTransparentContainer *ENBStatusTransferTransparentContainer
}

func (v MMEStatusTransferIEValue) matchesID(id s00.ProtocolIEID, _ ...*aper.DecodeBudget) bool {
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
	case s00.ProtocolIEID(90):
		return v.rowENBStatusTransferTransparentContainer != nil
	}
	return false
}

// Opaque returns the retained opaque open value of MMEStatusTransferIEValue and reports whether the opaque alternative is selected.
func (v *MMEStatusTransferIEValue) Opaque() (aper.OpaqueOpenType, bool) {
	if v == nil || !v.isOpaque {
		return aper.OpaqueOpenType{}, false
	}
	return v.opaque, true
}
func (MMEStatusTransferIEValue) rule() aper.SourceRule {
	return aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "MMEStatusTransferIEs"}}
}
func (MMEStatusTransferIEValue) reason(id s00.ProtocolIEID) aper.OpaqueReason {
	switch id {
	case s00.ProtocolIEID(0):
		return aper.UnknownSelector
	case s00.ProtocolIEID(8):
		return aper.UnknownSelector
	case s00.ProtocolIEID(90):
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

// AsMMEUES1APID returns the selected MMEUES1APID value of MMEStatusTransferIEValue and reports whether that alternative is active.
func (v *MMEStatusTransferIEValue) AsMMEUES1APID() (*s00.MMEUES1APID, bool) {
	if v == nil || v.id != s00.ProtocolIEID(0) || v.rowMMEUES1APID == nil {
		return nil, false
	}
	return v.rowMMEUES1APID, true
}

// AsENBUES1APID returns the selected ENBUES1APID value of MMEStatusTransferIEValue and reports whether that alternative is active.
func (v *MMEStatusTransferIEValue) AsENBUES1APID() (*s00.ENBUES1APID, bool) {
	if v == nil || v.id != s00.ProtocolIEID(8) || v.rowENBUES1APID == nil {
		return nil, false
	}
	return v.rowENBUES1APID, true
}

// AsENBStatusTransferTransparentContainer returns the selected ENBStatusTransferTransparentContainer value of MMEStatusTransferIEValue and reports whether that alternative is active.
func (v *MMEStatusTransferIEValue) AsENBStatusTransferTransparentContainer() (*ENBStatusTransferTransparentContainer, bool) {
	if v == nil || v.id != s00.ProtocolIEID(90) || v.rowENBStatusTransferTransparentContainer == nil {
		return nil, false
	}
	return v.rowENBStatusTransferTransparentContainer, true
}
func (v MMEStatusTransferIEValue) decode(id s00.ProtocolIEID, raw aper.OpaqueOpenType) (MMEStatusTransferIEValue, error) {
	out := MMEStatusTransferIEValue{id: id}
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
	case s00.ProtocolIEID(90):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		var value ENBStatusTransferTransparentContainer
		child := scope
		if err := value.unmarshalAPERFrom(child); err != nil {
			return out, fmt.Errorf("%s %w", "ENBStatusTransferTransparentContainer:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "ENBStatusTransferTransparentContainer")
		if err != nil {
			return out, err
		}
		value.perPadding = padding
		value.received = true
		raw.RetainContents(&value.receivedBytes)
		value.receivedLocation = raw.ContentLocation()
		out.rowENBStatusTransferTransparentContainer = &value
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
func (v MMEStatusTransferIEValue) encode() ([]byte, error) { return v.encodeFresh(false, nil) }
func (v MMEStatusTransferIEValue) encodeFresh(fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
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
			return nil, fmt.Errorf("%s missing value", "MMEStatusTransferIEs.id-MME-UE-S1AP-ID:")
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
			return nil, fmt.Errorf("%s missing value", "MMEStatusTransferIEs.id-eNB-UE-S1AP-ID:")
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
	case s00.ProtocolIEID(90):
		if v.rowENBStatusTransferTransparentContainer == nil {
			return nil, fmt.Errorf("%s missing value", "MMEStatusTransferIEs.id-eNB-StatusTransfer-TransparentContainer:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		candidate, err := v.rowENBStatusTransferTransparentContainer.marshalAPERBudget(budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	default:
		return nil, fmt.Errorf("%s id %d has no value", "MMEStatusTransferIEValue:", v.id)
	}
}

type UEContextModificationIndicationIEValue struct {
	id                   s00.ProtocolIEID
	received             aper.WireSpan
	replay               aper.Snapshot
	opaque               aper.OpaqueOpenType
	isOpaque             bool
	rowMMEUES1APID       *s00.MMEUES1APID
	rowENBUES1APID       *s00.ENBUES1APID
	rowCSGMembershipInfo *s14.CSGMembershipInfo
}

func (v UEContextModificationIndicationIEValue) matchesID(id s00.ProtocolIEID, _ ...*aper.DecodeBudget) bool {
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
	case s00.ProtocolIEID(226):
		return v.rowCSGMembershipInfo != nil
	}
	return false
}

// Opaque returns the retained opaque open value of UEContextModificationIndicationIEValue and reports whether the opaque alternative is selected.
func (v *UEContextModificationIndicationIEValue) Opaque() (aper.OpaqueOpenType, bool) {
	if v == nil || !v.isOpaque {
		return aper.OpaqueOpenType{}, false
	}
	return v.opaque, true
}
func (UEContextModificationIndicationIEValue) rule() aper.SourceRule {
	return aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "UEContextModificationIndicationIEs"}}
}
func (UEContextModificationIndicationIEValue) reason(id s00.ProtocolIEID) aper.OpaqueReason {
	switch id {
	case s00.ProtocolIEID(0):
		return aper.UnknownSelector
	case s00.ProtocolIEID(8):
		return aper.UnknownSelector
	case s00.ProtocolIEID(226):
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

// AsMMEUES1APID returns the selected MMEUES1APID value of UEContextModificationIndicationIEValue and reports whether that alternative is active.
func (v *UEContextModificationIndicationIEValue) AsMMEUES1APID() (*s00.MMEUES1APID, bool) {
	if v == nil || v.id != s00.ProtocolIEID(0) || v.rowMMEUES1APID == nil {
		return nil, false
	}
	return v.rowMMEUES1APID, true
}

// AsENBUES1APID returns the selected ENBUES1APID value of UEContextModificationIndicationIEValue and reports whether that alternative is active.
func (v *UEContextModificationIndicationIEValue) AsENBUES1APID() (*s00.ENBUES1APID, bool) {
	if v == nil || v.id != s00.ProtocolIEID(8) || v.rowENBUES1APID == nil {
		return nil, false
	}
	return v.rowENBUES1APID, true
}

// AsCSGMembershipInfo returns the selected CSGMembershipInfo value of UEContextModificationIndicationIEValue and reports whether that alternative is active.
func (v *UEContextModificationIndicationIEValue) AsCSGMembershipInfo() (*s14.CSGMembershipInfo, bool) {
	if v == nil || v.id != s00.ProtocolIEID(226) || v.rowCSGMembershipInfo == nil {
		return nil, false
	}
	return v.rowCSGMembershipInfo, true
}
func (v UEContextModificationIndicationIEValue) decode(id s00.ProtocolIEID, raw aper.OpaqueOpenType) (UEContextModificationIndicationIEValue, error) {
	out := UEContextModificationIndicationIEValue{id: id}
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
	case s00.ProtocolIEID(226):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		var value s14.CSGMembershipInfo
		child := scope
		if err := s14.BridgeCSGMembershipInfoMethodUnmarshalAPERFrom(&value, child); err != nil {
			return out, fmt.Errorf("%s %w", "CSGMembershipInfo:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "CSGMembershipInfo")
		if err != nil {
			return out, err
		}
		*s14.BridgeCSGMembershipInfoFieldPerPadding(&value) = padding
		*s14.BridgeCSGMembershipInfoFieldReceived(&value) = true
		raw.RetainContents(s14.BridgeCSGMembershipInfoFieldReceivedBytes(&value))
		*s14.BridgeCSGMembershipInfoFieldReceivedLocation(&value) = raw.ContentLocation()
		out.rowCSGMembershipInfo = &value
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
func (v UEContextModificationIndicationIEValue) encode() ([]byte, error) {
	return v.encodeFresh(false, nil)
}
func (v UEContextModificationIndicationIEValue) encodeFresh(fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
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
			return nil, fmt.Errorf("%s missing value", "UEContextModificationIndicationIEs.id-MME-UE-S1AP-ID:")
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
			return nil, fmt.Errorf("%s missing value", "UEContextModificationIndicationIEs.id-eNB-UE-S1AP-ID:")
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
	case s00.ProtocolIEID(226):
		if v.rowCSGMembershipInfo == nil {
			return nil, fmt.Errorf("%s missing value", "UEContextModificationIndicationIEs.id-CSGMembershipInfo:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		candidate, err := s14.BridgeCSGMembershipInfoMethodMarshalAPERBudget(v.rowCSGMembershipInfo, budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	default:
		return nil, fmt.Errorf("%s id %d has no value", "UEContextModificationIndicationIEValue:", v.id)
	}
}

type UplinkS1cdma2000tunnellingIEValue struct {
	id                                    s00.ProtocolIEID
	received                              aper.WireSpan
	replay                                aper.Snapshot
	opaque                                aper.OpaqueOpenType
	isOpaque                              bool
	rowMMEUES1APID                        *s00.MMEUES1APID
	rowENBUES1APID                        *s00.ENBUES1APID
	rowCdma2000RATType                    *s00.Cdma2000RATType
	rowCdma2000SectorID                   *s00.Cdma2000SectorID
	rowCdma2000HORequiredIndication       *s00.Cdma2000HORequiredIndication
	rowCdma2000OneXSRVCCInfo              *s14.Cdma2000OneXSRVCCInfo
	rowCdma2000OneXRAND                   *s00.Cdma2000OneXRAND
	rowCdma2000PDU                        *s00.Cdma2000PDU
	rowEUTRANRoundTripDelayEstimationInfo *s00.EUTRANRoundTripDelayEstimationInfo
}

func (v UplinkS1cdma2000tunnellingIEValue) matchesID(id s00.ProtocolIEID, _ ...*aper.DecodeBudget) bool {
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
	case s00.ProtocolIEID(71):
		return v.rowCdma2000RATType != nil
	case s00.ProtocolIEID(72):
		return v.rowCdma2000SectorID != nil
	case s00.ProtocolIEID(84):
		return v.rowCdma2000HORequiredIndication != nil
	case s00.ProtocolIEID(102):
		return v.rowCdma2000OneXSRVCCInfo != nil
	case s00.ProtocolIEID(97):
		return v.rowCdma2000OneXRAND != nil
	case s00.ProtocolIEID(70):
		return v.rowCdma2000PDU != nil
	case s00.ProtocolIEID(140):
		return v.rowEUTRANRoundTripDelayEstimationInfo != nil
	}
	return false
}

// Opaque returns the retained opaque open value of UplinkS1cdma2000tunnellingIEValue and reports whether the opaque alternative is selected.
func (v *UplinkS1cdma2000tunnellingIEValue) Opaque() (aper.OpaqueOpenType, bool) {
	if v == nil || !v.isOpaque {
		return aper.OpaqueOpenType{}, false
	}
	return v.opaque, true
}
func (UplinkS1cdma2000tunnellingIEValue) rule() aper.SourceRule {
	return aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "UplinkS1cdma2000tunnellingIEs"}}
}
func (UplinkS1cdma2000tunnellingIEValue) reason(id s00.ProtocolIEID) aper.OpaqueReason {
	switch id {
	case s00.ProtocolIEID(0):
		return aper.UnknownSelector
	case s00.ProtocolIEID(8):
		return aper.UnknownSelector
	case s00.ProtocolIEID(71):
		return aper.UnknownSelector
	case s00.ProtocolIEID(72):
		return aper.UnknownSelector
	case s00.ProtocolIEID(84):
		return aper.UnknownSelector
	case s00.ProtocolIEID(102):
		return aper.UnknownSelector
	case s00.ProtocolIEID(97):
		return aper.UnknownSelector
	case s00.ProtocolIEID(70):
		return aper.UnknownSelector
	case s00.ProtocolIEID(140):
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
	case s00.ProtocolIEID(98):
		return aper.NotInTable
	case s00.ProtocolIEID(99):
		return aper.NotInTable
	case s00.ProtocolIEID(100):
		return aper.NotInTable
	case s00.ProtocolIEID(101):
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

// AsMMEUES1APID returns the selected MMEUES1APID value of UplinkS1cdma2000tunnellingIEValue and reports whether that alternative is active.
func (v *UplinkS1cdma2000tunnellingIEValue) AsMMEUES1APID() (*s00.MMEUES1APID, bool) {
	if v == nil || v.id != s00.ProtocolIEID(0) || v.rowMMEUES1APID == nil {
		return nil, false
	}
	return v.rowMMEUES1APID, true
}

// AsENBUES1APID returns the selected ENBUES1APID value of UplinkS1cdma2000tunnellingIEValue and reports whether that alternative is active.
func (v *UplinkS1cdma2000tunnellingIEValue) AsENBUES1APID() (*s00.ENBUES1APID, bool) {
	if v == nil || v.id != s00.ProtocolIEID(8) || v.rowENBUES1APID == nil {
		return nil, false
	}
	return v.rowENBUES1APID, true
}

// AsCdma2000RATType returns the selected Cdma2000RATType value of UplinkS1cdma2000tunnellingIEValue and reports whether that alternative is active.
func (v *UplinkS1cdma2000tunnellingIEValue) AsCdma2000RATType() (*s00.Cdma2000RATType, bool) {
	if v == nil || v.id != s00.ProtocolIEID(71) || v.rowCdma2000RATType == nil {
		return nil, false
	}
	return v.rowCdma2000RATType, true
}

// AsCdma2000SectorID returns the selected Cdma2000SectorID value of UplinkS1cdma2000tunnellingIEValue and reports whether that alternative is active.
func (v *UplinkS1cdma2000tunnellingIEValue) AsCdma2000SectorID() (*s00.Cdma2000SectorID, bool) {
	if v == nil || v.id != s00.ProtocolIEID(72) || v.rowCdma2000SectorID == nil {
		return nil, false
	}
	return v.rowCdma2000SectorID, true
}

// AsCdma2000HORequiredIndication returns the selected Cdma2000HORequiredIndication value of UplinkS1cdma2000tunnellingIEValue and reports whether that alternative is active.
func (v *UplinkS1cdma2000tunnellingIEValue) AsCdma2000HORequiredIndication() (*s00.Cdma2000HORequiredIndication, bool) {
	if v == nil || v.id != s00.ProtocolIEID(84) || v.rowCdma2000HORequiredIndication == nil {
		return nil, false
	}
	return v.rowCdma2000HORequiredIndication, true
}

// AsCdma2000OneXSRVCCInfo returns the selected Cdma2000OneXSRVCCInfo value of UplinkS1cdma2000tunnellingIEValue and reports whether that alternative is active.
func (v *UplinkS1cdma2000tunnellingIEValue) AsCdma2000OneXSRVCCInfo() (*s14.Cdma2000OneXSRVCCInfo, bool) {
	if v == nil || v.id != s00.ProtocolIEID(102) || v.rowCdma2000OneXSRVCCInfo == nil {
		return nil, false
	}
	return v.rowCdma2000OneXSRVCCInfo, true
}

// AsCdma2000OneXRAND returns the selected Cdma2000OneXRAND value of UplinkS1cdma2000tunnellingIEValue and reports whether that alternative is active.
func (v *UplinkS1cdma2000tunnellingIEValue) AsCdma2000OneXRAND() (*s00.Cdma2000OneXRAND, bool) {
	if v == nil || v.id != s00.ProtocolIEID(97) || v.rowCdma2000OneXRAND == nil {
		return nil, false
	}
	return v.rowCdma2000OneXRAND, true
}

// AsCdma2000PDU returns the selected Cdma2000PDU value of UplinkS1cdma2000tunnellingIEValue and reports whether that alternative is active.
func (v *UplinkS1cdma2000tunnellingIEValue) AsCdma2000PDU() (*s00.Cdma2000PDU, bool) {
	if v == nil || v.id != s00.ProtocolIEID(70) || v.rowCdma2000PDU == nil {
		return nil, false
	}
	return v.rowCdma2000PDU, true
}

// AsEUTRANRoundTripDelayEstimationInfo returns the selected EUTRANRoundTripDelayEstimationInfo value of UplinkS1cdma2000tunnellingIEValue and reports whether that alternative is active.
func (v *UplinkS1cdma2000tunnellingIEValue) AsEUTRANRoundTripDelayEstimationInfo() (*s00.EUTRANRoundTripDelayEstimationInfo, bool) {
	if v == nil || v.id != s00.ProtocolIEID(140) || v.rowEUTRANRoundTripDelayEstimationInfo == nil {
		return nil, false
	}
	return v.rowEUTRANRoundTripDelayEstimationInfo, true
}
func (v UplinkS1cdma2000tunnellingIEValue) decode(id s00.ProtocolIEID, raw aper.OpaqueOpenType) (UplinkS1cdma2000tunnellingIEValue, error) {
	out := UplinkS1cdma2000tunnellingIEValue{id: id}
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
	case s00.ProtocolIEID(71):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		bb := scope
		decoded, err := aper.DecodeEnumeratedAligned(bb, 2, true, aper.EnumerationSource{KnownExtensions: 0, Path: "Cdma2000RATType"})
		value := s00.Cdma2000RATType(decoded)
		if err != nil {
			return out, fmt.Errorf("%s %w", "Cdma2000RATType:", err)
		}
		if _, err := aper.CompleteOpenTypeValue(bb, value); err != nil {
			return out, err
		}
		out.rowCdma2000RATType = &value
		raw.RetainContents(&out.received)
	case s00.ProtocolIEID(72):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		child := scope
		value, err := (func(bb *aper.BitBuffer) (s00.Cdma2000SectorID, error) {
			var v struct{ Value s00.Cdma2000SectorID }
			err := func() error {
				val_value, err := aper.DecodeOctetStringAligned(bb, 0, 0, false)
				if err != nil {
					return runtime.WrapDecodePath(err, "Value")
				}
				v.Value = s00.Cdma2000SectorID(val_value)
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
		out.rowCdma2000SectorID = &value
		raw.RetainContents(&out.received)
	case s00.ProtocolIEID(84):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		bb := scope
		decoded, err := aper.DecodeEnumeratedAligned(bb, 1, true, aper.EnumerationSource{KnownExtensions: 0, Path: "Cdma2000HORequiredIndication"})
		value := s00.Cdma2000HORequiredIndication(decoded)
		if err != nil {
			return out, fmt.Errorf("%s %w", "Cdma2000HORequiredIndication:", err)
		}
		if _, err := aper.CompleteOpenTypeValue(bb, value); err != nil {
			return out, err
		}
		out.rowCdma2000HORequiredIndication = &value
		raw.RetainContents(&out.received)
	case s00.ProtocolIEID(102):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		var value s14.Cdma2000OneXSRVCCInfo
		child := scope
		if err := s14.BridgeCdma2000OneXSRVCCInfoMethodUnmarshalAPERFrom(&value, child); err != nil {
			return out, fmt.Errorf("%s %w", "Cdma2000OneXSRVCCInfo:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "Cdma2000OneXSRVCCInfo")
		if err != nil {
			return out, err
		}
		*s14.BridgeCdma2000OneXSRVCCInfoFieldPerPadding(&value) = padding
		*s14.BridgeCdma2000OneXSRVCCInfoFieldReceived(&value) = true
		raw.RetainContents(s14.BridgeCdma2000OneXSRVCCInfoFieldReceivedBytes(&value))
		*s14.BridgeCdma2000OneXSRVCCInfoFieldReceivedLocation(&value) = raw.ContentLocation()
		out.rowCdma2000OneXSRVCCInfo = &value
		raw.RetainContents(&out.received)
	case s00.ProtocolIEID(97):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		child := scope
		value, err := (func(bb *aper.BitBuffer) (s00.Cdma2000OneXRAND, error) {
			var v struct{ Value s00.Cdma2000OneXRAND }
			err := func() error {
				val_value, err := aper.DecodeOctetStringAligned(bb, 0, 0, false)
				if err != nil {
					return runtime.WrapDecodePath(err, "Value")
				}
				v.Value = s00.Cdma2000OneXRAND(val_value)
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
		out.rowCdma2000OneXRAND = &value
		raw.RetainContents(&out.received)
	case s00.ProtocolIEID(70):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		child := scope
		value, err := (func(bb *aper.BitBuffer) (s00.Cdma2000PDU, error) {
			var v struct{ Value s00.Cdma2000PDU }
			err := func() error {
				val_value, err := aper.DecodeOctetStringAligned(bb, 0, 0, false)
				if err != nil {
					return runtime.WrapDecodePath(err, "Value")
				}
				v.Value = s00.Cdma2000PDU(val_value)
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
		out.rowCdma2000PDU = &value
		raw.RetainContents(&out.received)
	case s00.ProtocolIEID(140):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		bb := scope
		decoded, err := aper.DecodeIntegerAligned(bb, s07.BridgeInt64Ptr(0), s07.BridgeInt64Ptr(2047), false)
		value := s00.EUTRANRoundTripDelayEstimationInfo(decoded)
		if err != nil {
			return out, fmt.Errorf("%s %w", "EUTRANRoundTripDelayEstimationInfo:", err)
		}
		if _, err := aper.CompleteOpenTypeValue(bb, value); err != nil {
			return out, err
		}
		out.rowEUTRANRoundTripDelayEstimationInfo = &value
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
func (v UplinkS1cdma2000tunnellingIEValue) encode() ([]byte, error) {
	return v.encodeFresh(false, nil)
}
func (v UplinkS1cdma2000tunnellingIEValue) encodeFresh(fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
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
			return nil, fmt.Errorf("%s missing value", "UplinkS1cdma2000tunnellingIEs.id-MME-UE-S1AP-ID:")
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
			return nil, fmt.Errorf("%s missing value", "UplinkS1cdma2000tunnellingIEs.id-eNB-UE-S1AP-ID:")
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
	case s00.ProtocolIEID(71):
		if v.rowCdma2000RATType == nil {
			return nil, fmt.Errorf("%s missing value", "UplinkS1cdma2000tunnellingIEs.id-cdma2000RATType:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		encodeBB := aper.NewBudgetBuffer(budget)
		if err := aper.EncodeEnumeratedAligned(encodeBB, int64(*v.rowCdma2000RATType), 2, true); err != nil {
			return nil, err
		}
		candidate := encodeBB.CompleteBytes()
		return candidate, nil
	case s00.ProtocolIEID(72):
		if v.rowCdma2000SectorID == nil {
			return nil, fmt.Errorf("%s missing value", "UplinkS1cdma2000tunnellingIEs.id-cdma2000SectorID:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		candidate, err := (func(value s00.Cdma2000SectorID, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			v := struct{ Value s00.Cdma2000SectorID }{Value: value}
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
		})(*v.rowCdma2000SectorID, budget)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	case s00.ProtocolIEID(84):
		if v.rowCdma2000HORequiredIndication == nil {
			return nil, fmt.Errorf("%s missing value", "UplinkS1cdma2000tunnellingIEs.id-cdma2000HORequiredIndication:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		encodeBB := aper.NewBudgetBuffer(budget)
		if err := aper.EncodeEnumeratedAligned(encodeBB, int64(*v.rowCdma2000HORequiredIndication), 1, true); err != nil {
			return nil, err
		}
		candidate := encodeBB.CompleteBytes()
		return candidate, nil
	case s00.ProtocolIEID(102):
		if v.rowCdma2000OneXSRVCCInfo == nil {
			return nil, fmt.Errorf("%s missing value", "UplinkS1cdma2000tunnellingIEs.id-cdma2000OneXSRVCCInfo:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		candidate, err := s14.BridgeCdma2000OneXSRVCCInfoMethodMarshalAPERBudget(v.rowCdma2000OneXSRVCCInfo, budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	case s00.ProtocolIEID(97):
		if v.rowCdma2000OneXRAND == nil {
			return nil, fmt.Errorf("%s missing value", "UplinkS1cdma2000tunnellingIEs.id-cdma2000OneXRAND:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		candidate, err := (func(value s00.Cdma2000OneXRAND, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			v := struct{ Value s00.Cdma2000OneXRAND }{Value: value}
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
		})(*v.rowCdma2000OneXRAND, budget)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	case s00.ProtocolIEID(70):
		if v.rowCdma2000PDU == nil {
			return nil, fmt.Errorf("%s missing value", "UplinkS1cdma2000tunnellingIEs.id-cdma2000PDU:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		candidate, err := (func(value s00.Cdma2000PDU, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			v := struct{ Value s00.Cdma2000PDU }{Value: value}
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
		})(*v.rowCdma2000PDU, budget)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	case s00.ProtocolIEID(140):
		if v.rowEUTRANRoundTripDelayEstimationInfo == nil {
			return nil, fmt.Errorf("%s missing value", "UplinkS1cdma2000tunnellingIEs.id-EUTRANRoundTripDelayEstimationInfo:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		encodeBB := aper.NewBudgetBuffer(budget)
		if err := aper.EncodeIntegerAligned(encodeBB, int64(*v.rowEUTRANRoundTripDelayEstimationInfo), s07.BridgeInt64Ptr(0), s07.BridgeInt64Ptr(2047), false); err != nil {
			return nil, err
		}
		candidate := encodeBB.CompleteBytes()
		return candidate, nil
	default:
		return nil, fmt.Errorf("%s id %d has no value", "UplinkS1cdma2000tunnellingIEValue:", v.id)
	}
}

// TS 36.413 V19.2.0 §9.3.7: the private selector owns its scalar pointers.
func BridgeClonePrivateID(id s20.PrivateIEID, budget *aper.DecodeBudget) (s20.PrivateIEID, error) {
	bb := aper.NewBudgetBuffer(budget)
	if id.Local != nil {
		if err := aper.ChargeValue(bb, *id.Local); err != nil {
			return s20.PrivateIEID{}, err
		}
		v := *id.Local
		id.Local = &v
	}
	if id.Global != nil {
		if err := aper.ChargeValue(bb, *id.Global); err != nil {
			return s20.PrivateIEID{}, err
		}
		v := *id.Global
		id.Global = &v
	}
	return id, nil
}

type BearersSubjectToStatusTransferItemIETable struct{}

func BearersSubjectToStatusTransferItemIEs() BearersSubjectToStatusTransferItemIETable {
	return BearersSubjectToStatusTransferItemIETable{}
}

// ID returns the ASN.1 object-set identity of BearersSubjectToStatusTransferItemIETable.
func (BearersSubjectToStatusTransferItemIETable) ID() s00.TableID {
	return func() s00.TableID {
		sealed := s00.TableID{}
		*s00.BridgeTableIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "Bearers-SubjectToStatusTransfer-ItemIEs"}
		return sealed
	}()
}

// Table returns the ASN.1 object-set table described by BearersSubjectToStatusTransferItemIETable.
func (BearersSubjectToStatusTransferItemIETable) Table() s00.BearersSubjectToStatusTransferItemIEValueIETable {
	return func() s00.BearersSubjectToStatusTransferItemIEValueIETable {
		sealed := s00.BearersSubjectToStatusTransferItemIEValueIETable{}
		*s00.BridgeBearersSubjectToStatusTransferItemIEValueIETableFieldBound(&sealed) = true
		return sealed
	}()
}
func (BearersSubjectToStatusTransferItemIETable) infoBearersSubjectToStatusTransferItem() s00.FieldInfo {
	return s00.FieldInfo{Table: BearersSubjectToStatusTransferItemIEs().ID(), ID: s00.ProtocolIEID(89), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceMandatory, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "Bearers-SubjectToStatusTransfer-Item"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.4", Assignment: aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "Bearers-SubjectToStatusTransfer-ItemIEs", Row: "id-Bearers-SubjectToStatusTransfer-Item"}}}
}

// BearersSubjectToStatusTransferItem returns the typed binding for the BearersSubjectToStatusTransferItem row of BearersSubjectToStatusTransferItemIETable.
func (t BearersSubjectToStatusTransferItemIETable) BearersSubjectToStatusTransferItem() BearersSubjectToStatusTransferItemBearersSubjectToStatusTransferItemIEBinding {
	return BearersSubjectToStatusTransferItemBearersSubjectToStatusTransferItemIEBinding{info: t.infoBearersSubjectToStatusTransferItem(), codec: BearersSubjectToStatusTransferItemValueCodec{path: "BearersSubjectToStatusTransferItem",
		decode: func(data []byte, options aper.DecodeState) (BearersSubjectToStatusTransferItem, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty BearersSubjectToStatusTransferItem
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("BearersSubjectToStatusTransferItem")
			var zero BearersSubjectToStatusTransferItemIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(89), raw)
			if err != nil {
				var empty BearersSubjectToStatusTransferItem
				return empty, err
			}
			value, ok := decoded.AsBearersSubjectToStatusTransferItem()
			if !ok {
				var empty BearersSubjectToStatusTransferItem
				return empty, fmt.Errorf("binding Bearers-SubjectToStatusTransfer-ItemIEs.id-Bearers-SubjectToStatusTransfer-Item: no selected value")
			}
			return *value, nil
		},
		encode: func(value BearersSubjectToStatusTransferItem, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (BearersSubjectToStatusTransferItemIEValue{id: s00.ProtocolIEID(89), rowBearersSubjectToStatusTransferItem: &value}).encodeFresh(fresh, budget)
		}, capture: func(v BearersSubjectToStatusTransferItem, options aper.DecodeState) (BearersSubjectToStatusTransferItem, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeCaptureS1APBearersSubjectToStatusTransferItem(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}, compare: func(v BearersSubjectToStatusTransferItem, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeCompareS1APBearersSubjectToStatusTransferItem(
				&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}, context: func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:BearersSubjectToStatusTransferItem"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}(),
	}, inject: func(value BearersSubjectToStatusTransferItem) BearersSubjectToStatusTransferItemIEValue {
		return BearersSubjectToStatusTransferItemIEValue{id: s00.ProtocolIEID(89), rowBearersSubjectToStatusTransferItem: &value}
	}, get: func(value *BearersSubjectToStatusTransferItemIEValue) (*BearersSubjectToStatusTransferItem, bool) {
		return value.AsBearersSubjectToStatusTransferItem()
	}}
}

// NewOpaque constructs an owned opaque field for an identifier without a typed row in BearersSubjectToStatusTransferItemIETable.
func (t BearersSubjectToStatusTransferItemIETable) NewOpaque(id s00.ProtocolIEID, criticality s00.Criticality, data []byte) (BearersSubjectToStatusTransferItemIEField, error) {
	if id < 0 || id > 65535 || criticality < 0 || criticality > 2 {
		return BearersSubjectToStatusTransferItemIEField{}, aper.OperationError(fmt.Errorf("invalid opaque IE selector or criticality"), "Opaque")
	}
	switch id {
	case s00.ProtocolIEID(89):
		return BearersSubjectToStatusTransferItemIEField{}, aper.OperationError(fmt.Errorf("known IE id-Bearers-SubjectToStatusTransfer-Item requires its typed binding"), "Opaque")
	default:
		budget, err := aper.BuildBudget()
		if err != nil {
			return BearersSubjectToStatusTransferItemIEField{}, aper.OperationError(err, "Opaque")
		}
		opaque, err := aper.BuildOpaqueOpenType(data, budget)
		if err != nil {
			return BearersSubjectToStatusTransferItemIEField{}, aper.OperationError(err, "Opaque")
		}
		return BearersSubjectToStatusTransferItemIEField{Id: id, Criticality: criticality, Value: BearersSubjectToStatusTransferItemIEValue{id: id, opaque: opaque, isOpaque: true}}, aper.OperationError(nil, "Opaque")
	}
}

type UserLocationInformationExtIETable struct{}

func UserLocationInformationExtIEs() UserLocationInformationExtIETable {
	return UserLocationInformationExtIETable{}
}

// ID returns the ASN.1 object-set identity of UserLocationInformationExtIETable.
func (UserLocationInformationExtIETable) ID() s00.TableID {
	return func() s00.TableID {
		sealed := s00.TableID{}
		*s00.BridgeTableIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "UserLocationInformation-ExtIEs"}
		return sealed
	}()
}

// Table returns the ASN.1 object-set table described by UserLocationInformationExtIETable.
func (UserLocationInformationExtIETable) Table() s00.UserLocationInformationExtIEsValueExtensionTable {
	return func() s00.UserLocationInformationExtIEsValueExtensionTable {
		sealed := s00.UserLocationInformationExtIEsValueExtensionTable{}
		*s00.BridgeUserLocationInformationExtIEsValueExtensionTableFieldBound(&sealed) = true
		return sealed
	}()
}
func (UserLocationInformationExtIETable) infoPSCellInformation() s00.ExtensionInfo {
	return s00.ExtensionInfo{Table: UserLocationInformationExtIEs().ID(), ID: s00.ProtocolExtensionID(288), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "PSCellInformation"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.4", Assignment: aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "UserLocationInformation-ExtIEs", Row: "id-PSCellInformation"}}}
}

// PSCellInformation returns the typed binding for the PSCellInformation row of UserLocationInformationExtIETable.
func (t UserLocationInformationExtIETable) PSCellInformation() UserLocationInformationExtIEsPSCellInformationExtBinding {
	return UserLocationInformationExtIEsPSCellInformationExtBinding{info: t.infoPSCellInformation(), codec: func() s20.PSCellInformationValueCodec {
		sealed := s20.PSCellInformationValueCodec{}
		*s20.BridgePSCellInformationValueCodecFieldPath(&sealed) = "PSCellInformation"
		*s20.BridgePSCellInformationValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s20.PSCellInformation, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s20.PSCellInformation
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("PSCellInformation")
			var zero UserLocationInformationExtIEsValue
			decoded, err := zero.decode(s00.ProtocolIEID(288), raw)
			if err != nil {
				var empty s20.PSCellInformation
				return empty, err
			}
			value, ok := decoded.AsPSCellInformation()
			if !ok {
				var empty s20.PSCellInformation
				return empty, fmt.Errorf("binding UserLocationInformation-ExtIEs.id-PSCellInformation: no selected value")
			}
			return *value, nil
		}
		*s20.BridgePSCellInformationValueCodecFieldEncode(&sealed) = func(value s20.PSCellInformation, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (UserLocationInformationExtIEsValue{id: s00.ProtocolIEID(288), rowPSCellInformation: &value}).encodeFresh(fresh, budget)
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
		inject: func(value s20.PSCellInformation) UserLocationInformationExtIEsValue {
			return UserLocationInformationExtIEsValue{id: s00.ProtocolIEID(288), rowPSCellInformation: &value}
		}, get: func(value *UserLocationInformationExtIEsValue) (*s20.PSCellInformation, bool) {
			return value.AsPSCellInformation()
		}}
}
func (UserLocationInformationExtIETable) infoLTENTNTAIInformation() s00.ExtensionInfo {
	return s00.ExtensionInfo{Table: UserLocationInformationExtIEs().ID(), ID: s00.ProtocolExtensionID(339), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "LTE-NTN-TAI-Information"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.4", Assignment: aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "UserLocationInformation-ExtIEs", Row: "id-LTE-NTN-TAI-Information"}}}
}

// LTENTNTAIInformation returns the typed binding for the LTENTNTAIInformation row of UserLocationInformationExtIETable.
func (t UserLocationInformationExtIETable) LTENTNTAIInformation() UserLocationInformationExtIEsLTENTNTAIInformationExtBinding {
	return UserLocationInformationExtIEsLTENTNTAIInformationExtBinding{info: t.infoLTENTNTAIInformation(), codec: func() s18.LTENTNTAIInformationValueCodec {
		sealed := s18.LTENTNTAIInformationValueCodec{}
		*s18.BridgeLTENTNTAIInformationValueCodecFieldPath(&sealed) = "LTENTNTAIInformation"
		*s18.BridgeLTENTNTAIInformationValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s18.LTENTNTAIInformation, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s18.LTENTNTAIInformation
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("LTENTNTAIInformation")
			var zero UserLocationInformationExtIEsValue
			decoded, err := zero.decode(s00.ProtocolIEID(339), raw)
			if err != nil {
				var empty s18.LTENTNTAIInformation
				return empty, err
			}
			value, ok := decoded.AsLTENTNTAIInformation()
			if !ok {
				var empty s18.LTENTNTAIInformation
				return empty, fmt.Errorf("binding UserLocationInformation-ExtIEs.id-LTE-NTN-TAI-Information: no selected value")
			}
			return *value, nil
		}
		*s18.BridgeLTENTNTAIInformationValueCodecFieldEncode(&sealed) = func(value s18.LTENTNTAIInformation, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (UserLocationInformationExtIEsValue{id: s00.ProtocolIEID(339), rowLTENTNTAIInformation: &value}).encodeFresh(fresh, budget)
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
		inject: func(value s18.LTENTNTAIInformation) UserLocationInformationExtIEsValue {
			return UserLocationInformationExtIEsValue{id: s00.ProtocolIEID(339), rowLTENTNTAIInformation: &value}
		}, get: func(value *UserLocationInformationExtIEsValue) (*s18.LTENTNTAIInformation, bool) {
			return value.AsLTENTNTAIInformation()
		}}
}

// NewOpaque constructs an owned opaque field for an identifier without a typed row in UserLocationInformationExtIETable.
func (t UserLocationInformationExtIETable) NewOpaque(id s00.ProtocolExtensionID, criticality s00.Criticality, data []byte) (UserLocationInformationExtIEsExtField, error) {
	if id < 0 || id > 65535 || criticality < 0 || criticality > 2 {
		return UserLocationInformationExtIEsExtField{}, aper.OperationError(fmt.Errorf("invalid opaque extension selector or criticality"), "Opaque")
	}
	switch id {
	case s00.ProtocolIEID(288):
		return UserLocationInformationExtIEsExtField{}, aper.OperationError(fmt.Errorf("known extension id-PSCellInformation requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(339):
		return UserLocationInformationExtIEsExtField{}, aper.OperationError(fmt.Errorf("known extension id-LTE-NTN-TAI-Information requires its typed binding"), "Opaque")
	default:
		budget, err := aper.BuildBudget()
		if err != nil {
			return UserLocationInformationExtIEsExtField{}, aper.OperationError(err, "Opaque")
		}
		opaque, err := aper.BuildOpaqueOpenType(data, budget)
		if err != nil {
			return UserLocationInformationExtIEsExtField{}, aper.OperationError(err, "Opaque")
		}
		return UserLocationInformationExtIEsExtField{Id: id, Criticality: criticality, ExtensionValue: UserLocationInformationExtIEsValue{id: id, opaque: opaque, isOpaque: true}}, aper.OperationError(nil, "Opaque")
	}
}

type ERABToBeModifyItemBearerModReqExtIETable struct{}

func ERABToBeModifyItemBearerModReqExtIEs() ERABToBeModifyItemBearerModReqExtIETable {
	return ERABToBeModifyItemBearerModReqExtIETable{}
}

// ID returns the ASN.1 object-set identity of ERABToBeModifyItemBearerModReqExtIETable.
func (ERABToBeModifyItemBearerModReqExtIETable) ID() s00.TableID {
	return func() s00.TableID {
		sealed := s00.TableID{}
		*s00.BridgeTableIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "E-RABToBeModifyItemBearerModReqExtIEs"}
		return sealed
	}()
}

// Table returns the ASN.1 object-set table described by ERABToBeModifyItemBearerModReqExtIETable.
func (ERABToBeModifyItemBearerModReqExtIETable) Table() s00.ERABToBeModifyItemBearerModReqExtIEsValueExtensionTable {
	return func() s00.ERABToBeModifyItemBearerModReqExtIEsValueExtensionTable {
		sealed := s00.ERABToBeModifyItemBearerModReqExtIEsValueExtensionTable{}
		*s00.BridgeERABToBeModifyItemBearerModReqExtIEsValueExtensionTableFieldBound(&sealed) = true
		return sealed
	}()
}
func (ERABToBeModifyItemBearerModReqExtIETable) infoTransportInformation() s00.ExtensionInfo {
	return s00.ExtensionInfo{Table: ERABToBeModifyItemBearerModReqExtIEs().ID(), ID: s00.ProtocolExtensionID(185), Criticality: s00.CriticalityReject, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "TransportInformation"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "E-RABToBeModifyItemBearerModReqExtIEs", Row: "id-TransportInformation"}}}
}

// TransportInformation returns the typed binding for the TransportInformation row of ERABToBeModifyItemBearerModReqExtIETable.
func (t ERABToBeModifyItemBearerModReqExtIETable) TransportInformation() ERABToBeModifyItemBearerModReqExtIEsTransportInformationExtBinding {
	return ERABToBeModifyItemBearerModReqExtIEsTransportInformationExtBinding{info: t.infoTransportInformation(), codec: TransportInformationValueCodec{path: "TransportInformation",
		decode: func(data []byte, options aper.DecodeState) (TransportInformation, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty TransportInformation
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("TransportInformation")
			var zero ERABToBeModifyItemBearerModReqExtIEsValue
			decoded, err := zero.decode(s00.ProtocolIEID(185), raw)
			if err != nil {
				var empty TransportInformation
				return empty, err
			}
			value, ok := decoded.AsTransportInformation()
			if !ok {
				var empty TransportInformation
				return empty, fmt.Errorf("binding E-RABToBeModifyItemBearerModReqExtIEs.id-TransportInformation: no selected value")
			}
			return *value, nil
		},
		encode: func(value TransportInformation, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (ERABToBeModifyItemBearerModReqExtIEsValue{id: s00.ProtocolIEID(185), rowTransportInformation: &value}).encodeFresh(fresh, budget)
		}, capture: func(v TransportInformation, options aper.DecodeState) (TransportInformation, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeCaptureS1APTransportInformation(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}, compare: func(v TransportInformation, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeCompareS1APTransportInformation(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}, context: func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:TransportInformation"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}(),
	}, inject: func(value TransportInformation) ERABToBeModifyItemBearerModReqExtIEsValue {
		return ERABToBeModifyItemBearerModReqExtIEsValue{id: s00.ProtocolIEID(185), rowTransportInformation: &value}
	}, get: func(value *ERABToBeModifyItemBearerModReqExtIEsValue) (*TransportInformation, bool) {
		return value.AsTransportInformation()
	}}
}

// NewOpaque constructs an owned opaque field for an identifier without a typed row in ERABToBeModifyItemBearerModReqExtIETable.
func (t ERABToBeModifyItemBearerModReqExtIETable) NewOpaque(id s00.ProtocolExtensionID, criticality s00.Criticality, data []byte) (ERABToBeModifyItemBearerModReqExtIEsExtField, error) {
	if id < 0 || id > 65535 || criticality < 0 || criticality > 2 {
		return ERABToBeModifyItemBearerModReqExtIEsExtField{}, aper.OperationError(fmt.Errorf("invalid opaque extension selector or criticality"), "Opaque")
	}
	switch id {
	case s00.ProtocolIEID(185):
		return ERABToBeModifyItemBearerModReqExtIEsExtField{}, aper.OperationError(fmt.Errorf("known extension id-TransportInformation requires its typed binding"), "Opaque")
	default:
		budget, err := aper.BuildBudget()
		if err != nil {
			return ERABToBeModifyItemBearerModReqExtIEsExtField{}, aper.OperationError(err, "Opaque")
		}
		opaque, err := aper.BuildOpaqueOpenType(data, budget)
		if err != nil {
			return ERABToBeModifyItemBearerModReqExtIEsExtField{}, aper.OperationError(err, "Opaque")
		}
		return ERABToBeModifyItemBearerModReqExtIEsExtField{Id: id, Criticality: criticality, ExtensionValue: ERABToBeModifyItemBearerModReqExtIEsValue{id: id, opaque: opaque, isOpaque: true}}, aper.OperationError(nil, "Opaque")
	}
}

type ENBStatusTransferIETable struct{}

func ENBStatusTransferIEs() ENBStatusTransferIETable { return ENBStatusTransferIETable{} }

// ID returns the ASN.1 object-set identity of ENBStatusTransferIETable.
func (ENBStatusTransferIETable) ID() s00.TableID {
	return func() s00.TableID {
		sealed := s00.TableID{}
		*s00.BridgeTableIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "ENBStatusTransferIEs"}
		return sealed
	}()
}

// Table returns the ASN.1 object-set table described by ENBStatusTransferIETable.
func (ENBStatusTransferIETable) Table() s00.ENBStatusTransferIEValueIETable {
	return func() s00.ENBStatusTransferIEValueIETable {
		sealed := s00.ENBStatusTransferIEValueIETable{}
		*s00.BridgeENBStatusTransferIEValueIETableFieldBound(&sealed) = true
		return sealed
	}()
}
func (ENBStatusTransferIETable) infoMMEUES1APID() s00.FieldInfo {
	return s00.FieldInfo{Table: ENBStatusTransferIEs().ID(), ID: s00.ProtocolIEID(0), Criticality: s00.CriticalityReject, Presence: s00.PresenceMandatory, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "MME-UE-S1AP-ID"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "ENBStatusTransferIEs", Row: "id-MME-UE-S1AP-ID"}}}
}

// MMEUES1APID returns the typed binding for the MMEUES1APID row of ENBStatusTransferIETable.
func (t ENBStatusTransferIETable) MMEUES1APID() ENBStatusTransferMMEUES1APIDIEBinding {
	return ENBStatusTransferMMEUES1APIDIEBinding{info: t.infoMMEUES1APID(), codec: func() s01.MMEUES1APIDValueCodec {
		sealed := s01.MMEUES1APIDValueCodec{}
		*s01.BridgeMMEUES1APIDValueCodecFieldPath(&sealed) = "MMEUES1APID"
		*s01.BridgeMMEUES1APIDValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.MMEUES1APID, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s00.MMEUES1APID
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("MMEUES1APID")
			var zero ENBStatusTransferIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(0), raw)
			if err != nil {
				var empty s00.MMEUES1APID
				return empty, err
			}
			value, ok := decoded.AsMMEUES1APID()
			if !ok {
				var empty s00.MMEUES1APID
				return empty, fmt.Errorf("binding ENBStatusTransferIEs.id-MME-UE-S1AP-ID: no selected value")
			}
			return *value, nil
		}
		*s01.BridgeMMEUES1APIDValueCodecFieldEncode(&sealed) = func(value s00.MMEUES1APID, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (ENBStatusTransferIEValue{id: s00.ProtocolIEID(0), rowMMEUES1APID: &value}).encodeFresh(fresh, budget)
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
		inject: func(value s00.MMEUES1APID) ENBStatusTransferIEValue {
			return ENBStatusTransferIEValue{id: s00.ProtocolIEID(0), rowMMEUES1APID: &value}
		}, get: func(value *ENBStatusTransferIEValue) (*s00.MMEUES1APID, bool) { return value.AsMMEUES1APID() }}
}
func (ENBStatusTransferIETable) infoENBUES1APID() s00.FieldInfo {
	return s00.FieldInfo{Table: ENBStatusTransferIEs().ID(), ID: s00.ProtocolIEID(8), Criticality: s00.CriticalityReject, Presence: s00.PresenceMandatory, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "ENB-UE-S1AP-ID"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "ENBStatusTransferIEs", Row: "id-eNB-UE-S1AP-ID"}}}
}

// ENBUES1APID returns the typed binding for the ENBUES1APID row of ENBStatusTransferIETable.
func (t ENBStatusTransferIETable) ENBUES1APID() ENBStatusTransferENBUES1APIDIEBinding {
	return ENBStatusTransferENBUES1APIDIEBinding{info: t.infoENBUES1APID(), codec: func() s00.ENBUES1APIDValueCodec {
		sealed := s00.ENBUES1APIDValueCodec{}
		*s00.BridgeENBUES1APIDValueCodecFieldPath(&sealed) = "ENBUES1APID"
		*s00.BridgeENBUES1APIDValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.ENBUES1APID, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s00.ENBUES1APID
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("ENBUES1APID")
			var zero ENBStatusTransferIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(8), raw)
			if err != nil {
				var empty s00.ENBUES1APID
				return empty, err
			}
			value, ok := decoded.AsENBUES1APID()
			if !ok {
				var empty s00.ENBUES1APID
				return empty, fmt.Errorf("binding ENBStatusTransferIEs.id-eNB-UE-S1AP-ID: no selected value")
			}
			return *value, nil
		}
		*s00.BridgeENBUES1APIDValueCodecFieldEncode(&sealed) = func(value s00.ENBUES1APID, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (ENBStatusTransferIEValue{id: s00.ProtocolIEID(8), rowENBUES1APID: &value}).encodeFresh(fresh, budget)
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
		inject: func(value s00.ENBUES1APID) ENBStatusTransferIEValue {
			return ENBStatusTransferIEValue{id: s00.ProtocolIEID(8), rowENBUES1APID: &value}
		}, get: func(value *ENBStatusTransferIEValue) (*s00.ENBUES1APID, bool) { return value.AsENBUES1APID() }}
}
func (ENBStatusTransferIETable) infoENBStatusTransferTransparentContainer() s00.FieldInfo {
	return s00.FieldInfo{Table: ENBStatusTransferIEs().ID(), ID: s00.ProtocolIEID(90), Criticality: s00.CriticalityReject, Presence: s00.PresenceMandatory, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "ENB-StatusTransfer-TransparentContainer"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "ENBStatusTransferIEs", Row: "id-eNB-StatusTransfer-TransparentContainer"}}}
}

// ENBStatusTransferTransparentContainer returns the typed binding for the ENBStatusTransferTransparentContainer row of ENBStatusTransferIETable.
func (t ENBStatusTransferIETable) ENBStatusTransferTransparentContainer() ENBStatusTransferENBStatusTransferTransparentContainerIEBinding {
	return ENBStatusTransferENBStatusTransferTransparentContainerIEBinding{info: t.infoENBStatusTransferTransparentContainer(), codec: ENBStatusTransferTransparentContainerValueCodec{path: "ENBStatusTransferTransparentContainer",
		decode: func(data []byte, options aper.DecodeState) (ENBStatusTransferTransparentContainer, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty ENBStatusTransferTransparentContainer
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("ENBStatusTransferTransparentContainer")
			var zero ENBStatusTransferIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(90), raw)
			if err != nil {
				var empty ENBStatusTransferTransparentContainer
				return empty, err
			}
			value, ok := decoded.AsENBStatusTransferTransparentContainer()
			if !ok {
				var empty ENBStatusTransferTransparentContainer
				return empty, fmt.Errorf("binding ENBStatusTransferIEs.id-eNB-StatusTransfer-TransparentContainer: no selected value")
			}
			return *value, nil
		},
		encode: func(value ENBStatusTransferTransparentContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (ENBStatusTransferIEValue{id: s00.ProtocolIEID(90), rowENBStatusTransferTransparentContainer: &value}).encodeFresh(fresh, budget)
		}, capture: func(v ENBStatusTransferTransparentContainer, options aper.DecodeState) (ENBStatusTransferTransparentContainer, aper.Snapshot,

		) {
			s := aper.SemanticCaptureFor(options)
			f :=
				s.Begin()
			BridgeCaptureS1APENBStatusTransferTransparentContainer(
				&v,

				&s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}, compare: func(v ENBStatusTransferTransparentContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeCompareS1APENBStatusTransferTransparentContainer(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}, context: func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ENBStatusTransferTransparentContainer"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}(),
	}, inject: func(value ENBStatusTransferTransparentContainer) ENBStatusTransferIEValue {
		return ENBStatusTransferIEValue{id: s00.ProtocolIEID(90), rowENBStatusTransferTransparentContainer: &value}
	}, get: func(value *ENBStatusTransferIEValue) (*ENBStatusTransferTransparentContainer, bool) {
		return value.AsENBStatusTransferTransparentContainer()
	}}
}

// NewOpaque constructs an owned opaque field for an identifier without a typed row in ENBStatusTransferIETable.
func (t ENBStatusTransferIETable) NewOpaque(id s00.ProtocolIEID, criticality s00.Criticality, data []byte) (ENBStatusTransferIEField, error) {
	if id < 0 || id > 65535 || criticality < 0 || criticality > 2 {
		return ENBStatusTransferIEField{}, aper.OperationError(fmt.Errorf("invalid opaque IE selector or criticality"), "Opaque")
	}
	switch id {
	case s00.ProtocolIEID(0):
		return ENBStatusTransferIEField{}, aper.OperationError(fmt.Errorf("known IE id-MME-UE-S1AP-ID requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(8):
		return ENBStatusTransferIEField{}, aper.OperationError(fmt.Errorf("known IE id-eNB-UE-S1AP-ID requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(90):
		return ENBStatusTransferIEField{}, aper.OperationError(fmt.Errorf("known IE id-eNB-StatusTransfer-TransparentContainer requires its typed binding"), "Opaque")
	default:
		budget, err := aper.BuildBudget()
		if err != nil {
			return ENBStatusTransferIEField{}, aper.OperationError(err, "Opaque")
		}
		opaque, err := aper.BuildOpaqueOpenType(data, budget)
		if err != nil {
			return ENBStatusTransferIEField{}, aper.OperationError(err, "Opaque")
		}
		return ENBStatusTransferIEField{Id: id, Criticality: criticality, Value: ENBStatusTransferIEValue{id: id, opaque: opaque, isOpaque: true}}, aper.OperationError(nil, "Opaque")
	}
}

type TraceFailureIndicationIETable struct{}

func TraceFailureIndicationIEs() TraceFailureIndicationIETable {
	return TraceFailureIndicationIETable{}
}

// ID returns the ASN.1 object-set identity of TraceFailureIndicationIETable.
func (TraceFailureIndicationIETable) ID() s00.TableID {
	return func() s00.TableID {
		sealed := s00.TableID{}
		*s00.BridgeTableIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "TraceFailureIndicationIEs"}
		return sealed
	}()
}

// Table returns the ASN.1 object-set table described by TraceFailureIndicationIETable.
func (TraceFailureIndicationIETable) Table() s00.TraceFailureIndicationIEValueIETable {
	return func() s00.TraceFailureIndicationIEValueIETable {
		sealed := s00.TraceFailureIndicationIEValueIETable{}
		*s00.BridgeTraceFailureIndicationIEValueIETableFieldBound(&sealed) = true
		return sealed
	}()
}
func (TraceFailureIndicationIETable) infoMMEUES1APID() s00.FieldInfo {
	return s00.FieldInfo{Table: TraceFailureIndicationIEs().ID(), ID: s00.ProtocolIEID(0), Criticality: s00.CriticalityReject, Presence: s00.PresenceMandatory, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "MME-UE-S1AP-ID"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "TraceFailureIndicationIEs", Row: "id-MME-UE-S1AP-ID"}}}
}

// MMEUES1APID returns the typed binding for the MMEUES1APID row of TraceFailureIndicationIETable.
func (t TraceFailureIndicationIETable) MMEUES1APID() TraceFailureIndicationMMEUES1APIDIEBinding {
	return TraceFailureIndicationMMEUES1APIDIEBinding{info: t.infoMMEUES1APID(), codec: func() s01.MMEUES1APIDValueCodec {
		sealed := s01.MMEUES1APIDValueCodec{}
		*s01.BridgeMMEUES1APIDValueCodecFieldPath(&sealed) = "MMEUES1APID"
		*s01.BridgeMMEUES1APIDValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.MMEUES1APID, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s00.MMEUES1APID
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("MMEUES1APID")
			var zero s20.TraceFailureIndicationIEValue
			decoded, err := s20.BridgeTraceFailureIndicationIEValueMethodDecode(zero, s00.ProtocolIEID(0), raw)
			if err != nil {
				var empty s00.MMEUES1APID
				return empty, err
			}
			value, ok := decoded.AsMMEUES1APID()
			if !ok {
				var empty s00.MMEUES1APID
				return empty, fmt.Errorf("binding TraceFailureIndicationIEs.id-MME-UE-S1AP-ID: no selected value")
			}
			return *value, nil
		}
		*s01.BridgeMMEUES1APIDValueCodecFieldEncode(&sealed) = func(value s00.MMEUES1APID, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return s20.BridgeTraceFailureIndicationIEValueMethodEncodeFresh((func() s20.TraceFailureIndicationIEValue {
				sealed := s20.TraceFailureIndicationIEValue{}
				*s20.BridgeTraceFailureIndicationIEValueFieldId(&sealed) = s00.ProtocolIEID(0)
				*s20.BridgeTraceFailureIndicationIEValueFieldRowMMEUES1APID(&sealed) = &value
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
		inject: func(value s00.MMEUES1APID) s20.TraceFailureIndicationIEValue {
			return func() s20.TraceFailureIndicationIEValue {
				sealed := s20.TraceFailureIndicationIEValue{}
				*s20.BridgeTraceFailureIndicationIEValueFieldId(&sealed) = s00.ProtocolIEID(0)
				*s20.BridgeTraceFailureIndicationIEValueFieldRowMMEUES1APID(&sealed) = &value
				return sealed
			}()
		}, get: func(value *s20.TraceFailureIndicationIEValue) (*s00.MMEUES1APID, bool) { return value.AsMMEUES1APID() }}
}
func (TraceFailureIndicationIETable) infoENBUES1APID() s00.FieldInfo {
	return s00.FieldInfo{Table: TraceFailureIndicationIEs().ID(), ID: s00.ProtocolIEID(8), Criticality: s00.CriticalityReject, Presence: s00.PresenceMandatory, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "ENB-UE-S1AP-ID"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "TraceFailureIndicationIEs", Row: "id-eNB-UE-S1AP-ID"}}}
}

// ENBUES1APID returns the typed binding for the ENBUES1APID row of TraceFailureIndicationIETable.
func (t TraceFailureIndicationIETable) ENBUES1APID() s20.TraceFailureIndicationENBUES1APIDIEBinding {
	return func() s20.TraceFailureIndicationENBUES1APIDIEBinding {
		sealed := s20.TraceFailureIndicationENBUES1APIDIEBinding{}
		*s20.BridgeTraceFailureIndicationENBUES1APIDIEBindingFieldInfo(&sealed) = t.infoENBUES1APID()
		*s20.BridgeTraceFailureIndicationENBUES1APIDIEBindingFieldCodec(&sealed) = func() s00.ENBUES1APIDValueCodec {
			sealed := s00.ENBUES1APIDValueCodec{}
			*s00.BridgeENBUES1APIDValueCodecFieldPath(&sealed) = "ENBUES1APID"
			*s00.BridgeENBUES1APIDValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.ENBUES1APID, error) {
				raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
				if err != nil {
					var empty s00.ENBUES1APID
					return empty, err
				}
				raw.BudgetBuffer().EnterComponent("ENBUES1APID")
				var zero s20.TraceFailureIndicationIEValue
				decoded, err := s20.BridgeTraceFailureIndicationIEValueMethodDecode(zero, s00.ProtocolIEID(8), raw)
				if err != nil {
					var empty s00.ENBUES1APID
					return empty, err
				}
				value, ok := decoded.AsENBUES1APID()
				if !ok {
					var empty s00.ENBUES1APID
					return empty, fmt.Errorf("binding TraceFailureIndicationIEs.id-eNB-UE-S1AP-ID: no selected value")
				}
				return *value, nil
			}
			*s00.BridgeENBUES1APIDValueCodecFieldEncode(&sealed) = func(value s00.ENBUES1APID, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
				return s20.BridgeTraceFailureIndicationIEValueMethodEncodeFresh((func() s20.TraceFailureIndicationIEValue {
					sealed := s20.TraceFailureIndicationIEValue{}
					*s20.BridgeTraceFailureIndicationIEValueFieldId(&sealed) = s00.ProtocolIEID(8)
					*s20.BridgeTraceFailureIndicationIEValueFieldRowENBUES1APID(&sealed) = &value
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
		*s20.BridgeTraceFailureIndicationENBUES1APIDIEBindingFieldInject(&sealed) = func(value s00.ENBUES1APID) s20.TraceFailureIndicationIEValue {
			return func() s20.TraceFailureIndicationIEValue {
				sealed := s20.TraceFailureIndicationIEValue{}
				*s20.BridgeTraceFailureIndicationIEValueFieldId(&sealed) = s00.ProtocolIEID(8)
				*s20.BridgeTraceFailureIndicationIEValueFieldRowENBUES1APID(&sealed) = &value
				return sealed
			}()
		}
		*s20.BridgeTraceFailureIndicationENBUES1APIDIEBindingFieldGet(&sealed) = func(value *s20.TraceFailureIndicationIEValue) (*s00.ENBUES1APID, bool) { return value.AsENBUES1APID() }
		return sealed
	}()
}
func (TraceFailureIndicationIETable) infoEUTRANTraceID() s00.FieldInfo {
	return s00.FieldInfo{Table: TraceFailureIndicationIEs().ID(), ID: s00.ProtocolIEID(86), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceMandatory, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "E-UTRAN-Trace-ID"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "TraceFailureIndicationIEs", Row: "id-E-UTRAN-Trace-ID"}}}
}

// EUTRANTraceID returns the typed binding for the EUTRANTraceID row of TraceFailureIndicationIETable.
func (t TraceFailureIndicationIETable) EUTRANTraceID() s20.TraceFailureIndicationEUTRANTraceIDIEBinding {
	return func() s20.TraceFailureIndicationEUTRANTraceIDIEBinding {
		sealed := s20.TraceFailureIndicationEUTRANTraceIDIEBinding{}
		*s20.BridgeTraceFailureIndicationEUTRANTraceIDIEBindingFieldInfo(&sealed) = t.infoEUTRANTraceID()
		*s20.BridgeTraceFailureIndicationEUTRANTraceIDIEBindingFieldCodec(&sealed) = func() s00.EUTRANTraceIDValueCodec {
			sealed := s00.EUTRANTraceIDValueCodec{}
			*s00.BridgeEUTRANTraceIDValueCodecFieldPath(&sealed) = "EUTRANTraceID"
			*s00.BridgeEUTRANTraceIDValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.EUTRANTraceID, error) {
				raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
				if err != nil {
					var empty s00.EUTRANTraceID
					return empty, err
				}
				raw.BudgetBuffer().EnterComponent("EUTRANTraceID")
				var zero s20.TraceFailureIndicationIEValue
				decoded, err := s20.BridgeTraceFailureIndicationIEValueMethodDecode(zero, s00.ProtocolIEID(86), raw)
				if err != nil {
					var empty s00.EUTRANTraceID
					return empty, err
				}
				value, ok := decoded.AsEUTRANTraceID()
				if !ok {
					var empty s00.EUTRANTraceID
					return empty, fmt.Errorf("binding TraceFailureIndicationIEs.id-E-UTRAN-Trace-ID: no selected value")
				}
				return *value, nil
			}
			*s00.BridgeEUTRANTraceIDValueCodecFieldEncode(&sealed) = func(value s00.EUTRANTraceID, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
				return s20.BridgeTraceFailureIndicationIEValueMethodEncodeFresh((func() s20.TraceFailureIndicationIEValue {
					sealed := s20.TraceFailureIndicationIEValue{}
					*s20.BridgeTraceFailureIndicationIEValueFieldId(&sealed) = s00.ProtocolIEID(86)
					*s20.BridgeTraceFailureIndicationIEValueFieldRowEUTRANTraceID(&sealed) = &value
					return sealed
				}()), fresh, budget)
			}
			*s00.BridgeEUTRANTraceIDValueCodecFieldCapture(&sealed) = func(v s00.EUTRANTraceID, options aper.DecodeState) (s00.EUTRANTraceID, aper.Snapshot) {
				s := aper.SemanticCaptureFor(options)
				f := s.Begin()
				s00.BridgeCaptureS1APEUTRANTraceID(&v, &s)
				var root aper.Snapshot
				s.End(f, &root, false)
				return v, root
			}
			*s00.BridgeEUTRANTraceIDValueCodecFieldCompare(&sealed) = func(v s00.EUTRANTraceID, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
				s := aper.NewSemanticComparison(root, budget)
				f := s.Begin()
				s02.BridgeCompareS1APEUTRANTraceID(&v, &s)
				s.End(f, root, false)
				return s.Plan(),

					s.BudgetValue()
			}
			*s00.BridgeEUTRANTraceIDValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
				sealed := s00.BridgeCodecContext{}
				*s00.BridgecodecContextFieldSource(&sealed) = "source-value:EUTRANTraceID"
				*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
				return sealed
			}()
			return sealed
		}()
		*s20.BridgeTraceFailureIndicationEUTRANTraceIDIEBindingFieldInject(&sealed) = func(value s00.EUTRANTraceID) s20.TraceFailureIndicationIEValue {
			return func() s20.TraceFailureIndicationIEValue {
				sealed := s20.TraceFailureIndicationIEValue{}
				*s20.BridgeTraceFailureIndicationIEValueFieldId(&sealed) = s00.ProtocolIEID(86)
				*s20.BridgeTraceFailureIndicationIEValueFieldRowEUTRANTraceID(&sealed) = &value
				return sealed
			}()
		}
		*s20.BridgeTraceFailureIndicationEUTRANTraceIDIEBindingFieldGet(&sealed) = func(value *s20.TraceFailureIndicationIEValue) (*s00.EUTRANTraceID, bool) {
			return value.AsEUTRANTraceID()
		}
		return sealed
	}()
}
func (TraceFailureIndicationIETable) infoCause() s00.FieldInfo {
	return s00.FieldInfo{Table: TraceFailureIndicationIEs().ID(), ID: s00.ProtocolIEID(2), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceMandatory, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "Cause"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "TraceFailureIndicationIEs", Row: "id-Cause"}}}
}

// Cause returns the typed binding for the Cause row of TraceFailureIndicationIETable.
func (t TraceFailureIndicationIETable) Cause() s20.TraceFailureIndicationCauseIEBinding {
	return func() s20.TraceFailureIndicationCauseIEBinding {
		sealed := s20.TraceFailureIndicationCauseIEBinding{}
		*s20.BridgeTraceFailureIndicationCauseIEBindingFieldInfo(&sealed) = t.infoCause()
		*s20.BridgeTraceFailureIndicationCauseIEBindingFieldCodec(&sealed) = func() s14.CauseValueCodec {
			sealed := s14.CauseValueCodec{}
			*s14.BridgeCauseValueCodecFieldPath(&sealed) = "Cause"
			*s14.BridgeCauseValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s14.Cause, error) {
				raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
				if err != nil {
					var empty s14.Cause
					return empty, err
				}
				raw.BudgetBuffer().EnterComponent("Cause")
				var zero s20.TraceFailureIndicationIEValue
				decoded, err := s20.BridgeTraceFailureIndicationIEValueMethodDecode(zero, s00.ProtocolIEID(2), raw)
				if err != nil {
					var empty s14.Cause
					return empty, err
				}
				value, ok := decoded.AsCause()
				if !ok {
					var empty s14.Cause
					return empty, fmt.Errorf("binding TraceFailureIndicationIEs.id-Cause: no selected value")
				}
				return *value, nil
			}
			*s14.BridgeCauseValueCodecFieldEncode(&sealed) = func(value s14.Cause, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
				return s20.BridgeTraceFailureIndicationIEValueMethodEncodeFresh((func() s20.TraceFailureIndicationIEValue {
					sealed := s20.TraceFailureIndicationIEValue{}
					*s20.BridgeTraceFailureIndicationIEValueFieldId(&sealed) = s00.ProtocolIEID(2)
					*s20.BridgeTraceFailureIndicationIEValueFieldRowCause(&sealed) = &value
					return sealed
				}()), fresh, budget)
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
		}()
		*s20.BridgeTraceFailureIndicationCauseIEBindingFieldInject(&sealed) = func(value s14.Cause) s20.TraceFailureIndicationIEValue {
			return func() s20.TraceFailureIndicationIEValue {
				sealed := s20.TraceFailureIndicationIEValue{}
				*s20.BridgeTraceFailureIndicationIEValueFieldId(&sealed) = s00.ProtocolIEID(2)
				*s20.BridgeTraceFailureIndicationIEValueFieldRowCause(&sealed) = &value
				return sealed
			}()
		}
		*s20.BridgeTraceFailureIndicationCauseIEBindingFieldGet(&sealed) = func(value *s20.TraceFailureIndicationIEValue) (*s14.Cause, bool) { return value.AsCause() }
		return sealed
	}()
}

// NewOpaque constructs an owned opaque field for an identifier without a typed row in TraceFailureIndicationIETable.
func (t TraceFailureIndicationIETable) NewOpaque(id s00.ProtocolIEID, criticality s00.Criticality, data []byte) (s20.TraceFailureIndicationIEField, error) {
	if id < 0 || id > 65535 || criticality < 0 || criticality > 2 {
		return s20.TraceFailureIndicationIEField{}, aper.OperationError(fmt.Errorf("invalid opaque IE selector or criticality"), "Opaque")
	}
	switch id {
	case s00.ProtocolIEID(0):
		return s20.TraceFailureIndicationIEField{}, aper.OperationError(fmt.Errorf("known IE id-MME-UE-S1AP-ID requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(8):
		return s20.TraceFailureIndicationIEField{}, aper.OperationError(fmt.Errorf("known IE id-eNB-UE-S1AP-ID requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(86):
		return s20.TraceFailureIndicationIEField{}, aper.OperationError(fmt.Errorf("known IE id-E-UTRAN-Trace-ID requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(2):
		return s20.TraceFailureIndicationIEField{}, aper.OperationError(fmt.Errorf("known IE id-Cause requires its typed binding"), "Opaque")
	default:
		budget, err := aper.BuildBudget()
		if err != nil {
			return s20.TraceFailureIndicationIEField{}, aper.OperationError(err, "Opaque")
		}
		opaque, err := aper.BuildOpaqueOpenType(data, budget)
		if err != nil {
			return s20.TraceFailureIndicationIEField{}, aper.OperationError(err, "Opaque")
		}
		return s20.TraceFailureIndicationIEField{Id: id, Criticality: criticality, Value: func() s20.TraceFailureIndicationIEValue {
			sealed := s20.TraceFailureIndicationIEValue{}
			*s20.BridgeTraceFailureIndicationIEValueFieldId(&sealed) = id
			*s20.BridgeTraceFailureIndicationIEValueFieldOpaque(&sealed) = opaque
			*s20.BridgeTraceFailureIndicationIEValueFieldIsOpaque(&sealed) = true
			return sealed
		}()}, aper.OperationError(nil, "Opaque")
	}
}

type UEContextModificationIndicationIETable struct{}

func UEContextModificationIndicationIEs() UEContextModificationIndicationIETable {
	return UEContextModificationIndicationIETable{}
}

// ID returns the ASN.1 object-set identity of UEContextModificationIndicationIETable.
func (UEContextModificationIndicationIETable) ID() s00.TableID {
	return func() s00.TableID {
		sealed := s00.TableID{}
		*s00.BridgeTableIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "UEContextModificationIndicationIEs"}
		return sealed
	}()
}

// Table returns the ASN.1 object-set table described by UEContextModificationIndicationIETable.
func (UEContextModificationIndicationIETable) Table() s00.UEContextModificationIndicationIEValueIETable {
	return func() s00.UEContextModificationIndicationIEValueIETable {
		sealed := s00.UEContextModificationIndicationIEValueIETable{}
		*s00.BridgeUEContextModificationIndicationIEValueIETableFieldBound(&sealed) = true
		return sealed
	}()
}
func (UEContextModificationIndicationIETable) infoMMEUES1APID() s00.FieldInfo {
	return s00.FieldInfo{Table: UEContextModificationIndicationIEs().ID(), ID: s00.ProtocolIEID(0), Criticality: s00.CriticalityReject, Presence: s00.PresenceMandatory, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "MME-UE-S1AP-ID"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "UEContextModificationIndicationIEs", Row: "id-MME-UE-S1AP-ID"}}}
}

// MMEUES1APID returns the typed binding for the MMEUES1APID row of UEContextModificationIndicationIETable.
func (t UEContextModificationIndicationIETable) MMEUES1APID() UEContextModificationIndicationMMEUES1APIDIEBinding {
	return UEContextModificationIndicationMMEUES1APIDIEBinding{info: t.infoMMEUES1APID(), codec: func() s01.MMEUES1APIDValueCodec {
		sealed := s01.MMEUES1APIDValueCodec{}
		*s01.BridgeMMEUES1APIDValueCodecFieldPath(&sealed) = "MMEUES1APID"
		*s01.BridgeMMEUES1APIDValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.MMEUES1APID, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s00.MMEUES1APID
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("MMEUES1APID")
			var zero UEContextModificationIndicationIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(0), raw)
			if err != nil {
				var empty s00.MMEUES1APID
				return empty, err
			}
			value, ok := decoded.AsMMEUES1APID()
			if !ok {
				var empty s00.MMEUES1APID
				return empty, fmt.Errorf("binding UEContextModificationIndicationIEs.id-MME-UE-S1AP-ID: no selected value")
			}
			return *value, nil
		}
		*s01.BridgeMMEUES1APIDValueCodecFieldEncode(&sealed) = func(value s00.MMEUES1APID, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (UEContextModificationIndicationIEValue{id: s00.ProtocolIEID(0), rowMMEUES1APID: &value}).encodeFresh(fresh, budget)
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
		inject: func(value s00.MMEUES1APID) UEContextModificationIndicationIEValue {
			return UEContextModificationIndicationIEValue{id: s00.ProtocolIEID(0), rowMMEUES1APID: &value}
		}, get: func(value *UEContextModificationIndicationIEValue) (*s00.MMEUES1APID, bool) {
			return value.AsMMEUES1APID()
		}}
}
func (UEContextModificationIndicationIETable) infoENBUES1APID() s00.FieldInfo {
	return s00.FieldInfo{Table: UEContextModificationIndicationIEs().ID(), ID: s00.ProtocolIEID(8), Criticality: s00.CriticalityReject, Presence: s00.PresenceMandatory, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "ENB-UE-S1AP-ID"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "UEContextModificationIndicationIEs", Row: "id-eNB-UE-S1AP-ID"}}}
}

// ENBUES1APID returns the typed binding for the ENBUES1APID row of UEContextModificationIndicationIETable.
func (t UEContextModificationIndicationIETable) ENBUES1APID() UEContextModificationIndicationENBUES1APIDIEBinding {
	return UEContextModificationIndicationENBUES1APIDIEBinding{info: t.infoENBUES1APID(), codec: func() s00.ENBUES1APIDValueCodec {
		sealed := s00.ENBUES1APIDValueCodec{}
		*s00.BridgeENBUES1APIDValueCodecFieldPath(&sealed) = "ENBUES1APID"
		*s00.BridgeENBUES1APIDValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.ENBUES1APID, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s00.ENBUES1APID
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("ENBUES1APID")
			var zero UEContextModificationIndicationIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(8), raw)
			if err != nil {
				var empty s00.ENBUES1APID
				return empty, err
			}
			value, ok := decoded.AsENBUES1APID()
			if !ok {
				var empty s00.ENBUES1APID
				return empty, fmt.Errorf("binding UEContextModificationIndicationIEs.id-eNB-UE-S1AP-ID: no selected value")
			}
			return *value, nil
		}
		*s00.BridgeENBUES1APIDValueCodecFieldEncode(&sealed) = func(value s00.ENBUES1APID, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (UEContextModificationIndicationIEValue{id: s00.ProtocolIEID(8), rowENBUES1APID: &value}).encodeFresh(fresh, budget)
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
		inject: func(value s00.ENBUES1APID) UEContextModificationIndicationIEValue {
			return UEContextModificationIndicationIEValue{id: s00.ProtocolIEID(8), rowENBUES1APID: &value}
		}, get: func(value *UEContextModificationIndicationIEValue) (*s00.ENBUES1APID, bool) {
			return value.AsENBUES1APID()
		}}
}
func (UEContextModificationIndicationIETable) infoCSGMembershipInfo() s00.FieldInfo {
	return s00.FieldInfo{Table: UEContextModificationIndicationIEs().ID(), ID: s00.ProtocolIEID(226), Criticality: s00.CriticalityReject, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "CSGMembershipInfo"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "UEContextModificationIndicationIEs", Row: "id-CSGMembershipInfo"}}}
}

// CSGMembershipInfo returns the typed binding for the CSGMembershipInfo row of UEContextModificationIndicationIETable.
func (t UEContextModificationIndicationIETable) CSGMembershipInfo() UEContextModificationIndicationCSGMembershipInfoIEBinding {
	return UEContextModificationIndicationCSGMembershipInfoIEBinding{info: t.infoCSGMembershipInfo(), codec: func() s14.CSGMembershipInfoValueCodec {
		sealed := s14.CSGMembershipInfoValueCodec{}
		*s14.BridgeCSGMembershipInfoValueCodecFieldPath(&sealed) = "CSGMembershipInfo"
		*s14.BridgeCSGMembershipInfoValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s14.CSGMembershipInfo, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s14.CSGMembershipInfo
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("CSGMembershipInfo")
			var zero UEContextModificationIndicationIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(226), raw)
			if err != nil {
				var empty s14.CSGMembershipInfo
				return empty, err
			}
			value, ok := decoded.AsCSGMembershipInfo()
			if !ok {
				var empty s14.CSGMembershipInfo
				return empty, fmt.Errorf("binding UEContextModificationIndicationIEs.id-CSGMembershipInfo: no selected value")
			}
			return *value, nil
		}
		*s14.BridgeCSGMembershipInfoValueCodecFieldEncode(&sealed) = func(value s14.CSGMembershipInfo, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (UEContextModificationIndicationIEValue{id: s00.ProtocolIEID(226), rowCSGMembershipInfo: &value}).encodeFresh(fresh, budget)
		}
		*s14.BridgeCSGMembershipInfoValueCodecFieldCapture(&sealed) = func(v s14.CSGMembershipInfo, options aper.DecodeState) (s14.CSGMembershipInfo, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s14.BridgeCaptureS1APCSGMembershipInfo(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v,
				root

		}
		*s14.BridgeCSGMembershipInfoValueCodecFieldCompare(&sealed) = func(v s14.CSGMembershipInfo, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s14.BridgeCompareS1APCSGMembershipInfo(&v, &s)
			s.End(f, root, false)
			return s.
				Plan(), s.BudgetValue()
		}
		*s14.BridgeCSGMembershipInfoValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:CSGMembershipInfo"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s14.CSGMembershipInfo) UEContextModificationIndicationIEValue {
			return UEContextModificationIndicationIEValue{id: s00.ProtocolIEID(226), rowCSGMembershipInfo: &value}
		}, get: func(value *UEContextModificationIndicationIEValue) (*s14.CSGMembershipInfo, bool) {
			return value.AsCSGMembershipInfo()
		}}
}

// NewOpaque constructs an owned opaque field for an identifier without a typed row in UEContextModificationIndicationIETable.
func (t UEContextModificationIndicationIETable) NewOpaque(id s00.ProtocolIEID, criticality s00.Criticality, data []byte) (UEContextModificationIndicationIEField, error) {
	if id < 0 || id > 65535 || criticality < 0 || criticality > 2 {
		return UEContextModificationIndicationIEField{}, aper.OperationError(fmt.Errorf("invalid opaque IE selector or criticality"), "Opaque")
	}
	switch id {
	case s00.ProtocolIEID(0):
		return UEContextModificationIndicationIEField{}, aper.OperationError(fmt.Errorf("known IE id-MME-UE-S1AP-ID requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(8):
		return UEContextModificationIndicationIEField{}, aper.OperationError(fmt.Errorf("known IE id-eNB-UE-S1AP-ID requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(226):
		return UEContextModificationIndicationIEField{}, aper.OperationError(fmt.Errorf("known IE id-CSGMembershipInfo requires its typed binding"), "Opaque")
	default:
		budget, err := aper.BuildBudget()
		if err != nil {
			return UEContextModificationIndicationIEField{}, aper.OperationError(err, "Opaque")
		}
		opaque, err := aper.BuildOpaqueOpenType(data, budget)
		if err != nil {
			return UEContextModificationIndicationIEField{}, aper.OperationError(err, "Opaque")
		}
		return UEContextModificationIndicationIEField{Id: id, Criticality: criticality, Value: UEContextModificationIndicationIEValue{id: id, opaque: opaque, isOpaque: true}}, aper.OperationError(nil, "Opaque")
	}
}

type UplinkS1cdma2000tunnellingIETable struct{}

func UplinkS1cdma2000tunnellingIEs() UplinkS1cdma2000tunnellingIETable {
	return UplinkS1cdma2000tunnellingIETable{}
}

// ID returns the ASN.1 object-set identity of UplinkS1cdma2000tunnellingIETable.
func (UplinkS1cdma2000tunnellingIETable) ID() s00.TableID {
	return func() s00.TableID {
		sealed := s00.TableID{}
		*s00.BridgeTableIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "UplinkS1cdma2000tunnellingIEs"}
		return sealed
	}()
}

// Table returns the ASN.1 object-set table described by UplinkS1cdma2000tunnellingIETable.
func (UplinkS1cdma2000tunnellingIETable) Table() s00.UplinkS1cdma2000tunnellingIEValueIETable {
	return func() s00.UplinkS1cdma2000tunnellingIEValueIETable {
		sealed := s00.UplinkS1cdma2000tunnellingIEValueIETable{}
		*s00.BridgeUplinkS1cdma2000tunnellingIEValueIETableFieldBound(&sealed) = true
		return sealed
	}()
}
func (UplinkS1cdma2000tunnellingIETable) infoMMEUES1APID() s00.FieldInfo {
	return s00.FieldInfo{Table: UplinkS1cdma2000tunnellingIEs().ID(), ID: s00.ProtocolIEID(0), Criticality: s00.CriticalityReject, Presence: s00.PresenceMandatory, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "MME-UE-S1AP-ID"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "UplinkS1cdma2000tunnellingIEs", Row: "id-MME-UE-S1AP-ID"}}}
}

// MMEUES1APID returns the typed binding for the MMEUES1APID row of UplinkS1cdma2000tunnellingIETable.
func (t UplinkS1cdma2000tunnellingIETable) MMEUES1APID() UplinkS1cdma2000tunnellingMMEUES1APIDIEBinding {
	return UplinkS1cdma2000tunnellingMMEUES1APIDIEBinding{info: t.infoMMEUES1APID(), codec: func() s01.MMEUES1APIDValueCodec {
		sealed := s01.MMEUES1APIDValueCodec{}
		*s01.BridgeMMEUES1APIDValueCodecFieldPath(&sealed) = "MMEUES1APID"
		*s01.BridgeMMEUES1APIDValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.MMEUES1APID, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s00.MMEUES1APID
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("MMEUES1APID")
			var zero UplinkS1cdma2000tunnellingIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(0), raw)
			if err != nil {
				var empty s00.MMEUES1APID
				return empty, err
			}
			value, ok := decoded.AsMMEUES1APID()
			if !ok {
				var empty s00.MMEUES1APID
				return empty, fmt.Errorf("binding UplinkS1cdma2000tunnellingIEs.id-MME-UE-S1AP-ID: no selected value")
			}
			return *value, nil
		}
		*s01.BridgeMMEUES1APIDValueCodecFieldEncode(&sealed) = func(value s00.MMEUES1APID, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (UplinkS1cdma2000tunnellingIEValue{id: s00.ProtocolIEID(0), rowMMEUES1APID: &value}).encodeFresh(fresh, budget)
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
		inject: func(value s00.MMEUES1APID) UplinkS1cdma2000tunnellingIEValue {
			return UplinkS1cdma2000tunnellingIEValue{id: s00.ProtocolIEID(0), rowMMEUES1APID: &value}
		}, get: func(value *UplinkS1cdma2000tunnellingIEValue) (*s00.MMEUES1APID, bool) { return value.AsMMEUES1APID() }}
}
func (UplinkS1cdma2000tunnellingIETable) infoENBUES1APID() s00.FieldInfo {
	return s00.FieldInfo{Table: UplinkS1cdma2000tunnellingIEs().ID(), ID: s00.ProtocolIEID(8), Criticality: s00.CriticalityReject, Presence: s00.PresenceMandatory, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "ENB-UE-S1AP-ID"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "UplinkS1cdma2000tunnellingIEs", Row: "id-eNB-UE-S1AP-ID"}}}
}

// ENBUES1APID returns the typed binding for the ENBUES1APID row of UplinkS1cdma2000tunnellingIETable.
func (t UplinkS1cdma2000tunnellingIETable) ENBUES1APID() UplinkS1cdma2000tunnellingENBUES1APIDIEBinding {
	return UplinkS1cdma2000tunnellingENBUES1APIDIEBinding{info: t.infoENBUES1APID(), codec: func() s00.ENBUES1APIDValueCodec {
		sealed := s00.ENBUES1APIDValueCodec{}
		*s00.BridgeENBUES1APIDValueCodecFieldPath(&sealed) = "ENBUES1APID"
		*s00.BridgeENBUES1APIDValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.ENBUES1APID, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s00.ENBUES1APID
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("ENBUES1APID")
			var zero UplinkS1cdma2000tunnellingIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(8), raw)
			if err != nil {
				var empty s00.ENBUES1APID
				return empty, err
			}
			value, ok := decoded.AsENBUES1APID()
			if !ok {
				var empty s00.ENBUES1APID
				return empty, fmt.Errorf("binding UplinkS1cdma2000tunnellingIEs.id-eNB-UE-S1AP-ID: no selected value")
			}
			return *value, nil
		}
		*s00.BridgeENBUES1APIDValueCodecFieldEncode(&sealed) = func(value s00.ENBUES1APID, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (UplinkS1cdma2000tunnellingIEValue{id: s00.ProtocolIEID(8), rowENBUES1APID: &value}).encodeFresh(fresh, budget)
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
		inject: func(value s00.ENBUES1APID) UplinkS1cdma2000tunnellingIEValue {
			return UplinkS1cdma2000tunnellingIEValue{id: s00.ProtocolIEID(8), rowENBUES1APID: &value}
		}, get: func(value *UplinkS1cdma2000tunnellingIEValue) (*s00.ENBUES1APID, bool) { return value.AsENBUES1APID() }}
}
func (UplinkS1cdma2000tunnellingIETable) infoCdma2000RATType() s00.FieldInfo {
	return s00.FieldInfo{Table: UplinkS1cdma2000tunnellingIEs().ID(), ID: s00.ProtocolIEID(71), Criticality: s00.CriticalityReject, Presence: s00.PresenceMandatory, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "Cdma2000RATType"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "UplinkS1cdma2000tunnellingIEs", Row: "id-cdma2000RATType"}}}
}

// Cdma2000RATType returns the typed binding for the Cdma2000RATType row of UplinkS1cdma2000tunnellingIETable.
func (t UplinkS1cdma2000tunnellingIETable) Cdma2000RATType() UplinkS1cdma2000tunnellingCdma2000RATTypeIEBinding {
	return UplinkS1cdma2000tunnellingCdma2000RATTypeIEBinding{info: t.infoCdma2000RATType(), codec: func() s00.Cdma2000RATTypeValueCodec {
		sealed := s00.Cdma2000RATTypeValueCodec{}
		*s00.BridgeCdma2000RATTypeValueCodecFieldPath(&sealed) = "Cdma2000RATType"
		*s00.BridgeCdma2000RATTypeValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.Cdma2000RATType, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s00.Cdma2000RATType
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("Cdma2000RATType")
			var zero UplinkS1cdma2000tunnellingIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(71), raw)
			if err != nil {
				var empty s00.Cdma2000RATType
				return empty, err
			}
			value, ok := decoded.AsCdma2000RATType()
			if !ok {
				var empty s00.Cdma2000RATType
				return empty, fmt.Errorf("binding UplinkS1cdma2000tunnellingIEs.id-cdma2000RATType: no selected value")
			}
			return *value, nil
		}
		*s00.BridgeCdma2000RATTypeValueCodecFieldEncode(&sealed) = func(value s00.Cdma2000RATType, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (UplinkS1cdma2000tunnellingIEValue{id: s00.ProtocolIEID(71), rowCdma2000RATType: &value}).encodeFresh(fresh, budget)
		}
		*s00.BridgeCdma2000RATTypeValueCodecFieldCapture(&sealed) = func(v s00.Cdma2000RATType, options aper.DecodeState) (s00.Cdma2000RATType, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s00.BridgeCaptureS1APCdma2000RATType(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s00.BridgeCdma2000RATTypeValueCodecFieldCompare(&sealed) = func(v s00.Cdma2000RATType, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s02.BridgeCompareS1APCdma2000RATType(&v, &s)
			s.End(f, root, false)
			return s.
				Plan(), s.BudgetValue()
		}
		*s00.BridgeCdma2000RATTypeValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:Cdma2000RATType"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s00.Cdma2000RATType) UplinkS1cdma2000tunnellingIEValue {
			return UplinkS1cdma2000tunnellingIEValue{id: s00.ProtocolIEID(71), rowCdma2000RATType: &value}
		}, get: func(value *UplinkS1cdma2000tunnellingIEValue) (*s00.Cdma2000RATType, bool) {
			return value.AsCdma2000RATType()
		}}
}
func (UplinkS1cdma2000tunnellingIETable) infoCdma2000SectorID() s00.FieldInfo {
	return s00.FieldInfo{Table: UplinkS1cdma2000tunnellingIEs().ID(), ID: s00.ProtocolIEID(72), Criticality: s00.CriticalityReject, Presence: s00.PresenceMandatory, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "Cdma2000SectorID"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "UplinkS1cdma2000tunnellingIEs", Row: "id-cdma2000SectorID"}}}
}

// Cdma2000SectorID returns the typed binding for the Cdma2000SectorID row of UplinkS1cdma2000tunnellingIETable.
func (t UplinkS1cdma2000tunnellingIETable) Cdma2000SectorID() UplinkS1cdma2000tunnellingCdma2000SectorIDIEBinding {
	return UplinkS1cdma2000tunnellingCdma2000SectorIDIEBinding{info: t.infoCdma2000SectorID(), codec: func() s00.Cdma2000SectorIDValueCodec {
		sealed := s00.Cdma2000SectorIDValueCodec{}
		*s00.BridgeCdma2000SectorIDValueCodecFieldPath(&sealed) = "Cdma2000SectorID"
		*s00.BridgeCdma2000SectorIDValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.Cdma2000SectorID, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s00.Cdma2000SectorID
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("Cdma2000SectorID")
			var zero UplinkS1cdma2000tunnellingIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(72), raw)
			if err != nil {
				var empty s00.Cdma2000SectorID
				return empty, err
			}
			value, ok := decoded.AsCdma2000SectorID()
			if !ok {
				var empty s00.Cdma2000SectorID
				return empty, fmt.Errorf("binding UplinkS1cdma2000tunnellingIEs.id-cdma2000SectorID: no selected value")
			}
			return *value, nil
		}
		*s00.BridgeCdma2000SectorIDValueCodecFieldEncode(&sealed) = func(value s00.Cdma2000SectorID, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (UplinkS1cdma2000tunnellingIEValue{id: s00.ProtocolIEID(72), rowCdma2000SectorID: &value}).encodeFresh(fresh, budget)
		}
		*s00.BridgeCdma2000SectorIDValueCodecFieldCapture(&sealed) = func(v s00.Cdma2000SectorID, options aper.DecodeState) (s00.Cdma2000SectorID, aper.Snapshot) {
			s := aper.SemanticCaptureFor(
				options)
			f := s.Begin()
			s00.BridgeCaptureS1APCdma2000SectorID(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s00.BridgeCdma2000SectorIDValueCodecFieldCompare(&sealed) = func(v s00.Cdma2000SectorID, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s02.BridgeCompareS1APCdma2000SectorID(&v, &s)
			s.End(f, root, false)
			return s.
				Plan(), s.BudgetValue()
		}
		*s00.BridgeCdma2000SectorIDValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:Cdma2000SectorID"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s00.Cdma2000SectorID) UplinkS1cdma2000tunnellingIEValue {
			return UplinkS1cdma2000tunnellingIEValue{id: s00.ProtocolIEID(72), rowCdma2000SectorID: &value}
		}, get: func(value *UplinkS1cdma2000tunnellingIEValue) (*s00.Cdma2000SectorID, bool) {
			return value.AsCdma2000SectorID()
		}}
}
func (UplinkS1cdma2000tunnellingIETable) infoCdma2000HORequiredIndication() s00.FieldInfo {
	return s00.FieldInfo{Table: UplinkS1cdma2000tunnellingIEs().ID(), ID: s00.ProtocolIEID(84), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "Cdma2000HORequiredIndication"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "UplinkS1cdma2000tunnellingIEs", Row: "id-cdma2000HORequiredIndication"}}}
}

// Cdma2000HORequiredIndication returns the typed binding for the Cdma2000HORequiredIndication row of UplinkS1cdma2000tunnellingIETable.
func (t UplinkS1cdma2000tunnellingIETable) Cdma2000HORequiredIndication() UplinkS1cdma2000tunnellingCdma2000HORequiredIndicationIEBinding {
	return UplinkS1cdma2000tunnellingCdma2000HORequiredIndicationIEBinding{info: t.infoCdma2000HORequiredIndication(), codec: func() s00.Cdma2000HORequiredIndicationValueCodec {
		sealed := s00.Cdma2000HORequiredIndicationValueCodec{}
		*s00.BridgeCdma2000HORequiredIndicationValueCodecFieldPath(&sealed) = "Cdma2000HORequiredIndication"
		*s00.BridgeCdma2000HORequiredIndicationValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.Cdma2000HORequiredIndication, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s00.Cdma2000HORequiredIndication
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("Cdma2000HORequiredIndication")
			var zero UplinkS1cdma2000tunnellingIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(84), raw)
			if err != nil {
				var empty s00.Cdma2000HORequiredIndication
				return empty, err
			}
			value, ok := decoded.AsCdma2000HORequiredIndication()
			if !ok {
				var empty s00.Cdma2000HORequiredIndication
				return empty, fmt.Errorf("binding UplinkS1cdma2000tunnellingIEs.id-cdma2000HORequiredIndication: no selected value")
			}
			return *value, nil
		}
		*s00.BridgeCdma2000HORequiredIndicationValueCodecFieldEncode(&sealed) = func(value s00.Cdma2000HORequiredIndication, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (UplinkS1cdma2000tunnellingIEValue{id: s00.ProtocolIEID(84), rowCdma2000HORequiredIndication: &value}).encodeFresh(fresh, budget)
		}
		*s00.BridgeCdma2000HORequiredIndicationValueCodecFieldCapture(&sealed) = func(v s00.Cdma2000HORequiredIndication, options aper.DecodeState) (s00.Cdma2000HORequiredIndication, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s00.BridgeCaptureS1APCdma2000HORequiredIndication(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s00.BridgeCdma2000HORequiredIndicationValueCodecFieldCompare(&sealed) = func(v s00.Cdma2000HORequiredIndication, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.
				Begin()
			s02.BridgeCompareS1APCdma2000HORequiredIndication(&v, &s)
			s.End(
				f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s00.BridgeCdma2000HORequiredIndicationValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:Cdma2000HORequiredIndication"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s00.Cdma2000HORequiredIndication) UplinkS1cdma2000tunnellingIEValue {
			return UplinkS1cdma2000tunnellingIEValue{id: s00.ProtocolIEID(84), rowCdma2000HORequiredIndication: &value}
		}, get: func(value *UplinkS1cdma2000tunnellingIEValue) (*s00.Cdma2000HORequiredIndication, bool) {
			return value.AsCdma2000HORequiredIndication()
		}}
}
func (UplinkS1cdma2000tunnellingIETable) infoCdma2000OneXSRVCCInfo() s00.FieldInfo {
	return s00.FieldInfo{Table: UplinkS1cdma2000tunnellingIEs().ID(), ID: s00.ProtocolIEID(102), Criticality: s00.CriticalityReject, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "Cdma2000OneXSRVCCInfo"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "UplinkS1cdma2000tunnellingIEs", Row: "id-cdma2000OneXSRVCCInfo"}}}
}

// Cdma2000OneXSRVCCInfo returns the typed binding for the Cdma2000OneXSRVCCInfo row of UplinkS1cdma2000tunnellingIETable.
func (t UplinkS1cdma2000tunnellingIETable) Cdma2000OneXSRVCCInfo() UplinkS1cdma2000tunnellingCdma2000OneXSRVCCInfoIEBinding {
	return UplinkS1cdma2000tunnellingCdma2000OneXSRVCCInfoIEBinding{info: t.infoCdma2000OneXSRVCCInfo(), codec: func() s14.Cdma2000OneXSRVCCInfoValueCodec {
		sealed := s14.Cdma2000OneXSRVCCInfoValueCodec{}
		*s14.BridgeCdma2000OneXSRVCCInfoValueCodecFieldPath(&sealed) = "Cdma2000OneXSRVCCInfo"
		*s14.BridgeCdma2000OneXSRVCCInfoValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s14.Cdma2000OneXSRVCCInfo, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s14.Cdma2000OneXSRVCCInfo
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("Cdma2000OneXSRVCCInfo")
			var zero UplinkS1cdma2000tunnellingIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(102), raw)
			if err != nil {
				var empty s14.Cdma2000OneXSRVCCInfo
				return empty, err
			}
			value, ok := decoded.AsCdma2000OneXSRVCCInfo()
			if !ok {
				var empty s14.Cdma2000OneXSRVCCInfo
				return empty, fmt.Errorf("binding UplinkS1cdma2000tunnellingIEs.id-cdma2000OneXSRVCCInfo: no selected value")
			}
			return *value, nil
		}
		*s14.BridgeCdma2000OneXSRVCCInfoValueCodecFieldEncode(&sealed) = func(value s14.Cdma2000OneXSRVCCInfo, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (UplinkS1cdma2000tunnellingIEValue{id: s00.ProtocolIEID(102), rowCdma2000OneXSRVCCInfo: &value}).encodeFresh(fresh, budget)
		}
		*s14.BridgeCdma2000OneXSRVCCInfoValueCodecFieldCapture(&sealed) = func(v s14.Cdma2000OneXSRVCCInfo, options aper.DecodeState) (s14.Cdma2000OneXSRVCCInfo, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s14.BridgeCaptureS1APCdma2000OneXSRVCCInfo(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)

			return v, root
		}
		*s14.BridgeCdma2000OneXSRVCCInfoValueCodecFieldCompare(&sealed) = func(v s14.Cdma2000OneXSRVCCInfo, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s14.BridgeCompareS1APCdma2000OneXSRVCCInfo(&v, &s)
			s.End(f, root, false)

			return s.Plan(), s.BudgetValue()
		}
		*s14.BridgeCdma2000OneXSRVCCInfoValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:Cdma2000OneXSRVCCInfo"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s14.Cdma2000OneXSRVCCInfo) UplinkS1cdma2000tunnellingIEValue {
			return UplinkS1cdma2000tunnellingIEValue{id: s00.ProtocolIEID(102), rowCdma2000OneXSRVCCInfo: &value}
		}, get: func(value *UplinkS1cdma2000tunnellingIEValue) (*s14.Cdma2000OneXSRVCCInfo, bool) {
			return value.AsCdma2000OneXSRVCCInfo()
		}}
}
func (UplinkS1cdma2000tunnellingIETable) infoCdma2000OneXRAND() s00.FieldInfo {
	return s00.FieldInfo{Table: UplinkS1cdma2000tunnellingIEs().ID(), ID: s00.ProtocolIEID(97), Criticality: s00.CriticalityReject, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "Cdma2000OneXRAND"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "UplinkS1cdma2000tunnellingIEs", Row: "id-cdma2000OneXRAND"}}}
}

// Cdma2000OneXRAND returns the typed binding for the Cdma2000OneXRAND row of UplinkS1cdma2000tunnellingIETable.
func (t UplinkS1cdma2000tunnellingIETable) Cdma2000OneXRAND() UplinkS1cdma2000tunnellingCdma2000OneXRANDIEBinding {
	return UplinkS1cdma2000tunnellingCdma2000OneXRANDIEBinding{info: t.infoCdma2000OneXRAND(), codec: func() s00.Cdma2000OneXRANDValueCodec {
		sealed := s00.Cdma2000OneXRANDValueCodec{}
		*s00.BridgeCdma2000OneXRANDValueCodecFieldPath(&sealed) = "Cdma2000OneXRAND"
		*s00.BridgeCdma2000OneXRANDValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.Cdma2000OneXRAND, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s00.Cdma2000OneXRAND
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("Cdma2000OneXRAND")
			var zero UplinkS1cdma2000tunnellingIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(97), raw)
			if err != nil {
				var empty s00.Cdma2000OneXRAND
				return empty, err
			}
			value, ok := decoded.AsCdma2000OneXRAND()
			if !ok {
				var empty s00.Cdma2000OneXRAND
				return empty, fmt.Errorf("binding UplinkS1cdma2000tunnellingIEs.id-cdma2000OneXRAND: no selected value")
			}
			return *value, nil
		}
		*s00.BridgeCdma2000OneXRANDValueCodecFieldEncode(&sealed) = func(value s00.Cdma2000OneXRAND, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (UplinkS1cdma2000tunnellingIEValue{id: s00.ProtocolIEID(97), rowCdma2000OneXRAND: &value}).encodeFresh(fresh, budget)
		}
		*s00.BridgeCdma2000OneXRANDValueCodecFieldCapture(&sealed) = func(v s00.Cdma2000OneXRAND, options aper.DecodeState) (s00.Cdma2000OneXRAND, aper.Snapshot) {
			s := aper.SemanticCaptureFor(
				options)
			f := s.Begin()
			s00.BridgeCaptureS1APCdma2000OneXRAND(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s00.BridgeCdma2000OneXRANDValueCodecFieldCompare(&sealed) = func(v s00.Cdma2000OneXRAND, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s02.BridgeCompareS1APCdma2000OneXRAND(&v, &s)
			s.End(f, root, false)
			return s.
				Plan(), s.BudgetValue()
		}
		*s00.BridgeCdma2000OneXRANDValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:Cdma2000OneXRAND"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s00.Cdma2000OneXRAND) UplinkS1cdma2000tunnellingIEValue {
			return UplinkS1cdma2000tunnellingIEValue{id: s00.ProtocolIEID(97), rowCdma2000OneXRAND: &value}
		}, get: func(value *UplinkS1cdma2000tunnellingIEValue) (*s00.Cdma2000OneXRAND, bool) {
			return value.AsCdma2000OneXRAND()
		}}
}
func (UplinkS1cdma2000tunnellingIETable) infoCdma2000PDU() s00.FieldInfo {
	return s00.FieldInfo{Table: UplinkS1cdma2000tunnellingIEs().ID(), ID: s00.ProtocolIEID(70), Criticality: s00.CriticalityReject, Presence: s00.PresenceMandatory, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "Cdma2000PDU"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "UplinkS1cdma2000tunnellingIEs", Row: "id-cdma2000PDU"}}}
}

// Cdma2000PDU returns the typed binding for the Cdma2000PDU row of UplinkS1cdma2000tunnellingIETable.
func (t UplinkS1cdma2000tunnellingIETable) Cdma2000PDU() UplinkS1cdma2000tunnellingCdma2000PDUIEBinding {
	return UplinkS1cdma2000tunnellingCdma2000PDUIEBinding{info: t.infoCdma2000PDU(), codec: func() s00.Cdma2000PDUValueCodec {
		sealed := s00.Cdma2000PDUValueCodec{}
		*s00.BridgeCdma2000PDUValueCodecFieldPath(&sealed) = "Cdma2000PDU"
		*s00.BridgeCdma2000PDUValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.Cdma2000PDU, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s00.Cdma2000PDU
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("Cdma2000PDU")
			var zero UplinkS1cdma2000tunnellingIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(70), raw)
			if err != nil {
				var empty s00.Cdma2000PDU
				return empty, err
			}
			value, ok := decoded.AsCdma2000PDU()
			if !ok {
				var empty s00.Cdma2000PDU
				return empty, fmt.Errorf("binding UplinkS1cdma2000tunnellingIEs.id-cdma2000PDU: no selected value")
			}
			return *value, nil
		}
		*s00.BridgeCdma2000PDUValueCodecFieldEncode(&sealed) = func(value s00.Cdma2000PDU, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (UplinkS1cdma2000tunnellingIEValue{id: s00.ProtocolIEID(70), rowCdma2000PDU: &value}).encodeFresh(fresh, budget)
		}
		*s00.BridgeCdma2000PDUValueCodecFieldCapture(&sealed) = func(v s00.Cdma2000PDU, options aper.DecodeState) (s00.Cdma2000PDU, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s00.BridgeCaptureS1APCdma2000PDU(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s00.BridgeCdma2000PDUValueCodecFieldCompare(&sealed) = func(v s00.Cdma2000PDU, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s02.BridgeCompareS1APCdma2000PDU(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.
				BudgetValue()
		}
		*s00.BridgeCdma2000PDUValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:Cdma2000PDU"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s00.Cdma2000PDU) UplinkS1cdma2000tunnellingIEValue {
			return UplinkS1cdma2000tunnellingIEValue{id: s00.ProtocolIEID(70), rowCdma2000PDU: &value}
		}, get: func(value *UplinkS1cdma2000tunnellingIEValue) (*s00.Cdma2000PDU, bool) { return value.AsCdma2000PDU() }}
}
func (UplinkS1cdma2000tunnellingIETable) infoEUTRANRoundTripDelayEstimationInfo() s00.FieldInfo {
	return s00.FieldInfo{Table: UplinkS1cdma2000tunnellingIEs().ID(), ID: s00.ProtocolIEID(140), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "EUTRANRoundTripDelayEstimationInfo"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "UplinkS1cdma2000tunnellingIEs", Row: "id-EUTRANRoundTripDelayEstimationInfo"}}}
}

// EUTRANRoundTripDelayEstimationInfo returns the typed binding for the EUTRANRoundTripDelayEstimationInfo row of UplinkS1cdma2000tunnellingIETable.
func (t UplinkS1cdma2000tunnellingIETable) EUTRANRoundTripDelayEstimationInfo() UplinkS1cdma2000tunnellingEUTRANRoundTripDelayEstimationInfoIEBinding {
	return UplinkS1cdma2000tunnellingEUTRANRoundTripDelayEstimationInfoIEBinding{info: t.infoEUTRANRoundTripDelayEstimationInfo(), codec: func() s00.EUTRANRoundTripDelayEstimationInfoValueCodec {
		sealed := s00.EUTRANRoundTripDelayEstimationInfoValueCodec{}
		*s00.BridgeEUTRANRoundTripDelayEstimationInfoValueCodecFieldPath(&sealed) = "EUTRANRoundTripDelayEstimationInfo"
		*s00.BridgeEUTRANRoundTripDelayEstimationInfoValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.EUTRANRoundTripDelayEstimationInfo, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s00.EUTRANRoundTripDelayEstimationInfo
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("EUTRANRoundTripDelayEstimationInfo")
			var zero UplinkS1cdma2000tunnellingIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(140), raw)
			if err != nil {
				var empty s00.EUTRANRoundTripDelayEstimationInfo
				return empty, err
			}
			value, ok := decoded.AsEUTRANRoundTripDelayEstimationInfo()
			if !ok {
				var empty s00.EUTRANRoundTripDelayEstimationInfo
				return empty, fmt.Errorf("binding UplinkS1cdma2000tunnellingIEs.id-EUTRANRoundTripDelayEstimationInfo: no selected value")
			}
			return *value, nil
		}
		*s00.BridgeEUTRANRoundTripDelayEstimationInfoValueCodecFieldEncode(&sealed) = func(value s00.EUTRANRoundTripDelayEstimationInfo, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (UplinkS1cdma2000tunnellingIEValue{id: s00.ProtocolIEID(140), rowEUTRANRoundTripDelayEstimationInfo: &value}).encodeFresh(fresh, budget)
		}
		*s00.BridgeEUTRANRoundTripDelayEstimationInfoValueCodecFieldCapture(&sealed) = func(v s00.EUTRANRoundTripDelayEstimationInfo, options aper.DecodeState) (s00.EUTRANRoundTripDelayEstimationInfo, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s00.BridgeCaptureS1APEUTRANRoundTripDelayEstimationInfo(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s00.BridgeEUTRANRoundTripDelayEstimationInfoValueCodecFieldCompare(&sealed) = func(v s00.EUTRANRoundTripDelayEstimationInfo, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s02.BridgeCompareS1APEUTRANRoundTripDelayEstimationInfo(
				&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s00.BridgeEUTRANRoundTripDelayEstimationInfoValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:EUTRANRoundTripDelayEstimationInfo"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s00.EUTRANRoundTripDelayEstimationInfo) UplinkS1cdma2000tunnellingIEValue {
			return UplinkS1cdma2000tunnellingIEValue{id: s00.ProtocolIEID(140), rowEUTRANRoundTripDelayEstimationInfo: &value}
		}, get: func(value *UplinkS1cdma2000tunnellingIEValue) (*s00.EUTRANRoundTripDelayEstimationInfo, bool) {
			return value.AsEUTRANRoundTripDelayEstimationInfo()
		}}
}

// NewOpaque constructs an owned opaque field for an identifier without a typed row in UplinkS1cdma2000tunnellingIETable.
func (t UplinkS1cdma2000tunnellingIETable) NewOpaque(id s00.ProtocolIEID, criticality s00.Criticality, data []byte) (UplinkS1cdma2000tunnellingIEField, error) {
	if id < 0 || id > 65535 || criticality < 0 || criticality > 2 {
		return UplinkS1cdma2000tunnellingIEField{}, aper.OperationError(fmt.Errorf("invalid opaque IE selector or criticality"), "Opaque")
	}
	switch id {
	case s00.ProtocolIEID(0):
		return UplinkS1cdma2000tunnellingIEField{}, aper.OperationError(fmt.Errorf("known IE id-MME-UE-S1AP-ID requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(8):
		return UplinkS1cdma2000tunnellingIEField{}, aper.OperationError(fmt.Errorf("known IE id-eNB-UE-S1AP-ID requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(71):
		return UplinkS1cdma2000tunnellingIEField{}, aper.OperationError(fmt.Errorf("known IE id-cdma2000RATType requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(72):
		return UplinkS1cdma2000tunnellingIEField{}, aper.OperationError(fmt.Errorf("known IE id-cdma2000SectorID requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(84):
		return UplinkS1cdma2000tunnellingIEField{}, aper.OperationError(fmt.Errorf("known IE id-cdma2000HORequiredIndication requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(102):
		return UplinkS1cdma2000tunnellingIEField{}, aper.OperationError(fmt.Errorf("known IE id-cdma2000OneXSRVCCInfo requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(97):
		return UplinkS1cdma2000tunnellingIEField{}, aper.OperationError(fmt.Errorf("known IE id-cdma2000OneXRAND requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(70):
		return UplinkS1cdma2000tunnellingIEField{}, aper.OperationError(fmt.Errorf("known IE id-cdma2000PDU requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(140):
		return UplinkS1cdma2000tunnellingIEField{}, aper.OperationError(fmt.Errorf("known IE id-EUTRANRoundTripDelayEstimationInfo requires its typed binding"), "Opaque")
	default:
		budget, err := aper.BuildBudget()
		if err != nil {
			return UplinkS1cdma2000tunnellingIEField{}, aper.OperationError(err, "Opaque")
		}
		opaque, err := aper.BuildOpaqueOpenType(data, budget)
		if err != nil {
			return UplinkS1cdma2000tunnellingIEField{}, aper.OperationError(err, "Opaque")
		}
		return UplinkS1cdma2000tunnellingIEField{Id: id, Criticality: criticality, Value: UplinkS1cdma2000tunnellingIEValue{id: id, opaque: opaque, isOpaque: true}}, aper.OperationError(nil, "Opaque")
	}
}

// BearersSubjectToStatusTransferItemCodec binds the complete APER value type.
func BearersSubjectToStatusTransferItemCodec() BearersSubjectToStatusTransferItemValueCodec {
	return BearersSubjectToStatusTransferItemIEs().BearersSubjectToStatusTransferItem().Codec()
}

// Cdma2000HORequiredIndicationCodec binds the complete APER value type.
func Cdma2000HORequiredIndicationCodec() s00.Cdma2000HORequiredIndicationValueCodec {
	return UplinkS1cdma2000tunnellingIEs().Cdma2000HORequiredIndication().Codec()
}

// Cdma2000OneXRANDCodec binds the complete APER value type.
func Cdma2000OneXRANDCodec() s00.Cdma2000OneXRANDValueCodec {
	return UplinkS1cdma2000tunnellingIEs().Cdma2000OneXRAND().Codec()
}

// Cdma2000OneXSRVCCInfoCodec binds the complete APER value type.
func Cdma2000OneXSRVCCInfoCodec() s14.Cdma2000OneXSRVCCInfoValueCodec {
	return UplinkS1cdma2000tunnellingIEs().Cdma2000OneXSRVCCInfo().Codec()
}

// Cdma2000SectorIDCodec binds the complete APER value type.
func Cdma2000SectorIDCodec() s00.Cdma2000SectorIDValueCodec {
	return UplinkS1cdma2000tunnellingIEs().Cdma2000SectorID().Codec()
}

// CellActivationResponseCodec binds the complete source value type.
func CellActivationResponseCodec() CellActivationResponseValueCodec {
	return CellActivationResponseValueCodec{path: "CellActivationResponse", decode: func(data []byte, options aper.DecodeState) (CellActivationResponse, error) {
		var value CellActivationResponse
		if err := value.unmarshalAPERWithOptions(data, options); err != nil {
			return CellActivationResponse{}, err
		}
		value.received = true
		value.receivedAbsolute = true
		value.receivedBytes = aper.OriginalWire(data)
		return value, nil
	}, encode: func(value CellActivationResponse, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return (&value).marshalAPERBudget(budget, fresh)
	}, capture: func(v CellActivationResponse, options aper.DecodeState) (CellActivationResponse, aper.Snapshot,

	) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeCaptureS1APCellActivationResponse(&v, &s)
		var root aper.Snapshot
		s.End(f, &root, false)
		return v, root
	}, compare: func(v CellActivationResponse, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

	) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		BridgeCompareS1APCellActivationResponse(&v, &s)
		s.End(f, root, false)
		return s.Plan(), s.BudgetValue()
	}, context: func() s00.BridgeCodecContext {
		sealed := s00.BridgeCodecContext{}
		*s00.BridgecodecContextFieldSource(&sealed) = "source-value:CellActivationResponse"
		*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
		return sealed
	}(),
	}
}

// ENBStatusTransferTransparentContainerCodec binds the complete APER value type.
func ENBStatusTransferTransparentContainerCodec() ENBStatusTransferTransparentContainerValueCodec {
	return ENBStatusTransferIEs().ENBStatusTransferTransparentContainer().Codec()
}

// EUTRANRoundTripDelayEstimationInfoCodec binds the complete APER value type.
func EUTRANRoundTripDelayEstimationInfoCodec() s00.EUTRANRoundTripDelayEstimationInfoValueCodec {
	return UplinkS1cdma2000tunnellingIEs().EUTRANRoundTripDelayEstimationInfo().Codec()
}

// LTENTNTAIInformationCodec binds the complete APER value type.
func LTENTNTAIInformationCodec() s18.LTENTNTAIInformationValueCodec {
	return UserLocationInformationExtIEs().LTENTNTAIInformation().Codec()
}

// PSCellInformationCodec binds the complete APER value type.
func PSCellInformationCodec() s20.PSCellInformationValueCodec {
	return UserLocationInformationExtIEs().PSCellInformation().Codec()
}

// TransportInformationCodec binds the complete APER value type.
func TransportInformationCodec() TransportInformationValueCodec {
	return ERABToBeModifyItemBearerModReqExtIEs().TransportInformation().Codec()
}
func (r *ValidationReport) addIssue(issue ValidationIssue) {
	if err := r.reserveReport(issue.Location); err != nil {
		return
	}
	r.Issues = append(r.Issues, issue)
}
func (r *ValidationReport) addDeferred(item s00.DeferredCondition) {
	if err := r.reserveReport(item.Location); err != nil {
		return
	}
	r.Deferred = append(r.Deferred, item)
}
func (r *ValidationReport) addUnchecked(location aper.Location) {
	if err := r.reserveReport(location); err != nil {
		return
	}
	r.Unchecked = append(r.Unchecked, location)
}
func (r *ValidationReport) reserveReport(location aper.Location) error {
	if r.err != nil {
		return r.err
	}
	if r.budget == nil {
		return nil
	}
	bb := aper.NewBudgetBuffer(r.budget)
	if err := bb.ChargeLocatedReport(location, 1024); err != nil {
		r.err = err
		return err
	}
	return nil
}

type ValidationIssue struct {
	Code                s00.ValidationCode
	Severity            s00.ValidationSeverity
	Location            aper.Location
	Table               s00.TableID
	IEID                s00.ProtocolIEID
	HasIEID             bool
	PrivateID           *s20.PrivateIEID
	ExpectedCriticality *s00.Criticality
	ReceivedCriticality *s00.Criticality
	Rule                aper.SourceRule
	RelatedRules        []aper.SourceRule
}
type ValidationReport struct {
	budget    *aper.DecodeBudget
	err       error
	Issues    []ValidationIssue
	Deferred  []s00.DeferredCondition
	Unchecked []aper.Location
	Complete  bool
}

func BridgeBearersSubjectToStatusTransferItemAPERValueFieldContext(v *BearersSubjectToStatusTransferItemAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeBearersSubjectToStatusTransferItemAPERValueFieldReceived(v *BearersSubjectToStatusTransferItemAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeBearersSubjectToStatusTransferItemAPERValueFieldReplay(v *BearersSubjectToStatusTransferItemAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeBearersSubjectToStatusTransferItemAPERValueFieldWithoutReplay(v *BearersSubjectToStatusTransferItemAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeBearersSubjectToStatusTransferItemBearersSubjectToStatusTransferItemIEBindingFieldCodec(v *BearersSubjectToStatusTransferItemBearersSubjectToStatusTransferItemIEBinding) *BearersSubjectToStatusTransferItemValueCodec {
	return &v.codec
}
func BridgeBearersSubjectToStatusTransferItemBearersSubjectToStatusTransferItemIEBindingFieldGet(v *BearersSubjectToStatusTransferItemBearersSubjectToStatusTransferItemIEBinding) *func(*BearersSubjectToStatusTransferItemIEValue) (*BearersSubjectToStatusTransferItem, bool) {
	return &v.get
}
func BridgeBearersSubjectToStatusTransferItemBearersSubjectToStatusTransferItemIEBindingFieldInfo(v *BearersSubjectToStatusTransferItemBearersSubjectToStatusTransferItemIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeBearersSubjectToStatusTransferItemBearersSubjectToStatusTransferItemIEBindingFieldInject(v *BearersSubjectToStatusTransferItemBearersSubjectToStatusTransferItemIEBinding) *func(BearersSubjectToStatusTransferItem) BearersSubjectToStatusTransferItemIEValue {
	return &v.inject
}
func BridgeBearersSubjectToStatusTransferItemFieldExtCount(v *BearersSubjectToStatusTransferItem) *int64 {
	return &v.extCount
}
func BridgeBearersSubjectToStatusTransferItemFieldExtData(v *BearersSubjectToStatusTransferItem) *[][]byte {
	return &v.extData
}
func BridgeBearersSubjectToStatusTransferItemFieldExtOrigin(v *BearersSubjectToStatusTransferItem) *[]aper.OpaqueOrigin {
	return &v.extOrigin
}
func BridgeBearersSubjectToStatusTransferItemFieldExtPresent(v *BearersSubjectToStatusTransferItem) *[]bool {
	return &v.extPresent
}
func BridgeBearersSubjectToStatusTransferItemFieldExtWire(v *BearersSubjectToStatusTransferItem) *[]aper.WireSpan {
	return &v.extWire
}
func BridgeBearersSubjectToStatusTransferItemFieldIEExtensionsIndef(v *BearersSubjectToStatusTransferItem) *bool {
	return &v.iEExtensionsIndef
}
func BridgeBearersSubjectToStatusTransferItemFieldPerExtPadding(v *BearersSubjectToStatusTransferItem) *[]aper.CompletePadding {
	return &v.perExtPadding
}
func BridgeBearersSubjectToStatusTransferItemFieldPerPadding(v *BearersSubjectToStatusTransferItem) *aper.FinalPadding {
	return &v.perPadding
}
func BridgeBearersSubjectToStatusTransferItemFieldReceived(v *BearersSubjectToStatusTransferItem) *bool {
	return &v.received
}
func BridgeBearersSubjectToStatusTransferItemFieldReceivedAbsolute(v *BearersSubjectToStatusTransferItem) *bool {
	return &v.receivedAbsolute
}
func BridgeBearersSubjectToStatusTransferItemFieldReceivedBytes(v *BearersSubjectToStatusTransferItem) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeBearersSubjectToStatusTransferItemFieldReceivedLocation(v *BearersSubjectToStatusTransferItem) *aper.Location {
	return &v.receivedLocation
}
func BridgeBearersSubjectToStatusTransferItemFieldReplay(v *BearersSubjectToStatusTransferItem) *aper.Snapshot {
	return &v.replay
}
func BridgeBearersSubjectToStatusTransferItemFieldStream(v *BearersSubjectToStatusTransferItem) *aper.WireSpan {
	return &v.stream
}
func BridgeBearersSubjectToStatusTransferItemFieldWithoutReplay(v *BearersSubjectToStatusTransferItem) *bool {
	return &v.withoutReplay
}
func BridgeBearersSubjectToStatusTransferItemIEContainerAPERValueFieldContext(v *BearersSubjectToStatusTransferItemIEContainerAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeBearersSubjectToStatusTransferItemIEContainerAPERValueFieldReceived(v *BearersSubjectToStatusTransferItemIEContainerAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeBearersSubjectToStatusTransferItemIEContainerAPERValueFieldReplay(v *BearersSubjectToStatusTransferItemIEContainerAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeBearersSubjectToStatusTransferItemIEContainerAPERValueFieldWithoutReplay(v *BearersSubjectToStatusTransferItemIEContainerAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeBearersSubjectToStatusTransferItemIEContainerValueCodecFieldCapture(v *BearersSubjectToStatusTransferItemIEContainerValueCodec) *func(BearersSubjectToStatusTransferItemIEContainer, aper.DecodeState) (BearersSubjectToStatusTransferItemIEContainer, aper.Snapshot) {
	return &v.capture
}
func BridgeBearersSubjectToStatusTransferItemIEContainerValueCodecFieldCompare(v *BearersSubjectToStatusTransferItemIEContainerValueCodec) *func(BearersSubjectToStatusTransferItemIEContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeBearersSubjectToStatusTransferItemIEContainerValueCodecFieldContext(v *BearersSubjectToStatusTransferItemIEContainerValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeBearersSubjectToStatusTransferItemIEContainerValueCodecFieldDecode(v *BearersSubjectToStatusTransferItemIEContainerValueCodec) *func([]byte, aper.DecodeState) (BearersSubjectToStatusTransferItemIEContainer, error) {
	return &v.decode
}
func BridgeBearersSubjectToStatusTransferItemIEContainerValueCodecFieldEncode(v *BearersSubjectToStatusTransferItemIEContainerValueCodec) *func(BearersSubjectToStatusTransferItemIEContainer, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeBearersSubjectToStatusTransferItemIEContainerValueCodecFieldPath(v *BearersSubjectToStatusTransferItemIEContainerValueCodec) *aper.Path {
	return &v.path
}
func BridgeBearersSubjectToStatusTransferItemIEContainerValueCodecMethodEncodeBudgetValue(v BearersSubjectToStatusTransferItemIEContainerValueCodec, a0 BearersSubjectToStatusTransferItemIEContainer, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeBearersSubjectToStatusTransferItemIEContainerValueCodecMethodEncodeChanged(v BearersSubjectToStatusTransferItemIEContainerValueCodec, a0 BearersSubjectToStatusTransferItemIEContainer, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeBearersSubjectToStatusTransferItemIEFieldAPERValueFieldContext(v *BearersSubjectToStatusTransferItemIEFieldAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeBearersSubjectToStatusTransferItemIEFieldAPERValueFieldReceived(v *BearersSubjectToStatusTransferItemIEFieldAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeBearersSubjectToStatusTransferItemIEFieldAPERValueFieldReplay(v *BearersSubjectToStatusTransferItemIEFieldAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeBearersSubjectToStatusTransferItemIEFieldAPERValueFieldWithoutReplay(v *BearersSubjectToStatusTransferItemIEFieldAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeBearersSubjectToStatusTransferItemIEFieldFieldReceived(v *BearersSubjectToStatusTransferItemIEField) *aper.CompletePadding {
	return &v.received
}
func BridgeBearersSubjectToStatusTransferItemIEFieldFieldReplay(v *BearersSubjectToStatusTransferItemIEField) *aper.Snapshot {
	return &v.replay
}
func BridgeBearersSubjectToStatusTransferItemIEFieldFieldStream(v *BearersSubjectToStatusTransferItemIEField) *aper.WireSpan {
	return &v.stream
}
func BridgeBearersSubjectToStatusTransferItemIEFieldFieldWithoutReplay(v *BearersSubjectToStatusTransferItemIEField) *bool {
	return &v.withoutReplay
}
func BridgeBearersSubjectToStatusTransferItemIEFieldMethodMarshalAPERTo(v *BearersSubjectToStatusTransferItemIEField, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeBearersSubjectToStatusTransferItemIEFieldMethodUnmarshalAPERFrom(v *BearersSubjectToStatusTransferItemIEField, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeBearersSubjectToStatusTransferItemIEFieldValueCodecFieldCapture(v *BearersSubjectToStatusTransferItemIEFieldValueCodec) *func(BearersSubjectToStatusTransferItemIEField, aper.DecodeState) (BearersSubjectToStatusTransferItemIEField, aper.Snapshot) {
	return &v.capture
}
func BridgeBearersSubjectToStatusTransferItemIEFieldValueCodecFieldCompare(v *BearersSubjectToStatusTransferItemIEFieldValueCodec) *func(BearersSubjectToStatusTransferItemIEField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeBearersSubjectToStatusTransferItemIEFieldValueCodecFieldContext(v *BearersSubjectToStatusTransferItemIEFieldValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeBearersSubjectToStatusTransferItemIEFieldValueCodecFieldDecode(v *BearersSubjectToStatusTransferItemIEFieldValueCodec) *func([]byte, aper.DecodeState) (BearersSubjectToStatusTransferItemIEField, error) {
	return &v.decode
}
func BridgeBearersSubjectToStatusTransferItemIEFieldValueCodecFieldEncode(v *BearersSubjectToStatusTransferItemIEFieldValueCodec) *func(BearersSubjectToStatusTransferItemIEField, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeBearersSubjectToStatusTransferItemIEFieldValueCodecFieldPath(v *BearersSubjectToStatusTransferItemIEFieldValueCodec) *aper.Path {
	return &v.path
}
func BridgeBearersSubjectToStatusTransferItemIEFieldValueCodecMethodEncodeBudgetValue(v BearersSubjectToStatusTransferItemIEFieldValueCodec, a0 BearersSubjectToStatusTransferItemIEField, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeBearersSubjectToStatusTransferItemIEFieldValueCodecMethodEncodeChanged(v BearersSubjectToStatusTransferItemIEFieldValueCodec, a0 BearersSubjectToStatusTransferItemIEField, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeBearersSubjectToStatusTransferItemIETableMethodInfoBearersSubjectToStatusTransferItem(v BearersSubjectToStatusTransferItemIETable) s00.FieldInfo {
	return v.infoBearersSubjectToStatusTransferItem()
}
func BridgeBearersSubjectToStatusTransferItemIEValueERABIEContainerListAPERValueFieldContext(v *BearersSubjectToStatusTransferItemIEValueERABIEContainerListAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeBearersSubjectToStatusTransferItemIEValueERABIEContainerListAPERValueFieldReceived(v *BearersSubjectToStatusTransferItemIEValueERABIEContainerListAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeBearersSubjectToStatusTransferItemIEValueERABIEContainerListAPERValueFieldReplay(v *BearersSubjectToStatusTransferItemIEValueERABIEContainerListAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeBearersSubjectToStatusTransferItemIEValueERABIEContainerListAPERValueFieldWithoutReplay(v *BearersSubjectToStatusTransferItemIEValueERABIEContainerListAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeBearersSubjectToStatusTransferItemIEValueERABIEContainerListValueCodecFieldCapture(v *BearersSubjectToStatusTransferItemIEValueERABIEContainerListValueCodec) *func(BearersSubjectToStatusTransferItemIEValueERABIEContainerList, aper.DecodeState) (BearersSubjectToStatusTransferItemIEValueERABIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgeBearersSubjectToStatusTransferItemIEValueERABIEContainerListValueCodecFieldCompare(v *BearersSubjectToStatusTransferItemIEValueERABIEContainerListValueCodec) *func(BearersSubjectToStatusTransferItemIEValueERABIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeBearersSubjectToStatusTransferItemIEValueERABIEContainerListValueCodecFieldContext(v *BearersSubjectToStatusTransferItemIEValueERABIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeBearersSubjectToStatusTransferItemIEValueERABIEContainerListValueCodecFieldDecode(v *BearersSubjectToStatusTransferItemIEValueERABIEContainerListValueCodec) *func([]byte, aper.DecodeState) (BearersSubjectToStatusTransferItemIEValueERABIEContainerList, error) {
	return &v.decode
}
func BridgeBearersSubjectToStatusTransferItemIEValueERABIEContainerListValueCodecFieldEncode(v *BearersSubjectToStatusTransferItemIEValueERABIEContainerListValueCodec) *func(BearersSubjectToStatusTransferItemIEValueERABIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeBearersSubjectToStatusTransferItemIEValueERABIEContainerListValueCodecFieldPath(v *BearersSubjectToStatusTransferItemIEValueERABIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgeBearersSubjectToStatusTransferItemIEValueERABIEContainerListValueCodecMethodEncodeBudgetValue(v BearersSubjectToStatusTransferItemIEValueERABIEContainerListValueCodec, a0 BearersSubjectToStatusTransferItemIEValueERABIEContainerList, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeBearersSubjectToStatusTransferItemIEValueERABIEContainerListValueCodecMethodEncodeChanged(v BearersSubjectToStatusTransferItemIEValueERABIEContainerListValueCodec, a0 BearersSubjectToStatusTransferItemIEValueERABIEContainerList, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeBearersSubjectToStatusTransferItemIEValueFieldId(v *BearersSubjectToStatusTransferItemIEValue) *s00.ProtocolIEID {
	return &v.id
}
func BridgeBearersSubjectToStatusTransferItemIEValueFieldIsOpaque(v *BearersSubjectToStatusTransferItemIEValue) *bool {
	return &v.isOpaque
}
func BridgeBearersSubjectToStatusTransferItemIEValueFieldOpaque(v *BearersSubjectToStatusTransferItemIEValue) *aper.OpaqueOpenType {
	return &v.opaque
}
func BridgeBearersSubjectToStatusTransferItemIEValueFieldReceived(v *BearersSubjectToStatusTransferItemIEValue) *aper.WireSpan {
	return &v.received
}
func BridgeBearersSubjectToStatusTransferItemIEValueFieldReplay(v *BearersSubjectToStatusTransferItemIEValue) *aper.Snapshot {
	return &v.replay
}
func BridgeBearersSubjectToStatusTransferItemIEValueFieldRowBearersSubjectToStatusTransferItem(v *BearersSubjectToStatusTransferItemIEValue) **BearersSubjectToStatusTransferItem {
	return &v.rowBearersSubjectToStatusTransferItem
}
func BridgeBearersSubjectToStatusTransferItemIEValueMethodCaptureSemantics(v BearersSubjectToStatusTransferItemIEValue, a0 aper.SemanticCapture) BearersSubjectToStatusTransferItemIEValue {
	return v.captureSemantics(a0)
}
func BridgeBearersSubjectToStatusTransferItemIEValueMethodCompareSemantics(v BearersSubjectToStatusTransferItemIEValue, a0 aper.SemanticComparison) aper.SemanticComparison {
	return v.compareSemantics(a0)
}
func BridgeBearersSubjectToStatusTransferItemIEValueMethodDecode(v BearersSubjectToStatusTransferItemIEValue, a0 s00.ProtocolIEID, a1 aper.OpaqueOpenType) (BearersSubjectToStatusTransferItemIEValue, error) {
	return v.decode(a0, a1)
}
func BridgeBearersSubjectToStatusTransferItemIEValueMethodEncode(v BearersSubjectToStatusTransferItemIEValue) ([]byte, error) {
	return v.encode()
}
func BridgeBearersSubjectToStatusTransferItemIEValueMethodEncodeFresh(v BearersSubjectToStatusTransferItemIEValue, a0 bool, a1 *aper.DecodeBudget) ([]byte, error) {
	return v.encodeFresh(a0, a1)
}
func BridgeBearersSubjectToStatusTransferItemIEValueMethodMatchesID(v BearersSubjectToStatusTransferItemIEValue, a0 s00.ProtocolIEID, a1 ...*aper.DecodeBudget) bool {
	return v.matchesID(a0, a1...)
}
func BridgeBearersSubjectToStatusTransferItemIEValueMethodReason(v BearersSubjectToStatusTransferItemIEValue, a0 s00.ProtocolIEID) aper.OpaqueReason {
	return v.reason(a0)
}
func BridgeBearersSubjectToStatusTransferItemIEValueMethodRule(v BearersSubjectToStatusTransferItemIEValue) aper.SourceRule {
	return v.rule()
}
func BridgeBearersSubjectToStatusTransferItemIEValueProtocolErrorIEContainerListAPERValueFieldContext(v *BearersSubjectToStatusTransferItemIEValueProtocolErrorIEContainerListAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeBearersSubjectToStatusTransferItemIEValueProtocolErrorIEContainerListAPERValueFieldReceived(v *BearersSubjectToStatusTransferItemIEValueProtocolErrorIEContainerListAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeBearersSubjectToStatusTransferItemIEValueProtocolErrorIEContainerListAPERValueFieldReplay(v *BearersSubjectToStatusTransferItemIEValueProtocolErrorIEContainerListAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeBearersSubjectToStatusTransferItemIEValueProtocolErrorIEContainerListAPERValueFieldWithoutReplay(v *BearersSubjectToStatusTransferItemIEValueProtocolErrorIEContainerListAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeBearersSubjectToStatusTransferItemIEValueProtocolErrorIEContainerListValueCodecFieldCapture(v *BearersSubjectToStatusTransferItemIEValueProtocolErrorIEContainerListValueCodec) *func(BearersSubjectToStatusTransferItemIEValueProtocolErrorIEContainerList, aper.DecodeState) (BearersSubjectToStatusTransferItemIEValueProtocolErrorIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgeBearersSubjectToStatusTransferItemIEValueProtocolErrorIEContainerListValueCodecFieldCompare(v *BearersSubjectToStatusTransferItemIEValueProtocolErrorIEContainerListValueCodec) *func(BearersSubjectToStatusTransferItemIEValueProtocolErrorIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeBearersSubjectToStatusTransferItemIEValueProtocolErrorIEContainerListValueCodecFieldContext(v *BearersSubjectToStatusTransferItemIEValueProtocolErrorIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeBearersSubjectToStatusTransferItemIEValueProtocolErrorIEContainerListValueCodecFieldDecode(v *BearersSubjectToStatusTransferItemIEValueProtocolErrorIEContainerListValueCodec) *func([]byte, aper.DecodeState) (BearersSubjectToStatusTransferItemIEValueProtocolErrorIEContainerList, error) {
	return &v.decode
}
func BridgeBearersSubjectToStatusTransferItemIEValueProtocolErrorIEContainerListValueCodecFieldEncode(v *BearersSubjectToStatusTransferItemIEValueProtocolErrorIEContainerListValueCodec) *func(BearersSubjectToStatusTransferItemIEValueProtocolErrorIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeBearersSubjectToStatusTransferItemIEValueProtocolErrorIEContainerListValueCodecFieldPath(v *BearersSubjectToStatusTransferItemIEValueProtocolErrorIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgeBearersSubjectToStatusTransferItemIEValueProtocolErrorIEContainerListValueCodecMethodEncodeBudgetValue(v BearersSubjectToStatusTransferItemIEValueProtocolErrorIEContainerListValueCodec, a0 BearersSubjectToStatusTransferItemIEValueProtocolErrorIEContainerList, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeBearersSubjectToStatusTransferItemIEValueProtocolErrorIEContainerListValueCodecMethodEncodeChanged(v BearersSubjectToStatusTransferItemIEValueProtocolErrorIEContainerListValueCodec, a0 BearersSubjectToStatusTransferItemIEValueProtocolErrorIEContainerList, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeBearersSubjectToStatusTransferItemIEValueProtocolIEContainerListAPERValueFieldContext(v *BearersSubjectToStatusTransferItemIEValueProtocolIEContainerListAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeBearersSubjectToStatusTransferItemIEValueProtocolIEContainerListAPERValueFieldReceived(v *BearersSubjectToStatusTransferItemIEValueProtocolIEContainerListAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeBearersSubjectToStatusTransferItemIEValueProtocolIEContainerListAPERValueFieldReplay(v *BearersSubjectToStatusTransferItemIEValueProtocolIEContainerListAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeBearersSubjectToStatusTransferItemIEValueProtocolIEContainerListAPERValueFieldWithoutReplay(v *BearersSubjectToStatusTransferItemIEValueProtocolIEContainerListAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeBearersSubjectToStatusTransferItemIEValueProtocolIEContainerListValueCodecFieldCapture(v *BearersSubjectToStatusTransferItemIEValueProtocolIEContainerListValueCodec) *func(BearersSubjectToStatusTransferItemIEValueProtocolIEContainerList, aper.DecodeState) (BearersSubjectToStatusTransferItemIEValueProtocolIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgeBearersSubjectToStatusTransferItemIEValueProtocolIEContainerListValueCodecFieldCompare(v *BearersSubjectToStatusTransferItemIEValueProtocolIEContainerListValueCodec) *func(BearersSubjectToStatusTransferItemIEValueProtocolIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeBearersSubjectToStatusTransferItemIEValueProtocolIEContainerListValueCodecFieldContext(v *BearersSubjectToStatusTransferItemIEValueProtocolIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeBearersSubjectToStatusTransferItemIEValueProtocolIEContainerListValueCodecFieldDecode(v *BearersSubjectToStatusTransferItemIEValueProtocolIEContainerListValueCodec) *func([]byte, aper.DecodeState) (BearersSubjectToStatusTransferItemIEValueProtocolIEContainerList, error) {
	return &v.decode
}
func BridgeBearersSubjectToStatusTransferItemIEValueProtocolIEContainerListValueCodecFieldEncode(v *BearersSubjectToStatusTransferItemIEValueProtocolIEContainerListValueCodec) *func(BearersSubjectToStatusTransferItemIEValueProtocolIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeBearersSubjectToStatusTransferItemIEValueProtocolIEContainerListValueCodecFieldPath(v *BearersSubjectToStatusTransferItemIEValueProtocolIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgeBearersSubjectToStatusTransferItemIEValueProtocolIEContainerListValueCodecMethodEncodeBudgetValue(v BearersSubjectToStatusTransferItemIEValueProtocolIEContainerListValueCodec, a0 BearersSubjectToStatusTransferItemIEValueProtocolIEContainerList, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeBearersSubjectToStatusTransferItemIEValueProtocolIEContainerListValueCodecMethodEncodeChanged(v BearersSubjectToStatusTransferItemIEValueProtocolIEContainerListValueCodec, a0 BearersSubjectToStatusTransferItemIEValueProtocolIEContainerList, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeBearersSubjectToStatusTransferItemMethodMarshalAPERBudget(v *BearersSubjectToStatusTransferItem, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeBearersSubjectToStatusTransferItemMethodMarshalAPERBudgetValue(v *BearersSubjectToStatusTransferItem, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudgetValue(a0, a1)
}
func BridgeBearersSubjectToStatusTransferItemMethodMarshalAPERChanged(v *BearersSubjectToStatusTransferItem, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeBearersSubjectToStatusTransferItemMethodMarshalAPERChangedValue(v *BearersSubjectToStatusTransferItem, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeBearersSubjectToStatusTransferItemMethodMarshalAPERLegacy(v *BearersSubjectToStatusTransferItem) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeBearersSubjectToStatusTransferItemMethodMarshalAPERNewValue(v *BearersSubjectToStatusTransferItem, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERNewValue(a0, a1)
}
func BridgeBearersSubjectToStatusTransferItemMethodMarshalAPERPlanned(v *BearersSubjectToStatusTransferItem, a0 *aper.DecodeBudget, a1 bool, a2 *aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1, a2)
}
func BridgeBearersSubjectToStatusTransferItemMethodMarshalAPERTo(v *BearersSubjectToStatusTransferItem, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeBearersSubjectToStatusTransferItemMethodUnmarshalAPERFrom(v *BearersSubjectToStatusTransferItem, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeBearersSubjectToStatusTransferItemMethodUnmarshalAPERLegacy(v *BearersSubjectToStatusTransferItem, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeBearersSubjectToStatusTransferItemMethodUnmarshalAPERWithOptions(v *BearersSubjectToStatusTransferItem, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeBearersSubjectToStatusTransferItemValueCodecFieldCapture(v *BearersSubjectToStatusTransferItemValueCodec) *func(BearersSubjectToStatusTransferItem, aper.DecodeState) (BearersSubjectToStatusTransferItem, aper.Snapshot) {
	return &v.capture
}
func BridgeBearersSubjectToStatusTransferItemValueCodecFieldCompare(v *BearersSubjectToStatusTransferItemValueCodec) *func(BearersSubjectToStatusTransferItem, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeBearersSubjectToStatusTransferItemValueCodecFieldContext(v *BearersSubjectToStatusTransferItemValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeBearersSubjectToStatusTransferItemValueCodecFieldDecode(v *BearersSubjectToStatusTransferItemValueCodec) *func([]byte, aper.DecodeState) (BearersSubjectToStatusTransferItem, error) {
	return &v.decode
}
func BridgeBearersSubjectToStatusTransferItemValueCodecFieldEncode(v *BearersSubjectToStatusTransferItemValueCodec) *func(BearersSubjectToStatusTransferItem, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeBearersSubjectToStatusTransferItemValueCodecFieldPath(v *BearersSubjectToStatusTransferItemValueCodec) *aper.Path {
	return &v.path
}
func BridgeBearersSubjectToStatusTransferItemValueCodecMethodEncodeBudgetValue(v BearersSubjectToStatusTransferItemValueCodec, a0 BearersSubjectToStatusTransferItem, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeBearersSubjectToStatusTransferItemValueCodecMethodEncodeChanged(v BearersSubjectToStatusTransferItemValueCodec, a0 BearersSubjectToStatusTransferItem, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeBearersSubjectToStatusTransferListAPERValueFieldContext(v *BearersSubjectToStatusTransferListAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeBearersSubjectToStatusTransferListAPERValueFieldReceived(v *BearersSubjectToStatusTransferListAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeBearersSubjectToStatusTransferListAPERValueFieldReplay(v *BearersSubjectToStatusTransferListAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeBearersSubjectToStatusTransferListAPERValueFieldWithoutReplay(v *BearersSubjectToStatusTransferListAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeBearersSubjectToStatusTransferListValueCodecFieldCapture(v *BearersSubjectToStatusTransferListValueCodec) *func(BearersSubjectToStatusTransferList, aper.DecodeState) (BearersSubjectToStatusTransferList, aper.Snapshot) {
	return &v.capture
}
func BridgeBearersSubjectToStatusTransferListValueCodecFieldCompare(v *BearersSubjectToStatusTransferListValueCodec) *func(BearersSubjectToStatusTransferList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeBearersSubjectToStatusTransferListValueCodecFieldContext(v *BearersSubjectToStatusTransferListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeBearersSubjectToStatusTransferListValueCodecFieldDecode(v *BearersSubjectToStatusTransferListValueCodec) *func([]byte, aper.DecodeState) (BearersSubjectToStatusTransferList, error) {
	return &v.decode
}
func BridgeBearersSubjectToStatusTransferListValueCodecFieldEncode(v *BearersSubjectToStatusTransferListValueCodec) *func(BearersSubjectToStatusTransferList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeBearersSubjectToStatusTransferListValueCodecFieldPath(v *BearersSubjectToStatusTransferListValueCodec) *aper.Path {
	return &v.path
}
func BridgeBearersSubjectToStatusTransferListValueCodecMethodEncodeBudgetValue(v BearersSubjectToStatusTransferListValueCodec, a0 BearersSubjectToStatusTransferList, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeBearersSubjectToStatusTransferListValueCodecMethodEncodeChanged(v BearersSubjectToStatusTransferListValueCodec, a0 BearersSubjectToStatusTransferList, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeCellActivationResponseAPERValueFieldContext(v *CellActivationResponseAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeCellActivationResponseAPERValueFieldReceived(v *CellActivationResponseAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeCellActivationResponseAPERValueFieldReplay(v *CellActivationResponseAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeCellActivationResponseAPERValueFieldWithoutReplay(v *CellActivationResponseAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeCellActivationResponseFieldActivatedCellsListIndef(v *CellActivationResponse) *bool {
	return &v.activatedCellsListIndef
}
func BridgeCellActivationResponseFieldExtCount(v *CellActivationResponse) *int64   { return &v.extCount }
func BridgeCellActivationResponseFieldExtData(v *CellActivationResponse) *[][]byte { return &v.extData }
func BridgeCellActivationResponseFieldExtOrigin(v *CellActivationResponse) *[]aper.OpaqueOrigin {
	return &v.extOrigin
}
func BridgeCellActivationResponseFieldExtPresent(v *CellActivationResponse) *[]bool {
	return &v.extPresent
}
func BridgeCellActivationResponseFieldExtWire(v *CellActivationResponse) *[]aper.WireSpan {
	return &v.extWire
}
func BridgeCellActivationResponseFieldPerExtPadding(v *CellActivationResponse) *[]aper.CompletePadding {
	return &v.perExtPadding
}
func BridgeCellActivationResponseFieldPerPadding(v *CellActivationResponse) *aper.FinalPadding {
	return &v.perPadding
}
func BridgeCellActivationResponseFieldReceived(v *CellActivationResponse) *bool { return &v.received }
func BridgeCellActivationResponseFieldReceivedAbsolute(v *CellActivationResponse) *bool {
	return &v.receivedAbsolute
}
func BridgeCellActivationResponseFieldReceivedBytes(v *CellActivationResponse) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeCellActivationResponseFieldReceivedLocation(v *CellActivationResponse) *aper.Location {
	return &v.receivedLocation
}
func BridgeCellActivationResponseFieldReplay(v *CellActivationResponse) *aper.Snapshot {
	return &v.replay
}
func BridgeCellActivationResponseFieldStream(v *CellActivationResponse) *aper.WireSpan {
	return &v.stream
}
func BridgeCellActivationResponseFieldWithoutReplay(v *CellActivationResponse) *bool {
	return &v.withoutReplay
}
func BridgeCellActivationResponseMethodMarshalAPERBudget(v *CellActivationResponse, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeCellActivationResponseMethodMarshalAPERBudgetValue(v *CellActivationResponse, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudgetValue(a0, a1)
}
func BridgeCellActivationResponseMethodMarshalAPERChanged(v *CellActivationResponse, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeCellActivationResponseMethodMarshalAPERChangedValue(v *CellActivationResponse, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeCellActivationResponseMethodMarshalAPERLegacy(v *CellActivationResponse) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeCellActivationResponseMethodMarshalAPERNewValue(v *CellActivationResponse, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERNewValue(a0, a1)
}
func BridgeCellActivationResponseMethodMarshalAPERPlanned(v *CellActivationResponse, a0 *aper.DecodeBudget, a1 bool, a2 *aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1, a2)
}
func BridgeCellActivationResponseMethodMarshalAPERTo(v *CellActivationResponse, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeCellActivationResponseMethodUnmarshalAPERFrom(v *CellActivationResponse, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeCellActivationResponseMethodUnmarshalAPERLegacy(v *CellActivationResponse, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeCellActivationResponseMethodUnmarshalAPERWithOptions(v *CellActivationResponse, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeCellActivationResponseValueCodecFieldCapture(v *CellActivationResponseValueCodec) *func(CellActivationResponse, aper.DecodeState) (CellActivationResponse, aper.Snapshot) {
	return &v.capture
}
func BridgeCellActivationResponseValueCodecFieldCompare(v *CellActivationResponseValueCodec) *func(CellActivationResponse, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeCellActivationResponseValueCodecFieldContext(v *CellActivationResponseValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeCellActivationResponseValueCodecFieldDecode(v *CellActivationResponseValueCodec) *func([]byte, aper.DecodeState) (CellActivationResponse, error) {
	return &v.decode
}
func BridgeCellActivationResponseValueCodecFieldEncode(v *CellActivationResponseValueCodec) *func(CellActivationResponse, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeCellActivationResponseValueCodecFieldPath(v *CellActivationResponseValueCodec) *aper.Path {
	return &v.path
}
func BridgeCellActivationResponseValueCodecMethodEncodeBudgetValue(v CellActivationResponseValueCodec, a0 CellActivationResponse, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeCellActivationResponseValueCodecMethodEncodeChanged(v CellActivationResponseValueCodec, a0 CellActivationResponse, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeCellTrafficTraceAPERValueFieldContext(v *CellTrafficTraceAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeCellTrafficTraceAPERValueFieldReceived(v *CellTrafficTraceAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeCellTrafficTraceAPERValueFieldReplay(v *CellTrafficTraceAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeCellTrafficTraceAPERValueFieldWithoutReplay(v *CellTrafficTraceAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeCellTrafficTraceFieldExtCount(v *CellTrafficTrace) *int64   { return &v.extCount }
func BridgeCellTrafficTraceFieldExtData(v *CellTrafficTrace) *[][]byte { return &v.extData }
func BridgeCellTrafficTraceFieldExtOrigin(v *CellTrafficTrace) *[]aper.OpaqueOrigin {
	return &v.extOrigin
}
func BridgeCellTrafficTraceFieldExtPresent(v *CellTrafficTrace) *[]bool       { return &v.extPresent }
func BridgeCellTrafficTraceFieldExtWire(v *CellTrafficTrace) *[]aper.WireSpan { return &v.extWire }
func BridgeCellTrafficTraceFieldPerExtPadding(v *CellTrafficTrace) *[]aper.CompletePadding {
	return &v.perExtPadding
}
func BridgeCellTrafficTraceFieldPerPadding(v *CellTrafficTrace) *aper.FinalPadding {
	return &v.perPadding
}
func BridgeCellTrafficTraceFieldProtocolIEsIndef(v *CellTrafficTrace) *bool {
	return &v.protocolIEsIndef
}
func BridgeCellTrafficTraceFieldReceived(v *CellTrafficTrace) *bool { return &v.received }
func BridgeCellTrafficTraceFieldReceivedAbsolute(v *CellTrafficTrace) *bool {
	return &v.receivedAbsolute
}
func BridgeCellTrafficTraceFieldReceivedBytes(v *CellTrafficTrace) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeCellTrafficTraceFieldReceivedLocation(v *CellTrafficTrace) *aper.Location {
	return &v.receivedLocation
}
func BridgeCellTrafficTraceFieldReplay(v *CellTrafficTrace) *aper.Snapshot { return &v.replay }
func BridgeCellTrafficTraceFieldStream(v *CellTrafficTrace) *aper.WireSpan { return &v.stream }
func BridgeCellTrafficTraceFieldWithoutReplay(v *CellTrafficTrace) *bool   { return &v.withoutReplay }
func BridgeCellTrafficTraceMethodMarshalAPERBudget(v *CellTrafficTrace, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeCellTrafficTraceMethodMarshalAPERBudgetValue(v *CellTrafficTrace, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudgetValue(a0, a1)
}
func BridgeCellTrafficTraceMethodMarshalAPERChanged(v *CellTrafficTrace, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeCellTrafficTraceMethodMarshalAPERChangedValue(v *CellTrafficTrace, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeCellTrafficTraceMethodMarshalAPERLegacy(v *CellTrafficTrace) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeCellTrafficTraceMethodMarshalAPERNewValue(v *CellTrafficTrace, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERNewValue(a0, a1)
}
func BridgeCellTrafficTraceMethodMarshalAPERPlanned(v *CellTrafficTrace, a0 *aper.DecodeBudget, a1 bool, a2 *aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1, a2)
}
func BridgeCellTrafficTraceMethodMarshalAPERTo(v *CellTrafficTrace, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeCellTrafficTraceMethodUnmarshalAPERFrom(v *CellTrafficTrace, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeCellTrafficTraceMethodUnmarshalAPERLegacy(v *CellTrafficTrace, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeCellTrafficTraceMethodUnmarshalAPERWithOptions(v *CellTrafficTrace, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeCellTrafficTraceValueCodecFieldCapture(v *CellTrafficTraceValueCodec) *func(CellTrafficTrace, aper.DecodeState) (CellTrafficTrace, aper.Snapshot) {
	return &v.capture
}
func BridgeCellTrafficTraceValueCodecFieldCompare(v *CellTrafficTraceValueCodec) *func(CellTrafficTrace, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeCellTrafficTraceValueCodecFieldContext(v *CellTrafficTraceValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeCellTrafficTraceValueCodecFieldDecode(v *CellTrafficTraceValueCodec) *func([]byte, aper.DecodeState) (CellTrafficTrace, error) {
	return &v.decode
}
func BridgeCellTrafficTraceValueCodecFieldEncode(v *CellTrafficTraceValueCodec) *func(CellTrafficTrace, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeCellTrafficTraceValueCodecFieldPath(v *CellTrafficTraceValueCodec) *aper.Path {
	return &v.path
}
func BridgeCellTrafficTraceValueCodecMethodEncodeBudgetValue(v CellTrafficTraceValueCodec, a0 CellTrafficTrace, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeCellTrafficTraceValueCodecMethodEncodeChanged(v CellTrafficTraceValueCodec, a0 CellTrafficTrace, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeENBStatusTransferENBStatusTransferTransparentContainerIEBindingFieldCodec(v *ENBStatusTransferENBStatusTransferTransparentContainerIEBinding) *ENBStatusTransferTransparentContainerValueCodec {
	return &v.codec
}
func BridgeENBStatusTransferENBStatusTransferTransparentContainerIEBindingFieldGet(v *ENBStatusTransferENBStatusTransferTransparentContainerIEBinding) *func(*ENBStatusTransferIEValue) (*ENBStatusTransferTransparentContainer, bool) {
	return &v.get
}
func BridgeENBStatusTransferENBStatusTransferTransparentContainerIEBindingFieldInfo(v *ENBStatusTransferENBStatusTransferTransparentContainerIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeENBStatusTransferENBStatusTransferTransparentContainerIEBindingFieldInject(v *ENBStatusTransferENBStatusTransferTransparentContainerIEBinding) *func(ENBStatusTransferTransparentContainer) ENBStatusTransferIEValue {
	return &v.inject
}
func BridgeENBStatusTransferENBUES1APIDIEBindingFieldCodec(v *ENBStatusTransferENBUES1APIDIEBinding) *s00.ENBUES1APIDValueCodec {
	return &v.codec
}
func BridgeENBStatusTransferENBUES1APIDIEBindingFieldGet(v *ENBStatusTransferENBUES1APIDIEBinding) *func(*ENBStatusTransferIEValue) (*s00.ENBUES1APID, bool) {
	return &v.get
}
func BridgeENBStatusTransferENBUES1APIDIEBindingFieldInfo(v *ENBStatusTransferENBUES1APIDIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeENBStatusTransferENBUES1APIDIEBindingFieldInject(v *ENBStatusTransferENBUES1APIDIEBinding) *func(s00.ENBUES1APID) ENBStatusTransferIEValue {
	return &v.inject
}
func BridgeENBStatusTransferIEContainerAPERValueFieldContext(v *ENBStatusTransferIEContainerAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeENBStatusTransferIEContainerAPERValueFieldReceived(v *ENBStatusTransferIEContainerAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeENBStatusTransferIEContainerAPERValueFieldReplay(v *ENBStatusTransferIEContainerAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeENBStatusTransferIEContainerAPERValueFieldWithoutReplay(v *ENBStatusTransferIEContainerAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeENBStatusTransferIEContainerValueCodecFieldCapture(v *ENBStatusTransferIEContainerValueCodec) *func(ENBStatusTransferIEContainer, aper.DecodeState) (ENBStatusTransferIEContainer, aper.Snapshot) {
	return &v.capture
}
func BridgeENBStatusTransferIEContainerValueCodecFieldCompare(v *ENBStatusTransferIEContainerValueCodec) *func(ENBStatusTransferIEContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeENBStatusTransferIEContainerValueCodecFieldContext(v *ENBStatusTransferIEContainerValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeENBStatusTransferIEContainerValueCodecFieldDecode(v *ENBStatusTransferIEContainerValueCodec) *func([]byte, aper.DecodeState) (ENBStatusTransferIEContainer, error) {
	return &v.decode
}
func BridgeENBStatusTransferIEContainerValueCodecFieldEncode(v *ENBStatusTransferIEContainerValueCodec) *func(ENBStatusTransferIEContainer, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeENBStatusTransferIEContainerValueCodecFieldPath(v *ENBStatusTransferIEContainerValueCodec) *aper.Path {
	return &v.path
}
func BridgeENBStatusTransferIEContainerValueCodecMethodEncodeBudgetValue(v ENBStatusTransferIEContainerValueCodec, a0 ENBStatusTransferIEContainer, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeENBStatusTransferIEContainerValueCodecMethodEncodeChanged(v ENBStatusTransferIEContainerValueCodec, a0 ENBStatusTransferIEContainer, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeENBStatusTransferIEFieldAPERValueFieldContext(v *ENBStatusTransferIEFieldAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeENBStatusTransferIEFieldAPERValueFieldReceived(v *ENBStatusTransferIEFieldAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeENBStatusTransferIEFieldAPERValueFieldReplay(v *ENBStatusTransferIEFieldAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeENBStatusTransferIEFieldAPERValueFieldWithoutReplay(v *ENBStatusTransferIEFieldAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeENBStatusTransferIEFieldFieldReceived(v *ENBStatusTransferIEField) *aper.CompletePadding {
	return &v.received
}
func BridgeENBStatusTransferIEFieldFieldReplay(v *ENBStatusTransferIEField) *aper.Snapshot {
	return &v.replay
}
func BridgeENBStatusTransferIEFieldFieldStream(v *ENBStatusTransferIEField) *aper.WireSpan {
	return &v.stream
}
func BridgeENBStatusTransferIEFieldFieldWithoutReplay(v *ENBStatusTransferIEField) *bool {
	return &v.withoutReplay
}
func BridgeENBStatusTransferIEFieldMethodMarshalAPERTo(v *ENBStatusTransferIEField, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeENBStatusTransferIEFieldMethodUnmarshalAPERFrom(v *ENBStatusTransferIEField, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeENBStatusTransferIEFieldValueCodecFieldCapture(v *ENBStatusTransferIEFieldValueCodec) *func(ENBStatusTransferIEField, aper.DecodeState) (ENBStatusTransferIEField, aper.Snapshot) {
	return &v.capture
}
func BridgeENBStatusTransferIEFieldValueCodecFieldCompare(v *ENBStatusTransferIEFieldValueCodec) *func(ENBStatusTransferIEField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeENBStatusTransferIEFieldValueCodecFieldContext(v *ENBStatusTransferIEFieldValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeENBStatusTransferIEFieldValueCodecFieldDecode(v *ENBStatusTransferIEFieldValueCodec) *func([]byte, aper.DecodeState) (ENBStatusTransferIEField, error) {
	return &v.decode
}
func BridgeENBStatusTransferIEFieldValueCodecFieldEncode(v *ENBStatusTransferIEFieldValueCodec) *func(ENBStatusTransferIEField, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeENBStatusTransferIEFieldValueCodecFieldPath(v *ENBStatusTransferIEFieldValueCodec) *aper.Path {
	return &v.path
}
func BridgeENBStatusTransferIEFieldValueCodecMethodEncodeBudgetValue(v ENBStatusTransferIEFieldValueCodec, a0 ENBStatusTransferIEField, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeENBStatusTransferIEFieldValueCodecMethodEncodeChanged(v ENBStatusTransferIEFieldValueCodec, a0 ENBStatusTransferIEField, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeENBStatusTransferIETableMethodInfoENBStatusTransferTransparentContainer(v ENBStatusTransferIETable) s00.FieldInfo {
	return v.infoENBStatusTransferTransparentContainer()
}
func BridgeENBStatusTransferIETableMethodInfoENBUES1APID(v ENBStatusTransferIETable) s00.FieldInfo {
	return v.infoENBUES1APID()
}
func BridgeENBStatusTransferIETableMethodInfoMMEUES1APID(v ENBStatusTransferIETable) s00.FieldInfo {
	return v.infoMMEUES1APID()
}
func BridgeENBStatusTransferIEValueERABIEContainerListAPERValueFieldContext(v *ENBStatusTransferIEValueERABIEContainerListAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeENBStatusTransferIEValueERABIEContainerListAPERValueFieldReceived(v *ENBStatusTransferIEValueERABIEContainerListAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeENBStatusTransferIEValueERABIEContainerListAPERValueFieldReplay(v *ENBStatusTransferIEValueERABIEContainerListAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeENBStatusTransferIEValueERABIEContainerListAPERValueFieldWithoutReplay(v *ENBStatusTransferIEValueERABIEContainerListAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeENBStatusTransferIEValueERABIEContainerListValueCodecFieldCapture(v *ENBStatusTransferIEValueERABIEContainerListValueCodec) *func(ENBStatusTransferIEValueERABIEContainerList, aper.DecodeState) (ENBStatusTransferIEValueERABIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgeENBStatusTransferIEValueERABIEContainerListValueCodecFieldCompare(v *ENBStatusTransferIEValueERABIEContainerListValueCodec) *func(ENBStatusTransferIEValueERABIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeENBStatusTransferIEValueERABIEContainerListValueCodecFieldContext(v *ENBStatusTransferIEValueERABIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeENBStatusTransferIEValueERABIEContainerListValueCodecFieldDecode(v *ENBStatusTransferIEValueERABIEContainerListValueCodec) *func([]byte, aper.DecodeState) (ENBStatusTransferIEValueERABIEContainerList, error) {
	return &v.decode
}
func BridgeENBStatusTransferIEValueERABIEContainerListValueCodecFieldEncode(v *ENBStatusTransferIEValueERABIEContainerListValueCodec) *func(ENBStatusTransferIEValueERABIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeENBStatusTransferIEValueERABIEContainerListValueCodecFieldPath(v *ENBStatusTransferIEValueERABIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgeENBStatusTransferIEValueERABIEContainerListValueCodecMethodEncodeBudgetValue(v ENBStatusTransferIEValueERABIEContainerListValueCodec, a0 ENBStatusTransferIEValueERABIEContainerList, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeENBStatusTransferIEValueERABIEContainerListValueCodecMethodEncodeChanged(v ENBStatusTransferIEValueERABIEContainerListValueCodec, a0 ENBStatusTransferIEValueERABIEContainerList, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeENBStatusTransferIEValueFieldId(v *ENBStatusTransferIEValue) *s00.ProtocolIEID {
	return &v.id
}
func BridgeENBStatusTransferIEValueFieldIsOpaque(v *ENBStatusTransferIEValue) *bool {
	return &v.isOpaque
}
func BridgeENBStatusTransferIEValueFieldOpaque(v *ENBStatusTransferIEValue) *aper.OpaqueOpenType {
	return &v.opaque
}
func BridgeENBStatusTransferIEValueFieldReceived(v *ENBStatusTransferIEValue) *aper.WireSpan {
	return &v.received
}
func BridgeENBStatusTransferIEValueFieldReplay(v *ENBStatusTransferIEValue) *aper.Snapshot {
	return &v.replay
}
func BridgeENBStatusTransferIEValueFieldRowENBStatusTransferTransparentContainer(v *ENBStatusTransferIEValue) **ENBStatusTransferTransparentContainer {
	return &v.rowENBStatusTransferTransparentContainer
}
func BridgeENBStatusTransferIEValueFieldRowENBUES1APID(v *ENBStatusTransferIEValue) **s00.ENBUES1APID {
	return &v.rowENBUES1APID
}
func BridgeENBStatusTransferIEValueFieldRowMMEUES1APID(v *ENBStatusTransferIEValue) **s00.MMEUES1APID {
	return &v.rowMMEUES1APID
}
func BridgeENBStatusTransferIEValueMethodCaptureSemantics(v ENBStatusTransferIEValue, a0 aper.SemanticCapture) ENBStatusTransferIEValue {
	return v.captureSemantics(a0)
}
func BridgeENBStatusTransferIEValueMethodCompareSemantics(v ENBStatusTransferIEValue, a0 aper.SemanticComparison) aper.SemanticComparison {
	return v.compareSemantics(a0)
}
func BridgeENBStatusTransferIEValueMethodDecode(v ENBStatusTransferIEValue, a0 s00.ProtocolIEID, a1 aper.OpaqueOpenType) (ENBStatusTransferIEValue, error) {
	return v.decode(a0, a1)
}
func BridgeENBStatusTransferIEValueMethodEncode(v ENBStatusTransferIEValue) ([]byte, error) {
	return v.encode()
}
func BridgeENBStatusTransferIEValueMethodEncodeFresh(v ENBStatusTransferIEValue, a0 bool, a1 *aper.DecodeBudget) ([]byte, error) {
	return v.encodeFresh(a0, a1)
}
func BridgeENBStatusTransferIEValueMethodMatchesID(v ENBStatusTransferIEValue, a0 s00.ProtocolIEID, a1 ...*aper.DecodeBudget) bool {
	return v.matchesID(a0, a1...)
}
func BridgeENBStatusTransferIEValueMethodReason(v ENBStatusTransferIEValue, a0 s00.ProtocolIEID) aper.OpaqueReason {
	return v.reason(a0)
}
func BridgeENBStatusTransferIEValueMethodRule(v ENBStatusTransferIEValue) aper.SourceRule {
	return v.rule()
}
func BridgeENBStatusTransferIEValueProtocolErrorIEContainerListAPERValueFieldContext(v *ENBStatusTransferIEValueProtocolErrorIEContainerListAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeENBStatusTransferIEValueProtocolErrorIEContainerListAPERValueFieldReceived(v *ENBStatusTransferIEValueProtocolErrorIEContainerListAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeENBStatusTransferIEValueProtocolErrorIEContainerListAPERValueFieldReplay(v *ENBStatusTransferIEValueProtocolErrorIEContainerListAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeENBStatusTransferIEValueProtocolErrorIEContainerListAPERValueFieldWithoutReplay(v *ENBStatusTransferIEValueProtocolErrorIEContainerListAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeENBStatusTransferIEValueProtocolErrorIEContainerListValueCodecFieldCapture(v *ENBStatusTransferIEValueProtocolErrorIEContainerListValueCodec) *func(ENBStatusTransferIEValueProtocolErrorIEContainerList, aper.DecodeState) (ENBStatusTransferIEValueProtocolErrorIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgeENBStatusTransferIEValueProtocolErrorIEContainerListValueCodecFieldCompare(v *ENBStatusTransferIEValueProtocolErrorIEContainerListValueCodec) *func(ENBStatusTransferIEValueProtocolErrorIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeENBStatusTransferIEValueProtocolErrorIEContainerListValueCodecFieldContext(v *ENBStatusTransferIEValueProtocolErrorIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeENBStatusTransferIEValueProtocolErrorIEContainerListValueCodecFieldDecode(v *ENBStatusTransferIEValueProtocolErrorIEContainerListValueCodec) *func([]byte, aper.DecodeState) (ENBStatusTransferIEValueProtocolErrorIEContainerList, error) {
	return &v.decode
}
func BridgeENBStatusTransferIEValueProtocolErrorIEContainerListValueCodecFieldEncode(v *ENBStatusTransferIEValueProtocolErrorIEContainerListValueCodec) *func(ENBStatusTransferIEValueProtocolErrorIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeENBStatusTransferIEValueProtocolErrorIEContainerListValueCodecFieldPath(v *ENBStatusTransferIEValueProtocolErrorIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgeENBStatusTransferIEValueProtocolErrorIEContainerListValueCodecMethodEncodeBudgetValue(v ENBStatusTransferIEValueProtocolErrorIEContainerListValueCodec, a0 ENBStatusTransferIEValueProtocolErrorIEContainerList, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeENBStatusTransferIEValueProtocolErrorIEContainerListValueCodecMethodEncodeChanged(v ENBStatusTransferIEValueProtocolErrorIEContainerListValueCodec, a0 ENBStatusTransferIEValueProtocolErrorIEContainerList, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeENBStatusTransferIEValueProtocolIEContainerListAPERValueFieldContext(v *ENBStatusTransferIEValueProtocolIEContainerListAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeENBStatusTransferIEValueProtocolIEContainerListAPERValueFieldReceived(v *ENBStatusTransferIEValueProtocolIEContainerListAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeENBStatusTransferIEValueProtocolIEContainerListAPERValueFieldReplay(v *ENBStatusTransferIEValueProtocolIEContainerListAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeENBStatusTransferIEValueProtocolIEContainerListAPERValueFieldWithoutReplay(v *ENBStatusTransferIEValueProtocolIEContainerListAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeENBStatusTransferIEValueProtocolIEContainerListValueCodecFieldCapture(v *ENBStatusTransferIEValueProtocolIEContainerListValueCodec) *func(ENBStatusTransferIEValueProtocolIEContainerList, aper.DecodeState) (ENBStatusTransferIEValueProtocolIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgeENBStatusTransferIEValueProtocolIEContainerListValueCodecFieldCompare(v *ENBStatusTransferIEValueProtocolIEContainerListValueCodec) *func(ENBStatusTransferIEValueProtocolIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeENBStatusTransferIEValueProtocolIEContainerListValueCodecFieldContext(v *ENBStatusTransferIEValueProtocolIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeENBStatusTransferIEValueProtocolIEContainerListValueCodecFieldDecode(v *ENBStatusTransferIEValueProtocolIEContainerListValueCodec) *func([]byte, aper.DecodeState) (ENBStatusTransferIEValueProtocolIEContainerList, error) {
	return &v.decode
}
func BridgeENBStatusTransferIEValueProtocolIEContainerListValueCodecFieldEncode(v *ENBStatusTransferIEValueProtocolIEContainerListValueCodec) *func(ENBStatusTransferIEValueProtocolIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeENBStatusTransferIEValueProtocolIEContainerListValueCodecFieldPath(v *ENBStatusTransferIEValueProtocolIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgeENBStatusTransferIEValueProtocolIEContainerListValueCodecMethodEncodeBudgetValue(v ENBStatusTransferIEValueProtocolIEContainerListValueCodec, a0 ENBStatusTransferIEValueProtocolIEContainerList, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeENBStatusTransferIEValueProtocolIEContainerListValueCodecMethodEncodeChanged(v ENBStatusTransferIEValueProtocolIEContainerListValueCodec, a0 ENBStatusTransferIEValueProtocolIEContainerList, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeENBStatusTransferMMEUES1APIDIEBindingFieldCodec(v *ENBStatusTransferMMEUES1APIDIEBinding) *s01.MMEUES1APIDValueCodec {
	return &v.codec
}
func BridgeENBStatusTransferMMEUES1APIDIEBindingFieldGet(v *ENBStatusTransferMMEUES1APIDIEBinding) *func(*ENBStatusTransferIEValue) (*s00.MMEUES1APID, bool) {
	return &v.get
}
func BridgeENBStatusTransferMMEUES1APIDIEBindingFieldInfo(v *ENBStatusTransferMMEUES1APIDIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeENBStatusTransferMMEUES1APIDIEBindingFieldInject(v *ENBStatusTransferMMEUES1APIDIEBinding) *func(s00.MMEUES1APID) ENBStatusTransferIEValue {
	return &v.inject
}
func BridgeENBStatusTransferTransparentContainerAPERValueFieldContext(v *ENBStatusTransferTransparentContainerAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeENBStatusTransferTransparentContainerAPERValueFieldReceived(v *ENBStatusTransferTransparentContainerAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeENBStatusTransferTransparentContainerAPERValueFieldReplay(v *ENBStatusTransferTransparentContainerAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeENBStatusTransferTransparentContainerAPERValueFieldWithoutReplay(v *ENBStatusTransferTransparentContainerAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeENBStatusTransferTransparentContainerFieldBearersSubjectToStatusTransferListIndef(v *ENBStatusTransferTransparentContainer) *bool {
	return &v.bearersSubjectToStatusTransferListIndef
}
func BridgeENBStatusTransferTransparentContainerFieldExtCount(v *ENBStatusTransferTransparentContainer) *int64 {
	return &v.extCount
}
func BridgeENBStatusTransferTransparentContainerFieldExtData(v *ENBStatusTransferTransparentContainer) *[][]byte {
	return &v.extData
}
func BridgeENBStatusTransferTransparentContainerFieldExtOrigin(v *ENBStatusTransferTransparentContainer) *[]aper.OpaqueOrigin {
	return &v.extOrigin
}
func BridgeENBStatusTransferTransparentContainerFieldExtPresent(v *ENBStatusTransferTransparentContainer) *[]bool {
	return &v.extPresent
}
func BridgeENBStatusTransferTransparentContainerFieldExtWire(v *ENBStatusTransferTransparentContainer) *[]aper.WireSpan {
	return &v.extWire
}
func BridgeENBStatusTransferTransparentContainerFieldIEExtensionsIndef(v *ENBStatusTransferTransparentContainer) *bool {
	return &v.iEExtensionsIndef
}
func BridgeENBStatusTransferTransparentContainerFieldPerExtPadding(v *ENBStatusTransferTransparentContainer) *[]aper.CompletePadding {
	return &v.perExtPadding
}
func BridgeENBStatusTransferTransparentContainerFieldPerPadding(v *ENBStatusTransferTransparentContainer) *aper.FinalPadding {
	return &v.perPadding
}
func BridgeENBStatusTransferTransparentContainerFieldReceived(v *ENBStatusTransferTransparentContainer) *bool {
	return &v.received
}
func BridgeENBStatusTransferTransparentContainerFieldReceivedAbsolute(v *ENBStatusTransferTransparentContainer) *bool {
	return &v.receivedAbsolute
}
func BridgeENBStatusTransferTransparentContainerFieldReceivedBytes(v *ENBStatusTransferTransparentContainer) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeENBStatusTransferTransparentContainerFieldReceivedLocation(v *ENBStatusTransferTransparentContainer) *aper.Location {
	return &v.receivedLocation
}
func BridgeENBStatusTransferTransparentContainerFieldReplay(v *ENBStatusTransferTransparentContainer) *aper.Snapshot {
	return &v.replay
}
func BridgeENBStatusTransferTransparentContainerFieldStream(v *ENBStatusTransferTransparentContainer) *aper.WireSpan {
	return &v.stream
}
func BridgeENBStatusTransferTransparentContainerFieldWithoutReplay(v *ENBStatusTransferTransparentContainer) *bool {
	return &v.withoutReplay
}
func BridgeENBStatusTransferTransparentContainerMethodMarshalAPERBudget(v *ENBStatusTransferTransparentContainer, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeENBStatusTransferTransparentContainerMethodMarshalAPERBudgetValue(v *ENBStatusTransferTransparentContainer, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudgetValue(a0, a1)
}
func BridgeENBStatusTransferTransparentContainerMethodMarshalAPERChanged(v *ENBStatusTransferTransparentContainer, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeENBStatusTransferTransparentContainerMethodMarshalAPERChangedValue(v *ENBStatusTransferTransparentContainer, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeENBStatusTransferTransparentContainerMethodMarshalAPERLegacy(v *ENBStatusTransferTransparentContainer) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeENBStatusTransferTransparentContainerMethodMarshalAPERNewValue(v *ENBStatusTransferTransparentContainer, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERNewValue(a0, a1)
}
func BridgeENBStatusTransferTransparentContainerMethodMarshalAPERPlanned(v *ENBStatusTransferTransparentContainer, a0 *aper.DecodeBudget, a1 bool, a2 *aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1, a2)
}
func BridgeENBStatusTransferTransparentContainerMethodMarshalAPERTo(v *ENBStatusTransferTransparentContainer, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeENBStatusTransferTransparentContainerMethodUnmarshalAPERFrom(v *ENBStatusTransferTransparentContainer, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeENBStatusTransferTransparentContainerMethodUnmarshalAPERLegacy(v *ENBStatusTransferTransparentContainer, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeENBStatusTransferTransparentContainerMethodUnmarshalAPERWithOptions(v *ENBStatusTransferTransparentContainer, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeENBStatusTransferTransparentContainerValueCodecFieldCapture(v *ENBStatusTransferTransparentContainerValueCodec) *func(ENBStatusTransferTransparentContainer, aper.DecodeState) (ENBStatusTransferTransparentContainer, aper.Snapshot) {
	return &v.capture
}
func BridgeENBStatusTransferTransparentContainerValueCodecFieldCompare(v *ENBStatusTransferTransparentContainerValueCodec) *func(ENBStatusTransferTransparentContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeENBStatusTransferTransparentContainerValueCodecFieldContext(v *ENBStatusTransferTransparentContainerValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeENBStatusTransferTransparentContainerValueCodecFieldDecode(v *ENBStatusTransferTransparentContainerValueCodec) *func([]byte, aper.DecodeState) (ENBStatusTransferTransparentContainer, error) {
	return &v.decode
}
func BridgeENBStatusTransferTransparentContainerValueCodecFieldEncode(v *ENBStatusTransferTransparentContainerValueCodec) *func(ENBStatusTransferTransparentContainer, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeENBStatusTransferTransparentContainerValueCodecFieldPath(v *ENBStatusTransferTransparentContainerValueCodec) *aper.Path {
	return &v.path
}
func BridgeENBStatusTransferTransparentContainerValueCodecMethodEncodeBudgetValue(v ENBStatusTransferTransparentContainerValueCodec, a0 ENBStatusTransferTransparentContainer, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeENBStatusTransferTransparentContainerValueCodecMethodEncodeChanged(v ENBStatusTransferTransparentContainerValueCodec, a0 ENBStatusTransferTransparentContainer, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeERABToBeModifyItemBearerModReqExtIETableMethodInfoTransportInformation(v ERABToBeModifyItemBearerModReqExtIETable) s00.ExtensionInfo {
	return v.infoTransportInformation()
}
func BridgeERABToBeModifyItemBearerModReqExtIEsExtContainerAPERValueFieldContext(v *ERABToBeModifyItemBearerModReqExtIEsExtContainerAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABToBeModifyItemBearerModReqExtIEsExtContainerAPERValueFieldReceived(v *ERABToBeModifyItemBearerModReqExtIEsExtContainerAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeERABToBeModifyItemBearerModReqExtIEsExtContainerAPERValueFieldReplay(v *ERABToBeModifyItemBearerModReqExtIEsExtContainerAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeERABToBeModifyItemBearerModReqExtIEsExtContainerAPERValueFieldWithoutReplay(v *ERABToBeModifyItemBearerModReqExtIEsExtContainerAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeERABToBeModifyItemBearerModReqExtIEsExtContainerValueCodecFieldCapture(v *ERABToBeModifyItemBearerModReqExtIEsExtContainerValueCodec) *func(ERABToBeModifyItemBearerModReqExtIEsExtContainer, aper.DecodeState) (ERABToBeModifyItemBearerModReqExtIEsExtContainer, aper.Snapshot) {
	return &v.capture
}
func BridgeERABToBeModifyItemBearerModReqExtIEsExtContainerValueCodecFieldCompare(v *ERABToBeModifyItemBearerModReqExtIEsExtContainerValueCodec) *func(ERABToBeModifyItemBearerModReqExtIEsExtContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeERABToBeModifyItemBearerModReqExtIEsExtContainerValueCodecFieldContext(v *ERABToBeModifyItemBearerModReqExtIEsExtContainerValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABToBeModifyItemBearerModReqExtIEsExtContainerValueCodecFieldDecode(v *ERABToBeModifyItemBearerModReqExtIEsExtContainerValueCodec) *func([]byte, aper.DecodeState) (ERABToBeModifyItemBearerModReqExtIEsExtContainer, error) {
	return &v.decode
}
func BridgeERABToBeModifyItemBearerModReqExtIEsExtContainerValueCodecFieldEncode(v *ERABToBeModifyItemBearerModReqExtIEsExtContainerValueCodec) *func(ERABToBeModifyItemBearerModReqExtIEsExtContainer, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeERABToBeModifyItemBearerModReqExtIEsExtContainerValueCodecFieldPath(v *ERABToBeModifyItemBearerModReqExtIEsExtContainerValueCodec) *aper.Path {
	return &v.path
}
func BridgeERABToBeModifyItemBearerModReqExtIEsExtContainerValueCodecMethodEncodeBudgetValue(v ERABToBeModifyItemBearerModReqExtIEsExtContainerValueCodec, a0 ERABToBeModifyItemBearerModReqExtIEsExtContainer, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeERABToBeModifyItemBearerModReqExtIEsExtContainerValueCodecMethodEncodeChanged(v ERABToBeModifyItemBearerModReqExtIEsExtContainerValueCodec, a0 ERABToBeModifyItemBearerModReqExtIEsExtContainer, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeERABToBeModifyItemBearerModReqExtIEsExtFieldAPERValueFieldContext(v *ERABToBeModifyItemBearerModReqExtIEsExtFieldAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABToBeModifyItemBearerModReqExtIEsExtFieldAPERValueFieldReceived(v *ERABToBeModifyItemBearerModReqExtIEsExtFieldAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeERABToBeModifyItemBearerModReqExtIEsExtFieldAPERValueFieldReplay(v *ERABToBeModifyItemBearerModReqExtIEsExtFieldAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeERABToBeModifyItemBearerModReqExtIEsExtFieldAPERValueFieldWithoutReplay(v *ERABToBeModifyItemBearerModReqExtIEsExtFieldAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeERABToBeModifyItemBearerModReqExtIEsExtFieldFieldReceived(v *ERABToBeModifyItemBearerModReqExtIEsExtField) *aper.CompletePadding {
	return &v.received
}
func BridgeERABToBeModifyItemBearerModReqExtIEsExtFieldFieldReplay(v *ERABToBeModifyItemBearerModReqExtIEsExtField) *aper.Snapshot {
	return &v.replay
}
func BridgeERABToBeModifyItemBearerModReqExtIEsExtFieldFieldStream(v *ERABToBeModifyItemBearerModReqExtIEsExtField) *aper.WireSpan {
	return &v.stream
}
func BridgeERABToBeModifyItemBearerModReqExtIEsExtFieldFieldWithoutReplay(v *ERABToBeModifyItemBearerModReqExtIEsExtField) *bool {
	return &v.withoutReplay
}
func BridgeERABToBeModifyItemBearerModReqExtIEsExtFieldMethodMarshalAPERTo(v *ERABToBeModifyItemBearerModReqExtIEsExtField, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeERABToBeModifyItemBearerModReqExtIEsExtFieldMethodUnmarshalAPERFrom(v *ERABToBeModifyItemBearerModReqExtIEsExtField, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeERABToBeModifyItemBearerModReqExtIEsExtFieldValueCodecFieldCapture(v *ERABToBeModifyItemBearerModReqExtIEsExtFieldValueCodec) *func(ERABToBeModifyItemBearerModReqExtIEsExtField, aper.DecodeState) (ERABToBeModifyItemBearerModReqExtIEsExtField, aper.Snapshot) {
	return &v.capture
}
func BridgeERABToBeModifyItemBearerModReqExtIEsExtFieldValueCodecFieldCompare(v *ERABToBeModifyItemBearerModReqExtIEsExtFieldValueCodec) *func(ERABToBeModifyItemBearerModReqExtIEsExtField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeERABToBeModifyItemBearerModReqExtIEsExtFieldValueCodecFieldContext(v *ERABToBeModifyItemBearerModReqExtIEsExtFieldValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABToBeModifyItemBearerModReqExtIEsExtFieldValueCodecFieldDecode(v *ERABToBeModifyItemBearerModReqExtIEsExtFieldValueCodec) *func([]byte, aper.DecodeState) (ERABToBeModifyItemBearerModReqExtIEsExtField, error) {
	return &v.decode
}
func BridgeERABToBeModifyItemBearerModReqExtIEsExtFieldValueCodecFieldEncode(v *ERABToBeModifyItemBearerModReqExtIEsExtFieldValueCodec) *func(ERABToBeModifyItemBearerModReqExtIEsExtField, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeERABToBeModifyItemBearerModReqExtIEsExtFieldValueCodecFieldPath(v *ERABToBeModifyItemBearerModReqExtIEsExtFieldValueCodec) *aper.Path {
	return &v.path
}
func BridgeERABToBeModifyItemBearerModReqExtIEsExtFieldValueCodecMethodEncodeBudgetValue(v ERABToBeModifyItemBearerModReqExtIEsExtFieldValueCodec, a0 ERABToBeModifyItemBearerModReqExtIEsExtField, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeERABToBeModifyItemBearerModReqExtIEsExtFieldValueCodecMethodEncodeChanged(v ERABToBeModifyItemBearerModReqExtIEsExtFieldValueCodec, a0 ERABToBeModifyItemBearerModReqExtIEsExtField, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeERABToBeModifyItemBearerModReqExtIEsIEFieldFieldReceived(v *ERABToBeModifyItemBearerModReqExtIEsIEField) *aper.CompletePadding {
	return &v.received
}
func BridgeERABToBeModifyItemBearerModReqExtIEsIEFieldFieldReplay(v *ERABToBeModifyItemBearerModReqExtIEsIEField) *aper.Snapshot {
	return &v.replay
}
func BridgeERABToBeModifyItemBearerModReqExtIEsIEFieldFieldStream(v *ERABToBeModifyItemBearerModReqExtIEsIEField) *aper.WireSpan {
	return &v.stream
}
func BridgeERABToBeModifyItemBearerModReqExtIEsIEFieldFieldWithoutReplay(v *ERABToBeModifyItemBearerModReqExtIEsIEField) *bool {
	return &v.withoutReplay
}
func BridgeERABToBeModifyItemBearerModReqExtIEsIEFieldMethodMarshalAPERTo(v *ERABToBeModifyItemBearerModReqExtIEsIEField, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeERABToBeModifyItemBearerModReqExtIEsIEFieldMethodUnmarshalAPERFrom(v *ERABToBeModifyItemBearerModReqExtIEsIEField, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeERABToBeModifyItemBearerModReqExtIEsTransportInformationExtBindingFieldCodec(v *ERABToBeModifyItemBearerModReqExtIEsTransportInformationExtBinding) *TransportInformationValueCodec {
	return &v.codec
}
func BridgeERABToBeModifyItemBearerModReqExtIEsTransportInformationExtBindingFieldGet(v *ERABToBeModifyItemBearerModReqExtIEsTransportInformationExtBinding) *func(*ERABToBeModifyItemBearerModReqExtIEsValue) (*TransportInformation, bool) {
	return &v.get
}
func BridgeERABToBeModifyItemBearerModReqExtIEsTransportInformationExtBindingFieldInfo(v *ERABToBeModifyItemBearerModReqExtIEsTransportInformationExtBinding) *s00.ExtensionInfo {
	return &v.info
}
func BridgeERABToBeModifyItemBearerModReqExtIEsTransportInformationExtBindingFieldInject(v *ERABToBeModifyItemBearerModReqExtIEsTransportInformationExtBinding) *func(TransportInformation) ERABToBeModifyItemBearerModReqExtIEsValue {
	return &v.inject
}
func BridgeERABToBeModifyItemBearerModReqExtIEsValueFieldId(v *ERABToBeModifyItemBearerModReqExtIEsValue) *s00.ProtocolIEID {
	return &v.id
}
func BridgeERABToBeModifyItemBearerModReqExtIEsValueFieldIsOpaque(v *ERABToBeModifyItemBearerModReqExtIEsValue) *bool {
	return &v.isOpaque
}
func BridgeERABToBeModifyItemBearerModReqExtIEsValueFieldOpaque(v *ERABToBeModifyItemBearerModReqExtIEsValue) *aper.OpaqueOpenType {
	return &v.opaque
}
func BridgeERABToBeModifyItemBearerModReqExtIEsValueFieldReceived(v *ERABToBeModifyItemBearerModReqExtIEsValue) *aper.WireSpan {
	return &v.received
}
func BridgeERABToBeModifyItemBearerModReqExtIEsValueFieldReplay(v *ERABToBeModifyItemBearerModReqExtIEsValue) *aper.Snapshot {
	return &v.replay
}
func BridgeERABToBeModifyItemBearerModReqExtIEsValueFieldRowTransportInformation(v *ERABToBeModifyItemBearerModReqExtIEsValue) **TransportInformation {
	return &v.rowTransportInformation
}
func BridgeERABToBeModifyItemBearerModReqExtIEsValueMethodCaptureSemantics(v ERABToBeModifyItemBearerModReqExtIEsValue, a0 aper.SemanticCapture) ERABToBeModifyItemBearerModReqExtIEsValue {
	return v.captureSemantics(a0)
}
func BridgeERABToBeModifyItemBearerModReqExtIEsValueMethodCompareSemantics(v ERABToBeModifyItemBearerModReqExtIEsValue, a0 aper.SemanticComparison) aper.SemanticComparison {
	return v.compareSemantics(a0)
}
func BridgeERABToBeModifyItemBearerModReqExtIEsValueMethodDecode(v ERABToBeModifyItemBearerModReqExtIEsValue, a0 s00.ProtocolIEID, a1 aper.OpaqueOpenType) (ERABToBeModifyItemBearerModReqExtIEsValue, error) {
	return v.decode(a0, a1)
}
func BridgeERABToBeModifyItemBearerModReqExtIEsValueMethodEncode(v ERABToBeModifyItemBearerModReqExtIEsValue) ([]byte, error) {
	return v.encode()
}
func BridgeERABToBeModifyItemBearerModReqExtIEsValueMethodEncodeFresh(v ERABToBeModifyItemBearerModReqExtIEsValue, a0 bool, a1 *aper.DecodeBudget) ([]byte, error) {
	return v.encodeFresh(a0, a1)
}
func BridgeERABToBeModifyItemBearerModReqExtIEsValueMethodMatchesID(v ERABToBeModifyItemBearerModReqExtIEsValue, a0 s00.ProtocolIEID, a1 ...*aper.DecodeBudget) bool {
	return v.matchesID(a0, a1...)
}
func BridgeERABToBeModifyItemBearerModReqExtIEsValueMethodReason(v ERABToBeModifyItemBearerModReqExtIEsValue, a0 s00.ProtocolIEID) aper.OpaqueReason {
	return v.reason(a0)
}
func BridgeERABToBeModifyItemBearerModReqExtIEsValueMethodRule(v ERABToBeModifyItemBearerModReqExtIEsValue) aper.SourceRule {
	return v.rule()
}
func BridgeMMEStatusTransferENBStatusTransferTransparentContainerIEBindingFieldCodec(v *MMEStatusTransferENBStatusTransferTransparentContainerIEBinding) *ENBStatusTransferTransparentContainerValueCodec {
	return &v.codec
}
func BridgeMMEStatusTransferENBStatusTransferTransparentContainerIEBindingFieldGet(v *MMEStatusTransferENBStatusTransferTransparentContainerIEBinding) *func(*MMEStatusTransferIEValue) (*ENBStatusTransferTransparentContainer, bool) {
	return &v.get
}
func BridgeMMEStatusTransferENBStatusTransferTransparentContainerIEBindingFieldInfo(v *MMEStatusTransferENBStatusTransferTransparentContainerIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeMMEStatusTransferENBStatusTransferTransparentContainerIEBindingFieldInject(v *MMEStatusTransferENBStatusTransferTransparentContainerIEBinding) *func(ENBStatusTransferTransparentContainer) MMEStatusTransferIEValue {
	return &v.inject
}
func BridgeMMEStatusTransferENBUES1APIDIEBindingFieldCodec(v *MMEStatusTransferENBUES1APIDIEBinding) *s00.ENBUES1APIDValueCodec {
	return &v.codec
}
func BridgeMMEStatusTransferENBUES1APIDIEBindingFieldGet(v *MMEStatusTransferENBUES1APIDIEBinding) *func(*MMEStatusTransferIEValue) (*s00.ENBUES1APID, bool) {
	return &v.get
}
func BridgeMMEStatusTransferENBUES1APIDIEBindingFieldInfo(v *MMEStatusTransferENBUES1APIDIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeMMEStatusTransferENBUES1APIDIEBindingFieldInject(v *MMEStatusTransferENBUES1APIDIEBinding) *func(s00.ENBUES1APID) MMEStatusTransferIEValue {
	return &v.inject
}
func BridgeMMEStatusTransferIEContainerAPERValueFieldContext(v *MMEStatusTransferIEContainerAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeMMEStatusTransferIEContainerAPERValueFieldReceived(v *MMEStatusTransferIEContainerAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeMMEStatusTransferIEContainerAPERValueFieldReplay(v *MMEStatusTransferIEContainerAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeMMEStatusTransferIEContainerAPERValueFieldWithoutReplay(v *MMEStatusTransferIEContainerAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeMMEStatusTransferIEContainerValueCodecFieldCapture(v *MMEStatusTransferIEContainerValueCodec) *func(MMEStatusTransferIEContainer, aper.DecodeState) (MMEStatusTransferIEContainer, aper.Snapshot) {
	return &v.capture
}
func BridgeMMEStatusTransferIEContainerValueCodecFieldCompare(v *MMEStatusTransferIEContainerValueCodec) *func(MMEStatusTransferIEContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeMMEStatusTransferIEContainerValueCodecFieldContext(v *MMEStatusTransferIEContainerValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeMMEStatusTransferIEContainerValueCodecFieldDecode(v *MMEStatusTransferIEContainerValueCodec) *func([]byte, aper.DecodeState) (MMEStatusTransferIEContainer, error) {
	return &v.decode
}
func BridgeMMEStatusTransferIEContainerValueCodecFieldEncode(v *MMEStatusTransferIEContainerValueCodec) *func(MMEStatusTransferIEContainer, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeMMEStatusTransferIEContainerValueCodecFieldPath(v *MMEStatusTransferIEContainerValueCodec) *aper.Path {
	return &v.path
}
func BridgeMMEStatusTransferIEContainerValueCodecMethodEncodeBudgetValue(v MMEStatusTransferIEContainerValueCodec, a0 MMEStatusTransferIEContainer, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeMMEStatusTransferIEContainerValueCodecMethodEncodeChanged(v MMEStatusTransferIEContainerValueCodec, a0 MMEStatusTransferIEContainer, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeMMEStatusTransferIEFieldAPERValueFieldContext(v *MMEStatusTransferIEFieldAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeMMEStatusTransferIEFieldAPERValueFieldReceived(v *MMEStatusTransferIEFieldAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeMMEStatusTransferIEFieldAPERValueFieldReplay(v *MMEStatusTransferIEFieldAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeMMEStatusTransferIEFieldAPERValueFieldWithoutReplay(v *MMEStatusTransferIEFieldAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeMMEStatusTransferIEFieldFieldReceived(v *MMEStatusTransferIEField) *aper.CompletePadding {
	return &v.received
}
func BridgeMMEStatusTransferIEFieldFieldReplay(v *MMEStatusTransferIEField) *aper.Snapshot {
	return &v.replay
}
func BridgeMMEStatusTransferIEFieldFieldStream(v *MMEStatusTransferIEField) *aper.WireSpan {
	return &v.stream
}
func BridgeMMEStatusTransferIEFieldFieldWithoutReplay(v *MMEStatusTransferIEField) *bool {
	return &v.withoutReplay
}
func BridgeMMEStatusTransferIEFieldMethodMarshalAPERTo(v *MMEStatusTransferIEField, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeMMEStatusTransferIEFieldMethodUnmarshalAPERFrom(v *MMEStatusTransferIEField, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeMMEStatusTransferIEFieldValueCodecFieldCapture(v *MMEStatusTransferIEFieldValueCodec) *func(MMEStatusTransferIEField, aper.DecodeState) (MMEStatusTransferIEField, aper.Snapshot) {
	return &v.capture
}
func BridgeMMEStatusTransferIEFieldValueCodecFieldCompare(v *MMEStatusTransferIEFieldValueCodec) *func(MMEStatusTransferIEField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeMMEStatusTransferIEFieldValueCodecFieldContext(v *MMEStatusTransferIEFieldValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeMMEStatusTransferIEFieldValueCodecFieldDecode(v *MMEStatusTransferIEFieldValueCodec) *func([]byte, aper.DecodeState) (MMEStatusTransferIEField, error) {
	return &v.decode
}
func BridgeMMEStatusTransferIEFieldValueCodecFieldEncode(v *MMEStatusTransferIEFieldValueCodec) *func(MMEStatusTransferIEField, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeMMEStatusTransferIEFieldValueCodecFieldPath(v *MMEStatusTransferIEFieldValueCodec) *aper.Path {
	return &v.path
}
func BridgeMMEStatusTransferIEFieldValueCodecMethodEncodeBudgetValue(v MMEStatusTransferIEFieldValueCodec, a0 MMEStatusTransferIEField, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeMMEStatusTransferIEFieldValueCodecMethodEncodeChanged(v MMEStatusTransferIEFieldValueCodec, a0 MMEStatusTransferIEField, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeMMEStatusTransferIEValueERABIEContainerListAPERValueFieldContext(v *MMEStatusTransferIEValueERABIEContainerListAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeMMEStatusTransferIEValueERABIEContainerListAPERValueFieldReceived(v *MMEStatusTransferIEValueERABIEContainerListAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeMMEStatusTransferIEValueERABIEContainerListAPERValueFieldReplay(v *MMEStatusTransferIEValueERABIEContainerListAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeMMEStatusTransferIEValueERABIEContainerListAPERValueFieldWithoutReplay(v *MMEStatusTransferIEValueERABIEContainerListAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeMMEStatusTransferIEValueERABIEContainerListValueCodecFieldCapture(v *MMEStatusTransferIEValueERABIEContainerListValueCodec) *func(MMEStatusTransferIEValueERABIEContainerList, aper.DecodeState) (MMEStatusTransferIEValueERABIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgeMMEStatusTransferIEValueERABIEContainerListValueCodecFieldCompare(v *MMEStatusTransferIEValueERABIEContainerListValueCodec) *func(MMEStatusTransferIEValueERABIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeMMEStatusTransferIEValueERABIEContainerListValueCodecFieldContext(v *MMEStatusTransferIEValueERABIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeMMEStatusTransferIEValueERABIEContainerListValueCodecFieldDecode(v *MMEStatusTransferIEValueERABIEContainerListValueCodec) *func([]byte, aper.DecodeState) (MMEStatusTransferIEValueERABIEContainerList, error) {
	return &v.decode
}
func BridgeMMEStatusTransferIEValueERABIEContainerListValueCodecFieldEncode(v *MMEStatusTransferIEValueERABIEContainerListValueCodec) *func(MMEStatusTransferIEValueERABIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeMMEStatusTransferIEValueERABIEContainerListValueCodecFieldPath(v *MMEStatusTransferIEValueERABIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgeMMEStatusTransferIEValueERABIEContainerListValueCodecMethodEncodeBudgetValue(v MMEStatusTransferIEValueERABIEContainerListValueCodec, a0 MMEStatusTransferIEValueERABIEContainerList, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeMMEStatusTransferIEValueERABIEContainerListValueCodecMethodEncodeChanged(v MMEStatusTransferIEValueERABIEContainerListValueCodec, a0 MMEStatusTransferIEValueERABIEContainerList, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeMMEStatusTransferIEValueFieldId(v *MMEStatusTransferIEValue) *s00.ProtocolIEID {
	return &v.id
}
func BridgeMMEStatusTransferIEValueFieldIsOpaque(v *MMEStatusTransferIEValue) *bool {
	return &v.isOpaque
}
func BridgeMMEStatusTransferIEValueFieldOpaque(v *MMEStatusTransferIEValue) *aper.OpaqueOpenType {
	return &v.opaque
}
func BridgeMMEStatusTransferIEValueFieldReceived(v *MMEStatusTransferIEValue) *aper.WireSpan {
	return &v.received
}
func BridgeMMEStatusTransferIEValueFieldReplay(v *MMEStatusTransferIEValue) *aper.Snapshot {
	return &v.replay
}
func BridgeMMEStatusTransferIEValueFieldRowENBStatusTransferTransparentContainer(v *MMEStatusTransferIEValue) **ENBStatusTransferTransparentContainer {
	return &v.rowENBStatusTransferTransparentContainer
}
func BridgeMMEStatusTransferIEValueFieldRowENBUES1APID(v *MMEStatusTransferIEValue) **s00.ENBUES1APID {
	return &v.rowENBUES1APID
}
func BridgeMMEStatusTransferIEValueFieldRowMMEUES1APID(v *MMEStatusTransferIEValue) **s00.MMEUES1APID {
	return &v.rowMMEUES1APID
}
func BridgeMMEStatusTransferIEValueMethodCaptureSemantics(v MMEStatusTransferIEValue, a0 aper.SemanticCapture) MMEStatusTransferIEValue {
	return v.captureSemantics(a0)
}
func BridgeMMEStatusTransferIEValueMethodCompareSemantics(v MMEStatusTransferIEValue, a0 aper.SemanticComparison) aper.SemanticComparison {
	return v.compareSemantics(a0)
}
func BridgeMMEStatusTransferIEValueMethodDecode(v MMEStatusTransferIEValue, a0 s00.ProtocolIEID, a1 aper.OpaqueOpenType) (MMEStatusTransferIEValue, error) {
	return v.decode(a0, a1)
}
func BridgeMMEStatusTransferIEValueMethodEncode(v MMEStatusTransferIEValue) ([]byte, error) {
	return v.encode()
}
func BridgeMMEStatusTransferIEValueMethodEncodeFresh(v MMEStatusTransferIEValue, a0 bool, a1 *aper.DecodeBudget) ([]byte, error) {
	return v.encodeFresh(a0, a1)
}
func BridgeMMEStatusTransferIEValueMethodMatchesID(v MMEStatusTransferIEValue, a0 s00.ProtocolIEID, a1 ...*aper.DecodeBudget) bool {
	return v.matchesID(a0, a1...)
}
func BridgeMMEStatusTransferIEValueMethodReason(v MMEStatusTransferIEValue, a0 s00.ProtocolIEID) aper.OpaqueReason {
	return v.reason(a0)
}
func BridgeMMEStatusTransferIEValueMethodRule(v MMEStatusTransferIEValue) aper.SourceRule {
	return v.rule()
}
func BridgeMMEStatusTransferIEValueProtocolErrorIEContainerListAPERValueFieldContext(v *MMEStatusTransferIEValueProtocolErrorIEContainerListAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeMMEStatusTransferIEValueProtocolErrorIEContainerListAPERValueFieldReceived(v *MMEStatusTransferIEValueProtocolErrorIEContainerListAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeMMEStatusTransferIEValueProtocolErrorIEContainerListAPERValueFieldReplay(v *MMEStatusTransferIEValueProtocolErrorIEContainerListAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeMMEStatusTransferIEValueProtocolErrorIEContainerListAPERValueFieldWithoutReplay(v *MMEStatusTransferIEValueProtocolErrorIEContainerListAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeMMEStatusTransferIEValueProtocolErrorIEContainerListValueCodecFieldCapture(v *MMEStatusTransferIEValueProtocolErrorIEContainerListValueCodec) *func(MMEStatusTransferIEValueProtocolErrorIEContainerList, aper.DecodeState) (MMEStatusTransferIEValueProtocolErrorIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgeMMEStatusTransferIEValueProtocolErrorIEContainerListValueCodecFieldCompare(v *MMEStatusTransferIEValueProtocolErrorIEContainerListValueCodec) *func(MMEStatusTransferIEValueProtocolErrorIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeMMEStatusTransferIEValueProtocolErrorIEContainerListValueCodecFieldContext(v *MMEStatusTransferIEValueProtocolErrorIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeMMEStatusTransferIEValueProtocolErrorIEContainerListValueCodecFieldDecode(v *MMEStatusTransferIEValueProtocolErrorIEContainerListValueCodec) *func([]byte, aper.DecodeState) (MMEStatusTransferIEValueProtocolErrorIEContainerList, error) {
	return &v.decode
}
func BridgeMMEStatusTransferIEValueProtocolErrorIEContainerListValueCodecFieldEncode(v *MMEStatusTransferIEValueProtocolErrorIEContainerListValueCodec) *func(MMEStatusTransferIEValueProtocolErrorIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeMMEStatusTransferIEValueProtocolErrorIEContainerListValueCodecFieldPath(v *MMEStatusTransferIEValueProtocolErrorIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgeMMEStatusTransferIEValueProtocolErrorIEContainerListValueCodecMethodEncodeBudgetValue(v MMEStatusTransferIEValueProtocolErrorIEContainerListValueCodec, a0 MMEStatusTransferIEValueProtocolErrorIEContainerList, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeMMEStatusTransferIEValueProtocolErrorIEContainerListValueCodecMethodEncodeChanged(v MMEStatusTransferIEValueProtocolErrorIEContainerListValueCodec, a0 MMEStatusTransferIEValueProtocolErrorIEContainerList, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeTraceFailureIndicationIETableMethodInfoCause(v TraceFailureIndicationIETable) s00.FieldInfo {
	return v.infoCause()
}
func BridgeTraceFailureIndicationIETableMethodInfoENBUES1APID(v TraceFailureIndicationIETable) s00.FieldInfo {
	return v.infoENBUES1APID()
}
func BridgeTraceFailureIndicationIETableMethodInfoEUTRANTraceID(v TraceFailureIndicationIETable) s00.FieldInfo {
	return v.infoEUTRANTraceID()
}
func BridgeTraceFailureIndicationIETableMethodInfoMMEUES1APID(v TraceFailureIndicationIETable) s00.FieldInfo {
	return v.infoMMEUES1APID()
}
func BridgeTraceFailureIndicationIEValueProtocolIEContainerListValueCodecFieldCapture(v *TraceFailureIndicationIEValueProtocolIEContainerListValueCodec) *func(s20.TraceFailureIndicationIEValueProtocolIEContainerList, aper.DecodeState) (s20.TraceFailureIndicationIEValueProtocolIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgeTraceFailureIndicationIEValueProtocolIEContainerListValueCodecFieldCompare(v *TraceFailureIndicationIEValueProtocolIEContainerListValueCodec) *func(s20.TraceFailureIndicationIEValueProtocolIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeTraceFailureIndicationIEValueProtocolIEContainerListValueCodecFieldContext(v *TraceFailureIndicationIEValueProtocolIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeTraceFailureIndicationIEValueProtocolIEContainerListValueCodecFieldDecode(v *TraceFailureIndicationIEValueProtocolIEContainerListValueCodec) *func([]byte, aper.DecodeState) (s20.TraceFailureIndicationIEValueProtocolIEContainerList, error) {
	return &v.decode
}
func BridgeTraceFailureIndicationIEValueProtocolIEContainerListValueCodecFieldEncode(v *TraceFailureIndicationIEValueProtocolIEContainerListValueCodec) *func(s20.TraceFailureIndicationIEValueProtocolIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeTraceFailureIndicationIEValueProtocolIEContainerListValueCodecFieldPath(v *TraceFailureIndicationIEValueProtocolIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgeTraceFailureIndicationIEValueProtocolIEContainerListValueCodecMethodEncodeBudgetValue(v TraceFailureIndicationIEValueProtocolIEContainerListValueCodec, a0 s20.TraceFailureIndicationIEValueProtocolIEContainerList, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeTraceFailureIndicationIEValueProtocolIEContainerListValueCodecMethodEncodeChanged(v TraceFailureIndicationIEValueProtocolIEContainerListValueCodec, a0 s20.TraceFailureIndicationIEValueProtocolIEContainerList, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeTraceFailureIndicationMMEUES1APIDIEBindingFieldCodec(v *TraceFailureIndicationMMEUES1APIDIEBinding) *s01.MMEUES1APIDValueCodec {
	return &v.codec
}
func BridgeTraceFailureIndicationMMEUES1APIDIEBindingFieldGet(v *TraceFailureIndicationMMEUES1APIDIEBinding) *func(*s20.TraceFailureIndicationIEValue) (*s00.MMEUES1APID, bool) {
	return &v.get
}
func BridgeTraceFailureIndicationMMEUES1APIDIEBindingFieldInfo(v *TraceFailureIndicationMMEUES1APIDIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeTraceFailureIndicationMMEUES1APIDIEBindingFieldInject(v *TraceFailureIndicationMMEUES1APIDIEBinding) *func(s00.MMEUES1APID) s20.TraceFailureIndicationIEValue {
	return &v.inject
}
func BridgeTransportInformationAPERValueFieldContext(v *TransportInformationAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeTransportInformationAPERValueFieldReceived(v *TransportInformationAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeTransportInformationAPERValueFieldReplay(v *TransportInformationAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeTransportInformationAPERValueFieldWithoutReplay(v *TransportInformationAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeTransportInformationFieldExtCount(v *TransportInformation) *int64   { return &v.extCount }
func BridgeTransportInformationFieldExtData(v *TransportInformation) *[][]byte { return &v.extData }
func BridgeTransportInformationFieldExtOrigin(v *TransportInformation) *[]aper.OpaqueOrigin {
	return &v.extOrigin
}
func BridgeTransportInformationFieldExtPresent(v *TransportInformation) *[]bool { return &v.extPresent }
func BridgeTransportInformationFieldExtWire(v *TransportInformation) *[]aper.WireSpan {
	return &v.extWire
}
func BridgeTransportInformationFieldPerExtPadding(v *TransportInformation) *[]aper.CompletePadding {
	return &v.perExtPadding
}
func BridgeTransportInformationFieldPerPadding(v *TransportInformation) *aper.FinalPadding {
	return &v.perPadding
}
func BridgeTransportInformationFieldReceived(v *TransportInformation) *bool { return &v.received }
func BridgeTransportInformationFieldReceivedAbsolute(v *TransportInformation) *bool {
	return &v.receivedAbsolute
}
func BridgeTransportInformationFieldReceivedBytes(v *TransportInformation) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeTransportInformationFieldReceivedLocation(v *TransportInformation) *aper.Location {
	return &v.receivedLocation
}
func BridgeTransportInformationFieldReplay(v *TransportInformation) *aper.Snapshot { return &v.replay }
func BridgeTransportInformationFieldStream(v *TransportInformation) *aper.WireSpan { return &v.stream }
func BridgeTransportInformationFieldWithoutReplay(v *TransportInformation) *bool {
	return &v.withoutReplay
}
func BridgeTransportInformationMethodMarshalAPERBudget(v *TransportInformation, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeTransportInformationMethodMarshalAPERBudgetValue(v *TransportInformation, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudgetValue(a0, a1)
}
func BridgeTransportInformationMethodMarshalAPERChanged(v *TransportInformation, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeTransportInformationMethodMarshalAPERChangedValue(v *TransportInformation, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeTransportInformationMethodMarshalAPERLegacy(v *TransportInformation) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeTransportInformationMethodMarshalAPERNewValue(v *TransportInformation, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERNewValue(a0, a1)
}
func BridgeTransportInformationMethodMarshalAPERPlanned(v *TransportInformation, a0 *aper.DecodeBudget, a1 bool, a2 *aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1, a2)
}
func BridgeTransportInformationMethodMarshalAPERTo(v *TransportInformation, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeTransportInformationMethodUnmarshalAPERFrom(v *TransportInformation, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeTransportInformationMethodUnmarshalAPERLegacy(v *TransportInformation, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeTransportInformationMethodUnmarshalAPERWithOptions(v *TransportInformation, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeTransportInformationValueCodecFieldCapture(v *TransportInformationValueCodec) *func(TransportInformation, aper.DecodeState) (TransportInformation, aper.Snapshot) {
	return &v.capture
}
func BridgeTransportInformationValueCodecFieldCompare(v *TransportInformationValueCodec) *func(TransportInformation, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeTransportInformationValueCodecFieldContext(v *TransportInformationValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeTransportInformationValueCodecFieldDecode(v *TransportInformationValueCodec) *func([]byte, aper.DecodeState) (TransportInformation, error) {
	return &v.decode
}
func BridgeTransportInformationValueCodecFieldEncode(v *TransportInformationValueCodec) *func(TransportInformation, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeTransportInformationValueCodecFieldPath(v *TransportInformationValueCodec) *aper.Path {
	return &v.path
}
func BridgeTransportInformationValueCodecMethodEncodeBudgetValue(v TransportInformationValueCodec, a0 TransportInformation, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeTransportInformationValueCodecMethodEncodeChanged(v TransportInformationValueCodec, a0 TransportInformation, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeUEContextModificationIndicationCSGMembershipInfoIEBindingFieldCodec(v *UEContextModificationIndicationCSGMembershipInfoIEBinding) *s14.CSGMembershipInfoValueCodec {
	return &v.codec
}
func BridgeUEContextModificationIndicationCSGMembershipInfoIEBindingFieldGet(v *UEContextModificationIndicationCSGMembershipInfoIEBinding) *func(*UEContextModificationIndicationIEValue) (*s14.CSGMembershipInfo, bool) {
	return &v.get
}
func BridgeUEContextModificationIndicationCSGMembershipInfoIEBindingFieldInfo(v *UEContextModificationIndicationCSGMembershipInfoIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeUEContextModificationIndicationCSGMembershipInfoIEBindingFieldInject(v *UEContextModificationIndicationCSGMembershipInfoIEBinding) *func(s14.CSGMembershipInfo) UEContextModificationIndicationIEValue {
	return &v.inject
}
func BridgeUEContextModificationIndicationENBUES1APIDIEBindingFieldCodec(v *UEContextModificationIndicationENBUES1APIDIEBinding) *s00.ENBUES1APIDValueCodec {
	return &v.codec
}
func BridgeUEContextModificationIndicationENBUES1APIDIEBindingFieldGet(v *UEContextModificationIndicationENBUES1APIDIEBinding) *func(*UEContextModificationIndicationIEValue) (*s00.ENBUES1APID, bool) {
	return &v.get
}
func BridgeUEContextModificationIndicationENBUES1APIDIEBindingFieldInfo(v *UEContextModificationIndicationENBUES1APIDIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeUEContextModificationIndicationENBUES1APIDIEBindingFieldInject(v *UEContextModificationIndicationENBUES1APIDIEBinding) *func(s00.ENBUES1APID) UEContextModificationIndicationIEValue {
	return &v.inject
}
func BridgeUEContextModificationIndicationIEContainerAPERValueFieldContext(v *UEContextModificationIndicationIEContainerAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeUEContextModificationIndicationIEContainerAPERValueFieldReceived(v *UEContextModificationIndicationIEContainerAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeUEContextModificationIndicationIEContainerAPERValueFieldReplay(v *UEContextModificationIndicationIEContainerAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeUEContextModificationIndicationIEContainerAPERValueFieldWithoutReplay(v *UEContextModificationIndicationIEContainerAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeUEContextModificationIndicationIEContainerValueCodecFieldCapture(v *UEContextModificationIndicationIEContainerValueCodec) *func(UEContextModificationIndicationIEContainer, aper.DecodeState) (UEContextModificationIndicationIEContainer, aper.Snapshot) {
	return &v.capture
}
func BridgeUEContextModificationIndicationIEContainerValueCodecFieldCompare(v *UEContextModificationIndicationIEContainerValueCodec) *func(UEContextModificationIndicationIEContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeUEContextModificationIndicationIEContainerValueCodecFieldContext(v *UEContextModificationIndicationIEContainerValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeUEContextModificationIndicationIEContainerValueCodecFieldDecode(v *UEContextModificationIndicationIEContainerValueCodec) *func([]byte, aper.DecodeState) (UEContextModificationIndicationIEContainer, error) {
	return &v.decode
}
func BridgeUEContextModificationIndicationIEContainerValueCodecFieldEncode(v *UEContextModificationIndicationIEContainerValueCodec) *func(UEContextModificationIndicationIEContainer, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeUEContextModificationIndicationIEContainerValueCodecFieldPath(v *UEContextModificationIndicationIEContainerValueCodec) *aper.Path {
	return &v.path
}
func BridgeUEContextModificationIndicationIEContainerValueCodecMethodEncodeBudgetValue(v UEContextModificationIndicationIEContainerValueCodec, a0 UEContextModificationIndicationIEContainer, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeUEContextModificationIndicationIEContainerValueCodecMethodEncodeChanged(v UEContextModificationIndicationIEContainerValueCodec, a0 UEContextModificationIndicationIEContainer, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeUEContextModificationIndicationIEFieldAPERValueFieldContext(v *UEContextModificationIndicationIEFieldAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeUEContextModificationIndicationIEFieldAPERValueFieldReceived(v *UEContextModificationIndicationIEFieldAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeUEContextModificationIndicationIEFieldAPERValueFieldReplay(v *UEContextModificationIndicationIEFieldAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeUEContextModificationIndicationIEFieldAPERValueFieldWithoutReplay(v *UEContextModificationIndicationIEFieldAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeUEContextModificationIndicationIEFieldFieldReceived(v *UEContextModificationIndicationIEField) *aper.CompletePadding {
	return &v.received
}
func BridgeUEContextModificationIndicationIEFieldFieldReplay(v *UEContextModificationIndicationIEField) *aper.Snapshot {
	return &v.replay
}
func BridgeUEContextModificationIndicationIEFieldFieldStream(v *UEContextModificationIndicationIEField) *aper.WireSpan {
	return &v.stream
}
func BridgeUEContextModificationIndicationIEFieldFieldWithoutReplay(v *UEContextModificationIndicationIEField) *bool {
	return &v.withoutReplay
}
func BridgeUEContextModificationIndicationIEFieldMethodMarshalAPERTo(v *UEContextModificationIndicationIEField, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeUEContextModificationIndicationIEFieldMethodUnmarshalAPERFrom(v *UEContextModificationIndicationIEField, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeUEContextModificationIndicationIEFieldValueCodecFieldCapture(v *UEContextModificationIndicationIEFieldValueCodec) *func(UEContextModificationIndicationIEField, aper.DecodeState) (UEContextModificationIndicationIEField, aper.Snapshot) {
	return &v.capture
}
func BridgeUEContextModificationIndicationIEFieldValueCodecFieldCompare(v *UEContextModificationIndicationIEFieldValueCodec) *func(UEContextModificationIndicationIEField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeUEContextModificationIndicationIEFieldValueCodecFieldContext(v *UEContextModificationIndicationIEFieldValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeUEContextModificationIndicationIEFieldValueCodecFieldDecode(v *UEContextModificationIndicationIEFieldValueCodec) *func([]byte, aper.DecodeState) (UEContextModificationIndicationIEField, error) {
	return &v.decode
}
func BridgeUEContextModificationIndicationIEFieldValueCodecFieldEncode(v *UEContextModificationIndicationIEFieldValueCodec) *func(UEContextModificationIndicationIEField, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeUEContextModificationIndicationIEFieldValueCodecFieldPath(v *UEContextModificationIndicationIEFieldValueCodec) *aper.Path {
	return &v.path
}
func BridgeUEContextModificationIndicationIEFieldValueCodecMethodEncodeBudgetValue(v UEContextModificationIndicationIEFieldValueCodec, a0 UEContextModificationIndicationIEField, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeUEContextModificationIndicationIEFieldValueCodecMethodEncodeChanged(v UEContextModificationIndicationIEFieldValueCodec, a0 UEContextModificationIndicationIEField, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeUEContextModificationIndicationIETableMethodInfoCSGMembershipInfo(v UEContextModificationIndicationIETable) s00.FieldInfo {
	return v.infoCSGMembershipInfo()
}
func BridgeUEContextModificationIndicationIETableMethodInfoENBUES1APID(v UEContextModificationIndicationIETable) s00.FieldInfo {
	return v.infoENBUES1APID()
}
func BridgeUEContextModificationIndicationIETableMethodInfoMMEUES1APID(v UEContextModificationIndicationIETable) s00.FieldInfo {
	return v.infoMMEUES1APID()
}
func BridgeUEContextModificationIndicationIEValueERABIEContainerListAPERValueFieldContext(v *UEContextModificationIndicationIEValueERABIEContainerListAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeUEContextModificationIndicationIEValueERABIEContainerListAPERValueFieldReceived(v *UEContextModificationIndicationIEValueERABIEContainerListAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeUEContextModificationIndicationIEValueERABIEContainerListAPERValueFieldReplay(v *UEContextModificationIndicationIEValueERABIEContainerListAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeUEContextModificationIndicationIEValueERABIEContainerListAPERValueFieldWithoutReplay(v *UEContextModificationIndicationIEValueERABIEContainerListAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeUEContextModificationIndicationIEValueERABIEContainerListValueCodecFieldCapture(v *UEContextModificationIndicationIEValueERABIEContainerListValueCodec) *func(UEContextModificationIndicationIEValueERABIEContainerList, aper.DecodeState) (UEContextModificationIndicationIEValueERABIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgeUEContextModificationIndicationIEValueERABIEContainerListValueCodecFieldCompare(v *UEContextModificationIndicationIEValueERABIEContainerListValueCodec) *func(UEContextModificationIndicationIEValueERABIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeUEContextModificationIndicationIEValueERABIEContainerListValueCodecFieldContext(v *UEContextModificationIndicationIEValueERABIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeUEContextModificationIndicationIEValueERABIEContainerListValueCodecFieldDecode(v *UEContextModificationIndicationIEValueERABIEContainerListValueCodec) *func([]byte, aper.DecodeState) (UEContextModificationIndicationIEValueERABIEContainerList, error) {
	return &v.decode
}
func BridgeUEContextModificationIndicationIEValueERABIEContainerListValueCodecFieldEncode(v *UEContextModificationIndicationIEValueERABIEContainerListValueCodec) *func(UEContextModificationIndicationIEValueERABIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeUEContextModificationIndicationIEValueERABIEContainerListValueCodecFieldPath(v *UEContextModificationIndicationIEValueERABIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgeUEContextModificationIndicationIEValueERABIEContainerListValueCodecMethodEncodeBudgetValue(v UEContextModificationIndicationIEValueERABIEContainerListValueCodec, a0 UEContextModificationIndicationIEValueERABIEContainerList, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeUEContextModificationIndicationIEValueERABIEContainerListValueCodecMethodEncodeChanged(v UEContextModificationIndicationIEValueERABIEContainerListValueCodec, a0 UEContextModificationIndicationIEValueERABIEContainerList, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeUEContextModificationIndicationIEValueFieldId(v *UEContextModificationIndicationIEValue) *s00.ProtocolIEID {
	return &v.id
}
func BridgeUEContextModificationIndicationIEValueFieldIsOpaque(v *UEContextModificationIndicationIEValue) *bool {
	return &v.isOpaque
}
func BridgeUEContextModificationIndicationIEValueFieldOpaque(v *UEContextModificationIndicationIEValue) *aper.OpaqueOpenType {
	return &v.opaque
}
func BridgeUEContextModificationIndicationIEValueFieldReceived(v *UEContextModificationIndicationIEValue) *aper.WireSpan {
	return &v.received
}
func BridgeUEContextModificationIndicationIEValueFieldReplay(v *UEContextModificationIndicationIEValue) *aper.Snapshot {
	return &v.replay
}
func BridgeUEContextModificationIndicationIEValueFieldRowCSGMembershipInfo(v *UEContextModificationIndicationIEValue) **s14.CSGMembershipInfo {
	return &v.rowCSGMembershipInfo
}
func BridgeUEContextModificationIndicationIEValueFieldRowENBUES1APID(v *UEContextModificationIndicationIEValue) **s00.ENBUES1APID {
	return &v.rowENBUES1APID
}
func BridgeUEContextModificationIndicationIEValueFieldRowMMEUES1APID(v *UEContextModificationIndicationIEValue) **s00.MMEUES1APID {
	return &v.rowMMEUES1APID
}
func BridgeUEContextModificationIndicationIEValueMethodCaptureSemantics(v UEContextModificationIndicationIEValue, a0 aper.SemanticCapture) UEContextModificationIndicationIEValue {
	return v.captureSemantics(a0)
}
func BridgeUEContextModificationIndicationIEValueMethodCompareSemantics(v UEContextModificationIndicationIEValue, a0 aper.SemanticComparison) aper.SemanticComparison {
	return v.compareSemantics(a0)
}
func BridgeUEContextModificationIndicationIEValueMethodDecode(v UEContextModificationIndicationIEValue, a0 s00.ProtocolIEID, a1 aper.OpaqueOpenType) (UEContextModificationIndicationIEValue, error) {
	return v.decode(a0, a1)
}
func BridgeUEContextModificationIndicationIEValueMethodEncode(v UEContextModificationIndicationIEValue) ([]byte, error) {
	return v.encode()
}
func BridgeUEContextModificationIndicationIEValueMethodEncodeFresh(v UEContextModificationIndicationIEValue, a0 bool, a1 *aper.DecodeBudget) ([]byte, error) {
	return v.encodeFresh(a0, a1)
}
func BridgeUEContextModificationIndicationIEValueMethodMatchesID(v UEContextModificationIndicationIEValue, a0 s00.ProtocolIEID, a1 ...*aper.DecodeBudget) bool {
	return v.matchesID(a0, a1...)
}
func BridgeUEContextModificationIndicationIEValueMethodReason(v UEContextModificationIndicationIEValue, a0 s00.ProtocolIEID) aper.OpaqueReason {
	return v.reason(a0)
}
func BridgeUEContextModificationIndicationIEValueMethodRule(v UEContextModificationIndicationIEValue) aper.SourceRule {
	return v.rule()
}
func BridgeUEContextModificationIndicationIEValueProtocolErrorIEContainerListAPERValueFieldContext(v *UEContextModificationIndicationIEValueProtocolErrorIEContainerListAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeUEContextModificationIndicationIEValueProtocolErrorIEContainerListAPERValueFieldReceived(v *UEContextModificationIndicationIEValueProtocolErrorIEContainerListAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeUEContextModificationIndicationIEValueProtocolErrorIEContainerListAPERValueFieldReplay(v *UEContextModificationIndicationIEValueProtocolErrorIEContainerListAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeUEContextModificationIndicationIEValueProtocolErrorIEContainerListAPERValueFieldWithoutReplay(v *UEContextModificationIndicationIEValueProtocolErrorIEContainerListAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeUEContextModificationIndicationIEValueProtocolErrorIEContainerListValueCodecFieldCapture(v *UEContextModificationIndicationIEValueProtocolErrorIEContainerListValueCodec) *func(UEContextModificationIndicationIEValueProtocolErrorIEContainerList, aper.DecodeState) (UEContextModificationIndicationIEValueProtocolErrorIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgeUEContextModificationIndicationIEValueProtocolErrorIEContainerListValueCodecFieldCompare(v *UEContextModificationIndicationIEValueProtocolErrorIEContainerListValueCodec) *func(UEContextModificationIndicationIEValueProtocolErrorIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeUEContextModificationIndicationIEValueProtocolErrorIEContainerListValueCodecFieldContext(v *UEContextModificationIndicationIEValueProtocolErrorIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeUEContextModificationIndicationIEValueProtocolErrorIEContainerListValueCodecFieldDecode(v *UEContextModificationIndicationIEValueProtocolErrorIEContainerListValueCodec) *func([]byte, aper.DecodeState) (UEContextModificationIndicationIEValueProtocolErrorIEContainerList, error) {
	return &v.decode
}
func BridgeUEContextModificationIndicationIEValueProtocolErrorIEContainerListValueCodecFieldEncode(v *UEContextModificationIndicationIEValueProtocolErrorIEContainerListValueCodec) *func(UEContextModificationIndicationIEValueProtocolErrorIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeUEContextModificationIndicationIEValueProtocolErrorIEContainerListValueCodecFieldPath(v *UEContextModificationIndicationIEValueProtocolErrorIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgeUEContextModificationIndicationIEValueProtocolErrorIEContainerListValueCodecMethodEncodeBudgetValue(v UEContextModificationIndicationIEValueProtocolErrorIEContainerListValueCodec, a0 UEContextModificationIndicationIEValueProtocolErrorIEContainerList, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeUEContextModificationIndicationIEValueProtocolErrorIEContainerListValueCodecMethodEncodeChanged(v UEContextModificationIndicationIEValueProtocolErrorIEContainerListValueCodec, a0 UEContextModificationIndicationIEValueProtocolErrorIEContainerList, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeUEContextModificationIndicationIEValueProtocolIEContainerListAPERValueFieldContext(v *UEContextModificationIndicationIEValueProtocolIEContainerListAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeUEContextModificationIndicationIEValueProtocolIEContainerListAPERValueFieldReceived(v *UEContextModificationIndicationIEValueProtocolIEContainerListAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeUEContextModificationIndicationIEValueProtocolIEContainerListAPERValueFieldReplay(v *UEContextModificationIndicationIEValueProtocolIEContainerListAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeUEContextModificationIndicationIEValueProtocolIEContainerListAPERValueFieldWithoutReplay(v *UEContextModificationIndicationIEValueProtocolIEContainerListAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeUEContextModificationIndicationIEValueProtocolIEContainerListValueCodecFieldCapture(v *UEContextModificationIndicationIEValueProtocolIEContainerListValueCodec) *func(UEContextModificationIndicationIEValueProtocolIEContainerList, aper.DecodeState) (UEContextModificationIndicationIEValueProtocolIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgeUEContextModificationIndicationIEValueProtocolIEContainerListValueCodecFieldCompare(v *UEContextModificationIndicationIEValueProtocolIEContainerListValueCodec) *func(UEContextModificationIndicationIEValueProtocolIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeUEContextModificationIndicationIEValueProtocolIEContainerListValueCodecFieldContext(v *UEContextModificationIndicationIEValueProtocolIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeUEContextModificationIndicationIEValueProtocolIEContainerListValueCodecFieldDecode(v *UEContextModificationIndicationIEValueProtocolIEContainerListValueCodec) *func([]byte, aper.DecodeState) (UEContextModificationIndicationIEValueProtocolIEContainerList, error) {
	return &v.decode
}
func BridgeUEContextModificationIndicationIEValueProtocolIEContainerListValueCodecFieldEncode(v *UEContextModificationIndicationIEValueProtocolIEContainerListValueCodec) *func(UEContextModificationIndicationIEValueProtocolIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeUEContextModificationIndicationIEValueProtocolIEContainerListValueCodecFieldPath(v *UEContextModificationIndicationIEValueProtocolIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgeUEContextModificationIndicationIEValueProtocolIEContainerListValueCodecMethodEncodeBudgetValue(v UEContextModificationIndicationIEValueProtocolIEContainerListValueCodec, a0 UEContextModificationIndicationIEValueProtocolIEContainerList, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeUEContextModificationIndicationIEValueProtocolIEContainerListValueCodecMethodEncodeChanged(v UEContextModificationIndicationIEValueProtocolIEContainerListValueCodec, a0 UEContextModificationIndicationIEValueProtocolIEContainerList, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeUEContextModificationIndicationMMEUES1APIDIEBindingFieldCodec(v *UEContextModificationIndicationMMEUES1APIDIEBinding) *s01.MMEUES1APIDValueCodec {
	return &v.codec
}
func BridgeUEContextModificationIndicationMMEUES1APIDIEBindingFieldGet(v *UEContextModificationIndicationMMEUES1APIDIEBinding) *func(*UEContextModificationIndicationIEValue) (*s00.MMEUES1APID, bool) {
	return &v.get
}
func BridgeUEContextModificationIndicationMMEUES1APIDIEBindingFieldInfo(v *UEContextModificationIndicationMMEUES1APIDIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeUEContextModificationIndicationMMEUES1APIDIEBindingFieldInject(v *UEContextModificationIndicationMMEUES1APIDIEBinding) *func(s00.MMEUES1APID) UEContextModificationIndicationIEValue {
	return &v.inject
}
func BridgeUplinkS1cdma2000tunnellingCdma2000HORequiredIndicationIEBindingFieldCodec(v *UplinkS1cdma2000tunnellingCdma2000HORequiredIndicationIEBinding) *s00.Cdma2000HORequiredIndicationValueCodec {
	return &v.codec
}
func BridgeUplinkS1cdma2000tunnellingCdma2000HORequiredIndicationIEBindingFieldGet(v *UplinkS1cdma2000tunnellingCdma2000HORequiredIndicationIEBinding) *func(*UplinkS1cdma2000tunnellingIEValue) (*s00.Cdma2000HORequiredIndication, bool) {
	return &v.get
}
func BridgeUplinkS1cdma2000tunnellingCdma2000HORequiredIndicationIEBindingFieldInfo(v *UplinkS1cdma2000tunnellingCdma2000HORequiredIndicationIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeUplinkS1cdma2000tunnellingCdma2000HORequiredIndicationIEBindingFieldInject(v *UplinkS1cdma2000tunnellingCdma2000HORequiredIndicationIEBinding) *func(s00.Cdma2000HORequiredIndication) UplinkS1cdma2000tunnellingIEValue {
	return &v.inject
}
func BridgeUplinkS1cdma2000tunnellingCdma2000OneXRANDIEBindingFieldCodec(v *UplinkS1cdma2000tunnellingCdma2000OneXRANDIEBinding) *s00.Cdma2000OneXRANDValueCodec {
	return &v.codec
}
func BridgeUplinkS1cdma2000tunnellingCdma2000OneXRANDIEBindingFieldGet(v *UplinkS1cdma2000tunnellingCdma2000OneXRANDIEBinding) *func(*UplinkS1cdma2000tunnellingIEValue) (*s00.Cdma2000OneXRAND, bool) {
	return &v.get
}
func BridgeUplinkS1cdma2000tunnellingCdma2000OneXRANDIEBindingFieldInfo(v *UplinkS1cdma2000tunnellingCdma2000OneXRANDIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeUplinkS1cdma2000tunnellingCdma2000OneXRANDIEBindingFieldInject(v *UplinkS1cdma2000tunnellingCdma2000OneXRANDIEBinding) *func(s00.Cdma2000OneXRAND) UplinkS1cdma2000tunnellingIEValue {
	return &v.inject
}
func BridgeUplinkS1cdma2000tunnellingCdma2000OneXSRVCCInfoIEBindingFieldCodec(v *UplinkS1cdma2000tunnellingCdma2000OneXSRVCCInfoIEBinding) *s14.Cdma2000OneXSRVCCInfoValueCodec {
	return &v.codec
}
func BridgeUplinkS1cdma2000tunnellingCdma2000OneXSRVCCInfoIEBindingFieldGet(v *UplinkS1cdma2000tunnellingCdma2000OneXSRVCCInfoIEBinding) *func(*UplinkS1cdma2000tunnellingIEValue) (*s14.Cdma2000OneXSRVCCInfo, bool) {
	return &v.get
}
func BridgeUplinkS1cdma2000tunnellingCdma2000OneXSRVCCInfoIEBindingFieldInfo(v *UplinkS1cdma2000tunnellingCdma2000OneXSRVCCInfoIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeUplinkS1cdma2000tunnellingCdma2000OneXSRVCCInfoIEBindingFieldInject(v *UplinkS1cdma2000tunnellingCdma2000OneXSRVCCInfoIEBinding) *func(s14.Cdma2000OneXSRVCCInfo) UplinkS1cdma2000tunnellingIEValue {
	return &v.inject
}
func BridgeUplinkS1cdma2000tunnellingCdma2000PDUIEBindingFieldCodec(v *UplinkS1cdma2000tunnellingCdma2000PDUIEBinding) *s00.Cdma2000PDUValueCodec {
	return &v.codec
}
func BridgeUplinkS1cdma2000tunnellingCdma2000PDUIEBindingFieldGet(v *UplinkS1cdma2000tunnellingCdma2000PDUIEBinding) *func(*UplinkS1cdma2000tunnellingIEValue) (*s00.Cdma2000PDU, bool) {
	return &v.get
}
func BridgeUplinkS1cdma2000tunnellingCdma2000PDUIEBindingFieldInfo(v *UplinkS1cdma2000tunnellingCdma2000PDUIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeUplinkS1cdma2000tunnellingCdma2000PDUIEBindingFieldInject(v *UplinkS1cdma2000tunnellingCdma2000PDUIEBinding) *func(s00.Cdma2000PDU) UplinkS1cdma2000tunnellingIEValue {
	return &v.inject
}
func BridgeUplinkS1cdma2000tunnellingCdma2000RATTypeIEBindingFieldCodec(v *UplinkS1cdma2000tunnellingCdma2000RATTypeIEBinding) *s00.Cdma2000RATTypeValueCodec {
	return &v.codec
}
func BridgeUplinkS1cdma2000tunnellingCdma2000RATTypeIEBindingFieldGet(v *UplinkS1cdma2000tunnellingCdma2000RATTypeIEBinding) *func(*UplinkS1cdma2000tunnellingIEValue) (*s00.Cdma2000RATType, bool) {
	return &v.get
}
func BridgeUplinkS1cdma2000tunnellingCdma2000RATTypeIEBindingFieldInfo(v *UplinkS1cdma2000tunnellingCdma2000RATTypeIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeUplinkS1cdma2000tunnellingCdma2000RATTypeIEBindingFieldInject(v *UplinkS1cdma2000tunnellingCdma2000RATTypeIEBinding) *func(s00.Cdma2000RATType) UplinkS1cdma2000tunnellingIEValue {
	return &v.inject
}
func BridgeUplinkS1cdma2000tunnellingCdma2000SectorIDIEBindingFieldCodec(v *UplinkS1cdma2000tunnellingCdma2000SectorIDIEBinding) *s00.Cdma2000SectorIDValueCodec {
	return &v.codec
}
func BridgeUplinkS1cdma2000tunnellingCdma2000SectorIDIEBindingFieldGet(v *UplinkS1cdma2000tunnellingCdma2000SectorIDIEBinding) *func(*UplinkS1cdma2000tunnellingIEValue) (*s00.Cdma2000SectorID, bool) {
	return &v.get
}
func BridgeUplinkS1cdma2000tunnellingCdma2000SectorIDIEBindingFieldInfo(v *UplinkS1cdma2000tunnellingCdma2000SectorIDIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeUplinkS1cdma2000tunnellingCdma2000SectorIDIEBindingFieldInject(v *UplinkS1cdma2000tunnellingCdma2000SectorIDIEBinding) *func(s00.Cdma2000SectorID) UplinkS1cdma2000tunnellingIEValue {
	return &v.inject
}
func BridgeUplinkS1cdma2000tunnellingENBUES1APIDIEBindingFieldCodec(v *UplinkS1cdma2000tunnellingENBUES1APIDIEBinding) *s00.ENBUES1APIDValueCodec {
	return &v.codec
}
func BridgeUplinkS1cdma2000tunnellingENBUES1APIDIEBindingFieldGet(v *UplinkS1cdma2000tunnellingENBUES1APIDIEBinding) *func(*UplinkS1cdma2000tunnellingIEValue) (*s00.ENBUES1APID, bool) {
	return &v.get
}
func BridgeUplinkS1cdma2000tunnellingENBUES1APIDIEBindingFieldInfo(v *UplinkS1cdma2000tunnellingENBUES1APIDIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeUplinkS1cdma2000tunnellingENBUES1APIDIEBindingFieldInject(v *UplinkS1cdma2000tunnellingENBUES1APIDIEBinding) *func(s00.ENBUES1APID) UplinkS1cdma2000tunnellingIEValue {
	return &v.inject
}
func BridgeUplinkS1cdma2000tunnellingEUTRANRoundTripDelayEstimationInfoIEBindingFieldCodec(v *UplinkS1cdma2000tunnellingEUTRANRoundTripDelayEstimationInfoIEBinding) *s00.EUTRANRoundTripDelayEstimationInfoValueCodec {
	return &v.codec
}
func BridgeUplinkS1cdma2000tunnellingEUTRANRoundTripDelayEstimationInfoIEBindingFieldGet(v *UplinkS1cdma2000tunnellingEUTRANRoundTripDelayEstimationInfoIEBinding) *func(*UplinkS1cdma2000tunnellingIEValue) (*s00.EUTRANRoundTripDelayEstimationInfo, bool) {
	return &v.get
}
func BridgeUplinkS1cdma2000tunnellingEUTRANRoundTripDelayEstimationInfoIEBindingFieldInfo(v *UplinkS1cdma2000tunnellingEUTRANRoundTripDelayEstimationInfoIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeUplinkS1cdma2000tunnellingEUTRANRoundTripDelayEstimationInfoIEBindingFieldInject(v *UplinkS1cdma2000tunnellingEUTRANRoundTripDelayEstimationInfoIEBinding) *func(s00.EUTRANRoundTripDelayEstimationInfo) UplinkS1cdma2000tunnellingIEValue {
	return &v.inject
}
func BridgeUplinkS1cdma2000tunnellingIEContainerAPERValueFieldContext(v *UplinkS1cdma2000tunnellingIEContainerAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeUplinkS1cdma2000tunnellingIEContainerAPERValueFieldReceived(v *UplinkS1cdma2000tunnellingIEContainerAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeUplinkS1cdma2000tunnellingIEContainerAPERValueFieldReplay(v *UplinkS1cdma2000tunnellingIEContainerAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeUplinkS1cdma2000tunnellingIEContainerAPERValueFieldWithoutReplay(v *UplinkS1cdma2000tunnellingIEContainerAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeUplinkS1cdma2000tunnellingIEContainerValueCodecFieldCapture(v *UplinkS1cdma2000tunnellingIEContainerValueCodec) *func(UplinkS1cdma2000tunnellingIEContainer, aper.DecodeState) (UplinkS1cdma2000tunnellingIEContainer, aper.Snapshot) {
	return &v.capture
}
func BridgeUplinkS1cdma2000tunnellingIEContainerValueCodecFieldCompare(v *UplinkS1cdma2000tunnellingIEContainerValueCodec) *func(UplinkS1cdma2000tunnellingIEContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeUplinkS1cdma2000tunnellingIEContainerValueCodecFieldContext(v *UplinkS1cdma2000tunnellingIEContainerValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeUplinkS1cdma2000tunnellingIEContainerValueCodecFieldDecode(v *UplinkS1cdma2000tunnellingIEContainerValueCodec) *func([]byte, aper.DecodeState) (UplinkS1cdma2000tunnellingIEContainer, error) {
	return &v.decode
}
func BridgeUplinkS1cdma2000tunnellingIEContainerValueCodecFieldEncode(v *UplinkS1cdma2000tunnellingIEContainerValueCodec) *func(UplinkS1cdma2000tunnellingIEContainer, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeUplinkS1cdma2000tunnellingIEContainerValueCodecFieldPath(v *UplinkS1cdma2000tunnellingIEContainerValueCodec) *aper.Path {
	return &v.path
}
func BridgeUplinkS1cdma2000tunnellingIEContainerValueCodecMethodEncodeBudgetValue(v UplinkS1cdma2000tunnellingIEContainerValueCodec, a0 UplinkS1cdma2000tunnellingIEContainer, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeUplinkS1cdma2000tunnellingIEContainerValueCodecMethodEncodeChanged(v UplinkS1cdma2000tunnellingIEContainerValueCodec, a0 UplinkS1cdma2000tunnellingIEContainer, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeUplinkS1cdma2000tunnellingIEFieldAPERValueFieldContext(v *UplinkS1cdma2000tunnellingIEFieldAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeUplinkS1cdma2000tunnellingIEFieldAPERValueFieldReceived(v *UplinkS1cdma2000tunnellingIEFieldAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeUplinkS1cdma2000tunnellingIEFieldAPERValueFieldReplay(v *UplinkS1cdma2000tunnellingIEFieldAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeUplinkS1cdma2000tunnellingIEFieldAPERValueFieldWithoutReplay(v *UplinkS1cdma2000tunnellingIEFieldAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeUplinkS1cdma2000tunnellingIEFieldFieldReceived(v *UplinkS1cdma2000tunnellingIEField) *aper.CompletePadding {
	return &v.received
}
func BridgeUplinkS1cdma2000tunnellingIEFieldFieldReplay(v *UplinkS1cdma2000tunnellingIEField) *aper.Snapshot {
	return &v.replay
}
func BridgeUplinkS1cdma2000tunnellingIEFieldFieldStream(v *UplinkS1cdma2000tunnellingIEField) *aper.WireSpan {
	return &v.stream
}
func BridgeUplinkS1cdma2000tunnellingIEFieldFieldWithoutReplay(v *UplinkS1cdma2000tunnellingIEField) *bool {
	return &v.withoutReplay
}
func BridgeUplinkS1cdma2000tunnellingIEFieldMethodMarshalAPERTo(v *UplinkS1cdma2000tunnellingIEField, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeUplinkS1cdma2000tunnellingIEFieldMethodUnmarshalAPERFrom(v *UplinkS1cdma2000tunnellingIEField, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeUplinkS1cdma2000tunnellingIEFieldValueCodecFieldCapture(v *UplinkS1cdma2000tunnellingIEFieldValueCodec) *func(UplinkS1cdma2000tunnellingIEField, aper.DecodeState) (UplinkS1cdma2000tunnellingIEField, aper.Snapshot) {
	return &v.capture
}
func BridgeUplinkS1cdma2000tunnellingIEFieldValueCodecFieldCompare(v *UplinkS1cdma2000tunnellingIEFieldValueCodec) *func(UplinkS1cdma2000tunnellingIEField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeUplinkS1cdma2000tunnellingIEFieldValueCodecFieldContext(v *UplinkS1cdma2000tunnellingIEFieldValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeUplinkS1cdma2000tunnellingIEFieldValueCodecFieldDecode(v *UplinkS1cdma2000tunnellingIEFieldValueCodec) *func([]byte, aper.DecodeState) (UplinkS1cdma2000tunnellingIEField, error) {
	return &v.decode
}
func BridgeUplinkS1cdma2000tunnellingIEFieldValueCodecFieldEncode(v *UplinkS1cdma2000tunnellingIEFieldValueCodec) *func(UplinkS1cdma2000tunnellingIEField, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeUplinkS1cdma2000tunnellingIEFieldValueCodecFieldPath(v *UplinkS1cdma2000tunnellingIEFieldValueCodec) *aper.Path {
	return &v.path
}
func BridgeUplinkS1cdma2000tunnellingIEFieldValueCodecMethodEncodeBudgetValue(v UplinkS1cdma2000tunnellingIEFieldValueCodec, a0 UplinkS1cdma2000tunnellingIEField, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeUplinkS1cdma2000tunnellingIEFieldValueCodecMethodEncodeChanged(v UplinkS1cdma2000tunnellingIEFieldValueCodec, a0 UplinkS1cdma2000tunnellingIEField, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeUplinkS1cdma2000tunnellingIETableMethodInfoCdma2000HORequiredIndication(v UplinkS1cdma2000tunnellingIETable) s00.FieldInfo {
	return v.infoCdma2000HORequiredIndication()
}
func BridgeUplinkS1cdma2000tunnellingIETableMethodInfoCdma2000OneXRAND(v UplinkS1cdma2000tunnellingIETable) s00.FieldInfo {
	return v.infoCdma2000OneXRAND()
}
func BridgeUplinkS1cdma2000tunnellingIETableMethodInfoCdma2000OneXSRVCCInfo(v UplinkS1cdma2000tunnellingIETable) s00.FieldInfo {
	return v.infoCdma2000OneXSRVCCInfo()
}
func BridgeUplinkS1cdma2000tunnellingIETableMethodInfoCdma2000PDU(v UplinkS1cdma2000tunnellingIETable) s00.FieldInfo {
	return v.infoCdma2000PDU()
}
func BridgeUplinkS1cdma2000tunnellingIETableMethodInfoCdma2000RATType(v UplinkS1cdma2000tunnellingIETable) s00.FieldInfo {
	return v.infoCdma2000RATType()
}
func BridgeUplinkS1cdma2000tunnellingIETableMethodInfoCdma2000SectorID(v UplinkS1cdma2000tunnellingIETable) s00.FieldInfo {
	return v.infoCdma2000SectorID()
}
func BridgeUplinkS1cdma2000tunnellingIETableMethodInfoENBUES1APID(v UplinkS1cdma2000tunnellingIETable) s00.FieldInfo {
	return v.infoENBUES1APID()
}
func BridgeUplinkS1cdma2000tunnellingIETableMethodInfoEUTRANRoundTripDelayEstimationInfo(v UplinkS1cdma2000tunnellingIETable) s00.FieldInfo {
	return v.infoEUTRANRoundTripDelayEstimationInfo()
}
func BridgeUplinkS1cdma2000tunnellingIETableMethodInfoMMEUES1APID(v UplinkS1cdma2000tunnellingIETable) s00.FieldInfo {
	return v.infoMMEUES1APID()
}
func BridgeUplinkS1cdma2000tunnellingIEValueERABIEContainerListAPERValueFieldContext(v *UplinkS1cdma2000tunnellingIEValueERABIEContainerListAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeUplinkS1cdma2000tunnellingIEValueERABIEContainerListAPERValueFieldReceived(v *UplinkS1cdma2000tunnellingIEValueERABIEContainerListAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeUplinkS1cdma2000tunnellingIEValueERABIEContainerListAPERValueFieldReplay(v *UplinkS1cdma2000tunnellingIEValueERABIEContainerListAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeUplinkS1cdma2000tunnellingIEValueERABIEContainerListAPERValueFieldWithoutReplay(v *UplinkS1cdma2000tunnellingIEValueERABIEContainerListAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeUplinkS1cdma2000tunnellingIEValueERABIEContainerListValueCodecFieldCapture(v *UplinkS1cdma2000tunnellingIEValueERABIEContainerListValueCodec) *func(UplinkS1cdma2000tunnellingIEValueERABIEContainerList, aper.DecodeState) (UplinkS1cdma2000tunnellingIEValueERABIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgeUplinkS1cdma2000tunnellingIEValueERABIEContainerListValueCodecFieldCompare(v *UplinkS1cdma2000tunnellingIEValueERABIEContainerListValueCodec) *func(UplinkS1cdma2000tunnellingIEValueERABIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeUplinkS1cdma2000tunnellingIEValueERABIEContainerListValueCodecFieldContext(v *UplinkS1cdma2000tunnellingIEValueERABIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeUplinkS1cdma2000tunnellingIEValueERABIEContainerListValueCodecFieldDecode(v *UplinkS1cdma2000tunnellingIEValueERABIEContainerListValueCodec) *func([]byte, aper.DecodeState) (UplinkS1cdma2000tunnellingIEValueERABIEContainerList, error) {
	return &v.decode
}
func BridgeUplinkS1cdma2000tunnellingIEValueERABIEContainerListValueCodecFieldEncode(v *UplinkS1cdma2000tunnellingIEValueERABIEContainerListValueCodec) *func(UplinkS1cdma2000tunnellingIEValueERABIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeUplinkS1cdma2000tunnellingIEValueERABIEContainerListValueCodecFieldPath(v *UplinkS1cdma2000tunnellingIEValueERABIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgeUplinkS1cdma2000tunnellingIEValueERABIEContainerListValueCodecMethodEncodeBudgetValue(v UplinkS1cdma2000tunnellingIEValueERABIEContainerListValueCodec, a0 UplinkS1cdma2000tunnellingIEValueERABIEContainerList, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeUplinkS1cdma2000tunnellingIEValueERABIEContainerListValueCodecMethodEncodeChanged(v UplinkS1cdma2000tunnellingIEValueERABIEContainerListValueCodec, a0 UplinkS1cdma2000tunnellingIEValueERABIEContainerList, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeUplinkS1cdma2000tunnellingIEValueFieldId(v *UplinkS1cdma2000tunnellingIEValue) *s00.ProtocolIEID {
	return &v.id
}
func BridgeUplinkS1cdma2000tunnellingIEValueFieldIsOpaque(v *UplinkS1cdma2000tunnellingIEValue) *bool {
	return &v.isOpaque
}
func BridgeUplinkS1cdma2000tunnellingIEValueFieldOpaque(v *UplinkS1cdma2000tunnellingIEValue) *aper.OpaqueOpenType {
	return &v.opaque
}
func BridgeUplinkS1cdma2000tunnellingIEValueFieldReceived(v *UplinkS1cdma2000tunnellingIEValue) *aper.WireSpan {
	return &v.received
}
func BridgeUplinkS1cdma2000tunnellingIEValueFieldReplay(v *UplinkS1cdma2000tunnellingIEValue) *aper.Snapshot {
	return &v.replay
}
func BridgeUplinkS1cdma2000tunnellingIEValueFieldRowCdma2000HORequiredIndication(v *UplinkS1cdma2000tunnellingIEValue) **s00.Cdma2000HORequiredIndication {
	return &v.rowCdma2000HORequiredIndication
}
func BridgeUplinkS1cdma2000tunnellingIEValueFieldRowCdma2000OneXRAND(v *UplinkS1cdma2000tunnellingIEValue) **s00.Cdma2000OneXRAND {
	return &v.rowCdma2000OneXRAND
}
func BridgeUplinkS1cdma2000tunnellingIEValueFieldRowCdma2000OneXSRVCCInfo(v *UplinkS1cdma2000tunnellingIEValue) **s14.Cdma2000OneXSRVCCInfo {
	return &v.rowCdma2000OneXSRVCCInfo
}
func BridgeUplinkS1cdma2000tunnellingIEValueFieldRowCdma2000PDU(v *UplinkS1cdma2000tunnellingIEValue) **s00.Cdma2000PDU {
	return &v.rowCdma2000PDU
}
func BridgeUplinkS1cdma2000tunnellingIEValueFieldRowCdma2000RATType(v *UplinkS1cdma2000tunnellingIEValue) **s00.Cdma2000RATType {
	return &v.rowCdma2000RATType
}
func BridgeUplinkS1cdma2000tunnellingIEValueFieldRowCdma2000SectorID(v *UplinkS1cdma2000tunnellingIEValue) **s00.Cdma2000SectorID {
	return &v.rowCdma2000SectorID
}
func BridgeUplinkS1cdma2000tunnellingIEValueFieldRowENBUES1APID(v *UplinkS1cdma2000tunnellingIEValue) **s00.ENBUES1APID {
	return &v.rowENBUES1APID
}
func BridgeUplinkS1cdma2000tunnellingIEValueFieldRowEUTRANRoundTripDelayEstimationInfo(v *UplinkS1cdma2000tunnellingIEValue) **s00.EUTRANRoundTripDelayEstimationInfo {
	return &v.rowEUTRANRoundTripDelayEstimationInfo
}
func BridgeUplinkS1cdma2000tunnellingIEValueFieldRowMMEUES1APID(v *UplinkS1cdma2000tunnellingIEValue) **s00.MMEUES1APID {
	return &v.rowMMEUES1APID
}
func BridgeUplinkS1cdma2000tunnellingIEValueMethodCaptureSemantics(v UplinkS1cdma2000tunnellingIEValue, a0 aper.SemanticCapture) UplinkS1cdma2000tunnellingIEValue {
	return v.captureSemantics(a0)
}
func BridgeUplinkS1cdma2000tunnellingIEValueMethodCompareSemantics(v UplinkS1cdma2000tunnellingIEValue, a0 aper.SemanticComparison) aper.SemanticComparison {
	return v.compareSemantics(a0)
}
func BridgeUplinkS1cdma2000tunnellingIEValueMethodDecode(v UplinkS1cdma2000tunnellingIEValue, a0 s00.ProtocolIEID, a1 aper.OpaqueOpenType) (UplinkS1cdma2000tunnellingIEValue, error) {
	return v.decode(a0, a1)
}
func BridgeUplinkS1cdma2000tunnellingIEValueMethodEncode(v UplinkS1cdma2000tunnellingIEValue) ([]byte, error) {
	return v.encode()
}
func BridgeUplinkS1cdma2000tunnellingIEValueMethodEncodeFresh(v UplinkS1cdma2000tunnellingIEValue, a0 bool, a1 *aper.DecodeBudget) ([]byte, error) {
	return v.encodeFresh(a0, a1)
}
func BridgeUplinkS1cdma2000tunnellingIEValueMethodMatchesID(v UplinkS1cdma2000tunnellingIEValue, a0 s00.ProtocolIEID, a1 ...*aper.DecodeBudget) bool {
	return v.matchesID(a0, a1...)
}
func BridgeUplinkS1cdma2000tunnellingIEValueMethodReason(v UplinkS1cdma2000tunnellingIEValue, a0 s00.ProtocolIEID) aper.OpaqueReason {
	return v.reason(a0)
}
func BridgeUplinkS1cdma2000tunnellingIEValueMethodRule(v UplinkS1cdma2000tunnellingIEValue) aper.SourceRule {
	return v.rule()
}
func BridgeUplinkS1cdma2000tunnellingIEValueProtocolErrorIEContainerListAPERValueFieldContext(v *UplinkS1cdma2000tunnellingIEValueProtocolErrorIEContainerListAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeUplinkS1cdma2000tunnellingIEValueProtocolErrorIEContainerListAPERValueFieldReceived(v *UplinkS1cdma2000tunnellingIEValueProtocolErrorIEContainerListAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeUplinkS1cdma2000tunnellingIEValueProtocolErrorIEContainerListAPERValueFieldReplay(v *UplinkS1cdma2000tunnellingIEValueProtocolErrorIEContainerListAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeUplinkS1cdma2000tunnellingIEValueProtocolErrorIEContainerListAPERValueFieldWithoutReplay(v *UplinkS1cdma2000tunnellingIEValueProtocolErrorIEContainerListAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeUplinkS1cdma2000tunnellingIEValueProtocolErrorIEContainerListValueCodecFieldCapture(v *UplinkS1cdma2000tunnellingIEValueProtocolErrorIEContainerListValueCodec) *func(UplinkS1cdma2000tunnellingIEValueProtocolErrorIEContainerList, aper.DecodeState) (UplinkS1cdma2000tunnellingIEValueProtocolErrorIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgeUplinkS1cdma2000tunnellingIEValueProtocolErrorIEContainerListValueCodecFieldCompare(v *UplinkS1cdma2000tunnellingIEValueProtocolErrorIEContainerListValueCodec) *func(UplinkS1cdma2000tunnellingIEValueProtocolErrorIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeUplinkS1cdma2000tunnellingIEValueProtocolErrorIEContainerListValueCodecFieldContext(v *UplinkS1cdma2000tunnellingIEValueProtocolErrorIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeUplinkS1cdma2000tunnellingIEValueProtocolErrorIEContainerListValueCodecFieldDecode(v *UplinkS1cdma2000tunnellingIEValueProtocolErrorIEContainerListValueCodec) *func([]byte, aper.DecodeState) (UplinkS1cdma2000tunnellingIEValueProtocolErrorIEContainerList, error) {
	return &v.decode
}
func BridgeUplinkS1cdma2000tunnellingIEValueProtocolErrorIEContainerListValueCodecFieldEncode(v *UplinkS1cdma2000tunnellingIEValueProtocolErrorIEContainerListValueCodec) *func(UplinkS1cdma2000tunnellingIEValueProtocolErrorIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeUplinkS1cdma2000tunnellingIEValueProtocolErrorIEContainerListValueCodecFieldPath(v *UplinkS1cdma2000tunnellingIEValueProtocolErrorIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgeUplinkS1cdma2000tunnellingIEValueProtocolErrorIEContainerListValueCodecMethodEncodeBudgetValue(v UplinkS1cdma2000tunnellingIEValueProtocolErrorIEContainerListValueCodec, a0 UplinkS1cdma2000tunnellingIEValueProtocolErrorIEContainerList, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeUplinkS1cdma2000tunnellingIEValueProtocolErrorIEContainerListValueCodecMethodEncodeChanged(v UplinkS1cdma2000tunnellingIEValueProtocolErrorIEContainerListValueCodec, a0 UplinkS1cdma2000tunnellingIEValueProtocolErrorIEContainerList, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeUplinkS1cdma2000tunnellingIEValueProtocolIEContainerListAPERValueFieldContext(v *UplinkS1cdma2000tunnellingIEValueProtocolIEContainerListAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeUplinkS1cdma2000tunnellingIEValueProtocolIEContainerListAPERValueFieldReceived(v *UplinkS1cdma2000tunnellingIEValueProtocolIEContainerListAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeUplinkS1cdma2000tunnellingIEValueProtocolIEContainerListAPERValueFieldReplay(v *UplinkS1cdma2000tunnellingIEValueProtocolIEContainerListAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeUplinkS1cdma2000tunnellingIEValueProtocolIEContainerListAPERValueFieldWithoutReplay(v *UplinkS1cdma2000tunnellingIEValueProtocolIEContainerListAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeUplinkS1cdma2000tunnellingIEValueProtocolIEContainerListValueCodecFieldCapture(v *UplinkS1cdma2000tunnellingIEValueProtocolIEContainerListValueCodec) *func(UplinkS1cdma2000tunnellingIEValueProtocolIEContainerList, aper.DecodeState) (UplinkS1cdma2000tunnellingIEValueProtocolIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgeUplinkS1cdma2000tunnellingIEValueProtocolIEContainerListValueCodecFieldCompare(v *UplinkS1cdma2000tunnellingIEValueProtocolIEContainerListValueCodec) *func(UplinkS1cdma2000tunnellingIEValueProtocolIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeUplinkS1cdma2000tunnellingIEValueProtocolIEContainerListValueCodecFieldContext(v *UplinkS1cdma2000tunnellingIEValueProtocolIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeUplinkS1cdma2000tunnellingIEValueProtocolIEContainerListValueCodecFieldDecode(v *UplinkS1cdma2000tunnellingIEValueProtocolIEContainerListValueCodec) *func([]byte, aper.DecodeState) (UplinkS1cdma2000tunnellingIEValueProtocolIEContainerList, error) {
	return &v.decode
}
func BridgeUplinkS1cdma2000tunnellingIEValueProtocolIEContainerListValueCodecFieldEncode(v *UplinkS1cdma2000tunnellingIEValueProtocolIEContainerListValueCodec) *func(UplinkS1cdma2000tunnellingIEValueProtocolIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeUplinkS1cdma2000tunnellingIEValueProtocolIEContainerListValueCodecFieldPath(v *UplinkS1cdma2000tunnellingIEValueProtocolIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgeUplinkS1cdma2000tunnellingIEValueProtocolIEContainerListValueCodecMethodEncodeBudgetValue(v UplinkS1cdma2000tunnellingIEValueProtocolIEContainerListValueCodec, a0 UplinkS1cdma2000tunnellingIEValueProtocolIEContainerList, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeUplinkS1cdma2000tunnellingIEValueProtocolIEContainerListValueCodecMethodEncodeChanged(v UplinkS1cdma2000tunnellingIEValueProtocolIEContainerListValueCodec, a0 UplinkS1cdma2000tunnellingIEValueProtocolIEContainerList, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeUplinkS1cdma2000tunnellingMMEUES1APIDIEBindingFieldCodec(v *UplinkS1cdma2000tunnellingMMEUES1APIDIEBinding) *s01.MMEUES1APIDValueCodec {
	return &v.codec
}
func BridgeUplinkS1cdma2000tunnellingMMEUES1APIDIEBindingFieldGet(v *UplinkS1cdma2000tunnellingMMEUES1APIDIEBinding) *func(*UplinkS1cdma2000tunnellingIEValue) (*s00.MMEUES1APID, bool) {
	return &v.get
}
func BridgeUplinkS1cdma2000tunnellingMMEUES1APIDIEBindingFieldInfo(v *UplinkS1cdma2000tunnellingMMEUES1APIDIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeUplinkS1cdma2000tunnellingMMEUES1APIDIEBindingFieldInject(v *UplinkS1cdma2000tunnellingMMEUES1APIDIEBinding) *func(s00.MMEUES1APID) UplinkS1cdma2000tunnellingIEValue {
	return &v.inject
}
func BridgeUserLocationInformationExtIETableMethodInfoLTENTNTAIInformation(v UserLocationInformationExtIETable) s00.ExtensionInfo {
	return v.infoLTENTNTAIInformation()
}
func BridgeUserLocationInformationExtIETableMethodInfoPSCellInformation(v UserLocationInformationExtIETable) s00.ExtensionInfo {
	return v.infoPSCellInformation()
}
func BridgeUserLocationInformationExtIEsExtContainerAPERValueFieldContext(v *UserLocationInformationExtIEsExtContainerAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeUserLocationInformationExtIEsExtContainerAPERValueFieldReceived(v *UserLocationInformationExtIEsExtContainerAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeUserLocationInformationExtIEsExtContainerAPERValueFieldReplay(v *UserLocationInformationExtIEsExtContainerAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeUserLocationInformationExtIEsExtContainerAPERValueFieldWithoutReplay(v *UserLocationInformationExtIEsExtContainerAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeUserLocationInformationExtIEsExtContainerValueCodecFieldCapture(v *UserLocationInformationExtIEsExtContainerValueCodec) *func(UserLocationInformationExtIEsExtContainer, aper.DecodeState) (UserLocationInformationExtIEsExtContainer, aper.Snapshot) {
	return &v.capture
}
func BridgeUserLocationInformationExtIEsExtContainerValueCodecFieldCompare(v *UserLocationInformationExtIEsExtContainerValueCodec) *func(UserLocationInformationExtIEsExtContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeUserLocationInformationExtIEsExtContainerValueCodecFieldContext(v *UserLocationInformationExtIEsExtContainerValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeUserLocationInformationExtIEsExtContainerValueCodecFieldDecode(v *UserLocationInformationExtIEsExtContainerValueCodec) *func([]byte, aper.DecodeState) (UserLocationInformationExtIEsExtContainer, error) {
	return &v.decode
}
func BridgeUserLocationInformationExtIEsExtContainerValueCodecFieldEncode(v *UserLocationInformationExtIEsExtContainerValueCodec) *func(UserLocationInformationExtIEsExtContainer, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeUserLocationInformationExtIEsExtContainerValueCodecFieldPath(v *UserLocationInformationExtIEsExtContainerValueCodec) *aper.Path {
	return &v.path
}
func BridgeUserLocationInformationExtIEsExtContainerValueCodecMethodEncodeBudgetValue(v UserLocationInformationExtIEsExtContainerValueCodec, a0 UserLocationInformationExtIEsExtContainer, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeUserLocationInformationExtIEsExtContainerValueCodecMethodEncodeChanged(v UserLocationInformationExtIEsExtContainerValueCodec, a0 UserLocationInformationExtIEsExtContainer, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeUserLocationInformationExtIEsExtFieldAPERValueFieldContext(v *UserLocationInformationExtIEsExtFieldAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeUserLocationInformationExtIEsExtFieldAPERValueFieldReceived(v *UserLocationInformationExtIEsExtFieldAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeUserLocationInformationExtIEsExtFieldAPERValueFieldReplay(v *UserLocationInformationExtIEsExtFieldAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeUserLocationInformationExtIEsExtFieldAPERValueFieldWithoutReplay(v *UserLocationInformationExtIEsExtFieldAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeUserLocationInformationExtIEsExtFieldFieldReceived(v *UserLocationInformationExtIEsExtField) *aper.CompletePadding {
	return &v.received
}
func BridgeUserLocationInformationExtIEsExtFieldFieldReplay(v *UserLocationInformationExtIEsExtField) *aper.Snapshot {
	return &v.replay
}
func BridgeUserLocationInformationExtIEsExtFieldFieldStream(v *UserLocationInformationExtIEsExtField) *aper.WireSpan {
	return &v.stream
}
func BridgeUserLocationInformationExtIEsExtFieldFieldWithoutReplay(v *UserLocationInformationExtIEsExtField) *bool {
	return &v.withoutReplay
}
func BridgeUserLocationInformationExtIEsExtFieldMethodMarshalAPERTo(v *UserLocationInformationExtIEsExtField, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeUserLocationInformationExtIEsExtFieldMethodUnmarshalAPERFrom(v *UserLocationInformationExtIEsExtField, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeUserLocationInformationExtIEsExtFieldValueCodecFieldCapture(v *UserLocationInformationExtIEsExtFieldValueCodec) *func(UserLocationInformationExtIEsExtField, aper.DecodeState) (UserLocationInformationExtIEsExtField, aper.Snapshot) {
	return &v.capture
}
func BridgeUserLocationInformationExtIEsExtFieldValueCodecFieldCompare(v *UserLocationInformationExtIEsExtFieldValueCodec) *func(UserLocationInformationExtIEsExtField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeUserLocationInformationExtIEsExtFieldValueCodecFieldContext(v *UserLocationInformationExtIEsExtFieldValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeUserLocationInformationExtIEsExtFieldValueCodecFieldDecode(v *UserLocationInformationExtIEsExtFieldValueCodec) *func([]byte, aper.DecodeState) (UserLocationInformationExtIEsExtField, error) {
	return &v.decode
}
func BridgeUserLocationInformationExtIEsExtFieldValueCodecFieldEncode(v *UserLocationInformationExtIEsExtFieldValueCodec) *func(UserLocationInformationExtIEsExtField, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeUserLocationInformationExtIEsExtFieldValueCodecFieldPath(v *UserLocationInformationExtIEsExtFieldValueCodec) *aper.Path {
	return &v.path
}
func BridgeUserLocationInformationExtIEsExtFieldValueCodecMethodEncodeBudgetValue(v UserLocationInformationExtIEsExtFieldValueCodec, a0 UserLocationInformationExtIEsExtField, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeUserLocationInformationExtIEsExtFieldValueCodecMethodEncodeChanged(v UserLocationInformationExtIEsExtFieldValueCodec, a0 UserLocationInformationExtIEsExtField, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeUserLocationInformationExtIEsIEFieldFieldReceived(v *UserLocationInformationExtIEsIEField) *aper.CompletePadding {
	return &v.received
}
func BridgeUserLocationInformationExtIEsIEFieldFieldReplay(v *UserLocationInformationExtIEsIEField) *aper.Snapshot {
	return &v.replay
}
func BridgeUserLocationInformationExtIEsIEFieldFieldStream(v *UserLocationInformationExtIEsIEField) *aper.WireSpan {
	return &v.stream
}
func BridgeUserLocationInformationExtIEsIEFieldFieldWithoutReplay(v *UserLocationInformationExtIEsIEField) *bool {
	return &v.withoutReplay
}
func BridgeUserLocationInformationExtIEsIEFieldMethodMarshalAPERTo(v *UserLocationInformationExtIEsIEField, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeUserLocationInformationExtIEsIEFieldMethodUnmarshalAPERFrom(v *UserLocationInformationExtIEsIEField, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeUserLocationInformationExtIEsLTENTNTAIInformationExtBindingFieldCodec(v *UserLocationInformationExtIEsLTENTNTAIInformationExtBinding) *s18.LTENTNTAIInformationValueCodec {
	return &v.codec
}
func BridgeUserLocationInformationExtIEsLTENTNTAIInformationExtBindingFieldGet(v *UserLocationInformationExtIEsLTENTNTAIInformationExtBinding) *func(*UserLocationInformationExtIEsValue) (*s18.LTENTNTAIInformation, bool) {
	return &v.get
}
func BridgeUserLocationInformationExtIEsLTENTNTAIInformationExtBindingFieldInfo(v *UserLocationInformationExtIEsLTENTNTAIInformationExtBinding) *s00.ExtensionInfo {
	return &v.info
}
func BridgeUserLocationInformationExtIEsLTENTNTAIInformationExtBindingFieldInject(v *UserLocationInformationExtIEsLTENTNTAIInformationExtBinding) *func(s18.LTENTNTAIInformation) UserLocationInformationExtIEsValue {
	return &v.inject
}
func BridgeUserLocationInformationExtIEsPSCellInformationExtBindingFieldCodec(v *UserLocationInformationExtIEsPSCellInformationExtBinding) *s20.PSCellInformationValueCodec {
	return &v.codec
}
func BridgeUserLocationInformationExtIEsPSCellInformationExtBindingFieldGet(v *UserLocationInformationExtIEsPSCellInformationExtBinding) *func(*UserLocationInformationExtIEsValue) (*s20.PSCellInformation, bool) {
	return &v.get
}
func BridgeUserLocationInformationExtIEsPSCellInformationExtBindingFieldInfo(v *UserLocationInformationExtIEsPSCellInformationExtBinding) *s00.ExtensionInfo {
	return &v.info
}
func BridgeUserLocationInformationExtIEsPSCellInformationExtBindingFieldInject(v *UserLocationInformationExtIEsPSCellInformationExtBinding) *func(s20.PSCellInformation) UserLocationInformationExtIEsValue {
	return &v.inject
}
func BridgeUserLocationInformationExtIEsValueFieldId(v *UserLocationInformationExtIEsValue) *s00.ProtocolIEID {
	return &v.id
}
func BridgeUserLocationInformationExtIEsValueFieldIsOpaque(v *UserLocationInformationExtIEsValue) *bool {
	return &v.isOpaque
}
func BridgeUserLocationInformationExtIEsValueFieldOpaque(v *UserLocationInformationExtIEsValue) *aper.OpaqueOpenType {
	return &v.opaque
}
func BridgeUserLocationInformationExtIEsValueFieldReceived(v *UserLocationInformationExtIEsValue) *aper.WireSpan {
	return &v.received
}
func BridgeUserLocationInformationExtIEsValueFieldReplay(v *UserLocationInformationExtIEsValue) *aper.Snapshot {
	return &v.replay
}
func BridgeUserLocationInformationExtIEsValueFieldRowLTENTNTAIInformation(v *UserLocationInformationExtIEsValue) **s18.LTENTNTAIInformation {
	return &v.rowLTENTNTAIInformation
}
func BridgeUserLocationInformationExtIEsValueFieldRowPSCellInformation(v *UserLocationInformationExtIEsValue) **s20.PSCellInformation {
	return &v.rowPSCellInformation
}
func BridgeUserLocationInformationExtIEsValueMethodCaptureSemantics(v UserLocationInformationExtIEsValue, a0 aper.SemanticCapture) UserLocationInformationExtIEsValue {
	return v.captureSemantics(a0)
}
func BridgeUserLocationInformationExtIEsValueMethodCompareSemantics(v UserLocationInformationExtIEsValue, a0 aper.SemanticComparison) aper.SemanticComparison {
	return v.compareSemantics(a0)
}
func BridgeUserLocationInformationExtIEsValueMethodDecode(v UserLocationInformationExtIEsValue, a0 s00.ProtocolIEID, a1 aper.OpaqueOpenType) (UserLocationInformationExtIEsValue, error) {
	return v.decode(a0, a1)
}
func BridgeUserLocationInformationExtIEsValueMethodEncode(v UserLocationInformationExtIEsValue) ([]byte, error) {
	return v.encode()
}
func BridgeUserLocationInformationExtIEsValueMethodEncodeFresh(v UserLocationInformationExtIEsValue, a0 bool, a1 *aper.DecodeBudget) ([]byte, error) {
	return v.encodeFresh(a0, a1)
}
func BridgeUserLocationInformationExtIEsValueMethodMatchesID(v UserLocationInformationExtIEsValue, a0 s00.ProtocolIEID, a1 ...*aper.DecodeBudget) bool {
	return v.matchesID(a0, a1...)
}
func BridgeUserLocationInformationExtIEsValueMethodReason(v UserLocationInformationExtIEsValue, a0 s00.ProtocolIEID) aper.OpaqueReason {
	return v.reason(a0)
}
func BridgeUserLocationInformationExtIEsValueMethodRule(v UserLocationInformationExtIEsValue) aper.SourceRule {
	return v.rule()
}
func BridgeValidationReportFieldBudget(v *ValidationReport) **aper.DecodeBudget { return &v.budget }
func BridgeValidationReportFieldErr(v *ValidationReport) *error                 { return &v.err }
func BridgeValidationReportMethodAddDeferred(v *ValidationReport, a0 s00.DeferredCondition) {
	v.addDeferred(a0)
}
func BridgeValidationReportMethodAddIssue(v *ValidationReport, a0 ValidationIssue) { v.addIssue(a0) }
func BridgeValidationReportMethodAddUnchecked(v *ValidationReport, a0 aper.Location) {
	v.addUnchecked(a0)
}
func BridgeValidationReportMethodReserveReport(v *ValidationReport, a0 aper.Location) error {
	return v.reserveReport(a0)
}
