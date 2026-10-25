// Code generated from the pinned S1AP source closure. DO NOT EDIT.

// Package s47 implements the github.com/gomaja/go-asn1/telecom/lte/s1ap root package.
package s47

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
	s16 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s16"
	s17 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s17"
	s18 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s18"
	s19 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s19"
	s20 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s20"
	s21 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s21"
	s22 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s22"
	s24 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s24"
	s25 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s25"
	s26 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s26"
	s28 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s28"
	s29 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s29"
	s30 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s30"
	s31 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s31"
	s32 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s32"
	s35 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s35"
	s37 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s37"
	s42 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s42"
	s46 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s46"
	runtime "github.com/gomaja/go-asn1/telecom/lte/s1ap/runtime"
	aper "github.com/gomaja/go-asn1/telecom/lte/s1ap/runtime/aper"
)

func NewPrivateMessage(fields s25.PrivateMessageIEsValuePrivateIEContainer, options ...aper.BuildOption) (s26.PrivateMessage, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s26.PrivateMessage{}, aper.OperationError(err, "PrivateMessage")
	}
	bb := aper.NewBudgetBuffer(budget)
	if err := aper.ChargeSlice[s25.PrivateMessageIEsValuePrivateIEField](bb, uint64(len(fields))); err != nil {
		return s26.PrivateMessage{}, aper.OperationError(err, "PrivateMessage")
	}
	v := s26.PrivateMessage{PrivateIEs: append(s25.PrivateMessageIEsValuePrivateIEContainer(nil), fields...)}
	report, err := BridgeValidatePrivateMessageBudget(&v, budget)
	if err != nil {
		return s26.PrivateMessage{}, aper.OperationError(err, "PrivateMessage")
	}
	if *s21.BridgeValidationReportFieldErr(&report) != nil {
		return s26.PrivateMessage{}, aper.OperationError(*s21.BridgeValidationReportFieldErr(&report), "PrivateMessage")
	}
	if issues := s21.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return s26.PrivateMessage{}, aper.OperationError(&s21.BuildError{Issues: issues}, "PrivateMessage")
	}
	if _, err := s26.BridgePrivateMessageMethodMarshalAPERBudget(&v, budget, false); err != nil {
		return s26.PrivateMessage{}, aper.OperationError(fmt.Errorf("%s %w", "PrivateMessage.privateIEs:", err), "PrivateMessage")
	}
	return v, aper.OperationError(nil, "PrivateMessage")
}
func BridgeImmediateMDTExtIEsValueCaptureS1APProtocolExtensionContainer(v *ImmediateMDTExtIEsExtContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeImmediateMDTExtIEsValueCaptureS1APProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeImmediateMDTExtIEsValueCompareS1APProtocolExtensionContainer(v *ImmediateMDTExtIEsExtContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeImmediateMDTExtIEsValueCompareS1APProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeLoggedMDTExtIEsValueCaptureS1APProtocolExtensionContainer(v *LoggedMDTExtIEsExtContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeLoggedMDTExtIEsValueCaptureS1APProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeLoggedMDTExtIEsValueCompareS1APProtocolExtensionContainer(v *LoggedMDTExtIEsExtContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeLoggedMDTExtIEsValueCompareS1APProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgePathSwitchRequestAcknowledgeIEValueCaptureS1APProtocolIEContainer(v *s46.PathSwitchRequestAcknowledgeIEContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgePathSwitchRequestAcknowledgeIEValueCaptureS1APProtocolIEField(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgePathSwitchRequestAcknowledgeIEValueCompareS1APProtocolIEContainer(v *s46.PathSwitchRequestAcknowledgeIEContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgePathSwitchRequestAcknowledgeIEValueCompareS1APProtocolIEField(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeTraceActivationExtIEsValueCaptureS1APProtocolExtensionContainer(v *TraceActivationExtIEsExtContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeTraceActivationExtIEsValueCaptureS1APProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeTraceActivationExtIEsValueCompareS1APProtocolExtensionContainer(v *TraceActivationExtIEsExtContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeTraceActivationExtIEsValueCompareS1APProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeUEContextModificationRequestIEValueCaptureS1APProtocolIEContainer(v *s46.UEContextModificationRequestIEContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeUEContextModificationRequestIEValueCaptureS1APProtocolIEField(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeUEContextModificationRequestIEValueCompareS1APProtocolIEContainer(v *s46.UEContextModificationRequestIEContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeUEContextModificationRequestIEValueCompareS1APProtocolIEField(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeWLANMeasurementConfigurationExtIEsValueCaptureS1APProtocolExtensionContainer(v *s12.WLANMeasurementConfigurationExtIEsExtContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeWLANMeasurementConfigurationExtIEsValueCaptureS1APProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeWLANMeasurementConfigurationExtIEsValueCompareS1APProtocolExtensionContainer(v *s12.WLANMeasurementConfigurationExtIEsExtContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeWLANMeasurementConfigurationExtIEsValueCompareS1APProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}

// ImmediateMDTExtIEsExtContainer is ProtocolExtensionContainer {{ImmediateMDT-ExtIEs}} of TS 36.413: a list of ImmediateMDTExtIEsExtField values.
type ImmediateMDTExtIEsExtContainer []ImmediateMDTExtIEsExtField

// LoggedMDTExtIEsExtContainer is ProtocolExtensionContainer {{LoggedMDT-ExtIEs}} of TS 36.413: a list of LoggedMDTExtIEsExtField values.
type LoggedMDTExtIEsExtContainer []LoggedMDTExtIEsExtField

// TraceActivationExtIEsExtContainer is ProtocolExtensionContainer {{TraceActivation-ExtIEs}} of TS 36.413: a list of TraceActivationExtIEsExtField values.
type TraceActivationExtIEsExtContainer []TraceActivationExtIEsExtField

// ImmediateMDTExtIEsExtField is ProtocolExtensionField {{ImmediateMDT-ExtIEs}} of TS 36.413: an extension field.
type ImmediateMDTExtIEsExtField struct {
	withoutReplay  bool
	replay         aper.Snapshot
	stream         aper.WireSpan
	Id             s00.ProtocolExtensionID
	Criticality    s00.Criticality
	ExtensionValue ImmediateMDTExtIEsValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ImmediateMDTExtIEsExtField) WithoutReplay() ImmediateMDTExtIEsExtField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *ImmediateMDTExtIEsExtField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *ImmediateMDTExtIEsExtField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
func (v *ImmediateMDTExtIEsExtField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolExtensionField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = ImmediateMDTExtIEsExtField{}
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
	var zero ImmediateMDTExtIEsValue

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

// LoggedMDTExtIEsExtField is ProtocolExtensionField {{LoggedMDT-ExtIEs}} of TS 36.413: an extension field.
type LoggedMDTExtIEsExtField struct {
	withoutReplay  bool
	replay         aper.Snapshot
	stream         aper.WireSpan
	Id             s00.ProtocolExtensionID
	Criticality    s00.Criticality
	ExtensionValue LoggedMDTExtIEsValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v LoggedMDTExtIEsExtField) WithoutReplay() LoggedMDTExtIEsExtField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *LoggedMDTExtIEsExtField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *LoggedMDTExtIEsExtField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
func (v *LoggedMDTExtIEsExtField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolExtensionField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = LoggedMDTExtIEsExtField{}
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
	var zero LoggedMDTExtIEsValue

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

// TraceActivationExtIEsExtField is ProtocolExtensionField {{TraceActivation-ExtIEs}} of TS 36.413: an extension field.
type TraceActivationExtIEsExtField struct {
	withoutReplay  bool
	replay         aper.Snapshot
	stream         aper.WireSpan
	Id             s00.ProtocolExtensionID
	Criticality    s00.Criticality
	ExtensionValue TraceActivationExtIEsValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v TraceActivationExtIEsExtField) WithoutReplay() TraceActivationExtIEsExtField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *TraceActivationExtIEsExtField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *TraceActivationExtIEsExtField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
func (v *TraceActivationExtIEsExtField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolExtensionField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = TraceActivationExtIEsExtField{}
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
	var zero TraceActivationExtIEsValue

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

// ImmediateMDTExtIEsM3ConfigurationExtBinding binds M3Configuration to the ImmediateMDT-ExtIEs object set of TS 36.413.
type ImmediateMDTExtIEsM3ConfigurationExtBinding struct {
	info   s00.ExtensionInfo
	codec  s19.M3ConfigurationValueCodec
	inject func(s19.M3Configuration,

	) ImmediateMDTExtIEsValue

	get func(*ImmediateMDTExtIEsValue,

	) (*s19.M3Configuration,

		bool)
}

// Info returns the source descriptor for this binding.
func (b ImmediateMDTExtIEsM3ConfigurationExtBinding) Info() s00.ExtensionInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b ImmediateMDTExtIEsM3ConfigurationExtBinding) Codec() s19.M3ConfigurationValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b ImmediateMDTExtIEsM3ConfigurationExtBinding) New(value s19.M3Configuration,

) (ImmediateMDTExtIEsExtField, error) {
	if b.inject == nil {
		return ImmediateMDTExtIEsExtField{}, aper.OperationError(fmt.Errorf("unbound extension binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ImmediateMDTExtIEsExtField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s19.BridgeM3ConfigurationValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return ImmediateMDTExtIEsExtField{}, aper.OperationError(fmt.Errorf("extension %d: %w", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return ImmediateMDTExtIEsExtField{}, aper.OperationError(err, "Value.New")
	}
	return ImmediateMDTExtIEsExtField{Id: b.info.ID, Criticality: b.info.Criticality, ExtensionValue: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b ImmediateMDTExtIEsM3ConfigurationExtBinding) Get(field *ImmediateMDTExtIEsExtField) (*s19.M3Configuration,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.ExtensionValue)
}

// ImmediateMDTExtIEsM4ConfigurationExtBinding binds M4Configuration to the ImmediateMDT-ExtIEs object set of TS 36.413.
type ImmediateMDTExtIEsM4ConfigurationExtBinding struct {
	info   s00.ExtensionInfo
	codec  s19.M4ConfigurationValueCodec
	inject func(s19.M4Configuration,

	) ImmediateMDTExtIEsValue

	get func(*ImmediateMDTExtIEsValue,

	) (*s19.M4Configuration,

		bool)
}

// Info returns the source descriptor for this binding.
func (b ImmediateMDTExtIEsM4ConfigurationExtBinding) Info() s00.ExtensionInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b ImmediateMDTExtIEsM4ConfigurationExtBinding) Codec() s19.M4ConfigurationValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b ImmediateMDTExtIEsM4ConfigurationExtBinding) New(value s19.M4Configuration,

) (ImmediateMDTExtIEsExtField, error) {
	if b.inject == nil {
		return ImmediateMDTExtIEsExtField{}, aper.OperationError(fmt.Errorf("unbound extension binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ImmediateMDTExtIEsExtField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s19.BridgeM4ConfigurationValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return ImmediateMDTExtIEsExtField{}, aper.OperationError(fmt.Errorf("extension %d: %w", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return ImmediateMDTExtIEsExtField{}, aper.OperationError(err, "Value.New")
	}
	return ImmediateMDTExtIEsExtField{Id: b.info.ID, Criticality: b.info.Criticality, ExtensionValue: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b ImmediateMDTExtIEsM4ConfigurationExtBinding) Get(field *ImmediateMDTExtIEsExtField) (*s19.M4Configuration,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.ExtensionValue)
}

// ImmediateMDTExtIEsM5ConfigurationExtBinding binds M5Configuration to the ImmediateMDT-ExtIEs object set of TS 36.413.
type ImmediateMDTExtIEsM5ConfigurationExtBinding struct {
	info   s00.ExtensionInfo
	codec  s19.M5ConfigurationValueCodec
	inject func(s19.M5Configuration,

	) ImmediateMDTExtIEsValue

	get func(*ImmediateMDTExtIEsValue,

	) (*s19.M5Configuration,

		bool)
}

// Info returns the source descriptor for this binding.
func (b ImmediateMDTExtIEsM5ConfigurationExtBinding) Info() s00.ExtensionInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b ImmediateMDTExtIEsM5ConfigurationExtBinding) Codec() s19.M5ConfigurationValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b ImmediateMDTExtIEsM5ConfigurationExtBinding) New(value s19.M5Configuration,

) (ImmediateMDTExtIEsExtField, error) {
	if b.inject == nil {
		return ImmediateMDTExtIEsExtField{}, aper.OperationError(fmt.Errorf("unbound extension binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ImmediateMDTExtIEsExtField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s19.BridgeM5ConfigurationValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return ImmediateMDTExtIEsExtField{}, aper.OperationError(fmt.Errorf("extension %d: %w", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return ImmediateMDTExtIEsExtField{}, aper.OperationError(err, "Value.New")
	}
	return ImmediateMDTExtIEsExtField{Id: b.info.ID, Criticality: b.info.Criticality, ExtensionValue: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b ImmediateMDTExtIEsM5ConfigurationExtBinding) Get(field *ImmediateMDTExtIEsExtField) (*s19.M5Configuration,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.ExtensionValue)
}

// ImmediateMDTExtIEsMDTLocationInfoExtBinding binds MDTLocationInfo to the ImmediateMDT-ExtIEs object set of TS 36.413.
type ImmediateMDTExtIEsMDTLocationInfoExtBinding struct {
	info   s00.ExtensionInfo
	codec  s01.MDTLocationInfoValueCodec
	inject func(s00.MDTLocationInfo,

	) ImmediateMDTExtIEsValue

	get func(*ImmediateMDTExtIEsValue,

	) (*s00.MDTLocationInfo,

		bool)
}

// Info returns the source descriptor for this binding.
func (b ImmediateMDTExtIEsMDTLocationInfoExtBinding) Info() s00.ExtensionInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b ImmediateMDTExtIEsMDTLocationInfoExtBinding) Codec() s01.MDTLocationInfoValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b ImmediateMDTExtIEsMDTLocationInfoExtBinding) New(value s00.MDTLocationInfo,

) (ImmediateMDTExtIEsExtField, error) {
	if b.inject == nil {
		return ImmediateMDTExtIEsExtField{}, aper.OperationError(fmt.Errorf("unbound extension binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ImmediateMDTExtIEsExtField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s01.BridgeMDTLocationInfoValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return ImmediateMDTExtIEsExtField{}, aper.OperationError(fmt.Errorf("extension %d: %w", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return ImmediateMDTExtIEsExtField{}, aper.OperationError(err, "Value.New")
	}
	return ImmediateMDTExtIEsExtField{Id: b.info.ID, Criticality: b.info.Criticality, ExtensionValue: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b ImmediateMDTExtIEsMDTLocationInfoExtBinding) Get(field *ImmediateMDTExtIEsExtField) (*s00.MDTLocationInfo,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.ExtensionValue)
}

// ImmediateMDTExtIEsM6ConfigurationExtBinding binds M6Configuration to the ImmediateMDT-ExtIEs object set of TS 36.413.
type ImmediateMDTExtIEsM6ConfigurationExtBinding struct {
	info   s00.ExtensionInfo
	codec  s19.M6ConfigurationValueCodec
	inject func(s19.M6Configuration,

	) ImmediateMDTExtIEsValue

	get func(*ImmediateMDTExtIEsValue,

	) (*s19.M6Configuration,

		bool)
}

// Info returns the source descriptor for this binding.
func (b ImmediateMDTExtIEsM6ConfigurationExtBinding) Info() s00.ExtensionInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b ImmediateMDTExtIEsM6ConfigurationExtBinding) Codec() s19.M6ConfigurationValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b ImmediateMDTExtIEsM6ConfigurationExtBinding) New(value s19.M6Configuration,

) (ImmediateMDTExtIEsExtField, error) {
	if b.inject == nil {
		return ImmediateMDTExtIEsExtField{}, aper.OperationError(fmt.Errorf("unbound extension binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ImmediateMDTExtIEsExtField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s19.BridgeM6ConfigurationValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return ImmediateMDTExtIEsExtField{}, aper.OperationError(fmt.Errorf("extension %d: %w", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return ImmediateMDTExtIEsExtField{}, aper.OperationError(err, "Value.New")
	}
	return ImmediateMDTExtIEsExtField{Id: b.info.ID, Criticality: b.info.Criticality, ExtensionValue: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b ImmediateMDTExtIEsM6ConfigurationExtBinding) Get(field *ImmediateMDTExtIEsExtField) (*s19.M6Configuration,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.ExtensionValue)
}

// ImmediateMDTExtIEsM7ConfigurationExtBinding binds M7Configuration to the ImmediateMDT-ExtIEs object set of TS 36.413.
type ImmediateMDTExtIEsM7ConfigurationExtBinding struct {
	info   s00.ExtensionInfo
	codec  s19.M7ConfigurationValueCodec
	inject func(s19.M7Configuration,

	) ImmediateMDTExtIEsValue

	get func(*ImmediateMDTExtIEsValue,

	) (*s19.M7Configuration,

		bool)
}

// Info returns the source descriptor for this binding.
func (b ImmediateMDTExtIEsM7ConfigurationExtBinding) Info() s00.ExtensionInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b ImmediateMDTExtIEsM7ConfigurationExtBinding) Codec() s19.M7ConfigurationValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b ImmediateMDTExtIEsM7ConfigurationExtBinding) New(value s19.M7Configuration,

) (ImmediateMDTExtIEsExtField, error) {
	if b.inject == nil {
		return ImmediateMDTExtIEsExtField{}, aper.OperationError(fmt.Errorf("unbound extension binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ImmediateMDTExtIEsExtField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s19.BridgeM7ConfigurationValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return ImmediateMDTExtIEsExtField{}, aper.OperationError(fmt.Errorf("extension %d: %w", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return ImmediateMDTExtIEsExtField{}, aper.OperationError(err, "Value.New")
	}
	return ImmediateMDTExtIEsExtField{Id: b.info.ID, Criticality: b.info.Criticality, ExtensionValue: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b ImmediateMDTExtIEsM7ConfigurationExtBinding) Get(field *ImmediateMDTExtIEsExtField) (*s19.M7Configuration,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.ExtensionValue)
}

// ImmediateMDTExtIEsBluetoothMeasurementConfigurationExtBinding binds BluetoothMeasurementConfiguration to the ImmediateMDT-ExtIEs object set of TS 36.413.
type ImmediateMDTExtIEsBluetoothMeasurementConfigurationExtBinding struct {
	info   s00.ExtensionInfo
	codec  s14.BluetoothMeasurementConfigurationValueCodec
	inject func(s14.BluetoothMeasurementConfiguration,

	) ImmediateMDTExtIEsValue

	get func(*ImmediateMDTExtIEsValue,

	) (*s14.BluetoothMeasurementConfiguration,

		bool)
}

// Info returns the source descriptor for this binding.
func (b ImmediateMDTExtIEsBluetoothMeasurementConfigurationExtBinding) Info() s00.ExtensionInfo {
	return b.info
}

// Codec returns the complete value codec for this binding.
func (b ImmediateMDTExtIEsBluetoothMeasurementConfigurationExtBinding) Codec() s14.BluetoothMeasurementConfigurationValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b ImmediateMDTExtIEsBluetoothMeasurementConfigurationExtBinding) New(value s14.BluetoothMeasurementConfiguration,

) (ImmediateMDTExtIEsExtField, error) {
	if b.inject == nil {
		return ImmediateMDTExtIEsExtField{}, aper.OperationError(fmt.Errorf("unbound extension binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ImmediateMDTExtIEsExtField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s14.BridgeBluetoothMeasurementConfigurationValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return ImmediateMDTExtIEsExtField{}, aper.OperationError(fmt.Errorf("extension %d: %w", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return ImmediateMDTExtIEsExtField{}, aper.OperationError(err, "Value.New")
	}
	return ImmediateMDTExtIEsExtField{Id: b.info.ID, Criticality: b.info.Criticality, ExtensionValue: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b ImmediateMDTExtIEsBluetoothMeasurementConfigurationExtBinding) Get(field *ImmediateMDTExtIEsExtField) (*s14.BluetoothMeasurementConfiguration,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.ExtensionValue)
}

// ImmediateMDTExtIEsWLANMeasurementConfigurationExtBinding binds WLANMeasurementConfiguration to the ImmediateMDT-ExtIEs object set of TS 36.413.
type ImmediateMDTExtIEsWLANMeasurementConfigurationExtBinding struct {
	info   s00.ExtensionInfo
	codec  WLANMeasurementConfigurationValueCodec
	inject func(WLANMeasurementConfiguration,

	) ImmediateMDTExtIEsValue

	get func(*ImmediateMDTExtIEsValue,

	) (*WLANMeasurementConfiguration,

		bool)
}

// Info returns the source descriptor for this binding.
func (b ImmediateMDTExtIEsWLANMeasurementConfigurationExtBinding) Info() s00.ExtensionInfo {
	return b.info
}

// Codec returns the complete value codec for this binding.
func (b ImmediateMDTExtIEsWLANMeasurementConfigurationExtBinding) Codec() WLANMeasurementConfigurationValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b ImmediateMDTExtIEsWLANMeasurementConfigurationExtBinding) New(value WLANMeasurementConfiguration,

) (ImmediateMDTExtIEsExtField, error) {
	if b.inject == nil {
		return ImmediateMDTExtIEsExtField{}, aper.OperationError(fmt.Errorf("unbound extension binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ImmediateMDTExtIEsExtField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := b.codec.encode(value, false, budget); err != nil {
		return ImmediateMDTExtIEsExtField{}, aper.OperationError(fmt.Errorf("extension %d: %w", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return ImmediateMDTExtIEsExtField{}, aper.OperationError(err, "Value.New")
	}
	return ImmediateMDTExtIEsExtField{Id: b.info.ID, Criticality: b.info.Criticality, ExtensionValue: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b ImmediateMDTExtIEsWLANMeasurementConfigurationExtBinding) Get(field *ImmediateMDTExtIEsExtField) (*WLANMeasurementConfiguration,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.ExtensionValue)
}

// WLANMeasurementConfigurationValueCodec is the concrete ValueCodec[WLANMeasurementConfiguration].
type WLANMeasurementConfigurationValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (WLANMeasurementConfiguration,

		error)
	encode func(WLANMeasurementConfiguration,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(WLANMeasurementConfiguration, aper.DecodeState,

	) (WLANMeasurementConfiguration, aper.Snapshot,

	)
	compare func(WLANMeasurementConfiguration, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c WLANMeasurementConfigurationValueCodec) New(value WLANMeasurementConfiguration,

) (WLANMeasurementConfigurationAPERValue, error) {
	if c.encode == nil {
		return WLANMeasurementConfigurationAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return WLANMeasurementConfigurationAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return WLANMeasurementConfigurationAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return WLANMeasurementConfigurationAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c WLANMeasurementConfigurationValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (WLANMeasurementConfigurationAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return WLANMeasurementConfigurationAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return WLANMeasurementConfigurationAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return WLANMeasurementConfigurationAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return WLANMeasurementConfigurationAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c WLANMeasurementConfigurationValueCodec) EncodeAPER(value WLANMeasurementConfigurationAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c WLANMeasurementConfigurationValueCodec) encodeBudgetValue(value WLANMeasurementConfiguration,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c WLANMeasurementConfigurationValueCodec) encodeChanged(value WLANMeasurementConfiguration,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ImmediateMDTExtIEsSensorMeasurementConfigurationExtBinding binds SensorMeasurementConfiguration to the ImmediateMDT-ExtIEs object set of TS 36.413.
type ImmediateMDTExtIEsSensorMeasurementConfigurationExtBinding struct {
	info   s00.ExtensionInfo
	codec  s30.SensorMeasurementConfigurationValueCodec
	inject func(s30.SensorMeasurementConfiguration,

	) ImmediateMDTExtIEsValue

	get func(*ImmediateMDTExtIEsValue,

	) (*s30.SensorMeasurementConfiguration,

		bool)
}

// Info returns the source descriptor for this binding.
func (b ImmediateMDTExtIEsSensorMeasurementConfigurationExtBinding) Info() s00.ExtensionInfo {
	return b.info
}

// Codec returns the complete value codec for this binding.
func (b ImmediateMDTExtIEsSensorMeasurementConfigurationExtBinding) Codec() s30.SensorMeasurementConfigurationValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b ImmediateMDTExtIEsSensorMeasurementConfigurationExtBinding) New(value s30.SensorMeasurementConfiguration,

) (ImmediateMDTExtIEsExtField, error) {
	if b.inject == nil {
		return ImmediateMDTExtIEsExtField{}, aper.OperationError(fmt.Errorf("unbound extension binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ImmediateMDTExtIEsExtField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s30.BridgeSensorMeasurementConfigurationValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return ImmediateMDTExtIEsExtField{}, aper.OperationError(fmt.Errorf("extension %d: %w", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return ImmediateMDTExtIEsExtField{}, aper.OperationError(err, "Value.New")
	}
	return ImmediateMDTExtIEsExtField{Id: b.info.ID, Criticality: b.info.Criticality, ExtensionValue: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b ImmediateMDTExtIEsSensorMeasurementConfigurationExtBinding) Get(field *ImmediateMDTExtIEsExtField) (*s30.SensorMeasurementConfiguration,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.ExtensionValue)
}

// LoggedMDTExtIEsBluetoothMeasurementConfigurationExtBinding binds BluetoothMeasurementConfiguration to the LoggedMDT-ExtIEs object set of TS 36.413.
type LoggedMDTExtIEsBluetoothMeasurementConfigurationExtBinding struct {
	info   s00.ExtensionInfo
	codec  s14.BluetoothMeasurementConfigurationValueCodec
	inject func(s14.BluetoothMeasurementConfiguration,

	) LoggedMDTExtIEsValue

	get func(*LoggedMDTExtIEsValue,

	) (*s14.BluetoothMeasurementConfiguration,

		bool)
}

// Info returns the source descriptor for this binding.
func (b LoggedMDTExtIEsBluetoothMeasurementConfigurationExtBinding) Info() s00.ExtensionInfo {
	return b.info
}

// Codec returns the complete value codec for this binding.
func (b LoggedMDTExtIEsBluetoothMeasurementConfigurationExtBinding) Codec() s14.BluetoothMeasurementConfigurationValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b LoggedMDTExtIEsBluetoothMeasurementConfigurationExtBinding) New(value s14.BluetoothMeasurementConfiguration,

) (LoggedMDTExtIEsExtField, error) {
	if b.inject == nil {
		return LoggedMDTExtIEsExtField{}, aper.OperationError(fmt.Errorf("unbound extension binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return LoggedMDTExtIEsExtField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s14.BridgeBluetoothMeasurementConfigurationValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return LoggedMDTExtIEsExtField{}, aper.OperationError(fmt.Errorf("extension %d: %w", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return LoggedMDTExtIEsExtField{}, aper.OperationError(err, "Value.New")
	}
	return LoggedMDTExtIEsExtField{Id: b.info.ID, Criticality: b.info.Criticality, ExtensionValue: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b LoggedMDTExtIEsBluetoothMeasurementConfigurationExtBinding) Get(field *LoggedMDTExtIEsExtField) (*s14.BluetoothMeasurementConfiguration,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.ExtensionValue)
}

// LoggedMDTExtIEsWLANMeasurementConfigurationExtBinding binds WLANMeasurementConfiguration to the LoggedMDT-ExtIEs object set of TS 36.413.
type LoggedMDTExtIEsWLANMeasurementConfigurationExtBinding struct {
	info   s00.ExtensionInfo
	codec  WLANMeasurementConfigurationValueCodec
	inject func(WLANMeasurementConfiguration,

	) LoggedMDTExtIEsValue

	get func(*LoggedMDTExtIEsValue,

	) (*WLANMeasurementConfiguration,

		bool)
}

// Info returns the source descriptor for this binding.
func (b LoggedMDTExtIEsWLANMeasurementConfigurationExtBinding) Info() s00.ExtensionInfo {
	return b.info
}

// Codec returns the complete value codec for this binding.
func (b LoggedMDTExtIEsWLANMeasurementConfigurationExtBinding) Codec() WLANMeasurementConfigurationValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b LoggedMDTExtIEsWLANMeasurementConfigurationExtBinding) New(value WLANMeasurementConfiguration,

) (LoggedMDTExtIEsExtField, error) {
	if b.inject == nil {
		return LoggedMDTExtIEsExtField{}, aper.OperationError(fmt.Errorf("unbound extension binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return LoggedMDTExtIEsExtField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := b.codec.encode(value, false, budget); err != nil {
		return LoggedMDTExtIEsExtField{}, aper.OperationError(fmt.Errorf("extension %d: %w", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return LoggedMDTExtIEsExtField{}, aper.OperationError(err, "Value.New")
	}
	return LoggedMDTExtIEsExtField{Id: b.info.ID, Criticality: b.info.Criticality, ExtensionValue: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b LoggedMDTExtIEsWLANMeasurementConfigurationExtBinding) Get(field *LoggedMDTExtIEsExtField) (*WLANMeasurementConfiguration,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.ExtensionValue)
}

// LoggedMDTExtIEsLoggedMDTTriggerExtBinding binds LoggedMDTTrigger to the LoggedMDT-ExtIEs object set of TS 36.413.
type LoggedMDTExtIEsLoggedMDTTriggerExtBinding struct {
	info   s00.ExtensionInfo
	codec  s19.LoggedMDTTriggerValueCodec
	inject func(s19.LoggedMDTTrigger,

	) LoggedMDTExtIEsValue

	get func(*LoggedMDTExtIEsValue,

	) (*s19.LoggedMDTTrigger,

		bool)
}

// Info returns the source descriptor for this binding.
func (b LoggedMDTExtIEsLoggedMDTTriggerExtBinding) Info() s00.ExtensionInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b LoggedMDTExtIEsLoggedMDTTriggerExtBinding) Codec() s19.LoggedMDTTriggerValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b LoggedMDTExtIEsLoggedMDTTriggerExtBinding) New(value s19.LoggedMDTTrigger,

) (LoggedMDTExtIEsExtField, error) {
	if b.inject == nil {
		return LoggedMDTExtIEsExtField{}, aper.OperationError(fmt.Errorf("unbound extension binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return LoggedMDTExtIEsExtField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s19.BridgeLoggedMDTTriggerValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return LoggedMDTExtIEsExtField{}, aper.OperationError(fmt.Errorf("extension %d: %w", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return LoggedMDTExtIEsExtField{}, aper.OperationError(err, "Value.New")
	}
	return LoggedMDTExtIEsExtField{Id: b.info.ID, Criticality: b.info.Criticality, ExtensionValue: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b LoggedMDTExtIEsLoggedMDTTriggerExtBinding) Get(field *LoggedMDTExtIEsExtField) (*s19.LoggedMDTTrigger,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.ExtensionValue)
}

// LoggedMDTExtIEsSensorMeasurementConfigurationExtBinding binds SensorMeasurementConfiguration to the LoggedMDT-ExtIEs object set of TS 36.413.
type LoggedMDTExtIEsSensorMeasurementConfigurationExtBinding struct {
	info   s00.ExtensionInfo
	codec  s30.SensorMeasurementConfigurationValueCodec
	inject func(s30.SensorMeasurementConfiguration,

	) LoggedMDTExtIEsValue

	get func(*LoggedMDTExtIEsValue,

	) (*s30.SensorMeasurementConfiguration,

		bool)
}

// Info returns the source descriptor for this binding.
func (b LoggedMDTExtIEsSensorMeasurementConfigurationExtBinding) Info() s00.ExtensionInfo {
	return b.info
}

// Codec returns the complete value codec for this binding.
func (b LoggedMDTExtIEsSensorMeasurementConfigurationExtBinding) Codec() s30.SensorMeasurementConfigurationValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b LoggedMDTExtIEsSensorMeasurementConfigurationExtBinding) New(value s30.SensorMeasurementConfiguration,

) (LoggedMDTExtIEsExtField, error) {
	if b.inject == nil {
		return LoggedMDTExtIEsExtField{}, aper.OperationError(fmt.Errorf("unbound extension binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return LoggedMDTExtIEsExtField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s30.BridgeSensorMeasurementConfigurationValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return LoggedMDTExtIEsExtField{}, aper.OperationError(fmt.Errorf("extension %d: %w", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return LoggedMDTExtIEsExtField{}, aper.OperationError(err, "Value.New")
	}
	return LoggedMDTExtIEsExtField{Id: b.info.ID, Criticality: b.info.Criticality, ExtensionValue: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b LoggedMDTExtIEsSensorMeasurementConfigurationExtBinding) Get(field *LoggedMDTExtIEsExtField) (*s30.SensorMeasurementConfiguration,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.ExtensionValue)
}

// TraceActivationExtIEsMDTConfigurationExtBinding binds MDTConfiguration to the TraceActivation-ExtIEs object set of TS 36.413.
type TraceActivationExtIEsMDTConfigurationExtBinding struct {
	info   s00.ExtensionInfo
	codec  MDTConfigurationValueCodec
	inject func(MDTConfiguration,

	) TraceActivationExtIEsValue

	get func(*TraceActivationExtIEsValue,

	) (*MDTConfiguration,

		bool)
}

// Info returns the source descriptor for this binding.
func (b TraceActivationExtIEsMDTConfigurationExtBinding) Info() s00.ExtensionInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b TraceActivationExtIEsMDTConfigurationExtBinding) Codec() MDTConfigurationValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b TraceActivationExtIEsMDTConfigurationExtBinding) New(value MDTConfiguration,

) (TraceActivationExtIEsExtField, error) {
	if b.inject == nil {
		return TraceActivationExtIEsExtField{}, aper.OperationError(fmt.Errorf("unbound extension binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return TraceActivationExtIEsExtField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := b.codec.encode(value, false, budget); err != nil {
		return TraceActivationExtIEsExtField{}, aper.OperationError(fmt.Errorf("extension %d: %w", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return TraceActivationExtIEsExtField{}, aper.OperationError(err, "Value.New")
	}
	return TraceActivationExtIEsExtField{Id: b.info.ID, Criticality: b.info.Criticality, ExtensionValue: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b TraceActivationExtIEsMDTConfigurationExtBinding) Get(field *TraceActivationExtIEsExtField) (*MDTConfiguration,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.ExtensionValue)
}

// MDTConfigurationValueCodec is the concrete ValueCodec[MDTConfiguration].
type MDTConfigurationValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (MDTConfiguration,

		error)
	encode func(MDTConfiguration,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(MDTConfiguration, aper.DecodeState,

	) (MDTConfiguration, aper.Snapshot,

	)
	compare func(MDTConfiguration, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c MDTConfigurationValueCodec) New(value MDTConfiguration,

) (MDTConfigurationAPERValue, error) {
	if c.encode == nil {
		return MDTConfigurationAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return MDTConfigurationAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return MDTConfigurationAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return MDTConfigurationAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c MDTConfigurationValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (MDTConfigurationAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return MDTConfigurationAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return MDTConfigurationAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return MDTConfigurationAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return MDTConfigurationAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c MDTConfigurationValueCodec) EncodeAPER(value MDTConfigurationAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c MDTConfigurationValueCodec) encodeBudgetValue(value MDTConfiguration,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c MDTConfigurationValueCodec) encodeChanged(value MDTConfiguration,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// TraceActivationExtIEsUEAppLayerMeasConfigExtBinding binds UEAppLayerMeasConfig to the TraceActivation-ExtIEs object set of TS 36.413.
type TraceActivationExtIEsUEAppLayerMeasConfigExtBinding struct {
	info   s00.ExtensionInfo
	codec  s35.UEAppLayerMeasConfigValueCodec
	inject func(s35.UEAppLayerMeasConfig,

	) TraceActivationExtIEsValue

	get func(*TraceActivationExtIEsValue,

	) (*s35.UEAppLayerMeasConfig,

		bool)
}

// Info returns the source descriptor for this binding.
func (b TraceActivationExtIEsUEAppLayerMeasConfigExtBinding) Info() s00.ExtensionInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b TraceActivationExtIEsUEAppLayerMeasConfigExtBinding) Codec() s35.UEAppLayerMeasConfigValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b TraceActivationExtIEsUEAppLayerMeasConfigExtBinding) New(value s35.UEAppLayerMeasConfig,

) (TraceActivationExtIEsExtField, error) {
	if b.inject == nil {
		return TraceActivationExtIEsExtField{}, aper.OperationError(fmt.Errorf("unbound extension binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return TraceActivationExtIEsExtField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s35.BridgeUEAppLayerMeasConfigValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return TraceActivationExtIEsExtField{}, aper.OperationError(fmt.Errorf("extension %d: %w", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return TraceActivationExtIEsExtField{}, aper.OperationError(err, "Value.New")
	}
	return TraceActivationExtIEsExtField{Id: b.info.ID, Criticality: b.info.Criticality, ExtensionValue: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b TraceActivationExtIEsUEAppLayerMeasConfigExtBinding) Get(field *TraceActivationExtIEsExtField) (*s35.UEAppLayerMeasConfig,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.ExtensionValue)
}

// TraceActivationExtIEsMDTConfigurationNRExtBinding binds MDTConfigurationNR to the TraceActivation-ExtIEs object set of TS 36.413.
type TraceActivationExtIEsMDTConfigurationNRExtBinding struct {
	info   s00.ExtensionInfo
	codec  s01.MDTConfigurationNRValueCodec
	inject func(s00.MDTConfigurationNR,

	) TraceActivationExtIEsValue

	get func(*TraceActivationExtIEsValue,

	) (*s00.MDTConfigurationNR,

		bool)
}

// Info returns the source descriptor for this binding.
func (b TraceActivationExtIEsMDTConfigurationNRExtBinding) Info() s00.ExtensionInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b TraceActivationExtIEsMDTConfigurationNRExtBinding) Codec() s01.MDTConfigurationNRValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b TraceActivationExtIEsMDTConfigurationNRExtBinding) New(value s00.MDTConfigurationNR,

) (TraceActivationExtIEsExtField, error) {
	if b.inject == nil {
		return TraceActivationExtIEsExtField{}, aper.OperationError(fmt.Errorf("unbound extension binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return TraceActivationExtIEsExtField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s01.BridgeMDTConfigurationNRValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return TraceActivationExtIEsExtField{}, aper.OperationError(fmt.Errorf("extension %d: %w", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return TraceActivationExtIEsExtField{}, aper.OperationError(err, "Value.New")
	}
	return TraceActivationExtIEsExtField{Id: b.info.ID, Criticality: b.info.Criticality, ExtensionValue: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b TraceActivationExtIEsMDTConfigurationNRExtBinding) Get(field *TraceActivationExtIEsExtField) (*s00.MDTConfigurationNR,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.ExtensionValue)
}

// TraceActivationExtIEsURIAddressExtBinding binds URIAddress to the TraceActivation-ExtIEs object set of TS 36.413.
type TraceActivationExtIEsURIAddressExtBinding struct {
	info   s00.ExtensionInfo
	codec  s02.URIAddressValueCodec
	inject func(s00.URIAddress,

	) TraceActivationExtIEsValue

	get func(*TraceActivationExtIEsValue,

	) (*s00.URIAddress,

		bool)
}

// Info returns the source descriptor for this binding.
func (b TraceActivationExtIEsURIAddressExtBinding) Info() s00.ExtensionInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b TraceActivationExtIEsURIAddressExtBinding) Codec() s02.URIAddressValueCodec { return b.codec }

// New validates a source value and constructs its bound field.
func (b TraceActivationExtIEsURIAddressExtBinding) New(value s00.URIAddress,

) (TraceActivationExtIEsExtField, error) {
	if b.inject == nil {
		return TraceActivationExtIEsExtField{}, aper.OperationError(fmt.Errorf("unbound extension binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return TraceActivationExtIEsExtField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s02.BridgeURIAddressValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return TraceActivationExtIEsExtField{}, aper.OperationError(fmt.Errorf("extension %d: %w", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return TraceActivationExtIEsExtField{}, aper.OperationError(err, "Value.New")
	}
	return TraceActivationExtIEsExtField{Id: b.info.ID, Criticality: b.info.Criticality, ExtensionValue: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b TraceActivationExtIEsURIAddressExtBinding) Get(field *TraceActivationExtIEsExtField) (*s00.URIAddress,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.ExtensionValue)
}

// UEContextModificationRequestV2XServicesAuthorizedIEBinding binds V2XServicesAuthorized to the UEContextModificationRequestIEs object set of TS 36.413.
type UEContextModificationRequestV2XServicesAuthorizedIEBinding struct {
	info   s00.FieldInfo
	codec  s46.V2XServicesAuthorizedValueCodec
	inject func(s46.V2XServicesAuthorized,

	) s46.UEContextModificationRequestIEValue

	get func(*s46.UEContextModificationRequestIEValue,

	) (*s46.V2XServicesAuthorized,

		bool)
}

// Info returns the source descriptor for this binding.
func (b UEContextModificationRequestV2XServicesAuthorizedIEBinding) Info() s00.FieldInfo {
	return b.info
}

// Codec returns the complete value codec for this binding.
func (b UEContextModificationRequestV2XServicesAuthorizedIEBinding) Codec() s46.V2XServicesAuthorizedValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b UEContextModificationRequestV2XServicesAuthorizedIEBinding) New(value s46.V2XServicesAuthorized,

) (s46.UEContextModificationRequestIEField, error) {
	if b.inject == nil {
		return s46.UEContextModificationRequestIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return s46.UEContextModificationRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s46.BridgeV2XServicesAuthorizedValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return s46.UEContextModificationRequestIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return s46.UEContextModificationRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	return s46.UEContextModificationRequestIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b UEContextModificationRequestV2XServicesAuthorizedIEBinding) Get(field *s46.UEContextModificationRequestIEField) (*s46.V2XServicesAuthorized,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// ImmediateMDTValueCodec is the concrete ValueCodec[ImmediateMDT].
type ImmediateMDTValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ImmediateMDT,

		error)
	encode func(ImmediateMDT,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ImmediateMDT, aper.DecodeState,

	) (ImmediateMDT, aper.Snapshot,

	)
	compare func(ImmediateMDT, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ImmediateMDTValueCodec) New(value ImmediateMDT,

) (ImmediateMDTAPERValue, error) {
	if c.encode == nil {
		return ImmediateMDTAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ImmediateMDTAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ImmediateMDTAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ImmediateMDTAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ImmediateMDTValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ImmediateMDTAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ImmediateMDTAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ImmediateMDTAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ImmediateMDTAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ImmediateMDTAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ImmediateMDTValueCodec) EncodeAPER(value ImmediateMDTAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c ImmediateMDTValueCodec) encodeBudgetValue(value ImmediateMDT,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ImmediateMDTValueCodec) encodeChanged(value ImmediateMDT,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// LoggedMDTValueCodec is the concrete ValueCodec[LoggedMDT].
type LoggedMDTValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (LoggedMDT,

		error)
	encode func(LoggedMDT,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(LoggedMDT, aper.DecodeState,

	) (LoggedMDT, aper.Snapshot,

	)
	compare func(LoggedMDT, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c LoggedMDTValueCodec) New(value LoggedMDT,

) (LoggedMDTAPERValue, error) {
	if c.encode == nil {
		return LoggedMDTAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return LoggedMDTAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return LoggedMDTAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return LoggedMDTAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c LoggedMDTValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (LoggedMDTAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return LoggedMDTAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return LoggedMDTAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return LoggedMDTAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return LoggedMDTAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c LoggedMDTValueCodec) EncodeAPER(value LoggedMDTAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c LoggedMDTValueCodec) encodeBudgetValue(value LoggedMDT,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c LoggedMDTValueCodec) encodeChanged(value LoggedMDT,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// MDTModeValueCodec is the concrete ValueCodec[MDTMode].
type MDTModeValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (MDTMode,

		error)
	encode func(MDTMode,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(MDTMode, aper.DecodeState,

	) (MDTMode, aper.Snapshot,

	)
	compare func(MDTMode, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c MDTModeValueCodec) New(value MDTMode,

) (MDTModeAPERValue, error) {
	if c.encode == nil {
		return MDTModeAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return MDTModeAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return MDTModeAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return MDTModeAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c MDTModeValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (MDTModeAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return MDTModeAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return MDTModeAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return MDTModeAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return MDTModeAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c MDTModeValueCodec) EncodeAPER(value MDTModeAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c MDTModeValueCodec) encodeBudgetValue(value MDTMode,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c MDTModeValueCodec) encodeChanged(value MDTMode,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// PathSwitchRequestAcknowledgeValueCodec is the concrete ValueCodec[PathSwitchRequestAcknowledge].
type PathSwitchRequestAcknowledgeValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (PathSwitchRequestAcknowledge,

		error)
	encode func(PathSwitchRequestAcknowledge,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(PathSwitchRequestAcknowledge, aper.DecodeState,

	) (PathSwitchRequestAcknowledge, aper.Snapshot,

	)
	compare func(PathSwitchRequestAcknowledge, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c PathSwitchRequestAcknowledgeValueCodec) New(value PathSwitchRequestAcknowledge,

) (PathSwitchRequestAcknowledgeAPERValue, error) {
	if c.encode == nil {
		return PathSwitchRequestAcknowledgeAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return PathSwitchRequestAcknowledgeAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return PathSwitchRequestAcknowledgeAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return PathSwitchRequestAcknowledgeAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c PathSwitchRequestAcknowledgeValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (PathSwitchRequestAcknowledgeAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return PathSwitchRequestAcknowledgeAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return PathSwitchRequestAcknowledgeAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return PathSwitchRequestAcknowledgeAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return PathSwitchRequestAcknowledgeAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c PathSwitchRequestAcknowledgeValueCodec) EncodeAPER(value PathSwitchRequestAcknowledgeAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c PathSwitchRequestAcknowledgeValueCodec) encodeBudgetValue(value PathSwitchRequestAcknowledge,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c PathSwitchRequestAcknowledgeValueCodec) encodeChanged(value PathSwitchRequestAcknowledge,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// UEContextModificationRequestValueCodec is the concrete ValueCodec[UEContextModificationRequest].
type UEContextModificationRequestValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (UEContextModificationRequest,

		error)
	encode func(UEContextModificationRequest,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(UEContextModificationRequest, aper.DecodeState,

	) (UEContextModificationRequest, aper.Snapshot,

	)
	compare func(UEContextModificationRequest, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c UEContextModificationRequestValueCodec) New(value UEContextModificationRequest,

) (UEContextModificationRequestAPERValue, error) {
	if c.encode == nil {
		return UEContextModificationRequestAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return UEContextModificationRequestAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return UEContextModificationRequestAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return UEContextModificationRequestAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c UEContextModificationRequestValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (UEContextModificationRequestAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return UEContextModificationRequestAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return UEContextModificationRequestAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return UEContextModificationRequestAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return UEContextModificationRequestAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c UEContextModificationRequestValueCodec) EncodeAPER(value UEContextModificationRequestAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c UEContextModificationRequestValueCodec) encodeBudgetValue(value UEContextModificationRequest,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c UEContextModificationRequestValueCodec) encodeChanged(value UEContextModificationRequest,

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
func BridgePathSwitchRequestAcknowledgeIEValueValidateS1APIEContainer(fields s46.PathSwitchRequestAcknowledgeIEContainer, rows []s00.FieldInfo, path string, budget *aper.DecodeBudget,

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
		if !s46.BridgePathSwitchRequestAcknowledgeIEValueMethodMatchesID(field.Value, field.Id, budget) {
			rule := s46.BridgePathSwitchRequestAcknowledgeIEValueMethodRule(field.Value)
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.ValueIDMismatch, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: aper.Path(fmt.Sprintf("%s.id", location.Path))}, Table: func() s00.TableID {
				sealed := s00.TableID{}
				*s00.BridgeTableIDFieldSource(&sealed) = rule.Assignment
				return sealed
			}(), IEID: field.Id, HasIEID: true, Rule: s26.BridgeS1apValidationRule(s00.ValueIDMismatch), RelatedRules: []aper.SourceRule{rule}})
		}
		rank, allowed := byID[field.Id]
		table := func() s00.TableID {
			sealed := s00.TableID{}
			*s00.BridgeTableIDFieldSource(&sealed) = s46.BridgePathSwitchRequestAcknowledgeIEValueMethodRule(field.Value).Assignment
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
func BridgeUEContextModificationRequestIEValueValidateS1APIEContainer(fields s46.UEContextModificationRequestIEContainer, rows []s00.FieldInfo, path string, budget *aper.DecodeBudget,

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
		if !s46.BridgeUEContextModificationRequestIEValueMethodMatchesID(field.Value, field.Id, budget) {
			rule := s46.BridgeUEContextModificationRequestIEValueMethodRule(field.Value)
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.ValueIDMismatch, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: aper.Path(fmt.Sprintf("%s.id", location.Path))}, Table: func() s00.TableID {
				sealed := s00.TableID{}
				*s00.BridgeTableIDFieldSource(&sealed) = rule.Assignment
				return sealed
			}(), IEID: field.Id, HasIEID: true, Rule: s26.BridgeS1apValidationRule(s00.ValueIDMismatch), RelatedRules: []aper.SourceRule{rule}})
		}
		rank, allowed := byID[field.Id]
		table := func() s00.TableID {
			sealed := s00.TableID{}
			*s00.BridgeTableIDFieldSource(&sealed) = s46.BridgeUEContextModificationRequestIEValueMethodRule(field.Value).Assignment
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
func BridgeImmediateMDTExtIEsValueValidateS1APExtensionContainer(fields ImmediateMDTExtIEsExtContainer, rows []s00.FieldInfo, path string, budget *aper.DecodeBudget) s21.ValidationReport {
	bb := aper.NewBudgetBuffer(budget)
	if err := aper.ChargeSlice[ImmediateMDTExtIEsIEField](bb, uint64(len(fields))); err != nil {
		return func() s21.ValidationReport {
			sealed := s21.ValidationReport{}
			*s21.BridgeValidationReportFieldErr(&sealed) = err
			*s21.BridgeValidationReportFieldBudget(&sealed) = budget
			return sealed
		}()
	}
	asIE := make(ImmediateMDTExtIEsIEContainer, len(fields))
	for i := range fields {
		asIE[i].Id = fields[i].Id
		asIE[i].Criticality = fields[i].Criticality
		asIE[i].Value = fields[i].ExtensionValue
	}
	return BridgeImmediateMDTExtIEsValueValidateS1APIEContainer(asIE, rows, path, budget)
}
func BridgeLoggedMDTExtIEsValueValidateS1APExtensionContainer(fields LoggedMDTExtIEsExtContainer, rows []s00.FieldInfo, path string, budget *aper.DecodeBudget) s21.ValidationReport {
	bb := aper.NewBudgetBuffer(budget)
	if err := aper.ChargeSlice[LoggedMDTExtIEsIEField](bb, uint64(len(fields))); err != nil {
		return func() s21.ValidationReport {
			sealed := s21.ValidationReport{}
			*s21.BridgeValidationReportFieldErr(&sealed) = err
			*s21.BridgeValidationReportFieldBudget(&sealed) = budget
			return sealed
		}()
	}
	asIE := make(LoggedMDTExtIEsIEContainer, len(fields))
	for i := range fields {
		asIE[i].Id = fields[i].Id
		asIE[i].Criticality = fields[i].Criticality
		asIE[i].Value = fields[i].ExtensionValue
	}
	return BridgeLoggedMDTExtIEsValueValidateS1APIEContainer(asIE, rows, path, budget)
}
func BridgeV2XServicesAuthorizedExtIEsValueValidateS1APExtensionContainer(fields s12.V2XServicesAuthorizedExtIEsExtContainer, rows []s00.FieldInfo, path string, budget *aper.DecodeBudget) s21.ValidationReport {
	bb := aper.NewBudgetBuffer(budget)
	if err := aper.ChargeSlice[s12.V2XServicesAuthorizedExtIEsIEField](bb, uint64(len(fields))); err != nil {
		return func() s21.ValidationReport {
			sealed := s21.ValidationReport{}
			*s21.BridgeValidationReportFieldErr(&sealed) = err
			*s21.BridgeValidationReportFieldBudget(&sealed) = budget
			return sealed
		}()
	}
	asIE := make(s12.V2XServicesAuthorizedExtIEsIEContainer, len(fields))
	for i := range fields {
		asIE[i].Id = fields[i].Id
		asIE[i].Criticality = fields[i].Criticality
		asIE[i].Value = fields[i].ExtensionValue
	}
	return BridgeV2XServicesAuthorizedExtIEsValueValidateS1APIEContainer(asIE, rows, path, budget)
}

// PathSwitchRequestAcknowledgeIEValueERABIEContainerListCodec constructs the E-RAB-IE-ContainerList {{PathSwitchRequestAcknowledgeIEs}} codec of TS 36.413.
func PathSwitchRequestAcknowledgeIEValueERABIEContainerListCodec(table s00.PathSwitchRequestAcknowledgeIEValueIETable) s46.PathSwitchRequestAcknowledgeIEValueERABIEContainerListValueCodec {
	codec := PathSwitchRequestAcknowledgeIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if *s46.BridgePathSwitchRequestAcknowledgeIEContainerValueCodecFieldDecode(&codec) == nil {
		return s46.PathSwitchRequestAcknowledgeIEValueERABIEContainerListValueCodec{}
	}
	return func() s46.PathSwitchRequestAcknowledgeIEValueERABIEContainerListValueCodec {
		sealed := s46.PathSwitchRequestAcknowledgeIEValueERABIEContainerListValueCodec{}
		*s46.BridgePathSwitchRequestAcknowledgeIEValueERABIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s46.PathSwitchRequestAcknowledgeIEValueERABIEContainerList, error) {
			value, err := (*s46.BridgePathSwitchRequestAcknowledgeIEContainerValueCodecFieldDecode(&codec))(data, options)
			return s46.PathSwitchRequestAcknowledgeIEValueERABIEContainerList(value), err
		}
		*s46.BridgePathSwitchRequestAcknowledgeIEValueERABIEContainerListValueCodecFieldEncode(&sealed) = func(value s46.PathSwitchRequestAcknowledgeIEValueERABIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s46.BridgePathSwitchRequestAcknowledgeIEContainerValueCodecFieldEncode(&codec))(s46.PathSwitchRequestAcknowledgeIEContainer(value), fresh, budget)
		}
		*s46.BridgePathSwitchRequestAcknowledgeIEValueERABIEContainerListValueCodecFieldCapture(&sealed) = func(v s46.PathSwitchRequestAcknowledgeIEValueERABIEContainerList, options aper.DecodeState) (s46.PathSwitchRequestAcknowledgeIEValueERABIEContainerList, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgePathSwitchRequestAcknowledgeIEValueCaptureS1APERABIEContainerList(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s46.BridgePathSwitchRequestAcknowledgeIEValueERABIEContainerListValueCodecFieldCompare(&sealed) = func(v s46.PathSwitchRequestAcknowledgeIEValueERABIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgePathSwitchRequestAcknowledgeIEValueCompareS1APERABIEContainerList(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s46.BridgePathSwitchRequestAcknowledgeIEValueERABIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ERABIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// UEContextModificationRequestIEValueERABIEContainerListCodec constructs the E-RAB-IE-ContainerList {{UEContextModificationRequestIEs}} codec of TS 36.413.
func UEContextModificationRequestIEValueERABIEContainerListCodec(table s00.UEContextModificationRequestIEValueIETable) s46.UEContextModificationRequestIEValueERABIEContainerListValueCodec {
	codec := UEContextModificationRequestIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if *s46.BridgeUEContextModificationRequestIEContainerValueCodecFieldDecode(&codec) == nil {
		return s46.UEContextModificationRequestIEValueERABIEContainerListValueCodec{}
	}
	return func() s46.UEContextModificationRequestIEValueERABIEContainerListValueCodec {
		sealed := s46.UEContextModificationRequestIEValueERABIEContainerListValueCodec{}
		*s46.BridgeUEContextModificationRequestIEValueERABIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s46.UEContextModificationRequestIEValueERABIEContainerList, error) {
			value, err := (*s46.BridgeUEContextModificationRequestIEContainerValueCodecFieldDecode(&codec))(data, options)
			return s46.UEContextModificationRequestIEValueERABIEContainerList(value), err
		}
		*s46.BridgeUEContextModificationRequestIEValueERABIEContainerListValueCodecFieldEncode(&sealed) = func(value s46.UEContextModificationRequestIEValueERABIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s46.BridgeUEContextModificationRequestIEContainerValueCodecFieldEncode(&codec))(s46.UEContextModificationRequestIEContainer(value), fresh, budget)
		}
		*s46.BridgeUEContextModificationRequestIEValueERABIEContainerListValueCodecFieldCapture(&sealed) = func(v s46.UEContextModificationRequestIEValueERABIEContainerList, options aper.DecodeState) (s46.UEContextModificationRequestIEValueERABIEContainerList, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeUEContextModificationRequestIEValueCaptureS1APERABIEContainerList(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s46.BridgeUEContextModificationRequestIEValueERABIEContainerListValueCodecFieldCompare(&sealed) = func(v s46.UEContextModificationRequestIEValueERABIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeUEContextModificationRequestIEValueCompareS1APERABIEContainerList(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s46.BridgeUEContextModificationRequestIEValueERABIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ERABIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// ImmediateMDTExtIEsValueExtensionFieldTableCodec constructs the ProtocolExtensionField {{ImmediateMDT-ExtIEs}} codec of TS 36.413.
func ImmediateMDTExtIEsValueExtensionFieldTableCodec(table s00.ImmediateMDTExtIEsValueExtensionTable) ImmediateMDTExtIEsExtFieldValueCodec {
	if !*s00.BridgeImmediateMDTExtIEsValueExtensionTableFieldBound(&table) {
		return ImmediateMDTExtIEsExtFieldValueCodec{}
	}
	return ImmediateMDTExtIEsExtFieldValueCodec{decode: func(data []byte, options aper.DecodeState) (ImmediateMDTExtIEsExtField, error) {
		var field ImmediateMDTExtIEsExtField
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
	}, encode: func(field ImmediateMDTExtIEsExtField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		bb := aper.NewBudgetBuffer(budget)
		if err := field.marshalAPERTo(bb, fresh); err != nil {
			return nil, err
		}
		return bb.CompleteBytes(), nil
	}, capture: func(v ImmediateMDTExtIEsExtField, options aper.DecodeState) (ImmediateMDTExtIEsExtField, aper.Snapshot,
	) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeImmediateMDTExtIEsValueCaptureS1APProtocolExtensionField(&v, &s)
		var root aper.Snapshot
		s.End(f, &root,
			false)
		return v, root
	}, compare: func(v ImmediateMDTExtIEsExtField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
	) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		BridgeImmediateMDTExtIEsValueCompareS1APProtocolExtensionField(&v, &s)
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

// LoggedMDTExtIEsValueExtensionFieldTableCodec constructs the ProtocolExtensionField {{LoggedMDT-ExtIEs}} codec of TS 36.413.
func LoggedMDTExtIEsValueExtensionFieldTableCodec(table s00.LoggedMDTExtIEsValueExtensionTable) LoggedMDTExtIEsExtFieldValueCodec {
	if !*s00.BridgeLoggedMDTExtIEsValueExtensionTableFieldBound(&table) {
		return LoggedMDTExtIEsExtFieldValueCodec{}
	}
	return LoggedMDTExtIEsExtFieldValueCodec{decode: func(data []byte, options aper.DecodeState) (LoggedMDTExtIEsExtField, error) {
		var field LoggedMDTExtIEsExtField
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
	}, encode: func(field LoggedMDTExtIEsExtField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		bb := aper.NewBudgetBuffer(budget)
		if err := field.marshalAPERTo(bb, fresh); err != nil {
			return nil, err
		}
		return bb.CompleteBytes(), nil
	}, capture: func(v LoggedMDTExtIEsExtField, options aper.DecodeState) (LoggedMDTExtIEsExtField, aper.Snapshot,
	) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeLoggedMDTExtIEsValueCaptureS1APProtocolExtensionField(&v, &s)
		var root aper.Snapshot
		s.End(f, &root,
			false)
		return v, root
	}, compare: func(v LoggedMDTExtIEsExtField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
	) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		BridgeLoggedMDTExtIEsValueCompareS1APProtocolExtensionField(&v, &s)
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

// TraceActivationExtIEsValueExtensionFieldTableCodec constructs the ProtocolExtensionField {{TraceActivation-ExtIEs}} codec of TS 36.413.
func TraceActivationExtIEsValueExtensionFieldTableCodec(table s00.TraceActivationExtIEsValueExtensionTable) TraceActivationExtIEsExtFieldValueCodec {
	if !*s00.BridgeTraceActivationExtIEsValueExtensionTableFieldBound(&table) {
		return TraceActivationExtIEsExtFieldValueCodec{}
	}
	return TraceActivationExtIEsExtFieldValueCodec{decode: func(data []byte, options aper.DecodeState) (TraceActivationExtIEsExtField, error) {
		var field TraceActivationExtIEsExtField
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
	}, encode: func(field TraceActivationExtIEsExtField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		bb := aper.NewBudgetBuffer(budget)
		if err := field.marshalAPERTo(bb, fresh); err != nil {
			return nil, err
		}
		return bb.CompleteBytes(), nil
	}, capture: func(v TraceActivationExtIEsExtField, options aper.DecodeState) (TraceActivationExtIEsExtField, aper.Snapshot,
	) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeTraceActivationExtIEsValueCaptureS1APProtocolExtensionField(&v, &s)
		var root aper.Snapshot
		s.End(f, &root,
			false)
		return v, root
	}, compare: func(v TraceActivationExtIEsExtField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
	) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		BridgeTraceActivationExtIEsValueCompareS1APProtocolExtensionField(&v, &s)
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

// WLANMeasurementConfigurationExtIEsValueExtensionFieldTableCodec constructs the ProtocolExtensionField {{WLANMeasurementConfiguration-ExtIEs}} codec of TS 36.413.
func WLANMeasurementConfigurationExtIEsValueExtensionFieldTableCodec(table s00.WLANMeasurementConfigurationExtIEsValueExtensionTable) s12.WLANMeasurementConfigurationExtIEsExtFieldValueCodec {
	if !*s00.BridgeWLANMeasurementConfigurationExtIEsValueExtensionTableFieldBound(&table) {
		return s12.WLANMeasurementConfigurationExtIEsExtFieldValueCodec{}
	}
	return func() s12.WLANMeasurementConfigurationExtIEsExtFieldValueCodec {
		sealed := s12.WLANMeasurementConfigurationExtIEsExtFieldValueCodec{}
		*s12.BridgeWLANMeasurementConfigurationExtIEsExtFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s12.WLANMeasurementConfigurationExtIEsExtField, error) {
			var field s12.WLANMeasurementConfigurationExtIEsExtField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s12.BridgeWLANMeasurementConfigurationExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, err
			}
			if _, err := aper.CaptureFinalBits(bb, "ProtocolExtensionField"); err != nil {
				return field, err
			}
			return field, nil
		}
		*s12.BridgeWLANMeasurementConfigurationExtIEsExtFieldValueCodecFieldEncode(&sealed) = func(field s12.WLANMeasurementConfigurationExtIEsExtField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s12.BridgeWLANMeasurementConfigurationExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s12.BridgeWLANMeasurementConfigurationExtIEsExtFieldValueCodecFieldCapture(&sealed) = func(v s12.WLANMeasurementConfigurationExtIEsExtField, options aper.DecodeState) (s12.WLANMeasurementConfigurationExtIEsExtField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeWLANMeasurementConfigurationExtIEsValueCaptureS1APProtocolExtensionField(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,
				false)
			return v, root
		}
		*s12.BridgeWLANMeasurementConfigurationExtIEsExtFieldValueCodecFieldCompare(&sealed) = func(v s12.WLANMeasurementConfigurationExtIEsExtField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeWLANMeasurementConfigurationExtIEsValueCompareS1APProtocolExtensionField(&v, &s)
			s.End(f, root,

				false)
			return s.Plan(), s.BudgetValue()
		}
		*s12.BridgeWLANMeasurementConfigurationExtIEsExtFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// ImmediateMDTExtIEsValueExtensionTableCodec constructs the ProtocolExtensionContainer {{ImmediateMDT-ExtIEs}} codec of TS 36.413.
func ImmediateMDTExtIEsValueExtensionTableCodec(table s00.ImmediateMDTExtIEsValueExtensionTable, bounds aper.ListBounds) ImmediateMDTExtIEsExtContainerValueCodec {
	if !*s00.BridgeImmediateMDTExtIEsValueExtensionTableFieldBound(&table) {
		return ImmediateMDTExtIEsExtContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return ImmediateMDTExtIEsExtContainerValueCodec{decode: func(data []byte, options aper.DecodeState) (ImmediateMDTExtIEsExtContainer, error) {
		bb := aper.NewCompleteDecodeBuffer(data, options)
		if err := bb.SetDecodeOptionsAligned(options); err != nil {
			return nil, err
		}
		var fields ImmediateMDTExtIEsExtContainer
		_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
			for i := int64(0); i < length; i++ {
				var field ImmediateMDTExtIEsExtField
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
		encode: func(fields ImmediateMDTExtIEsExtContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
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
		}, capture: func(v ImmediateMDTExtIEsExtContainer, options aper.DecodeState) (ImmediateMDTExtIEsExtContainer, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeImmediateMDTExtIEsValueCaptureS1APProtocolExtensionContainer(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}, compare: func(v ImmediateMDTExtIEsExtContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.
				Begin()
			BridgeImmediateMDTExtIEsValueCompareS1APProtocolExtensionContainer(&v, &s)
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

// LoggedMDTExtIEsValueExtensionTableCodec constructs the ProtocolExtensionContainer {{LoggedMDT-ExtIEs}} codec of TS 36.413.
func LoggedMDTExtIEsValueExtensionTableCodec(table s00.LoggedMDTExtIEsValueExtensionTable, bounds aper.ListBounds) LoggedMDTExtIEsExtContainerValueCodec {
	if !*s00.BridgeLoggedMDTExtIEsValueExtensionTableFieldBound(&table) {
		return LoggedMDTExtIEsExtContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return LoggedMDTExtIEsExtContainerValueCodec{decode: func(data []byte, options aper.DecodeState) (LoggedMDTExtIEsExtContainer, error) {
		bb := aper.NewCompleteDecodeBuffer(data, options)
		if err := bb.SetDecodeOptionsAligned(options); err != nil {
			return nil, err
		}
		var fields LoggedMDTExtIEsExtContainer
		_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
			for i := int64(0); i < length; i++ {
				var field LoggedMDTExtIEsExtField
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
		encode: func(fields LoggedMDTExtIEsExtContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
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
		}, capture: func(v LoggedMDTExtIEsExtContainer, options aper.DecodeState) (LoggedMDTExtIEsExtContainer, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeLoggedMDTExtIEsValueCaptureS1APProtocolExtensionContainer(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}, compare: func(v LoggedMDTExtIEsExtContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.
				Begin()
			BridgeLoggedMDTExtIEsValueCompareS1APProtocolExtensionContainer(&v, &s)
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

// WLANMeasurementConfigurationExtIEsValueExtensionTableCodec constructs the ProtocolExtensionContainer {{WLANMeasurementConfiguration-ExtIEs}} codec of TS 36.413.
func WLANMeasurementConfigurationExtIEsValueExtensionTableCodec(table s00.WLANMeasurementConfigurationExtIEsValueExtensionTable, bounds aper.ListBounds) s12.WLANMeasurementConfigurationExtIEsExtContainerValueCodec {
	if !*s00.BridgeWLANMeasurementConfigurationExtIEsValueExtensionTableFieldBound(&table) {
		return s12.WLANMeasurementConfigurationExtIEsExtContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s12.WLANMeasurementConfigurationExtIEsExtContainerValueCodec {
		sealed := s12.WLANMeasurementConfigurationExtIEsExtContainerValueCodec{}
		*s12.BridgeWLANMeasurementConfigurationExtIEsExtContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s12.WLANMeasurementConfigurationExtIEsExtContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s12.WLANMeasurementConfigurationExtIEsExtContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s12.WLANMeasurementConfigurationExtIEsExtField
					if err := s12.BridgeWLANMeasurementConfigurationExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
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
		*s12.BridgeWLANMeasurementConfigurationExtIEsExtContainerValueCodecFieldEncode(&sealed) = func(fields s12.WLANMeasurementConfigurationExtIEsExtContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s12.BridgeWLANMeasurementConfigurationExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
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
		*s12.BridgeWLANMeasurementConfigurationExtIEsExtContainerValueCodecFieldCapture(&sealed) = func(v s12.WLANMeasurementConfigurationExtIEsExtContainer, options aper.DecodeState) (s12.WLANMeasurementConfigurationExtIEsExtContainer, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeWLANMeasurementConfigurationExtIEsValueCaptureS1APProtocolExtensionContainer(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s12.BridgeWLANMeasurementConfigurationExtIEsExtContainerValueCodecFieldCompare(&sealed) = func(v s12.WLANMeasurementConfigurationExtIEsExtContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.
				Begin()
			BridgeWLANMeasurementConfigurationExtIEsValueCompareS1APProtocolExtensionContainer(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s12.BridgeWLANMeasurementConfigurationExtIEsExtContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}

// PathSwitchRequestAcknowledgeIEValueIEFieldTableCodec constructs the ProtocolIE-Field {{PathSwitchRequestAcknowledgeIEs}} codec of TS 36.413.
func PathSwitchRequestAcknowledgeIEValueIEFieldTableCodec(table s00.PathSwitchRequestAcknowledgeIEValueIETable) s46.PathSwitchRequestAcknowledgeIEFieldValueCodec {
	if !*s00.BridgePathSwitchRequestAcknowledgeIEValueIETableFieldBound(&table) {
		return s46.PathSwitchRequestAcknowledgeIEFieldValueCodec{}
	}
	return func() s46.PathSwitchRequestAcknowledgeIEFieldValueCodec {
		sealed := s46.PathSwitchRequestAcknowledgeIEFieldValueCodec{}
		*s46.BridgePathSwitchRequestAcknowledgeIEFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s46.PathSwitchRequestAcknowledgeIEField, error) {
			var field s46.PathSwitchRequestAcknowledgeIEField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s46.BridgePathSwitchRequestAcknowledgeIEFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, err
			}
			if _, err := aper.CaptureFinalBits(bb, "ProtocolIEField"); err != nil {
				return field, err
			}
			return field, nil
		}
		*s46.BridgePathSwitchRequestAcknowledgeIEFieldValueCodecFieldEncode(&sealed) = func(field s46.PathSwitchRequestAcknowledgeIEField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s46.BridgePathSwitchRequestAcknowledgeIEFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s46.BridgePathSwitchRequestAcknowledgeIEFieldValueCodecFieldCapture(&sealed) = func(v s46.PathSwitchRequestAcknowledgeIEField, options aper.DecodeState) (s46.PathSwitchRequestAcknowledgeIEField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgePathSwitchRequestAcknowledgeIEValueCaptureS1APProtocolIEField(&v,
				&s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v,
				root
		}
		*s46.BridgePathSwitchRequestAcknowledgeIEFieldValueCodecFieldCompare(&sealed) = func(v s46.PathSwitchRequestAcknowledgeIEField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgePathSwitchRequestAcknowledgeIEValueCompareS1APProtocolIEField(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s46.BridgePathSwitchRequestAcknowledgeIEFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// UEContextModificationRequestIEValueIEFieldTableCodec constructs the ProtocolIE-Field {{UEContextModificationRequestIEs}} codec of TS 36.413.
func UEContextModificationRequestIEValueIEFieldTableCodec(table s00.UEContextModificationRequestIEValueIETable) s46.UEContextModificationRequestIEFieldValueCodec {
	if !*s00.BridgeUEContextModificationRequestIEValueIETableFieldBound(&table) {
		return s46.UEContextModificationRequestIEFieldValueCodec{}
	}
	return func() s46.UEContextModificationRequestIEFieldValueCodec {
		sealed := s46.UEContextModificationRequestIEFieldValueCodec{}
		*s46.BridgeUEContextModificationRequestIEFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s46.UEContextModificationRequestIEField, error) {
			var field s46.UEContextModificationRequestIEField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s46.BridgeUEContextModificationRequestIEFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, err
			}
			if _, err := aper.CaptureFinalBits(bb, "ProtocolIEField"); err != nil {
				return field, err
			}
			return field, nil
		}
		*s46.BridgeUEContextModificationRequestIEFieldValueCodecFieldEncode(&sealed) = func(field s46.UEContextModificationRequestIEField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s46.BridgeUEContextModificationRequestIEFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s46.BridgeUEContextModificationRequestIEFieldValueCodecFieldCapture(&sealed) = func(v s46.UEContextModificationRequestIEField, options aper.DecodeState) (s46.UEContextModificationRequestIEField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeUEContextModificationRequestIEValueCaptureS1APProtocolIEField(&v,
				&s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v,
				root
		}
		*s46.BridgeUEContextModificationRequestIEFieldValueCodecFieldCompare(&sealed) = func(v s46.UEContextModificationRequestIEField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeUEContextModificationRequestIEValueCompareS1APProtocolIEField(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s46.BridgeUEContextModificationRequestIEFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// PathSwitchRequestAcknowledgeIEValueIETableCodec constructs the ProtocolIE-Container {{PathSwitchRequestAcknowledgeIEs}} codec of TS 36.413.
func PathSwitchRequestAcknowledgeIEValueIETableCodec(table s00.PathSwitchRequestAcknowledgeIEValueIETable, bounds aper.ListBounds) s46.PathSwitchRequestAcknowledgeIEContainerValueCodec {
	if !*s00.BridgePathSwitchRequestAcknowledgeIEValueIETableFieldBound(&table) {
		return s46.PathSwitchRequestAcknowledgeIEContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s46.PathSwitchRequestAcknowledgeIEContainerValueCodec {
		sealed := s46.PathSwitchRequestAcknowledgeIEContainerValueCodec{}
		*s46.BridgePathSwitchRequestAcknowledgeIEContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s46.PathSwitchRequestAcknowledgeIEContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s46.PathSwitchRequestAcknowledgeIEContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s46.PathSwitchRequestAcknowledgeIEField
					if err := s46.BridgePathSwitchRequestAcknowledgeIEFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
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
		*s46.BridgePathSwitchRequestAcknowledgeIEContainerValueCodecFieldEncode(&sealed) = func(fields s46.PathSwitchRequestAcknowledgeIEContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s46.BridgePathSwitchRequestAcknowledgeIEFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
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
		*s46.BridgePathSwitchRequestAcknowledgeIEContainerValueCodecFieldCapture(&sealed) = func(v s46.PathSwitchRequestAcknowledgeIEContainer, options aper.DecodeState) (s46.PathSwitchRequestAcknowledgeIEContainer, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgePathSwitchRequestAcknowledgeIEValueCaptureS1APProtocolIEContainer(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s46.BridgePathSwitchRequestAcknowledgeIEContainerValueCodecFieldCompare(&sealed) = func(v s46.PathSwitchRequestAcknowledgeIEContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgePathSwitchRequestAcknowledgeIEValueCompareS1APProtocolIEContainer(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s46.BridgePathSwitchRequestAcknowledgeIEContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}

// UEContextModificationRequestIEValueIETableCodec constructs the ProtocolIE-Container {{UEContextModificationRequestIEs}} codec of TS 36.413.
func UEContextModificationRequestIEValueIETableCodec(table s00.UEContextModificationRequestIEValueIETable, bounds aper.ListBounds) s46.UEContextModificationRequestIEContainerValueCodec {
	if !*s00.BridgeUEContextModificationRequestIEValueIETableFieldBound(&table) {
		return s46.UEContextModificationRequestIEContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s46.UEContextModificationRequestIEContainerValueCodec {
		sealed := s46.UEContextModificationRequestIEContainerValueCodec{}
		*s46.BridgeUEContextModificationRequestIEContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s46.UEContextModificationRequestIEContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s46.UEContextModificationRequestIEContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s46.UEContextModificationRequestIEField
					if err := s46.BridgeUEContextModificationRequestIEFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
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
		*s46.BridgeUEContextModificationRequestIEContainerValueCodecFieldEncode(&sealed) = func(fields s46.UEContextModificationRequestIEContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s46.BridgeUEContextModificationRequestIEFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
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
		*s46.BridgeUEContextModificationRequestIEContainerValueCodecFieldCapture(&sealed) = func(v s46.UEContextModificationRequestIEContainer, options aper.DecodeState) (s46.UEContextModificationRequestIEContainer, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeUEContextModificationRequestIEValueCaptureS1APProtocolIEContainer(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s46.BridgeUEContextModificationRequestIEContainerValueCodecFieldCompare(&sealed) = func(v s46.UEContextModificationRequestIEContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeUEContextModificationRequestIEValueCompareS1APProtocolIEContainer(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s46.BridgeUEContextModificationRequestIEContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}

// PathSwitchRequestAcknowledgeIEValueProtocolErrorIEContainerListCodec constructs the ProtocolError-IE-ContainerList {{PathSwitchRequestAcknowledgeIEs}} codec of TS 36.413.
func PathSwitchRequestAcknowledgeIEValueProtocolErrorIEContainerListCodec(table s00.PathSwitchRequestAcknowledgeIEValueIETable) s46.PathSwitchRequestAcknowledgeIEValueProtocolErrorIEContainerListValueCodec {
	codec := PathSwitchRequestAcknowledgeIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if *s46.BridgePathSwitchRequestAcknowledgeIEContainerValueCodecFieldDecode(&codec) == nil {
		return s46.PathSwitchRequestAcknowledgeIEValueProtocolErrorIEContainerListValueCodec{}
	}
	return func() s46.PathSwitchRequestAcknowledgeIEValueProtocolErrorIEContainerListValueCodec {
		sealed := s46.PathSwitchRequestAcknowledgeIEValueProtocolErrorIEContainerListValueCodec{}
		*s46.BridgePathSwitchRequestAcknowledgeIEValueProtocolErrorIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s46.PathSwitchRequestAcknowledgeIEValueProtocolErrorIEContainerList, error) {
			value, err := (*s46.BridgePathSwitchRequestAcknowledgeIEContainerValueCodecFieldDecode(&codec))(data, options)
			return s46.PathSwitchRequestAcknowledgeIEValueProtocolErrorIEContainerList(value), err
		}
		*s46.BridgePathSwitchRequestAcknowledgeIEValueProtocolErrorIEContainerListValueCodecFieldEncode(&sealed) = func(value s46.PathSwitchRequestAcknowledgeIEValueProtocolErrorIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s46.BridgePathSwitchRequestAcknowledgeIEContainerValueCodecFieldEncode(&codec))(s46.PathSwitchRequestAcknowledgeIEContainer(value), fresh, budget)
		}
		*s46.BridgePathSwitchRequestAcknowledgeIEValueProtocolErrorIEContainerListValueCodecFieldCapture(&sealed) = func(v s46.PathSwitchRequestAcknowledgeIEValueProtocolErrorIEContainerList, options aper.DecodeState) (s46.PathSwitchRequestAcknowledgeIEValueProtocolErrorIEContainerList, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgePathSwitchRequestAcknowledgeIEValueCaptureS1APProtocolErrorIEContainerList(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s46.BridgePathSwitchRequestAcknowledgeIEValueProtocolErrorIEContainerListValueCodecFieldCompare(&sealed) = func(v s46.PathSwitchRequestAcknowledgeIEValueProtocolErrorIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f :=
				s.
					Begin()
			BridgePathSwitchRequestAcknowledgeIEValueCompareS1APProtocolErrorIEContainerList(&v, &s)
			s.
				End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s46.BridgePathSwitchRequestAcknowledgeIEValueProtocolErrorIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolErrorIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// UEContextModificationRequestIEValueProtocolErrorIEContainerListCodec constructs the ProtocolError-IE-ContainerList {{UEContextModificationRequestIEs}} codec of TS 36.413.
func UEContextModificationRequestIEValueProtocolErrorIEContainerListCodec(table s00.UEContextModificationRequestIEValueIETable) s46.UEContextModificationRequestIEValueProtocolErrorIEContainerListValueCodec {
	codec := UEContextModificationRequestIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if *s46.BridgeUEContextModificationRequestIEContainerValueCodecFieldDecode(&codec) == nil {
		return s46.UEContextModificationRequestIEValueProtocolErrorIEContainerListValueCodec{}
	}
	return func() s46.UEContextModificationRequestIEValueProtocolErrorIEContainerListValueCodec {
		sealed := s46.UEContextModificationRequestIEValueProtocolErrorIEContainerListValueCodec{}
		*s46.BridgeUEContextModificationRequestIEValueProtocolErrorIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s46.UEContextModificationRequestIEValueProtocolErrorIEContainerList, error) {
			value, err := (*s46.BridgeUEContextModificationRequestIEContainerValueCodecFieldDecode(&codec))(data, options)
			return s46.UEContextModificationRequestIEValueProtocolErrorIEContainerList(value), err
		}
		*s46.BridgeUEContextModificationRequestIEValueProtocolErrorIEContainerListValueCodecFieldEncode(&sealed) = func(value s46.UEContextModificationRequestIEValueProtocolErrorIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s46.BridgeUEContextModificationRequestIEContainerValueCodecFieldEncode(&codec))(s46.UEContextModificationRequestIEContainer(value), fresh, budget)
		}
		*s46.BridgeUEContextModificationRequestIEValueProtocolErrorIEContainerListValueCodecFieldCapture(&sealed) = func(v s46.UEContextModificationRequestIEValueProtocolErrorIEContainerList, options aper.DecodeState) (s46.UEContextModificationRequestIEValueProtocolErrorIEContainerList, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeUEContextModificationRequestIEValueCaptureS1APProtocolErrorIEContainerList(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s46.BridgeUEContextModificationRequestIEValueProtocolErrorIEContainerListValueCodecFieldCompare(&sealed) = func(v s46.UEContextModificationRequestIEValueProtocolErrorIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f :=
				s.
					Begin()
			BridgeUEContextModificationRequestIEValueCompareS1APProtocolErrorIEContainerList(&v, &s)
			s.
				End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s46.BridgeUEContextModificationRequestIEValueProtocolErrorIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolErrorIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// PathSwitchRequestAcknowledgeIEValueProtocolIEContainerListCodec constructs a codec for ProtocolIE-ContainerList with IEsSetParam = {PathSwitchRequestAcknowledgeIEs} of TS 36.413, with lowerBound and upperBound supplied by its arguments.
func PathSwitchRequestAcknowledgeIEValueProtocolIEContainerListCodec(table s00.PathSwitchRequestAcknowledgeIEValueIETable, bounds aper.ListBounds) s46.PathSwitchRequestAcknowledgeIEValueProtocolIEContainerListValueCodec {
	codec := PathSwitchRequestAcknowledgeIEValueIETableCodec(table, bounds)
	if *s46.BridgePathSwitchRequestAcknowledgeIEContainerValueCodecFieldDecode(&codec) == nil {
		return s46.PathSwitchRequestAcknowledgeIEValueProtocolIEContainerListValueCodec{}
	}
	return func() s46.PathSwitchRequestAcknowledgeIEValueProtocolIEContainerListValueCodec {
		sealed := s46.PathSwitchRequestAcknowledgeIEValueProtocolIEContainerListValueCodec{}
		*s46.BridgePathSwitchRequestAcknowledgeIEValueProtocolIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s46.PathSwitchRequestAcknowledgeIEValueProtocolIEContainerList, error) {
			value, err := (*s46.BridgePathSwitchRequestAcknowledgeIEContainerValueCodecFieldDecode(&codec))(data, options)
			return s46.PathSwitchRequestAcknowledgeIEValueProtocolIEContainerList(value), err
		}
		*s46.BridgePathSwitchRequestAcknowledgeIEValueProtocolIEContainerListValueCodecFieldEncode(&sealed) = func(value s46.PathSwitchRequestAcknowledgeIEValueProtocolIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s46.BridgePathSwitchRequestAcknowledgeIEContainerValueCodecFieldEncode(&codec))(s46.PathSwitchRequestAcknowledgeIEContainer(value), fresh, budget)
		}
		*s46.BridgePathSwitchRequestAcknowledgeIEValueProtocolIEContainerListValueCodecFieldCapture(&sealed) = func(v s46.PathSwitchRequestAcknowledgeIEValueProtocolIEContainerList, options aper.DecodeState) (s46.PathSwitchRequestAcknowledgeIEValueProtocolIEContainerList, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgePathSwitchRequestAcknowledgeIEValueCaptureS1APProtocolIEContainerList(&v, &s)
			var root aper.Snapshot
			s.End(
				f,
				&root, false)
			return v, root
		}
		*s46.BridgePathSwitchRequestAcknowledgeIEValueProtocolIEContainerListValueCodecFieldCompare(&sealed) = func(v s46.PathSwitchRequestAcknowledgeIEValueProtocolIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgePathSwitchRequestAcknowledgeIEValueCompareS1APProtocolIEContainerList(&v, &s)
			s.End(f, root,

				false)
			return s.Plan(), s.BudgetValue()
		}
		*s46.BridgePathSwitchRequestAcknowledgeIEValueProtocolIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}

// UEContextModificationRequestIEValueProtocolIEContainerListCodec constructs a codec for ProtocolIE-ContainerList with IEsSetParam = {UEContextModificationRequestIEs} of TS 36.413, with lowerBound and upperBound supplied by its arguments.
func UEContextModificationRequestIEValueProtocolIEContainerListCodec(table s00.UEContextModificationRequestIEValueIETable, bounds aper.ListBounds) s46.UEContextModificationRequestIEValueProtocolIEContainerListValueCodec {
	codec := UEContextModificationRequestIEValueIETableCodec(table, bounds)
	if *s46.BridgeUEContextModificationRequestIEContainerValueCodecFieldDecode(&codec) == nil {
		return s46.UEContextModificationRequestIEValueProtocolIEContainerListValueCodec{}
	}
	return func() s46.UEContextModificationRequestIEValueProtocolIEContainerListValueCodec {
		sealed := s46.UEContextModificationRequestIEValueProtocolIEContainerListValueCodec{}
		*s46.BridgeUEContextModificationRequestIEValueProtocolIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s46.UEContextModificationRequestIEValueProtocolIEContainerList, error) {
			value, err := (*s46.BridgeUEContextModificationRequestIEContainerValueCodecFieldDecode(&codec))(data, options)
			return s46.UEContextModificationRequestIEValueProtocolIEContainerList(value), err
		}
		*s46.BridgeUEContextModificationRequestIEValueProtocolIEContainerListValueCodecFieldEncode(&sealed) = func(value s46.UEContextModificationRequestIEValueProtocolIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s46.BridgeUEContextModificationRequestIEContainerValueCodecFieldEncode(&codec))(s46.UEContextModificationRequestIEContainer(value), fresh, budget)
		}
		*s46.BridgeUEContextModificationRequestIEValueProtocolIEContainerListValueCodecFieldCapture(&sealed) = func(v s46.UEContextModificationRequestIEValueProtocolIEContainerList, options aper.DecodeState) (s46.UEContextModificationRequestIEValueProtocolIEContainerList, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeUEContextModificationRequestIEValueCaptureS1APProtocolIEContainerList(&v, &s)
			var root aper.Snapshot
			s.End(
				f,
				&root, false)
			return v, root
		}
		*s46.BridgeUEContextModificationRequestIEValueProtocolIEContainerListValueCodecFieldCompare(&sealed) = func(v s46.UEContextModificationRequestIEValueProtocolIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeUEContextModificationRequestIEValueCompareS1APProtocolIEContainerList(&v, &s)
			s.End(f, root,

				false)
			return s.Plan(), s.BudgetValue()
		}
		*s46.BridgeUEContextModificationRequestIEValueProtocolIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}

// immediateMDTExtIEsValueProtocolOpenValue is the concrete protocolOpenValue[ImmediateMDTExtIEsValue].
type ImmediateMDTExtIEsValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) ImmediateMDTExtIEsValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (ImmediateMDTExtIEsValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

func BridgeImmediateMDTExtIEsValueCaptureS1APProtocolExtensionField(v *ImmediateMDTExtIEsExtField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolExtensionID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.ExtensionValue = v.ExtensionValue.captureSemantics(*s)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeImmediateMDTExtIEsValueCompareS1APProtocolExtensionField(v *ImmediateMDTExtIEsExtField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s02.BridgeCompareS1APProtocolExtensionID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = v.ExtensionValue.compareSemantics(*s)
	s.End(f, v.replay, v.withoutReplay)
}

// loggedMDTExtIEsValueProtocolOpenValue is the concrete protocolOpenValue[LoggedMDTExtIEsValue].
type LoggedMDTExtIEsValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) LoggedMDTExtIEsValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (LoggedMDTExtIEsValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

func BridgeLoggedMDTExtIEsValueCaptureS1APProtocolExtensionField(v *LoggedMDTExtIEsExtField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolExtensionID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.ExtensionValue = v.ExtensionValue.captureSemantics(*s)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeLoggedMDTExtIEsValueCompareS1APProtocolExtensionField(v *LoggedMDTExtIEsExtField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s02.BridgeCompareS1APProtocolExtensionID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = v.ExtensionValue.compareSemantics(*s)
	s.End(f, v.replay, v.withoutReplay)
}

// pathSwitchRequestAcknowledgeIEValueProtocolOpenValue is the concrete protocolOpenValue[PathSwitchRequestAcknowledgeIEValue].
type PathSwitchRequestAcknowledgeIEValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) s46.PathSwitchRequestAcknowledgeIEValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (s46.PathSwitchRequestAcknowledgeIEValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

func BridgePathSwitchRequestAcknowledgeIEValueCaptureS1APProtocolIEField(v *s46.PathSwitchRequestAcknowledgeIEField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolIEID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.Value = s46.BridgePathSwitchRequestAcknowledgeIEValueMethodCaptureSemantics(v.Value, *s)
	s.End(f, s46.BridgePathSwitchRequestAcknowledgeIEFieldFieldReplay(v), *s46.BridgePathSwitchRequestAcknowledgeIEFieldFieldWithoutReplay(v))
}
func BridgePathSwitchRequestAcknowledgeIEValueCompareS1APProtocolIEField(v *s46.PathSwitchRequestAcknowledgeIEField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s02.BridgeCompareS1APProtocolIEID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s46.BridgePathSwitchRequestAcknowledgeIEValueMethodCompareSemantics(v.Value, *s)
	s.End(f, *s46.BridgePathSwitchRequestAcknowledgeIEFieldFieldReplay(v), *s46.BridgePathSwitchRequestAcknowledgeIEFieldFieldWithoutReplay(v))
}
func BridgeTraceActivationExtIEsValueCaptureS1APProtocolExtensionField(v *TraceActivationExtIEsExtField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolExtensionID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.ExtensionValue = v.ExtensionValue.captureSemantics(*s)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeTraceActivationExtIEsValueCompareS1APProtocolExtensionField(v *TraceActivationExtIEsExtField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s02.BridgeCompareS1APProtocolExtensionID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = v.ExtensionValue.compareSemantics(*s)
	s.End(f, v.replay, v.withoutReplay)
}

// uEContextModificationRequestIEValueProtocolOpenValue is the concrete protocolOpenValue[UEContextModificationRequestIEValue].
type UEContextModificationRequestIEValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) s46.UEContextModificationRequestIEValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (s46.UEContextModificationRequestIEValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

func BridgeUEContextModificationRequestIEValueCaptureS1APProtocolIEField(v *s46.UEContextModificationRequestIEField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolIEID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.Value = s46.BridgeUEContextModificationRequestIEValueMethodCaptureSemantics(v.Value, *s)
	s.End(f, s46.BridgeUEContextModificationRequestIEFieldFieldReplay(v), *s46.BridgeUEContextModificationRequestIEFieldFieldWithoutReplay(v))
}
func BridgeUEContextModificationRequestIEValueCompareS1APProtocolIEField(v *s46.UEContextModificationRequestIEField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s02.BridgeCompareS1APProtocolIEID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s46.BridgeUEContextModificationRequestIEValueMethodCompareSemantics(v.Value, *s)
	s.End(f, *s46.BridgeUEContextModificationRequestIEFieldFieldReplay(v), *s46.BridgeUEContextModificationRequestIEFieldFieldWithoutReplay(v))
}

// v2XServicesAuthorizedExtIEsValueProtocolOpenValue is the concrete protocolOpenValue[V2XServicesAuthorizedExtIEsValue].
type V2XServicesAuthorizedExtIEsValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) s06.V2XServicesAuthorizedExtIEsValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (s06.V2XServicesAuthorizedExtIEsValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

func BridgeWLANMeasurementConfigurationExtIEsValueCaptureS1APProtocolExtensionField(v *s12.WLANMeasurementConfigurationExtIEsExtField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolExtensionID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.ExtensionValue = s06.BridgeWLANMeasurementConfigurationExtIEsValueMethodCaptureSemantics(v.ExtensionValue, *s)
	s.End(f, s12.BridgeWLANMeasurementConfigurationExtIEsExtFieldFieldReplay(v), *s12.BridgeWLANMeasurementConfigurationExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeWLANMeasurementConfigurationExtIEsValueCompareS1APProtocolExtensionField(v *s12.WLANMeasurementConfigurationExtIEsExtField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s02.BridgeCompareS1APProtocolExtensionID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s06.BridgeWLANMeasurementConfigurationExtIEsValueMethodCompareSemantics(v.ExtensionValue, *s)
	s.End(f, *s12.BridgeWLANMeasurementConfigurationExtIEsExtFieldFieldReplay(v), *s12.BridgeWLANMeasurementConfigurationExtIEsExtFieldFieldWithoutReplay(v))
}

// WLANMeasurementConfigurationAPERValue is the concrete APERValue[WLANMeasurementConfiguration].
type WLANMeasurementConfigurationAPERValue struct {
	context s00.BridgeCodecContext
	Value   WLANMeasurementConfiguration

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v WLANMeasurementConfigurationAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v WLANMeasurementConfigurationAPERValue) WithoutReplay() WLANMeasurementConfigurationAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// MDTConfigurationAPERValue is the concrete APERValue[MDTConfiguration].
type MDTConfigurationAPERValue struct {
	context s00.BridgeCodecContext
	Value   MDTConfiguration

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v MDTConfigurationAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v MDTConfigurationAPERValue) WithoutReplay() MDTConfigurationAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ImmediateMDTAPERValue is the concrete APERValue[ImmediateMDT].
type ImmediateMDTAPERValue struct {
	context s00.BridgeCodecContext
	Value   ImmediateMDT

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ImmediateMDTAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ImmediateMDTAPERValue) WithoutReplay() ImmediateMDTAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// LoggedMDTAPERValue is the concrete APERValue[LoggedMDT].
type LoggedMDTAPERValue struct {
	context s00.BridgeCodecContext
	Value   LoggedMDT

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v LoggedMDTAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v LoggedMDTAPERValue) WithoutReplay() LoggedMDTAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// MDTModeAPERValue is the concrete APERValue[MDTMode].
type MDTModeAPERValue struct {
	context s00.BridgeCodecContext
	Value   MDTMode

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v MDTModeAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v MDTModeAPERValue) WithoutReplay() MDTModeAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// PathSwitchRequestAcknowledgeAPERValue is the concrete APERValue[PathSwitchRequestAcknowledge].
type PathSwitchRequestAcknowledgeAPERValue struct {
	context s00.BridgeCodecContext
	Value   PathSwitchRequestAcknowledge

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v PathSwitchRequestAcknowledgeAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v PathSwitchRequestAcknowledgeAPERValue) WithoutReplay() PathSwitchRequestAcknowledgeAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// UEContextModificationRequestAPERValue is the concrete APERValue[UEContextModificationRequest].
type UEContextModificationRequestAPERValue struct {
	context s00.BridgeCodecContext
	Value   UEContextModificationRequest

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v UEContextModificationRequestAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v UEContextModificationRequestAPERValue) WithoutReplay() UEContextModificationRequestAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ImmediateMDTExtIEsIEField uses the ProtocolIE-Field shape for object set ImmediateMDT-ExtIEs of TS 36.413.
type ImmediateMDTExtIEsIEField struct {
	withoutReplay bool
	replay        aper.Snapshot
	stream        aper.WireSpan
	Id            s00.ProtocolIEID
	Criticality   s00.Criticality
	Value         ImmediateMDTExtIEsValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ImmediateMDTExtIEsIEField) WithoutReplay() ImmediateMDTExtIEsIEField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *ImmediateMDTExtIEsIEField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *ImmediateMDTExtIEsIEField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
func (v *ImmediateMDTExtIEsIEField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolIEField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = ImmediateMDTExtIEsIEField{}
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
	var zero ImmediateMDTExtIEsValue

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

// ImmediateMDTExtIEsIEContainer uses the ProtocolIE-Container shape for object set ImmediateMDT-ExtIEs of TS 36.413: a list of ImmediateMDTExtIEsIEField values.
type ImmediateMDTExtIEsIEContainer []ImmediateMDTExtIEsIEField

// TS 36.413 V19.2.0 §§9.3.3–9.3.4 supply the selected object-set order and
// presence. §§10.3.1–10.3.6 define abstract-syntax diagnostics. Unknown IEs do
// not determine the order of known rows.
func BridgeImmediateMDTExtIEsValueValidateS1APIEContainer(fields ImmediateMDTExtIEsIEContainer, rows []s00.FieldInfo, path string, budget *aper.DecodeBudget,

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

// LoggedMDTExtIEsIEField uses the ProtocolIE-Field shape for object set LoggedMDT-ExtIEs of TS 36.413.
type LoggedMDTExtIEsIEField struct {
	withoutReplay bool
	replay        aper.Snapshot
	stream        aper.WireSpan
	Id            s00.ProtocolIEID
	Criticality   s00.Criticality
	Value         LoggedMDTExtIEsValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v LoggedMDTExtIEsIEField) WithoutReplay() LoggedMDTExtIEsIEField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *LoggedMDTExtIEsIEField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *LoggedMDTExtIEsIEField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
func (v *LoggedMDTExtIEsIEField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolIEField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = LoggedMDTExtIEsIEField{}
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
	var zero LoggedMDTExtIEsValue

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

// LoggedMDTExtIEsIEContainer uses the ProtocolIE-Container shape for object set LoggedMDT-ExtIEs of TS 36.413: a list of LoggedMDTExtIEsIEField values.
type LoggedMDTExtIEsIEContainer []LoggedMDTExtIEsIEField

// TS 36.413 V19.2.0 §§9.3.3–9.3.4 supply the selected object-set order and
// presence. §§10.3.1–10.3.6 define abstract-syntax diagnostics. Unknown IEs do
// not determine the order of known rows.
func BridgeLoggedMDTExtIEsValueValidateS1APIEContainer(fields LoggedMDTExtIEsIEContainer, rows []s00.FieldInfo, path string, budget *aper.DecodeBudget,

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

// TraceActivationExtIEsIEField uses the ProtocolIE-Field shape for object set TraceActivation-ExtIEs of TS 36.413.
type TraceActivationExtIEsIEField struct {
	withoutReplay bool
	replay        aper.Snapshot
	stream        aper.WireSpan
	Id            s00.ProtocolIEID
	Criticality   s00.Criticality
	Value         TraceActivationExtIEsValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v TraceActivationExtIEsIEField) WithoutReplay() TraceActivationExtIEsIEField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *TraceActivationExtIEsIEField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *TraceActivationExtIEsIEField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
func (v *TraceActivationExtIEsIEField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolIEField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = TraceActivationExtIEsIEField{}
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
	var zero TraceActivationExtIEsValue

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

// TraceActivationExtIEsIEContainer uses the ProtocolIE-Container shape for object set TraceActivation-ExtIEs of TS 36.413: a list of TraceActivationExtIEsIEField values.
type TraceActivationExtIEsIEContainer []TraceActivationExtIEsIEField

// TS 36.413 V19.2.0 §§9.3.3–9.3.4 supply the selected object-set order and
// presence. §§10.3.1–10.3.6 define abstract-syntax diagnostics. Unknown IEs do
// not determine the order of known rows.
func BridgeV2XServicesAuthorizedExtIEsValueValidateS1APIEContainer(fields s12.V2XServicesAuthorizedExtIEsIEContainer, rows []s00.FieldInfo, path string, budget *aper.DecodeBudget,

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
		if !s06.BridgeV2XServicesAuthorizedExtIEsValueMethodMatchesID(field.Value, field.Id, budget) {
			rule := s06.BridgeV2XServicesAuthorizedExtIEsValueMethodRule(field.Value)
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.ValueIDMismatch, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: aper.Path(fmt.Sprintf("%s.id", location.Path))}, Table: func() s00.TableID {
				sealed := s00.TableID{}
				*s00.BridgeTableIDFieldSource(&sealed) = rule.Assignment
				return sealed
			}(), IEID: field.Id, HasIEID: true, Rule: s26.BridgeS1apValidationRule(s00.ValueIDMismatch), RelatedRules: []aper.SourceRule{rule}})
		}
		rank, allowed := byID[field.Id]
		table := func() s00.TableID {
			sealed := s00.TableID{}
			*s00.BridgeTableIDFieldSource(&sealed) = s06.BridgeV2XServicesAuthorizedExtIEsValueMethodRule(field.Value).Assignment
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
func BridgePathSwitchRequestAcknowledgeIEValueCaptureS1APERABIEContainerList(v *s46.PathSwitchRequestAcknowledgeIEValueERABIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgePathSwitchRequestAcknowledgeIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgePathSwitchRequestAcknowledgeIEValueCompareS1APERABIEContainerList(v *s46.PathSwitchRequestAcknowledgeIEValueERABIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgePathSwitchRequestAcknowledgeIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeUEContextModificationRequestIEValueCaptureS1APERABIEContainerList(v *s46.UEContextModificationRequestIEValueERABIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeUEContextModificationRequestIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeUEContextModificationRequestIEValueCompareS1APERABIEContainerList(v *s46.UEContextModificationRequestIEValueERABIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeUEContextModificationRequestIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}

// ImmediateMDTExtIEsExtFieldValueCodec is the concrete ValueCodec[ImmediateMDTExtIEsExtField].
type ImmediateMDTExtIEsExtFieldValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ImmediateMDTExtIEsExtField, error)
	encode  func(ImmediateMDTExtIEsExtField, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ImmediateMDTExtIEsExtField, aper.DecodeState) (ImmediateMDTExtIEsExtField, aper.Snapshot)
	compare func(ImmediateMDTExtIEsExtField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ImmediateMDTExtIEsExtFieldValueCodec) New(value ImmediateMDTExtIEsExtField) (ImmediateMDTExtIEsExtFieldAPERValue, error) {
	if c.encode == nil {
		return ImmediateMDTExtIEsExtFieldAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ImmediateMDTExtIEsExtFieldAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ImmediateMDTExtIEsExtFieldAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ImmediateMDTExtIEsExtFieldAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ImmediateMDTExtIEsExtFieldValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ImmediateMDTExtIEsExtFieldAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ImmediateMDTExtIEsExtFieldAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ImmediateMDTExtIEsExtFieldAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ImmediateMDTExtIEsExtFieldAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ImmediateMDTExtIEsExtFieldAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ImmediateMDTExtIEsExtFieldValueCodec) EncodeAPER(value ImmediateMDTExtIEsExtFieldAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c ImmediateMDTExtIEsExtFieldValueCodec) encodeBudgetValue(value ImmediateMDTExtIEsExtField, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ImmediateMDTExtIEsExtFieldValueCodec) encodeChanged(value ImmediateMDTExtIEsExtField, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// LoggedMDTExtIEsExtFieldValueCodec is the concrete ValueCodec[LoggedMDTExtIEsExtField].
type LoggedMDTExtIEsExtFieldValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (LoggedMDTExtIEsExtField, error)
	encode  func(LoggedMDTExtIEsExtField, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(LoggedMDTExtIEsExtField, aper.DecodeState) (LoggedMDTExtIEsExtField, aper.Snapshot)
	compare func(LoggedMDTExtIEsExtField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c LoggedMDTExtIEsExtFieldValueCodec) New(value LoggedMDTExtIEsExtField) (LoggedMDTExtIEsExtFieldAPERValue, error) {
	if c.encode == nil {
		return LoggedMDTExtIEsExtFieldAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return LoggedMDTExtIEsExtFieldAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return LoggedMDTExtIEsExtFieldAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return LoggedMDTExtIEsExtFieldAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c LoggedMDTExtIEsExtFieldValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (LoggedMDTExtIEsExtFieldAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return LoggedMDTExtIEsExtFieldAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return LoggedMDTExtIEsExtFieldAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return LoggedMDTExtIEsExtFieldAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return LoggedMDTExtIEsExtFieldAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c LoggedMDTExtIEsExtFieldValueCodec) EncodeAPER(value LoggedMDTExtIEsExtFieldAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c LoggedMDTExtIEsExtFieldValueCodec) encodeBudgetValue(value LoggedMDTExtIEsExtField, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c LoggedMDTExtIEsExtFieldValueCodec) encodeChanged(value LoggedMDTExtIEsExtField, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// TraceActivationExtIEsExtFieldValueCodec is the concrete ValueCodec[TraceActivationExtIEsExtField].
type TraceActivationExtIEsExtFieldValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (TraceActivationExtIEsExtField, error)
	encode  func(TraceActivationExtIEsExtField, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(TraceActivationExtIEsExtField, aper.DecodeState) (TraceActivationExtIEsExtField, aper.Snapshot)
	compare func(TraceActivationExtIEsExtField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c TraceActivationExtIEsExtFieldValueCodec) New(value TraceActivationExtIEsExtField) (TraceActivationExtIEsExtFieldAPERValue, error) {
	if c.encode == nil {
		return TraceActivationExtIEsExtFieldAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return TraceActivationExtIEsExtFieldAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return TraceActivationExtIEsExtFieldAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return TraceActivationExtIEsExtFieldAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c TraceActivationExtIEsExtFieldValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (TraceActivationExtIEsExtFieldAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return TraceActivationExtIEsExtFieldAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return TraceActivationExtIEsExtFieldAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return TraceActivationExtIEsExtFieldAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return TraceActivationExtIEsExtFieldAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c TraceActivationExtIEsExtFieldValueCodec) EncodeAPER(value TraceActivationExtIEsExtFieldAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c TraceActivationExtIEsExtFieldValueCodec) encodeBudgetValue(value TraceActivationExtIEsExtField, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c TraceActivationExtIEsExtFieldValueCodec) encodeChanged(value TraceActivationExtIEsExtField, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ImmediateMDTExtIEsExtContainerValueCodec is the concrete ValueCodec[ImmediateMDTExtIEsExtContainer].
type ImmediateMDTExtIEsExtContainerValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ImmediateMDTExtIEsExtContainer, error)
	encode  func(ImmediateMDTExtIEsExtContainer, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ImmediateMDTExtIEsExtContainer, aper.DecodeState) (ImmediateMDTExtIEsExtContainer, aper.Snapshot)
	compare func(ImmediateMDTExtIEsExtContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ImmediateMDTExtIEsExtContainerValueCodec) New(value ImmediateMDTExtIEsExtContainer) (ImmediateMDTExtIEsExtContainerAPERValue, error) {
	if c.encode == nil {
		return ImmediateMDTExtIEsExtContainerAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ImmediateMDTExtIEsExtContainerAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ImmediateMDTExtIEsExtContainerAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ImmediateMDTExtIEsExtContainerAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ImmediateMDTExtIEsExtContainerValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ImmediateMDTExtIEsExtContainerAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ImmediateMDTExtIEsExtContainerAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ImmediateMDTExtIEsExtContainerAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ImmediateMDTExtIEsExtContainerAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ImmediateMDTExtIEsExtContainerAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ImmediateMDTExtIEsExtContainerValueCodec) EncodeAPER(value ImmediateMDTExtIEsExtContainerAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c ImmediateMDTExtIEsExtContainerValueCodec) encodeBudgetValue(value ImmediateMDTExtIEsExtContainer, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ImmediateMDTExtIEsExtContainerValueCodec) encodeChanged(value ImmediateMDTExtIEsExtContainer, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// LoggedMDTExtIEsExtContainerValueCodec is the concrete ValueCodec[LoggedMDTExtIEsExtContainer].
type LoggedMDTExtIEsExtContainerValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (LoggedMDTExtIEsExtContainer, error)
	encode  func(LoggedMDTExtIEsExtContainer, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(LoggedMDTExtIEsExtContainer, aper.DecodeState) (LoggedMDTExtIEsExtContainer, aper.Snapshot)
	compare func(LoggedMDTExtIEsExtContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c LoggedMDTExtIEsExtContainerValueCodec) New(value LoggedMDTExtIEsExtContainer) (LoggedMDTExtIEsExtContainerAPERValue, error) {
	if c.encode == nil {
		return LoggedMDTExtIEsExtContainerAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return LoggedMDTExtIEsExtContainerAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return LoggedMDTExtIEsExtContainerAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return LoggedMDTExtIEsExtContainerAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c LoggedMDTExtIEsExtContainerValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (LoggedMDTExtIEsExtContainerAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return LoggedMDTExtIEsExtContainerAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return LoggedMDTExtIEsExtContainerAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return LoggedMDTExtIEsExtContainerAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return LoggedMDTExtIEsExtContainerAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c LoggedMDTExtIEsExtContainerValueCodec) EncodeAPER(value LoggedMDTExtIEsExtContainerAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c LoggedMDTExtIEsExtContainerValueCodec) encodeBudgetValue(value LoggedMDTExtIEsExtContainer, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c LoggedMDTExtIEsExtContainerValueCodec) encodeChanged(value LoggedMDTExtIEsExtContainer, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// TraceActivationExtIEsExtContainerValueCodec is the concrete ValueCodec[TraceActivationExtIEsExtContainer].
type TraceActivationExtIEsExtContainerValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (TraceActivationExtIEsExtContainer, error)
	encode  func(TraceActivationExtIEsExtContainer, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(TraceActivationExtIEsExtContainer, aper.DecodeState) (TraceActivationExtIEsExtContainer, aper.Snapshot)
	compare func(TraceActivationExtIEsExtContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c TraceActivationExtIEsExtContainerValueCodec) New(value TraceActivationExtIEsExtContainer) (TraceActivationExtIEsExtContainerAPERValue, error) {
	if c.encode == nil {
		return TraceActivationExtIEsExtContainerAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return TraceActivationExtIEsExtContainerAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return TraceActivationExtIEsExtContainerAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return TraceActivationExtIEsExtContainerAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c TraceActivationExtIEsExtContainerValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (TraceActivationExtIEsExtContainerAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return TraceActivationExtIEsExtContainerAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return TraceActivationExtIEsExtContainerAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return TraceActivationExtIEsExtContainerAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return TraceActivationExtIEsExtContainerAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c TraceActivationExtIEsExtContainerValueCodec) EncodeAPER(value TraceActivationExtIEsExtContainerAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c TraceActivationExtIEsExtContainerValueCodec) encodeBudgetValue(value TraceActivationExtIEsExtContainer, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c TraceActivationExtIEsExtContainerValueCodec) encodeChanged(value TraceActivationExtIEsExtContainer, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func BridgePathSwitchRequestAcknowledgeIEValueCaptureS1APProtocolErrorIEContainerList(v *s46.PathSwitchRequestAcknowledgeIEValueProtocolErrorIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgePathSwitchRequestAcknowledgeIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgePathSwitchRequestAcknowledgeIEValueCompareS1APProtocolErrorIEContainerList(v *s46.PathSwitchRequestAcknowledgeIEValueProtocolErrorIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgePathSwitchRequestAcknowledgeIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeUEContextModificationRequestIEValueCaptureS1APProtocolErrorIEContainerList(v *s46.UEContextModificationRequestIEValueProtocolErrorIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeUEContextModificationRequestIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeUEContextModificationRequestIEValueCompareS1APProtocolErrorIEContainerList(v *s46.UEContextModificationRequestIEValueProtocolErrorIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeUEContextModificationRequestIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgePathSwitchRequestAcknowledgeIEValueCaptureS1APProtocolIEContainerList(v *s46.PathSwitchRequestAcknowledgeIEValueProtocolIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgePathSwitchRequestAcknowledgeIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgePathSwitchRequestAcknowledgeIEValueCompareS1APProtocolIEContainerList(v *s46.PathSwitchRequestAcknowledgeIEValueProtocolIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgePathSwitchRequestAcknowledgeIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeUEContextModificationRequestIEValueCaptureS1APProtocolIEContainerList(v *s46.UEContextModificationRequestIEValueProtocolIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeUEContextModificationRequestIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeUEContextModificationRequestIEValueCompareS1APProtocolIEContainerList(v *s46.UEContextModificationRequestIEValueProtocolIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeUEContextModificationRequestIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgePathSwitchRequestAcknowledgeIEValueCaptureS1APProtocolIESingleContainer(v *s46.PathSwitchRequestAcknowledgeIEValueProtocolIESingleContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgePathSwitchRequestAcknowledgeIEValueCaptureS1APProtocolIEField(v, s)
	s.End(f, nil, false)
}
func BridgePathSwitchRequestAcknowledgeIEValueCompareS1APProtocolIESingleContainer(v *s46.PathSwitchRequestAcknowledgeIEValueProtocolIESingleContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgePathSwitchRequestAcknowledgeIEValueCompareS1APProtocolIEField(v, s)
	s.End(f, aper.Snapshot{}, false)
}
func BridgeUEContextModificationRequestIEValueCaptureS1APProtocolIESingleContainer(v *s46.UEContextModificationRequestIEValueProtocolIESingleContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeUEContextModificationRequestIEValueCaptureS1APProtocolIEField(v, s)
	s.End(f, nil, false)
}
func BridgeUEContextModificationRequestIEValueCompareS1APProtocolIESingleContainer(v *s46.UEContextModificationRequestIEValueProtocolIESingleContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeUEContextModificationRequestIEValueCompareS1APProtocolIEField(v, s)
	s.End(f, aper.Snapshot{}, false)
}

// ImmediateMDTExtIEsExtFieldAPERValue is the concrete APERValue[ImmediateMDTExtIEsExtField].
type ImmediateMDTExtIEsExtFieldAPERValue struct {
	context       s00.BridgeCodecContext
	Value         ImmediateMDTExtIEsExtField
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ImmediateMDTExtIEsExtFieldAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ImmediateMDTExtIEsExtFieldAPERValue) WithoutReplay() ImmediateMDTExtIEsExtFieldAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// LoggedMDTExtIEsExtFieldAPERValue is the concrete APERValue[LoggedMDTExtIEsExtField].
type LoggedMDTExtIEsExtFieldAPERValue struct {
	context       s00.BridgeCodecContext
	Value         LoggedMDTExtIEsExtField
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v LoggedMDTExtIEsExtFieldAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v LoggedMDTExtIEsExtFieldAPERValue) WithoutReplay() LoggedMDTExtIEsExtFieldAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// TraceActivationExtIEsExtFieldAPERValue is the concrete APERValue[TraceActivationExtIEsExtField].
type TraceActivationExtIEsExtFieldAPERValue struct {
	context       s00.BridgeCodecContext
	Value         TraceActivationExtIEsExtField
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v TraceActivationExtIEsExtFieldAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v TraceActivationExtIEsExtFieldAPERValue) WithoutReplay() TraceActivationExtIEsExtFieldAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ImmediateMDTExtIEsExtContainerAPERValue is the concrete APERValue[ImmediateMDTExtIEsExtContainer].
type ImmediateMDTExtIEsExtContainerAPERValue struct {
	context       s00.BridgeCodecContext
	Value         ImmediateMDTExtIEsExtContainer
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ImmediateMDTExtIEsExtContainerAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ImmediateMDTExtIEsExtContainerAPERValue) WithoutReplay() ImmediateMDTExtIEsExtContainerAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// LoggedMDTExtIEsExtContainerAPERValue is the concrete APERValue[LoggedMDTExtIEsExtContainer].
type LoggedMDTExtIEsExtContainerAPERValue struct {
	context       s00.BridgeCodecContext
	Value         LoggedMDTExtIEsExtContainer
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v LoggedMDTExtIEsExtContainerAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v LoggedMDTExtIEsExtContainerAPERValue) WithoutReplay() LoggedMDTExtIEsExtContainerAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// TraceActivationExtIEsExtContainerAPERValue is the concrete APERValue[TraceActivationExtIEsExtContainer].
type TraceActivationExtIEsExtContainerAPERValue struct {
	context       s00.BridgeCodecContext
	Value         TraceActivationExtIEsExtContainer
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v TraceActivationExtIEsExtContainerAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v TraceActivationExtIEsExtContainerAPERValue) WithoutReplay() TraceActivationExtIEsExtContainerAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}
func BridgeCaptureS1APImmediateMDT(v *ImmediateMDT, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APMeasurementsToActivate(&v.MeasurementsToActivate, s)
	s00.BridgeCaptureS1APM1ReportingTrigger(&v.M1reportingTrigger, s)
	{
		f := s.Begin()
		s.Bool(v.M1thresholdeventA2 == nil)
		if v.M1thresholdeventA2 != nil {
			s19.BridgeCaptureS1APM1ThresholdEventA2(v.M1thresholdeventA2, s)
		}
		s.End(f, nil, false)
	}
	{
		f := s.Begin()
		s.Bool(v.M1periodicReporting == nil)
		if v.M1periodicReporting != nil {
			s19.BridgeCaptureS1APM1PeriodicReporting(v.M1periodicReporting, s)
		}
		s.End(f, nil, false)
	}
	s.Bool(v.IEExtensions == nil)
	BridgeImmediateMDTExtIEsValueCaptureS1APProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APImmediateMDT(v *ImmediateMDT, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s02.BridgeCompareS1APMeasurementsToActivate(&v.MeasurementsToActivate, s)
	s02.BridgeCompareS1APM1ReportingTrigger(&v.M1reportingTrigger, s)
	{
		f := s.Begin()
		s.Bool(v.M1thresholdeventA2 == nil)
		if v.M1thresholdeventA2 != nil {
			s19.BridgeCompareS1APM1ThresholdEventA2(v.M1thresholdeventA2, s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	{
		f := s.Begin()
		s.Bool(v.M1periodicReporting == nil)
		if v.M1periodicReporting != nil {
			s19.BridgeCompareS1APM1PeriodicReporting(v.M1periodicReporting, s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.Bool(v.IEExtensions == nil)
	BridgeImmediateMDTExtIEsValueCompareS1APProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APImmediateMDTExtIEsValue(v *ImmediateMDTExtIEsValue, s *aper.SemanticCapture) {
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
		case s00.ProtocolIEID(171):
			{
				f := s.Begin()
				s.Bool(v.rowM3Configuration == nil)
				if v.rowM3Configuration != nil {
					s19.BridgeCaptureS1APM3Configuration(v.rowM3Configuration, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(172):
			{
				f := s.Begin()
				s.Bool(v.rowM4Configuration == nil)
				if v.rowM4Configuration != nil {
					s19.BridgeCaptureS1APM4Configuration(v.rowM4Configuration, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(173):
			{
				f := s.Begin()
				s.Bool(v.rowM5Configuration == nil)
				if v.rowM5Configuration != nil {
					s19.BridgeCaptureS1APM5Configuration(v.rowM5Configuration, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(174):
			{
				f := s.Begin()
				s.Bool(v.rowMDTLocationInfo == nil)
				if v.rowMDTLocationInfo != nil {
					s00.BridgeCaptureS1APMDTLocationInfo(v.rowMDTLocationInfo, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(220):
			{
				f := s.Begin()
				s.Bool(v.rowM6Configuration == nil)
				if v.rowM6Configuration != nil {
					s19.BridgeCaptureS1APM6Configuration(v.rowM6Configuration, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(221):
			{
				f := s.Begin()
				s.Bool(v.rowM7Configuration == nil)
				if v.rowM7Configuration != nil {
					s19.BridgeCaptureS1APM7Configuration(v.rowM7Configuration, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(284):
			{
				f := s.Begin()
				s.Bool(v.rowBluetoothMeasurementConfiguration == nil)
				if v.rowBluetoothMeasurementConfiguration != nil {
					s14.BridgeCaptureS1APBluetoothMeasurementConfiguration(v.rowBluetoothMeasurementConfiguration, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(285):
			{
				f := s.Begin()
				s.Bool(v.rowWLANMeasurementConfiguration == nil)
				if v.rowWLANMeasurementConfiguration != nil {
					BridgeCaptureS1APWLANMeasurementConfiguration(v.rowWLANMeasurementConfiguration, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(345):
			{
				f := s.Begin()
				s.Bool(v.rowSensorMeasurementConfiguration == nil)
				if v.rowSensorMeasurementConfiguration != nil {
					s30.BridgeCaptureS1APSensorMeasurementConfiguration(v.rowSensorMeasurementConfiguration, s)
				}
				s.End(f, nil, false)
			}
		}
	}
	s.End(f, &v.replay, false)
	s.CheckReceived(v.replay, v.received)
}
func (v ImmediateMDTExtIEsValue) captureSemantics(s aper.SemanticCapture) ImmediateMDTExtIEsValue {
	BridgeCaptureS1APImmediateMDTExtIEsValue(&v, &s)
	return v
}
func BridgeCompareS1APImmediateMDTExtIEsValue(v *ImmediateMDTExtIEsValue, s *aper.SemanticComparison) {
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
		case s00.ProtocolIEID(171):
			{
				f := s.Begin()
				s.Bool(v.rowM3Configuration == nil)
				if v.rowM3Configuration != nil {
					s19.BridgeCompareS1APM3Configuration(v.rowM3Configuration, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(172):
			{
				f := s.Begin()
				s.Bool(v.rowM4Configuration == nil)
				if v.rowM4Configuration != nil {
					s19.BridgeCompareS1APM4Configuration(v.rowM4Configuration, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(173):
			{
				f := s.Begin()
				s.Bool(v.rowM5Configuration == nil)
				if v.rowM5Configuration != nil {
					s19.BridgeCompareS1APM5Configuration(v.rowM5Configuration, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(174):
			{
				f := s.Begin()
				s.Bool(v.rowMDTLocationInfo == nil)
				if v.rowMDTLocationInfo != nil {
					s02.BridgeCompareS1APMDTLocationInfo(v.rowMDTLocationInfo, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(220):
			{
				f := s.Begin()
				s.Bool(v.rowM6Configuration == nil)
				if v.rowM6Configuration != nil {
					s19.BridgeCompareS1APM6Configuration(v.rowM6Configuration, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(221):
			{
				f := s.Begin()
				s.Bool(v.rowM7Configuration == nil)
				if v.rowM7Configuration != nil {
					s19.BridgeCompareS1APM7Configuration(v.rowM7Configuration, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(284):
			{
				f := s.Begin()
				s.Bool(v.rowBluetoothMeasurementConfiguration == nil)
				if v.rowBluetoothMeasurementConfiguration != nil {
					s14.BridgeCompareS1APBluetoothMeasurementConfiguration(v.rowBluetoothMeasurementConfiguration, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(285):
			{
				f := s.Begin()
				s.Bool(v.rowWLANMeasurementConfiguration == nil)
				if v.rowWLANMeasurementConfiguration != nil {
					BridgeCompareS1APWLANMeasurementConfiguration(v.rowWLANMeasurementConfiguration, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(345):
			{
				f := s.Begin()
				s.Bool(v.rowSensorMeasurementConfiguration == nil)
				if v.rowSensorMeasurementConfiguration != nil {
					s30.BridgeCompareS1APSensorMeasurementConfiguration(v.rowSensorMeasurementConfiguration, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		}
	}
	s.End(f, v.replay, false)
	s.CheckReceived(v.replay, v.received)
}
func (v ImmediateMDTExtIEsValue) compareSemantics(s aper.SemanticComparison) aper.SemanticComparison {
	BridgeCompareS1APImmediateMDTExtIEsValue(&v, &s)
	return s
}
func BridgeCaptureS1APLoggedMDT(v *LoggedMDT, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APLoggingInterval(&v.LoggingInterval, s)
	s00.BridgeCaptureS1APLoggingDuration(&v.LoggingDuration, s)
	s.Bool(v.IEExtensions == nil)
	BridgeLoggedMDTExtIEsValueCaptureS1APProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APLoggedMDT(v *LoggedMDT, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s02.BridgeCompareS1APLoggingInterval(&v.LoggingInterval, s)
	s02.BridgeCompareS1APLoggingDuration(&v.LoggingDuration, s)
	s.Bool(v.IEExtensions == nil)
	BridgeLoggedMDTExtIEsValueCompareS1APProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APLoggedMDTExtIEsValue(v *LoggedMDTExtIEsValue, s *aper.SemanticCapture) {
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
		case s00.ProtocolIEID(284):
			{
				f := s.Begin()
				s.Bool(v.rowBluetoothMeasurementConfiguration == nil)
				if v.rowBluetoothMeasurementConfiguration != nil {
					s14.BridgeCaptureS1APBluetoothMeasurementConfiguration(v.rowBluetoothMeasurementConfiguration, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(285):
			{
				f := s.Begin()
				s.Bool(v.rowWLANMeasurementConfiguration == nil)
				if v.rowWLANMeasurementConfiguration != nil {
					BridgeCaptureS1APWLANMeasurementConfiguration(v.rowWLANMeasurementConfiguration, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(344):
			{
				f := s.Begin()
				s.Bool(v.rowLoggedMDTTrigger == nil)
				if v.rowLoggedMDTTrigger != nil {
					s19.BridgeCaptureS1APLoggedMDTTrigger(v.rowLoggedMDTTrigger, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(345):
			{
				f := s.Begin()
				s.Bool(v.rowSensorMeasurementConfiguration == nil)
				if v.rowSensorMeasurementConfiguration != nil {
					s30.BridgeCaptureS1APSensorMeasurementConfiguration(v.rowSensorMeasurementConfiguration, s)
				}
				s.End(f, nil, false)
			}
		}
	}
	s.End(f, &v.replay, false)
	s.CheckReceived(v.replay, v.received)
}
func (v LoggedMDTExtIEsValue) captureSemantics(s aper.SemanticCapture) LoggedMDTExtIEsValue {
	BridgeCaptureS1APLoggedMDTExtIEsValue(&v, &s)
	return v
}
func BridgeCompareS1APLoggedMDTExtIEsValue(v *LoggedMDTExtIEsValue, s *aper.SemanticComparison) {
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
		case s00.ProtocolIEID(284):
			{
				f := s.Begin()
				s.Bool(v.rowBluetoothMeasurementConfiguration == nil)
				if v.rowBluetoothMeasurementConfiguration != nil {
					s14.BridgeCompareS1APBluetoothMeasurementConfiguration(v.rowBluetoothMeasurementConfiguration, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(285):
			{
				f := s.Begin()
				s.Bool(v.rowWLANMeasurementConfiguration == nil)
				if v.rowWLANMeasurementConfiguration != nil {
					BridgeCompareS1APWLANMeasurementConfiguration(v.rowWLANMeasurementConfiguration, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(344):
			{
				f := s.Begin()
				s.Bool(v.rowLoggedMDTTrigger == nil)
				if v.rowLoggedMDTTrigger != nil {
					s19.BridgeCompareS1APLoggedMDTTrigger(v.rowLoggedMDTTrigger, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(345):
			{
				f := s.Begin()
				s.Bool(v.rowSensorMeasurementConfiguration == nil)
				if v.rowSensorMeasurementConfiguration != nil {
					s30.BridgeCompareS1APSensorMeasurementConfiguration(v.rowSensorMeasurementConfiguration, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		}
	}
	s.End(f, v.replay, false)
	s.CheckReceived(v.replay, v.received)
}
func (v LoggedMDTExtIEsValue) compareSemantics(s aper.SemanticComparison) aper.SemanticComparison {
	BridgeCompareS1APLoggedMDTExtIEsValue(&v, &s)
	return s
}
func BridgeCaptureS1APMDTConfiguration(v *MDTConfiguration, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APMDTActivation(&v.MdtActivation, s)
	s32.BridgeCaptureS1APAreaScopeOfMDT(&v.AreaScopeOfMDT, s)
	BridgeCaptureS1APMDTMode(&v.MDTMode, s)
	s.Bool(v.IEExtensions == nil)
	s42.BridgeMDTConfigurationExtIEsValueCaptureS1APProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APMDTConfiguration(v *MDTConfiguration, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s02.BridgeCompareS1APMDTActivation(&v.MdtActivation, s)
	s32.BridgeCompareS1APAreaScopeOfMDT(&v.AreaScopeOfMDT, s)
	BridgeCompareS1APMDTMode(&v.MDTMode, s)
	s.Bool(v.IEExtensions == nil)
	s42.BridgeMDTConfigurationExtIEsValueCompareS1APProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APMDTMode(v *MDTMode, s *aper.SemanticCapture) {
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
	case s00.MDTModeChoiceImmediateMDT:
		{
			f := s.Begin()
			s.Bool(v.ImmediateMDT == nil)
			if v.ImmediateMDT != nil {
				BridgeCaptureS1APImmediateMDT(v.ImmediateMDT, s)
			}
			s.End(f, nil, false)
		}
	case s00.MDTModeChoiceLoggedMDT:
		{
			f := s.Begin()
			s.Bool(v.LoggedMDT == nil)
			if v.LoggedMDT != nil {
				BridgeCaptureS1APLoggedMDT(v.LoggedMDT, s)
			}
			s.End(f, nil, false)
		}
	case s00.MDTModeChoiceMDTModeExtension:
		{
			f := s.Begin()
			s.Bool(v.MDTModeExtension == nil)
			if v.MDTModeExtension != nil {
				s19.BridgeCaptureS1APMDTModeExtension(v.MDTModeExtension, s)
			}
			s.End(f, nil, false)
		}
	}
	s.End(f, &v.replay, v.withoutReplay)
	if v.UnknownExtension == nil && v.Choice > 2 {
		s.CheckChoice(v.replay, v.stream)
	}
}
func BridgeCompareS1APMDTMode(v *MDTMode, s *aper.SemanticComparison) {
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
	case s00.MDTModeChoiceImmediateMDT:
		{
			f := s.Begin()
			s.Bool(v.ImmediateMDT == nil)
			if v.ImmediateMDT != nil {
				BridgeCompareS1APImmediateMDT(v.ImmediateMDT, s)
			}
			s.End(f, aper.Snapshot{}, false)
		}
	case s00.MDTModeChoiceLoggedMDT:
		{
			f := s.Begin()
			s.Bool(v.LoggedMDT == nil)
			if v.LoggedMDT != nil {
				BridgeCompareS1APLoggedMDT(v.LoggedMDT, s)
			}
			s.End(f, aper.Snapshot{}, false)
		}
	case s00.MDTModeChoiceMDTModeExtension:
		{
			f := s.Begin()
			s.Bool(v.MDTModeExtension == nil)
			if v.MDTModeExtension != nil {
				s19.BridgeCompareS1APMDTModeExtension(v.MDTModeExtension, s)
			}
			s.End(f, aper.Snapshot{}, false)
		}
	}
	s.End(f, v.replay, v.withoutReplay)
	if v.UnknownExtension == nil && v.Choice > 2 {
		s.CheckChoice(v.replay, v.stream)
	}
}
func BridgeCaptureS1APPathSwitchRequestAcknowledge(v *PathSwitchRequestAcknowledge, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgePathSwitchRequestAcknowledgeIEValueCaptureS1APProtocolIEContainer(&v.ProtocolIEs, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APPathSwitchRequestAcknowledge(v *PathSwitchRequestAcknowledge, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgePathSwitchRequestAcknowledgeIEValueCompareS1APProtocolIEContainer(&v.ProtocolIEs, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APTraceActivation(v *TraceActivation, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APEUTRANTraceID(&v.EUTRANTraceID, s)
	s00.BridgeCaptureS1APInterfacesToTrace(&v.InterfacesToTrace, s)
	s00.BridgeCaptureS1APTraceDepth(&v.TraceDepth, s)
	s00.BridgeCaptureS1APTransportLayerAddress(&v.TraceCollectionEntityIPAddress, s)
	s.Bool(v.IEExtensions == nil)
	BridgeTraceActivationExtIEsValueCaptureS1APProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APTraceActivation(v *TraceActivation, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s02.BridgeCompareS1APEUTRANTraceID(&v.EUTRANTraceID, s)
	s02.BridgeCompareS1APInterfacesToTrace(&v.InterfacesToTrace, s)
	s07.BridgeCompareS1APTraceDepth(&v.TraceDepth, s)
	s07.BridgeCompareS1APTransportLayerAddress(&v.TraceCollectionEntityIPAddress, s)
	s.Bool(v.IEExtensions == nil)
	BridgeTraceActivationExtIEsValueCompareS1APProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APTraceActivationExtIEsValue(v *TraceActivationExtIEsValue, s *aper.SemanticCapture) {
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
		case s00.ProtocolIEID(162):
			{
				f := s.Begin()
				s.Bool(v.rowMDTConfiguration == nil)
				if v.rowMDTConfiguration != nil {
					BridgeCaptureS1APMDTConfiguration(v.rowMDTConfiguration, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(262):
			{
				f := s.Begin()
				s.Bool(v.rowUEAppLayerMeasConfig == nil)
				if v.rowUEAppLayerMeasConfig != nil {
					s35.BridgeCaptureS1APUEAppLayerMeasConfig(v.rowUEAppLayerMeasConfig, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(316):
			{
				f := s.Begin()
				s.Bool(v.rowMDTConfigurationNR == nil)
				if v.rowMDTConfigurationNR != nil {
					s00.BridgeCaptureS1APMDTConfigurationNR(v.rowMDTConfigurationNR, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(325):
			{
				f := s.Begin()
				s.Bool(v.rowTraceCollectionEntityURI == nil)
				if v.rowTraceCollectionEntityURI != nil {
					s00.BridgeCaptureS1APURIAddress(v.rowTraceCollectionEntityURI, s)
				}
				s.End(f, nil, false)
			}
		}
	}
	s.End(f, &v.replay, false)
	s.CheckReceived(v.replay, v.received)
}
func (v TraceActivationExtIEsValue) captureSemantics(s aper.SemanticCapture) TraceActivationExtIEsValue {
	BridgeCaptureS1APTraceActivationExtIEsValue(&v, &s)
	return v
}
func BridgeCompareS1APTraceActivationExtIEsValue(v *TraceActivationExtIEsValue, s *aper.SemanticComparison) {
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
		case s00.ProtocolIEID(162):
			{
				f := s.Begin()
				s.Bool(v.rowMDTConfiguration == nil)
				if v.rowMDTConfiguration != nil {
					BridgeCompareS1APMDTConfiguration(v.rowMDTConfiguration, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(262):
			{
				f := s.Begin()
				s.Bool(v.rowUEAppLayerMeasConfig == nil)
				if v.rowUEAppLayerMeasConfig != nil {
					s35.BridgeCompareS1APUEAppLayerMeasConfig(v.rowUEAppLayerMeasConfig, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(316):
			{
				f := s.Begin()
				s.Bool(v.rowMDTConfigurationNR == nil)
				if v.rowMDTConfigurationNR != nil {
					s02.BridgeCompareS1APMDTConfigurationNR(v.rowMDTConfigurationNR, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(325):
			{
				f := s.Begin()
				s.Bool(v.rowTraceCollectionEntityURI == nil)
				if v.rowTraceCollectionEntityURI != nil {
					s07.BridgeCompareS1APURIAddress(v.rowTraceCollectionEntityURI, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		}
	}
	s.End(f, v.replay, false)
	s.CheckReceived(v.replay, v.received)
}
func (v TraceActivationExtIEsValue) compareSemantics(s aper.SemanticComparison) aper.SemanticComparison {
	BridgeCompareS1APTraceActivationExtIEsValue(&v, &s)
	return s
}
func BridgeCaptureS1APUEContextModificationRequest(v *UEContextModificationRequest, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeUEContextModificationRequestIEValueCaptureS1APProtocolIEContainer(&v.ProtocolIEs, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APUEContextModificationRequest(v *UEContextModificationRequest, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeUEContextModificationRequestIEValueCompareS1APProtocolIEContainer(&v.ProtocolIEs, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APWLANMeasurementConfiguration(v *WLANMeasurementConfiguration, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APWLANMeasConfig(&v.WlanMeasConfig, s)
	s.Bool(v.WlanMeasConfigNameList == nil)
	s00.BridgeCaptureS1APWLANMeasConfigNameList(&v.WlanMeasConfigNameList, s)
	{
		f := s.Begin()
		s.Bool(v.WlanRssi == nil)
		if v.WlanRssi != nil {
			s.Int(int64((*v.WlanRssi)))
		}
		s.End(f, nil, false)
	}
	{
		f := s.Begin()
		s.Bool(v.WlanRtt == nil)
		if v.WlanRtt != nil {
			s.Int(int64((*v.WlanRtt)))
		}
		s.End(f, nil, false)
	}
	s.Bool(v.IEExtensions == nil)
	BridgeWLANMeasurementConfigurationExtIEsValueCaptureS1APProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APWLANMeasurementConfiguration(v *WLANMeasurementConfiguration, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s07.BridgeCompareS1APWLANMeasConfig(&v.WlanMeasConfig, s)
	s.Bool(v.WlanMeasConfigNameList == nil)
	s07.BridgeCompareS1APWLANMeasConfigNameList(&v.WlanMeasConfigNameList, s)
	{
		f := s.Begin()
		s.Bool(v.WlanRssi == nil)
		if v.WlanRssi != nil {
			s.Int(int64((*v.WlanRssi)))
		}
		s.End(f, aper.Snapshot{}, false)
	}
	{
		f := s.Begin()
		s.Bool(v.WlanRtt == nil)
		if v.WlanRtt != nil {
			s.Int(int64((*v.WlanRtt)))
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.Bool(v.IEExtensions == nil)
	BridgeWLANMeasurementConfigurationExtIEsValueCompareS1APProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, v.replay, v.withoutReplay)
}

// ImmediateMDT represents the ASN.1 type ImmediateMDT (SEQUENCE).
type ImmediateMDT struct {
	replay                 aper.Snapshot
	stream                 aper.WireSpan
	received               bool
	withoutReplay          bool
	receivedAbsolute       bool
	receivedBytes          aper.WireSpan
	receivedLocation       aper.Location
	MeasurementsToActivate s00.MeasurementsToActivate     `asn1:"tag:0,context,implicit"`
	M1reportingTrigger     s00.M1ReportingTrigger         `asn1:"tag:1,context,implicit"`
	M1thresholdeventA2     *s19.M1ThresholdEventA2        `asn1:"tag:2,context,implicit,optional" json:"M1thresholdeventA2,omitempty"`
	M1periodicReporting    *s19.M1PeriodicReporting       `asn1:"tag:3,context,implicit,optional" json:"M1periodicReporting,omitempty"`
	IEExtensions           ImmediateMDTExtIEsExtContainer `asn1:"tag:4,context,implicit,optional" json:"IEExtensions,omitzero"`
	iEExtensionsIndef      bool                           `asn1:"-" json:"-"`
	extCount               int64                          `asn1:"-" json:"-"`
	extPresent             []bool                         `asn1:"-" json:"-"`
	extData                [][]byte                       `asn1:"-" json:"-"`
	perPadding             aper.FinalPadding              `asn1:"-" json:"-"`
	perExtPadding          []aper.CompletePadding         `asn1:"-" json:"-"`
	extOrigin              []aper.OpaqueOrigin
	extWire                []aper.WireSpan
}

// LoggedMDT represents the ASN.1 type LoggedMDT (SEQUENCE).
type LoggedMDT struct {
	replay            aper.Snapshot
	stream            aper.WireSpan
	received          bool
	withoutReplay     bool
	receivedAbsolute  bool
	receivedBytes     aper.WireSpan
	receivedLocation  aper.Location
	LoggingInterval   s00.LoggingInterval         `asn1:"tag:0,context,implicit"`
	LoggingDuration   s00.LoggingDuration         `asn1:"tag:1,context,implicit"`
	IEExtensions      LoggedMDTExtIEsExtContainer `asn1:"tag:2,context,implicit,optional" json:"IEExtensions,omitzero"`
	iEExtensionsIndef bool                        `asn1:"-" json:"-"`
	extCount          int64                       `asn1:"-" json:"-"`
	extPresent        []bool                      `asn1:"-" json:"-"`
	extData           [][]byte                    `asn1:"-" json:"-"`
	perPadding        aper.FinalPadding           `asn1:"-" json:"-"`
	perExtPadding     []aper.CompletePadding      `asn1:"-" json:"-"`
	extOrigin         []aper.OpaqueOrigin
	extWire           []aper.WireSpan
}

// MDTConfiguration represents the ASN.1 type MDT-Configuration (SEQUENCE).
type MDTConfiguration struct {
	replay            aper.Snapshot
	stream            aper.WireSpan
	received          bool
	withoutReplay     bool
	receivedAbsolute  bool
	receivedBytes     aper.WireSpan
	receivedLocation  aper.Location
	MdtActivation     s00.MDTActivation                      `asn1:"tag:0,context,implicit"`
	AreaScopeOfMDT    s32.AreaScopeOfMDT                     `asn1:"tag:1,context,explicit"`
	MDTMode           MDTMode                                `asn1:"tag:2,context,explicit"`
	IEExtensions      s42.MDTConfigurationExtIEsExtContainer `asn1:"tag:3,context,implicit,optional" json:"IEExtensions,omitzero"`
	iEExtensionsIndef bool                                   `asn1:"-" json:"-"`
	extCount          int64                                  `asn1:"-" json:"-"`
	extPresent        []bool                                 `asn1:"-" json:"-"`
	extData           [][]byte                               `asn1:"-" json:"-"`
	perPadding        aper.FinalPadding                      `asn1:"-" json:"-"`
	perExtPadding     []aper.CompletePadding                 `asn1:"-" json:"-"`
	extOrigin         []aper.OpaqueOrigin
	extWire           []aper.WireSpan
}

// MDTMode represents the ASN.1 CHOICE type MDTMode.
type MDTMode struct {
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
	ImmediateMDT       *ImmediateMDT         `json:"ImmediateMDT,omitempty"`
	LoggedMDT          *LoggedMDT            `json:"LoggedMDT,omitempty"`
	MDTModeExtension   *s19.MDTModeExtension `json:"MDTModeExtension,omitempty"`
}

// NewMDTModeImmediateMDT creates a MDTMode with the immediateMDT alternative.
func BridgeNewMDTModeImmediateMDTLegacy(v ImmediateMDT) MDTMode {
	return MDTMode{
		Choice:       s00.MDTModeChoiceImmediateMDT,
		ImmediateMDT: &v,
	}
}

// NewMDTModeLoggedMDT creates a MDTMode with the loggedMDT alternative.
func BridgeNewMDTModeLoggedMDTLegacy(v LoggedMDT) MDTMode {
	return MDTMode{
		Choice:    s00.MDTModeChoiceLoggedMDT,
		LoggedMDT: &v,
	}
}

// NewMDTModeMDTModeExtension creates a MDTMode with the mDTMode-Extension alternative.
func BridgeNewMDTModeMDTModeExtensionLegacy(v s19.MDTModeExtension) MDTMode {
	return MDTMode{
		Choice:           s00.MDTModeChoiceMDTModeExtension,
		MDTModeExtension: &v,
	}
}

// TraceActivation represents the ASN.1 type TraceActivation (SEQUENCE).
type TraceActivation struct {
	replay                         aper.Snapshot
	stream                         aper.WireSpan
	received                       bool
	withoutReplay                  bool
	receivedAbsolute               bool
	receivedBytes                  aper.WireSpan
	receivedLocation               aper.Location
	EUTRANTraceID                  s00.EUTRANTraceID                 `asn1:"tag:0,context,implicit"`
	InterfacesToTrace              s00.InterfacesToTrace             `asn1:"tag:1,context,implicit"`
	TraceDepth                     s00.TraceDepth                    `asn1:"tag:2,context,implicit"`
	TraceCollectionEntityIPAddress s00.TransportLayerAddress         `asn1:"tag:3,context,implicit"`
	IEExtensions                   TraceActivationExtIEsExtContainer `asn1:"tag:4,context,implicit,optional" json:"IEExtensions,omitzero"`
	iEExtensionsIndef              bool                              `asn1:"-" json:"-"`
	extCount                       int64                             `asn1:"-" json:"-"`
	extPresent                     []bool                            `asn1:"-" json:"-"`
	extData                        [][]byte                          `asn1:"-" json:"-"`
	perPadding                     aper.FinalPadding                 `asn1:"-" json:"-"`
	perExtPadding                  []aper.CompletePadding            `asn1:"-" json:"-"`
	extOrigin                      []aper.OpaqueOrigin
	extWire                        []aper.WireSpan
}

// WLANMeasurementConfiguration represents the ASN.1 type WLANMeasurementConfiguration (SEQUENCE).
type WLANMeasurementConfiguration struct {
	replay                      aper.Snapshot
	stream                      aper.WireSpan
	received                    bool
	withoutReplay               bool
	receivedAbsolute            bool
	receivedBytes               aper.WireSpan
	receivedLocation            aper.Location
	WlanMeasConfig              s00.WLANMeasConfig                                 `asn1:"tag:0,context,implicit"`
	WlanMeasConfigNameList      s00.WLANMeasConfigNameList                         `asn1:"tag:1,context,implicit,optional" json:"WlanMeasConfigNameList,omitzero"`
	wlanMeasConfigNameListIndef bool                                               `asn1:"-" json:"-"`
	WlanRssi                    *int64                                             `asn1:"tag:2,context,implicit,optional" json:"WlanRssi,omitempty"`
	WlanRtt                     *int64                                             `asn1:"tag:3,context,implicit,optional" json:"WlanRtt,omitempty"`
	IEExtensions                s12.WLANMeasurementConfigurationExtIEsExtContainer `asn1:"tag:4,context,implicit,optional" json:"IEExtensions,omitzero"`
	iEExtensionsIndef           bool                                               `asn1:"-" json:"-"`
	extCount                    int64                                              `asn1:"-" json:"-"`
	extPresent                  []bool                                             `asn1:"-" json:"-"`
	extData                     [][]byte                                           `asn1:"-" json:"-"`
	perPadding                  aper.FinalPadding                                  `asn1:"-" json:"-"`
	perExtPadding               []aper.CompletePadding                             `asn1:"-" json:"-"`
	extOrigin                   []aper.OpaqueOrigin
	extWire                     []aper.WireSpan
}

// MarshalAPER encodes ImmediateMDT to APER format.
func (v *ImmediateMDT) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *ImmediateMDT) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
	if err := aper.EncodeBoolean(bb, v.M1thresholdeventA2 != nil); err != nil {
		return err
	}
	if err := aper.EncodeBoolean(bb, v.M1periodicReporting != nil); err != nil {
		return err
	}
	if err := aper.EncodeBoolean(bb, v.IEExtensions != nil); err != nil {
		return err
	}
	if err := aper.EncodeBitStringAligned(bb, v.MeasurementsToActivate.Bytes, v.MeasurementsToActivate.BitLength, 8, 8, true); err != nil {
		return fmt.Errorf("encoding measurementsToActivate: %w", err)
	}
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.M1reportingTrigger), 2, true); err != nil {
		return fmt.Errorf("encoding m1reportingTrigger: %w", err)
	}
	if v.M1thresholdeventA2 != nil {
		if err := s19.BridgeM1ThresholdEventA2MethodMarshalAPERTo(v.M1thresholdeventA2, bb, len(fresh) != 0 && fresh[0]); err != nil {
			return fmt.Errorf("encoding m1thresholdeventA2: %w", err)
		}
	}
	if v.M1periodicReporting != nil {
		if err := s19.BridgeM1PeriodicReportingMethodMarshalAPERTo(v.M1periodicReporting, bb, len(fresh) != 0 && fresh[0]); err != nil {
			return fmt.Errorf("encoding m1periodicReporting: %w", err)
		}
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

// UnmarshalAPER decodes ImmediateMDT from APER format.
func (v *ImmediateMDT) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes ImmediateMDT with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *ImmediateMDT) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "ImmediateMDT")
	}
	bb.EnterComponent("ImmediateMDT")
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "ImmediateMDT")
	}
	padding, err := aper.CaptureFinalBits(bb, "ImmediateMDT")
	if err != nil {
		return runtime.WrapDecodePath(err, "ImmediateMDT")
	}
	v.perPadding = padding.WithRecords(v.perPadding)
	return nil
}
func (v *ImmediateMDT) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = ImmediateMDT{}
	extAdditions := aper.BeginExtensionAdditions(bb)
	hasExtensions, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	// Read preamble bitmap for optional root fields
	opt_m1thresholdeventa2, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	opt_m1periodicreporting, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	opt_ieextensions, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	bsBytes_measurementstoactivate, bsBitLen_measurementstoactivate, err := aper.DecodeBitStringAligned(bb, 8, 8, true)
	if err != nil {
		return runtime.WrapDecodePath(err, "MeasurementsToActivate")
	}
	v.MeasurementsToActivate = runtime.BitString{Bytes: bsBytes_measurementstoactivate, BitLength: bsBitLen_measurementstoactivate}
	val_m1reportingtrigger, err := aper.DecodeEnumeratedAligned(bb, 2, true, aper.EnumerationSource{KnownExtensions: 1, Path: "M1reportingTrigger"})
	if err != nil {
		return runtime.WrapDecodePath(err, "M1reportingTrigger")
	}
	v.M1reportingTrigger = s00.M1ReportingTrigger(val_m1reportingtrigger)
	if opt_m1thresholdeventa2 {
		toleranceMark_m1thresholdeventa2 := bb.EnterComponent("M1thresholdeventA2")
		var dec_m1thresholdeventa2 s19.M1ThresholdEventA2
		if err := s19.BridgeM1ThresholdEventA2MethodUnmarshalAPERFrom(&dec_m1thresholdeventa2, bb); err != nil {
			return runtime.WrapDecodePath(err, "M1thresholdeventA2")
		}
		if err := aper.ChargeValue(bb, dec_m1thresholdeventa2); err != nil {
			return err
		}
		v.M1thresholdeventA2 = &dec_m1thresholdeventa2
		bb.LeaveComponent(toleranceMark_m1thresholdeventa2)
	}
	if opt_m1periodicreporting {
		toleranceMark_m1periodicreporting := bb.EnterComponent("M1periodicReporting")
		var dec_m1periodicreporting s19.M1PeriodicReporting
		if err := s19.BridgeM1PeriodicReportingMethodUnmarshalAPERFrom(&dec_m1periodicreporting, bb); err != nil {
			return runtime.WrapDecodePath(err, "M1periodicReporting")
		}
		if err := aper.ChargeValue(bb, dec_m1periodicreporting); err != nil {
			return err
		}
		v.M1periodicReporting = &dec_m1periodicreporting
		bb.LeaveComponent(toleranceMark_m1periodicreporting)
	}
	if opt_ieextensions {
		toleranceMark_ieextensions := bb.EnterComponent("IEExtensions")
		tmp_ieextensions := make(ImmediateMDTExtIEsExtContainer, 0)
		_, errCollection_ieextensions := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1128
			if fragmentOffset_ieextensions < 0 || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(^uint(0)>>1) || fragmentOffset_ieextensions > int64(^uint(0)>>1)-fragmentLength_ieextensions {
				return fmt.Errorf("collection fragment count out of range")
			}
			for i := int64(0); i < fragmentLength_ieextensions; i++ {
				var elem ImmediateMDTExtIEsExtField
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

// MarshalAPER encodes LoggedMDT to APER format.
func (v *LoggedMDT) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *LoggedMDT) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.LoggingInterval), 8, false); err != nil {
		return fmt.Errorf("encoding loggingInterval: %w", err)
	}
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.LoggingDuration), 6, false); err != nil {
		return fmt.Errorf("encoding loggingDuration: %w", err)
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

// UnmarshalAPER decodes LoggedMDT from APER format.
func (v *LoggedMDT) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes LoggedMDT with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *LoggedMDT) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "LoggedMDT")
	}
	bb.EnterComponent("LoggedMDT")
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "LoggedMDT")
	}
	padding, err := aper.CaptureFinalBits(bb, "LoggedMDT")
	if err != nil {
		return runtime.WrapDecodePath(err, "LoggedMDT")
	}
	v.perPadding = padding.WithRecords(v.perPadding)
	return nil
}
func (v *LoggedMDT) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = LoggedMDT{}
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
	val_logginginterval, err := aper.DecodeEnumeratedAligned(bb, 8, false, aper.EnumerationSource{KnownExtensions: 0, Path: "LoggingInterval"})
	if err != nil {
		return runtime.WrapDecodePath(err, "LoggingInterval")
	}
	v.LoggingInterval = s00.LoggingInterval(val_logginginterval)
	val_loggingduration, err := aper.DecodeEnumeratedAligned(bb, 6, false, aper.EnumerationSource{KnownExtensions: 0, Path: "LoggingDuration"})
	if err != nil {
		return runtime.WrapDecodePath(err, "LoggingDuration")
	}
	v.LoggingDuration = s00.LoggingDuration(val_loggingduration)
	if opt_ieextensions {
		toleranceMark_ieextensions := bb.EnterComponent("IEExtensions")
		tmp_ieextensions := make(LoggedMDTExtIEsExtContainer, 0)
		_, errCollection_ieextensions := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1128
			if fragmentOffset_ieextensions < 0 || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(^uint(0)>>1) || fragmentOffset_ieextensions > int64(^uint(0)>>1)-fragmentLength_ieextensions {
				return fmt.Errorf("collection fragment count out of range")
			}
			for i := int64(0); i < fragmentLength_ieextensions; i++ {
				var elem LoggedMDTExtIEsExtField
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

// MarshalAPER encodes MDTConfiguration to APER format.
func (v *MDTConfiguration) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *MDTConfiguration) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.MdtActivation), 3, true); err != nil {
		return fmt.Errorf("encoding mdt-Activation: %w", err)
	}
	if err := s32.BridgeAreaScopeOfMDTMethodMarshalAPERTo(&v.AreaScopeOfMDT, bb, len(fresh) != 0 && fresh[0]); err != nil {
		return fmt.Errorf("encoding areaScopeOfMDT: %w", err)
	}
	if err := v.MDTMode.marshalAPERTo(bb, len(fresh) != 0 && fresh[0]); err != nil {
		return fmt.Errorf("encoding mDTMode: %w", err)
	}
	if v.IEExtensions != nil {
		if err := aper.EncodeCollection(bb, int64(len(v.IEExtensions)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
			if fragmentOffset_ieextensions < 0 || fragmentOffset_ieextensions > int64(len(v.IEExtensions)) || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(len(v.IEExtensions[fragmentOffset_ieextensions:])) {
				return fmt.Errorf("collection fragment outside value")
			}
			for _, elem := range v.IEExtensions[fragmentOffset_ieextensions : fragmentOffset_ieextensions+fragmentLength_ieextensions] {
				if err := s42.BridgeMDTConfigurationExtIEsExtFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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

// UnmarshalAPER decodes MDTConfiguration from APER format.
func (v *MDTConfiguration) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes MDTConfiguration with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *MDTConfiguration) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "MDTConfiguration")
	}
	bb.EnterComponent("MDTConfiguration")
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "MDTConfiguration")
	}
	padding, err := aper.CaptureFinalBits(bb, "MDTConfiguration")
	if err != nil {
		return runtime.WrapDecodePath(err, "MDTConfiguration")
	}
	v.perPadding = padding.WithRecords(v.perPadding)
	return nil
}
func (v *MDTConfiguration) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = MDTConfiguration{}
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
	val_mdtactivation, err := aper.DecodeEnumeratedAligned(bb, 3, true, aper.EnumerationSource{KnownExtensions: 1, Path: "MdtActivation"})
	if err != nil {
		return runtime.WrapDecodePath(err, "MdtActivation")
	}
	v.MdtActivation = s00.MDTActivation(val_mdtactivation)
	toleranceMark_areascopeofmdt := bb.EnterComponent("AreaScopeOfMDT")
	if err := s32.BridgeAreaScopeOfMDTMethodUnmarshalAPERFrom(&v.AreaScopeOfMDT, bb); err != nil {
		return runtime.WrapDecodePath(err, "AreaScopeOfMDT")
	}
	bb.LeaveComponent(toleranceMark_areascopeofmdt)
	toleranceMark_mdtmode := bb.EnterComponent("MDTMode")
	if err := v.MDTMode.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "MDTMode")
	}
	bb.LeaveComponent(toleranceMark_mdtmode)
	if opt_ieextensions {
		toleranceMark_ieextensions := bb.EnterComponent("IEExtensions")
		tmp_ieextensions := make(s42.MDTConfigurationExtIEsExtContainer, 0)
		_, errCollection_ieextensions := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1128
			if fragmentOffset_ieextensions < 0 || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(^uint(0)>>1) || fragmentOffset_ieextensions > int64(^uint(0)>>1)-fragmentLength_ieextensions {
				return fmt.Errorf("collection fragment count out of range")
			}
			for i := int64(0); i < fragmentLength_ieextensions; i++ {
				var elem s42.MDTConfigurationExtIEsExtField
				elementMark := bb.EnterIndex(fragmentOffset_ieextensions + i)
				if err := s42.BridgeMDTConfigurationExtIEsExtFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
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

// MarshalAPER encodes MDTMode to APER format.
func (v *MDTMode) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.perPadding)
}
func (v *MDTMode) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
			return fmt.Errorf("%s known choice %d and unknown extension are both selected", "MDTMode:", v.Choice)
		}
		if v.UnknownExtension.Index() < 0 {
			return fmt.Errorf("%s extension index %d must be non-negative", "MDTMode:", v.UnknownExtension.Index())
		}
		if v.UnknownExtension.Index() < 1 {
			return fmt.Errorf("%s extension index %d is known to this schema", "MDTMode:", v.UnknownExtension.Index())
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
		return fmt.Errorf("%s choice %d must be positive", "MDTMode:", v.Choice)
	}
	isExtension := v.Choice > 2
	if err := aper.EncodeBoolean(bb, isExtension); err != nil {
		return err
	}
	if isExtension {
		// arithmetic pattern APER_CHOICE_EXT_ENCODE: choice index fits the emitted representation; gen/codegen_aper.go:117
		if v.Choice <= 2 {
			return fmt.Errorf("extension choice index outside root")
		}
		if err := aper.EncodeNormallySmallNonNegativeAligned(bb, int64(v.Choice-2-1)); err != nil {
			return err
		}
		inner := aper.NewBudgetBuffer(bb.Budget())
		switch v.Choice {
		case s00.MDTModeChoiceMDTModeExtension:
			if v.MDTModeExtension == nil {
				return fmt.Errorf("choice alternative mDTMode-Extension is nil")
			}
			if err := s19.BridgeMDTModeExtensionMethodMarshalAPERTo(v.MDTModeExtension, inner, len(fresh) != 0 && fresh[0]); err != nil {
				return fmt.Errorf("encoding mDTMode-Extension: %w", err)
			}
		default:
			return fmt.Errorf("unknown MDTMode extension choice %d", v.Choice)
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
	if err := aper.EncodeConstrainedWholeNumberAligned(bb, int64(v.Choice-1), 0, 1); err != nil {
		return err
	}
	switch v.Choice {
	case s00.MDTModeChoiceImmediateMDT:
		if v.ImmediateMDT == nil {
			return fmt.Errorf("choice alternative immediateMDT is nil")
		}
		if err := v.ImmediateMDT.marshalAPERTo(bb, len(fresh) != 0 && fresh[0]); err != nil {
			return fmt.Errorf("encoding immediateMDT: %w", err)
		}
	case s00.MDTModeChoiceLoggedMDT:
		if v.LoggedMDT == nil {
			return fmt.Errorf("choice alternative loggedMDT is nil")
		}
		if err := v.LoggedMDT.marshalAPERTo(bb, len(fresh) != 0 && fresh[0]); err != nil {
			return fmt.Errorf("encoding loggedMDT: %w", err)
		}
	default:
		return fmt.Errorf("unknown MDTMode choice %d", v.Choice)
	}
	return nil
}

// UnmarshalAPER decodes MDTMode from APER format.
func (v *MDTMode) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes MDTMode with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *MDTMode) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "MDTMode")
	}
	bb.EnterComponent("MDTMode")
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "MDTMode")
	}
	padding, err := aper.CaptureFinalBits(bb, "MDTMode")
	if err != nil {
		return runtime.WrapDecodePath(err, "MDTMode")
	}
	v.perPadding = padding.Padding()
	return nil
}
func (v *MDTMode) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = MDTMode{}
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
		if extIdx < 0 || extIdx >= int64(^uint(0)>>1)-int64(2) {
			return fmt.Errorf("extension choice index exceeds host int")
		}
		v.Choice = int(extIdx) + 2 + 1
		extensionPath := "UnknownExtension"
		switch v.Choice {
		case s00.MDTModeChoiceMDTModeExtension:
			extensionPath = "MDTModeExtension"
			toleranceMark_mdtmodeextension := inner.EnterComponent("MDTModeExtension")
			var dec_mdtmodeextension s19.MDTModeExtension
			if err := s19.BridgeMDTModeExtensionMethodUnmarshalAPERFrom(&dec_mdtmodeextension, inner); err != nil {
				return runtime.WrapDecodePath(err, "MDTModeExtension")
			}
			if err := aper.ChargeValue(inner, dec_mdtmodeextension); err != nil {
				return err
			}
			v.MDTModeExtension = &dec_mdtmodeextension
			inner.LeaveComponent(toleranceMark_mdtmodeextension)
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
	case s00.MDTModeChoiceImmediateMDT:
		toleranceMark_immediatemdt := bb.EnterComponent("ImmediateMDT")
		var dec_immediatemdt ImmediateMDT
		if err := dec_immediatemdt.unmarshalAPERFrom(bb); err != nil {
			return runtime.WrapDecodePath(err, "ImmediateMDT")
		}
		if err := aper.ChargeValue(bb, dec_immediatemdt); err != nil {
			return err
		}
		v.ImmediateMDT = &dec_immediatemdt
		bb.LeaveComponent(toleranceMark_immediatemdt)
	case s00.MDTModeChoiceLoggedMDT:
		toleranceMark_loggedmdt := bb.EnterComponent("LoggedMDT")
		var dec_loggedmdt LoggedMDT
		if err := dec_loggedmdt.unmarshalAPERFrom(bb); err != nil {
			return runtime.WrapDecodePath(err, "LoggedMDT")
		}
		if err := aper.ChargeValue(bb, dec_loggedmdt); err != nil {
			return err
		}
		v.LoggedMDT = &dec_loggedmdt
		bb.LeaveComponent(toleranceMark_loggedmdt)
	}
	v.stream = bb.CaptureWireSpan(replayStart)

	return nil
}

// MarshalAPER encodes TraceActivation to APER format.
func (v *TraceActivation) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *TraceActivation) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
	if err := aper.EncodeOctetStringAligned(bb, []byte(v.EUTRANTraceID), 8, 8, true); err != nil {
		return fmt.Errorf("encoding e-UTRAN-Trace-ID: %w", err)
	}
	if err := aper.EncodeBitStringAligned(bb, v.InterfacesToTrace.Bytes, v.InterfacesToTrace.BitLength, 8, 8, true); err != nil {
		return fmt.Errorf("encoding interfacesToTrace: %w", err)
	}
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.TraceDepth), 6, true); err != nil {
		return fmt.Errorf("encoding traceDepth: %w", err)
	}
	if err := aper.EncodeBitStringAlignedExt(bb, v.TraceCollectionEntityIPAddress.Bytes, v.TraceCollectionEntityIPAddress.BitLength, 1, 160, true, true); err != nil {
		return fmt.Errorf("encoding traceCollectionEntityIPAddress: %w", err)
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

// UnmarshalAPER decodes TraceActivation from APER format.
func (v *TraceActivation) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes TraceActivation with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *TraceActivation) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "TraceActivation")
	}
	bb.EnterComponent("TraceActivation")
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "TraceActivation")
	}
	padding, err := aper.CaptureFinalBits(bb, "TraceActivation")
	if err != nil {
		return runtime.WrapDecodePath(err, "TraceActivation")
	}
	v.perPadding = padding.WithRecords(v.perPadding)
	return nil
}
func (v *TraceActivation) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = TraceActivation{}
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
	val_eutrantraceid, err := aper.DecodeOctetStringAligned(bb, 8, 8, true)
	if err != nil {
		return runtime.WrapDecodePath(err, "EUTRANTraceID")
	}
	v.EUTRANTraceID = s00.EUTRANTraceID(val_eutrantraceid)
	bsBytes_interfacestotrace, bsBitLen_interfacestotrace, err := aper.DecodeBitStringAligned(bb, 8, 8, true)
	if err != nil {
		return runtime.WrapDecodePath(err, "InterfacesToTrace")
	}
	v.InterfacesToTrace = runtime.BitString{Bytes: bsBytes_interfacestotrace, BitLength: bsBitLen_interfacestotrace}
	val_tracedepth, err := aper.DecodeEnumeratedAligned(bb, 6, true, aper.EnumerationSource{KnownExtensions: 0, Path: "TraceDepth"})
	if err != nil {
		return runtime.WrapDecodePath(err, "TraceDepth")
	}
	v.TraceDepth = s00.TraceDepth(val_tracedepth)
	bsBytes_tracecollectionentityipaddress, bsBitLen_tracecollectionentityipaddress, err := aper.DecodeBitStringAlignedExt(bb, 1, 160, true, true)
	if err != nil {
		return runtime.WrapDecodePath(err, "TraceCollectionEntityIPAddress")
	}
	v.TraceCollectionEntityIPAddress = runtime.BitString{Bytes: bsBytes_tracecollectionentityipaddress, BitLength: bsBitLen_tracecollectionentityipaddress}
	if opt_ieextensions {
		toleranceMark_ieextensions := bb.EnterComponent("IEExtensions")
		tmp_ieextensions := make(TraceActivationExtIEsExtContainer, 0)
		_, errCollection_ieextensions := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1128
			if fragmentOffset_ieextensions < 0 || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(^uint(0)>>1) || fragmentOffset_ieextensions > int64(^uint(0)>>1)-fragmentLength_ieextensions {
				return fmt.Errorf("collection fragment count out of range")
			}
			for i := int64(0); i < fragmentLength_ieextensions; i++ {
				var elem TraceActivationExtIEsExtField
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

// MarshalAPER encodes WLANMeasurementConfiguration to APER format.
func (v *WLANMeasurementConfiguration) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *WLANMeasurementConfiguration) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
	if err := aper.EncodeBoolean(bb, v.WlanMeasConfigNameList != nil); err != nil {
		return err
	}
	if err := aper.EncodeBoolean(bb, v.WlanRssi != nil); err != nil {
		return err
	}
	if err := aper.EncodeBoolean(bb, v.WlanRtt != nil); err != nil {
		return err
	}
	if err := aper.EncodeBoolean(bb, v.IEExtensions != nil); err != nil {
		return err
	}
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.WlanMeasConfig), 1, true); err != nil {
		return fmt.Errorf("encoding wlanMeasConfig: %w", err)
	}
	if v.WlanMeasConfigNameList != nil {
		if err := aper.EncodeCollection(bb, int64(len(v.WlanMeasConfigNameList)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 4, HasUpper: true}, true, func(fragmentOffset_wlanmeasconfignamelist, fragmentLength_wlanmeasconfignamelist int64) error {
			// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
			if fragmentOffset_wlanmeasconfignamelist < 0 || fragmentOffset_wlanmeasconfignamelist > int64(len(v.WlanMeasConfigNameList)) || fragmentLength_wlanmeasconfignamelist < 0 || fragmentLength_wlanmeasconfignamelist > int64(len(v.WlanMeasConfigNameList[fragmentOffset_wlanmeasconfignamelist:])) {
				return fmt.Errorf("collection fragment outside value")
			}
			for _, elem := range v.WlanMeasConfigNameList[fragmentOffset_wlanmeasconfignamelist : fragmentOffset_wlanmeasconfignamelist+fragmentLength_wlanmeasconfignamelist] {
				if err := aper.EncodeOctetStringAligned(bb, []byte(elem), 1, 32, true); err != nil {
					return fmt.Errorf("encoding wlanMeasConfigNameList element: %w", err)
				}
			}
			return nil
		}); err != nil {
			return fmt.Errorf("encoding wlanMeasConfigNameList: %w", err)
		}
	}
	if v.WlanRssi != nil {
		if err := aper.EncodeEnumeratedAligned(bb, int64(*v.WlanRssi), 1, true); err != nil {
			return fmt.Errorf("encoding wlan-rssi: %w", err)
		}
	}
	if v.WlanRtt != nil {
		if err := aper.EncodeEnumeratedAligned(bb, int64(*v.WlanRtt), 1, true); err != nil {
			return fmt.Errorf("encoding wlan-rtt: %w", err)
		}
	}
	if v.IEExtensions != nil {
		if err := aper.EncodeCollection(bb, int64(len(v.IEExtensions)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
			if fragmentOffset_ieextensions < 0 || fragmentOffset_ieextensions > int64(len(v.IEExtensions)) || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(len(v.IEExtensions[fragmentOffset_ieextensions:])) {
				return fmt.Errorf("collection fragment outside value")
			}
			for _, elem := range v.IEExtensions[fragmentOffset_ieextensions : fragmentOffset_ieextensions+fragmentLength_ieextensions] {
				if err := s12.BridgeWLANMeasurementConfigurationExtIEsExtFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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

// UnmarshalAPER decodes WLANMeasurementConfiguration from APER format.
func (v *WLANMeasurementConfiguration) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes WLANMeasurementConfiguration with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *WLANMeasurementConfiguration) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "WLANMeasurementConfiguration")
	}
	bb.EnterComponent("WLANMeasurementConfiguration")
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "WLANMeasurementConfiguration")
	}
	padding, err := aper.CaptureFinalBits(bb, "WLANMeasurementConfiguration")
	if err != nil {
		return runtime.WrapDecodePath(err, "WLANMeasurementConfiguration")
	}
	v.perPadding = padding.WithRecords(v.perPadding)
	return nil
}
func (v *WLANMeasurementConfiguration) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = WLANMeasurementConfiguration{}
	extAdditions := aper.BeginExtensionAdditions(bb)
	hasExtensions, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	// Read preamble bitmap for optional root fields
	opt_wlanmeasconfignamelist, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	opt_wlanrssi, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	opt_wlanrtt, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	opt_ieextensions, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	val_wlanmeasconfig, err := aper.DecodeEnumeratedAligned(bb, 1, true, aper.EnumerationSource{KnownExtensions: 0, Path: "WlanMeasConfig"})
	if err != nil {
		return runtime.WrapDecodePath(err, "WlanMeasConfig")
	}
	v.WlanMeasConfig = s00.WLANMeasConfig(val_wlanmeasconfig)
	if opt_wlanmeasconfignamelist {
		toleranceMark_wlanmeasconfignamelist := bb.EnterComponent("WlanMeasConfigNameList")
		tmp_wlanmeasconfignamelist := make(s00.WLANMeasConfigNameList, 0)
		_, errCollection_wlanmeasconfignamelist := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 4, HasUpper: true}, true, func(fragmentOffset_wlanmeasconfignamelist, fragmentLength_wlanmeasconfignamelist int64) error {
			// arithmetic pattern APER_FRAGMENT_LOOP_5: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1191
			if fragmentOffset_wlanmeasconfignamelist < 0 || fragmentLength_wlanmeasconfignamelist < 0 || fragmentLength_wlanmeasconfignamelist > int64(^uint(0)>>1) || fragmentOffset_wlanmeasconfignamelist > int64(^uint(0)>>1)-fragmentLength_wlanmeasconfignamelist {
				return fmt.Errorf("collection fragment count out of range")
			}
			for i := int64(0); i < fragmentLength_wlanmeasconfignamelist; i++ {
				val, err := aper.DecodeOctetStringAligned(bb, 1, 32, true)
				if err != nil {
					return runtime.WrapDecodePath(err, fmt.Sprintf("WlanMeasConfigNameList[%d]", fragmentOffset_wlanmeasconfignamelist+i))
				}
				if next, err := aper.AppendValues(bb, tmp_wlanmeasconfignamelist, val); err != nil {
					return err
				} else {
					tmp_wlanmeasconfignamelist = next
				}
			}
			return nil
		})
		if errCollection_wlanmeasconfignamelist != nil {
			return runtime.WrapDecodePath(errCollection_wlanmeasconfignamelist, "WlanMeasConfigNameList")
		}
		v.WlanMeasConfigNameList = tmp_wlanmeasconfignamelist
		bb.LeaveComponent(toleranceMark_wlanmeasconfignamelist)
	}
	if opt_wlanrssi {
		val_wlanrssi, err := aper.DecodeEnumeratedAligned(bb, 1, true, aper.EnumerationSource{KnownExtensions: 0, Path: "WlanRssi"})
		if err != nil {
			return runtime.WrapDecodePath(err, "WlanRssi")
		}
		if err := aper.ChargeValue(bb, val_wlanrssi); err != nil {
			return err
		}
		v.WlanRssi = (*int64)(bb.OwnInt64(int64(val_wlanrssi)))

	}
	if opt_wlanrtt {
		val_wlanrtt, err := aper.DecodeEnumeratedAligned(bb, 1, true, aper.EnumerationSource{KnownExtensions: 0, Path: "WlanRtt"})
		if err != nil {
			return runtime.WrapDecodePath(err, "WlanRtt")
		}
		if err := aper.ChargeValue(bb, val_wlanrtt); err != nil {
			return err
		}
		v.WlanRtt = (*int64)(bb.OwnInt64(int64(val_wlanrtt)))

	}
	if opt_ieextensions {
		toleranceMark_ieextensions := bb.EnterComponent("IEExtensions")
		tmp_ieextensions := make(s12.WLANMeasurementConfigurationExtIEsExtContainer, 0)
		_, errCollection_ieextensions := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1128
			if fragmentOffset_ieextensions < 0 || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(^uint(0)>>1) || fragmentOffset_ieextensions > int64(^uint(0)>>1)-fragmentLength_ieextensions {
				return fmt.Errorf("collection fragment count out of range")
			}
			for i := int64(0); i < fragmentLength_ieextensions; i++ {
				var elem s12.WLANMeasurementConfigurationExtIEsExtField
				elementMark := bb.EnterIndex(fragmentOffset_ieextensions + i)
				if err := s12.BridgeWLANMeasurementConfigurationExtIEsExtFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
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
func (v *ImmediateMDT) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s14.BridgeReceivedFormAt(v.received, v.receivedBytes, "ImmediateMDT", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "ImmediateMDT", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v ImmediateMDT) WithoutReplay() ImmediateMDT {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero ImmediateMDT
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *LoggedMDT) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s14.BridgeReceivedFormAt(v.received, v.receivedBytes, "LoggedMDT", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "LoggedMDT", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v LoggedMDT) WithoutReplay() LoggedMDT {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero LoggedMDT
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *MDTConfiguration) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s14.BridgeReceivedFormAt(v.received, v.receivedBytes, "MDTConfiguration", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "MDTConfiguration", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v MDTConfiguration) WithoutReplay() MDTConfiguration {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero MDTConfiguration
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *MDTMode) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s14.BridgeReceivedFormAt(v.received, v.receivedBytes, "MDTMode", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "MDTMode", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v MDTMode) WithoutReplay() MDTMode {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero MDTMode
	v.perPadding = zero.perPadding
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *TraceActivation) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s14.BridgeReceivedFormAt(v.received, v.receivedBytes, "TraceActivation", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "TraceActivation", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v TraceActivation) WithoutReplay() TraceActivation {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero TraceActivation
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *WLANMeasurementConfiguration) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s14.BridgeReceivedFormAt(v.received, v.receivedBytes, "WLANMeasurementConfiguration", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "WLANMeasurementConfiguration", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v WLANMeasurementConfiguration) WithoutReplay() WLANMeasurementConfiguration {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero WLANMeasurementConfiguration
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// Extensions returns owned unknown sequence additions.
func (v *ImmediateMDT) Extensions() []aper.SequenceExtension {
	if v == nil {
		return nil
	}
	views := aper.SequenceExtensionViews(v.extPresent, aper.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *ImmediateMDT) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("ImmediateMDT.Extensions[%d]", index))
	}
	if err := aper.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("ImmediateMDT.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *ImmediateMDT) RemoveExtension(index uint64) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("ImmediateMDT.Extensions[%d]", index))
	}
	if err := aper.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("ImmediateMDT.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// Extensions returns owned unknown sequence additions.
func (v *LoggedMDT) Extensions() []aper.SequenceExtension {
	if v == nil {
		return nil
	}
	views := aper.SequenceExtensionViews(v.extPresent, aper.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *LoggedMDT) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("LoggedMDT.Extensions[%d]", index))
	}
	if err := aper.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("LoggedMDT.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *LoggedMDT) RemoveExtension(index uint64) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("LoggedMDT.Extensions[%d]", index))
	}
	if err := aper.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("LoggedMDT.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// Extensions returns owned unknown sequence additions.
func (v *MDTConfiguration) Extensions() []aper.SequenceExtension {
	if v == nil {
		return nil
	}
	views := aper.SequenceExtensionViews(v.extPresent, aper.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *MDTConfiguration) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("MDTConfiguration.Extensions[%d]", index))
	}
	if err := aper.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("MDTConfiguration.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *MDTConfiguration) RemoveExtension(index uint64) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("MDTConfiguration.Extensions[%d]", index))
	}
	if err := aper.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("MDTConfiguration.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// Extensions returns owned unknown sequence additions.
func (v *TraceActivation) Extensions() []aper.SequenceExtension {
	if v == nil {
		return nil
	}
	views := aper.SequenceExtensionViews(v.extPresent, aper.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *TraceActivation) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("TraceActivation.Extensions[%d]", index))
	}
	if err := aper.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("TraceActivation.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *TraceActivation) RemoveExtension(index uint64) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("TraceActivation.Extensions[%d]", index))
	}
	if err := aper.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("TraceActivation.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// Extensions returns owned unknown sequence additions.
func (v *WLANMeasurementConfiguration) Extensions() []aper.SequenceExtension {
	if v == nil {
		return nil
	}
	views := aper.SequenceExtensionViews(v.extPresent, aper.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *WLANMeasurementConfiguration) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("WLANMeasurementConfiguration.Extensions[%d]", index))
	}
	if err := aper.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("WLANMeasurementConfiguration.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *WLANMeasurementConfiguration) RemoveExtension(index uint64) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("WLANMeasurementConfiguration.Extensions[%d]", index))
	}
	if err := aper.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("WLANMeasurementConfiguration.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// MarshalAPER encodes a complete value using one per-call change plan.
func (v *ImmediateMDT) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "ImmediateMDT")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *ImmediateMDT) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "ImmediateMDT")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APImmediateMDT(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "ImmediateMDT")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "ImmediateMDT")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *ImmediateMDT) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "ImmediateMDT")
}
func (v *ImmediateMDT) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "ImmediateMDT")
}
func (v *ImmediateMDT) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APImmediateMDT(v, &s)
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
func (v *ImmediateMDT) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *ImmediateMDT) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
func (v *LoggedMDT) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "LoggedMDT")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *LoggedMDT) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "LoggedMDT")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APLoggedMDT(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "LoggedMDT")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "LoggedMDT")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *LoggedMDT) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "LoggedMDT")
}
func (v *LoggedMDT) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "LoggedMDT")
}
func (v *LoggedMDT) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APLoggedMDT(v, &s)
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
func (v *LoggedMDT) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *LoggedMDT) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
func (v *MDTConfiguration) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "MDTConfiguration")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *MDTConfiguration) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "MDTConfiguration")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APMDTConfiguration(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "MDTConfiguration")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "MDTConfiguration")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *MDTConfiguration) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "MDTConfiguration")
}
func (v *MDTConfiguration) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "MDTConfiguration")
}
func (v *MDTConfiguration) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APMDTConfiguration(v, &s)
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
func (v *MDTConfiguration) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *MDTConfiguration) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
func (v *MDTMode) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "MDTMode")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *MDTMode) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "MDTMode")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APMDTMode(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "MDTMode")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "MDTMode")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *MDTMode) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "MDTMode")
}
func (v *MDTMode) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "MDTMode")
}
func (v *MDTMode) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APMDTMode(v, &s)
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
func (v *MDTMode) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *MDTMode) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
func (v *TraceActivation) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "TraceActivation")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *TraceActivation) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "TraceActivation")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APTraceActivation(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "TraceActivation")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "TraceActivation")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *TraceActivation) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "TraceActivation")
}
func (v *TraceActivation) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "TraceActivation")
}
func (v *TraceActivation) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APTraceActivation(v, &s)
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
func (v *TraceActivation) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *TraceActivation) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
func (v *WLANMeasurementConfiguration) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "WLANMeasurementConfiguration")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *WLANMeasurementConfiguration) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "WLANMeasurementConfiguration")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APWLANMeasurementConfiguration(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "WLANMeasurementConfiguration")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "WLANMeasurementConfiguration")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *WLANMeasurementConfiguration) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "WLANMeasurementConfiguration")
}
func (v *WLANMeasurementConfiguration) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "WLANMeasurementConfiguration")
}
func (v *WLANMeasurementConfiguration) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APWLANMeasurementConfiguration(v, &s)
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
func (v *WLANMeasurementConfiguration) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *WLANMeasurementConfiguration) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
func (v *ImmediateMDT) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "ImmediateMDT")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded ImmediateMDT
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APImmediateMDT(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = ImmediateMDT{}
		return report, aper.OperationError(err, "ImmediateMDT")
	}
	*v = decoded
	return report, aper.OperationError(nil, "ImmediateMDT")
}

// UnmarshalAPER decodes one complete value and returns its report.
func (v *LoggedMDT) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "LoggedMDT")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded LoggedMDT
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APLoggedMDT(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = LoggedMDT{}
		return report, aper.OperationError(err, "LoggedMDT")
	}
	*v = decoded
	return report, aper.OperationError(nil, "LoggedMDT")
}

// UnmarshalAPER decodes one complete value and returns its report.
func (v *MDTConfiguration) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "MDTConfiguration")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded MDTConfiguration
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APMDTConfiguration(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = MDTConfiguration{}
		return report, aper.OperationError(err, "MDTConfiguration")
	}
	*v = decoded
	return report, aper.OperationError(nil, "MDTConfiguration")
}

// UnmarshalAPER decodes one complete value and returns its report.
func (v *MDTMode) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "MDTMode")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded MDTMode
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APMDTMode(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = MDTMode{}
		return report, aper.OperationError(err, "MDTMode")
	}
	*v = decoded
	return report, aper.OperationError(nil, "MDTMode")
}

// UnmarshalAPER decodes one complete value and returns its report.
func (v *TraceActivation) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "TraceActivation")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded TraceActivation
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APTraceActivation(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = TraceActivation{}
		return report, aper.OperationError(err, "TraceActivation")
	}
	*v = decoded
	return report, aper.OperationError(nil, "TraceActivation")
}

// UnmarshalAPER decodes one complete value and returns its report.
func (v *WLANMeasurementConfiguration) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "WLANMeasurementConfiguration")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded WLANMeasurementConfiguration
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APWLANMeasurementConfiguration(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = WLANMeasurementConfiguration{}
		return report, aper.OperationError(err, "WLANMeasurementConfiguration")
	}
	*v = decoded
	return report, aper.OperationError(nil, "WLANMeasurementConfiguration")
}

// NewMDTModeImmediateMDT constructs a checked complete value.
func NewMDTModeImmediateMDT(v ImmediateMDT, options ...aper.BuildOption) (MDTMode, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return MDTMode{}, aper.OperationError(err, "MDTModeImmediateMDT")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), v); err != nil {
		return MDTMode{}, aper.OperationError(err, "MDTModeImmediateMDT")
	}
	value := BridgeNewMDTModeImmediateMDTLegacy(v)
	if _, err := (&value).marshalAPERBudget(budget, false); err != nil {
		return MDTMode{}, aper.OperationError(err, "MDTModeImmediateMDT")
	}
	return value, aper.OperationError(nil, "MDTModeImmediateMDT")
}

// NewMDTModeLoggedMDT constructs a checked complete value.
func NewMDTModeLoggedMDT(v LoggedMDT, options ...aper.BuildOption) (MDTMode, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return MDTMode{}, aper.OperationError(err, "MDTModeLoggedMDT")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), v); err != nil {
		return MDTMode{}, aper.OperationError(err, "MDTModeLoggedMDT")
	}
	value := BridgeNewMDTModeLoggedMDTLegacy(v)
	if _, err := (&value).marshalAPERBudget(budget, false); err != nil {
		return MDTMode{}, aper.OperationError(err, "MDTModeLoggedMDT")
	}
	return value, aper.OperationError(nil, "MDTModeLoggedMDT")
}

// NewMDTModeMDTModeExtension constructs a checked complete value.
func NewMDTModeMDTModeExtension(v s19.MDTModeExtension, options ...aper.BuildOption) (MDTMode, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return MDTMode{}, aper.OperationError(err, "MDTModeMDTModeExtension")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), v); err != nil {
		return MDTMode{}, aper.OperationError(err, "MDTModeMDTModeExtension")
	}
	value := BridgeNewMDTModeMDTModeExtensionLegacy(v)
	if _, err := (&value).marshalAPERBudget(budget, false); err != nil {
		return MDTMode{}, aper.OperationError(err, "MDTModeMDTModeExtension")
	}
	return value, aper.OperationError(nil, "MDTModeMDTModeExtension")
}

// NewMDTModeUnknownExtension builds a checked, owned unknown CHOICE alternative.
func NewMDTModeUnknownExtension(index uint64, contents []byte, options ...aper.BuildOption) (MDTMode, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return MDTMode{}, aper.OperationError(err, "MDTModeUnknownExtension")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), aper.ChoiceExtension{}); err != nil {
		return MDTMode{}, aper.OperationError(err, "MDTModeUnknownExtension")
	}
	extension, err := aper.BuildChoiceExtension(index, contents, budget)
	if err != nil {
		return MDTMode{}, aper.OperationError(err, "MDTModeUnknownExtension")
	}
	value := MDTMode{UnknownExtension: &extension}
	if _, err := value.marshalAPERBudget(budget, false); err != nil {
		return MDTMode{}, aper.OperationError(err, "MDTModeUnknownExtension")
	}
	return value, aper.OperationError(nil, "MDTModeUnknownExtension")
}

// PathSwitchRequestAcknowledge represents the ASN.1 type PathSwitchRequestAcknowledge (SEQUENCE).
type PathSwitchRequestAcknowledge struct {
	replay           aper.Snapshot
	stream           aper.WireSpan
	received         bool
	withoutReplay    bool
	receivedAbsolute bool
	receivedBytes    aper.WireSpan
	receivedLocation aper.Location
	ProtocolIEs      s46.PathSwitchRequestAcknowledgeIEContainer `asn1:"tag:0,context,implicit"`
	protocolIEsIndef bool                                        `asn1:"-" json:"-"`
	extCount         int64                                       `asn1:"-" json:"-"`
	extPresent       []bool                                      `asn1:"-" json:"-"`
	extData          [][]byte                                    `asn1:"-" json:"-"`
	perPadding       aper.FinalPadding                           `asn1:"-" json:"-"`
	perExtPadding    []aper.CompletePadding                      `asn1:"-" json:"-"`
	extOrigin        []aper.OpaqueOrigin
	extWire          []aper.WireSpan
}

// UEContextModificationRequest represents the ASN.1 type UEContextModificationRequest (SEQUENCE).
type UEContextModificationRequest struct {
	replay           aper.Snapshot
	stream           aper.WireSpan
	received         bool
	withoutReplay    bool
	receivedAbsolute bool
	receivedBytes    aper.WireSpan
	receivedLocation aper.Location
	ProtocolIEs      s46.UEContextModificationRequestIEContainer `asn1:"tag:0,context,implicit"`
	protocolIEsIndef bool                                        `asn1:"-" json:"-"`
	extCount         int64                                       `asn1:"-" json:"-"`
	extPresent       []bool                                      `asn1:"-" json:"-"`
	extData          [][]byte                                    `asn1:"-" json:"-"`
	perPadding       aper.FinalPadding                           `asn1:"-" json:"-"`
	perExtPadding    []aper.CompletePadding                      `asn1:"-" json:"-"`
	extOrigin        []aper.OpaqueOrigin
	extWire          []aper.WireSpan
}

// MarshalAPER encodes PathSwitchRequestAcknowledge to APER format.
func (v *PathSwitchRequestAcknowledge) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *PathSwitchRequestAcknowledge) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
			if err := s46.BridgePathSwitchRequestAcknowledgeIEFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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

// UnmarshalAPER decodes PathSwitchRequestAcknowledge from APER format.
func (v *PathSwitchRequestAcknowledge) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes PathSwitchRequestAcknowledge with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *PathSwitchRequestAcknowledge) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "PathSwitchRequestAcknowledge")
	}
	bb.EnterComponent("PathSwitchRequestAcknowledge")
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "PathSwitchRequestAcknowledge")
	}
	padding, err := aper.CaptureFinalBits(bb, "PathSwitchRequestAcknowledge")
	if err != nil {
		return runtime.WrapDecodePath(err, "PathSwitchRequestAcknowledge")
	}
	v.perPadding = padding.WithRecords(v.perPadding)
	return nil
}
func (v *PathSwitchRequestAcknowledge) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = PathSwitchRequestAcknowledge{}
	extAdditions := aper.BeginExtensionAdditions(bb)
	hasExtensions, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	toleranceMark_protocolies := bb.EnterComponent("ProtocolIEs")
	v.ProtocolIEs = make(s46.PathSwitchRequestAcknowledgeIEContainer, 0)
	_, errCollection_protocolies := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1128
		if fragmentOffset_protocolies < 0 || fragmentLength_protocolies < 0 || fragmentLength_protocolies > int64(^uint(0)>>1) || fragmentOffset_protocolies > int64(^uint(0)>>1)-fragmentLength_protocolies {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_protocolies; i++ {
			var elem s46.PathSwitchRequestAcknowledgeIEField
			elementMark := bb.EnterIndex(fragmentOffset_protocolies + i)
			if err := s46.BridgePathSwitchRequestAcknowledgeIEFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
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

// MarshalAPER encodes UEContextModificationRequest to APER format.
func (v *UEContextModificationRequest) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *UEContextModificationRequest) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
			if err := s46.BridgeUEContextModificationRequestIEFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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

// UnmarshalAPER decodes UEContextModificationRequest from APER format.
func (v *UEContextModificationRequest) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes UEContextModificationRequest with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *UEContextModificationRequest) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "UEContextModificationRequest")
	}
	bb.EnterComponent("UEContextModificationRequest")
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "UEContextModificationRequest")
	}
	padding, err := aper.CaptureFinalBits(bb, "UEContextModificationRequest")
	if err != nil {
		return runtime.WrapDecodePath(err, "UEContextModificationRequest")
	}
	v.perPadding = padding.WithRecords(v.perPadding)
	return nil
}
func (v *UEContextModificationRequest) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = UEContextModificationRequest{}
	extAdditions := aper.BeginExtensionAdditions(bb)
	hasExtensions, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	toleranceMark_protocolies := bb.EnterComponent("ProtocolIEs")
	v.ProtocolIEs = make(s46.UEContextModificationRequestIEContainer, 0)
	_, errCollection_protocolies := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1128
		if fragmentOffset_protocolies < 0 || fragmentLength_protocolies < 0 || fragmentLength_protocolies > int64(^uint(0)>>1) || fragmentOffset_protocolies > int64(^uint(0)>>1)-fragmentLength_protocolies {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_protocolies; i++ {
			var elem s46.UEContextModificationRequestIEField
			elementMark := bb.EnterIndex(fragmentOffset_protocolies + i)
			if err := s46.BridgeUEContextModificationRequestIEFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
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
func (v *PathSwitchRequestAcknowledge) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s14.BridgeReceivedFormAt(v.received, v.receivedBytes, "PathSwitchRequestAcknowledge", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "PathSwitchRequestAcknowledge", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v PathSwitchRequestAcknowledge) WithoutReplay() PathSwitchRequestAcknowledge {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero PathSwitchRequestAcknowledge
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *UEContextModificationRequest) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s14.BridgeReceivedFormAt(v.received, v.receivedBytes, "UEContextModificationRequest", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "UEContextModificationRequest", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v UEContextModificationRequest) WithoutReplay() UEContextModificationRequest {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero UEContextModificationRequest
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// Extensions returns owned unknown sequence additions.
func (v *PathSwitchRequestAcknowledge) Extensions() []aper.SequenceExtension {
	if v == nil {
		return nil
	}
	views := aper.SequenceExtensionViews(v.extPresent, aper.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *PathSwitchRequestAcknowledge) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("PathSwitchRequestAcknowledge.Extensions[%d]", index))
	}
	if err := aper.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("PathSwitchRequestAcknowledge.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *PathSwitchRequestAcknowledge) RemoveExtension(index uint64) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("PathSwitchRequestAcknowledge.Extensions[%d]", index))
	}
	if err := aper.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("PathSwitchRequestAcknowledge.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// Extensions returns owned unknown sequence additions.
func (v *UEContextModificationRequest) Extensions() []aper.SequenceExtension {
	if v == nil {
		return nil
	}
	views := aper.SequenceExtensionViews(v.extPresent, aper.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *UEContextModificationRequest) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("UEContextModificationRequest.Extensions[%d]", index))
	}
	if err := aper.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("UEContextModificationRequest.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *UEContextModificationRequest) RemoveExtension(index uint64) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("UEContextModificationRequest.Extensions[%d]", index))
	}
	if err := aper.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("UEContextModificationRequest.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// MarshalAPER encodes a complete value using one per-call change plan.
func (v *PathSwitchRequestAcknowledge) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "PathSwitchRequestAcknowledge")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *PathSwitchRequestAcknowledge) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "PathSwitchRequestAcknowledge")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APPathSwitchRequestAcknowledge(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "PathSwitchRequestAcknowledge")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "PathSwitchRequestAcknowledge")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *PathSwitchRequestAcknowledge) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "PathSwitchRequestAcknowledge")
}
func (v *PathSwitchRequestAcknowledge) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "PathSwitchRequestAcknowledge")
}
func (v *PathSwitchRequestAcknowledge) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APPathSwitchRequestAcknowledge(v, &s)
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
func (v *PathSwitchRequestAcknowledge) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *PathSwitchRequestAcknowledge) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
func (v *UEContextModificationRequest) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "UEContextModificationRequest")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *UEContextModificationRequest) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "UEContextModificationRequest")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APUEContextModificationRequest(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "UEContextModificationRequest")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "UEContextModificationRequest")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *UEContextModificationRequest) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "UEContextModificationRequest")
}
func (v *UEContextModificationRequest) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "UEContextModificationRequest")
}
func (v *UEContextModificationRequest) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APUEContextModificationRequest(v, &s)
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
func (v *UEContextModificationRequest) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *UEContextModificationRequest) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
func (v *PathSwitchRequestAcknowledge) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "PathSwitchRequestAcknowledge")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded PathSwitchRequestAcknowledge
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APPathSwitchRequestAcknowledge(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = PathSwitchRequestAcknowledge{}
		return report, aper.OperationError(err, "PathSwitchRequestAcknowledge")
	}
	*v = decoded
	return report, aper.OperationError(nil, "PathSwitchRequestAcknowledge")
}

// UnmarshalAPER decodes one complete value and returns its report.
func (v *UEContextModificationRequest) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "UEContextModificationRequest")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded UEContextModificationRequest
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APUEContextModificationRequest(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = UEContextModificationRequest{}
		return report, aper.OperationError(err, "UEContextModificationRequest")
	}
	*v = decoded
	return report, aper.OperationError(nil, "UEContextModificationRequest")
}

type ImmediateMDTExtIEsValue struct {
	id                                   s00.ProtocolIEID
	received                             aper.WireSpan
	replay                               aper.Snapshot
	opaque                               aper.OpaqueOpenType
	isOpaque                             bool
	rowM3Configuration                   *s19.M3Configuration
	rowM4Configuration                   *s19.M4Configuration
	rowM5Configuration                   *s19.M5Configuration
	rowMDTLocationInfo                   *s00.MDTLocationInfo
	rowM6Configuration                   *s19.M6Configuration
	rowM7Configuration                   *s19.M7Configuration
	rowBluetoothMeasurementConfiguration *s14.BluetoothMeasurementConfiguration
	rowWLANMeasurementConfiguration      *WLANMeasurementConfiguration
	rowSensorMeasurementConfiguration    *s30.SensorMeasurementConfiguration
}

func (v ImmediateMDTExtIEsValue) matchesID(id s00.ProtocolIEID, _ ...*aper.DecodeBudget) bool {
	if v.id != id {
		return false
	}
	if v.isOpaque {
		return true
	}
	switch id {
	case s00.ProtocolIEID(171):
		return v.rowM3Configuration != nil
	case s00.ProtocolIEID(172):
		return v.rowM4Configuration != nil
	case s00.ProtocolIEID(173):
		return v.rowM5Configuration != nil
	case s00.ProtocolIEID(174):
		return v.rowMDTLocationInfo != nil
	case s00.ProtocolIEID(220):
		return v.rowM6Configuration != nil
	case s00.ProtocolIEID(221):
		return v.rowM7Configuration != nil
	case s00.ProtocolIEID(284):
		return v.rowBluetoothMeasurementConfiguration != nil
	case s00.ProtocolIEID(285):
		return v.rowWLANMeasurementConfiguration != nil
	case s00.ProtocolIEID(345):
		return v.rowSensorMeasurementConfiguration != nil
	}
	return false
}

// Opaque returns the retained opaque open value of ImmediateMDTExtIEsValue and reports whether the opaque alternative is selected.
func (v *ImmediateMDTExtIEsValue) Opaque() (aper.OpaqueOpenType, bool) {
	if v == nil || !v.isOpaque {
		return aper.OpaqueOpenType{}, false
	}
	return v.opaque, true
}
func (ImmediateMDTExtIEsValue) rule() aper.SourceRule {
	return aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.4", Assignment: aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "ImmediateMDT-ExtIEs"}}
}
func (ImmediateMDTExtIEsValue) reason(id s00.ProtocolIEID) aper.OpaqueReason {
	switch id {
	case s00.ProtocolIEID(171):
		return aper.UnknownSelector
	case s00.ProtocolIEID(172):
		return aper.UnknownSelector
	case s00.ProtocolIEID(173):
		return aper.UnknownSelector
	case s00.ProtocolIEID(174):
		return aper.UnknownSelector
	case s00.ProtocolIEID(220):
		return aper.UnknownSelector
	case s00.ProtocolIEID(221):
		return aper.UnknownSelector
	case s00.ProtocolIEID(284):
		return aper.UnknownSelector
	case s00.ProtocolIEID(285):
		return aper.UnknownSelector
	case s00.ProtocolIEID(345):
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

// AsM3Configuration returns the selected M3Configuration value of ImmediateMDTExtIEsValue and reports whether that alternative is active.
func (v *ImmediateMDTExtIEsValue) AsM3Configuration() (*s19.M3Configuration, bool) {
	if v == nil || v.id != s00.ProtocolIEID(171) || v.rowM3Configuration == nil {
		return nil, false
	}
	return v.rowM3Configuration, true
}

// AsM4Configuration returns the selected M4Configuration value of ImmediateMDTExtIEsValue and reports whether that alternative is active.
func (v *ImmediateMDTExtIEsValue) AsM4Configuration() (*s19.M4Configuration, bool) {
	if v == nil || v.id != s00.ProtocolIEID(172) || v.rowM4Configuration == nil {
		return nil, false
	}
	return v.rowM4Configuration, true
}

// AsM5Configuration returns the selected M5Configuration value of ImmediateMDTExtIEsValue and reports whether that alternative is active.
func (v *ImmediateMDTExtIEsValue) AsM5Configuration() (*s19.M5Configuration, bool) {
	if v == nil || v.id != s00.ProtocolIEID(173) || v.rowM5Configuration == nil {
		return nil, false
	}
	return v.rowM5Configuration, true
}

// AsMDTLocationInfo returns the selected MDTLocationInfo value of ImmediateMDTExtIEsValue and reports whether that alternative is active.
func (v *ImmediateMDTExtIEsValue) AsMDTLocationInfo() (*s00.MDTLocationInfo, bool) {
	if v == nil || v.id != s00.ProtocolIEID(174) || v.rowMDTLocationInfo == nil {
		return nil, false
	}
	return v.rowMDTLocationInfo, true
}

// AsM6Configuration returns the selected M6Configuration value of ImmediateMDTExtIEsValue and reports whether that alternative is active.
func (v *ImmediateMDTExtIEsValue) AsM6Configuration() (*s19.M6Configuration, bool) {
	if v == nil || v.id != s00.ProtocolIEID(220) || v.rowM6Configuration == nil {
		return nil, false
	}
	return v.rowM6Configuration, true
}

// AsM7Configuration returns the selected M7Configuration value of ImmediateMDTExtIEsValue and reports whether that alternative is active.
func (v *ImmediateMDTExtIEsValue) AsM7Configuration() (*s19.M7Configuration, bool) {
	if v == nil || v.id != s00.ProtocolIEID(221) || v.rowM7Configuration == nil {
		return nil, false
	}
	return v.rowM7Configuration, true
}

// AsBluetoothMeasurementConfiguration returns the selected BluetoothMeasurementConfiguration value of ImmediateMDTExtIEsValue and reports whether that alternative is active.
func (v *ImmediateMDTExtIEsValue) AsBluetoothMeasurementConfiguration() (*s14.BluetoothMeasurementConfiguration, bool) {
	if v == nil || v.id != s00.ProtocolIEID(284) || v.rowBluetoothMeasurementConfiguration == nil {
		return nil, false
	}
	return v.rowBluetoothMeasurementConfiguration, true
}

// AsWLANMeasurementConfiguration returns the selected WLANMeasurementConfiguration value of ImmediateMDTExtIEsValue and reports whether that alternative is active.
func (v *ImmediateMDTExtIEsValue) AsWLANMeasurementConfiguration() (*WLANMeasurementConfiguration, bool) {
	if v == nil || v.id != s00.ProtocolIEID(285) || v.rowWLANMeasurementConfiguration == nil {
		return nil, false
	}
	return v.rowWLANMeasurementConfiguration, true
}

// AsSensorMeasurementConfiguration returns the selected SensorMeasurementConfiguration value of ImmediateMDTExtIEsValue and reports whether that alternative is active.
func (v *ImmediateMDTExtIEsValue) AsSensorMeasurementConfiguration() (*s30.SensorMeasurementConfiguration, bool) {
	if v == nil || v.id != s00.ProtocolIEID(345) || v.rowSensorMeasurementConfiguration == nil {
		return nil, false
	}
	return v.rowSensorMeasurementConfiguration, true
}
func (v ImmediateMDTExtIEsValue) decode(id s00.ProtocolIEID, raw aper.OpaqueOpenType) (ImmediateMDTExtIEsValue, error) {
	out := ImmediateMDTExtIEsValue{id: id}
	switch id {
	case s00.ProtocolIEID(171):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		var value s19.M3Configuration
		child := scope
		if err := s19.BridgeM3ConfigurationMethodUnmarshalAPERFrom(&value, child); err != nil {
			return out, fmt.Errorf("%s %w", "M3Configuration:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "M3Configuration")
		if err != nil {
			return out, err
		}
		*s19.BridgeM3ConfigurationFieldPerPadding(&value) = padding
		*s19.BridgeM3ConfigurationFieldReceived(&value) = true
		raw.RetainContents(s19.BridgeM3ConfigurationFieldReceivedBytes(&value))
		*s19.BridgeM3ConfigurationFieldReceivedLocation(&value) = raw.ContentLocation()
		out.rowM3Configuration = &value
		raw.RetainContents(&out.received)
	case s00.ProtocolIEID(172):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		var value s19.M4Configuration
		child := scope
		if err := s19.BridgeM4ConfigurationMethodUnmarshalAPERFrom(&value, child); err != nil {
			return out, fmt.Errorf("%s %w", "M4Configuration:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "M4Configuration")
		if err != nil {
			return out, err
		}
		*s19.BridgeM4ConfigurationFieldPerPadding(&value) = padding
		*s19.BridgeM4ConfigurationFieldReceived(&value) = true
		raw.RetainContents(s19.BridgeM4ConfigurationFieldReceivedBytes(&value))
		*s19.BridgeM4ConfigurationFieldReceivedLocation(&value) = raw.ContentLocation()
		out.rowM4Configuration = &value
		raw.RetainContents(&out.received)
	case s00.ProtocolIEID(173):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		var value s19.M5Configuration
		child := scope
		if err := s19.BridgeM5ConfigurationMethodUnmarshalAPERFrom(&value, child); err != nil {
			return out, fmt.Errorf("%s %w", "M5Configuration:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "M5Configuration")
		if err != nil {
			return out, err
		}
		*s19.BridgeM5ConfigurationFieldPerPadding(&value) = padding
		*s19.BridgeM5ConfigurationFieldReceived(&value) = true
		raw.RetainContents(s19.BridgeM5ConfigurationFieldReceivedBytes(&value))
		*s19.BridgeM5ConfigurationFieldReceivedLocation(&value) = raw.ContentLocation()
		out.rowM5Configuration = &value
		raw.RetainContents(&out.received)
	case s00.ProtocolIEID(174):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		child := scope
		value, err := (func(bb *aper.BitBuffer) (s00.MDTLocationInfo, error) {
			var v struct{ Value s00.MDTLocationInfo }
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
		out.rowMDTLocationInfo = &value
		raw.RetainContents(&out.received)
	case s00.ProtocolIEID(220):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		var value s19.M6Configuration
		child := scope
		if err := s19.BridgeM6ConfigurationMethodUnmarshalAPERFrom(&value, child); err != nil {
			return out, fmt.Errorf("%s %w", "M6Configuration:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "M6Configuration")
		if err != nil {
			return out, err
		}
		*s19.BridgeM6ConfigurationFieldPerPadding(&value) = padding
		*s19.BridgeM6ConfigurationFieldReceived(&value) = true
		raw.RetainContents(s19.BridgeM6ConfigurationFieldReceivedBytes(&value))
		*s19.BridgeM6ConfigurationFieldReceivedLocation(&value) = raw.ContentLocation()
		out.rowM6Configuration = &value
		raw.RetainContents(&out.received)
	case s00.ProtocolIEID(221):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		var value s19.M7Configuration
		child := scope
		if err := s19.BridgeM7ConfigurationMethodUnmarshalAPERFrom(&value, child); err != nil {
			return out, fmt.Errorf("%s %w", "M7Configuration:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "M7Configuration")
		if err != nil {
			return out, err
		}
		*s19.BridgeM7ConfigurationFieldPerPadding(&value) = padding
		*s19.BridgeM7ConfigurationFieldReceived(&value) = true
		raw.RetainContents(s19.BridgeM7ConfigurationFieldReceivedBytes(&value))
		*s19.BridgeM7ConfigurationFieldReceivedLocation(&value) = raw.ContentLocation()
		out.rowM7Configuration = &value
		raw.RetainContents(&out.received)
	case s00.ProtocolIEID(284):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		var value s14.BluetoothMeasurementConfiguration
		child := scope
		if err := s14.BridgeBluetoothMeasurementConfigurationMethodUnmarshalAPERFrom(&value, child); err != nil {
			return out, fmt.Errorf("%s %w", "BluetoothMeasurementConfiguration:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "BluetoothMeasurementConfiguration")
		if err != nil {
			return out, err
		}
		*s14.BridgeBluetoothMeasurementConfigurationFieldPerPadding(&value) = padding
		*s14.BridgeBluetoothMeasurementConfigurationFieldReceived(&value) = true
		raw.RetainContents(s14.BridgeBluetoothMeasurementConfigurationFieldReceivedBytes(&value))
		*s14.BridgeBluetoothMeasurementConfigurationFieldReceivedLocation(&value) = raw.ContentLocation()
		out.rowBluetoothMeasurementConfiguration = &value
		raw.RetainContents(&out.received)
	case s00.ProtocolIEID(285):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		var value WLANMeasurementConfiguration
		child := scope
		if err := value.unmarshalAPERFrom(child); err != nil {
			return out, fmt.Errorf("%s %w", "WLANMeasurementConfiguration:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "WLANMeasurementConfiguration")
		if err != nil {
			return out, err
		}
		value.perPadding = padding
		value.received = true
		raw.RetainContents(&value.receivedBytes)
		value.receivedLocation = raw.ContentLocation()
		out.rowWLANMeasurementConfiguration = &value
		raw.RetainContents(&out.received)
	case s00.ProtocolIEID(345):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		var value s30.SensorMeasurementConfiguration
		child := scope
		if err := s30.BridgeSensorMeasurementConfigurationMethodUnmarshalAPERFrom(&value, child); err != nil {
			return out, fmt.Errorf("%s %w", "SensorMeasurementConfiguration:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "SensorMeasurementConfiguration")
		if err != nil {
			return out, err
		}
		*s30.BridgeSensorMeasurementConfigurationFieldPerPadding(&value) = padding
		*s30.BridgeSensorMeasurementConfigurationFieldReceived(&value) = true
		raw.RetainContents(s30.BridgeSensorMeasurementConfigurationFieldReceivedBytes(&value))
		*s30.BridgeSensorMeasurementConfigurationFieldReceivedLocation(&value) = raw.ContentLocation()
		out.rowSensorMeasurementConfiguration = &value
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
func (v ImmediateMDTExtIEsValue) encode() ([]byte, error) { return v.encodeFresh(false, nil) }
func (v ImmediateMDTExtIEsValue) encodeFresh(fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
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
	case s00.ProtocolIEID(171):
		if v.rowM3Configuration == nil {
			return nil, fmt.Errorf("%s missing value", "ImmediateMDT-ExtIEs.id-M3Configuration:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		candidate, err := s19.BridgeM3ConfigurationMethodMarshalAPERBudget(v.rowM3Configuration, budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	case s00.ProtocolIEID(172):
		if v.rowM4Configuration == nil {
			return nil, fmt.Errorf("%s missing value", "ImmediateMDT-ExtIEs.id-M4Configuration:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		candidate, err := s19.BridgeM4ConfigurationMethodMarshalAPERBudget(v.rowM4Configuration, budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	case s00.ProtocolIEID(173):
		if v.rowM5Configuration == nil {
			return nil, fmt.Errorf("%s missing value", "ImmediateMDT-ExtIEs.id-M5Configuration:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		candidate, err := s19.BridgeM5ConfigurationMethodMarshalAPERBudget(v.rowM5Configuration, budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	case s00.ProtocolIEID(174):
		if v.rowMDTLocationInfo == nil {
			return nil, fmt.Errorf("%s missing value", "ImmediateMDT-ExtIEs.id-MDT-Location-Info:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		candidate, err := (func(value s00.MDTLocationInfo, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			v := struct{ Value s00.MDTLocationInfo }{Value: value}
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
		})(*v.rowMDTLocationInfo, budget)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	case s00.ProtocolIEID(220):
		if v.rowM6Configuration == nil {
			return nil, fmt.Errorf("%s missing value", "ImmediateMDT-ExtIEs.id-M6Configuration:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		candidate, err := s19.BridgeM6ConfigurationMethodMarshalAPERBudget(v.rowM6Configuration, budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	case s00.ProtocolIEID(221):
		if v.rowM7Configuration == nil {
			return nil, fmt.Errorf("%s missing value", "ImmediateMDT-ExtIEs.id-M7Configuration:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		candidate, err := s19.BridgeM7ConfigurationMethodMarshalAPERBudget(v.rowM7Configuration, budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	case s00.ProtocolIEID(284):
		if v.rowBluetoothMeasurementConfiguration == nil {
			return nil, fmt.Errorf("%s missing value", "ImmediateMDT-ExtIEs.id-BluetoothMeasurementConfiguration:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		candidate, err := s14.BridgeBluetoothMeasurementConfigurationMethodMarshalAPERBudget(v.rowBluetoothMeasurementConfiguration, budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	case s00.ProtocolIEID(285):
		if v.rowWLANMeasurementConfiguration == nil {
			return nil, fmt.Errorf("%s missing value", "ImmediateMDT-ExtIEs.id-WLANMeasurementConfiguration:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		candidate, err := v.rowWLANMeasurementConfiguration.marshalAPERBudget(budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	case s00.ProtocolIEID(345):
		if v.rowSensorMeasurementConfiguration == nil {
			return nil, fmt.Errorf("%s missing value", "ImmediateMDT-ExtIEs.id-SensorMeasurementConfiguration:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		candidate, err := s30.BridgeSensorMeasurementConfigurationMethodMarshalAPERBudget(v.rowSensorMeasurementConfiguration, budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	default:
		return nil, fmt.Errorf("%s id %d has no value", "ImmediateMDTExtIEsValue:", v.id)
	}
}

type LoggedMDTExtIEsValue struct {
	id                                   s00.ProtocolIEID
	received                             aper.WireSpan
	replay                               aper.Snapshot
	opaque                               aper.OpaqueOpenType
	isOpaque                             bool
	rowBluetoothMeasurementConfiguration *s14.BluetoothMeasurementConfiguration
	rowWLANMeasurementConfiguration      *WLANMeasurementConfiguration
	rowLoggedMDTTrigger                  *s19.LoggedMDTTrigger
	rowSensorMeasurementConfiguration    *s30.SensorMeasurementConfiguration
}

func (v LoggedMDTExtIEsValue) matchesID(id s00.ProtocolIEID, _ ...*aper.DecodeBudget) bool {
	if v.id != id {
		return false
	}
	if v.isOpaque {
		return true
	}
	switch id {
	case s00.ProtocolIEID(284):
		return v.rowBluetoothMeasurementConfiguration != nil
	case s00.ProtocolIEID(285):
		return v.rowWLANMeasurementConfiguration != nil
	case s00.ProtocolIEID(344):
		return v.rowLoggedMDTTrigger != nil
	case s00.ProtocolIEID(345):
		return v.rowSensorMeasurementConfiguration != nil
	}
	return false
}

// Opaque returns the retained opaque open value of LoggedMDTExtIEsValue and reports whether the opaque alternative is selected.
func (v *LoggedMDTExtIEsValue) Opaque() (aper.OpaqueOpenType, bool) {
	if v == nil || !v.isOpaque {
		return aper.OpaqueOpenType{}, false
	}
	return v.opaque, true
}
func (LoggedMDTExtIEsValue) rule() aper.SourceRule {
	return aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.4", Assignment: aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "LoggedMDT-ExtIEs"}}
}
func (LoggedMDTExtIEsValue) reason(id s00.ProtocolIEID) aper.OpaqueReason {
	switch id {
	case s00.ProtocolIEID(284):
		return aper.UnknownSelector
	case s00.ProtocolIEID(285):
		return aper.UnknownSelector
	case s00.ProtocolIEID(344):
		return aper.UnknownSelector
	case s00.ProtocolIEID(345):
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

// AsBluetoothMeasurementConfiguration returns the selected BluetoothMeasurementConfiguration value of LoggedMDTExtIEsValue and reports whether that alternative is active.
func (v *LoggedMDTExtIEsValue) AsBluetoothMeasurementConfiguration() (*s14.BluetoothMeasurementConfiguration, bool) {
	if v == nil || v.id != s00.ProtocolIEID(284) || v.rowBluetoothMeasurementConfiguration == nil {
		return nil, false
	}
	return v.rowBluetoothMeasurementConfiguration, true
}

// AsWLANMeasurementConfiguration returns the selected WLANMeasurementConfiguration value of LoggedMDTExtIEsValue and reports whether that alternative is active.
func (v *LoggedMDTExtIEsValue) AsWLANMeasurementConfiguration() (*WLANMeasurementConfiguration, bool) {
	if v == nil || v.id != s00.ProtocolIEID(285) || v.rowWLANMeasurementConfiguration == nil {
		return nil, false
	}
	return v.rowWLANMeasurementConfiguration, true
}

// AsLoggedMDTTrigger returns the selected LoggedMDTTrigger value of LoggedMDTExtIEsValue and reports whether that alternative is active.
func (v *LoggedMDTExtIEsValue) AsLoggedMDTTrigger() (*s19.LoggedMDTTrigger, bool) {
	if v == nil || v.id != s00.ProtocolIEID(344) || v.rowLoggedMDTTrigger == nil {
		return nil, false
	}
	return v.rowLoggedMDTTrigger, true
}

// AsSensorMeasurementConfiguration returns the selected SensorMeasurementConfiguration value of LoggedMDTExtIEsValue and reports whether that alternative is active.
func (v *LoggedMDTExtIEsValue) AsSensorMeasurementConfiguration() (*s30.SensorMeasurementConfiguration, bool) {
	if v == nil || v.id != s00.ProtocolIEID(345) || v.rowSensorMeasurementConfiguration == nil {
		return nil, false
	}
	return v.rowSensorMeasurementConfiguration, true
}
func (v LoggedMDTExtIEsValue) decode(id s00.ProtocolIEID, raw aper.OpaqueOpenType) (LoggedMDTExtIEsValue, error) {
	out := LoggedMDTExtIEsValue{id: id}
	switch id {
	case s00.ProtocolIEID(284):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		var value s14.BluetoothMeasurementConfiguration
		child := scope
		if err := s14.BridgeBluetoothMeasurementConfigurationMethodUnmarshalAPERFrom(&value, child); err != nil {
			return out, fmt.Errorf("%s %w", "BluetoothMeasurementConfiguration:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "BluetoothMeasurementConfiguration")
		if err != nil {
			return out, err
		}
		*s14.BridgeBluetoothMeasurementConfigurationFieldPerPadding(&value) = padding
		*s14.BridgeBluetoothMeasurementConfigurationFieldReceived(&value) = true
		raw.RetainContents(s14.BridgeBluetoothMeasurementConfigurationFieldReceivedBytes(&value))
		*s14.BridgeBluetoothMeasurementConfigurationFieldReceivedLocation(&value) = raw.ContentLocation()
		out.rowBluetoothMeasurementConfiguration = &value
		raw.RetainContents(&out.received)
	case s00.ProtocolIEID(285):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		var value WLANMeasurementConfiguration
		child := scope
		if err := value.unmarshalAPERFrom(child); err != nil {
			return out, fmt.Errorf("%s %w", "WLANMeasurementConfiguration:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "WLANMeasurementConfiguration")
		if err != nil {
			return out, err
		}
		value.perPadding = padding
		value.received = true
		raw.RetainContents(&value.receivedBytes)
		value.receivedLocation = raw.ContentLocation()
		out.rowWLANMeasurementConfiguration = &value
		raw.RetainContents(&out.received)
	case s00.ProtocolIEID(344):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		var value s19.LoggedMDTTrigger
		child := scope
		if err := s19.BridgeLoggedMDTTriggerMethodUnmarshalAPERFrom(&value, child); err != nil {
			return out, fmt.Errorf("%s %w", "LoggedMDTTrigger:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "LoggedMDTTrigger")
		if err != nil {
			return out, err
		}
		*s19.BridgeLoggedMDTTriggerFieldPerPadding(&value) = padding.Padding()
		*s19.BridgeLoggedMDTTriggerFieldReceived(&value) = true
		raw.RetainContents(s19.BridgeLoggedMDTTriggerFieldReceivedBytes(&value))
		*s19.BridgeLoggedMDTTriggerFieldReceivedLocation(&value) = raw.ContentLocation()
		out.rowLoggedMDTTrigger = &value
		raw.RetainContents(&out.received)
	case s00.ProtocolIEID(345):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		var value s30.SensorMeasurementConfiguration
		child := scope
		if err := s30.BridgeSensorMeasurementConfigurationMethodUnmarshalAPERFrom(&value, child); err != nil {
			return out, fmt.Errorf("%s %w", "SensorMeasurementConfiguration:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "SensorMeasurementConfiguration")
		if err != nil {
			return out, err
		}
		*s30.BridgeSensorMeasurementConfigurationFieldPerPadding(&value) = padding
		*s30.BridgeSensorMeasurementConfigurationFieldReceived(&value) = true
		raw.RetainContents(s30.BridgeSensorMeasurementConfigurationFieldReceivedBytes(&value))
		*s30.BridgeSensorMeasurementConfigurationFieldReceivedLocation(&value) = raw.ContentLocation()
		out.rowSensorMeasurementConfiguration = &value
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
func (v LoggedMDTExtIEsValue) encode() ([]byte, error) { return v.encodeFresh(false, nil) }
func (v LoggedMDTExtIEsValue) encodeFresh(fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
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
	case s00.ProtocolIEID(284):
		if v.rowBluetoothMeasurementConfiguration == nil {
			return nil, fmt.Errorf("%s missing value", "LoggedMDT-ExtIEs.id-BluetoothMeasurementConfiguration:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		candidate, err := s14.BridgeBluetoothMeasurementConfigurationMethodMarshalAPERBudget(v.rowBluetoothMeasurementConfiguration, budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	case s00.ProtocolIEID(285):
		if v.rowWLANMeasurementConfiguration == nil {
			return nil, fmt.Errorf("%s missing value", "LoggedMDT-ExtIEs.id-WLANMeasurementConfiguration:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		candidate, err := v.rowWLANMeasurementConfiguration.marshalAPERBudget(budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	case s00.ProtocolIEID(344):
		if v.rowLoggedMDTTrigger == nil {
			return nil, fmt.Errorf("%s missing value", "LoggedMDT-ExtIEs.id-LoggedMDTTrigger:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		candidate, err := s19.BridgeLoggedMDTTriggerMethodMarshalAPERBudget(v.rowLoggedMDTTrigger, budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	case s00.ProtocolIEID(345):
		if v.rowSensorMeasurementConfiguration == nil {
			return nil, fmt.Errorf("%s missing value", "LoggedMDT-ExtIEs.id-SensorMeasurementConfiguration:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		candidate, err := s30.BridgeSensorMeasurementConfigurationMethodMarshalAPERBudget(v.rowSensorMeasurementConfiguration, budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	default:
		return nil, fmt.Errorf("%s id %d has no value", "LoggedMDTExtIEsValue:", v.id)
	}
}

type TraceActivationExtIEsValue struct {
	id                          s00.ProtocolIEID
	received                    aper.WireSpan
	replay                      aper.Snapshot
	opaque                      aper.OpaqueOpenType
	isOpaque                    bool
	rowMDTConfiguration         *MDTConfiguration
	rowUEAppLayerMeasConfig     *s35.UEAppLayerMeasConfig
	rowMDTConfigurationNR       *s00.MDTConfigurationNR
	rowTraceCollectionEntityURI *s00.URIAddress
}

func (v TraceActivationExtIEsValue) matchesID(id s00.ProtocolIEID, _ ...*aper.DecodeBudget) bool {
	if v.id != id {
		return false
	}
	if v.isOpaque {
		return true
	}
	switch id {
	case s00.ProtocolIEID(162):
		return v.rowMDTConfiguration != nil
	case s00.ProtocolIEID(262):
		return v.rowUEAppLayerMeasConfig != nil
	case s00.ProtocolIEID(316):
		return v.rowMDTConfigurationNR != nil
	case s00.ProtocolIEID(325):
		return v.rowTraceCollectionEntityURI != nil
	}
	return false
}

// Opaque returns the retained opaque open value of TraceActivationExtIEsValue and reports whether the opaque alternative is selected.
func (v *TraceActivationExtIEsValue) Opaque() (aper.OpaqueOpenType, bool) {
	if v == nil || !v.isOpaque {
		return aper.OpaqueOpenType{}, false
	}
	return v.opaque, true
}
func (TraceActivationExtIEsValue) rule() aper.SourceRule {
	return aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.4", Assignment: aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "TraceActivation-ExtIEs"}}
}
func (TraceActivationExtIEsValue) reason(id s00.ProtocolIEID) aper.OpaqueReason {
	switch id {
	case s00.ProtocolIEID(162):
		return aper.UnknownSelector
	case s00.ProtocolIEID(262):
		return aper.UnknownSelector
	case s00.ProtocolIEID(316):
		return aper.UnknownSelector
	case s00.ProtocolIEID(325):
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

// AsMDTConfiguration returns the selected MDTConfiguration value of TraceActivationExtIEsValue and reports whether that alternative is active.
func (v *TraceActivationExtIEsValue) AsMDTConfiguration() (*MDTConfiguration, bool) {
	if v == nil || v.id != s00.ProtocolIEID(162) || v.rowMDTConfiguration == nil {
		return nil, false
	}
	return v.rowMDTConfiguration, true
}

// AsUEAppLayerMeasConfig returns the selected UEAppLayerMeasConfig value of TraceActivationExtIEsValue and reports whether that alternative is active.
func (v *TraceActivationExtIEsValue) AsUEAppLayerMeasConfig() (*s35.UEAppLayerMeasConfig, bool) {
	if v == nil || v.id != s00.ProtocolIEID(262) || v.rowUEAppLayerMeasConfig == nil {
		return nil, false
	}
	return v.rowUEAppLayerMeasConfig, true
}

// AsMDTConfigurationNR returns the selected MDTConfigurationNR value of TraceActivationExtIEsValue and reports whether that alternative is active.
func (v *TraceActivationExtIEsValue) AsMDTConfigurationNR() (*s00.MDTConfigurationNR, bool) {
	if v == nil || v.id != s00.ProtocolIEID(316) || v.rowMDTConfigurationNR == nil {
		return nil, false
	}
	return v.rowMDTConfigurationNR, true
}

// AsTraceCollectionEntityURI returns the selected TraceCollectionEntityURI value of TraceActivationExtIEsValue and reports whether that alternative is active.
func (v *TraceActivationExtIEsValue) AsTraceCollectionEntityURI() (*s00.URIAddress, bool) {
	if v == nil || v.id != s00.ProtocolIEID(325) || v.rowTraceCollectionEntityURI == nil {
		return nil, false
	}
	return v.rowTraceCollectionEntityURI, true
}
func (v TraceActivationExtIEsValue) decode(id s00.ProtocolIEID, raw aper.OpaqueOpenType) (TraceActivationExtIEsValue, error) {
	out := TraceActivationExtIEsValue{id: id}
	switch id {
	case s00.ProtocolIEID(162):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		var value MDTConfiguration
		child := scope
		if err := value.unmarshalAPERFrom(child); err != nil {
			return out, fmt.Errorf("%s %w", "MDTConfiguration:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "MDTConfiguration")
		if err != nil {
			return out, err
		}
		value.perPadding = padding
		value.received = true
		raw.RetainContents(&value.receivedBytes)
		value.receivedLocation = raw.ContentLocation()
		out.rowMDTConfiguration = &value
		raw.RetainContents(&out.received)
	case s00.ProtocolIEID(262):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		var value s35.UEAppLayerMeasConfig
		child := scope
		if err := s35.BridgeUEAppLayerMeasConfigMethodUnmarshalAPERFrom(&value, child); err != nil {
			return out, fmt.Errorf("%s %w", "UEAppLayerMeasConfig:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "UEAppLayerMeasConfig")
		if err != nil {
			return out, err
		}
		*s35.BridgeUEAppLayerMeasConfigFieldPerPadding(&value) = padding
		*s35.BridgeUEAppLayerMeasConfigFieldReceived(&value) = true
		raw.RetainContents(s35.BridgeUEAppLayerMeasConfigFieldReceivedBytes(&value))
		*s35.BridgeUEAppLayerMeasConfigFieldReceivedLocation(&value) = raw.ContentLocation()
		out.rowUEAppLayerMeasConfig = &value
		raw.RetainContents(&out.received)
	case s00.ProtocolIEID(316):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		child := scope
		value, err := (func(bb *aper.BitBuffer) (s00.MDTConfigurationNR, error) {
			var v struct{ Value s00.MDTConfigurationNR }
			err := func() error {
				val_value, err := aper.DecodeOctetStringAligned(bb, 0, 0, false)
				if err != nil {
					return runtime.WrapDecodePath(err, "Value")
				}
				v.Value = s00.MDTConfigurationNR(val_value)
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
		out.rowMDTConfigurationNR = &value
		raw.RetainContents(&out.received)
	case s00.ProtocolIEID(325):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		child := scope
		value, err := (func(bb *aper.BitBuffer) (s00.URIAddress, error) {
			var v struct{ Value s00.URIAddress }
			err := func() error {
				val_value, err := aper.DecodeAlphabetStringAligned(bb, aper.PermittedAlphabet{' ', '~'}, 0, 0, false, false)
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
		out.rowTraceCollectionEntityURI = &value
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
func (v TraceActivationExtIEsValue) encode() ([]byte, error) { return v.encodeFresh(false, nil) }
func (v TraceActivationExtIEsValue) encodeFresh(fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
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
	case s00.ProtocolIEID(162):
		if v.rowMDTConfiguration == nil {
			return nil, fmt.Errorf("%s missing value", "TraceActivation-ExtIEs.id-MDTConfiguration:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		candidate, err := v.rowMDTConfiguration.marshalAPERBudget(budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	case s00.ProtocolIEID(262):
		if v.rowUEAppLayerMeasConfig == nil {
			return nil, fmt.Errorf("%s missing value", "TraceActivation-ExtIEs.id-UEAppLayerMeasConfig:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		candidate, err := s35.BridgeUEAppLayerMeasConfigMethodMarshalAPERBudget(v.rowUEAppLayerMeasConfig, budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	case s00.ProtocolIEID(316):
		if v.rowMDTConfigurationNR == nil {
			return nil, fmt.Errorf("%s missing value", "TraceActivation-ExtIEs.id-MDTConfigurationNR:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		candidate, err := (func(value s00.MDTConfigurationNR, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			v := struct{ Value s00.MDTConfigurationNR }{Value: value}
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
		})(*v.rowMDTConfigurationNR, budget)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	case s00.ProtocolIEID(325):
		if v.rowTraceCollectionEntityURI == nil {
			return nil, fmt.Errorf("%s missing value", "TraceActivation-ExtIEs.id-TraceCollectionEntityURI:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		candidate, err := (func(value s00.URIAddress, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			v := struct{ Value s00.URIAddress }{Value: value}
			_ = v
			err := func() error {
				if err := aper.EncodeAlphabetStringAligned(bb, string(v.Value), aper.PermittedAlphabet{' ', '~'}, 0, 0, false, false); err != nil {
					return fmt.Errorf("encoding value: %w", err)
				}
				return nil
			}()
			if err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		})(*v.rowTraceCollectionEntityURI, budget)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	default:
		return nil, fmt.Errorf("%s id %d has no value", "TraceActivationExtIEsValue:", v.id)
	}
}

type ImmediateMDTExtIETable struct{}

func ImmediateMDTExtIEs() ImmediateMDTExtIETable { return ImmediateMDTExtIETable{} }

// ID returns the ASN.1 object-set identity of ImmediateMDTExtIETable.
func (ImmediateMDTExtIETable) ID() s00.TableID {
	return func() s00.TableID {
		sealed := s00.TableID{}
		*s00.BridgeTableIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "ImmediateMDT-ExtIEs"}
		return sealed
	}()
}

// Table returns the ASN.1 object-set table described by ImmediateMDTExtIETable.
func (ImmediateMDTExtIETable) Table() s00.ImmediateMDTExtIEsValueExtensionTable {
	return func() s00.ImmediateMDTExtIEsValueExtensionTable {
		sealed := s00.ImmediateMDTExtIEsValueExtensionTable{}
		*s00.BridgeImmediateMDTExtIEsValueExtensionTableFieldBound(&sealed) = true
		return sealed
	}()
}
func (ImmediateMDTExtIETable) infoM3Configuration() s00.ExtensionInfo {
	return s00.ExtensionInfo{Table: ImmediateMDTExtIEs().ID(), ID: s00.ProtocolExtensionID(171), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceConditional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "M3Configuration"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.4", Assignment: aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "ImmediateMDT-ExtIEs", Row: "id-M3Configuration"}}}
}

// M3Configuration returns the typed binding for the M3Configuration row of ImmediateMDTExtIETable.
func (t ImmediateMDTExtIETable) M3Configuration() ImmediateMDTExtIEsM3ConfigurationExtBinding {
	return ImmediateMDTExtIEsM3ConfigurationExtBinding{info: t.infoM3Configuration(), codec: func() s19.M3ConfigurationValueCodec {
		sealed := s19.M3ConfigurationValueCodec{}
		*s19.BridgeM3ConfigurationValueCodecFieldPath(&sealed) = "M3Configuration"
		*s19.BridgeM3ConfigurationValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s19.M3Configuration, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s19.M3Configuration
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("M3Configuration")
			var zero ImmediateMDTExtIEsValue
			decoded, err := zero.decode(s00.ProtocolIEID(171), raw)
			if err != nil {
				var empty s19.M3Configuration
				return empty, runtime.WrapDecodePath(err, "M3Configuration")
			}
			value, ok := decoded.AsM3Configuration()
			if !ok {
				var empty s19.M3Configuration
				return empty, fmt.Errorf("binding ImmediateMDT-ExtIEs.id-M3Configuration: no selected value")
			}
			return *value, nil
		}
		*s19.BridgeM3ConfigurationValueCodecFieldEncode(&sealed) = func(value s19.M3Configuration, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (ImmediateMDTExtIEsValue{id: s00.ProtocolIEID(171), rowM3Configuration: &value}).encodeFresh(fresh, budget)
		}
		*s19.BridgeM3ConfigurationValueCodecFieldCapture(&sealed) = func(v s19.M3Configuration, options aper.DecodeState) (s19.M3Configuration, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s19.BridgeCaptureS1APM3Configuration(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s19.BridgeM3ConfigurationValueCodecFieldCompare(&sealed) = func(v s19.M3Configuration, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s19.BridgeCompareS1APM3Configuration(&v, &s)
			s.End(f, root, false)
			return s.
				Plan(), s.BudgetValue()
		}
		*s19.BridgeM3ConfigurationValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:M3Configuration"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s19.M3Configuration) ImmediateMDTExtIEsValue {
			return ImmediateMDTExtIEsValue{id: s00.ProtocolIEID(171), rowM3Configuration: &value}
		}, get: func(value *ImmediateMDTExtIEsValue) (*s19.M3Configuration, bool) { return value.AsM3Configuration() }}
}
func (ImmediateMDTExtIETable) infoM4Configuration() s00.ExtensionInfo {
	return s00.ExtensionInfo{Table: ImmediateMDTExtIEs().ID(), ID: s00.ProtocolExtensionID(172), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceConditional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "M4Configuration"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.4", Assignment: aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "ImmediateMDT-ExtIEs", Row: "id-M4Configuration"}}}
}

// M4Configuration returns the typed binding for the M4Configuration row of ImmediateMDTExtIETable.
func (t ImmediateMDTExtIETable) M4Configuration() ImmediateMDTExtIEsM4ConfigurationExtBinding {
	return ImmediateMDTExtIEsM4ConfigurationExtBinding{info: t.infoM4Configuration(), codec: func() s19.M4ConfigurationValueCodec {
		sealed := s19.M4ConfigurationValueCodec{}
		*s19.BridgeM4ConfigurationValueCodecFieldPath(&sealed) = "M4Configuration"
		*s19.BridgeM4ConfigurationValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s19.M4Configuration, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s19.M4Configuration
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("M4Configuration")
			var zero ImmediateMDTExtIEsValue
			decoded, err := zero.decode(s00.ProtocolIEID(172), raw)
			if err != nil {
				var empty s19.M4Configuration
				return empty, runtime.WrapDecodePath(err, "M4Configuration")
			}
			value, ok := decoded.AsM4Configuration()
			if !ok {
				var empty s19.M4Configuration
				return empty, fmt.Errorf("binding ImmediateMDT-ExtIEs.id-M4Configuration: no selected value")
			}
			return *value, nil
		}
		*s19.BridgeM4ConfigurationValueCodecFieldEncode(&sealed) = func(value s19.M4Configuration, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (ImmediateMDTExtIEsValue{id: s00.ProtocolIEID(172), rowM4Configuration: &value}).encodeFresh(fresh, budget)
		}
		*s19.BridgeM4ConfigurationValueCodecFieldCapture(&sealed) = func(v s19.M4Configuration, options aper.DecodeState) (s19.M4Configuration, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s19.BridgeCaptureS1APM4Configuration(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s19.BridgeM4ConfigurationValueCodecFieldCompare(&sealed) = func(v s19.M4Configuration, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s19.BridgeCompareS1APM4Configuration(&v, &s)
			s.End(f, root, false)
			return s.
				Plan(), s.BudgetValue()
		}
		*s19.BridgeM4ConfigurationValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:M4Configuration"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s19.M4Configuration) ImmediateMDTExtIEsValue {
			return ImmediateMDTExtIEsValue{id: s00.ProtocolIEID(172), rowM4Configuration: &value}
		}, get: func(value *ImmediateMDTExtIEsValue) (*s19.M4Configuration, bool) { return value.AsM4Configuration() }}
}
func (ImmediateMDTExtIETable) infoM5Configuration() s00.ExtensionInfo {
	return s00.ExtensionInfo{Table: ImmediateMDTExtIEs().ID(), ID: s00.ProtocolExtensionID(173), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceConditional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "M5Configuration"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.4", Assignment: aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "ImmediateMDT-ExtIEs", Row: "id-M5Configuration"}}}
}

// M5Configuration returns the typed binding for the M5Configuration row of ImmediateMDTExtIETable.
func (t ImmediateMDTExtIETable) M5Configuration() ImmediateMDTExtIEsM5ConfigurationExtBinding {
	return ImmediateMDTExtIEsM5ConfigurationExtBinding{info: t.infoM5Configuration(), codec: func() s19.M5ConfigurationValueCodec {
		sealed := s19.M5ConfigurationValueCodec{}
		*s19.BridgeM5ConfigurationValueCodecFieldPath(&sealed) = "M5Configuration"
		*s19.BridgeM5ConfigurationValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s19.M5Configuration, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s19.M5Configuration
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("M5Configuration")
			var zero ImmediateMDTExtIEsValue
			decoded, err := zero.decode(s00.ProtocolIEID(173), raw)
			if err != nil {
				var empty s19.M5Configuration
				return empty, runtime.WrapDecodePath(err, "M5Configuration")
			}
			value, ok := decoded.AsM5Configuration()
			if !ok {
				var empty s19.M5Configuration
				return empty, fmt.Errorf("binding ImmediateMDT-ExtIEs.id-M5Configuration: no selected value")
			}
			return *value, nil
		}
		*s19.BridgeM5ConfigurationValueCodecFieldEncode(&sealed) = func(value s19.M5Configuration, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (ImmediateMDTExtIEsValue{id: s00.ProtocolIEID(173), rowM5Configuration: &value}).encodeFresh(fresh, budget)
		}
		*s19.BridgeM5ConfigurationValueCodecFieldCapture(&sealed) = func(v s19.M5Configuration, options aper.DecodeState) (s19.M5Configuration, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s19.BridgeCaptureS1APM5Configuration(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s19.BridgeM5ConfigurationValueCodecFieldCompare(&sealed) = func(v s19.M5Configuration, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s19.BridgeCompareS1APM5Configuration(&v, &s)
			s.End(f, root, false)
			return s.
				Plan(), s.BudgetValue()
		}
		*s19.BridgeM5ConfigurationValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:M5Configuration"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s19.M5Configuration) ImmediateMDTExtIEsValue {
			return ImmediateMDTExtIEsValue{id: s00.ProtocolIEID(173), rowM5Configuration: &value}
		}, get: func(value *ImmediateMDTExtIEsValue) (*s19.M5Configuration, bool) { return value.AsM5Configuration() }}
}
func (ImmediateMDTExtIETable) infoMDTLocationInfo() s00.ExtensionInfo {
	return s00.ExtensionInfo{Table: ImmediateMDTExtIEs().ID(), ID: s00.ProtocolExtensionID(174), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "MDT-Location-Info"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.4", Assignment: aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "ImmediateMDT-ExtIEs", Row: "id-MDT-Location-Info"}}}
}

// MDTLocationInfo returns the typed binding for the MDTLocationInfo row of ImmediateMDTExtIETable.
func (t ImmediateMDTExtIETable) MDTLocationInfo() ImmediateMDTExtIEsMDTLocationInfoExtBinding {
	return ImmediateMDTExtIEsMDTLocationInfoExtBinding{info: t.infoMDTLocationInfo(), codec: func() s01.MDTLocationInfoValueCodec {
		sealed := s01.MDTLocationInfoValueCodec{}
		*s01.BridgeMDTLocationInfoValueCodecFieldPath(&sealed) = "MDTLocationInfo"
		*s01.BridgeMDTLocationInfoValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.MDTLocationInfo, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s00.MDTLocationInfo
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("MDTLocationInfo")
			var zero ImmediateMDTExtIEsValue
			decoded, err := zero.decode(s00.ProtocolIEID(174), raw)
			if err != nil {
				var empty s00.MDTLocationInfo
				return empty, runtime.WrapDecodePath(err, "MDTLocationInfo")
			}
			value, ok := decoded.AsMDTLocationInfo()
			if !ok {
				var empty s00.MDTLocationInfo
				return empty, fmt.Errorf("binding ImmediateMDT-ExtIEs.id-MDT-Location-Info: no selected value")
			}
			return *value, nil
		}
		*s01.BridgeMDTLocationInfoValueCodecFieldEncode(&sealed) = func(value s00.MDTLocationInfo, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (ImmediateMDTExtIEsValue{id: s00.ProtocolIEID(174), rowMDTLocationInfo: &value}).encodeFresh(fresh, budget)
		}
		*s01.BridgeMDTLocationInfoValueCodecFieldCapture(&sealed) = func(v s00.MDTLocationInfo, options aper.DecodeState) (s00.MDTLocationInfo, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s00.BridgeCaptureS1APMDTLocationInfo(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s01.BridgeMDTLocationInfoValueCodecFieldCompare(&sealed) = func(v s00.MDTLocationInfo, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s02.BridgeCompareS1APMDTLocationInfo(&v, &s)
			s.End(f, root, false)
			return s.
				Plan(), s.BudgetValue()
		}
		*s01.BridgeMDTLocationInfoValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:MDTLocationInfo"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s00.MDTLocationInfo) ImmediateMDTExtIEsValue {
			return ImmediateMDTExtIEsValue{id: s00.ProtocolIEID(174), rowMDTLocationInfo: &value}
		}, get: func(value *ImmediateMDTExtIEsValue) (*s00.MDTLocationInfo, bool) { return value.AsMDTLocationInfo() }}
}
func (ImmediateMDTExtIETable) infoM6Configuration() s00.ExtensionInfo {
	return s00.ExtensionInfo{Table: ImmediateMDTExtIEs().ID(), ID: s00.ProtocolExtensionID(220), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceConditional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "M6Configuration"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.4", Assignment: aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "ImmediateMDT-ExtIEs", Row: "id-M6Configuration"}}}
}

// M6Configuration returns the typed binding for the M6Configuration row of ImmediateMDTExtIETable.
func (t ImmediateMDTExtIETable) M6Configuration() ImmediateMDTExtIEsM6ConfigurationExtBinding {
	return ImmediateMDTExtIEsM6ConfigurationExtBinding{info: t.infoM6Configuration(), codec: func() s19.M6ConfigurationValueCodec {
		sealed := s19.M6ConfigurationValueCodec{}
		*s19.BridgeM6ConfigurationValueCodecFieldPath(&sealed) = "M6Configuration"
		*s19.BridgeM6ConfigurationValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s19.M6Configuration, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s19.M6Configuration
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("M6Configuration")
			var zero ImmediateMDTExtIEsValue
			decoded, err := zero.decode(s00.ProtocolIEID(220), raw)
			if err != nil {
				var empty s19.M6Configuration
				return empty, runtime.WrapDecodePath(err, "M6Configuration")
			}
			value, ok := decoded.AsM6Configuration()
			if !ok {
				var empty s19.M6Configuration
				return empty, fmt.Errorf("binding ImmediateMDT-ExtIEs.id-M6Configuration: no selected value")
			}
			return *value, nil
		}
		*s19.BridgeM6ConfigurationValueCodecFieldEncode(&sealed) = func(value s19.M6Configuration, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (ImmediateMDTExtIEsValue{id: s00.ProtocolIEID(220), rowM6Configuration: &value}).encodeFresh(fresh, budget)
		}
		*s19.BridgeM6ConfigurationValueCodecFieldCapture(&sealed) = func(v s19.M6Configuration, options aper.DecodeState) (s19.M6Configuration, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s19.BridgeCaptureS1APM6Configuration(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s19.BridgeM6ConfigurationValueCodecFieldCompare(&sealed) = func(v s19.M6Configuration, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s19.BridgeCompareS1APM6Configuration(&v, &s)
			s.End(f, root, false)
			return s.
				Plan(), s.BudgetValue()
		}
		*s19.BridgeM6ConfigurationValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:M6Configuration"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s19.M6Configuration) ImmediateMDTExtIEsValue {
			return ImmediateMDTExtIEsValue{id: s00.ProtocolIEID(220), rowM6Configuration: &value}
		}, get: func(value *ImmediateMDTExtIEsValue) (*s19.M6Configuration, bool) { return value.AsM6Configuration() }}
}
func (ImmediateMDTExtIETable) infoM7Configuration() s00.ExtensionInfo {
	return s00.ExtensionInfo{Table: ImmediateMDTExtIEs().ID(), ID: s00.ProtocolExtensionID(221), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceConditional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "M7Configuration"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.4", Assignment: aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "ImmediateMDT-ExtIEs", Row: "id-M7Configuration"}}}
}

// M7Configuration returns the typed binding for the M7Configuration row of ImmediateMDTExtIETable.
func (t ImmediateMDTExtIETable) M7Configuration() ImmediateMDTExtIEsM7ConfigurationExtBinding {
	return ImmediateMDTExtIEsM7ConfigurationExtBinding{info: t.infoM7Configuration(), codec: func() s19.M7ConfigurationValueCodec {
		sealed := s19.M7ConfigurationValueCodec{}
		*s19.BridgeM7ConfigurationValueCodecFieldPath(&sealed) = "M7Configuration"
		*s19.BridgeM7ConfigurationValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s19.M7Configuration, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s19.M7Configuration
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("M7Configuration")
			var zero ImmediateMDTExtIEsValue
			decoded, err := zero.decode(s00.ProtocolIEID(221), raw)
			if err != nil {
				var empty s19.M7Configuration
				return empty, runtime.WrapDecodePath(err, "M7Configuration")
			}
			value, ok := decoded.AsM7Configuration()
			if !ok {
				var empty s19.M7Configuration
				return empty, fmt.Errorf("binding ImmediateMDT-ExtIEs.id-M7Configuration: no selected value")
			}
			return *value, nil
		}
		*s19.BridgeM7ConfigurationValueCodecFieldEncode(&sealed) = func(value s19.M7Configuration, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (ImmediateMDTExtIEsValue{id: s00.ProtocolIEID(221), rowM7Configuration: &value}).encodeFresh(fresh, budget)
		}
		*s19.BridgeM7ConfigurationValueCodecFieldCapture(&sealed) = func(v s19.M7Configuration, options aper.DecodeState) (s19.M7Configuration, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s19.BridgeCaptureS1APM7Configuration(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s19.BridgeM7ConfigurationValueCodecFieldCompare(&sealed) = func(v s19.M7Configuration, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s19.BridgeCompareS1APM7Configuration(&v, &s)
			s.End(f, root, false)
			return s.
				Plan(), s.BudgetValue()
		}
		*s19.BridgeM7ConfigurationValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:M7Configuration"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s19.M7Configuration) ImmediateMDTExtIEsValue {
			return ImmediateMDTExtIEsValue{id: s00.ProtocolIEID(221), rowM7Configuration: &value}
		}, get: func(value *ImmediateMDTExtIEsValue) (*s19.M7Configuration, bool) { return value.AsM7Configuration() }}
}
func (ImmediateMDTExtIETable) infoBluetoothMeasurementConfiguration() s00.ExtensionInfo {
	return s00.ExtensionInfo{Table: ImmediateMDTExtIEs().ID(), ID: s00.ProtocolExtensionID(284), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "BluetoothMeasurementConfiguration"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.4", Assignment: aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "ImmediateMDT-ExtIEs", Row: "id-BluetoothMeasurementConfiguration"}}}
}

// BluetoothMeasurementConfiguration returns the typed binding for the BluetoothMeasurementConfiguration row of ImmediateMDTExtIETable.
func (t ImmediateMDTExtIETable) BluetoothMeasurementConfiguration() ImmediateMDTExtIEsBluetoothMeasurementConfigurationExtBinding {
	return ImmediateMDTExtIEsBluetoothMeasurementConfigurationExtBinding{info: t.infoBluetoothMeasurementConfiguration(), codec: func() s14.BluetoothMeasurementConfigurationValueCodec {
		sealed := s14.BluetoothMeasurementConfigurationValueCodec{}
		*s14.BridgeBluetoothMeasurementConfigurationValueCodecFieldPath(&sealed) = "BluetoothMeasurementConfiguration"
		*s14.BridgeBluetoothMeasurementConfigurationValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s14.BluetoothMeasurementConfiguration, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s14.BluetoothMeasurementConfiguration
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("BluetoothMeasurementConfiguration")
			var zero ImmediateMDTExtIEsValue
			decoded, err := zero.decode(s00.ProtocolIEID(284), raw)
			if err != nil {
				var empty s14.BluetoothMeasurementConfiguration
				return empty, runtime.WrapDecodePath(err, "BluetoothMeasurementConfiguration")
			}
			value, ok := decoded.AsBluetoothMeasurementConfiguration()
			if !ok {
				var empty s14.BluetoothMeasurementConfiguration
				return empty, fmt.Errorf("binding ImmediateMDT-ExtIEs.id-BluetoothMeasurementConfiguration: no selected value")
			}
			return *value, nil
		}
		*s14.BridgeBluetoothMeasurementConfigurationValueCodecFieldEncode(&sealed) = func(value s14.BluetoothMeasurementConfiguration, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (ImmediateMDTExtIEsValue{id: s00.ProtocolIEID(284), rowBluetoothMeasurementConfiguration: &value}).encodeFresh(fresh, budget)
		}
		*s14.BridgeBluetoothMeasurementConfigurationValueCodecFieldCapture(&sealed) = func(v s14.BluetoothMeasurementConfiguration, options aper.DecodeState) (s14.BluetoothMeasurementConfiguration, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s14.BridgeCaptureS1APBluetoothMeasurementConfiguration(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s14.BridgeBluetoothMeasurementConfigurationValueCodecFieldCompare(&sealed) = func(v s14.BluetoothMeasurementConfiguration, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s14.BridgeCompareS1APBluetoothMeasurementConfiguration(
				&v,

				&s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s14.BridgeBluetoothMeasurementConfigurationValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:BluetoothMeasurementConfiguration"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s14.BluetoothMeasurementConfiguration) ImmediateMDTExtIEsValue {
			return ImmediateMDTExtIEsValue{id: s00.ProtocolIEID(284), rowBluetoothMeasurementConfiguration: &value}
		}, get: func(value *ImmediateMDTExtIEsValue) (*s14.BluetoothMeasurementConfiguration, bool) {
			return value.AsBluetoothMeasurementConfiguration()
		}}
}
func (ImmediateMDTExtIETable) infoWLANMeasurementConfiguration() s00.ExtensionInfo {
	return s00.ExtensionInfo{Table: ImmediateMDTExtIEs().ID(), ID: s00.ProtocolExtensionID(285), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "WLANMeasurementConfiguration"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.4", Assignment: aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "ImmediateMDT-ExtIEs", Row: "id-WLANMeasurementConfiguration"}}}
}

// WLANMeasurementConfiguration returns the typed binding for the WLANMeasurementConfiguration row of ImmediateMDTExtIETable.
func (t ImmediateMDTExtIETable) WLANMeasurementConfiguration() ImmediateMDTExtIEsWLANMeasurementConfigurationExtBinding {
	return ImmediateMDTExtIEsWLANMeasurementConfigurationExtBinding{info: t.infoWLANMeasurementConfiguration(), codec: WLANMeasurementConfigurationValueCodec{path: "WLANMeasurementConfiguration",
		decode: func(data []byte, options aper.DecodeState) (WLANMeasurementConfiguration, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty WLANMeasurementConfiguration
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("WLANMeasurementConfiguration")
			var zero ImmediateMDTExtIEsValue
			decoded, err := zero.decode(s00.ProtocolIEID(285), raw)
			if err != nil {
				var empty WLANMeasurementConfiguration
				return empty, runtime.WrapDecodePath(err, "WLANMeasurementConfiguration")
			}
			value, ok := decoded.AsWLANMeasurementConfiguration()
			if !ok {
				var empty WLANMeasurementConfiguration
				return empty, fmt.Errorf("binding ImmediateMDT-ExtIEs.id-WLANMeasurementConfiguration: no selected value")
			}
			return *value, nil
		},
		encode: func(value WLANMeasurementConfiguration, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (ImmediateMDTExtIEsValue{id: s00.ProtocolIEID(285), rowWLANMeasurementConfiguration: &value}).encodeFresh(fresh, budget)
		}, capture: func(v WLANMeasurementConfiguration, options aper.DecodeState) (WLANMeasurementConfiguration, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeCaptureS1APWLANMeasurementConfiguration(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}, compare: func(v WLANMeasurementConfiguration, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.
				Begin()
			BridgeCompareS1APWLANMeasurementConfiguration(&v, &s)
			s.End(
				f, root, false)
			return s.Plan(), s.BudgetValue()
		}, context: func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:WLANMeasurementConfiguration"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}(),
	}, inject: func(value WLANMeasurementConfiguration) ImmediateMDTExtIEsValue {
		return ImmediateMDTExtIEsValue{id: s00.ProtocolIEID(285), rowWLANMeasurementConfiguration: &value}
	}, get: func(value *ImmediateMDTExtIEsValue) (*WLANMeasurementConfiguration, bool) {
		return value.AsWLANMeasurementConfiguration()
	}}
}
func (ImmediateMDTExtIETable) infoSensorMeasurementConfiguration() s00.ExtensionInfo {
	return s00.ExtensionInfo{Table: ImmediateMDTExtIEs().ID(), ID: s00.ProtocolExtensionID(345), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "SensorMeasurementConfiguration"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.4", Assignment: aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "ImmediateMDT-ExtIEs", Row: "id-SensorMeasurementConfiguration"}}}
}

// SensorMeasurementConfiguration returns the typed binding for the SensorMeasurementConfiguration row of ImmediateMDTExtIETable.
func (t ImmediateMDTExtIETable) SensorMeasurementConfiguration() ImmediateMDTExtIEsSensorMeasurementConfigurationExtBinding {
	return ImmediateMDTExtIEsSensorMeasurementConfigurationExtBinding{info: t.infoSensorMeasurementConfiguration(), codec: func() s30.SensorMeasurementConfigurationValueCodec {
		sealed := s30.SensorMeasurementConfigurationValueCodec{}
		*s30.BridgeSensorMeasurementConfigurationValueCodecFieldPath(&sealed) = "SensorMeasurementConfiguration"
		*s30.BridgeSensorMeasurementConfigurationValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s30.SensorMeasurementConfiguration, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s30.SensorMeasurementConfiguration
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("SensorMeasurementConfiguration")
			var zero ImmediateMDTExtIEsValue
			decoded, err := zero.decode(s00.ProtocolIEID(345), raw)
			if err != nil {
				var empty s30.SensorMeasurementConfiguration
				return empty, runtime.WrapDecodePath(err, "SensorMeasurementConfiguration")
			}
			value, ok := decoded.AsSensorMeasurementConfiguration()
			if !ok {
				var empty s30.SensorMeasurementConfiguration
				return empty, fmt.Errorf("binding ImmediateMDT-ExtIEs.id-SensorMeasurementConfiguration: no selected value")
			}
			return *value, nil
		}
		*s30.BridgeSensorMeasurementConfigurationValueCodecFieldEncode(&sealed) = func(value s30.SensorMeasurementConfiguration, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (ImmediateMDTExtIEsValue{id: s00.ProtocolIEID(345), rowSensorMeasurementConfiguration: &value}).encodeFresh(fresh, budget)
		}
		*s30.BridgeSensorMeasurementConfigurationValueCodecFieldCapture(&sealed) = func(v s30.SensorMeasurementConfiguration, options aper.DecodeState) (s30.SensorMeasurementConfiguration, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s30.BridgeCaptureS1APSensorMeasurementConfiguration(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s30.BridgeSensorMeasurementConfigurationValueCodecFieldCompare(&sealed) = func(v s30.SensorMeasurementConfiguration, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f :=
				s.Begin()
			s30.BridgeCompareS1APSensorMeasurementConfiguration(&v, &s)
			s.
				End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s30.BridgeSensorMeasurementConfigurationValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:SensorMeasurementConfiguration"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s30.SensorMeasurementConfiguration) ImmediateMDTExtIEsValue {
			return ImmediateMDTExtIEsValue{id: s00.ProtocolIEID(345), rowSensorMeasurementConfiguration: &value}
		}, get: func(value *ImmediateMDTExtIEsValue) (*s30.SensorMeasurementConfiguration, bool) {
			return value.AsSensorMeasurementConfiguration()
		}}
}

// NewOpaque constructs an owned opaque field for an identifier without a typed row in ImmediateMDTExtIETable.
func (t ImmediateMDTExtIETable) NewOpaque(id s00.ProtocolExtensionID, criticality s00.Criticality, data []byte) (ImmediateMDTExtIEsExtField, error) {
	if id < 0 || id > 65535 || criticality < 0 || criticality > 2 {
		return ImmediateMDTExtIEsExtField{}, aper.OperationError(fmt.Errorf("invalid opaque extension selector or criticality"), "Opaque")
	}
	switch id {
	case s00.ProtocolIEID(171):
		return ImmediateMDTExtIEsExtField{}, aper.OperationError(fmt.Errorf("known extension id-M3Configuration requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(172):
		return ImmediateMDTExtIEsExtField{}, aper.OperationError(fmt.Errorf("known extension id-M4Configuration requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(173):
		return ImmediateMDTExtIEsExtField{}, aper.OperationError(fmt.Errorf("known extension id-M5Configuration requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(174):
		return ImmediateMDTExtIEsExtField{}, aper.OperationError(fmt.Errorf("known extension id-MDT-Location-Info requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(220):
		return ImmediateMDTExtIEsExtField{}, aper.OperationError(fmt.Errorf("known extension id-M6Configuration requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(221):
		return ImmediateMDTExtIEsExtField{}, aper.OperationError(fmt.Errorf("known extension id-M7Configuration requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(284):
		return ImmediateMDTExtIEsExtField{}, aper.OperationError(fmt.Errorf("known extension id-BluetoothMeasurementConfiguration requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(285):
		return ImmediateMDTExtIEsExtField{}, aper.OperationError(fmt.Errorf("known extension id-WLANMeasurementConfiguration requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(345):
		return ImmediateMDTExtIEsExtField{}, aper.OperationError(fmt.Errorf("known extension id-SensorMeasurementConfiguration requires its typed binding"), "Opaque")
	default:
		budget, err := aper.BuildBudget()
		if err != nil {
			return ImmediateMDTExtIEsExtField{}, aper.OperationError(err, "Opaque")
		}
		opaque, err := aper.BuildOpaqueOpenType(data, budget)
		if err != nil {
			return ImmediateMDTExtIEsExtField{}, aper.OperationError(err, "Opaque")
		}
		return ImmediateMDTExtIEsExtField{Id: id, Criticality: criticality, ExtensionValue: ImmediateMDTExtIEsValue{id: id, opaque: opaque, isOpaque: true}}, aper.OperationError(nil, "Opaque")
	}
}

type LoggedMDTExtIETable struct{}

func LoggedMDTExtIEs() LoggedMDTExtIETable { return LoggedMDTExtIETable{} }

// ID returns the ASN.1 object-set identity of LoggedMDTExtIETable.
func (LoggedMDTExtIETable) ID() s00.TableID {
	return func() s00.TableID {
		sealed := s00.TableID{}
		*s00.BridgeTableIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "LoggedMDT-ExtIEs"}
		return sealed
	}()
}

// Table returns the ASN.1 object-set table described by LoggedMDTExtIETable.
func (LoggedMDTExtIETable) Table() s00.LoggedMDTExtIEsValueExtensionTable {
	return func() s00.LoggedMDTExtIEsValueExtensionTable {
		sealed := s00.LoggedMDTExtIEsValueExtensionTable{}
		*s00.BridgeLoggedMDTExtIEsValueExtensionTableFieldBound(&sealed) = true
		return sealed
	}()
}
func (LoggedMDTExtIETable) infoBluetoothMeasurementConfiguration() s00.ExtensionInfo {
	return s00.ExtensionInfo{Table: LoggedMDTExtIEs().ID(), ID: s00.ProtocolExtensionID(284), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "BluetoothMeasurementConfiguration"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.4", Assignment: aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "LoggedMDT-ExtIEs", Row: "id-BluetoothMeasurementConfiguration"}}}
}

// BluetoothMeasurementConfiguration returns the typed binding for the BluetoothMeasurementConfiguration row of LoggedMDTExtIETable.
func (t LoggedMDTExtIETable) BluetoothMeasurementConfiguration() LoggedMDTExtIEsBluetoothMeasurementConfigurationExtBinding {
	return LoggedMDTExtIEsBluetoothMeasurementConfigurationExtBinding{info: t.infoBluetoothMeasurementConfiguration(), codec: func() s14.BluetoothMeasurementConfigurationValueCodec {
		sealed := s14.BluetoothMeasurementConfigurationValueCodec{}
		*s14.BridgeBluetoothMeasurementConfigurationValueCodecFieldPath(&sealed) = "BluetoothMeasurementConfiguration"
		*s14.BridgeBluetoothMeasurementConfigurationValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s14.BluetoothMeasurementConfiguration, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s14.BluetoothMeasurementConfiguration
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("BluetoothMeasurementConfiguration")
			var zero LoggedMDTExtIEsValue
			decoded, err := zero.decode(s00.ProtocolIEID(284), raw)
			if err != nil {
				var empty s14.BluetoothMeasurementConfiguration
				return empty, runtime.WrapDecodePath(err, "BluetoothMeasurementConfiguration")
			}
			value, ok := decoded.AsBluetoothMeasurementConfiguration()
			if !ok {
				var empty s14.BluetoothMeasurementConfiguration
				return empty, fmt.Errorf("binding LoggedMDT-ExtIEs.id-BluetoothMeasurementConfiguration: no selected value")
			}
			return *value, nil
		}
		*s14.BridgeBluetoothMeasurementConfigurationValueCodecFieldEncode(&sealed) = func(value s14.BluetoothMeasurementConfiguration, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (LoggedMDTExtIEsValue{id: s00.ProtocolIEID(284), rowBluetoothMeasurementConfiguration: &value}).encodeFresh(fresh, budget)
		}
		*s14.BridgeBluetoothMeasurementConfigurationValueCodecFieldCapture(&sealed) = func(v s14.BluetoothMeasurementConfiguration, options aper.DecodeState) (s14.BluetoothMeasurementConfiguration, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s14.BridgeCaptureS1APBluetoothMeasurementConfiguration(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s14.BridgeBluetoothMeasurementConfigurationValueCodecFieldCompare(&sealed) = func(v s14.BluetoothMeasurementConfiguration, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s14.BridgeCompareS1APBluetoothMeasurementConfiguration(
				&v,

				&s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s14.BridgeBluetoothMeasurementConfigurationValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:BluetoothMeasurementConfiguration"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s14.BluetoothMeasurementConfiguration) LoggedMDTExtIEsValue {
			return LoggedMDTExtIEsValue{id: s00.ProtocolIEID(284), rowBluetoothMeasurementConfiguration: &value}
		}, get: func(value *LoggedMDTExtIEsValue) (*s14.BluetoothMeasurementConfiguration, bool) {
			return value.AsBluetoothMeasurementConfiguration()
		}}
}
func (LoggedMDTExtIETable) infoWLANMeasurementConfiguration() s00.ExtensionInfo {
	return s00.ExtensionInfo{Table: LoggedMDTExtIEs().ID(), ID: s00.ProtocolExtensionID(285), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "WLANMeasurementConfiguration"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.4", Assignment: aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "LoggedMDT-ExtIEs", Row: "id-WLANMeasurementConfiguration"}}}
}

// WLANMeasurementConfiguration returns the typed binding for the WLANMeasurementConfiguration row of LoggedMDTExtIETable.
func (t LoggedMDTExtIETable) WLANMeasurementConfiguration() LoggedMDTExtIEsWLANMeasurementConfigurationExtBinding {
	return LoggedMDTExtIEsWLANMeasurementConfigurationExtBinding{info: t.infoWLANMeasurementConfiguration(), codec: WLANMeasurementConfigurationValueCodec{path: "WLANMeasurementConfiguration",
		decode: func(data []byte, options aper.DecodeState) (WLANMeasurementConfiguration, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty WLANMeasurementConfiguration
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("WLANMeasurementConfiguration")
			var zero LoggedMDTExtIEsValue
			decoded, err := zero.decode(s00.ProtocolIEID(285), raw)
			if err != nil {
				var empty WLANMeasurementConfiguration
				return empty, runtime.WrapDecodePath(err, "WLANMeasurementConfiguration")
			}
			value, ok := decoded.AsWLANMeasurementConfiguration()
			if !ok {
				var empty WLANMeasurementConfiguration
				return empty, fmt.Errorf("binding LoggedMDT-ExtIEs.id-WLANMeasurementConfiguration: no selected value")
			}
			return *value, nil
		},
		encode: func(value WLANMeasurementConfiguration, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (LoggedMDTExtIEsValue{id: s00.ProtocolIEID(285), rowWLANMeasurementConfiguration: &value}).encodeFresh(fresh, budget)
		}, capture: func(v WLANMeasurementConfiguration, options aper.DecodeState) (WLANMeasurementConfiguration, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeCaptureS1APWLANMeasurementConfiguration(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}, compare: func(v WLANMeasurementConfiguration, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.
				Begin()
			BridgeCompareS1APWLANMeasurementConfiguration(&v, &s)
			s.End(
				f, root, false)
			return s.Plan(), s.BudgetValue()
		}, context: func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:WLANMeasurementConfiguration"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}(),
	}, inject: func(value WLANMeasurementConfiguration) LoggedMDTExtIEsValue {
		return LoggedMDTExtIEsValue{id: s00.ProtocolIEID(285), rowWLANMeasurementConfiguration: &value}
	}, get: func(value *LoggedMDTExtIEsValue) (*WLANMeasurementConfiguration, bool) {
		return value.AsWLANMeasurementConfiguration()
	}}
}
func (LoggedMDTExtIETable) infoLoggedMDTTrigger() s00.ExtensionInfo {
	return s00.ExtensionInfo{Table: LoggedMDTExtIEs().ID(), ID: s00.ProtocolExtensionID(344), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "LoggedMDTTrigger"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.4", Assignment: aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "LoggedMDT-ExtIEs", Row: "id-LoggedMDTTrigger"}}}
}

// LoggedMDTTrigger returns the typed binding for the LoggedMDTTrigger row of LoggedMDTExtIETable.
func (t LoggedMDTExtIETable) LoggedMDTTrigger() LoggedMDTExtIEsLoggedMDTTriggerExtBinding {
	return LoggedMDTExtIEsLoggedMDTTriggerExtBinding{info: t.infoLoggedMDTTrigger(), codec: func() s19.LoggedMDTTriggerValueCodec {
		sealed := s19.LoggedMDTTriggerValueCodec{}
		*s19.BridgeLoggedMDTTriggerValueCodecFieldPath(&sealed) = "LoggedMDTTrigger"
		*s19.BridgeLoggedMDTTriggerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s19.LoggedMDTTrigger, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s19.LoggedMDTTrigger
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("LoggedMDTTrigger")
			var zero LoggedMDTExtIEsValue
			decoded, err := zero.decode(s00.ProtocolIEID(344), raw)
			if err != nil {
				var empty s19.LoggedMDTTrigger
				return empty, runtime.WrapDecodePath(err, "LoggedMDTTrigger")
			}
			value, ok := decoded.AsLoggedMDTTrigger()
			if !ok {
				var empty s19.LoggedMDTTrigger
				return empty, fmt.Errorf("binding LoggedMDT-ExtIEs.id-LoggedMDTTrigger: no selected value")
			}
			return *value, nil
		}
		*s19.BridgeLoggedMDTTriggerValueCodecFieldEncode(&sealed) = func(value s19.LoggedMDTTrigger, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (LoggedMDTExtIEsValue{id: s00.ProtocolIEID(344), rowLoggedMDTTrigger: &value}).encodeFresh(fresh, budget)
		}
		*s19.BridgeLoggedMDTTriggerValueCodecFieldCapture(&sealed) = func(v s19.LoggedMDTTrigger, options aper.DecodeState) (s19.LoggedMDTTrigger, aper.Snapshot) {
			s := aper.SemanticCaptureFor(
				options)
			f := s.Begin()
			s19.BridgeCaptureS1APLoggedMDTTrigger(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s19.BridgeLoggedMDTTriggerValueCodecFieldCompare(&sealed) = func(v s19.LoggedMDTTrigger, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s19.BridgeCompareS1APLoggedMDTTrigger(&v, &s)
			s.End(f, root, false)
			return s.
				Plan(), s.BudgetValue()
		}
		*s19.BridgeLoggedMDTTriggerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:LoggedMDTTrigger"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s19.LoggedMDTTrigger) LoggedMDTExtIEsValue {
			return LoggedMDTExtIEsValue{id: s00.ProtocolIEID(344), rowLoggedMDTTrigger: &value}
		}, get: func(value *LoggedMDTExtIEsValue) (*s19.LoggedMDTTrigger, bool) { return value.AsLoggedMDTTrigger() }}
}
func (LoggedMDTExtIETable) infoSensorMeasurementConfiguration() s00.ExtensionInfo {
	return s00.ExtensionInfo{Table: LoggedMDTExtIEs().ID(), ID: s00.ProtocolExtensionID(345), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "SensorMeasurementConfiguration"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.4", Assignment: aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "LoggedMDT-ExtIEs", Row: "id-SensorMeasurementConfiguration"}}}
}

// SensorMeasurementConfiguration returns the typed binding for the SensorMeasurementConfiguration row of LoggedMDTExtIETable.
func (t LoggedMDTExtIETable) SensorMeasurementConfiguration() LoggedMDTExtIEsSensorMeasurementConfigurationExtBinding {
	return LoggedMDTExtIEsSensorMeasurementConfigurationExtBinding{info: t.infoSensorMeasurementConfiguration(), codec: func() s30.SensorMeasurementConfigurationValueCodec {
		sealed := s30.SensorMeasurementConfigurationValueCodec{}
		*s30.BridgeSensorMeasurementConfigurationValueCodecFieldPath(&sealed) = "SensorMeasurementConfiguration"
		*s30.BridgeSensorMeasurementConfigurationValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s30.SensorMeasurementConfiguration, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s30.SensorMeasurementConfiguration
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("SensorMeasurementConfiguration")
			var zero LoggedMDTExtIEsValue
			decoded, err := zero.decode(s00.ProtocolIEID(345), raw)
			if err != nil {
				var empty s30.SensorMeasurementConfiguration
				return empty, runtime.WrapDecodePath(err, "SensorMeasurementConfiguration")
			}
			value, ok := decoded.AsSensorMeasurementConfiguration()
			if !ok {
				var empty s30.SensorMeasurementConfiguration
				return empty, fmt.Errorf("binding LoggedMDT-ExtIEs.id-SensorMeasurementConfiguration: no selected value")
			}
			return *value, nil
		}
		*s30.BridgeSensorMeasurementConfigurationValueCodecFieldEncode(&sealed) = func(value s30.SensorMeasurementConfiguration, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (LoggedMDTExtIEsValue{id: s00.ProtocolIEID(345), rowSensorMeasurementConfiguration: &value}).encodeFresh(fresh, budget)
		}
		*s30.BridgeSensorMeasurementConfigurationValueCodecFieldCapture(&sealed) = func(v s30.SensorMeasurementConfiguration, options aper.DecodeState) (s30.SensorMeasurementConfiguration, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s30.BridgeCaptureS1APSensorMeasurementConfiguration(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s30.BridgeSensorMeasurementConfigurationValueCodecFieldCompare(&sealed) = func(v s30.SensorMeasurementConfiguration, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f :=
				s.Begin()
			s30.BridgeCompareS1APSensorMeasurementConfiguration(&v, &s)
			s.
				End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s30.BridgeSensorMeasurementConfigurationValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:SensorMeasurementConfiguration"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s30.SensorMeasurementConfiguration) LoggedMDTExtIEsValue {
			return LoggedMDTExtIEsValue{id: s00.ProtocolIEID(345), rowSensorMeasurementConfiguration: &value}
		}, get: func(value *LoggedMDTExtIEsValue) (*s30.SensorMeasurementConfiguration, bool) {
			return value.AsSensorMeasurementConfiguration()
		}}
}

// NewOpaque constructs an owned opaque field for an identifier without a typed row in LoggedMDTExtIETable.
func (t LoggedMDTExtIETable) NewOpaque(id s00.ProtocolExtensionID, criticality s00.Criticality, data []byte) (LoggedMDTExtIEsExtField, error) {
	if id < 0 || id > 65535 || criticality < 0 || criticality > 2 {
		return LoggedMDTExtIEsExtField{}, aper.OperationError(fmt.Errorf("invalid opaque extension selector or criticality"), "Opaque")
	}
	switch id {
	case s00.ProtocolIEID(284):
		return LoggedMDTExtIEsExtField{}, aper.OperationError(fmt.Errorf("known extension id-BluetoothMeasurementConfiguration requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(285):
		return LoggedMDTExtIEsExtField{}, aper.OperationError(fmt.Errorf("known extension id-WLANMeasurementConfiguration requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(344):
		return LoggedMDTExtIEsExtField{}, aper.OperationError(fmt.Errorf("known extension id-LoggedMDTTrigger requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(345):
		return LoggedMDTExtIEsExtField{}, aper.OperationError(fmt.Errorf("known extension id-SensorMeasurementConfiguration requires its typed binding"), "Opaque")
	default:
		budget, err := aper.BuildBudget()
		if err != nil {
			return LoggedMDTExtIEsExtField{}, aper.OperationError(err, "Opaque")
		}
		opaque, err := aper.BuildOpaqueOpenType(data, budget)
		if err != nil {
			return LoggedMDTExtIEsExtField{}, aper.OperationError(err, "Opaque")
		}
		return LoggedMDTExtIEsExtField{Id: id, Criticality: criticality, ExtensionValue: LoggedMDTExtIEsValue{id: id, opaque: opaque, isOpaque: true}}, aper.OperationError(nil, "Opaque")
	}
}

type TraceActivationExtIETable struct{}

func TraceActivationExtIEs() TraceActivationExtIETable { return TraceActivationExtIETable{} }

// ID returns the ASN.1 object-set identity of TraceActivationExtIETable.
func (TraceActivationExtIETable) ID() s00.TableID {
	return func() s00.TableID {
		sealed := s00.TableID{}
		*s00.BridgeTableIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "TraceActivation-ExtIEs"}
		return sealed
	}()
}

// Table returns the ASN.1 object-set table described by TraceActivationExtIETable.
func (TraceActivationExtIETable) Table() s00.TraceActivationExtIEsValueExtensionTable {
	return func() s00.TraceActivationExtIEsValueExtensionTable {
		sealed := s00.TraceActivationExtIEsValueExtensionTable{}
		*s00.BridgeTraceActivationExtIEsValueExtensionTableFieldBound(&sealed) = true
		return sealed
	}()
}
func (TraceActivationExtIETable) infoMDTConfiguration() s00.ExtensionInfo {
	return s00.ExtensionInfo{Table: TraceActivationExtIEs().ID(), ID: s00.ProtocolExtensionID(162), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "MDT-Configuration"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.4", Assignment: aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "TraceActivation-ExtIEs", Row: "id-MDTConfiguration"}}}
}

// MDTConfiguration returns the typed binding for the MDTConfiguration row of TraceActivationExtIETable.
func (t TraceActivationExtIETable) MDTConfiguration() TraceActivationExtIEsMDTConfigurationExtBinding {
	return TraceActivationExtIEsMDTConfigurationExtBinding{info: t.infoMDTConfiguration(), codec: MDTConfigurationValueCodec{path: "MDTConfiguration",
		decode: func(data []byte, options aper.DecodeState) (MDTConfiguration, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty MDTConfiguration
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("MDTConfiguration")
			var zero TraceActivationExtIEsValue
			decoded, err := zero.decode(s00.ProtocolIEID(162), raw)
			if err != nil {
				var empty MDTConfiguration
				return empty, runtime.WrapDecodePath(err, "MDTConfiguration")
			}
			value, ok := decoded.AsMDTConfiguration()
			if !ok {
				var empty MDTConfiguration
				return empty, fmt.Errorf("binding TraceActivation-ExtIEs.id-MDTConfiguration: no selected value")
			}
			return *value, nil
		},
		encode: func(value MDTConfiguration, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (TraceActivationExtIEsValue{id: s00.ProtocolIEID(162), rowMDTConfiguration: &value}).encodeFresh(fresh, budget)
		}, capture: func(v MDTConfiguration, options aper.DecodeState) (MDTConfiguration, aper.Snapshot) {
			s := aper.SemanticCaptureFor(
				options)
			f := s.Begin()
			BridgeCaptureS1APMDTConfiguration(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}, compare: func(v MDTConfiguration, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeCompareS1APMDTConfiguration(&v, &s)
			s.End(f, root, false)
			return s.
				Plan(), s.BudgetValue()
		}, context: func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:MDTConfiguration"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}(),
	}, inject: func(value MDTConfiguration) TraceActivationExtIEsValue {
		return TraceActivationExtIEsValue{id: s00.ProtocolIEID(162), rowMDTConfiguration: &value}
	}, get: func(value *TraceActivationExtIEsValue) (*MDTConfiguration, bool) { return value.AsMDTConfiguration() }}
}
func (TraceActivationExtIETable) infoUEAppLayerMeasConfig() s00.ExtensionInfo {
	return s00.ExtensionInfo{Table: TraceActivationExtIEs().ID(), ID: s00.ProtocolExtensionID(262), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "UEAppLayerMeasConfig"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.4", Assignment: aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "TraceActivation-ExtIEs", Row: "id-UEAppLayerMeasConfig"}}}
}

// UEAppLayerMeasConfig returns the typed binding for the UEAppLayerMeasConfig row of TraceActivationExtIETable.
func (t TraceActivationExtIETable) UEAppLayerMeasConfig() TraceActivationExtIEsUEAppLayerMeasConfigExtBinding {
	return TraceActivationExtIEsUEAppLayerMeasConfigExtBinding{info: t.infoUEAppLayerMeasConfig(), codec: func() s35.UEAppLayerMeasConfigValueCodec {
		sealed := s35.UEAppLayerMeasConfigValueCodec{}
		*s35.BridgeUEAppLayerMeasConfigValueCodecFieldPath(&sealed) = "UEAppLayerMeasConfig"
		*s35.BridgeUEAppLayerMeasConfigValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s35.UEAppLayerMeasConfig, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s35.UEAppLayerMeasConfig
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("UEAppLayerMeasConfig")
			var zero TraceActivationExtIEsValue
			decoded, err := zero.decode(s00.ProtocolIEID(262), raw)
			if err != nil {
				var empty s35.UEAppLayerMeasConfig
				return empty, runtime.WrapDecodePath(err, "UEAppLayerMeasConfig")
			}
			value, ok := decoded.AsUEAppLayerMeasConfig()
			if !ok {
				var empty s35.UEAppLayerMeasConfig
				return empty, fmt.Errorf("binding TraceActivation-ExtIEs.id-UEAppLayerMeasConfig: no selected value")
			}
			return *value, nil
		}
		*s35.BridgeUEAppLayerMeasConfigValueCodecFieldEncode(&sealed) = func(value s35.UEAppLayerMeasConfig, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (TraceActivationExtIEsValue{id: s00.ProtocolIEID(262), rowUEAppLayerMeasConfig: &value}).encodeFresh(fresh, budget)
		}
		*s35.BridgeUEAppLayerMeasConfigValueCodecFieldCapture(&sealed) = func(v s35.UEAppLayerMeasConfig, options aper.DecodeState) (s35.UEAppLayerMeasConfig, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s35.BridgeCaptureS1APUEAppLayerMeasConfig(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s35.BridgeUEAppLayerMeasConfigValueCodecFieldCompare(&sealed) = func(v s35.UEAppLayerMeasConfig, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s35.BridgeCompareS1APUEAppLayerMeasConfig(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s35.BridgeUEAppLayerMeasConfigValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:UEAppLayerMeasConfig"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s35.UEAppLayerMeasConfig) TraceActivationExtIEsValue {
			return TraceActivationExtIEsValue{id: s00.ProtocolIEID(262), rowUEAppLayerMeasConfig: &value}
		}, get: func(value *TraceActivationExtIEsValue) (*s35.UEAppLayerMeasConfig, bool) {
			return value.AsUEAppLayerMeasConfig()
		}}
}
func (TraceActivationExtIETable) infoMDTConfigurationNR() s00.ExtensionInfo {
	return s00.ExtensionInfo{Table: TraceActivationExtIEs().ID(), ID: s00.ProtocolExtensionID(316), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "MDT-ConfigurationNR"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.4", Assignment: aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "TraceActivation-ExtIEs", Row: "id-MDTConfigurationNR"}}}
}

// MDTConfigurationNR returns the typed binding for the MDTConfigurationNR row of TraceActivationExtIETable.
func (t TraceActivationExtIETable) MDTConfigurationNR() TraceActivationExtIEsMDTConfigurationNRExtBinding {
	return TraceActivationExtIEsMDTConfigurationNRExtBinding{info: t.infoMDTConfigurationNR(), codec: func() s01.MDTConfigurationNRValueCodec {
		sealed := s01.MDTConfigurationNRValueCodec{}
		*s01.BridgeMDTConfigurationNRValueCodecFieldPath(&sealed) = "MDTConfigurationNR"
		*s01.BridgeMDTConfigurationNRValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.MDTConfigurationNR, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s00.MDTConfigurationNR
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("MDTConfigurationNR")
			var zero TraceActivationExtIEsValue
			decoded, err := zero.decode(s00.ProtocolIEID(316), raw)
			if err != nil {
				var empty s00.MDTConfigurationNR
				return empty, runtime.WrapDecodePath(err, "MDTConfigurationNR")
			}
			value, ok := decoded.AsMDTConfigurationNR()
			if !ok {
				var empty s00.MDTConfigurationNR
				return empty, fmt.Errorf("binding TraceActivation-ExtIEs.id-MDTConfigurationNR: no selected value")
			}
			return *value, nil
		}
		*s01.BridgeMDTConfigurationNRValueCodecFieldEncode(&sealed) = func(value s00.MDTConfigurationNR, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (TraceActivationExtIEsValue{id: s00.ProtocolIEID(316), rowMDTConfigurationNR: &value}).encodeFresh(fresh, budget)
		}
		*s01.BridgeMDTConfigurationNRValueCodecFieldCapture(&sealed) = func(v s00.MDTConfigurationNR, options aper.DecodeState) (s00.MDTConfigurationNR, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s00.BridgeCaptureS1APMDTConfigurationNR(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v,

				root
		}
		*s01.BridgeMDTConfigurationNRValueCodecFieldCompare(&sealed) = func(v s00.MDTConfigurationNR, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s02.BridgeCompareS1APMDTConfigurationNR(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s01.BridgeMDTConfigurationNRValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:MDTConfigurationNR"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s00.MDTConfigurationNR) TraceActivationExtIEsValue {
			return TraceActivationExtIEsValue{id: s00.ProtocolIEID(316), rowMDTConfigurationNR: &value}
		}, get: func(value *TraceActivationExtIEsValue) (*s00.MDTConfigurationNR, bool) {
			return value.AsMDTConfigurationNR()
		}}
}
func (TraceActivationExtIETable) infoTraceCollectionEntityURI() s00.ExtensionInfo {
	return s00.ExtensionInfo{Table: TraceActivationExtIEs().ID(), ID: s00.ProtocolExtensionID(325), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "URI-Address"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.4", Assignment: aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "TraceActivation-ExtIEs", Row: "id-TraceCollectionEntityURI"}}}
}

// TraceCollectionEntityURI returns the typed binding for the TraceCollectionEntityURI row of TraceActivationExtIETable.
func (t TraceActivationExtIETable) TraceCollectionEntityURI() TraceActivationExtIEsURIAddressExtBinding {
	return TraceActivationExtIEsURIAddressExtBinding{info: t.infoTraceCollectionEntityURI(), codec: func() s02.URIAddressValueCodec {
		sealed := s02.URIAddressValueCodec{}
		*s02.BridgeURIAddressValueCodecFieldPath(&sealed) = "URIAddress"
		*s02.BridgeURIAddressValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.URIAddress, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s00.URIAddress
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("URIAddress")
			var zero TraceActivationExtIEsValue
			decoded, err := zero.decode(s00.ProtocolIEID(325), raw)
			if err != nil {
				var empty s00.URIAddress
				return empty, runtime.WrapDecodePath(err, "URIAddress")
			}
			value, ok := decoded.AsTraceCollectionEntityURI()
			if !ok {
				var empty s00.URIAddress
				return empty, fmt.Errorf("binding TraceActivation-ExtIEs.id-TraceCollectionEntityURI: no selected value")
			}
			return *value, nil
		}
		*s02.BridgeURIAddressValueCodecFieldEncode(&sealed) = func(value s00.URIAddress, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (TraceActivationExtIEsValue{id: s00.ProtocolIEID(325), rowTraceCollectionEntityURI: &value}).encodeFresh(fresh, budget)
		}
		*s02.BridgeURIAddressValueCodecFieldCapture(&sealed) = func(v s00.URIAddress, options aper.DecodeState) (s00.URIAddress, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f :=
				s.Begin()
			s00.BridgeCaptureS1APURIAddress(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s02.BridgeURIAddressValueCodecFieldCompare(&sealed) = func(v s00.URIAddress, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s07.BridgeCompareS1APURIAddress(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s02.BridgeURIAddressValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:URIAddress"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s00.URIAddress) TraceActivationExtIEsValue {
			return TraceActivationExtIEsValue{id: s00.ProtocolIEID(325), rowTraceCollectionEntityURI: &value}
		}, get: func(value *TraceActivationExtIEsValue) (*s00.URIAddress, bool) {
			return value.AsTraceCollectionEntityURI()
		}}
}

// NewOpaque constructs an owned opaque field for an identifier without a typed row in TraceActivationExtIETable.
func (t TraceActivationExtIETable) NewOpaque(id s00.ProtocolExtensionID, criticality s00.Criticality, data []byte) (TraceActivationExtIEsExtField, error) {
	if id < 0 || id > 65535 || criticality < 0 || criticality > 2 {
		return TraceActivationExtIEsExtField{}, aper.OperationError(fmt.Errorf("invalid opaque extension selector or criticality"), "Opaque")
	}
	switch id {
	case s00.ProtocolIEID(162):
		return TraceActivationExtIEsExtField{}, aper.OperationError(fmt.Errorf("known extension id-MDTConfiguration requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(262):
		return TraceActivationExtIEsExtField{}, aper.OperationError(fmt.Errorf("known extension id-UEAppLayerMeasConfig requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(316):
		return TraceActivationExtIEsExtField{}, aper.OperationError(fmt.Errorf("known extension id-MDTConfigurationNR requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(325):
		return TraceActivationExtIEsExtField{}, aper.OperationError(fmt.Errorf("known extension id-TraceCollectionEntityURI requires its typed binding"), "Opaque")
	default:
		budget, err := aper.BuildBudget()
		if err != nil {
			return TraceActivationExtIEsExtField{}, aper.OperationError(err, "Opaque")
		}
		opaque, err := aper.BuildOpaqueOpenType(data, budget)
		if err != nil {
			return TraceActivationExtIEsExtField{}, aper.OperationError(err, "Opaque")
		}
		return TraceActivationExtIEsExtField{Id: id, Criticality: criticality, ExtensionValue: TraceActivationExtIEsValue{id: id, opaque: opaque, isOpaque: true}}, aper.OperationError(nil, "Opaque")
	}
}

type PathSwitchRequestAcknowledgeIETable struct{}

func PathSwitchRequestAcknowledgeIEs() PathSwitchRequestAcknowledgeIETable {
	return PathSwitchRequestAcknowledgeIETable{}
}

// ID returns the ASN.1 object-set identity of PathSwitchRequestAcknowledgeIETable.
func (PathSwitchRequestAcknowledgeIETable) ID() s00.TableID {
	return func() s00.TableID {
		sealed := s00.TableID{}
		*s00.BridgeTableIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "PathSwitchRequestAcknowledgeIEs"}
		return sealed
	}()
}

// Table returns the ASN.1 object-set table described by PathSwitchRequestAcknowledgeIETable.
func (PathSwitchRequestAcknowledgeIETable) Table() s00.PathSwitchRequestAcknowledgeIEValueIETable {
	return func() s00.PathSwitchRequestAcknowledgeIEValueIETable {
		sealed := s00.PathSwitchRequestAcknowledgeIEValueIETable{}
		*s00.BridgePathSwitchRequestAcknowledgeIEValueIETableFieldBound(&sealed) = true
		return sealed
	}()
}
func (PathSwitchRequestAcknowledgeIETable) infoMMEUES1APID() s00.FieldInfo {
	return s00.FieldInfo{Table: PathSwitchRequestAcknowledgeIEs().ID(), ID: s00.ProtocolIEID(0), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceMandatory, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "MME-UE-S1AP-ID"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "PathSwitchRequestAcknowledgeIEs", Row: "id-MME-UE-S1AP-ID"}}}
}

// MMEUES1APID returns the typed binding for the MMEUES1APID row of PathSwitchRequestAcknowledgeIETable.
func (t PathSwitchRequestAcknowledgeIETable) MMEUES1APID() s46.PathSwitchRequestAcknowledgeMMEUES1APIDIEBinding {
	return func() s46.PathSwitchRequestAcknowledgeMMEUES1APIDIEBinding {
		sealed := s46.PathSwitchRequestAcknowledgeMMEUES1APIDIEBinding{}
		*s46.BridgePathSwitchRequestAcknowledgeMMEUES1APIDIEBindingFieldInfo(&sealed) = t.infoMMEUES1APID()
		*s46.BridgePathSwitchRequestAcknowledgeMMEUES1APIDIEBindingFieldCodec(&sealed) = func() s01.MMEUES1APIDValueCodec {
			sealed := s01.MMEUES1APIDValueCodec{}
			*s01.BridgeMMEUES1APIDValueCodecFieldPath(&sealed) = "MMEUES1APID"
			*s01.BridgeMMEUES1APIDValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.MMEUES1APID, error) {
				raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
				if err != nil {
					var empty s00.MMEUES1APID
					return empty, err
				}
				raw.BudgetBuffer().EnterComponent("MMEUES1APID")
				var zero s46.PathSwitchRequestAcknowledgeIEValue
				decoded, err := s46.BridgePathSwitchRequestAcknowledgeIEValueMethodDecode(zero, s00.ProtocolIEID(0), raw)
				if err != nil {
					var empty s00.MMEUES1APID
					return empty, runtime.WrapDecodePath(err, "MMEUES1APID")
				}
				value, ok := decoded.AsMMEUES1APID()
				if !ok {
					var empty s00.MMEUES1APID
					return empty, fmt.Errorf("binding PathSwitchRequestAcknowledgeIEs.id-MME-UE-S1AP-ID: no selected value")
				}
				return *value, nil
			}
			*s01.BridgeMMEUES1APIDValueCodecFieldEncode(&sealed) = func(value s00.MMEUES1APID, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
				return s46.BridgePathSwitchRequestAcknowledgeIEValueMethodEncodeFresh((func() s46.PathSwitchRequestAcknowledgeIEValue {
					sealed := s46.PathSwitchRequestAcknowledgeIEValue{}
					*s46.BridgePathSwitchRequestAcknowledgeIEValueFieldId(&sealed) = s00.ProtocolIEID(0)
					*s46.BridgePathSwitchRequestAcknowledgeIEValueFieldRowMMEUES1APID(&sealed) = &value
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
		}()
		*s46.BridgePathSwitchRequestAcknowledgeMMEUES1APIDIEBindingFieldInject(&sealed) = func(value s00.MMEUES1APID) s46.PathSwitchRequestAcknowledgeIEValue {
			return func() s46.PathSwitchRequestAcknowledgeIEValue {
				sealed := s46.PathSwitchRequestAcknowledgeIEValue{}
				*s46.BridgePathSwitchRequestAcknowledgeIEValueFieldId(&sealed) = s00.ProtocolIEID(0)
				*s46.BridgePathSwitchRequestAcknowledgeIEValueFieldRowMMEUES1APID(&sealed) = &value
				return sealed
			}()
		}
		*s46.BridgePathSwitchRequestAcknowledgeMMEUES1APIDIEBindingFieldGet(&sealed) = func(value *s46.PathSwitchRequestAcknowledgeIEValue) (*s00.MMEUES1APID, bool) {
			return value.AsMMEUES1APID()
		}
		return sealed
	}()
}
func (PathSwitchRequestAcknowledgeIETable) infoENBUES1APID() s00.FieldInfo {
	return s00.FieldInfo{Table: PathSwitchRequestAcknowledgeIEs().ID(), ID: s00.ProtocolIEID(8), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceMandatory, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "ENB-UE-S1AP-ID"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "PathSwitchRequestAcknowledgeIEs", Row: "id-eNB-UE-S1AP-ID"}}}
}

// ENBUES1APID returns the typed binding for the ENBUES1APID row of PathSwitchRequestAcknowledgeIETable.
func (t PathSwitchRequestAcknowledgeIETable) ENBUES1APID() s46.PathSwitchRequestAcknowledgeENBUES1APIDIEBinding {
	return func() s46.PathSwitchRequestAcknowledgeENBUES1APIDIEBinding {
		sealed := s46.PathSwitchRequestAcknowledgeENBUES1APIDIEBinding{}
		*s46.BridgePathSwitchRequestAcknowledgeENBUES1APIDIEBindingFieldInfo(&sealed) = t.infoENBUES1APID()
		*s46.BridgePathSwitchRequestAcknowledgeENBUES1APIDIEBindingFieldCodec(&sealed) = func() s00.ENBUES1APIDValueCodec {
			sealed := s00.ENBUES1APIDValueCodec{}
			*s00.BridgeENBUES1APIDValueCodecFieldPath(&sealed) = "ENBUES1APID"
			*s00.BridgeENBUES1APIDValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.ENBUES1APID, error) {
				raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
				if err != nil {
					var empty s00.ENBUES1APID
					return empty, err
				}
				raw.BudgetBuffer().EnterComponent("ENBUES1APID")
				var zero s46.PathSwitchRequestAcknowledgeIEValue
				decoded, err := s46.BridgePathSwitchRequestAcknowledgeIEValueMethodDecode(zero, s00.ProtocolIEID(8), raw)
				if err != nil {
					var empty s00.ENBUES1APID
					return empty, runtime.WrapDecodePath(err, "ENBUES1APID")
				}
				value, ok := decoded.AsENBUES1APID()
				if !ok {
					var empty s00.ENBUES1APID
					return empty, fmt.Errorf("binding PathSwitchRequestAcknowledgeIEs.id-eNB-UE-S1AP-ID: no selected value")
				}
				return *value, nil
			}
			*s00.BridgeENBUES1APIDValueCodecFieldEncode(&sealed) = func(value s00.ENBUES1APID, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
				return s46.BridgePathSwitchRequestAcknowledgeIEValueMethodEncodeFresh((func() s46.PathSwitchRequestAcknowledgeIEValue {
					sealed := s46.PathSwitchRequestAcknowledgeIEValue{}
					*s46.BridgePathSwitchRequestAcknowledgeIEValueFieldId(&sealed) = s00.ProtocolIEID(8)
					*s46.BridgePathSwitchRequestAcknowledgeIEValueFieldRowENBUES1APID(&sealed) = &value
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
		*s46.BridgePathSwitchRequestAcknowledgeENBUES1APIDIEBindingFieldInject(&sealed) = func(value s00.ENBUES1APID) s46.PathSwitchRequestAcknowledgeIEValue {
			return func() s46.PathSwitchRequestAcknowledgeIEValue {
				sealed := s46.PathSwitchRequestAcknowledgeIEValue{}
				*s46.BridgePathSwitchRequestAcknowledgeIEValueFieldId(&sealed) = s00.ProtocolIEID(8)
				*s46.BridgePathSwitchRequestAcknowledgeIEValueFieldRowENBUES1APID(&sealed) = &value
				return sealed
			}()
		}
		*s46.BridgePathSwitchRequestAcknowledgeENBUES1APIDIEBindingFieldGet(&sealed) = func(value *s46.PathSwitchRequestAcknowledgeIEValue) (*s00.ENBUES1APID, bool) {
			return value.AsENBUES1APID()
		}
		return sealed
	}()
}
func (PathSwitchRequestAcknowledgeIETable) infoUEaggregateMaximumBitrate() s00.FieldInfo {
	return s00.FieldInfo{Table: PathSwitchRequestAcknowledgeIEs().ID(), ID: s00.ProtocolIEID(66), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "UEAggregateMaximumBitrate"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "PathSwitchRequestAcknowledgeIEs", Row: "id-uEaggregateMaximumBitrate"}}}
}

// UEaggregateMaximumBitrate returns the typed binding for the UEaggregateMaximumBitrate row of PathSwitchRequestAcknowledgeIETable.
func (t PathSwitchRequestAcknowledgeIETable) UEaggregateMaximumBitrate() s46.PathSwitchRequestAcknowledgeUEAggregateMaximumBitrateIEBinding {
	return func() s46.PathSwitchRequestAcknowledgeUEAggregateMaximumBitrateIEBinding {
		sealed := s46.PathSwitchRequestAcknowledgeUEAggregateMaximumBitrateIEBinding{}
		*s46.BridgePathSwitchRequestAcknowledgeUEAggregateMaximumBitrateIEBindingFieldInfo(&sealed) = t.infoUEaggregateMaximumBitrate()
		*s46.BridgePathSwitchRequestAcknowledgeUEAggregateMaximumBitrateIEBindingFieldCodec(&sealed) = func() s35.UEAggregateMaximumBitrateValueCodec {
			sealed := s35.UEAggregateMaximumBitrateValueCodec{}
			*s35.BridgeUEAggregateMaximumBitrateValueCodecFieldPath(&sealed) = "UEAggregateMaximumBitrate"
			*s35.BridgeUEAggregateMaximumBitrateValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s35.UEAggregateMaximumBitrate, error) {
				raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
				if err != nil {
					var empty s35.UEAggregateMaximumBitrate
					return empty, err
				}
				raw.BudgetBuffer().EnterComponent("UEAggregateMaximumBitrate")
				var zero s46.PathSwitchRequestAcknowledgeIEValue
				decoded, err := s46.BridgePathSwitchRequestAcknowledgeIEValueMethodDecode(zero, s00.ProtocolIEID(66), raw)
				if err != nil {
					var empty s35.UEAggregateMaximumBitrate
					return empty, runtime.WrapDecodePath(err, "UEAggregateMaximumBitrate")
				}
				value, ok := decoded.AsUEaggregateMaximumBitrate()
				if !ok {
					var empty s35.UEAggregateMaximumBitrate
					return empty, fmt.Errorf("binding PathSwitchRequestAcknowledgeIEs.id-uEaggregateMaximumBitrate: no selected value")
				}
				return *value, nil
			}
			*s35.BridgeUEAggregateMaximumBitrateValueCodecFieldEncode(&sealed) = func(value s35.UEAggregateMaximumBitrate, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
				return s46.BridgePathSwitchRequestAcknowledgeIEValueMethodEncodeFresh((func() s46.PathSwitchRequestAcknowledgeIEValue {
					sealed := s46.PathSwitchRequestAcknowledgeIEValue{}
					*s46.BridgePathSwitchRequestAcknowledgeIEValueFieldId(&sealed) = s00.ProtocolIEID(66)
					*s46.BridgePathSwitchRequestAcknowledgeIEValueFieldRowUEaggregateMaximumBitrate(&sealed) = &value
					return sealed
				}()), fresh, budget)
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
		}()
		*s46.BridgePathSwitchRequestAcknowledgeUEAggregateMaximumBitrateIEBindingFieldInject(&sealed) = func(value s35.UEAggregateMaximumBitrate) s46.PathSwitchRequestAcknowledgeIEValue {
			return func() s46.PathSwitchRequestAcknowledgeIEValue {
				sealed := s46.PathSwitchRequestAcknowledgeIEValue{}
				*s46.BridgePathSwitchRequestAcknowledgeIEValueFieldId(&sealed) = s00.ProtocolIEID(66)
				*s46.BridgePathSwitchRequestAcknowledgeIEValueFieldRowUEaggregateMaximumBitrate(&sealed) = &value
				return sealed
			}()
		}
		*s46.BridgePathSwitchRequestAcknowledgeUEAggregateMaximumBitrateIEBindingFieldGet(&sealed) = func(value *s46.PathSwitchRequestAcknowledgeIEValue) (*s35.UEAggregateMaximumBitrate, bool) {
			return value.AsUEaggregateMaximumBitrate()
		}
		return sealed
	}()
}
func (PathSwitchRequestAcknowledgeIETable) infoERABToBeSwitchedULList() s00.FieldInfo {
	return s00.FieldInfo{Table: PathSwitchRequestAcknowledgeIEs().ID(), ID: s00.ProtocolIEID(95), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "E-RABToBeSwitchedULList"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "PathSwitchRequestAcknowledgeIEs", Row: "id-E-RABToBeSwitchedULList"}}}
}

// ERABToBeSwitchedULList returns the typed binding for the ERABToBeSwitchedULList row of PathSwitchRequestAcknowledgeIETable.
func (t PathSwitchRequestAcknowledgeIETable) ERABToBeSwitchedULList() s46.PathSwitchRequestAcknowledgeERABToBeSwitchedULListIEBinding {
	return func() s46.PathSwitchRequestAcknowledgeERABToBeSwitchedULListIEBinding {
		sealed := s46.PathSwitchRequestAcknowledgeERABToBeSwitchedULListIEBinding{}
		*s46.BridgePathSwitchRequestAcknowledgeERABToBeSwitchedULListIEBindingFieldInfo(&sealed) = t.infoERABToBeSwitchedULList()
		*s46.BridgePathSwitchRequestAcknowledgeERABToBeSwitchedULListIEBindingFieldCodec(&sealed) = func() s17.ERABToBeSwitchedULListValueCodec {
			sealed := s17.ERABToBeSwitchedULListValueCodec{}
			*s17.BridgeERABToBeSwitchedULListValueCodecFieldPath(&sealed) = "ERABToBeSwitchedULList"
			*s17.BridgeERABToBeSwitchedULListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s17.ERABToBeSwitchedULList, error) {
				raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
				if err != nil {
					var empty s17.ERABToBeSwitchedULList
					return empty, err
				}
				raw.BudgetBuffer().EnterComponent("ERABToBeSwitchedULList")
				var zero s46.PathSwitchRequestAcknowledgeIEValue
				decoded, err := s46.BridgePathSwitchRequestAcknowledgeIEValueMethodDecode(zero, s00.ProtocolIEID(95), raw)
				if err != nil {
					var empty s17.ERABToBeSwitchedULList
					return empty, runtime.WrapDecodePath(err, "ERABToBeSwitchedULList")
				}
				value, ok := decoded.AsERABToBeSwitchedULList()
				if !ok {
					var empty s17.ERABToBeSwitchedULList
					return empty, fmt.Errorf("binding PathSwitchRequestAcknowledgeIEs.id-E-RABToBeSwitchedULList: no selected value")
				}
				return *value, nil
			}
			*s17.BridgeERABToBeSwitchedULListValueCodecFieldEncode(&sealed) = func(value s17.ERABToBeSwitchedULList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
				return s46.BridgePathSwitchRequestAcknowledgeIEValueMethodEncodeFresh((func() s46.PathSwitchRequestAcknowledgeIEValue {
					sealed := s46.PathSwitchRequestAcknowledgeIEValue{}
					*s46.BridgePathSwitchRequestAcknowledgeIEValueFieldId(&sealed) = s00.ProtocolIEID(95)
					*s46.BridgePathSwitchRequestAcknowledgeIEValueFieldRowERABToBeSwitchedULList(&sealed) = &value
					return sealed
				}()), fresh, budget)
			}
			*s17.BridgeERABToBeSwitchedULListValueCodecFieldCapture(&sealed) = func(v s17.ERABToBeSwitchedULList, options aper.DecodeState) (s17.ERABToBeSwitchedULList, aper.Snapshot,

			) {
				s := aper.SemanticCaptureFor(options)
				f := s.Begin()
				s25.BridgeCaptureS1APERABToBeSwitchedULList(&v, &s)
				var root aper.Snapshot
				s.End(f, &root, false)
				return v, root
			}
			*s17.BridgeERABToBeSwitchedULListValueCodecFieldCompare(&sealed) = func(v s17.ERABToBeSwitchedULList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

			) {
				s := aper.NewSemanticComparison(root, budget)
				f := s.Begin()
				s25.BridgeCompareS1APERABToBeSwitchedULList(&v, &s)
				s.End(f, root, false)
				return s.Plan(), s.BudgetValue()
			}
			*s17.BridgeERABToBeSwitchedULListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
				sealed := s00.BridgeCodecContext{}
				*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ERABToBeSwitchedULList"
				*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
				return sealed
			}()
			return sealed
		}()
		*s46.BridgePathSwitchRequestAcknowledgeERABToBeSwitchedULListIEBindingFieldInject(&sealed) = func(value s17.ERABToBeSwitchedULList) s46.PathSwitchRequestAcknowledgeIEValue {
			return func() s46.PathSwitchRequestAcknowledgeIEValue {
				sealed := s46.PathSwitchRequestAcknowledgeIEValue{}
				*s46.BridgePathSwitchRequestAcknowledgeIEValueFieldId(&sealed) = s00.ProtocolIEID(95)
				*s46.BridgePathSwitchRequestAcknowledgeIEValueFieldRowERABToBeSwitchedULList(&sealed) = &value
				return sealed
			}()
		}
		*s46.BridgePathSwitchRequestAcknowledgeERABToBeSwitchedULListIEBindingFieldGet(&sealed) = func(value *s46.PathSwitchRequestAcknowledgeIEValue) (*s17.ERABToBeSwitchedULList, bool) {
			return value.AsERABToBeSwitchedULList()
		}
		return sealed
	}()
}
func (PathSwitchRequestAcknowledgeIETable) infoERABToBeReleasedList() s00.FieldInfo {
	return s00.FieldInfo{Table: PathSwitchRequestAcknowledgeIEs().ID(), ID: s00.ProtocolIEID(33), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "E-RABList"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "PathSwitchRequestAcknowledgeIEs", Row: "id-E-RABToBeReleasedList"}}}
}

// ERABToBeReleasedList returns the typed binding for the ERABToBeReleasedList row of PathSwitchRequestAcknowledgeIETable.
func (t PathSwitchRequestAcknowledgeIETable) ERABToBeReleasedList() s46.PathSwitchRequestAcknowledgeERABListIEBinding {
	return func() s46.PathSwitchRequestAcknowledgeERABListIEBinding {
		sealed := s46.PathSwitchRequestAcknowledgeERABListIEBinding{}
		*s46.BridgePathSwitchRequestAcknowledgeERABListIEBindingFieldInfo(&sealed) = t.infoERABToBeReleasedList()
		*s46.BridgePathSwitchRequestAcknowledgeERABListIEBindingFieldCodec(&sealed) = func() s16.ERABListValueCodec {
			sealed := s16.ERABListValueCodec{}
			*s16.BridgeERABListValueCodecFieldPath(&sealed) = "ERABList"
			*s16.BridgeERABListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s16.ERABList, error) {
				raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
				if err != nil {
					var empty s16.ERABList
					return empty, err
				}
				raw.BudgetBuffer().EnterComponent("ERABList")
				var zero s46.PathSwitchRequestAcknowledgeIEValue
				decoded, err := s46.BridgePathSwitchRequestAcknowledgeIEValueMethodDecode(zero, s00.ProtocolIEID(33), raw)
				if err != nil {
					var empty s16.ERABList
					return empty, runtime.WrapDecodePath(err, "ERABList")
				}
				value, ok := decoded.AsERABToBeReleasedList()
				if !ok {
					var empty s16.ERABList
					return empty, fmt.Errorf("binding PathSwitchRequestAcknowledgeIEs.id-E-RABToBeReleasedList: no selected value")
				}
				return *value, nil
			}
			*s16.BridgeERABListValueCodecFieldEncode(&sealed) = func(value s16.ERABList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
				return s46.BridgePathSwitchRequestAcknowledgeIEValueMethodEncodeFresh((func() s46.PathSwitchRequestAcknowledgeIEValue {
					sealed := s46.PathSwitchRequestAcknowledgeIEValue{}
					*s46.BridgePathSwitchRequestAcknowledgeIEValueFieldId(&sealed) = s00.ProtocolIEID(33)
					*s46.BridgePathSwitchRequestAcknowledgeIEValueFieldRowERABToBeReleasedList(&sealed) = &value
					return sealed
				}()), fresh, budget)
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
		}()
		*s46.BridgePathSwitchRequestAcknowledgeERABListIEBindingFieldInject(&sealed) = func(value s16.ERABList) s46.PathSwitchRequestAcknowledgeIEValue {
			return func() s46.PathSwitchRequestAcknowledgeIEValue {
				sealed := s46.PathSwitchRequestAcknowledgeIEValue{}
				*s46.BridgePathSwitchRequestAcknowledgeIEValueFieldId(&sealed) = s00.ProtocolIEID(33)
				*s46.BridgePathSwitchRequestAcknowledgeIEValueFieldRowERABToBeReleasedList(&sealed) = &value
				return sealed
			}()
		}
		*s46.BridgePathSwitchRequestAcknowledgeERABListIEBindingFieldGet(&sealed) = func(value *s46.PathSwitchRequestAcknowledgeIEValue) (*s16.ERABList, bool) {
			return value.AsERABToBeReleasedList()
		}
		return sealed
	}()
}
func (PathSwitchRequestAcknowledgeIETable) infoSecurityContext() s00.FieldInfo {
	return s00.FieldInfo{Table: PathSwitchRequestAcknowledgeIEs().ID(), ID: s00.ProtocolIEID(40), Criticality: s00.CriticalityReject, Presence: s00.PresenceMandatory, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "SecurityContext"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "PathSwitchRequestAcknowledgeIEs", Row: "id-SecurityContext"}}}
}

// SecurityContext returns the typed binding for the SecurityContext row of PathSwitchRequestAcknowledgeIETable.
func (t PathSwitchRequestAcknowledgeIETable) SecurityContext() s46.PathSwitchRequestAcknowledgeSecurityContextIEBinding {
	return func() s46.PathSwitchRequestAcknowledgeSecurityContextIEBinding {
		sealed := s46.PathSwitchRequestAcknowledgeSecurityContextIEBinding{}
		*s46.BridgePathSwitchRequestAcknowledgeSecurityContextIEBindingFieldInfo(&sealed) = t.infoSecurityContext()
		*s46.BridgePathSwitchRequestAcknowledgeSecurityContextIEBindingFieldCodec(&sealed) = func() s28.SecurityContextValueCodec {
			sealed := s28.SecurityContextValueCodec{}
			*s28.BridgeSecurityContextValueCodecFieldPath(&sealed) = "SecurityContext"
			*s28.BridgeSecurityContextValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s28.SecurityContext, error) {
				raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
				if err != nil {
					var empty s28.SecurityContext
					return empty, err
				}
				raw.BudgetBuffer().EnterComponent("SecurityContext")
				var zero s46.PathSwitchRequestAcknowledgeIEValue
				decoded, err := s46.BridgePathSwitchRequestAcknowledgeIEValueMethodDecode(zero, s00.ProtocolIEID(40), raw)
				if err != nil {
					var empty s28.SecurityContext
					return empty, runtime.WrapDecodePath(err, "SecurityContext")
				}
				value, ok := decoded.AsSecurityContext()
				if !ok {
					var empty s28.SecurityContext
					return empty, fmt.Errorf("binding PathSwitchRequestAcknowledgeIEs.id-SecurityContext: no selected value")
				}
				return *value, nil
			}
			*s28.BridgeSecurityContextValueCodecFieldEncode(&sealed) = func(value s28.SecurityContext, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
				return s46.BridgePathSwitchRequestAcknowledgeIEValueMethodEncodeFresh((func() s46.PathSwitchRequestAcknowledgeIEValue {
					sealed := s46.PathSwitchRequestAcknowledgeIEValue{}
					*s46.BridgePathSwitchRequestAcknowledgeIEValueFieldId(&sealed) = s00.ProtocolIEID(40)
					*s46.BridgePathSwitchRequestAcknowledgeIEValueFieldRowSecurityContext(&sealed) = &value
					return sealed
				}()), fresh, budget)
			}
			*s28.BridgeSecurityContextValueCodecFieldCapture(&sealed) = func(v s28.SecurityContext, options aper.DecodeState) (s28.SecurityContext, aper.Snapshot) {
				s := aper.SemanticCaptureFor(options)
				f := s.Begin()
				s28.BridgeCaptureS1APSecurityContext(&v, &s)
				var root aper.Snapshot
				s.End(f, &root, false)
				return v, root
			}
			*s28.BridgeSecurityContextValueCodecFieldCompare(&sealed) = func(v s28.SecurityContext, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
				s := aper.NewSemanticComparison(root, budget)
				f := s.Begin()
				s28.BridgeCompareS1APSecurityContext(&v, &s)
				s.End(f, root, false)
				return s.
					Plan(), s.BudgetValue()
			}
			*s28.BridgeSecurityContextValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
				sealed := s00.BridgeCodecContext{}
				*s00.BridgecodecContextFieldSource(&sealed) = "source-value:SecurityContext"
				*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
				return sealed
			}()
			return sealed
		}()
		*s46.BridgePathSwitchRequestAcknowledgeSecurityContextIEBindingFieldInject(&sealed) = func(value s28.SecurityContext) s46.PathSwitchRequestAcknowledgeIEValue {
			return func() s46.PathSwitchRequestAcknowledgeIEValue {
				sealed := s46.PathSwitchRequestAcknowledgeIEValue{}
				*s46.BridgePathSwitchRequestAcknowledgeIEValueFieldId(&sealed) = s00.ProtocolIEID(40)
				*s46.BridgePathSwitchRequestAcknowledgeIEValueFieldRowSecurityContext(&sealed) = &value
				return sealed
			}()
		}
		*s46.BridgePathSwitchRequestAcknowledgeSecurityContextIEBindingFieldGet(&sealed) = func(value *s46.PathSwitchRequestAcknowledgeIEValue) (*s28.SecurityContext, bool) {
			return value.AsSecurityContext()
		}
		return sealed
	}()
}
func (PathSwitchRequestAcknowledgeIETable) infoCriticalityDiagnostics() s00.FieldInfo {
	return s00.FieldInfo{Table: PathSwitchRequestAcknowledgeIEs().ID(), ID: s00.ProtocolIEID(58), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "CriticalityDiagnostics"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "PathSwitchRequestAcknowledgeIEs", Row: "id-CriticalityDiagnostics"}}}
}

// CriticalityDiagnostics returns the typed binding for the CriticalityDiagnostics row of PathSwitchRequestAcknowledgeIETable.
func (t PathSwitchRequestAcknowledgeIETable) CriticalityDiagnostics() s46.PathSwitchRequestAcknowledgeCriticalityDiagnosticsIEBinding {
	return func() s46.PathSwitchRequestAcknowledgeCriticalityDiagnosticsIEBinding {
		sealed := s46.PathSwitchRequestAcknowledgeCriticalityDiagnosticsIEBinding{}
		*s46.BridgePathSwitchRequestAcknowledgeCriticalityDiagnosticsIEBindingFieldInfo(&sealed) = t.infoCriticalityDiagnostics()
		*s46.BridgePathSwitchRequestAcknowledgeCriticalityDiagnosticsIEBindingFieldCodec(&sealed) = func() s22.CriticalityDiagnosticsValueCodec {
			sealed := s22.CriticalityDiagnosticsValueCodec{}
			*s22.BridgeCriticalityDiagnosticsValueCodecFieldPath(&sealed) = "CriticalityDiagnostics"
			*s22.BridgeCriticalityDiagnosticsValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s22.CriticalityDiagnostics, error) {
				raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
				if err != nil {
					var empty s22.CriticalityDiagnostics
					return empty, err
				}
				raw.BudgetBuffer().EnterComponent("CriticalityDiagnostics")
				var zero s46.PathSwitchRequestAcknowledgeIEValue
				decoded, err := s46.BridgePathSwitchRequestAcknowledgeIEValueMethodDecode(zero, s00.ProtocolIEID(58), raw)
				if err != nil {
					var empty s22.CriticalityDiagnostics
					return empty, runtime.WrapDecodePath(err, "CriticalityDiagnostics")
				}
				value, ok := decoded.AsCriticalityDiagnostics()
				if !ok {
					var empty s22.CriticalityDiagnostics
					return empty, fmt.Errorf("binding PathSwitchRequestAcknowledgeIEs.id-CriticalityDiagnostics: no selected value")
				}
				return *value, nil
			}
			*s22.BridgeCriticalityDiagnosticsValueCodecFieldEncode(&sealed) = func(value s22.CriticalityDiagnostics, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
				return s46.BridgePathSwitchRequestAcknowledgeIEValueMethodEncodeFresh((func() s46.PathSwitchRequestAcknowledgeIEValue {
					sealed := s46.PathSwitchRequestAcknowledgeIEValue{}
					*s46.BridgePathSwitchRequestAcknowledgeIEValueFieldId(&sealed) = s00.ProtocolIEID(58)
					*s46.BridgePathSwitchRequestAcknowledgeIEValueFieldRowCriticalityDiagnostics(&sealed) = &value
					return sealed
				}()), fresh, budget)
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
		}()
		*s46.BridgePathSwitchRequestAcknowledgeCriticalityDiagnosticsIEBindingFieldInject(&sealed) = func(value s22.CriticalityDiagnostics) s46.PathSwitchRequestAcknowledgeIEValue {
			return func() s46.PathSwitchRequestAcknowledgeIEValue {
				sealed := s46.PathSwitchRequestAcknowledgeIEValue{}
				*s46.BridgePathSwitchRequestAcknowledgeIEValueFieldId(&sealed) = s00.ProtocolIEID(58)
				*s46.BridgePathSwitchRequestAcknowledgeIEValueFieldRowCriticalityDiagnostics(&sealed) = &value
				return sealed
			}()
		}
		*s46.BridgePathSwitchRequestAcknowledgeCriticalityDiagnosticsIEBindingFieldGet(&sealed) = func(value *s46.PathSwitchRequestAcknowledgeIEValue) (*s22.CriticalityDiagnostics, bool) {
			return value.AsCriticalityDiagnostics()
		}
		return sealed
	}()
}
func (PathSwitchRequestAcknowledgeIETable) infoMMEUES1APID2() s00.FieldInfo {
	return s00.FieldInfo{Table: PathSwitchRequestAcknowledgeIEs().ID(), ID: s00.ProtocolIEID(158), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "MME-UE-S1AP-ID"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "PathSwitchRequestAcknowledgeIEs", Row: "id-MME-UE-S1AP-ID-2"}}}
}

// MMEUES1APID2 returns the typed binding for the MMEUES1APID2 row of PathSwitchRequestAcknowledgeIETable.
func (t PathSwitchRequestAcknowledgeIETable) MMEUES1APID2() s46.PathSwitchRequestAcknowledgeMMEUES1APIDIEBinding {
	return func() s46.PathSwitchRequestAcknowledgeMMEUES1APIDIEBinding {
		sealed := s46.PathSwitchRequestAcknowledgeMMEUES1APIDIEBinding{}
		*s46.BridgePathSwitchRequestAcknowledgeMMEUES1APIDIEBindingFieldInfo(&sealed) = t.infoMMEUES1APID2()
		*s46.BridgePathSwitchRequestAcknowledgeMMEUES1APIDIEBindingFieldCodec(&sealed) = func() s01.MMEUES1APIDValueCodec {
			sealed := s01.MMEUES1APIDValueCodec{}
			*s01.BridgeMMEUES1APIDValueCodecFieldPath(&sealed) = "MMEUES1APID"
			*s01.BridgeMMEUES1APIDValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.MMEUES1APID, error) {
				raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
				if err != nil {
					var empty s00.MMEUES1APID
					return empty, err
				}
				raw.BudgetBuffer().EnterComponent("MMEUES1APID")
				var zero s46.PathSwitchRequestAcknowledgeIEValue
				decoded, err := s46.BridgePathSwitchRequestAcknowledgeIEValueMethodDecode(zero, s00.ProtocolIEID(158), raw)
				if err != nil {
					var empty s00.MMEUES1APID
					return empty, runtime.WrapDecodePath(err, "MMEUES1APID")
				}
				value, ok := decoded.AsMMEUES1APID2()
				if !ok {
					var empty s00.MMEUES1APID
					return empty, fmt.Errorf("binding PathSwitchRequestAcknowledgeIEs.id-MME-UE-S1AP-ID-2: no selected value")
				}
				return *value, nil
			}
			*s01.BridgeMMEUES1APIDValueCodecFieldEncode(&sealed) = func(value s00.MMEUES1APID, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
				return s46.BridgePathSwitchRequestAcknowledgeIEValueMethodEncodeFresh((func() s46.PathSwitchRequestAcknowledgeIEValue {
					sealed := s46.PathSwitchRequestAcknowledgeIEValue{}
					*s46.BridgePathSwitchRequestAcknowledgeIEValueFieldId(&sealed) = s00.ProtocolIEID(158)
					*s46.BridgePathSwitchRequestAcknowledgeIEValueFieldRowMMEUES1APID2(&sealed) = &value
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
		}()
		*s46.BridgePathSwitchRequestAcknowledgeMMEUES1APIDIEBindingFieldInject(&sealed) = func(value s00.MMEUES1APID) s46.PathSwitchRequestAcknowledgeIEValue {
			return func() s46.PathSwitchRequestAcknowledgeIEValue {
				sealed := s46.PathSwitchRequestAcknowledgeIEValue{}
				*s46.BridgePathSwitchRequestAcknowledgeIEValueFieldId(&sealed) = s00.ProtocolIEID(158)
				*s46.BridgePathSwitchRequestAcknowledgeIEValueFieldRowMMEUES1APID2(&sealed) = &value
				return sealed
			}()
		}
		*s46.BridgePathSwitchRequestAcknowledgeMMEUES1APIDIEBindingFieldGet(&sealed) = func(value *s46.PathSwitchRequestAcknowledgeIEValue) (*s00.MMEUES1APID, bool) {
			return value.AsMMEUES1APID2()
		}
		return sealed
	}()
}
func (PathSwitchRequestAcknowledgeIETable) infoCSGMembershipStatus() s00.FieldInfo {
	return s00.FieldInfo{Table: PathSwitchRequestAcknowledgeIEs().ID(), ID: s00.ProtocolIEID(146), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "CSGMembershipStatus"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "PathSwitchRequestAcknowledgeIEs", Row: "id-CSGMembershipStatus"}}}
}

// CSGMembershipStatus returns the typed binding for the CSGMembershipStatus row of PathSwitchRequestAcknowledgeIETable.
func (t PathSwitchRequestAcknowledgeIETable) CSGMembershipStatus() s46.PathSwitchRequestAcknowledgeCSGMembershipStatusIEBinding {
	return func() s46.PathSwitchRequestAcknowledgeCSGMembershipStatusIEBinding {
		sealed := s46.PathSwitchRequestAcknowledgeCSGMembershipStatusIEBinding{}
		*s46.BridgePathSwitchRequestAcknowledgeCSGMembershipStatusIEBindingFieldInfo(&sealed) = t.infoCSGMembershipStatus()
		*s46.BridgePathSwitchRequestAcknowledgeCSGMembershipStatusIEBindingFieldCodec(&sealed) = func() s00.CSGMembershipStatusValueCodec {
			sealed := s00.CSGMembershipStatusValueCodec{}
			*s00.BridgeCSGMembershipStatusValueCodecFieldPath(&sealed) = "CSGMembershipStatus"
			*s00.BridgeCSGMembershipStatusValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.CSGMembershipStatus, error) {
				raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
				if err != nil {
					var empty s00.CSGMembershipStatus
					return empty, err
				}
				raw.BudgetBuffer().EnterComponent("CSGMembershipStatus")
				var zero s46.PathSwitchRequestAcknowledgeIEValue
				decoded, err := s46.BridgePathSwitchRequestAcknowledgeIEValueMethodDecode(zero, s00.ProtocolIEID(146), raw)
				if err != nil {
					var empty s00.CSGMembershipStatus
					return empty, runtime.WrapDecodePath(err, "CSGMembershipStatus")
				}
				value, ok := decoded.AsCSGMembershipStatus()
				if !ok {
					var empty s00.CSGMembershipStatus
					return empty, fmt.Errorf("binding PathSwitchRequestAcknowledgeIEs.id-CSGMembershipStatus: no selected value")
				}
				return *value, nil
			}
			*s00.BridgeCSGMembershipStatusValueCodecFieldEncode(&sealed) = func(value s00.CSGMembershipStatus, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
				return s46.BridgePathSwitchRequestAcknowledgeIEValueMethodEncodeFresh((func() s46.PathSwitchRequestAcknowledgeIEValue {
					sealed := s46.PathSwitchRequestAcknowledgeIEValue{}
					*s46.BridgePathSwitchRequestAcknowledgeIEValueFieldId(&sealed) = s00.ProtocolIEID(146)
					*s46.BridgePathSwitchRequestAcknowledgeIEValueFieldRowCSGMembershipStatus(&sealed) = &value
					return sealed
				}()), fresh, budget)
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
		}()
		*s46.BridgePathSwitchRequestAcknowledgeCSGMembershipStatusIEBindingFieldInject(&sealed) = func(value s00.CSGMembershipStatus) s46.PathSwitchRequestAcknowledgeIEValue {
			return func() s46.PathSwitchRequestAcknowledgeIEValue {
				sealed := s46.PathSwitchRequestAcknowledgeIEValue{}
				*s46.BridgePathSwitchRequestAcknowledgeIEValueFieldId(&sealed) = s00.ProtocolIEID(146)
				*s46.BridgePathSwitchRequestAcknowledgeIEValueFieldRowCSGMembershipStatus(&sealed) = &value
				return sealed
			}()
		}
		*s46.BridgePathSwitchRequestAcknowledgeCSGMembershipStatusIEBindingFieldGet(&sealed) = func(value *s46.PathSwitchRequestAcknowledgeIEValue) (*s00.CSGMembershipStatus, bool) {
			return value.AsCSGMembershipStatus()
		}
		return sealed
	}()
}
func (PathSwitchRequestAcknowledgeIETable) infoProSeAuthorized() s00.FieldInfo {
	return s00.FieldInfo{Table: PathSwitchRequestAcknowledgeIEs().ID(), ID: s00.ProtocolIEID(195), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "ProSeAuthorized"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "PathSwitchRequestAcknowledgeIEs", Row: "id-ProSeAuthorized"}}}
}

// ProSeAuthorized returns the typed binding for the ProSeAuthorized row of PathSwitchRequestAcknowledgeIETable.
func (t PathSwitchRequestAcknowledgeIETable) ProSeAuthorized() s46.PathSwitchRequestAcknowledgeProSeAuthorizedIEBinding {
	return func() s46.PathSwitchRequestAcknowledgeProSeAuthorizedIEBinding {
		sealed := s46.PathSwitchRequestAcknowledgeProSeAuthorizedIEBinding{}
		*s46.BridgePathSwitchRequestAcknowledgeProSeAuthorizedIEBindingFieldInfo(&sealed) = t.infoProSeAuthorized()
		*s46.BridgePathSwitchRequestAcknowledgeProSeAuthorizedIEBindingFieldCodec(&sealed) = func() s20.ProSeAuthorizedValueCodec {
			sealed := s20.ProSeAuthorizedValueCodec{}
			*s20.BridgeProSeAuthorizedValueCodecFieldPath(&sealed) = "ProSeAuthorized"
			*s20.BridgeProSeAuthorizedValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s20.ProSeAuthorized, error) {
				raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
				if err != nil {
					var empty s20.ProSeAuthorized
					return empty, err
				}
				raw.BudgetBuffer().EnterComponent("ProSeAuthorized")
				var zero s46.PathSwitchRequestAcknowledgeIEValue
				decoded, err := s46.BridgePathSwitchRequestAcknowledgeIEValueMethodDecode(zero, s00.ProtocolIEID(195), raw)
				if err != nil {
					var empty s20.ProSeAuthorized
					return empty, runtime.WrapDecodePath(err, "ProSeAuthorized")
				}
				value, ok := decoded.AsProSeAuthorized()
				if !ok {
					var empty s20.ProSeAuthorized
					return empty, fmt.Errorf("binding PathSwitchRequestAcknowledgeIEs.id-ProSeAuthorized: no selected value")
				}
				return *value, nil
			}
			*s20.BridgeProSeAuthorizedValueCodecFieldEncode(&sealed) = func(value s20.ProSeAuthorized, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
				return s46.BridgePathSwitchRequestAcknowledgeIEValueMethodEncodeFresh((func() s46.PathSwitchRequestAcknowledgeIEValue {
					sealed := s46.PathSwitchRequestAcknowledgeIEValue{}
					*s46.BridgePathSwitchRequestAcknowledgeIEValueFieldId(&sealed) = s00.ProtocolIEID(195)
					*s46.BridgePathSwitchRequestAcknowledgeIEValueFieldRowProSeAuthorized(&sealed) = &value
					return sealed
				}()), fresh, budget)
			}
			*s20.BridgeProSeAuthorizedValueCodecFieldCapture(&sealed) = func(v s20.ProSeAuthorized, options aper.DecodeState) (s20.ProSeAuthorized, aper.Snapshot) {
				s := aper.SemanticCaptureFor(options)
				f := s.Begin()
				s20.BridgeCaptureS1APProSeAuthorized(&v, &s)
				var root aper.Snapshot
				s.End(f, &root, false)
				return v, root
			}
			*s20.BridgeProSeAuthorizedValueCodecFieldCompare(&sealed) = func(v s20.ProSeAuthorized, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
				s := aper.NewSemanticComparison(root, budget)
				f := s.Begin()
				s20.BridgeCompareS1APProSeAuthorized(&v, &s)
				s.End(f, root, false)
				return s.
					Plan(), s.BudgetValue()
			}
			*s20.BridgeProSeAuthorizedValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
				sealed := s00.BridgeCodecContext{}
				*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProSeAuthorized"
				*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
				return sealed
			}()
			return sealed
		}()
		*s46.BridgePathSwitchRequestAcknowledgeProSeAuthorizedIEBindingFieldInject(&sealed) = func(value s20.ProSeAuthorized) s46.PathSwitchRequestAcknowledgeIEValue {
			return func() s46.PathSwitchRequestAcknowledgeIEValue {
				sealed := s46.PathSwitchRequestAcknowledgeIEValue{}
				*s46.BridgePathSwitchRequestAcknowledgeIEValueFieldId(&sealed) = s00.ProtocolIEID(195)
				*s46.BridgePathSwitchRequestAcknowledgeIEValueFieldRowProSeAuthorized(&sealed) = &value
				return sealed
			}()
		}
		*s46.BridgePathSwitchRequestAcknowledgeProSeAuthorizedIEBindingFieldGet(&sealed) = func(value *s46.PathSwitchRequestAcknowledgeIEValue) (*s20.ProSeAuthorized, bool) {
			return value.AsProSeAuthorized()
		}
		return sealed
	}()
}
func (PathSwitchRequestAcknowledgeIETable) infoUEUserPlaneCIoTSupportIndicator() s00.FieldInfo {
	return s00.FieldInfo{Table: PathSwitchRequestAcknowledgeIEs().ID(), ID: s00.ProtocolIEID(241), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "UEUserPlaneCIoTSupportIndicator"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "PathSwitchRequestAcknowledgeIEs", Row: "id-UEUserPlaneCIoTSupportIndicator"}}}
}

// UEUserPlaneCIoTSupportIndicator returns the typed binding for the UEUserPlaneCIoTSupportIndicator row of PathSwitchRequestAcknowledgeIETable.
func (t PathSwitchRequestAcknowledgeIETable) UEUserPlaneCIoTSupportIndicator() s46.PathSwitchRequestAcknowledgeUEUserPlaneCIoTSupportIndicatorIEBinding {
	return func() s46.PathSwitchRequestAcknowledgeUEUserPlaneCIoTSupportIndicatorIEBinding {
		sealed := s46.PathSwitchRequestAcknowledgeUEUserPlaneCIoTSupportIndicatorIEBinding{}
		*s46.BridgePathSwitchRequestAcknowledgeUEUserPlaneCIoTSupportIndicatorIEBindingFieldInfo(&sealed) = t.infoUEUserPlaneCIoTSupportIndicator()
		*s46.BridgePathSwitchRequestAcknowledgeUEUserPlaneCIoTSupportIndicatorIEBindingFieldCodec(&sealed) = func() s02.UEUserPlaneCIoTSupportIndicatorValueCodec {
			sealed := s02.UEUserPlaneCIoTSupportIndicatorValueCodec{}
			*s02.BridgeUEUserPlaneCIoTSupportIndicatorValueCodecFieldPath(&sealed) = "UEUserPlaneCIoTSupportIndicator"
			*s02.BridgeUEUserPlaneCIoTSupportIndicatorValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.UEUserPlaneCIoTSupportIndicator, error) {
				raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
				if err != nil {
					var empty s00.UEUserPlaneCIoTSupportIndicator
					return empty, err
				}
				raw.BudgetBuffer().EnterComponent("UEUserPlaneCIoTSupportIndicator")
				var zero s46.PathSwitchRequestAcknowledgeIEValue
				decoded, err := s46.BridgePathSwitchRequestAcknowledgeIEValueMethodDecode(zero, s00.ProtocolIEID(241), raw)
				if err != nil {
					var empty s00.UEUserPlaneCIoTSupportIndicator
					return empty, runtime.WrapDecodePath(err, "UEUserPlaneCIoTSupportIndicator")
				}
				value, ok := decoded.AsUEUserPlaneCIoTSupportIndicator()
				if !ok {
					var empty s00.UEUserPlaneCIoTSupportIndicator
					return empty, fmt.Errorf("binding PathSwitchRequestAcknowledgeIEs.id-UEUserPlaneCIoTSupportIndicator: no selected value")
				}
				return *value, nil
			}
			*s02.BridgeUEUserPlaneCIoTSupportIndicatorValueCodecFieldEncode(&sealed) = func(value s00.UEUserPlaneCIoTSupportIndicator, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
				return s46.BridgePathSwitchRequestAcknowledgeIEValueMethodEncodeFresh((func() s46.PathSwitchRequestAcknowledgeIEValue {
					sealed := s46.PathSwitchRequestAcknowledgeIEValue{}
					*s46.BridgePathSwitchRequestAcknowledgeIEValueFieldId(&sealed) = s00.ProtocolIEID(241)
					*s46.BridgePathSwitchRequestAcknowledgeIEValueFieldRowUEUserPlaneCIoTSupportIndicator(&sealed) = &value
					return sealed
				}()), fresh, budget)
			}
			*s02.BridgeUEUserPlaneCIoTSupportIndicatorValueCodecFieldCapture(&sealed) = func(v s00.UEUserPlaneCIoTSupportIndicator, options aper.DecodeState) (s00.UEUserPlaneCIoTSupportIndicator, aper.Snapshot,
			) {
				s := aper.SemanticCaptureFor(options)
				f := s.Begin()
				s00.BridgeCaptureS1APUEUserPlaneCIoTSupportIndicator(&v, &s)
				var root aper.Snapshot

				s.End(f, &root, false)
				return v, root
			}
			*s02.BridgeUEUserPlaneCIoTSupportIndicatorValueCodecFieldCompare(&sealed) = func(v s00.UEUserPlaneCIoTSupportIndicator, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
			) {
				s := aper.NewSemanticComparison(root, budget)
				f := s.Begin()
				s07.BridgeCompareS1APUEUserPlaneCIoTSupportIndicator(&v, &s)

				s.End(f, root, false)
				return s.Plan(), s.BudgetValue()
			}
			*s02.BridgeUEUserPlaneCIoTSupportIndicatorValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
				sealed := s00.BridgeCodecContext{}
				*s00.BridgecodecContextFieldSource(&sealed) = "source-value:UEUserPlaneCIoTSupportIndicator"
				*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
				return sealed
			}()
			return sealed
		}()
		*s46.BridgePathSwitchRequestAcknowledgeUEUserPlaneCIoTSupportIndicatorIEBindingFieldInject(&sealed) = func(value s00.UEUserPlaneCIoTSupportIndicator) s46.PathSwitchRequestAcknowledgeIEValue {
			return func() s46.PathSwitchRequestAcknowledgeIEValue {
				sealed := s46.PathSwitchRequestAcknowledgeIEValue{}
				*s46.BridgePathSwitchRequestAcknowledgeIEValueFieldId(&sealed) = s00.ProtocolIEID(241)
				*s46.BridgePathSwitchRequestAcknowledgeIEValueFieldRowUEUserPlaneCIoTSupportIndicator(&sealed) = &value
				return sealed
			}()
		}
		*s46.BridgePathSwitchRequestAcknowledgeUEUserPlaneCIoTSupportIndicatorIEBindingFieldGet(&sealed) = func(value *s46.PathSwitchRequestAcknowledgeIEValue) (*s00.UEUserPlaneCIoTSupportIndicator, bool) {
			return value.AsUEUserPlaneCIoTSupportIndicator()
		}
		return sealed
	}()
}
func (PathSwitchRequestAcknowledgeIETable) infoV2XServicesAuthorized() s00.FieldInfo {
	return s00.FieldInfo{Table: PathSwitchRequestAcknowledgeIEs().ID(), ID: s00.ProtocolIEID(240), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "V2XServicesAuthorized"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "PathSwitchRequestAcknowledgeIEs", Row: "id-V2XServicesAuthorized"}}}
}

// V2XServicesAuthorized returns the typed binding for the V2XServicesAuthorized row of PathSwitchRequestAcknowledgeIETable.
func (t PathSwitchRequestAcknowledgeIETable) V2XServicesAuthorized() s46.PathSwitchRequestAcknowledgeV2XServicesAuthorizedIEBinding {
	return func() s46.PathSwitchRequestAcknowledgeV2XServicesAuthorizedIEBinding {
		sealed := s46.PathSwitchRequestAcknowledgeV2XServicesAuthorizedIEBinding{}
		*s46.BridgePathSwitchRequestAcknowledgeV2XServicesAuthorizedIEBindingFieldInfo(&sealed) = t.infoV2XServicesAuthorized()
		*s46.BridgePathSwitchRequestAcknowledgeV2XServicesAuthorizedIEBindingFieldCodec(&sealed) = func() s46.V2XServicesAuthorizedValueCodec {
			sealed := s46.V2XServicesAuthorizedValueCodec{}
			*s46.BridgeV2XServicesAuthorizedValueCodecFieldPath(&sealed) = "V2XServicesAuthorized"
			*s46.BridgeV2XServicesAuthorizedValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s46.V2XServicesAuthorized, error) {
				raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
				if err != nil {
					var empty s46.V2XServicesAuthorized
					return empty, err
				}
				raw.BudgetBuffer().EnterComponent("V2XServicesAuthorized")
				var zero s46.PathSwitchRequestAcknowledgeIEValue
				decoded, err := s46.BridgePathSwitchRequestAcknowledgeIEValueMethodDecode(zero, s00.ProtocolIEID(240), raw)
				if err != nil {
					var empty s46.V2XServicesAuthorized
					return empty, runtime.WrapDecodePath(err, "V2XServicesAuthorized")
				}
				value, ok := decoded.AsV2XServicesAuthorized()
				if !ok {
					var empty s46.V2XServicesAuthorized
					return empty, fmt.Errorf("binding PathSwitchRequestAcknowledgeIEs.id-V2XServicesAuthorized: no selected value")
				}
				return *value, nil
			}
			*s46.BridgeV2XServicesAuthorizedValueCodecFieldEncode(&sealed) = func(value s46.V2XServicesAuthorized, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
				return s46.BridgePathSwitchRequestAcknowledgeIEValueMethodEncodeFresh((func() s46.PathSwitchRequestAcknowledgeIEValue {
					sealed := s46.PathSwitchRequestAcknowledgeIEValue{}
					*s46.BridgePathSwitchRequestAcknowledgeIEValueFieldId(&sealed) = s00.ProtocolIEID(240)
					*s46.BridgePathSwitchRequestAcknowledgeIEValueFieldRowV2XServicesAuthorized(&sealed) = &value
					return sealed
				}()), fresh, budget)
			}
			*s46.BridgeV2XServicesAuthorizedValueCodecFieldCapture(&sealed) = func(v s46.V2XServicesAuthorized, options aper.DecodeState) (s46.V2XServicesAuthorized, aper.Snapshot,
			) {
				s := aper.SemanticCaptureFor(options)
				f := s.Begin()
				s46.BridgeCaptureS1APV2XServicesAuthorized(&v, &s)
				var root aper.Snapshot
				s.End(f, &root, false)

				return v, root
			}
			*s46.BridgeV2XServicesAuthorizedValueCodecFieldCompare(&sealed) = func(v s46.V2XServicesAuthorized, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

			) {
				s := aper.NewSemanticComparison(root, budget)
				f := s.Begin()
				s46.BridgeCompareS1APV2XServicesAuthorized(&v, &s)
				s.End(f, root, false)

				return s.Plan(), s.BudgetValue()
			}
			*s46.BridgeV2XServicesAuthorizedValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
				sealed := s00.BridgeCodecContext{}
				*s00.BridgecodecContextFieldSource(&sealed) = "source-value:V2XServicesAuthorized"
				*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
				return sealed
			}()
			return sealed
		}()
		*s46.BridgePathSwitchRequestAcknowledgeV2XServicesAuthorizedIEBindingFieldInject(&sealed) = func(value s46.V2XServicesAuthorized) s46.PathSwitchRequestAcknowledgeIEValue {
			return func() s46.PathSwitchRequestAcknowledgeIEValue {
				sealed := s46.PathSwitchRequestAcknowledgeIEValue{}
				*s46.BridgePathSwitchRequestAcknowledgeIEValueFieldId(&sealed) = s00.ProtocolIEID(240)
				*s46.BridgePathSwitchRequestAcknowledgeIEValueFieldRowV2XServicesAuthorized(&sealed) = &value
				return sealed
			}()
		}
		*s46.BridgePathSwitchRequestAcknowledgeV2XServicesAuthorizedIEBindingFieldGet(&sealed) = func(value *s46.PathSwitchRequestAcknowledgeIEValue) (*s46.V2XServicesAuthorized, bool) {
			return value.AsV2XServicesAuthorized()
		}
		return sealed
	}()
}
func (PathSwitchRequestAcknowledgeIETable) infoUESidelinkAggregateMaximumBitrate() s00.FieldInfo {
	return s00.FieldInfo{Table: PathSwitchRequestAcknowledgeIEs().ID(), ID: s00.ProtocolIEID(248), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "UESidelinkAggregateMaximumBitrate"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "PathSwitchRequestAcknowledgeIEs", Row: "id-UESidelinkAggregateMaximumBitrate"}}}
}

// UESidelinkAggregateMaximumBitrate returns the typed binding for the UESidelinkAggregateMaximumBitrate row of PathSwitchRequestAcknowledgeIETable.
func (t PathSwitchRequestAcknowledgeIETable) UESidelinkAggregateMaximumBitrate() s46.PathSwitchRequestAcknowledgeUESidelinkAggregateMaximumBitrateIEBinding {
	return func() s46.PathSwitchRequestAcknowledgeUESidelinkAggregateMaximumBitrateIEBinding {
		sealed := s46.PathSwitchRequestAcknowledgeUESidelinkAggregateMaximumBitrateIEBinding{}
		*s46.BridgePathSwitchRequestAcknowledgeUESidelinkAggregateMaximumBitrateIEBindingFieldInfo(&sealed) = t.infoUESidelinkAggregateMaximumBitrate()
		*s46.BridgePathSwitchRequestAcknowledgeUESidelinkAggregateMaximumBitrateIEBindingFieldCodec(&sealed) = func() s37.UESidelinkAggregateMaximumBitrateValueCodec {
			sealed := s37.UESidelinkAggregateMaximumBitrateValueCodec{}
			*s37.BridgeUESidelinkAggregateMaximumBitrateValueCodecFieldPath(&sealed) = "UESidelinkAggregateMaximumBitrate"
			*s37.BridgeUESidelinkAggregateMaximumBitrateValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s37.UESidelinkAggregateMaximumBitrate, error) {
				raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
				if err != nil {
					var empty s37.UESidelinkAggregateMaximumBitrate
					return empty, err
				}
				raw.BudgetBuffer().EnterComponent("UESidelinkAggregateMaximumBitrate")
				var zero s46.PathSwitchRequestAcknowledgeIEValue
				decoded, err := s46.BridgePathSwitchRequestAcknowledgeIEValueMethodDecode(zero, s00.ProtocolIEID(248), raw)
				if err != nil {
					var empty s37.UESidelinkAggregateMaximumBitrate
					return empty, runtime.WrapDecodePath(err, "UESidelinkAggregateMaximumBitrate")
				}
				value, ok := decoded.AsUESidelinkAggregateMaximumBitrate()
				if !ok {
					var empty s37.UESidelinkAggregateMaximumBitrate
					return empty, fmt.Errorf("binding PathSwitchRequestAcknowledgeIEs.id-UESidelinkAggregateMaximumBitrate: no selected value")
				}
				return *value, nil
			}
			*s37.BridgeUESidelinkAggregateMaximumBitrateValueCodecFieldEncode(&sealed) = func(value s37.UESidelinkAggregateMaximumBitrate, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
				return s46.BridgePathSwitchRequestAcknowledgeIEValueMethodEncodeFresh((func() s46.PathSwitchRequestAcknowledgeIEValue {
					sealed := s46.PathSwitchRequestAcknowledgeIEValue{}
					*s46.BridgePathSwitchRequestAcknowledgeIEValueFieldId(&sealed) = s00.ProtocolIEID(248)
					*s46.BridgePathSwitchRequestAcknowledgeIEValueFieldRowUESidelinkAggregateMaximumBitrate(&sealed) = &value
					return sealed
				}()), fresh, budget)
			}
			*s37.BridgeUESidelinkAggregateMaximumBitrateValueCodecFieldCapture(&sealed) = func(v s37.UESidelinkAggregateMaximumBitrate, options aper.DecodeState) (s37.UESidelinkAggregateMaximumBitrate, aper.Snapshot,
			) {
				s := aper.SemanticCaptureFor(options)
				f := s.Begin()
				s37.BridgeCaptureS1APUESidelinkAggregateMaximumBitrate(&v, &s)
				var root aper.Snapshot
				s.End(f, &root, false)
				return v, root
			}
			*s37.BridgeUESidelinkAggregateMaximumBitrateValueCodecFieldCompare(&sealed) = func(v s37.UESidelinkAggregateMaximumBitrate, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

			) {
				s := aper.NewSemanticComparison(root, budget)
				f := s.Begin()
				s37.BridgeCompareS1APUESidelinkAggregateMaximumBitrate(
					&v,

					&s)
				s.End(f, root, false)
				return s.Plan(), s.BudgetValue()
			}
			*s37.BridgeUESidelinkAggregateMaximumBitrateValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
				sealed := s00.BridgeCodecContext{}
				*s00.BridgecodecContextFieldSource(&sealed) = "source-value:UESidelinkAggregateMaximumBitrate"
				*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
				return sealed
			}()
			return sealed
		}()
		*s46.BridgePathSwitchRequestAcknowledgeUESidelinkAggregateMaximumBitrateIEBindingFieldInject(&sealed) = func(value s37.UESidelinkAggregateMaximumBitrate) s46.PathSwitchRequestAcknowledgeIEValue {
			return func() s46.PathSwitchRequestAcknowledgeIEValue {
				sealed := s46.PathSwitchRequestAcknowledgeIEValue{}
				*s46.BridgePathSwitchRequestAcknowledgeIEValueFieldId(&sealed) = s00.ProtocolIEID(248)
				*s46.BridgePathSwitchRequestAcknowledgeIEValueFieldRowUESidelinkAggregateMaximumBitrate(&sealed) = &value
				return sealed
			}()
		}
		*s46.BridgePathSwitchRequestAcknowledgeUESidelinkAggregateMaximumBitrateIEBindingFieldGet(&sealed) = func(value *s46.PathSwitchRequestAcknowledgeIEValue) (*s37.UESidelinkAggregateMaximumBitrate, bool) {
			return value.AsUESidelinkAggregateMaximumBitrate()
		}
		return sealed
	}()
}
func (PathSwitchRequestAcknowledgeIETable) infoEnhancedCoverageRestricted() s00.FieldInfo {
	return s00.FieldInfo{Table: PathSwitchRequestAcknowledgeIEs().ID(), ID: s00.ProtocolIEID(251), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "EnhancedCoverageRestricted"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "PathSwitchRequestAcknowledgeIEs", Row: "id-EnhancedCoverageRestricted"}}}
}

// EnhancedCoverageRestricted returns the typed binding for the EnhancedCoverageRestricted row of PathSwitchRequestAcknowledgeIETable.
func (t PathSwitchRequestAcknowledgeIETable) EnhancedCoverageRestricted() s46.PathSwitchRequestAcknowledgeEnhancedCoverageRestrictedIEBinding {
	return func() s46.PathSwitchRequestAcknowledgeEnhancedCoverageRestrictedIEBinding {
		sealed := s46.PathSwitchRequestAcknowledgeEnhancedCoverageRestrictedIEBinding{}
		*s46.BridgePathSwitchRequestAcknowledgeEnhancedCoverageRestrictedIEBindingFieldInfo(&sealed) = t.infoEnhancedCoverageRestricted()
		*s46.BridgePathSwitchRequestAcknowledgeEnhancedCoverageRestrictedIEBindingFieldCodec(&sealed) = func() s00.EnhancedCoverageRestrictedValueCodec {
			sealed := s00.EnhancedCoverageRestrictedValueCodec{}
			*s00.BridgeEnhancedCoverageRestrictedValueCodecFieldPath(&sealed) = "EnhancedCoverageRestricted"
			*s00.BridgeEnhancedCoverageRestrictedValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.EnhancedCoverageRestricted, error) {
				raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
				if err != nil {
					var empty s00.EnhancedCoverageRestricted
					return empty, err
				}
				raw.BudgetBuffer().EnterComponent("EnhancedCoverageRestricted")
				var zero s46.PathSwitchRequestAcknowledgeIEValue
				decoded, err := s46.BridgePathSwitchRequestAcknowledgeIEValueMethodDecode(zero, s00.ProtocolIEID(251), raw)
				if err != nil {
					var empty s00.EnhancedCoverageRestricted
					return empty, runtime.WrapDecodePath(err, "EnhancedCoverageRestricted")
				}
				value, ok := decoded.AsEnhancedCoverageRestricted()
				if !ok {
					var empty s00.EnhancedCoverageRestricted
					return empty, fmt.Errorf("binding PathSwitchRequestAcknowledgeIEs.id-EnhancedCoverageRestricted: no selected value")
				}
				return *value, nil
			}
			*s00.BridgeEnhancedCoverageRestrictedValueCodecFieldEncode(&sealed) = func(value s00.EnhancedCoverageRestricted, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
				return s46.BridgePathSwitchRequestAcknowledgeIEValueMethodEncodeFresh((func() s46.PathSwitchRequestAcknowledgeIEValue {
					sealed := s46.PathSwitchRequestAcknowledgeIEValue{}
					*s46.BridgePathSwitchRequestAcknowledgeIEValueFieldId(&sealed) = s00.ProtocolIEID(251)
					*s46.BridgePathSwitchRequestAcknowledgeIEValueFieldRowEnhancedCoverageRestricted(&sealed) = &value
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
		*s46.BridgePathSwitchRequestAcknowledgeEnhancedCoverageRestrictedIEBindingFieldInject(&sealed) = func(value s00.EnhancedCoverageRestricted) s46.PathSwitchRequestAcknowledgeIEValue {
			return func() s46.PathSwitchRequestAcknowledgeIEValue {
				sealed := s46.PathSwitchRequestAcknowledgeIEValue{}
				*s46.BridgePathSwitchRequestAcknowledgeIEValueFieldId(&sealed) = s00.ProtocolIEID(251)
				*s46.BridgePathSwitchRequestAcknowledgeIEValueFieldRowEnhancedCoverageRestricted(&sealed) = &value
				return sealed
			}()
		}
		*s46.BridgePathSwitchRequestAcknowledgeEnhancedCoverageRestrictedIEBindingFieldGet(&sealed) = func(value *s46.PathSwitchRequestAcknowledgeIEValue) (*s00.EnhancedCoverageRestricted, bool) {
			return value.AsEnhancedCoverageRestricted()
		}
		return sealed
	}()
}
func (PathSwitchRequestAcknowledgeIETable) infoNRUESecurityCapabilities() s00.FieldInfo {
	return s00.FieldInfo{Table: PathSwitchRequestAcknowledgeIEs().ID(), ID: s00.ProtocolIEID(269), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "NRUESecurityCapabilities"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "PathSwitchRequestAcknowledgeIEs", Row: "id-NRUESecurityCapabilities"}}}
}

// NRUESecurityCapabilities returns the typed binding for the NRUESecurityCapabilities row of PathSwitchRequestAcknowledgeIETable.
func (t PathSwitchRequestAcknowledgeIETable) NRUESecurityCapabilities() s46.PathSwitchRequestAcknowledgeNRUESecurityCapabilitiesIEBinding {
	return func() s46.PathSwitchRequestAcknowledgeNRUESecurityCapabilitiesIEBinding {
		sealed := s46.PathSwitchRequestAcknowledgeNRUESecurityCapabilitiesIEBinding{}
		*s46.BridgePathSwitchRequestAcknowledgeNRUESecurityCapabilitiesIEBindingFieldInfo(&sealed) = t.infoNRUESecurityCapabilities()
		*s46.BridgePathSwitchRequestAcknowledgeNRUESecurityCapabilitiesIEBindingFieldCodec(&sealed) = func() s19.NRUESecurityCapabilitiesValueCodec {
			sealed := s19.NRUESecurityCapabilitiesValueCodec{}
			*s19.BridgeNRUESecurityCapabilitiesValueCodecFieldPath(&sealed) = "NRUESecurityCapabilities"
			*s19.BridgeNRUESecurityCapabilitiesValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s19.NRUESecurityCapabilities, error) {
				raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
				if err != nil {
					var empty s19.NRUESecurityCapabilities
					return empty, err
				}
				raw.BudgetBuffer().EnterComponent("NRUESecurityCapabilities")
				var zero s46.PathSwitchRequestAcknowledgeIEValue
				decoded, err := s46.BridgePathSwitchRequestAcknowledgeIEValueMethodDecode(zero, s00.ProtocolIEID(269), raw)
				if err != nil {
					var empty s19.NRUESecurityCapabilities
					return empty, runtime.WrapDecodePath(err, "NRUESecurityCapabilities")
				}
				value, ok := decoded.AsNRUESecurityCapabilities()
				if !ok {
					var empty s19.NRUESecurityCapabilities
					return empty, fmt.Errorf("binding PathSwitchRequestAcknowledgeIEs.id-NRUESecurityCapabilities: no selected value")
				}
				return *value, nil
			}
			*s19.BridgeNRUESecurityCapabilitiesValueCodecFieldEncode(&sealed) = func(value s19.NRUESecurityCapabilities, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
				return s46.BridgePathSwitchRequestAcknowledgeIEValueMethodEncodeFresh((func() s46.PathSwitchRequestAcknowledgeIEValue {
					sealed := s46.PathSwitchRequestAcknowledgeIEValue{}
					*s46.BridgePathSwitchRequestAcknowledgeIEValueFieldId(&sealed) = s00.ProtocolIEID(269)
					*s46.BridgePathSwitchRequestAcknowledgeIEValueFieldRowNRUESecurityCapabilities(&sealed) = &value
					return sealed
				}()), fresh, budget)
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
		}()
		*s46.BridgePathSwitchRequestAcknowledgeNRUESecurityCapabilitiesIEBindingFieldInject(&sealed) = func(value s19.NRUESecurityCapabilities) s46.PathSwitchRequestAcknowledgeIEValue {
			return func() s46.PathSwitchRequestAcknowledgeIEValue {
				sealed := s46.PathSwitchRequestAcknowledgeIEValue{}
				*s46.BridgePathSwitchRequestAcknowledgeIEValueFieldId(&sealed) = s00.ProtocolIEID(269)
				*s46.BridgePathSwitchRequestAcknowledgeIEValueFieldRowNRUESecurityCapabilities(&sealed) = &value
				return sealed
			}()
		}
		*s46.BridgePathSwitchRequestAcknowledgeNRUESecurityCapabilitiesIEBindingFieldGet(&sealed) = func(value *s46.PathSwitchRequestAcknowledgeIEValue) (*s19.NRUESecurityCapabilities, bool) {
			return value.AsNRUESecurityCapabilities()
		}
		return sealed
	}()
}
func (PathSwitchRequestAcknowledgeIETable) infoCEModeBRestricted() s00.FieldInfo {
	return s00.FieldInfo{Table: PathSwitchRequestAcknowledgeIEs().ID(), ID: s00.ProtocolIEID(271), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "CE-ModeBRestricted"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "PathSwitchRequestAcknowledgeIEs", Row: "id-CE-ModeBRestricted"}}}
}

// CEModeBRestricted returns the typed binding for the CEModeBRestricted row of PathSwitchRequestAcknowledgeIETable.
func (t PathSwitchRequestAcknowledgeIETable) CEModeBRestricted() s46.PathSwitchRequestAcknowledgeCEModeBRestrictedIEBinding {
	return func() s46.PathSwitchRequestAcknowledgeCEModeBRestrictedIEBinding {
		sealed := s46.PathSwitchRequestAcknowledgeCEModeBRestrictedIEBinding{}
		*s46.BridgePathSwitchRequestAcknowledgeCEModeBRestrictedIEBindingFieldInfo(&sealed) = t.infoCEModeBRestricted()
		*s46.BridgePathSwitchRequestAcknowledgeCEModeBRestrictedIEBindingFieldCodec(&sealed) = func() s00.CEModeBRestrictedValueCodec {
			sealed := s00.CEModeBRestrictedValueCodec{}
			*s00.BridgeCEModeBRestrictedValueCodecFieldPath(&sealed) = "CEModeBRestricted"
			*s00.BridgeCEModeBRestrictedValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.CEModeBRestricted, error) {
				raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
				if err != nil {
					var empty s00.CEModeBRestricted
					return empty, err
				}
				raw.BudgetBuffer().EnterComponent("CEModeBRestricted")
				var zero s46.PathSwitchRequestAcknowledgeIEValue
				decoded, err := s46.BridgePathSwitchRequestAcknowledgeIEValueMethodDecode(zero, s00.ProtocolIEID(271), raw)
				if err != nil {
					var empty s00.CEModeBRestricted
					return empty, runtime.WrapDecodePath(err, "CEModeBRestricted")
				}
				value, ok := decoded.AsCEModeBRestricted()
				if !ok {
					var empty s00.CEModeBRestricted
					return empty, fmt.Errorf("binding PathSwitchRequestAcknowledgeIEs.id-CE-ModeBRestricted: no selected value")
				}
				return *value, nil
			}
			*s00.BridgeCEModeBRestrictedValueCodecFieldEncode(&sealed) = func(value s00.CEModeBRestricted, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
				return s46.BridgePathSwitchRequestAcknowledgeIEValueMethodEncodeFresh((func() s46.PathSwitchRequestAcknowledgeIEValue {
					sealed := s46.PathSwitchRequestAcknowledgeIEValue{}
					*s46.BridgePathSwitchRequestAcknowledgeIEValueFieldId(&sealed) = s00.ProtocolIEID(271)
					*s46.BridgePathSwitchRequestAcknowledgeIEValueFieldRowCEModeBRestricted(&sealed) = &value
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
		*s46.BridgePathSwitchRequestAcknowledgeCEModeBRestrictedIEBindingFieldInject(&sealed) = func(value s00.CEModeBRestricted) s46.PathSwitchRequestAcknowledgeIEValue {
			return func() s46.PathSwitchRequestAcknowledgeIEValue {
				sealed := s46.PathSwitchRequestAcknowledgeIEValue{}
				*s46.BridgePathSwitchRequestAcknowledgeIEValueFieldId(&sealed) = s00.ProtocolIEID(271)
				*s46.BridgePathSwitchRequestAcknowledgeIEValueFieldRowCEModeBRestricted(&sealed) = &value
				return sealed
			}()
		}
		*s46.BridgePathSwitchRequestAcknowledgeCEModeBRestrictedIEBindingFieldGet(&sealed) = func(value *s46.PathSwitchRequestAcknowledgeIEValue) (*s00.CEModeBRestricted, bool) {
			return value.AsCEModeBRestricted()
		}
		return sealed
	}()
}
func (PathSwitchRequestAcknowledgeIETable) infoAerialUEsubscriptionInformation() s00.FieldInfo {
	return s00.FieldInfo{Table: PathSwitchRequestAcknowledgeIEs().ID(), ID: s00.ProtocolIEID(277), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "AerialUEsubscriptionInformation"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "PathSwitchRequestAcknowledgeIEs", Row: "id-AerialUEsubscriptionInformation"}}}
}

// AerialUEsubscriptionInformation returns the typed binding for the AerialUEsubscriptionInformation row of PathSwitchRequestAcknowledgeIETable.
func (t PathSwitchRequestAcknowledgeIETable) AerialUEsubscriptionInformation() s46.PathSwitchRequestAcknowledgeAerialUEsubscriptionInformationIEBinding {
	return func() s46.PathSwitchRequestAcknowledgeAerialUEsubscriptionInformationIEBinding {
		sealed := s46.PathSwitchRequestAcknowledgeAerialUEsubscriptionInformationIEBinding{}
		*s46.BridgePathSwitchRequestAcknowledgeAerialUEsubscriptionInformationIEBindingFieldInfo(&sealed) = t.infoAerialUEsubscriptionInformation()
		*s46.BridgePathSwitchRequestAcknowledgeAerialUEsubscriptionInformationIEBindingFieldCodec(&sealed) = func() s00.AerialUEsubscriptionInformationValueCodec {
			sealed := s00.AerialUEsubscriptionInformationValueCodec{}
			*s00.BridgeAerialUEsubscriptionInformationValueCodecFieldPath(&sealed) = "AerialUEsubscriptionInformation"
			*s00.BridgeAerialUEsubscriptionInformationValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.AerialUEsubscriptionInformation, error) {
				raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
				if err != nil {
					var empty s00.AerialUEsubscriptionInformation
					return empty, err
				}
				raw.BudgetBuffer().EnterComponent("AerialUEsubscriptionInformation")
				var zero s46.PathSwitchRequestAcknowledgeIEValue
				decoded, err := s46.BridgePathSwitchRequestAcknowledgeIEValueMethodDecode(zero, s00.ProtocolIEID(277), raw)
				if err != nil {
					var empty s00.AerialUEsubscriptionInformation
					return empty, runtime.WrapDecodePath(err, "AerialUEsubscriptionInformation")
				}
				value, ok := decoded.AsAerialUEsubscriptionInformation()
				if !ok {
					var empty s00.AerialUEsubscriptionInformation
					return empty, fmt.Errorf("binding PathSwitchRequestAcknowledgeIEs.id-AerialUEsubscriptionInformation: no selected value")
				}
				return *value, nil
			}
			*s00.BridgeAerialUEsubscriptionInformationValueCodecFieldEncode(&sealed) = func(value s00.AerialUEsubscriptionInformation, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
				return s46.BridgePathSwitchRequestAcknowledgeIEValueMethodEncodeFresh((func() s46.PathSwitchRequestAcknowledgeIEValue {
					sealed := s46.PathSwitchRequestAcknowledgeIEValue{}
					*s46.BridgePathSwitchRequestAcknowledgeIEValueFieldId(&sealed) = s00.ProtocolIEID(277)
					*s46.BridgePathSwitchRequestAcknowledgeIEValueFieldRowAerialUEsubscriptionInformation(&sealed) = &value
					return sealed
				}()), fresh, budget)
			}
			*s00.BridgeAerialUEsubscriptionInformationValueCodecFieldCapture(&sealed) = func(v s00.AerialUEsubscriptionInformation, options aper.DecodeState) (s00.AerialUEsubscriptionInformation, aper.Snapshot,
			) {
				s := aper.SemanticCaptureFor(options)
				f := s.Begin()
				s00.BridgeCaptureS1APAerialUEsubscriptionInformation(&v, &s)
				var root aper.Snapshot

				s.End(f, &root, false)
				return v, root
			}
			*s00.BridgeAerialUEsubscriptionInformationValueCodecFieldCompare(&sealed) = func(v s00.AerialUEsubscriptionInformation, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
			) {
				s := aper.NewSemanticComparison(root, budget)
				f := s.Begin()
				s02.BridgeCompareS1APAerialUEsubscriptionInformation(&v, &s)

				s.End(f, root, false)
				return s.Plan(), s.BudgetValue()
			}
			*s00.BridgeAerialUEsubscriptionInformationValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
				sealed := s00.BridgeCodecContext{}
				*s00.BridgecodecContextFieldSource(&sealed) = "source-value:AerialUEsubscriptionInformation"
				*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
				return sealed
			}()
			return sealed
		}()
		*s46.BridgePathSwitchRequestAcknowledgeAerialUEsubscriptionInformationIEBindingFieldInject(&sealed) = func(value s00.AerialUEsubscriptionInformation) s46.PathSwitchRequestAcknowledgeIEValue {
			return func() s46.PathSwitchRequestAcknowledgeIEValue {
				sealed := s46.PathSwitchRequestAcknowledgeIEValue{}
				*s46.BridgePathSwitchRequestAcknowledgeIEValueFieldId(&sealed) = s00.ProtocolIEID(277)
				*s46.BridgePathSwitchRequestAcknowledgeIEValueFieldRowAerialUEsubscriptionInformation(&sealed) = &value
				return sealed
			}()
		}
		*s46.BridgePathSwitchRequestAcknowledgeAerialUEsubscriptionInformationIEBindingFieldGet(&sealed) = func(value *s46.PathSwitchRequestAcknowledgeIEValue) (*s00.AerialUEsubscriptionInformation, bool) {
			return value.AsAerialUEsubscriptionInformation()
		}
		return sealed
	}()
}
func (PathSwitchRequestAcknowledgeIETable) infoPendingDataIndication() s00.FieldInfo {
	return s00.FieldInfo{Table: PathSwitchRequestAcknowledgeIEs().ID(), ID: s00.ProtocolIEID(283), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "PendingDataIndication"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "PathSwitchRequestAcknowledgeIEs", Row: "id-PendingDataIndication"}}}
}

// PendingDataIndication returns the typed binding for the PendingDataIndication row of PathSwitchRequestAcknowledgeIETable.
func (t PathSwitchRequestAcknowledgeIETable) PendingDataIndication() s46.PathSwitchRequestAcknowledgePendingDataIndicationIEBinding {
	return func() s46.PathSwitchRequestAcknowledgePendingDataIndicationIEBinding {
		sealed := s46.PathSwitchRequestAcknowledgePendingDataIndicationIEBinding{}
		*s46.BridgePathSwitchRequestAcknowledgePendingDataIndicationIEBindingFieldInfo(&sealed) = t.infoPendingDataIndication()
		*s46.BridgePathSwitchRequestAcknowledgePendingDataIndicationIEBindingFieldCodec(&sealed) = func() s01.PendingDataIndicationValueCodec {
			sealed := s01.PendingDataIndicationValueCodec{}
			*s01.BridgePendingDataIndicationValueCodecFieldPath(&sealed) = "PendingDataIndication"
			*s01.BridgePendingDataIndicationValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.PendingDataIndication, error) {
				raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
				if err != nil {
					var empty s00.PendingDataIndication
					return empty, err
				}
				raw.BudgetBuffer().EnterComponent("PendingDataIndication")
				var zero s46.PathSwitchRequestAcknowledgeIEValue
				decoded, err := s46.BridgePathSwitchRequestAcknowledgeIEValueMethodDecode(zero, s00.ProtocolIEID(283), raw)
				if err != nil {
					var empty s00.PendingDataIndication
					return empty, runtime.WrapDecodePath(err, "PendingDataIndication")
				}
				value, ok := decoded.AsPendingDataIndication()
				if !ok {
					var empty s00.PendingDataIndication
					return empty, fmt.Errorf("binding PathSwitchRequestAcknowledgeIEs.id-PendingDataIndication: no selected value")
				}
				return *value, nil
			}
			*s01.BridgePendingDataIndicationValueCodecFieldEncode(&sealed) = func(value s00.PendingDataIndication, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
				return s46.BridgePathSwitchRequestAcknowledgeIEValueMethodEncodeFresh((func() s46.PathSwitchRequestAcknowledgeIEValue {
					sealed := s46.PathSwitchRequestAcknowledgeIEValue{}
					*s46.BridgePathSwitchRequestAcknowledgeIEValueFieldId(&sealed) = s00.ProtocolIEID(283)
					*s46.BridgePathSwitchRequestAcknowledgeIEValueFieldRowPendingDataIndication(&sealed) = &value
					return sealed
				}()), fresh, budget)
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
		}()
		*s46.BridgePathSwitchRequestAcknowledgePendingDataIndicationIEBindingFieldInject(&sealed) = func(value s00.PendingDataIndication) s46.PathSwitchRequestAcknowledgeIEValue {
			return func() s46.PathSwitchRequestAcknowledgeIEValue {
				sealed := s46.PathSwitchRequestAcknowledgeIEValue{}
				*s46.BridgePathSwitchRequestAcknowledgeIEValueFieldId(&sealed) = s00.ProtocolIEID(283)
				*s46.BridgePathSwitchRequestAcknowledgeIEValueFieldRowPendingDataIndication(&sealed) = &value
				return sealed
			}()
		}
		*s46.BridgePathSwitchRequestAcknowledgePendingDataIndicationIEBindingFieldGet(&sealed) = func(value *s46.PathSwitchRequestAcknowledgeIEValue) (*s00.PendingDataIndication, bool) {
			return value.AsPendingDataIndication()
		}
		return sealed
	}()
}
func (PathSwitchRequestAcknowledgeIETable) infoSubscriptionBasedUEDifferentiationInfo() s00.FieldInfo {
	return s00.FieldInfo{Table: PathSwitchRequestAcknowledgeIEs().ID(), ID: s00.ProtocolIEID(278), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "Subscription-Based-UE-DifferentiationInfo"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "PathSwitchRequestAcknowledgeIEs", Row: "id-Subscription-Based-UE-DifferentiationInfo"}}}
}

// SubscriptionBasedUEDifferentiationInfo returns the typed binding for the SubscriptionBasedUEDifferentiationInfo row of PathSwitchRequestAcknowledgeIETable.
func (t PathSwitchRequestAcknowledgeIETable) SubscriptionBasedUEDifferentiationInfo() s46.PathSwitchRequestAcknowledgeSubscriptionBasedUEDifferentiationInfoIEBinding {
	return func() s46.PathSwitchRequestAcknowledgeSubscriptionBasedUEDifferentiationInfoIEBinding {
		sealed := s46.PathSwitchRequestAcknowledgeSubscriptionBasedUEDifferentiationInfoIEBinding{}
		*s46.BridgePathSwitchRequestAcknowledgeSubscriptionBasedUEDifferentiationInfoIEBindingFieldInfo(&sealed) = t.infoSubscriptionBasedUEDifferentiationInfo()
		*s46.BridgePathSwitchRequestAcknowledgeSubscriptionBasedUEDifferentiationInfoIEBindingFieldCodec(&sealed) = func() s31.SubscriptionBasedUEDifferentiationInfoValueCodec {
			sealed := s31.SubscriptionBasedUEDifferentiationInfoValueCodec{}
			*s31.BridgeSubscriptionBasedUEDifferentiationInfoValueCodecFieldPath(&sealed) = "SubscriptionBasedUEDifferentiationInfo"
			*s31.BridgeSubscriptionBasedUEDifferentiationInfoValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s30.SubscriptionBasedUEDifferentiationInfo, error) {
				raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
				if err != nil {
					var empty s30.SubscriptionBasedUEDifferentiationInfo
					return empty, err
				}
				raw.BudgetBuffer().EnterComponent("SubscriptionBasedUEDifferentiationInfo")
				var zero s46.PathSwitchRequestAcknowledgeIEValue
				decoded, err := s46.BridgePathSwitchRequestAcknowledgeIEValueMethodDecode(zero, s00.ProtocolIEID(278), raw)
				if err != nil {
					var empty s30.SubscriptionBasedUEDifferentiationInfo
					return empty, runtime.WrapDecodePath(err, "SubscriptionBasedUEDifferentiationInfo")
				}
				value, ok := decoded.AsSubscriptionBasedUEDifferentiationInfo()
				if !ok {
					var empty s30.SubscriptionBasedUEDifferentiationInfo
					return empty, fmt.Errorf("binding PathSwitchRequestAcknowledgeIEs.id-Subscription-Based-UE-DifferentiationInfo: no selected value")
				}
				return *value, nil
			}
			*s31.BridgeSubscriptionBasedUEDifferentiationInfoValueCodecFieldEncode(&sealed) = func(value s30.SubscriptionBasedUEDifferentiationInfo, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
				return s46.BridgePathSwitchRequestAcknowledgeIEValueMethodEncodeFresh((func() s46.PathSwitchRequestAcknowledgeIEValue {
					sealed := s46.PathSwitchRequestAcknowledgeIEValue{}
					*s46.BridgePathSwitchRequestAcknowledgeIEValueFieldId(&sealed) = s00.ProtocolIEID(278)
					*s46.BridgePathSwitchRequestAcknowledgeIEValueFieldRowSubscriptionBasedUEDifferentiationInfo(&sealed) = &value
					return sealed
				}()), fresh, budget)
			}
			*s31.BridgeSubscriptionBasedUEDifferentiationInfoValueCodecFieldCapture(&sealed) = func(v s30.SubscriptionBasedUEDifferentiationInfo, options aper.DecodeState) (s30.SubscriptionBasedUEDifferentiationInfo, aper.Snapshot) {
				s := aper.SemanticCaptureFor(options)
				f := s.Begin()
				s30.BridgeCaptureS1APSubscriptionBasedUEDifferentiationInfo(
					&v, &s)
				var root aper.Snapshot
				s.End(f, &root, false)
				return v, root
			}
			*s31.BridgeSubscriptionBasedUEDifferentiationInfoValueCodecFieldCompare(&sealed) = func(v s30.SubscriptionBasedUEDifferentiationInfo, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

			) {
				s := aper.NewSemanticComparison(root, budget)
				f := s.Begin()
				s30.BridgeCompareS1APSubscriptionBasedUEDifferentiationInfo(&v, &s)
				s.End(f, root, false)
				return s.Plan(), s.
					BudgetValue()
			}
			*s31.BridgeSubscriptionBasedUEDifferentiationInfoValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
				sealed := s00.BridgeCodecContext{}
				*s00.BridgecodecContextFieldSource(&sealed) = "source-value:SubscriptionBasedUEDifferentiationInfo"
				*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
				return sealed
			}()
			return sealed
		}()
		*s46.BridgePathSwitchRequestAcknowledgeSubscriptionBasedUEDifferentiationInfoIEBindingFieldInject(&sealed) = func(value s30.SubscriptionBasedUEDifferentiationInfo) s46.PathSwitchRequestAcknowledgeIEValue {
			return func() s46.PathSwitchRequestAcknowledgeIEValue {
				sealed := s46.PathSwitchRequestAcknowledgeIEValue{}
				*s46.BridgePathSwitchRequestAcknowledgeIEValueFieldId(&sealed) = s00.ProtocolIEID(278)
				*s46.BridgePathSwitchRequestAcknowledgeIEValueFieldRowSubscriptionBasedUEDifferentiationInfo(&sealed) = &value
				return sealed
			}()
		}
		*s46.BridgePathSwitchRequestAcknowledgeSubscriptionBasedUEDifferentiationInfoIEBindingFieldGet(&sealed) = func(value *s46.PathSwitchRequestAcknowledgeIEValue) (*s30.SubscriptionBasedUEDifferentiationInfo, bool) {
			return value.AsSubscriptionBasedUEDifferentiationInfo()
		}
		return sealed
	}()
}
func (PathSwitchRequestAcknowledgeIETable) infoHandoverRestrictionList() s00.FieldInfo {
	return s00.FieldInfo{Table: PathSwitchRequestAcknowledgeIEs().ID(), ID: s00.ProtocolIEID(41), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "HandoverRestrictionList"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "PathSwitchRequestAcknowledgeIEs", Row: "id-HandoverRestrictionList"}}}
}

// HandoverRestrictionList returns the typed binding for the HandoverRestrictionList row of PathSwitchRequestAcknowledgeIETable.
func (t PathSwitchRequestAcknowledgeIETable) HandoverRestrictionList() s46.PathSwitchRequestAcknowledgeHandoverRestrictionListIEBinding {
	return func() s46.PathSwitchRequestAcknowledgeHandoverRestrictionListIEBinding {
		sealed := s46.PathSwitchRequestAcknowledgeHandoverRestrictionListIEBinding{}
		*s46.BridgePathSwitchRequestAcknowledgeHandoverRestrictionListIEBindingFieldInfo(&sealed) = t.infoHandoverRestrictionList()
		*s46.BridgePathSwitchRequestAcknowledgeHandoverRestrictionListIEBindingFieldCodec(&sealed) = func() s42.HandoverRestrictionListValueCodec {
			sealed := s42.HandoverRestrictionListValueCodec{}
			*s42.BridgeHandoverRestrictionListValueCodecFieldPath(&sealed) = "HandoverRestrictionList"
			*s42.BridgeHandoverRestrictionListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s42.HandoverRestrictionList, error) {
				raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
				if err != nil {
					var empty s42.HandoverRestrictionList
					return empty, err
				}
				raw.BudgetBuffer().EnterComponent("HandoverRestrictionList")
				var zero s46.PathSwitchRequestAcknowledgeIEValue
				decoded, err := s46.BridgePathSwitchRequestAcknowledgeIEValueMethodDecode(zero, s00.ProtocolIEID(41), raw)
				if err != nil {
					var empty s42.HandoverRestrictionList
					return empty, runtime.WrapDecodePath(err, "HandoverRestrictionList")
				}
				value, ok := decoded.AsHandoverRestrictionList()
				if !ok {
					var empty s42.HandoverRestrictionList
					return empty, fmt.Errorf("binding PathSwitchRequestAcknowledgeIEs.id-HandoverRestrictionList: no selected value")
				}
				return *value, nil
			}
			*s42.BridgeHandoverRestrictionListValueCodecFieldEncode(&sealed) = func(value s42.HandoverRestrictionList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
				return s46.BridgePathSwitchRequestAcknowledgeIEValueMethodEncodeFresh((func() s46.PathSwitchRequestAcknowledgeIEValue {
					sealed := s46.PathSwitchRequestAcknowledgeIEValue{}
					*s46.BridgePathSwitchRequestAcknowledgeIEValueFieldId(&sealed) = s00.ProtocolIEID(41)
					*s46.BridgePathSwitchRequestAcknowledgeIEValueFieldRowHandoverRestrictionList(&sealed) = &value
					return sealed
				}()), fresh, budget)
			}
			*s42.BridgeHandoverRestrictionListValueCodecFieldCapture(&sealed) = func(v s42.HandoverRestrictionList, options aper.DecodeState) (s42.HandoverRestrictionList, aper.Snapshot) {
				s := aper.SemanticCaptureFor(options)
				f := s.Begin()
				s42.BridgeCaptureS1APHandoverRestrictionList(&v, &s)
				var root aper.Snapshot
				s.End(f, &root,

					false,
				)
				return v, root
			}
			*s42.BridgeHandoverRestrictionListValueCodecFieldCompare(&sealed) = func(v s42.HandoverRestrictionList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

			) {
				s := aper.NewSemanticComparison(root, budget)
				f := s.Begin()
				s42.BridgeCompareS1APHandoverRestrictionList(&v, &s)
				s.End(f, root,
					false,
				)
				return s.Plan(), s.BudgetValue()
			}
			*s42.BridgeHandoverRestrictionListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
				sealed := s00.BridgeCodecContext{}
				*s00.BridgecodecContextFieldSource(&sealed) = "source-value:HandoverRestrictionList"
				*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
				return sealed
			}()
			return sealed
		}()
		*s46.BridgePathSwitchRequestAcknowledgeHandoverRestrictionListIEBindingFieldInject(&sealed) = func(value s42.HandoverRestrictionList) s46.PathSwitchRequestAcknowledgeIEValue {
			return func() s46.PathSwitchRequestAcknowledgeIEValue {
				sealed := s46.PathSwitchRequestAcknowledgeIEValue{}
				*s46.BridgePathSwitchRequestAcknowledgeIEValueFieldId(&sealed) = s00.ProtocolIEID(41)
				*s46.BridgePathSwitchRequestAcknowledgeIEValueFieldRowHandoverRestrictionList(&sealed) = &value
				return sealed
			}()
		}
		*s46.BridgePathSwitchRequestAcknowledgeHandoverRestrictionListIEBindingFieldGet(&sealed) = func(value *s46.PathSwitchRequestAcknowledgeIEValue) (*s42.HandoverRestrictionList, bool) {
			return value.AsHandoverRestrictionList()
		}
		return sealed
	}()
}
func (PathSwitchRequestAcknowledgeIETable) infoAdditionalRRMPriorityIndex() s00.FieldInfo {
	return s00.FieldInfo{Table: PathSwitchRequestAcknowledgeIEs().ID(), ID: s00.ProtocolIEID(299), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "AdditionalRRMPriorityIndex"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "PathSwitchRequestAcknowledgeIEs", Row: "id-AdditionalRRMPriorityIndex"}}}
}

// AdditionalRRMPriorityIndex returns the typed binding for the AdditionalRRMPriorityIndex row of PathSwitchRequestAcknowledgeIETable.
func (t PathSwitchRequestAcknowledgeIETable) AdditionalRRMPriorityIndex() s46.PathSwitchRequestAcknowledgeAdditionalRRMPriorityIndexIEBinding {
	return func() s46.PathSwitchRequestAcknowledgeAdditionalRRMPriorityIndexIEBinding {
		sealed := s46.PathSwitchRequestAcknowledgeAdditionalRRMPriorityIndexIEBinding{}
		*s46.BridgePathSwitchRequestAcknowledgeAdditionalRRMPriorityIndexIEBindingFieldInfo(&sealed) = t.infoAdditionalRRMPriorityIndex()
		*s46.BridgePathSwitchRequestAcknowledgeAdditionalRRMPriorityIndexIEBindingFieldCodec(&sealed) = func() s00.AdditionalRRMPriorityIndexValueCodec {
			sealed := s00.AdditionalRRMPriorityIndexValueCodec{}
			*s00.BridgeAdditionalRRMPriorityIndexValueCodecFieldPath(&sealed) = "AdditionalRRMPriorityIndex"
			*s00.BridgeAdditionalRRMPriorityIndexValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.AdditionalRRMPriorityIndex, error) {
				raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
				if err != nil {
					var empty s00.AdditionalRRMPriorityIndex
					return empty, err
				}
				raw.BudgetBuffer().EnterComponent("AdditionalRRMPriorityIndex")
				var zero s46.PathSwitchRequestAcknowledgeIEValue
				decoded, err := s46.BridgePathSwitchRequestAcknowledgeIEValueMethodDecode(zero, s00.ProtocolIEID(299), raw)
				if err != nil {
					var empty s00.AdditionalRRMPriorityIndex
					return empty, runtime.WrapDecodePath(err, "AdditionalRRMPriorityIndex")
				}
				value, ok := decoded.AsAdditionalRRMPriorityIndex()
				if !ok {
					var empty s00.AdditionalRRMPriorityIndex
					return empty, fmt.Errorf("binding PathSwitchRequestAcknowledgeIEs.id-AdditionalRRMPriorityIndex: no selected value")
				}
				return *value, nil
			}
			*s00.BridgeAdditionalRRMPriorityIndexValueCodecFieldEncode(&sealed) = func(value s00.AdditionalRRMPriorityIndex, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
				return s46.BridgePathSwitchRequestAcknowledgeIEValueMethodEncodeFresh((func() s46.PathSwitchRequestAcknowledgeIEValue {
					sealed := s46.PathSwitchRequestAcknowledgeIEValue{}
					*s46.BridgePathSwitchRequestAcknowledgeIEValueFieldId(&sealed) = s00.ProtocolIEID(299)
					*s46.BridgePathSwitchRequestAcknowledgeIEValueFieldRowAdditionalRRMPriorityIndex(&sealed) = &value
					return sealed
				}()), fresh, budget)
			}
			*s00.BridgeAdditionalRRMPriorityIndexValueCodecFieldCapture(&sealed) = func(v s00.AdditionalRRMPriorityIndex, options aper.DecodeState) (s00.AdditionalRRMPriorityIndex, aper.Snapshot,
			) {
				s := aper.SemanticCaptureFor(options)
				f := s.Begin()
				s00.BridgeCaptureS1APAdditionalRRMPriorityIndex(&v, &s)
				var root aper.Snapshot
				s.End(
					f, &root, false)
				return v, root
			}
			*s00.BridgeAdditionalRRMPriorityIndexValueCodecFieldCompare(&sealed) = func(v s00.AdditionalRRMPriorityIndex, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
			) {
				s := aper.NewSemanticComparison(root, budget)
				f := s.Begin()
				s02.BridgeCompareS1APAdditionalRRMPriorityIndex(&v, &s)
				s.End(f,
					root,

					false)
				return s.Plan(), s.BudgetValue()
			}
			*s00.BridgeAdditionalRRMPriorityIndexValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
				sealed := s00.BridgeCodecContext{}
				*s00.BridgecodecContextFieldSource(&sealed) = "source-value:AdditionalRRMPriorityIndex"
				*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
				return sealed
			}()
			return sealed
		}()
		*s46.BridgePathSwitchRequestAcknowledgeAdditionalRRMPriorityIndexIEBindingFieldInject(&sealed) = func(value s00.AdditionalRRMPriorityIndex) s46.PathSwitchRequestAcknowledgeIEValue {
			return func() s46.PathSwitchRequestAcknowledgeIEValue {
				sealed := s46.PathSwitchRequestAcknowledgeIEValue{}
				*s46.BridgePathSwitchRequestAcknowledgeIEValueFieldId(&sealed) = s00.ProtocolIEID(299)
				*s46.BridgePathSwitchRequestAcknowledgeIEValueFieldRowAdditionalRRMPriorityIndex(&sealed) = &value
				return sealed
			}()
		}
		*s46.BridgePathSwitchRequestAcknowledgeAdditionalRRMPriorityIndexIEBindingFieldGet(&sealed) = func(value *s46.PathSwitchRequestAcknowledgeIEValue) (*s00.AdditionalRRMPriorityIndex, bool) {
			return value.AsAdditionalRRMPriorityIndex()
		}
		return sealed
	}()
}
func (PathSwitchRequestAcknowledgeIETable) infoNRV2XServicesAuthorized() s00.FieldInfo {
	return s00.FieldInfo{Table: PathSwitchRequestAcknowledgeIEs().ID(), ID: s00.ProtocolIEID(306), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "NRV2XServicesAuthorized"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "PathSwitchRequestAcknowledgeIEs", Row: "id-NRV2XServicesAuthorized"}}}
}

// NRV2XServicesAuthorized returns the typed binding for the NRV2XServicesAuthorized row of PathSwitchRequestAcknowledgeIETable.
func (t PathSwitchRequestAcknowledgeIETable) NRV2XServicesAuthorized() s46.PathSwitchRequestAcknowledgeNRV2XServicesAuthorizedIEBinding {
	return func() s46.PathSwitchRequestAcknowledgeNRV2XServicesAuthorizedIEBinding {
		sealed := s46.PathSwitchRequestAcknowledgeNRV2XServicesAuthorizedIEBinding{}
		*s46.BridgePathSwitchRequestAcknowledgeNRV2XServicesAuthorizedIEBindingFieldInfo(&sealed) = t.infoNRV2XServicesAuthorized()
		*s46.BridgePathSwitchRequestAcknowledgeNRV2XServicesAuthorizedIEBindingFieldCodec(&sealed) = func() s19.NRV2XServicesAuthorizedValueCodec {
			sealed := s19.NRV2XServicesAuthorizedValueCodec{}
			*s19.BridgeNRV2XServicesAuthorizedValueCodecFieldPath(&sealed) = "NRV2XServicesAuthorized"
			*s19.BridgeNRV2XServicesAuthorizedValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s19.NRV2XServicesAuthorized, error) {
				raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
				if err != nil {
					var empty s19.NRV2XServicesAuthorized
					return empty, err
				}
				raw.BudgetBuffer().EnterComponent("NRV2XServicesAuthorized")
				var zero s46.PathSwitchRequestAcknowledgeIEValue
				decoded, err := s46.BridgePathSwitchRequestAcknowledgeIEValueMethodDecode(zero, s00.ProtocolIEID(306), raw)
				if err != nil {
					var empty s19.NRV2XServicesAuthorized
					return empty, runtime.WrapDecodePath(err, "NRV2XServicesAuthorized")
				}
				value, ok := decoded.AsNRV2XServicesAuthorized()
				if !ok {
					var empty s19.NRV2XServicesAuthorized
					return empty, fmt.Errorf("binding PathSwitchRequestAcknowledgeIEs.id-NRV2XServicesAuthorized: no selected value")
				}
				return *value, nil
			}
			*s19.BridgeNRV2XServicesAuthorizedValueCodecFieldEncode(&sealed) = func(value s19.NRV2XServicesAuthorized, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
				return s46.BridgePathSwitchRequestAcknowledgeIEValueMethodEncodeFresh((func() s46.PathSwitchRequestAcknowledgeIEValue {
					sealed := s46.PathSwitchRequestAcknowledgeIEValue{}
					*s46.BridgePathSwitchRequestAcknowledgeIEValueFieldId(&sealed) = s00.ProtocolIEID(306)
					*s46.BridgePathSwitchRequestAcknowledgeIEValueFieldRowNRV2XServicesAuthorized(&sealed) = &value
					return sealed
				}()), fresh, budget)
			}
			*s19.BridgeNRV2XServicesAuthorizedValueCodecFieldCapture(&sealed) = func(v s19.NRV2XServicesAuthorized, options aper.DecodeState) (s19.NRV2XServicesAuthorized, aper.Snapshot) {
				s := aper.SemanticCaptureFor(options)
				f := s.Begin()
				s19.BridgeCaptureS1APNRV2XServicesAuthorized(&v, &s)
				var root aper.Snapshot
				s.End(f, &root,

					false,
				)
				return v, root
			}
			*s19.BridgeNRV2XServicesAuthorizedValueCodecFieldCompare(&sealed) = func(v s19.NRV2XServicesAuthorized, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

			) {
				s := aper.NewSemanticComparison(root, budget)
				f := s.Begin()
				s19.BridgeCompareS1APNRV2XServicesAuthorized(&v, &s)
				s.End(f, root,
					false,
				)
				return s.Plan(), s.BudgetValue()
			}
			*s19.BridgeNRV2XServicesAuthorizedValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
				sealed := s00.BridgeCodecContext{}
				*s00.BridgecodecContextFieldSource(&sealed) = "source-value:NRV2XServicesAuthorized"
				*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
				return sealed
			}()
			return sealed
		}()
		*s46.BridgePathSwitchRequestAcknowledgeNRV2XServicesAuthorizedIEBindingFieldInject(&sealed) = func(value s19.NRV2XServicesAuthorized) s46.PathSwitchRequestAcknowledgeIEValue {
			return func() s46.PathSwitchRequestAcknowledgeIEValue {
				sealed := s46.PathSwitchRequestAcknowledgeIEValue{}
				*s46.BridgePathSwitchRequestAcknowledgeIEValueFieldId(&sealed) = s00.ProtocolIEID(306)
				*s46.BridgePathSwitchRequestAcknowledgeIEValueFieldRowNRV2XServicesAuthorized(&sealed) = &value
				return sealed
			}()
		}
		*s46.BridgePathSwitchRequestAcknowledgeNRV2XServicesAuthorizedIEBindingFieldGet(&sealed) = func(value *s46.PathSwitchRequestAcknowledgeIEValue) (*s19.NRV2XServicesAuthorized, bool) {
			return value.AsNRV2XServicesAuthorized()
		}
		return sealed
	}()
}
func (PathSwitchRequestAcknowledgeIETable) infoNRUESidelinkAggregateMaximumBitrate() s00.FieldInfo {
	return s00.FieldInfo{Table: PathSwitchRequestAcknowledgeIEs().ID(), ID: s00.ProtocolIEID(307), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "NRUESidelinkAggregateMaximumBitrate"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "PathSwitchRequestAcknowledgeIEs", Row: "id-NRUESidelinkAggregateMaximumBitrate"}}}
}

// NRUESidelinkAggregateMaximumBitrate returns the typed binding for the NRUESidelinkAggregateMaximumBitrate row of PathSwitchRequestAcknowledgeIETable.
func (t PathSwitchRequestAcknowledgeIETable) NRUESidelinkAggregateMaximumBitrate() s46.PathSwitchRequestAcknowledgeNRUESidelinkAggregateMaximumBitrateIEBinding {
	return func() s46.PathSwitchRequestAcknowledgeNRUESidelinkAggregateMaximumBitrateIEBinding {
		sealed := s46.PathSwitchRequestAcknowledgeNRUESidelinkAggregateMaximumBitrateIEBinding{}
		*s46.BridgePathSwitchRequestAcknowledgeNRUESidelinkAggregateMaximumBitrateIEBindingFieldInfo(&sealed) = t.infoNRUESidelinkAggregateMaximumBitrate()
		*s46.BridgePathSwitchRequestAcknowledgeNRUESidelinkAggregateMaximumBitrateIEBindingFieldCodec(&sealed) = func() s19.NRUESidelinkAggregateMaximumBitrateValueCodec {
			sealed := s19.NRUESidelinkAggregateMaximumBitrateValueCodec{}
			*s19.BridgeNRUESidelinkAggregateMaximumBitrateValueCodecFieldPath(&sealed) = "NRUESidelinkAggregateMaximumBitrate"
			*s19.BridgeNRUESidelinkAggregateMaximumBitrateValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s19.NRUESidelinkAggregateMaximumBitrate, error) {
				raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
				if err != nil {
					var empty s19.NRUESidelinkAggregateMaximumBitrate
					return empty, err
				}
				raw.BudgetBuffer().EnterComponent("NRUESidelinkAggregateMaximumBitrate")
				var zero s46.PathSwitchRequestAcknowledgeIEValue
				decoded, err := s46.BridgePathSwitchRequestAcknowledgeIEValueMethodDecode(zero, s00.ProtocolIEID(307), raw)
				if err != nil {
					var empty s19.NRUESidelinkAggregateMaximumBitrate
					return empty, runtime.WrapDecodePath(err, "NRUESidelinkAggregateMaximumBitrate")
				}
				value, ok := decoded.AsNRUESidelinkAggregateMaximumBitrate()
				if !ok {
					var empty s19.NRUESidelinkAggregateMaximumBitrate
					return empty, fmt.Errorf("binding PathSwitchRequestAcknowledgeIEs.id-NRUESidelinkAggregateMaximumBitrate: no selected value")
				}
				return *value, nil
			}
			*s19.BridgeNRUESidelinkAggregateMaximumBitrateValueCodecFieldEncode(&sealed) = func(value s19.NRUESidelinkAggregateMaximumBitrate, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
				return s46.BridgePathSwitchRequestAcknowledgeIEValueMethodEncodeFresh((func() s46.PathSwitchRequestAcknowledgeIEValue {
					sealed := s46.PathSwitchRequestAcknowledgeIEValue{}
					*s46.BridgePathSwitchRequestAcknowledgeIEValueFieldId(&sealed) = s00.ProtocolIEID(307)
					*s46.BridgePathSwitchRequestAcknowledgeIEValueFieldRowNRUESidelinkAggregateMaximumBitrate(&sealed) = &value
					return sealed
				}()), fresh, budget)
			}
			*s19.BridgeNRUESidelinkAggregateMaximumBitrateValueCodecFieldCapture(&sealed) = func(v s19.NRUESidelinkAggregateMaximumBitrate, options aper.DecodeState) (s19.NRUESidelinkAggregateMaximumBitrate, aper.Snapshot,
			) {
				s := aper.SemanticCaptureFor(options)
				f := s.Begin()
				s19.BridgeCaptureS1APNRUESidelinkAggregateMaximumBitrate(&v, &s)
				var root aper.Snapshot
				s.End(f, &root, false)
				return v, root

			}
			*s19.BridgeNRUESidelinkAggregateMaximumBitrateValueCodecFieldCompare(&sealed) = func(v s19.NRUESidelinkAggregateMaximumBitrate, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

			) {
				s := aper.NewSemanticComparison(root, budget)
				f := s.Begin()
				s19.BridgeCompareS1APNRUESidelinkAggregateMaximumBitrate(&v, &s)
				s.End(f, root, false)
				return s.Plan(), s.BudgetValue()
			}
			*s19.BridgeNRUESidelinkAggregateMaximumBitrateValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
				sealed := s00.BridgeCodecContext{}
				*s00.BridgecodecContextFieldSource(&sealed) = "source-value:NRUESidelinkAggregateMaximumBitrate"
				*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
				return sealed
			}()
			return sealed
		}()
		*s46.BridgePathSwitchRequestAcknowledgeNRUESidelinkAggregateMaximumBitrateIEBindingFieldInject(&sealed) = func(value s19.NRUESidelinkAggregateMaximumBitrate) s46.PathSwitchRequestAcknowledgeIEValue {
			return func() s46.PathSwitchRequestAcknowledgeIEValue {
				sealed := s46.PathSwitchRequestAcknowledgeIEValue{}
				*s46.BridgePathSwitchRequestAcknowledgeIEValueFieldId(&sealed) = s00.ProtocolIEID(307)
				*s46.BridgePathSwitchRequestAcknowledgeIEValueFieldRowNRUESidelinkAggregateMaximumBitrate(&sealed) = &value
				return sealed
			}()
		}
		*s46.BridgePathSwitchRequestAcknowledgeNRUESidelinkAggregateMaximumBitrateIEBindingFieldGet(&sealed) = func(value *s46.PathSwitchRequestAcknowledgeIEValue) (*s19.NRUESidelinkAggregateMaximumBitrate, bool) {
			return value.AsNRUESidelinkAggregateMaximumBitrate()
		}
		return sealed
	}()
}
func (PathSwitchRequestAcknowledgeIETable) infoPC5QoSParameters() s00.FieldInfo {
	return s00.FieldInfo{Table: PathSwitchRequestAcknowledgeIEs().ID(), ID: s00.ProtocolIEID(308), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "PC5QoSParameters"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "PathSwitchRequestAcknowledgeIEs", Row: "id-PC5QoSParameters"}}}
}

// PC5QoSParameters returns the typed binding for the PC5QoSParameters row of PathSwitchRequestAcknowledgeIETable.
func (t PathSwitchRequestAcknowledgeIETable) PC5QoSParameters() s46.PathSwitchRequestAcknowledgePC5QoSParametersIEBinding {
	return func() s46.PathSwitchRequestAcknowledgePC5QoSParametersIEBinding {
		sealed := s46.PathSwitchRequestAcknowledgePC5QoSParametersIEBinding{}
		*s46.BridgePathSwitchRequestAcknowledgePC5QoSParametersIEBindingFieldInfo(&sealed) = t.infoPC5QoSParameters()
		*s46.BridgePathSwitchRequestAcknowledgePC5QoSParametersIEBindingFieldCodec(&sealed) = func() s24.PC5QoSParametersValueCodec {
			sealed := s24.PC5QoSParametersValueCodec{}
			*s24.BridgePC5QoSParametersValueCodecFieldPath(&sealed) = "PC5QoSParameters"
			*s24.BridgePC5QoSParametersValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s24.PC5QoSParameters, error) {
				raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
				if err != nil {
					var empty s24.PC5QoSParameters
					return empty, err
				}
				raw.BudgetBuffer().EnterComponent("PC5QoSParameters")
				var zero s46.PathSwitchRequestAcknowledgeIEValue
				decoded, err := s46.BridgePathSwitchRequestAcknowledgeIEValueMethodDecode(zero, s00.ProtocolIEID(308), raw)
				if err != nil {
					var empty s24.PC5QoSParameters
					return empty, runtime.WrapDecodePath(err, "PC5QoSParameters")
				}
				value, ok := decoded.AsPC5QoSParameters()
				if !ok {
					var empty s24.PC5QoSParameters
					return empty, fmt.Errorf("binding PathSwitchRequestAcknowledgeIEs.id-PC5QoSParameters: no selected value")
				}
				return *value, nil
			}
			*s24.BridgePC5QoSParametersValueCodecFieldEncode(&sealed) = func(value s24.PC5QoSParameters, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
				return s46.BridgePathSwitchRequestAcknowledgeIEValueMethodEncodeFresh((func() s46.PathSwitchRequestAcknowledgeIEValue {
					sealed := s46.PathSwitchRequestAcknowledgeIEValue{}
					*s46.BridgePathSwitchRequestAcknowledgeIEValueFieldId(&sealed) = s00.ProtocolIEID(308)
					*s46.BridgePathSwitchRequestAcknowledgeIEValueFieldRowPC5QoSParameters(&sealed) = &value
					return sealed
				}()), fresh, budget)
			}
			*s24.BridgePC5QoSParametersValueCodecFieldCapture(&sealed) = func(v s24.PC5QoSParameters, options aper.DecodeState) (s24.PC5QoSParameters, aper.Snapshot) {
				s := aper.SemanticCaptureFor(
					options)
				f := s.Begin()
				s24.BridgeCaptureS1APPC5QoSParameters(&v, &s)
				var root aper.Snapshot
				s.End(f, &root, false)
				return v, root
			}
			*s24.BridgePC5QoSParametersValueCodecFieldCompare(&sealed) = func(v s24.PC5QoSParameters, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
				s := aper.NewSemanticComparison(root, budget)
				f := s.Begin()
				s24.BridgeCompareS1APPC5QoSParameters(&v, &s)
				s.End(f, root, false)
				return s.
					Plan(), s.BudgetValue()
			}
			*s24.BridgePC5QoSParametersValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
				sealed := s00.BridgeCodecContext{}
				*s00.BridgecodecContextFieldSource(&sealed) = "source-value:PC5QoSParameters"
				*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
				return sealed
			}()
			return sealed
		}()
		*s46.BridgePathSwitchRequestAcknowledgePC5QoSParametersIEBindingFieldInject(&sealed) = func(value s24.PC5QoSParameters) s46.PathSwitchRequestAcknowledgeIEValue {
			return func() s46.PathSwitchRequestAcknowledgeIEValue {
				sealed := s46.PathSwitchRequestAcknowledgeIEValue{}
				*s46.BridgePathSwitchRequestAcknowledgeIEValueFieldId(&sealed) = s00.ProtocolIEID(308)
				*s46.BridgePathSwitchRequestAcknowledgeIEValueFieldRowPC5QoSParameters(&sealed) = &value
				return sealed
			}()
		}
		*s46.BridgePathSwitchRequestAcknowledgePC5QoSParametersIEBindingFieldGet(&sealed) = func(value *s46.PathSwitchRequestAcknowledgeIEValue) (*s24.PC5QoSParameters, bool) {
			return value.AsPC5QoSParameters()
		}
		return sealed
	}()
}
func (PathSwitchRequestAcknowledgeIETable) infoUERadioCapabilityID() s00.FieldInfo {
	return s00.FieldInfo{Table: PathSwitchRequestAcknowledgeIEs().ID(), ID: s00.ProtocolIEID(314), Criticality: s00.CriticalityReject, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "UERadioCapabilityID"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "PathSwitchRequestAcknowledgeIEs", Row: "id-UERadioCapabilityID"}}}
}

// UERadioCapabilityID returns the typed binding for the UERadioCapabilityID row of PathSwitchRequestAcknowledgeIETable.
func (t PathSwitchRequestAcknowledgeIETable) UERadioCapabilityID() s46.PathSwitchRequestAcknowledgeUERadioCapabilityIDIEBinding {
	return func() s46.PathSwitchRequestAcknowledgeUERadioCapabilityIDIEBinding {
		sealed := s46.PathSwitchRequestAcknowledgeUERadioCapabilityIDIEBinding{}
		*s46.BridgePathSwitchRequestAcknowledgeUERadioCapabilityIDIEBindingFieldInfo(&sealed) = t.infoUERadioCapabilityID()
		*s46.BridgePathSwitchRequestAcknowledgeUERadioCapabilityIDIEBindingFieldCodec(&sealed) = func() s02.UERadioCapabilityIDValueCodec {
			sealed := s02.UERadioCapabilityIDValueCodec{}
			*s02.BridgeUERadioCapabilityIDValueCodecFieldPath(&sealed) = "UERadioCapabilityID"
			*s02.BridgeUERadioCapabilityIDValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.UERadioCapabilityID, error) {
				raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
				if err != nil {
					var empty s00.UERadioCapabilityID
					return empty, err
				}
				raw.BudgetBuffer().EnterComponent("UERadioCapabilityID")
				var zero s46.PathSwitchRequestAcknowledgeIEValue
				decoded, err := s46.BridgePathSwitchRequestAcknowledgeIEValueMethodDecode(zero, s00.ProtocolIEID(314), raw)
				if err != nil {
					var empty s00.UERadioCapabilityID
					return empty, runtime.WrapDecodePath(err, "UERadioCapabilityID")
				}
				value, ok := decoded.AsUERadioCapabilityID()
				if !ok {
					var empty s00.UERadioCapabilityID
					return empty, fmt.Errorf("binding PathSwitchRequestAcknowledgeIEs.id-UERadioCapabilityID: no selected value")
				}
				return *value, nil
			}
			*s02.BridgeUERadioCapabilityIDValueCodecFieldEncode(&sealed) = func(value s00.UERadioCapabilityID, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
				return s46.BridgePathSwitchRequestAcknowledgeIEValueMethodEncodeFresh((func() s46.PathSwitchRequestAcknowledgeIEValue {
					sealed := s46.PathSwitchRequestAcknowledgeIEValue{}
					*s46.BridgePathSwitchRequestAcknowledgeIEValueFieldId(&sealed) = s00.ProtocolIEID(314)
					*s46.BridgePathSwitchRequestAcknowledgeIEValueFieldRowUERadioCapabilityID(&sealed) = &value
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
		}()
		*s46.BridgePathSwitchRequestAcknowledgeUERadioCapabilityIDIEBindingFieldInject(&sealed) = func(value s00.UERadioCapabilityID) s46.PathSwitchRequestAcknowledgeIEValue {
			return func() s46.PathSwitchRequestAcknowledgeIEValue {
				sealed := s46.PathSwitchRequestAcknowledgeIEValue{}
				*s46.BridgePathSwitchRequestAcknowledgeIEValueFieldId(&sealed) = s00.ProtocolIEID(314)
				*s46.BridgePathSwitchRequestAcknowledgeIEValueFieldRowUERadioCapabilityID(&sealed) = &value
				return sealed
			}()
		}
		*s46.BridgePathSwitchRequestAcknowledgeUERadioCapabilityIDIEBindingFieldGet(&sealed) = func(value *s46.PathSwitchRequestAcknowledgeIEValue) (*s00.UERadioCapabilityID, bool) {
			return value.AsUERadioCapabilityID()
		}
		return sealed
	}()
}
func (PathSwitchRequestAcknowledgeIETable) infoUESecurityCapabilities() s00.FieldInfo {
	return s00.FieldInfo{Table: PathSwitchRequestAcknowledgeIEs().ID(), ID: s00.ProtocolIEID(107), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "UESecurityCapabilities"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "PathSwitchRequestAcknowledgeIEs", Row: "id-UESecurityCapabilities"}}}
}

// UESecurityCapabilities returns the typed binding for the UESecurityCapabilities row of PathSwitchRequestAcknowledgeIETable.
func (t PathSwitchRequestAcknowledgeIETable) UESecurityCapabilities() s46.PathSwitchRequestAcknowledgeUESecurityCapabilitiesIEBinding {
	return func() s46.PathSwitchRequestAcknowledgeUESecurityCapabilitiesIEBinding {
		sealed := s46.PathSwitchRequestAcknowledgeUESecurityCapabilitiesIEBinding{}
		*s46.BridgePathSwitchRequestAcknowledgeUESecurityCapabilitiesIEBindingFieldInfo(&sealed) = t.infoUESecurityCapabilities()
		*s46.BridgePathSwitchRequestAcknowledgeUESecurityCapabilitiesIEBindingFieldCodec(&sealed) = func() s37.UESecurityCapabilitiesValueCodec {
			sealed := s37.UESecurityCapabilitiesValueCodec{}
			*s37.BridgeUESecurityCapabilitiesValueCodecFieldPath(&sealed) = "UESecurityCapabilities"
			*s37.BridgeUESecurityCapabilitiesValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s37.UESecurityCapabilities, error) {
				raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
				if err != nil {
					var empty s37.UESecurityCapabilities
					return empty, err
				}
				raw.BudgetBuffer().EnterComponent("UESecurityCapabilities")
				var zero s46.PathSwitchRequestAcknowledgeIEValue
				decoded, err := s46.BridgePathSwitchRequestAcknowledgeIEValueMethodDecode(zero, s00.ProtocolIEID(107), raw)
				if err != nil {
					var empty s37.UESecurityCapabilities
					return empty, runtime.WrapDecodePath(err, "UESecurityCapabilities")
				}
				value, ok := decoded.AsUESecurityCapabilities()
				if !ok {
					var empty s37.UESecurityCapabilities
					return empty, fmt.Errorf("binding PathSwitchRequestAcknowledgeIEs.id-UESecurityCapabilities: no selected value")
				}
				return *value, nil
			}
			*s37.BridgeUESecurityCapabilitiesValueCodecFieldEncode(&sealed) = func(value s37.UESecurityCapabilities, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
				return s46.BridgePathSwitchRequestAcknowledgeIEValueMethodEncodeFresh((func() s46.PathSwitchRequestAcknowledgeIEValue {
					sealed := s46.PathSwitchRequestAcknowledgeIEValue{}
					*s46.BridgePathSwitchRequestAcknowledgeIEValueFieldId(&sealed) = s00.ProtocolIEID(107)
					*s46.BridgePathSwitchRequestAcknowledgeIEValueFieldRowUESecurityCapabilities(&sealed) = &value
					return sealed
				}()), fresh, budget)
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
		}()
		*s46.BridgePathSwitchRequestAcknowledgeUESecurityCapabilitiesIEBindingFieldInject(&sealed) = func(value s37.UESecurityCapabilities) s46.PathSwitchRequestAcknowledgeIEValue {
			return func() s46.PathSwitchRequestAcknowledgeIEValue {
				sealed := s46.PathSwitchRequestAcknowledgeIEValue{}
				*s46.BridgePathSwitchRequestAcknowledgeIEValueFieldId(&sealed) = s00.ProtocolIEID(107)
				*s46.BridgePathSwitchRequestAcknowledgeIEValueFieldRowUESecurityCapabilities(&sealed) = &value
				return sealed
			}()
		}
		*s46.BridgePathSwitchRequestAcknowledgeUESecurityCapabilitiesIEBindingFieldGet(&sealed) = func(value *s46.PathSwitchRequestAcknowledgeIEValue) (*s37.UESecurityCapabilities, bool) {
			return value.AsUESecurityCapabilities()
		}
		return sealed
	}()
}
func (PathSwitchRequestAcknowledgeIETable) infoERABToBeUpdatedList() s00.FieldInfo {
	return s00.FieldInfo{Table: PathSwitchRequestAcknowledgeIEs().ID(), ID: s00.ProtocolIEID(341), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "E-RABToBeUpdatedList"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "PathSwitchRequestAcknowledgeIEs", Row: "id-E-RABToBeUpdatedList"}}}
}

// ERABToBeUpdatedList returns the typed binding for the ERABToBeUpdatedList row of PathSwitchRequestAcknowledgeIETable.
func (t PathSwitchRequestAcknowledgeIETable) ERABToBeUpdatedList() s46.PathSwitchRequestAcknowledgeERABToBeUpdatedListIEBinding {
	return func() s46.PathSwitchRequestAcknowledgeERABToBeUpdatedListIEBinding {
		sealed := s46.PathSwitchRequestAcknowledgeERABToBeUpdatedListIEBinding{}
		*s46.BridgePathSwitchRequestAcknowledgeERABToBeUpdatedListIEBindingFieldInfo(&sealed) = t.infoERABToBeUpdatedList()
		*s46.BridgePathSwitchRequestAcknowledgeERABToBeUpdatedListIEBindingFieldCodec(&sealed) = func() s29.ERABToBeUpdatedListValueCodec {
			sealed := s29.ERABToBeUpdatedListValueCodec{}
			*s29.BridgeERABToBeUpdatedListValueCodecFieldPath(&sealed) = "ERABToBeUpdatedList"
			*s29.BridgeERABToBeUpdatedListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s29.ERABToBeUpdatedList, error) {
				raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
				if err != nil {
					var empty s29.ERABToBeUpdatedList
					return empty, err
				}
				raw.BudgetBuffer().EnterComponent("ERABToBeUpdatedList")
				var zero s46.PathSwitchRequestAcknowledgeIEValue
				decoded, err := s46.BridgePathSwitchRequestAcknowledgeIEValueMethodDecode(zero, s00.ProtocolIEID(341), raw)
				if err != nil {
					var empty s29.ERABToBeUpdatedList
					return empty, runtime.WrapDecodePath(err, "ERABToBeUpdatedList")
				}
				value, ok := decoded.AsERABToBeUpdatedList()
				if !ok {
					var empty s29.ERABToBeUpdatedList
					return empty, fmt.Errorf("binding PathSwitchRequestAcknowledgeIEs.id-E-RABToBeUpdatedList: no selected value")
				}
				return *value, nil
			}
			*s29.BridgeERABToBeUpdatedListValueCodecFieldEncode(&sealed) = func(value s29.ERABToBeUpdatedList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
				return s46.BridgePathSwitchRequestAcknowledgeIEValueMethodEncodeFresh((func() s46.PathSwitchRequestAcknowledgeIEValue {
					sealed := s46.PathSwitchRequestAcknowledgeIEValue{}
					*s46.BridgePathSwitchRequestAcknowledgeIEValueFieldId(&sealed) = s00.ProtocolIEID(341)
					*s46.BridgePathSwitchRequestAcknowledgeIEValueFieldRowERABToBeUpdatedList(&sealed) = &value
					return sealed
				}()), fresh, budget)
			}
			*s29.BridgeERABToBeUpdatedListValueCodecFieldCapture(&sealed) = func(v s29.ERABToBeUpdatedList, options aper.DecodeState) (s29.ERABToBeUpdatedList, aper.Snapshot,
			) {
				s := aper.SemanticCaptureFor(options)
				f := s.Begin()
				s30.BridgeCaptureS1APERABToBeUpdatedList(&v, &s)
				var root aper.Snapshot
				s.End(f, &root, false)
				return v, root
			}
			*s29.BridgeERABToBeUpdatedListValueCodecFieldCompare(&sealed) = func(v s29.ERABToBeUpdatedList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
			) {
				s := aper.NewSemanticComparison(root, budget)
				f := s.Begin()
				s30.BridgeCompareS1APERABToBeUpdatedList(&v, &s)
				s.End(f, root, false)
				return s.Plan(), s.BudgetValue()
			}
			*s29.BridgeERABToBeUpdatedListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
				sealed := s00.BridgeCodecContext{}
				*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ERABToBeUpdatedList"
				*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
				return sealed
			}()
			return sealed
		}()
		*s46.BridgePathSwitchRequestAcknowledgeERABToBeUpdatedListIEBindingFieldInject(&sealed) = func(value s29.ERABToBeUpdatedList) s46.PathSwitchRequestAcknowledgeIEValue {
			return func() s46.PathSwitchRequestAcknowledgeIEValue {
				sealed := s46.PathSwitchRequestAcknowledgeIEValue{}
				*s46.BridgePathSwitchRequestAcknowledgeIEValueFieldId(&sealed) = s00.ProtocolIEID(341)
				*s46.BridgePathSwitchRequestAcknowledgeIEValueFieldRowERABToBeUpdatedList(&sealed) = &value
				return sealed
			}()
		}
		*s46.BridgePathSwitchRequestAcknowledgeERABToBeUpdatedListIEBindingFieldGet(&sealed) = func(value *s46.PathSwitchRequestAcknowledgeIEValue) (*s29.ERABToBeUpdatedList, bool) {
			return value.AsERABToBeUpdatedList()
		}
		return sealed
	}()
}
func (PathSwitchRequestAcknowledgeIETable) infoTimeRefDistribution() s00.FieldInfo {
	return s00.FieldInfo{Table: PathSwitchRequestAcknowledgeIEs().ID(), ID: s00.ProtocolIEID(355), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "TimeRefDistribution"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "PathSwitchRequestAcknowledgeIEs", Row: "id-TimeRefDistribution"}}}
}

// TimeRefDistribution returns the typed binding for the TimeRefDistribution row of PathSwitchRequestAcknowledgeIETable.
func (t PathSwitchRequestAcknowledgeIETable) TimeRefDistribution() s46.PathSwitchRequestAcknowledgeTimeRefDistributionIEBinding {
	return func() s46.PathSwitchRequestAcknowledgeTimeRefDistributionIEBinding {
		sealed := s46.PathSwitchRequestAcknowledgeTimeRefDistributionIEBinding{}
		*s46.BridgePathSwitchRequestAcknowledgeTimeRefDistributionIEBindingFieldInfo(&sealed) = t.infoTimeRefDistribution()
		*s46.BridgePathSwitchRequestAcknowledgeTimeRefDistributionIEBindingFieldCodec(&sealed) = func() s02.TimeRefDistributionValueCodec {
			sealed := s02.TimeRefDistributionValueCodec{}
			*s02.BridgeTimeRefDistributionValueCodecFieldPath(&sealed) = "TimeRefDistribution"
			*s02.BridgeTimeRefDistributionValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.TimeRefDistribution, error) {
				raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
				if err != nil {
					var empty s00.TimeRefDistribution
					return empty, err
				}
				raw.BudgetBuffer().EnterComponent("TimeRefDistribution")
				var zero s46.PathSwitchRequestAcknowledgeIEValue
				decoded, err := s46.BridgePathSwitchRequestAcknowledgeIEValueMethodDecode(zero, s00.ProtocolIEID(355), raw)
				if err != nil {
					var empty s00.TimeRefDistribution
					return empty, runtime.WrapDecodePath(err, "TimeRefDistribution")
				}
				value, ok := decoded.AsTimeRefDistribution()
				if !ok {
					var empty s00.TimeRefDistribution
					return empty, fmt.Errorf("binding PathSwitchRequestAcknowledgeIEs.id-TimeRefDistribution: no selected value")
				}
				return *value, nil
			}
			*s02.BridgeTimeRefDistributionValueCodecFieldEncode(&sealed) = func(value s00.TimeRefDistribution, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
				return s46.BridgePathSwitchRequestAcknowledgeIEValueMethodEncodeFresh((func() s46.PathSwitchRequestAcknowledgeIEValue {
					sealed := s46.PathSwitchRequestAcknowledgeIEValue{}
					*s46.BridgePathSwitchRequestAcknowledgeIEValueFieldId(&sealed) = s00.ProtocolIEID(355)
					*s46.BridgePathSwitchRequestAcknowledgeIEValueFieldRowTimeRefDistribution(&sealed) = &value
					return sealed
				}()), fresh, budget)
			}
			*s02.BridgeTimeRefDistributionValueCodecFieldCapture(&sealed) = func(v s00.TimeRefDistribution, options aper.DecodeState) (s00.TimeRefDistribution, aper.Snapshot,
			) {
				s := aper.SemanticCaptureFor(options)
				f := s.Begin()
				s00.BridgeCaptureS1APTimeRefDistribution(&v, &s)
				var root aper.Snapshot
				s.End(f, &root, false)
				return v, root
			}
			*s02.BridgeTimeRefDistributionValueCodecFieldCompare(&sealed) = func(v s00.TimeRefDistribution, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
			) {
				s := aper.NewSemanticComparison(root, budget)
				f := s.Begin()
				s07.BridgeCompareS1APTimeRefDistribution(&v, &s)
				s.End(f, root, false)
				return s.Plan(), s.BudgetValue()
			}
			*s02.BridgeTimeRefDistributionValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
				sealed := s00.BridgeCodecContext{}
				*s00.BridgecodecContextFieldSource(&sealed) = "source-value:TimeRefDistribution"
				*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
				return sealed
			}()
			return sealed
		}()
		*s46.BridgePathSwitchRequestAcknowledgeTimeRefDistributionIEBindingFieldInject(&sealed) = func(value s00.TimeRefDistribution) s46.PathSwitchRequestAcknowledgeIEValue {
			return func() s46.PathSwitchRequestAcknowledgeIEValue {
				sealed := s46.PathSwitchRequestAcknowledgeIEValue{}
				*s46.BridgePathSwitchRequestAcknowledgeIEValueFieldId(&sealed) = s00.ProtocolIEID(355)
				*s46.BridgePathSwitchRequestAcknowledgeIEValueFieldRowTimeRefDistribution(&sealed) = &value
				return sealed
			}()
		}
		*s46.BridgePathSwitchRequestAcknowledgeTimeRefDistributionIEBindingFieldGet(&sealed) = func(value *s46.PathSwitchRequestAcknowledgeIEValue) (*s00.TimeRefDistribution, bool) {
			return value.AsTimeRefDistribution()
		}
		return sealed
	}()
}

// NewOpaque constructs an owned opaque field for an identifier without a typed row in PathSwitchRequestAcknowledgeIETable.
func (t PathSwitchRequestAcknowledgeIETable) NewOpaque(id s00.ProtocolIEID, criticality s00.Criticality, data []byte) (s46.PathSwitchRequestAcknowledgeIEField, error) {
	if id < 0 || id > 65535 || criticality < 0 || criticality > 2 {
		return s46.PathSwitchRequestAcknowledgeIEField{}, aper.OperationError(fmt.Errorf("invalid opaque IE selector or criticality"), "Opaque")
	}
	switch id {
	case s00.ProtocolIEID(0):
		return s46.PathSwitchRequestAcknowledgeIEField{}, aper.OperationError(fmt.Errorf("known IE id-MME-UE-S1AP-ID requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(8):
		return s46.PathSwitchRequestAcknowledgeIEField{}, aper.OperationError(fmt.Errorf("known IE id-eNB-UE-S1AP-ID requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(66):
		return s46.PathSwitchRequestAcknowledgeIEField{}, aper.OperationError(fmt.Errorf("known IE id-uEaggregateMaximumBitrate requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(95):
		return s46.PathSwitchRequestAcknowledgeIEField{}, aper.OperationError(fmt.Errorf("known IE id-E-RABToBeSwitchedULList requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(33):
		return s46.PathSwitchRequestAcknowledgeIEField{}, aper.OperationError(fmt.Errorf("known IE id-E-RABToBeReleasedList requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(40):
		return s46.PathSwitchRequestAcknowledgeIEField{}, aper.OperationError(fmt.Errorf("known IE id-SecurityContext requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(58):
		return s46.PathSwitchRequestAcknowledgeIEField{}, aper.OperationError(fmt.Errorf("known IE id-CriticalityDiagnostics requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(158):
		return s46.PathSwitchRequestAcknowledgeIEField{}, aper.OperationError(fmt.Errorf("known IE id-MME-UE-S1AP-ID-2 requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(146):
		return s46.PathSwitchRequestAcknowledgeIEField{}, aper.OperationError(fmt.Errorf("known IE id-CSGMembershipStatus requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(195):
		return s46.PathSwitchRequestAcknowledgeIEField{}, aper.OperationError(fmt.Errorf("known IE id-ProSeAuthorized requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(241):
		return s46.PathSwitchRequestAcknowledgeIEField{}, aper.OperationError(fmt.Errorf("known IE id-UEUserPlaneCIoTSupportIndicator requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(240):
		return s46.PathSwitchRequestAcknowledgeIEField{}, aper.OperationError(fmt.Errorf("known IE id-V2XServicesAuthorized requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(248):
		return s46.PathSwitchRequestAcknowledgeIEField{}, aper.OperationError(fmt.Errorf("known IE id-UESidelinkAggregateMaximumBitrate requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(251):
		return s46.PathSwitchRequestAcknowledgeIEField{}, aper.OperationError(fmt.Errorf("known IE id-EnhancedCoverageRestricted requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(269):
		return s46.PathSwitchRequestAcknowledgeIEField{}, aper.OperationError(fmt.Errorf("known IE id-NRUESecurityCapabilities requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(271):
		return s46.PathSwitchRequestAcknowledgeIEField{}, aper.OperationError(fmt.Errorf("known IE id-CE-ModeBRestricted requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(277):
		return s46.PathSwitchRequestAcknowledgeIEField{}, aper.OperationError(fmt.Errorf("known IE id-AerialUEsubscriptionInformation requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(283):
		return s46.PathSwitchRequestAcknowledgeIEField{}, aper.OperationError(fmt.Errorf("known IE id-PendingDataIndication requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(278):
		return s46.PathSwitchRequestAcknowledgeIEField{}, aper.OperationError(fmt.Errorf("known IE id-Subscription-Based-UE-DifferentiationInfo requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(41):
		return s46.PathSwitchRequestAcknowledgeIEField{}, aper.OperationError(fmt.Errorf("known IE id-HandoverRestrictionList requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(299):
		return s46.PathSwitchRequestAcknowledgeIEField{}, aper.OperationError(fmt.Errorf("known IE id-AdditionalRRMPriorityIndex requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(306):
		return s46.PathSwitchRequestAcknowledgeIEField{}, aper.OperationError(fmt.Errorf("known IE id-NRV2XServicesAuthorized requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(307):
		return s46.PathSwitchRequestAcknowledgeIEField{}, aper.OperationError(fmt.Errorf("known IE id-NRUESidelinkAggregateMaximumBitrate requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(308):
		return s46.PathSwitchRequestAcknowledgeIEField{}, aper.OperationError(fmt.Errorf("known IE id-PC5QoSParameters requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(314):
		return s46.PathSwitchRequestAcknowledgeIEField{}, aper.OperationError(fmt.Errorf("known IE id-UERadioCapabilityID requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(107):
		return s46.PathSwitchRequestAcknowledgeIEField{}, aper.OperationError(fmt.Errorf("known IE id-UESecurityCapabilities requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(341):
		return s46.PathSwitchRequestAcknowledgeIEField{}, aper.OperationError(fmt.Errorf("known IE id-E-RABToBeUpdatedList requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(355):
		return s46.PathSwitchRequestAcknowledgeIEField{}, aper.OperationError(fmt.Errorf("known IE id-TimeRefDistribution requires its typed binding"), "Opaque")
	default:
		budget, err := aper.BuildBudget()
		if err != nil {
			return s46.PathSwitchRequestAcknowledgeIEField{}, aper.OperationError(err, "Opaque")
		}
		opaque, err := aper.BuildOpaqueOpenType(data, budget)
		if err != nil {
			return s46.PathSwitchRequestAcknowledgeIEField{}, aper.OperationError(err, "Opaque")
		}
		return s46.PathSwitchRequestAcknowledgeIEField{Id: id, Criticality: criticality, Value: func() s46.PathSwitchRequestAcknowledgeIEValue {
			sealed := s46.PathSwitchRequestAcknowledgeIEValue{}
			*s46.BridgePathSwitchRequestAcknowledgeIEValueFieldId(&sealed) = id
			*s46.BridgePathSwitchRequestAcknowledgeIEValueFieldOpaque(&sealed) = opaque
			*s46.BridgePathSwitchRequestAcknowledgeIEValueFieldIsOpaque(&sealed) = true
			return sealed
		}()}, aper.OperationError(nil, "Opaque")
	}
}

type UEContextModificationRequestIETable struct{}

func UEContextModificationRequestIEs() UEContextModificationRequestIETable {
	return UEContextModificationRequestIETable{}
}

// ID returns the ASN.1 object-set identity of UEContextModificationRequestIETable.
func (UEContextModificationRequestIETable) ID() s00.TableID {
	return func() s00.TableID {
		sealed := s00.TableID{}
		*s00.BridgeTableIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "UEContextModificationRequestIEs"}
		return sealed
	}()
}

// Table returns the ASN.1 object-set table described by UEContextModificationRequestIETable.
func (UEContextModificationRequestIETable) Table() s00.UEContextModificationRequestIEValueIETable {
	return func() s00.UEContextModificationRequestIEValueIETable {
		sealed := s00.UEContextModificationRequestIEValueIETable{}
		*s00.BridgeUEContextModificationRequestIEValueIETableFieldBound(&sealed) = true
		return sealed
	}()
}
func (UEContextModificationRequestIETable) infoMMEUES1APID() s00.FieldInfo {
	return s00.FieldInfo{Table: UEContextModificationRequestIEs().ID(), ID: s00.ProtocolIEID(0), Criticality: s00.CriticalityReject, Presence: s00.PresenceMandatory, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "MME-UE-S1AP-ID"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "UEContextModificationRequestIEs", Row: "id-MME-UE-S1AP-ID"}}}
}

// MMEUES1APID returns the typed binding for the MMEUES1APID row of UEContextModificationRequestIETable.
func (t UEContextModificationRequestIETable) MMEUES1APID() s46.UEContextModificationRequestMMEUES1APIDIEBinding {
	return func() s46.UEContextModificationRequestMMEUES1APIDIEBinding {
		sealed := s46.UEContextModificationRequestMMEUES1APIDIEBinding{}
		*s46.BridgeUEContextModificationRequestMMEUES1APIDIEBindingFieldInfo(&sealed) = t.infoMMEUES1APID()
		*s46.BridgeUEContextModificationRequestMMEUES1APIDIEBindingFieldCodec(&sealed) = func() s01.MMEUES1APIDValueCodec {
			sealed := s01.MMEUES1APIDValueCodec{}
			*s01.BridgeMMEUES1APIDValueCodecFieldPath(&sealed) = "MMEUES1APID"
			*s01.BridgeMMEUES1APIDValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.MMEUES1APID, error) {
				raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
				if err != nil {
					var empty s00.MMEUES1APID
					return empty, err
				}
				raw.BudgetBuffer().EnterComponent("MMEUES1APID")
				var zero s46.UEContextModificationRequestIEValue
				decoded, err := s46.BridgeUEContextModificationRequestIEValueMethodDecode(zero, s00.ProtocolIEID(0), raw)
				if err != nil {
					var empty s00.MMEUES1APID
					return empty, runtime.WrapDecodePath(err, "MMEUES1APID")
				}
				value, ok := decoded.AsMMEUES1APID()
				if !ok {
					var empty s00.MMEUES1APID
					return empty, fmt.Errorf("binding UEContextModificationRequestIEs.id-MME-UE-S1AP-ID: no selected value")
				}
				return *value, nil
			}
			*s01.BridgeMMEUES1APIDValueCodecFieldEncode(&sealed) = func(value s00.MMEUES1APID, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
				return s46.BridgeUEContextModificationRequestIEValueMethodEncodeFresh((func() s46.UEContextModificationRequestIEValue {
					sealed := s46.UEContextModificationRequestIEValue{}
					*s46.BridgeUEContextModificationRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(0)
					*s46.BridgeUEContextModificationRequestIEValueFieldRowMMEUES1APID(&sealed) = &value
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
		}()
		*s46.BridgeUEContextModificationRequestMMEUES1APIDIEBindingFieldInject(&sealed) = func(value s00.MMEUES1APID) s46.UEContextModificationRequestIEValue {
			return func() s46.UEContextModificationRequestIEValue {
				sealed := s46.UEContextModificationRequestIEValue{}
				*s46.BridgeUEContextModificationRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(0)
				*s46.BridgeUEContextModificationRequestIEValueFieldRowMMEUES1APID(&sealed) = &value
				return sealed
			}()
		}
		*s46.BridgeUEContextModificationRequestMMEUES1APIDIEBindingFieldGet(&sealed) = func(value *s46.UEContextModificationRequestIEValue) (*s00.MMEUES1APID, bool) {
			return value.AsMMEUES1APID()
		}
		return sealed
	}()
}
func (UEContextModificationRequestIETable) infoENBUES1APID() s00.FieldInfo {
	return s00.FieldInfo{Table: UEContextModificationRequestIEs().ID(), ID: s00.ProtocolIEID(8), Criticality: s00.CriticalityReject, Presence: s00.PresenceMandatory, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "ENB-UE-S1AP-ID"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "UEContextModificationRequestIEs", Row: "id-eNB-UE-S1AP-ID"}}}
}

// ENBUES1APID returns the typed binding for the ENBUES1APID row of UEContextModificationRequestIETable.
func (t UEContextModificationRequestIETable) ENBUES1APID() s46.UEContextModificationRequestENBUES1APIDIEBinding {
	return func() s46.UEContextModificationRequestENBUES1APIDIEBinding {
		sealed := s46.UEContextModificationRequestENBUES1APIDIEBinding{}
		*s46.BridgeUEContextModificationRequestENBUES1APIDIEBindingFieldInfo(&sealed) = t.infoENBUES1APID()
		*s46.BridgeUEContextModificationRequestENBUES1APIDIEBindingFieldCodec(&sealed) = func() s00.ENBUES1APIDValueCodec {
			sealed := s00.ENBUES1APIDValueCodec{}
			*s00.BridgeENBUES1APIDValueCodecFieldPath(&sealed) = "ENBUES1APID"
			*s00.BridgeENBUES1APIDValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.ENBUES1APID, error) {
				raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
				if err != nil {
					var empty s00.ENBUES1APID
					return empty, err
				}
				raw.BudgetBuffer().EnterComponent("ENBUES1APID")
				var zero s46.UEContextModificationRequestIEValue
				decoded, err := s46.BridgeUEContextModificationRequestIEValueMethodDecode(zero, s00.ProtocolIEID(8), raw)
				if err != nil {
					var empty s00.ENBUES1APID
					return empty, runtime.WrapDecodePath(err, "ENBUES1APID")
				}
				value, ok := decoded.AsENBUES1APID()
				if !ok {
					var empty s00.ENBUES1APID
					return empty, fmt.Errorf("binding UEContextModificationRequestIEs.id-eNB-UE-S1AP-ID: no selected value")
				}
				return *value, nil
			}
			*s00.BridgeENBUES1APIDValueCodecFieldEncode(&sealed) = func(value s00.ENBUES1APID, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
				return s46.BridgeUEContextModificationRequestIEValueMethodEncodeFresh((func() s46.UEContextModificationRequestIEValue {
					sealed := s46.UEContextModificationRequestIEValue{}
					*s46.BridgeUEContextModificationRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(8)
					*s46.BridgeUEContextModificationRequestIEValueFieldRowENBUES1APID(&sealed) = &value
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
		*s46.BridgeUEContextModificationRequestENBUES1APIDIEBindingFieldInject(&sealed) = func(value s00.ENBUES1APID) s46.UEContextModificationRequestIEValue {
			return func() s46.UEContextModificationRequestIEValue {
				sealed := s46.UEContextModificationRequestIEValue{}
				*s46.BridgeUEContextModificationRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(8)
				*s46.BridgeUEContextModificationRequestIEValueFieldRowENBUES1APID(&sealed) = &value
				return sealed
			}()
		}
		*s46.BridgeUEContextModificationRequestENBUES1APIDIEBindingFieldGet(&sealed) = func(value *s46.UEContextModificationRequestIEValue) (*s00.ENBUES1APID, bool) {
			return value.AsENBUES1APID()
		}
		return sealed
	}()
}
func (UEContextModificationRequestIETable) infoSecurityKey() s00.FieldInfo {
	return s00.FieldInfo{Table: UEContextModificationRequestIEs().ID(), ID: s00.ProtocolIEID(73), Criticality: s00.CriticalityReject, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "SecurityKey"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "UEContextModificationRequestIEs", Row: "id-SecurityKey"}}}
}

// SecurityKey returns the typed binding for the SecurityKey row of UEContextModificationRequestIETable.
func (t UEContextModificationRequestIETable) SecurityKey() s46.UEContextModificationRequestSecurityKeyIEBinding {
	return func() s46.UEContextModificationRequestSecurityKeyIEBinding {
		sealed := s46.UEContextModificationRequestSecurityKeyIEBinding{}
		*s46.BridgeUEContextModificationRequestSecurityKeyIEBindingFieldInfo(&sealed) = t.infoSecurityKey()
		*s46.BridgeUEContextModificationRequestSecurityKeyIEBindingFieldCodec(&sealed) = func() s01.SecurityKeyValueCodec {
			sealed := s01.SecurityKeyValueCodec{}
			*s01.BridgeSecurityKeyValueCodecFieldPath(&sealed) = "SecurityKey"
			*s01.BridgeSecurityKeyValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.SecurityKey, error) {
				raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
				if err != nil {
					var empty s00.SecurityKey
					return empty, err
				}
				raw.BudgetBuffer().EnterComponent("SecurityKey")
				var zero s46.UEContextModificationRequestIEValue
				decoded, err := s46.BridgeUEContextModificationRequestIEValueMethodDecode(zero, s00.ProtocolIEID(73), raw)
				if err != nil {
					var empty s00.SecurityKey
					return empty, runtime.WrapDecodePath(err, "SecurityKey")
				}
				value, ok := decoded.AsSecurityKey()
				if !ok {
					var empty s00.SecurityKey
					return empty, fmt.Errorf("binding UEContextModificationRequestIEs.id-SecurityKey: no selected value")
				}
				return *value, nil
			}
			*s01.BridgeSecurityKeyValueCodecFieldEncode(&sealed) = func(value s00.SecurityKey, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
				return s46.BridgeUEContextModificationRequestIEValueMethodEncodeFresh((func() s46.UEContextModificationRequestIEValue {
					sealed := s46.UEContextModificationRequestIEValue{}
					*s46.BridgeUEContextModificationRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(73)
					*s46.BridgeUEContextModificationRequestIEValueFieldRowSecurityKey(&sealed) = &value
					return sealed
				}()), fresh, budget)
			}
			*s01.BridgeSecurityKeyValueCodecFieldCapture(&sealed) = func(v s00.SecurityKey, options aper.DecodeState) (s00.SecurityKey, aper.Snapshot) {
				s := aper.SemanticCaptureFor(options)
				f := s.Begin()
				s00.BridgeCaptureS1APSecurityKey(&v, &s)
				var root aper.Snapshot

				s.End(f, &root, false)
				return v, root
			}
			*s01.BridgeSecurityKeyValueCodecFieldCompare(&sealed) = func(v s00.SecurityKey, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
				s := aper.NewSemanticComparison(root, budget)
				f := s.Begin()
				s07.BridgeCompareS1APSecurityKey(&v, &s)
				s.End(f, root, false)
				return s.Plan(), s.
					BudgetValue()
			}
			*s01.BridgeSecurityKeyValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
				sealed := s00.BridgeCodecContext{}
				*s00.BridgecodecContextFieldSource(&sealed) = "source-value:SecurityKey"
				*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
				return sealed
			}()
			return sealed
		}()
		*s46.BridgeUEContextModificationRequestSecurityKeyIEBindingFieldInject(&sealed) = func(value s00.SecurityKey) s46.UEContextModificationRequestIEValue {
			return func() s46.UEContextModificationRequestIEValue {
				sealed := s46.UEContextModificationRequestIEValue{}
				*s46.BridgeUEContextModificationRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(73)
				*s46.BridgeUEContextModificationRequestIEValueFieldRowSecurityKey(&sealed) = &value
				return sealed
			}()
		}
		*s46.BridgeUEContextModificationRequestSecurityKeyIEBindingFieldGet(&sealed) = func(value *s46.UEContextModificationRequestIEValue) (*s00.SecurityKey, bool) {
			return value.AsSecurityKey()
		}
		return sealed
	}()
}
func (UEContextModificationRequestIETable) infoSubscriberProfileIDforRFP() s00.FieldInfo {
	return s00.FieldInfo{Table: UEContextModificationRequestIEs().ID(), ID: s00.ProtocolIEID(106), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "SubscriberProfileIDforRFP"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "UEContextModificationRequestIEs", Row: "id-SubscriberProfileIDforRFP"}}}
}

// SubscriberProfileIDforRFP returns the typed binding for the SubscriberProfileIDforRFP row of UEContextModificationRequestIETable.
func (t UEContextModificationRequestIETable) SubscriberProfileIDforRFP() s46.UEContextModificationRequestSubscriberProfileIDforRFPIEBinding {
	return func() s46.UEContextModificationRequestSubscriberProfileIDforRFPIEBinding {
		sealed := s46.UEContextModificationRequestSubscriberProfileIDforRFPIEBinding{}
		*s46.BridgeUEContextModificationRequestSubscriberProfileIDforRFPIEBindingFieldInfo(&sealed) = t.infoSubscriberProfileIDforRFP()
		*s46.BridgeUEContextModificationRequestSubscriberProfileIDforRFPIEBindingFieldCodec(&sealed) = func() s01.SubscriberProfileIDforRFPValueCodec {
			sealed := s01.SubscriberProfileIDforRFPValueCodec{}
			*s01.BridgeSubscriberProfileIDforRFPValueCodecFieldPath(&sealed) = "SubscriberProfileIDforRFP"
			*s01.BridgeSubscriberProfileIDforRFPValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.SubscriberProfileIDforRFP, error) {
				raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
				if err != nil {
					var empty s00.SubscriberProfileIDforRFP
					return empty, err
				}
				raw.BudgetBuffer().EnterComponent("SubscriberProfileIDforRFP")
				var zero s46.UEContextModificationRequestIEValue
				decoded, err := s46.BridgeUEContextModificationRequestIEValueMethodDecode(zero, s00.ProtocolIEID(106), raw)
				if err != nil {
					var empty s00.SubscriberProfileIDforRFP
					return empty, runtime.WrapDecodePath(err, "SubscriberProfileIDforRFP")
				}
				value, ok := decoded.AsSubscriberProfileIDforRFP()
				if !ok {
					var empty s00.SubscriberProfileIDforRFP
					return empty, fmt.Errorf("binding UEContextModificationRequestIEs.id-SubscriberProfileIDforRFP: no selected value")
				}
				return *value, nil
			}
			*s01.BridgeSubscriberProfileIDforRFPValueCodecFieldEncode(&sealed) = func(value s00.SubscriberProfileIDforRFP, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
				return s46.BridgeUEContextModificationRequestIEValueMethodEncodeFresh((func() s46.UEContextModificationRequestIEValue {
					sealed := s46.UEContextModificationRequestIEValue{}
					*s46.BridgeUEContextModificationRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(106)
					*s46.BridgeUEContextModificationRequestIEValueFieldRowSubscriberProfileIDforRFP(&sealed) = &value
					return sealed
				}()), fresh, budget)
			}
			*s01.BridgeSubscriberProfileIDforRFPValueCodecFieldCapture(&sealed) = func(v s00.SubscriberProfileIDforRFP, options aper.DecodeState) (s00.SubscriberProfileIDforRFP, aper.Snapshot) {
				s := aper.SemanticCaptureFor(options)
				f := s.Begin()
				s00.BridgeCaptureS1APSubscriberProfileIDforRFP(&v, &s)
				var root aper.Snapshot
				s.End(
					f,
					&root, false)
				return v, root
			}
			*s01.BridgeSubscriberProfileIDforRFPValueCodecFieldCompare(&sealed) = func(v s00.SubscriberProfileIDforRFP, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

			) {
				s := aper.NewSemanticComparison(root, budget)
				f := s.Begin()
				s07.BridgeCompareS1APSubscriberProfileIDforRFP(&v, &s)
				s.End(f, root,

					false)
				return s.Plan(), s.BudgetValue()
			}
			*s01.BridgeSubscriberProfileIDforRFPValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
				sealed := s00.BridgeCodecContext{}
				*s00.BridgecodecContextFieldSource(&sealed) = "source-value:SubscriberProfileIDforRFP"
				*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
				return sealed
			}()
			return sealed
		}()
		*s46.BridgeUEContextModificationRequestSubscriberProfileIDforRFPIEBindingFieldInject(&sealed) = func(value s00.SubscriberProfileIDforRFP) s46.UEContextModificationRequestIEValue {
			return func() s46.UEContextModificationRequestIEValue {
				sealed := s46.UEContextModificationRequestIEValue{}
				*s46.BridgeUEContextModificationRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(106)
				*s46.BridgeUEContextModificationRequestIEValueFieldRowSubscriberProfileIDforRFP(&sealed) = &value
				return sealed
			}()
		}
		*s46.BridgeUEContextModificationRequestSubscriberProfileIDforRFPIEBindingFieldGet(&sealed) = func(value *s46.UEContextModificationRequestIEValue) (*s00.SubscriberProfileIDforRFP, bool) {
			return value.AsSubscriberProfileIDforRFP()
		}
		return sealed
	}()
}
func (UEContextModificationRequestIETable) infoUEaggregateMaximumBitrate() s00.FieldInfo {
	return s00.FieldInfo{Table: UEContextModificationRequestIEs().ID(), ID: s00.ProtocolIEID(66), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "UEAggregateMaximumBitrate"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "UEContextModificationRequestIEs", Row: "id-uEaggregateMaximumBitrate"}}}
}

// UEaggregateMaximumBitrate returns the typed binding for the UEaggregateMaximumBitrate row of UEContextModificationRequestIETable.
func (t UEContextModificationRequestIETable) UEaggregateMaximumBitrate() s46.UEContextModificationRequestUEAggregateMaximumBitrateIEBinding {
	return func() s46.UEContextModificationRequestUEAggregateMaximumBitrateIEBinding {
		sealed := s46.UEContextModificationRequestUEAggregateMaximumBitrateIEBinding{}
		*s46.BridgeUEContextModificationRequestUEAggregateMaximumBitrateIEBindingFieldInfo(&sealed) = t.infoUEaggregateMaximumBitrate()
		*s46.BridgeUEContextModificationRequestUEAggregateMaximumBitrateIEBindingFieldCodec(&sealed) = func() s35.UEAggregateMaximumBitrateValueCodec {
			sealed := s35.UEAggregateMaximumBitrateValueCodec{}
			*s35.BridgeUEAggregateMaximumBitrateValueCodecFieldPath(&sealed) = "UEAggregateMaximumBitrate"
			*s35.BridgeUEAggregateMaximumBitrateValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s35.UEAggregateMaximumBitrate, error) {
				raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
				if err != nil {
					var empty s35.UEAggregateMaximumBitrate
					return empty, err
				}
				raw.BudgetBuffer().EnterComponent("UEAggregateMaximumBitrate")
				var zero s46.UEContextModificationRequestIEValue
				decoded, err := s46.BridgeUEContextModificationRequestIEValueMethodDecode(zero, s00.ProtocolIEID(66), raw)
				if err != nil {
					var empty s35.UEAggregateMaximumBitrate
					return empty, runtime.WrapDecodePath(err, "UEAggregateMaximumBitrate")
				}
				value, ok := decoded.AsUEaggregateMaximumBitrate()
				if !ok {
					var empty s35.UEAggregateMaximumBitrate
					return empty, fmt.Errorf("binding UEContextModificationRequestIEs.id-uEaggregateMaximumBitrate: no selected value")
				}
				return *value, nil
			}
			*s35.BridgeUEAggregateMaximumBitrateValueCodecFieldEncode(&sealed) = func(value s35.UEAggregateMaximumBitrate, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
				return s46.BridgeUEContextModificationRequestIEValueMethodEncodeFresh((func() s46.UEContextModificationRequestIEValue {
					sealed := s46.UEContextModificationRequestIEValue{}
					*s46.BridgeUEContextModificationRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(66)
					*s46.BridgeUEContextModificationRequestIEValueFieldRowUEaggregateMaximumBitrate(&sealed) = &value
					return sealed
				}()), fresh, budget)
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
		}()
		*s46.BridgeUEContextModificationRequestUEAggregateMaximumBitrateIEBindingFieldInject(&sealed) = func(value s35.UEAggregateMaximumBitrate) s46.UEContextModificationRequestIEValue {
			return func() s46.UEContextModificationRequestIEValue {
				sealed := s46.UEContextModificationRequestIEValue{}
				*s46.BridgeUEContextModificationRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(66)
				*s46.BridgeUEContextModificationRequestIEValueFieldRowUEaggregateMaximumBitrate(&sealed) = &value
				return sealed
			}()
		}
		*s46.BridgeUEContextModificationRequestUEAggregateMaximumBitrateIEBindingFieldGet(&sealed) = func(value *s46.UEContextModificationRequestIEValue) (*s35.UEAggregateMaximumBitrate, bool) {
			return value.AsUEaggregateMaximumBitrate()
		}
		return sealed
	}()
}
func (UEContextModificationRequestIETable) infoCSFallbackIndicator() s00.FieldInfo {
	return s00.FieldInfo{Table: UEContextModificationRequestIEs().ID(), ID: s00.ProtocolIEID(108), Criticality: s00.CriticalityReject, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "CSFallbackIndicator"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "UEContextModificationRequestIEs", Row: "id-CSFallbackIndicator"}}}
}

// CSFallbackIndicator returns the typed binding for the CSFallbackIndicator row of UEContextModificationRequestIETable.
func (t UEContextModificationRequestIETable) CSFallbackIndicator() s46.UEContextModificationRequestCSFallbackIndicatorIEBinding {
	return func() s46.UEContextModificationRequestCSFallbackIndicatorIEBinding {
		sealed := s46.UEContextModificationRequestCSFallbackIndicatorIEBinding{}
		*s46.BridgeUEContextModificationRequestCSFallbackIndicatorIEBindingFieldInfo(&sealed) = t.infoCSFallbackIndicator()
		*s46.BridgeUEContextModificationRequestCSFallbackIndicatorIEBindingFieldCodec(&sealed) = func() s00.CSFallbackIndicatorValueCodec {
			sealed := s00.CSFallbackIndicatorValueCodec{}
			*s00.BridgeCSFallbackIndicatorValueCodecFieldPath(&sealed) = "CSFallbackIndicator"
			*s00.BridgeCSFallbackIndicatorValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.CSFallbackIndicator, error) {
				raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
				if err != nil {
					var empty s00.CSFallbackIndicator
					return empty, err
				}
				raw.BudgetBuffer().EnterComponent("CSFallbackIndicator")
				var zero s46.UEContextModificationRequestIEValue
				decoded, err := s46.BridgeUEContextModificationRequestIEValueMethodDecode(zero, s00.ProtocolIEID(108), raw)
				if err != nil {
					var empty s00.CSFallbackIndicator
					return empty, runtime.WrapDecodePath(err, "CSFallbackIndicator")
				}
				value, ok := decoded.AsCSFallbackIndicator()
				if !ok {
					var empty s00.CSFallbackIndicator
					return empty, fmt.Errorf("binding UEContextModificationRequestIEs.id-CSFallbackIndicator: no selected value")
				}
				return *value, nil
			}
			*s00.BridgeCSFallbackIndicatorValueCodecFieldEncode(&sealed) = func(value s00.CSFallbackIndicator, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
				return s46.BridgeUEContextModificationRequestIEValueMethodEncodeFresh((func() s46.UEContextModificationRequestIEValue {
					sealed := s46.UEContextModificationRequestIEValue{}
					*s46.BridgeUEContextModificationRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(108)
					*s46.BridgeUEContextModificationRequestIEValueFieldRowCSFallbackIndicator(&sealed) = &value
					return sealed
				}()), fresh, budget)
			}
			*s00.BridgeCSFallbackIndicatorValueCodecFieldCapture(&sealed) = func(v s00.CSFallbackIndicator, options aper.DecodeState) (s00.CSFallbackIndicator, aper.Snapshot,
			) {
				s := aper.SemanticCaptureFor(options)
				f := s.Begin()
				s00.BridgeCaptureS1APCSFallbackIndicator(&v, &s)
				var root aper.Snapshot
				s.End(f, &root, false)
				return v, root
			}
			*s00.BridgeCSFallbackIndicatorValueCodecFieldCompare(&sealed) = func(v s00.CSFallbackIndicator, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
			) {
				s := aper.NewSemanticComparison(root, budget)
				f := s.Begin()
				s02.BridgeCompareS1APCSFallbackIndicator(&v, &s)
				s.End(f, root, false)
				return s.Plan(), s.BudgetValue()
			}
			*s00.BridgeCSFallbackIndicatorValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
				sealed := s00.BridgeCodecContext{}
				*s00.BridgecodecContextFieldSource(&sealed) = "source-value:CSFallbackIndicator"
				*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
				return sealed
			}()
			return sealed
		}()
		*s46.BridgeUEContextModificationRequestCSFallbackIndicatorIEBindingFieldInject(&sealed) = func(value s00.CSFallbackIndicator) s46.UEContextModificationRequestIEValue {
			return func() s46.UEContextModificationRequestIEValue {
				sealed := s46.UEContextModificationRequestIEValue{}
				*s46.BridgeUEContextModificationRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(108)
				*s46.BridgeUEContextModificationRequestIEValueFieldRowCSFallbackIndicator(&sealed) = &value
				return sealed
			}()
		}
		*s46.BridgeUEContextModificationRequestCSFallbackIndicatorIEBindingFieldGet(&sealed) = func(value *s46.UEContextModificationRequestIEValue) (*s00.CSFallbackIndicator, bool) {
			return value.AsCSFallbackIndicator()
		}
		return sealed
	}()
}
func (UEContextModificationRequestIETable) infoUESecurityCapabilities() s00.FieldInfo {
	return s00.FieldInfo{Table: UEContextModificationRequestIEs().ID(), ID: s00.ProtocolIEID(107), Criticality: s00.CriticalityReject, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "UESecurityCapabilities"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "UEContextModificationRequestIEs", Row: "id-UESecurityCapabilities"}}}
}

// UESecurityCapabilities returns the typed binding for the UESecurityCapabilities row of UEContextModificationRequestIETable.
func (t UEContextModificationRequestIETable) UESecurityCapabilities() s46.UEContextModificationRequestUESecurityCapabilitiesIEBinding {
	return func() s46.UEContextModificationRequestUESecurityCapabilitiesIEBinding {
		sealed := s46.UEContextModificationRequestUESecurityCapabilitiesIEBinding{}
		*s46.BridgeUEContextModificationRequestUESecurityCapabilitiesIEBindingFieldInfo(&sealed) = t.infoUESecurityCapabilities()
		*s46.BridgeUEContextModificationRequestUESecurityCapabilitiesIEBindingFieldCodec(&sealed) = func() s37.UESecurityCapabilitiesValueCodec {
			sealed := s37.UESecurityCapabilitiesValueCodec{}
			*s37.BridgeUESecurityCapabilitiesValueCodecFieldPath(&sealed) = "UESecurityCapabilities"
			*s37.BridgeUESecurityCapabilitiesValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s37.UESecurityCapabilities, error) {
				raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
				if err != nil {
					var empty s37.UESecurityCapabilities
					return empty, err
				}
				raw.BudgetBuffer().EnterComponent("UESecurityCapabilities")
				var zero s46.UEContextModificationRequestIEValue
				decoded, err := s46.BridgeUEContextModificationRequestIEValueMethodDecode(zero, s00.ProtocolIEID(107), raw)
				if err != nil {
					var empty s37.UESecurityCapabilities
					return empty, runtime.WrapDecodePath(err, "UESecurityCapabilities")
				}
				value, ok := decoded.AsUESecurityCapabilities()
				if !ok {
					var empty s37.UESecurityCapabilities
					return empty, fmt.Errorf("binding UEContextModificationRequestIEs.id-UESecurityCapabilities: no selected value")
				}
				return *value, nil
			}
			*s37.BridgeUESecurityCapabilitiesValueCodecFieldEncode(&sealed) = func(value s37.UESecurityCapabilities, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
				return s46.BridgeUEContextModificationRequestIEValueMethodEncodeFresh((func() s46.UEContextModificationRequestIEValue {
					sealed := s46.UEContextModificationRequestIEValue{}
					*s46.BridgeUEContextModificationRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(107)
					*s46.BridgeUEContextModificationRequestIEValueFieldRowUESecurityCapabilities(&sealed) = &value
					return sealed
				}()), fresh, budget)
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
		}()
		*s46.BridgeUEContextModificationRequestUESecurityCapabilitiesIEBindingFieldInject(&sealed) = func(value s37.UESecurityCapabilities) s46.UEContextModificationRequestIEValue {
			return func() s46.UEContextModificationRequestIEValue {
				sealed := s46.UEContextModificationRequestIEValue{}
				*s46.BridgeUEContextModificationRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(107)
				*s46.BridgeUEContextModificationRequestIEValueFieldRowUESecurityCapabilities(&sealed) = &value
				return sealed
			}()
		}
		*s46.BridgeUEContextModificationRequestUESecurityCapabilitiesIEBindingFieldGet(&sealed) = func(value *s46.UEContextModificationRequestIEValue) (*s37.UESecurityCapabilities, bool) {
			return value.AsUESecurityCapabilities()
		}
		return sealed
	}()
}
func (UEContextModificationRequestIETable) infoCSGMembershipStatus() s00.FieldInfo {
	return s00.FieldInfo{Table: UEContextModificationRequestIEs().ID(), ID: s00.ProtocolIEID(146), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "CSGMembershipStatus"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "UEContextModificationRequestIEs", Row: "id-CSGMembershipStatus"}}}
}

// CSGMembershipStatus returns the typed binding for the CSGMembershipStatus row of UEContextModificationRequestIETable.
func (t UEContextModificationRequestIETable) CSGMembershipStatus() s46.UEContextModificationRequestCSGMembershipStatusIEBinding {
	return func() s46.UEContextModificationRequestCSGMembershipStatusIEBinding {
		sealed := s46.UEContextModificationRequestCSGMembershipStatusIEBinding{}
		*s46.BridgeUEContextModificationRequestCSGMembershipStatusIEBindingFieldInfo(&sealed) = t.infoCSGMembershipStatus()
		*s46.BridgeUEContextModificationRequestCSGMembershipStatusIEBindingFieldCodec(&sealed) = func() s00.CSGMembershipStatusValueCodec {
			sealed := s00.CSGMembershipStatusValueCodec{}
			*s00.BridgeCSGMembershipStatusValueCodecFieldPath(&sealed) = "CSGMembershipStatus"
			*s00.BridgeCSGMembershipStatusValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.CSGMembershipStatus, error) {
				raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
				if err != nil {
					var empty s00.CSGMembershipStatus
					return empty, err
				}
				raw.BudgetBuffer().EnterComponent("CSGMembershipStatus")
				var zero s46.UEContextModificationRequestIEValue
				decoded, err := s46.BridgeUEContextModificationRequestIEValueMethodDecode(zero, s00.ProtocolIEID(146), raw)
				if err != nil {
					var empty s00.CSGMembershipStatus
					return empty, runtime.WrapDecodePath(err, "CSGMembershipStatus")
				}
				value, ok := decoded.AsCSGMembershipStatus()
				if !ok {
					var empty s00.CSGMembershipStatus
					return empty, fmt.Errorf("binding UEContextModificationRequestIEs.id-CSGMembershipStatus: no selected value")
				}
				return *value, nil
			}
			*s00.BridgeCSGMembershipStatusValueCodecFieldEncode(&sealed) = func(value s00.CSGMembershipStatus, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
				return s46.BridgeUEContextModificationRequestIEValueMethodEncodeFresh((func() s46.UEContextModificationRequestIEValue {
					sealed := s46.UEContextModificationRequestIEValue{}
					*s46.BridgeUEContextModificationRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(146)
					*s46.BridgeUEContextModificationRequestIEValueFieldRowCSGMembershipStatus(&sealed) = &value
					return sealed
				}()), fresh, budget)
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
		}()
		*s46.BridgeUEContextModificationRequestCSGMembershipStatusIEBindingFieldInject(&sealed) = func(value s00.CSGMembershipStatus) s46.UEContextModificationRequestIEValue {
			return func() s46.UEContextModificationRequestIEValue {
				sealed := s46.UEContextModificationRequestIEValue{}
				*s46.BridgeUEContextModificationRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(146)
				*s46.BridgeUEContextModificationRequestIEValueFieldRowCSGMembershipStatus(&sealed) = &value
				return sealed
			}()
		}
		*s46.BridgeUEContextModificationRequestCSGMembershipStatusIEBindingFieldGet(&sealed) = func(value *s46.UEContextModificationRequestIEValue) (*s00.CSGMembershipStatus, bool) {
			return value.AsCSGMembershipStatus()
		}
		return sealed
	}()
}
func (UEContextModificationRequestIETable) infoRegisteredLAI() s00.FieldInfo {
	return s00.FieldInfo{Table: UEContextModificationRequestIEs().ID(), ID: s00.ProtocolIEID(159), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "LAI"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "UEContextModificationRequestIEs", Row: "id-RegisteredLAI"}}}
}

// RegisteredLAI returns the typed binding for the RegisteredLAI row of UEContextModificationRequestIETable.
func (t UEContextModificationRequestIETable) RegisteredLAI() s46.UEContextModificationRequestLAIIEBinding {
	return func() s46.UEContextModificationRequestLAIIEBinding {
		sealed := s46.UEContextModificationRequestLAIIEBinding{}
		*s46.BridgeUEContextModificationRequestLAIIEBindingFieldInfo(&sealed) = t.infoRegisteredLAI()
		*s46.BridgeUEContextModificationRequestLAIIEBindingFieldCodec(&sealed) = func() s18.LAIValueCodec {
			sealed := s18.LAIValueCodec{}
			*s18.BridgeLAIValueCodecFieldPath(&sealed) = "LAI"
			*s18.BridgeLAIValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s18.LAI, error) {
				raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
				if err != nil {
					var empty s18.LAI
					return empty, err
				}
				raw.BudgetBuffer().EnterComponent("LAI")
				var zero s46.UEContextModificationRequestIEValue
				decoded, err := s46.BridgeUEContextModificationRequestIEValueMethodDecode(zero, s00.ProtocolIEID(159), raw)
				if err != nil {
					var empty s18.LAI
					return empty, runtime.WrapDecodePath(err, "LAI")
				}
				value, ok := decoded.AsRegisteredLAI()
				if !ok {
					var empty s18.LAI
					return empty, fmt.Errorf("binding UEContextModificationRequestIEs.id-RegisteredLAI: no selected value")
				}
				return *value, nil
			}
			*s18.BridgeLAIValueCodecFieldEncode(&sealed) = func(value s18.LAI, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
				return s46.BridgeUEContextModificationRequestIEValueMethodEncodeFresh((func() s46.UEContextModificationRequestIEValue {
					sealed := s46.UEContextModificationRequestIEValue{}
					*s46.BridgeUEContextModificationRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(159)
					*s46.BridgeUEContextModificationRequestIEValueFieldRowRegisteredLAI(&sealed) = &value
					return sealed
				}()), fresh, budget)
			}
			*s18.BridgeLAIValueCodecFieldCapture(&sealed) = func(v s18.LAI, options aper.DecodeState) (s18.LAI, aper.Snapshot) {
				s := aper.SemanticCaptureFor(options)
				f := s.Begin()
				s18.BridgeCaptureS1APLAI(&v, &s)
				var root aper.Snapshot
				s.End(f, &root,
					false)
				return v, root
			}
			*s18.BridgeLAIValueCodecFieldCompare(&sealed) = func(v s18.LAI, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
				s := aper.NewSemanticComparison(root, budget)
				f := s.Begin()
				s18.BridgeCompareS1APLAI(&v, &s)
				s.End(f, root, false)
				return s.Plan(), s.BudgetValue()
			}
			*s18.BridgeLAIValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
				sealed := s00.BridgeCodecContext{}
				*s00.BridgecodecContextFieldSource(&sealed) = "source-value:LAI"
				*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
				return sealed
			}()
			return sealed
		}()
		*s46.BridgeUEContextModificationRequestLAIIEBindingFieldInject(&sealed) = func(value s18.LAI) s46.UEContextModificationRequestIEValue {
			return func() s46.UEContextModificationRequestIEValue {
				sealed := s46.UEContextModificationRequestIEValue{}
				*s46.BridgeUEContextModificationRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(159)
				*s46.BridgeUEContextModificationRequestIEValueFieldRowRegisteredLAI(&sealed) = &value
				return sealed
			}()
		}
		*s46.BridgeUEContextModificationRequestLAIIEBindingFieldGet(&sealed) = func(value *s46.UEContextModificationRequestIEValue) (*s18.LAI, bool) { return value.AsRegisteredLAI() }
		return sealed
	}()
}
func (UEContextModificationRequestIETable) infoAdditionalCSFallbackIndicator() s00.FieldInfo {
	return s00.FieldInfo{Table: UEContextModificationRequestIEs().ID(), ID: s00.ProtocolIEID(187), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceConditional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "AdditionalCSFallbackIndicator"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "UEContextModificationRequestIEs", Row: "id-AdditionalCSFallbackIndicator"}}}
}

// AdditionalCSFallbackIndicator returns the typed binding for the AdditionalCSFallbackIndicator row of UEContextModificationRequestIETable.
func (t UEContextModificationRequestIETable) AdditionalCSFallbackIndicator() s46.UEContextModificationRequestAdditionalCSFallbackIndicatorIEBinding {
	return func() s46.UEContextModificationRequestAdditionalCSFallbackIndicatorIEBinding {
		sealed := s46.UEContextModificationRequestAdditionalCSFallbackIndicatorIEBinding{}
		*s46.BridgeUEContextModificationRequestAdditionalCSFallbackIndicatorIEBindingFieldInfo(&sealed) = t.infoAdditionalCSFallbackIndicator()
		*s46.BridgeUEContextModificationRequestAdditionalCSFallbackIndicatorIEBindingFieldCodec(&sealed) = func() s00.AdditionalCSFallbackIndicatorValueCodec {
			sealed := s00.AdditionalCSFallbackIndicatorValueCodec{}
			*s00.BridgeAdditionalCSFallbackIndicatorValueCodecFieldPath(&sealed) = "AdditionalCSFallbackIndicator"
			*s00.BridgeAdditionalCSFallbackIndicatorValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.AdditionalCSFallbackIndicator, error) {
				raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
				if err != nil {
					var empty s00.AdditionalCSFallbackIndicator
					return empty, err
				}
				raw.BudgetBuffer().EnterComponent("AdditionalCSFallbackIndicator")
				var zero s46.UEContextModificationRequestIEValue
				decoded, err := s46.BridgeUEContextModificationRequestIEValueMethodDecode(zero, s00.ProtocolIEID(187), raw)
				if err != nil {
					var empty s00.AdditionalCSFallbackIndicator
					return empty, runtime.WrapDecodePath(err, "AdditionalCSFallbackIndicator")
				}
				value, ok := decoded.AsAdditionalCSFallbackIndicator()
				if !ok {
					var empty s00.AdditionalCSFallbackIndicator
					return empty, fmt.Errorf("binding UEContextModificationRequestIEs.id-AdditionalCSFallbackIndicator: no selected value")
				}
				return *value, nil
			}
			*s00.BridgeAdditionalCSFallbackIndicatorValueCodecFieldEncode(&sealed) = func(value s00.AdditionalCSFallbackIndicator, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
				return s46.BridgeUEContextModificationRequestIEValueMethodEncodeFresh((func() s46.UEContextModificationRequestIEValue {
					sealed := s46.UEContextModificationRequestIEValue{}
					*s46.BridgeUEContextModificationRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(187)
					*s46.BridgeUEContextModificationRequestIEValueFieldRowAdditionalCSFallbackIndicator(&sealed) = &value
					return sealed
				}()), fresh, budget)
			}
			*s00.BridgeAdditionalCSFallbackIndicatorValueCodecFieldCapture(&sealed) = func(v s00.AdditionalCSFallbackIndicator, options aper.DecodeState) (s00.AdditionalCSFallbackIndicator, aper.Snapshot,

			) {
				s := aper.SemanticCaptureFor(options)
				f := s.Begin()
				s00.BridgeCaptureS1APAdditionalCSFallbackIndicator(&v, &s)
				var root aper.Snapshot

				s.End(f, &root, false)
				return v, root
			}
			*s00.BridgeAdditionalCSFallbackIndicatorValueCodecFieldCompare(&sealed) = func(v s00.AdditionalCSFallbackIndicator, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
			) {
				s := aper.NewSemanticComparison(root, budget)
				f :=
					s.Begin()
				s02.BridgeCompareS1APAdditionalCSFallbackIndicator(&v, &s)
				s.
					End(f, root, false)
				return s.Plan(), s.BudgetValue()
			}
			*s00.BridgeAdditionalCSFallbackIndicatorValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
				sealed := s00.BridgeCodecContext{}
				*s00.BridgecodecContextFieldSource(&sealed) = "source-value:AdditionalCSFallbackIndicator"
				*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
				return sealed
			}()
			return sealed
		}()
		*s46.BridgeUEContextModificationRequestAdditionalCSFallbackIndicatorIEBindingFieldInject(&sealed) = func(value s00.AdditionalCSFallbackIndicator) s46.UEContextModificationRequestIEValue {
			return func() s46.UEContextModificationRequestIEValue {
				sealed := s46.UEContextModificationRequestIEValue{}
				*s46.BridgeUEContextModificationRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(187)
				*s46.BridgeUEContextModificationRequestIEValueFieldRowAdditionalCSFallbackIndicator(&sealed) = &value
				return sealed
			}()
		}
		*s46.BridgeUEContextModificationRequestAdditionalCSFallbackIndicatorIEBindingFieldGet(&sealed) = func(value *s46.UEContextModificationRequestIEValue) (*s00.AdditionalCSFallbackIndicator, bool) {
			return value.AsAdditionalCSFallbackIndicator()
		}
		return sealed
	}()
}
func (UEContextModificationRequestIETable) infoProSeAuthorized() s00.FieldInfo {
	return s00.FieldInfo{Table: UEContextModificationRequestIEs().ID(), ID: s00.ProtocolIEID(195), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "ProSeAuthorized"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "UEContextModificationRequestIEs", Row: "id-ProSeAuthorized"}}}
}

// ProSeAuthorized returns the typed binding for the ProSeAuthorized row of UEContextModificationRequestIETable.
func (t UEContextModificationRequestIETable) ProSeAuthorized() s46.UEContextModificationRequestProSeAuthorizedIEBinding {
	return func() s46.UEContextModificationRequestProSeAuthorizedIEBinding {
		sealed := s46.UEContextModificationRequestProSeAuthorizedIEBinding{}
		*s46.BridgeUEContextModificationRequestProSeAuthorizedIEBindingFieldInfo(&sealed) = t.infoProSeAuthorized()
		*s46.BridgeUEContextModificationRequestProSeAuthorizedIEBindingFieldCodec(&sealed) = func() s20.ProSeAuthorizedValueCodec {
			sealed := s20.ProSeAuthorizedValueCodec{}
			*s20.BridgeProSeAuthorizedValueCodecFieldPath(&sealed) = "ProSeAuthorized"
			*s20.BridgeProSeAuthorizedValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s20.ProSeAuthorized, error) {
				raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
				if err != nil {
					var empty s20.ProSeAuthorized
					return empty, err
				}
				raw.BudgetBuffer().EnterComponent("ProSeAuthorized")
				var zero s46.UEContextModificationRequestIEValue
				decoded, err := s46.BridgeUEContextModificationRequestIEValueMethodDecode(zero, s00.ProtocolIEID(195), raw)
				if err != nil {
					var empty s20.ProSeAuthorized
					return empty, runtime.WrapDecodePath(err, "ProSeAuthorized")
				}
				value, ok := decoded.AsProSeAuthorized()
				if !ok {
					var empty s20.ProSeAuthorized
					return empty, fmt.Errorf("binding UEContextModificationRequestIEs.id-ProSeAuthorized: no selected value")
				}
				return *value, nil
			}
			*s20.BridgeProSeAuthorizedValueCodecFieldEncode(&sealed) = func(value s20.ProSeAuthorized, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
				return s46.BridgeUEContextModificationRequestIEValueMethodEncodeFresh((func() s46.UEContextModificationRequestIEValue {
					sealed := s46.UEContextModificationRequestIEValue{}
					*s46.BridgeUEContextModificationRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(195)
					*s46.BridgeUEContextModificationRequestIEValueFieldRowProSeAuthorized(&sealed) = &value
					return sealed
				}()), fresh, budget)
			}
			*s20.BridgeProSeAuthorizedValueCodecFieldCapture(&sealed) = func(v s20.ProSeAuthorized, options aper.DecodeState) (s20.ProSeAuthorized, aper.Snapshot) {
				s := aper.SemanticCaptureFor(options)
				f := s.Begin()
				s20.BridgeCaptureS1APProSeAuthorized(&v, &s)
				var root aper.Snapshot
				s.End(f, &root, false)
				return v, root
			}
			*s20.BridgeProSeAuthorizedValueCodecFieldCompare(&sealed) = func(v s20.ProSeAuthorized, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
				s := aper.NewSemanticComparison(root, budget)
				f := s.Begin()
				s20.BridgeCompareS1APProSeAuthorized(&v, &s)
				s.End(f, root, false)
				return s.
					Plan(), s.BudgetValue()
			}
			*s20.BridgeProSeAuthorizedValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
				sealed := s00.BridgeCodecContext{}
				*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProSeAuthorized"
				*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
				return sealed
			}()
			return sealed
		}()
		*s46.BridgeUEContextModificationRequestProSeAuthorizedIEBindingFieldInject(&sealed) = func(value s20.ProSeAuthorized) s46.UEContextModificationRequestIEValue {
			return func() s46.UEContextModificationRequestIEValue {
				sealed := s46.UEContextModificationRequestIEValue{}
				*s46.BridgeUEContextModificationRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(195)
				*s46.BridgeUEContextModificationRequestIEValueFieldRowProSeAuthorized(&sealed) = &value
				return sealed
			}()
		}
		*s46.BridgeUEContextModificationRequestProSeAuthorizedIEBindingFieldGet(&sealed) = func(value *s46.UEContextModificationRequestIEValue) (*s20.ProSeAuthorized, bool) {
			return value.AsProSeAuthorized()
		}
		return sealed
	}()
}
func (UEContextModificationRequestIETable) infoSRVCCOperationPossible() s00.FieldInfo {
	return s00.FieldInfo{Table: UEContextModificationRequestIEs().ID(), ID: s00.ProtocolIEID(124), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "SRVCCOperationPossible"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "UEContextModificationRequestIEs", Row: "id-SRVCCOperationPossible"}}}
}

// SRVCCOperationPossible returns the typed binding for the SRVCCOperationPossible row of UEContextModificationRequestIETable.
func (t UEContextModificationRequestIETable) SRVCCOperationPossible() s46.UEContextModificationRequestSRVCCOperationPossibleIEBinding {
	return func() s46.UEContextModificationRequestSRVCCOperationPossibleIEBinding {
		sealed := s46.UEContextModificationRequestSRVCCOperationPossibleIEBinding{}
		*s46.BridgeUEContextModificationRequestSRVCCOperationPossibleIEBindingFieldInfo(&sealed) = t.infoSRVCCOperationPossible()
		*s46.BridgeUEContextModificationRequestSRVCCOperationPossibleIEBindingFieldCodec(&sealed) = func() s01.SRVCCOperationPossibleValueCodec {
			sealed := s01.SRVCCOperationPossibleValueCodec{}
			*s01.BridgeSRVCCOperationPossibleValueCodecFieldPath(&sealed) = "SRVCCOperationPossible"
			*s01.BridgeSRVCCOperationPossibleValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.SRVCCOperationPossible, error) {
				raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
				if err != nil {
					var empty s00.SRVCCOperationPossible
					return empty, err
				}
				raw.BudgetBuffer().EnterComponent("SRVCCOperationPossible")
				var zero s46.UEContextModificationRequestIEValue
				decoded, err := s46.BridgeUEContextModificationRequestIEValueMethodDecode(zero, s00.ProtocolIEID(124), raw)
				if err != nil {
					var empty s00.SRVCCOperationPossible
					return empty, runtime.WrapDecodePath(err, "SRVCCOperationPossible")
				}
				value, ok := decoded.AsSRVCCOperationPossible()
				if !ok {
					var empty s00.SRVCCOperationPossible
					return empty, fmt.Errorf("binding UEContextModificationRequestIEs.id-SRVCCOperationPossible: no selected value")
				}
				return *value, nil
			}
			*s01.BridgeSRVCCOperationPossibleValueCodecFieldEncode(&sealed) = func(value s00.SRVCCOperationPossible, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
				return s46.BridgeUEContextModificationRequestIEValueMethodEncodeFresh((func() s46.UEContextModificationRequestIEValue {
					sealed := s46.UEContextModificationRequestIEValue{}
					*s46.BridgeUEContextModificationRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(124)
					*s46.BridgeUEContextModificationRequestIEValueFieldRowSRVCCOperationPossible(&sealed) = &value
					return sealed
				}()), fresh, budget)
			}
			*s01.BridgeSRVCCOperationPossibleValueCodecFieldCapture(&sealed) = func(v s00.SRVCCOperationPossible, options aper.DecodeState) (s00.SRVCCOperationPossible, aper.Snapshot,

			) {
				s := aper.SemanticCaptureFor(options)
				f := s.Begin()
				s00.BridgeCaptureS1APSRVCCOperationPossible(&v, &s)
				var root aper.Snapshot
				s.End(f, &root, false)
				return v, root
			}
			*s01.BridgeSRVCCOperationPossibleValueCodecFieldCompare(&sealed) = func(v s00.SRVCCOperationPossible, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

			) {
				s := aper.NewSemanticComparison(root, budget)
				f := s.Begin()
				s06.BridgeCompareS1APSRVCCOperationPossible(&v, &s)
				s.End(f, root, false)
				return s.Plan(), s.BudgetValue()
			}
			*s01.BridgeSRVCCOperationPossibleValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
				sealed := s00.BridgeCodecContext{}
				*s00.BridgecodecContextFieldSource(&sealed) = "source-value:SRVCCOperationPossible"
				*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
				return sealed
			}()
			return sealed
		}()
		*s46.BridgeUEContextModificationRequestSRVCCOperationPossibleIEBindingFieldInject(&sealed) = func(value s00.SRVCCOperationPossible) s46.UEContextModificationRequestIEValue {
			return func() s46.UEContextModificationRequestIEValue {
				sealed := s46.UEContextModificationRequestIEValue{}
				*s46.BridgeUEContextModificationRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(124)
				*s46.BridgeUEContextModificationRequestIEValueFieldRowSRVCCOperationPossible(&sealed) = &value
				return sealed
			}()
		}
		*s46.BridgeUEContextModificationRequestSRVCCOperationPossibleIEBindingFieldGet(&sealed) = func(value *s46.UEContextModificationRequestIEValue) (*s00.SRVCCOperationPossible, bool) {
			return value.AsSRVCCOperationPossible()
		}
		return sealed
	}()
}
func (UEContextModificationRequestIETable) infoSRVCCOperationNotPossible() s00.FieldInfo {
	return s00.FieldInfo{Table: UEContextModificationRequestIEs().ID(), ID: s00.ProtocolIEID(243), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "SRVCCOperationNotPossible"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "UEContextModificationRequestIEs", Row: "id-SRVCCOperationNotPossible"}}}
}

// SRVCCOperationNotPossible returns the typed binding for the SRVCCOperationNotPossible row of UEContextModificationRequestIETable.
func (t UEContextModificationRequestIETable) SRVCCOperationNotPossible() s46.UEContextModificationRequestSRVCCOperationNotPossibleIEBinding {
	return func() s46.UEContextModificationRequestSRVCCOperationNotPossibleIEBinding {
		sealed := s46.UEContextModificationRequestSRVCCOperationNotPossibleIEBinding{}
		*s46.BridgeUEContextModificationRequestSRVCCOperationNotPossibleIEBindingFieldInfo(&sealed) = t.infoSRVCCOperationNotPossible()
		*s46.BridgeUEContextModificationRequestSRVCCOperationNotPossibleIEBindingFieldCodec(&sealed) = func() s01.SRVCCOperationNotPossibleValueCodec {
			sealed := s01.SRVCCOperationNotPossibleValueCodec{}
			*s01.BridgeSRVCCOperationNotPossibleValueCodecFieldPath(&sealed) = "SRVCCOperationNotPossible"
			*s01.BridgeSRVCCOperationNotPossibleValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.SRVCCOperationNotPossible, error) {
				raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
				if err != nil {
					var empty s00.SRVCCOperationNotPossible
					return empty, err
				}
				raw.BudgetBuffer().EnterComponent("SRVCCOperationNotPossible")
				var zero s46.UEContextModificationRequestIEValue
				decoded, err := s46.BridgeUEContextModificationRequestIEValueMethodDecode(zero, s00.ProtocolIEID(243), raw)
				if err != nil {
					var empty s00.SRVCCOperationNotPossible
					return empty, runtime.WrapDecodePath(err, "SRVCCOperationNotPossible")
				}
				value, ok := decoded.AsSRVCCOperationNotPossible()
				if !ok {
					var empty s00.SRVCCOperationNotPossible
					return empty, fmt.Errorf("binding UEContextModificationRequestIEs.id-SRVCCOperationNotPossible: no selected value")
				}
				return *value, nil
			}
			*s01.BridgeSRVCCOperationNotPossibleValueCodecFieldEncode(&sealed) = func(value s00.SRVCCOperationNotPossible, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
				return s46.BridgeUEContextModificationRequestIEValueMethodEncodeFresh((func() s46.UEContextModificationRequestIEValue {
					sealed := s46.UEContextModificationRequestIEValue{}
					*s46.BridgeUEContextModificationRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(243)
					*s46.BridgeUEContextModificationRequestIEValueFieldRowSRVCCOperationNotPossible(&sealed) = &value
					return sealed
				}()), fresh, budget)
			}
			*s01.BridgeSRVCCOperationNotPossibleValueCodecFieldCapture(&sealed) = func(v s00.SRVCCOperationNotPossible, options aper.DecodeState) (s00.SRVCCOperationNotPossible, aper.Snapshot) {
				s := aper.SemanticCaptureFor(options)
				f := s.Begin()
				s00.BridgeCaptureS1APSRVCCOperationNotPossible(&v, &s)
				var root aper.Snapshot
				s.End(
					f,
					&root, false)
				return v, root
			}
			*s01.BridgeSRVCCOperationNotPossibleValueCodecFieldCompare(&sealed) = func(v s00.SRVCCOperationNotPossible, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

			) {
				s := aper.NewSemanticComparison(root, budget)
				f := s.Begin()
				s06.BridgeCompareS1APSRVCCOperationNotPossible(&v, &s)
				s.End(f, root,

					false)
				return s.Plan(), s.BudgetValue()
			}
			*s01.BridgeSRVCCOperationNotPossibleValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
				sealed := s00.BridgeCodecContext{}
				*s00.BridgecodecContextFieldSource(&sealed) = "source-value:SRVCCOperationNotPossible"
				*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
				return sealed
			}()
			return sealed
		}()
		*s46.BridgeUEContextModificationRequestSRVCCOperationNotPossibleIEBindingFieldInject(&sealed) = func(value s00.SRVCCOperationNotPossible) s46.UEContextModificationRequestIEValue {
			return func() s46.UEContextModificationRequestIEValue {
				sealed := s46.UEContextModificationRequestIEValue{}
				*s46.BridgeUEContextModificationRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(243)
				*s46.BridgeUEContextModificationRequestIEValueFieldRowSRVCCOperationNotPossible(&sealed) = &value
				return sealed
			}()
		}
		*s46.BridgeUEContextModificationRequestSRVCCOperationNotPossibleIEBindingFieldGet(&sealed) = func(value *s46.UEContextModificationRequestIEValue) (*s00.SRVCCOperationNotPossible, bool) {
			return value.AsSRVCCOperationNotPossible()
		}
		return sealed
	}()
}
func (UEContextModificationRequestIETable) infoV2XServicesAuthorized() s00.FieldInfo {
	return s00.FieldInfo{Table: UEContextModificationRequestIEs().ID(), ID: s00.ProtocolIEID(240), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "V2XServicesAuthorized"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "UEContextModificationRequestIEs", Row: "id-V2XServicesAuthorized"}}}
}

// V2XServicesAuthorized returns the typed binding for the V2XServicesAuthorized row of UEContextModificationRequestIETable.
func (t UEContextModificationRequestIETable) V2XServicesAuthorized() UEContextModificationRequestV2XServicesAuthorizedIEBinding {
	return UEContextModificationRequestV2XServicesAuthorizedIEBinding{info: t.infoV2XServicesAuthorized(), codec: func() s46.V2XServicesAuthorizedValueCodec {
		sealed := s46.V2XServicesAuthorizedValueCodec{}
		*s46.BridgeV2XServicesAuthorizedValueCodecFieldPath(&sealed) = "V2XServicesAuthorized"
		*s46.BridgeV2XServicesAuthorizedValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s46.V2XServicesAuthorized, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s46.V2XServicesAuthorized
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("V2XServicesAuthorized")
			var zero s46.UEContextModificationRequestIEValue
			decoded, err := s46.BridgeUEContextModificationRequestIEValueMethodDecode(zero, s00.ProtocolIEID(240), raw)
			if err != nil {
				var empty s46.V2XServicesAuthorized
				return empty, runtime.WrapDecodePath(err, "V2XServicesAuthorized")
			}
			value, ok := decoded.AsV2XServicesAuthorized()
			if !ok {
				var empty s46.V2XServicesAuthorized
				return empty, fmt.Errorf("binding UEContextModificationRequestIEs.id-V2XServicesAuthorized: no selected value")
			}
			return *value, nil
		}
		*s46.BridgeV2XServicesAuthorizedValueCodecFieldEncode(&sealed) = func(value s46.V2XServicesAuthorized, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return s46.BridgeUEContextModificationRequestIEValueMethodEncodeFresh((func() s46.UEContextModificationRequestIEValue {
				sealed := s46.UEContextModificationRequestIEValue{}
				*s46.BridgeUEContextModificationRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(240)
				*s46.BridgeUEContextModificationRequestIEValueFieldRowV2XServicesAuthorized(&sealed) = &value
				return sealed
			}()), fresh, budget)
		}
		*s46.BridgeV2XServicesAuthorizedValueCodecFieldCapture(&sealed) = func(v s46.V2XServicesAuthorized, options aper.DecodeState) (s46.V2XServicesAuthorized, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s46.BridgeCaptureS1APV2XServicesAuthorized(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)

			return v, root
		}
		*s46.BridgeV2XServicesAuthorizedValueCodecFieldCompare(&sealed) = func(v s46.V2XServicesAuthorized, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s46.BridgeCompareS1APV2XServicesAuthorized(&v, &s)
			s.End(f, root, false)

			return s.Plan(), s.BudgetValue()
		}
		*s46.BridgeV2XServicesAuthorizedValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:V2XServicesAuthorized"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s46.V2XServicesAuthorized) s46.UEContextModificationRequestIEValue {
			return func() s46.UEContextModificationRequestIEValue {
				sealed := s46.UEContextModificationRequestIEValue{}
				*s46.BridgeUEContextModificationRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(240)
				*s46.BridgeUEContextModificationRequestIEValueFieldRowV2XServicesAuthorized(&sealed) = &value
				return sealed
			}()
		}, get: func(value *s46.UEContextModificationRequestIEValue) (*s46.V2XServicesAuthorized, bool) {
			return value.AsV2XServicesAuthorized()
		}}
}
func (UEContextModificationRequestIETable) infoUESidelinkAggregateMaximumBitrate() s00.FieldInfo {
	return s00.FieldInfo{Table: UEContextModificationRequestIEs().ID(), ID: s00.ProtocolIEID(248), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "UESidelinkAggregateMaximumBitrate"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "UEContextModificationRequestIEs", Row: "id-UESidelinkAggregateMaximumBitrate"}}}
}

// UESidelinkAggregateMaximumBitrate returns the typed binding for the UESidelinkAggregateMaximumBitrate row of UEContextModificationRequestIETable.
func (t UEContextModificationRequestIETable) UESidelinkAggregateMaximumBitrate() s46.UEContextModificationRequestUESidelinkAggregateMaximumBitrateIEBinding {
	return func() s46.UEContextModificationRequestUESidelinkAggregateMaximumBitrateIEBinding {
		sealed := s46.UEContextModificationRequestUESidelinkAggregateMaximumBitrateIEBinding{}
		*s46.BridgeUEContextModificationRequestUESidelinkAggregateMaximumBitrateIEBindingFieldInfo(&sealed) = t.infoUESidelinkAggregateMaximumBitrate()
		*s46.BridgeUEContextModificationRequestUESidelinkAggregateMaximumBitrateIEBindingFieldCodec(&sealed) = func() s37.UESidelinkAggregateMaximumBitrateValueCodec {
			sealed := s37.UESidelinkAggregateMaximumBitrateValueCodec{}
			*s37.BridgeUESidelinkAggregateMaximumBitrateValueCodecFieldPath(&sealed) = "UESidelinkAggregateMaximumBitrate"
			*s37.BridgeUESidelinkAggregateMaximumBitrateValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s37.UESidelinkAggregateMaximumBitrate, error) {
				raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
				if err != nil {
					var empty s37.UESidelinkAggregateMaximumBitrate
					return empty, err
				}
				raw.BudgetBuffer().EnterComponent("UESidelinkAggregateMaximumBitrate")
				var zero s46.UEContextModificationRequestIEValue
				decoded, err := s46.BridgeUEContextModificationRequestIEValueMethodDecode(zero, s00.ProtocolIEID(248), raw)
				if err != nil {
					var empty s37.UESidelinkAggregateMaximumBitrate
					return empty, runtime.WrapDecodePath(err, "UESidelinkAggregateMaximumBitrate")
				}
				value, ok := decoded.AsUESidelinkAggregateMaximumBitrate()
				if !ok {
					var empty s37.UESidelinkAggregateMaximumBitrate
					return empty, fmt.Errorf("binding UEContextModificationRequestIEs.id-UESidelinkAggregateMaximumBitrate: no selected value")
				}
				return *value, nil
			}
			*s37.BridgeUESidelinkAggregateMaximumBitrateValueCodecFieldEncode(&sealed) = func(value s37.UESidelinkAggregateMaximumBitrate, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
				return s46.BridgeUEContextModificationRequestIEValueMethodEncodeFresh((func() s46.UEContextModificationRequestIEValue {
					sealed := s46.UEContextModificationRequestIEValue{}
					*s46.BridgeUEContextModificationRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(248)
					*s46.BridgeUEContextModificationRequestIEValueFieldRowUESidelinkAggregateMaximumBitrate(&sealed) = &value
					return sealed
				}()), fresh, budget)
			}
			*s37.BridgeUESidelinkAggregateMaximumBitrateValueCodecFieldCapture(&sealed) = func(v s37.UESidelinkAggregateMaximumBitrate, options aper.DecodeState) (s37.UESidelinkAggregateMaximumBitrate, aper.Snapshot,
			) {
				s := aper.SemanticCaptureFor(options)
				f := s.Begin()
				s37.BridgeCaptureS1APUESidelinkAggregateMaximumBitrate(&v, &s)
				var root aper.Snapshot
				s.End(f, &root, false)
				return v, root
			}
			*s37.BridgeUESidelinkAggregateMaximumBitrateValueCodecFieldCompare(&sealed) = func(v s37.UESidelinkAggregateMaximumBitrate, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

			) {
				s := aper.NewSemanticComparison(root, budget)
				f := s.Begin()
				s37.BridgeCompareS1APUESidelinkAggregateMaximumBitrate(
					&v,

					&s)
				s.End(f, root, false)
				return s.Plan(), s.BudgetValue()
			}
			*s37.BridgeUESidelinkAggregateMaximumBitrateValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
				sealed := s00.BridgeCodecContext{}
				*s00.BridgecodecContextFieldSource(&sealed) = "source-value:UESidelinkAggregateMaximumBitrate"
				*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
				return sealed
			}()
			return sealed
		}()
		*s46.BridgeUEContextModificationRequestUESidelinkAggregateMaximumBitrateIEBindingFieldInject(&sealed) = func(value s37.UESidelinkAggregateMaximumBitrate) s46.UEContextModificationRequestIEValue {
			return func() s46.UEContextModificationRequestIEValue {
				sealed := s46.UEContextModificationRequestIEValue{}
				*s46.BridgeUEContextModificationRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(248)
				*s46.BridgeUEContextModificationRequestIEValueFieldRowUESidelinkAggregateMaximumBitrate(&sealed) = &value
				return sealed
			}()
		}
		*s46.BridgeUEContextModificationRequestUESidelinkAggregateMaximumBitrateIEBindingFieldGet(&sealed) = func(value *s46.UEContextModificationRequestIEValue) (*s37.UESidelinkAggregateMaximumBitrate, bool) {
			return value.AsUESidelinkAggregateMaximumBitrate()
		}
		return sealed
	}()
}
func (UEContextModificationRequestIETable) infoNRUESecurityCapabilities() s00.FieldInfo {
	return s00.FieldInfo{Table: UEContextModificationRequestIEs().ID(), ID: s00.ProtocolIEID(269), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "NRUESecurityCapabilities"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "UEContextModificationRequestIEs", Row: "id-NRUESecurityCapabilities"}}}
}

// NRUESecurityCapabilities returns the typed binding for the NRUESecurityCapabilities row of UEContextModificationRequestIETable.
func (t UEContextModificationRequestIETable) NRUESecurityCapabilities() s46.UEContextModificationRequestNRUESecurityCapabilitiesIEBinding {
	return func() s46.UEContextModificationRequestNRUESecurityCapabilitiesIEBinding {
		sealed := s46.UEContextModificationRequestNRUESecurityCapabilitiesIEBinding{}
		*s46.BridgeUEContextModificationRequestNRUESecurityCapabilitiesIEBindingFieldInfo(&sealed) = t.infoNRUESecurityCapabilities()
		*s46.BridgeUEContextModificationRequestNRUESecurityCapabilitiesIEBindingFieldCodec(&sealed) = func() s19.NRUESecurityCapabilitiesValueCodec {
			sealed := s19.NRUESecurityCapabilitiesValueCodec{}
			*s19.BridgeNRUESecurityCapabilitiesValueCodecFieldPath(&sealed) = "NRUESecurityCapabilities"
			*s19.BridgeNRUESecurityCapabilitiesValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s19.NRUESecurityCapabilities, error) {
				raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
				if err != nil {
					var empty s19.NRUESecurityCapabilities
					return empty, err
				}
				raw.BudgetBuffer().EnterComponent("NRUESecurityCapabilities")
				var zero s46.UEContextModificationRequestIEValue
				decoded, err := s46.BridgeUEContextModificationRequestIEValueMethodDecode(zero, s00.ProtocolIEID(269), raw)
				if err != nil {
					var empty s19.NRUESecurityCapabilities
					return empty, runtime.WrapDecodePath(err, "NRUESecurityCapabilities")
				}
				value, ok := decoded.AsNRUESecurityCapabilities()
				if !ok {
					var empty s19.NRUESecurityCapabilities
					return empty, fmt.Errorf("binding UEContextModificationRequestIEs.id-NRUESecurityCapabilities: no selected value")
				}
				return *value, nil
			}
			*s19.BridgeNRUESecurityCapabilitiesValueCodecFieldEncode(&sealed) = func(value s19.NRUESecurityCapabilities, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
				return s46.BridgeUEContextModificationRequestIEValueMethodEncodeFresh((func() s46.UEContextModificationRequestIEValue {
					sealed := s46.UEContextModificationRequestIEValue{}
					*s46.BridgeUEContextModificationRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(269)
					*s46.BridgeUEContextModificationRequestIEValueFieldRowNRUESecurityCapabilities(&sealed) = &value
					return sealed
				}()), fresh, budget)
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
		}()
		*s46.BridgeUEContextModificationRequestNRUESecurityCapabilitiesIEBindingFieldInject(&sealed) = func(value s19.NRUESecurityCapabilities) s46.UEContextModificationRequestIEValue {
			return func() s46.UEContextModificationRequestIEValue {
				sealed := s46.UEContextModificationRequestIEValue{}
				*s46.BridgeUEContextModificationRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(269)
				*s46.BridgeUEContextModificationRequestIEValueFieldRowNRUESecurityCapabilities(&sealed) = &value
				return sealed
			}()
		}
		*s46.BridgeUEContextModificationRequestNRUESecurityCapabilitiesIEBindingFieldGet(&sealed) = func(value *s46.UEContextModificationRequestIEValue) (*s19.NRUESecurityCapabilities, bool) {
			return value.AsNRUESecurityCapabilities()
		}
		return sealed
	}()
}
func (UEContextModificationRequestIETable) infoAerialUEsubscriptionInformation() s00.FieldInfo {
	return s00.FieldInfo{Table: UEContextModificationRequestIEs().ID(), ID: s00.ProtocolIEID(277), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "AerialUEsubscriptionInformation"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "UEContextModificationRequestIEs", Row: "id-AerialUEsubscriptionInformation"}}}
}

// AerialUEsubscriptionInformation returns the typed binding for the AerialUEsubscriptionInformation row of UEContextModificationRequestIETable.
func (t UEContextModificationRequestIETable) AerialUEsubscriptionInformation() s46.UEContextModificationRequestAerialUEsubscriptionInformationIEBinding {
	return func() s46.UEContextModificationRequestAerialUEsubscriptionInformationIEBinding {
		sealed := s46.UEContextModificationRequestAerialUEsubscriptionInformationIEBinding{}
		*s46.BridgeUEContextModificationRequestAerialUEsubscriptionInformationIEBindingFieldInfo(&sealed) = t.infoAerialUEsubscriptionInformation()
		*s46.BridgeUEContextModificationRequestAerialUEsubscriptionInformationIEBindingFieldCodec(&sealed) = func() s00.AerialUEsubscriptionInformationValueCodec {
			sealed := s00.AerialUEsubscriptionInformationValueCodec{}
			*s00.BridgeAerialUEsubscriptionInformationValueCodecFieldPath(&sealed) = "AerialUEsubscriptionInformation"
			*s00.BridgeAerialUEsubscriptionInformationValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.AerialUEsubscriptionInformation, error) {
				raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
				if err != nil {
					var empty s00.AerialUEsubscriptionInformation
					return empty, err
				}
				raw.BudgetBuffer().EnterComponent("AerialUEsubscriptionInformation")
				var zero s46.UEContextModificationRequestIEValue
				decoded, err := s46.BridgeUEContextModificationRequestIEValueMethodDecode(zero, s00.ProtocolIEID(277), raw)
				if err != nil {
					var empty s00.AerialUEsubscriptionInformation
					return empty, runtime.WrapDecodePath(err, "AerialUEsubscriptionInformation")
				}
				value, ok := decoded.AsAerialUEsubscriptionInformation()
				if !ok {
					var empty s00.AerialUEsubscriptionInformation
					return empty, fmt.Errorf("binding UEContextModificationRequestIEs.id-AerialUEsubscriptionInformation: no selected value")
				}
				return *value, nil
			}
			*s00.BridgeAerialUEsubscriptionInformationValueCodecFieldEncode(&sealed) = func(value s00.AerialUEsubscriptionInformation, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
				return s46.BridgeUEContextModificationRequestIEValueMethodEncodeFresh((func() s46.UEContextModificationRequestIEValue {
					sealed := s46.UEContextModificationRequestIEValue{}
					*s46.BridgeUEContextModificationRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(277)
					*s46.BridgeUEContextModificationRequestIEValueFieldRowAerialUEsubscriptionInformation(&sealed) = &value
					return sealed
				}()), fresh, budget)
			}
			*s00.BridgeAerialUEsubscriptionInformationValueCodecFieldCapture(&sealed) = func(v s00.AerialUEsubscriptionInformation, options aper.DecodeState) (s00.AerialUEsubscriptionInformation, aper.Snapshot,
			) {
				s := aper.SemanticCaptureFor(options)
				f := s.Begin()
				s00.BridgeCaptureS1APAerialUEsubscriptionInformation(&v, &s)
				var root aper.Snapshot

				s.End(f, &root, false)
				return v, root
			}
			*s00.BridgeAerialUEsubscriptionInformationValueCodecFieldCompare(&sealed) = func(v s00.AerialUEsubscriptionInformation, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
			) {
				s := aper.NewSemanticComparison(root, budget)
				f := s.Begin()
				s02.BridgeCompareS1APAerialUEsubscriptionInformation(&v, &s)

				s.End(f, root, false)
				return s.Plan(), s.BudgetValue()
			}
			*s00.BridgeAerialUEsubscriptionInformationValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
				sealed := s00.BridgeCodecContext{}
				*s00.BridgecodecContextFieldSource(&sealed) = "source-value:AerialUEsubscriptionInformation"
				*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
				return sealed
			}()
			return sealed
		}()
		*s46.BridgeUEContextModificationRequestAerialUEsubscriptionInformationIEBindingFieldInject(&sealed) = func(value s00.AerialUEsubscriptionInformation) s46.UEContextModificationRequestIEValue {
			return func() s46.UEContextModificationRequestIEValue {
				sealed := s46.UEContextModificationRequestIEValue{}
				*s46.BridgeUEContextModificationRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(277)
				*s46.BridgeUEContextModificationRequestIEValueFieldRowAerialUEsubscriptionInformation(&sealed) = &value
				return sealed
			}()
		}
		*s46.BridgeUEContextModificationRequestAerialUEsubscriptionInformationIEBindingFieldGet(&sealed) = func(value *s46.UEContextModificationRequestIEValue) (*s00.AerialUEsubscriptionInformation, bool) {
			return value.AsAerialUEsubscriptionInformation()
		}
		return sealed
	}()
}
func (UEContextModificationRequestIETable) infoAdditionalRRMPriorityIndex() s00.FieldInfo {
	return s00.FieldInfo{Table: UEContextModificationRequestIEs().ID(), ID: s00.ProtocolIEID(299), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "AdditionalRRMPriorityIndex"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "UEContextModificationRequestIEs", Row: "id-AdditionalRRMPriorityIndex"}}}
}

// AdditionalRRMPriorityIndex returns the typed binding for the AdditionalRRMPriorityIndex row of UEContextModificationRequestIETable.
func (t UEContextModificationRequestIETable) AdditionalRRMPriorityIndex() s46.UEContextModificationRequestAdditionalRRMPriorityIndexIEBinding {
	return func() s46.UEContextModificationRequestAdditionalRRMPriorityIndexIEBinding {
		sealed := s46.UEContextModificationRequestAdditionalRRMPriorityIndexIEBinding{}
		*s46.BridgeUEContextModificationRequestAdditionalRRMPriorityIndexIEBindingFieldInfo(&sealed) = t.infoAdditionalRRMPriorityIndex()
		*s46.BridgeUEContextModificationRequestAdditionalRRMPriorityIndexIEBindingFieldCodec(&sealed) = func() s00.AdditionalRRMPriorityIndexValueCodec {
			sealed := s00.AdditionalRRMPriorityIndexValueCodec{}
			*s00.BridgeAdditionalRRMPriorityIndexValueCodecFieldPath(&sealed) = "AdditionalRRMPriorityIndex"
			*s00.BridgeAdditionalRRMPriorityIndexValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.AdditionalRRMPriorityIndex, error) {
				raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
				if err != nil {
					var empty s00.AdditionalRRMPriorityIndex
					return empty, err
				}
				raw.BudgetBuffer().EnterComponent("AdditionalRRMPriorityIndex")
				var zero s46.UEContextModificationRequestIEValue
				decoded, err := s46.BridgeUEContextModificationRequestIEValueMethodDecode(zero, s00.ProtocolIEID(299), raw)
				if err != nil {
					var empty s00.AdditionalRRMPriorityIndex
					return empty, runtime.WrapDecodePath(err, "AdditionalRRMPriorityIndex")
				}
				value, ok := decoded.AsAdditionalRRMPriorityIndex()
				if !ok {
					var empty s00.AdditionalRRMPriorityIndex
					return empty, fmt.Errorf("binding UEContextModificationRequestIEs.id-AdditionalRRMPriorityIndex: no selected value")
				}
				return *value, nil
			}
			*s00.BridgeAdditionalRRMPriorityIndexValueCodecFieldEncode(&sealed) = func(value s00.AdditionalRRMPriorityIndex, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
				return s46.BridgeUEContextModificationRequestIEValueMethodEncodeFresh((func() s46.UEContextModificationRequestIEValue {
					sealed := s46.UEContextModificationRequestIEValue{}
					*s46.BridgeUEContextModificationRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(299)
					*s46.BridgeUEContextModificationRequestIEValueFieldRowAdditionalRRMPriorityIndex(&sealed) = &value
					return sealed
				}()), fresh, budget)
			}
			*s00.BridgeAdditionalRRMPriorityIndexValueCodecFieldCapture(&sealed) = func(v s00.AdditionalRRMPriorityIndex, options aper.DecodeState) (s00.AdditionalRRMPriorityIndex, aper.Snapshot,
			) {
				s := aper.SemanticCaptureFor(options)
				f := s.Begin()
				s00.BridgeCaptureS1APAdditionalRRMPriorityIndex(&v, &s)
				var root aper.Snapshot
				s.End(
					f, &root, false)
				return v, root
			}
			*s00.BridgeAdditionalRRMPriorityIndexValueCodecFieldCompare(&sealed) = func(v s00.AdditionalRRMPriorityIndex, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
			) {
				s := aper.NewSemanticComparison(root, budget)
				f := s.Begin()
				s02.BridgeCompareS1APAdditionalRRMPriorityIndex(&v, &s)
				s.End(f,
					root,

					false)
				return s.Plan(), s.BudgetValue()
			}
			*s00.BridgeAdditionalRRMPriorityIndexValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
				sealed := s00.BridgeCodecContext{}
				*s00.BridgecodecContextFieldSource(&sealed) = "source-value:AdditionalRRMPriorityIndex"
				*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
				return sealed
			}()
			return sealed
		}()
		*s46.BridgeUEContextModificationRequestAdditionalRRMPriorityIndexIEBindingFieldInject(&sealed) = func(value s00.AdditionalRRMPriorityIndex) s46.UEContextModificationRequestIEValue {
			return func() s46.UEContextModificationRequestIEValue {
				sealed := s46.UEContextModificationRequestIEValue{}
				*s46.BridgeUEContextModificationRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(299)
				*s46.BridgeUEContextModificationRequestIEValueFieldRowAdditionalRRMPriorityIndex(&sealed) = &value
				return sealed
			}()
		}
		*s46.BridgeUEContextModificationRequestAdditionalRRMPriorityIndexIEBindingFieldGet(&sealed) = func(value *s46.UEContextModificationRequestIEValue) (*s00.AdditionalRRMPriorityIndex, bool) {
			return value.AsAdditionalRRMPriorityIndex()
		}
		return sealed
	}()
}
func (UEContextModificationRequestIETable) infoIABAuthorized() s00.FieldInfo {
	return s00.FieldInfo{Table: UEContextModificationRequestIEs().ID(), ID: s00.ProtocolIEID(301), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "IAB-Authorized"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "UEContextModificationRequestIEs", Row: "id-IAB-Authorized"}}}
}

// IABAuthorized returns the typed binding for the IABAuthorized row of UEContextModificationRequestIETable.
func (t UEContextModificationRequestIETable) IABAuthorized() s46.UEContextModificationRequestIABAuthorizedIEBinding {
	return func() s46.UEContextModificationRequestIABAuthorizedIEBinding {
		sealed := s46.UEContextModificationRequestIABAuthorizedIEBinding{}
		*s46.BridgeUEContextModificationRequestIABAuthorizedIEBindingFieldInfo(&sealed) = t.infoIABAuthorized()
		*s46.BridgeUEContextModificationRequestIABAuthorizedIEBindingFieldCodec(&sealed) = func() s00.IABAuthorizedValueCodec {
			sealed := s00.IABAuthorizedValueCodec{}
			*s00.BridgeIABAuthorizedValueCodecFieldPath(&sealed) = "IABAuthorized"
			*s00.BridgeIABAuthorizedValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.IABAuthorized, error) {
				raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
				if err != nil {
					var empty s00.IABAuthorized
					return empty, err
				}
				raw.BudgetBuffer().EnterComponent("IABAuthorized")
				var zero s46.UEContextModificationRequestIEValue
				decoded, err := s46.BridgeUEContextModificationRequestIEValueMethodDecode(zero, s00.ProtocolIEID(301), raw)
				if err != nil {
					var empty s00.IABAuthorized
					return empty, runtime.WrapDecodePath(err, "IABAuthorized")
				}
				value, ok := decoded.AsIABAuthorized()
				if !ok {
					var empty s00.IABAuthorized
					return empty, fmt.Errorf("binding UEContextModificationRequestIEs.id-IAB-Authorized: no selected value")
				}
				return *value, nil
			}
			*s00.BridgeIABAuthorizedValueCodecFieldEncode(&sealed) = func(value s00.IABAuthorized, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
				return s46.BridgeUEContextModificationRequestIEValueMethodEncodeFresh((func() s46.UEContextModificationRequestIEValue {
					sealed := s46.UEContextModificationRequestIEValue{}
					*s46.BridgeUEContextModificationRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(301)
					*s46.BridgeUEContextModificationRequestIEValueFieldRowIABAuthorized(&sealed) = &value
					return sealed
				}()), fresh, budget)
			}
			*s00.BridgeIABAuthorizedValueCodecFieldCapture(&sealed) = func(v s00.IABAuthorized, options aper.DecodeState) (s00.IABAuthorized, aper.Snapshot) {
				s := aper.SemanticCaptureFor(options)
				f := s.Begin()
				s00.BridgeCaptureS1APIABAuthorized(&v, &s)
				var root aper.Snapshot
				s.End(f, &root, false)
				return v, root
			}
			*s00.BridgeIABAuthorizedValueCodecFieldCompare(&sealed) = func(v s00.IABAuthorized, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
				s := aper.NewSemanticComparison(root, budget)
				f := s.Begin()
				s02.BridgeCompareS1APIABAuthorized(&v, &s)
				s.End(f, root, false)
				return s.Plan(),

					s.BudgetValue()
			}
			*s00.BridgeIABAuthorizedValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
				sealed := s00.BridgeCodecContext{}
				*s00.BridgecodecContextFieldSource(&sealed) = "source-value:IABAuthorized"
				*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
				return sealed
			}()
			return sealed
		}()
		*s46.BridgeUEContextModificationRequestIABAuthorizedIEBindingFieldInject(&sealed) = func(value s00.IABAuthorized) s46.UEContextModificationRequestIEValue {
			return func() s46.UEContextModificationRequestIEValue {
				sealed := s46.UEContextModificationRequestIEValue{}
				*s46.BridgeUEContextModificationRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(301)
				*s46.BridgeUEContextModificationRequestIEValueFieldRowIABAuthorized(&sealed) = &value
				return sealed
			}()
		}
		*s46.BridgeUEContextModificationRequestIABAuthorizedIEBindingFieldGet(&sealed) = func(value *s46.UEContextModificationRequestIEValue) (*s00.IABAuthorized, bool) {
			return value.AsIABAuthorized()
		}
		return sealed
	}()
}
func (UEContextModificationRequestIETable) infoNRV2XServicesAuthorized() s00.FieldInfo {
	return s00.FieldInfo{Table: UEContextModificationRequestIEs().ID(), ID: s00.ProtocolIEID(306), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "NRV2XServicesAuthorized"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "UEContextModificationRequestIEs", Row: "id-NRV2XServicesAuthorized"}}}
}

// NRV2XServicesAuthorized returns the typed binding for the NRV2XServicesAuthorized row of UEContextModificationRequestIETable.
func (t UEContextModificationRequestIETable) NRV2XServicesAuthorized() s46.UEContextModificationRequestNRV2XServicesAuthorizedIEBinding {
	return func() s46.UEContextModificationRequestNRV2XServicesAuthorizedIEBinding {
		sealed := s46.UEContextModificationRequestNRV2XServicesAuthorizedIEBinding{}
		*s46.BridgeUEContextModificationRequestNRV2XServicesAuthorizedIEBindingFieldInfo(&sealed) = t.infoNRV2XServicesAuthorized()
		*s46.BridgeUEContextModificationRequestNRV2XServicesAuthorizedIEBindingFieldCodec(&sealed) = func() s19.NRV2XServicesAuthorizedValueCodec {
			sealed := s19.NRV2XServicesAuthorizedValueCodec{}
			*s19.BridgeNRV2XServicesAuthorizedValueCodecFieldPath(&sealed) = "NRV2XServicesAuthorized"
			*s19.BridgeNRV2XServicesAuthorizedValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s19.NRV2XServicesAuthorized, error) {
				raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
				if err != nil {
					var empty s19.NRV2XServicesAuthorized
					return empty, err
				}
				raw.BudgetBuffer().EnterComponent("NRV2XServicesAuthorized")
				var zero s46.UEContextModificationRequestIEValue
				decoded, err := s46.BridgeUEContextModificationRequestIEValueMethodDecode(zero, s00.ProtocolIEID(306), raw)
				if err != nil {
					var empty s19.NRV2XServicesAuthorized
					return empty, runtime.WrapDecodePath(err, "NRV2XServicesAuthorized")
				}
				value, ok := decoded.AsNRV2XServicesAuthorized()
				if !ok {
					var empty s19.NRV2XServicesAuthorized
					return empty, fmt.Errorf("binding UEContextModificationRequestIEs.id-NRV2XServicesAuthorized: no selected value")
				}
				return *value, nil
			}
			*s19.BridgeNRV2XServicesAuthorizedValueCodecFieldEncode(&sealed) = func(value s19.NRV2XServicesAuthorized, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
				return s46.BridgeUEContextModificationRequestIEValueMethodEncodeFresh((func() s46.UEContextModificationRequestIEValue {
					sealed := s46.UEContextModificationRequestIEValue{}
					*s46.BridgeUEContextModificationRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(306)
					*s46.BridgeUEContextModificationRequestIEValueFieldRowNRV2XServicesAuthorized(&sealed) = &value
					return sealed
				}()), fresh, budget)
			}
			*s19.BridgeNRV2XServicesAuthorizedValueCodecFieldCapture(&sealed) = func(v s19.NRV2XServicesAuthorized, options aper.DecodeState) (s19.NRV2XServicesAuthorized, aper.Snapshot) {
				s := aper.SemanticCaptureFor(options)
				f := s.Begin()
				s19.BridgeCaptureS1APNRV2XServicesAuthorized(&v, &s)
				var root aper.Snapshot
				s.End(f, &root,

					false,
				)
				return v, root
			}
			*s19.BridgeNRV2XServicesAuthorizedValueCodecFieldCompare(&sealed) = func(v s19.NRV2XServicesAuthorized, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

			) {
				s := aper.NewSemanticComparison(root, budget)
				f := s.Begin()
				s19.BridgeCompareS1APNRV2XServicesAuthorized(&v, &s)
				s.End(f, root,
					false,
				)
				return s.Plan(), s.BudgetValue()
			}
			*s19.BridgeNRV2XServicesAuthorizedValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
				sealed := s00.BridgeCodecContext{}
				*s00.BridgecodecContextFieldSource(&sealed) = "source-value:NRV2XServicesAuthorized"
				*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
				return sealed
			}()
			return sealed
		}()
		*s46.BridgeUEContextModificationRequestNRV2XServicesAuthorizedIEBindingFieldInject(&sealed) = func(value s19.NRV2XServicesAuthorized) s46.UEContextModificationRequestIEValue {
			return func() s46.UEContextModificationRequestIEValue {
				sealed := s46.UEContextModificationRequestIEValue{}
				*s46.BridgeUEContextModificationRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(306)
				*s46.BridgeUEContextModificationRequestIEValueFieldRowNRV2XServicesAuthorized(&sealed) = &value
				return sealed
			}()
		}
		*s46.BridgeUEContextModificationRequestNRV2XServicesAuthorizedIEBindingFieldGet(&sealed) = func(value *s46.UEContextModificationRequestIEValue) (*s19.NRV2XServicesAuthorized, bool) {
			return value.AsNRV2XServicesAuthorized()
		}
		return sealed
	}()
}
func (UEContextModificationRequestIETable) infoNRUESidelinkAggregateMaximumBitrate() s00.FieldInfo {
	return s00.FieldInfo{Table: UEContextModificationRequestIEs().ID(), ID: s00.ProtocolIEID(307), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "NRUESidelinkAggregateMaximumBitrate"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "UEContextModificationRequestIEs", Row: "id-NRUESidelinkAggregateMaximumBitrate"}}}
}

// NRUESidelinkAggregateMaximumBitrate returns the typed binding for the NRUESidelinkAggregateMaximumBitrate row of UEContextModificationRequestIETable.
func (t UEContextModificationRequestIETable) NRUESidelinkAggregateMaximumBitrate() s46.UEContextModificationRequestNRUESidelinkAggregateMaximumBitrateIEBinding {
	return func() s46.UEContextModificationRequestNRUESidelinkAggregateMaximumBitrateIEBinding {
		sealed := s46.UEContextModificationRequestNRUESidelinkAggregateMaximumBitrateIEBinding{}
		*s46.BridgeUEContextModificationRequestNRUESidelinkAggregateMaximumBitrateIEBindingFieldInfo(&sealed) = t.infoNRUESidelinkAggregateMaximumBitrate()
		*s46.BridgeUEContextModificationRequestNRUESidelinkAggregateMaximumBitrateIEBindingFieldCodec(&sealed) = func() s19.NRUESidelinkAggregateMaximumBitrateValueCodec {
			sealed := s19.NRUESidelinkAggregateMaximumBitrateValueCodec{}
			*s19.BridgeNRUESidelinkAggregateMaximumBitrateValueCodecFieldPath(&sealed) = "NRUESidelinkAggregateMaximumBitrate"
			*s19.BridgeNRUESidelinkAggregateMaximumBitrateValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s19.NRUESidelinkAggregateMaximumBitrate, error) {
				raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
				if err != nil {
					var empty s19.NRUESidelinkAggregateMaximumBitrate
					return empty, err
				}
				raw.BudgetBuffer().EnterComponent("NRUESidelinkAggregateMaximumBitrate")
				var zero s46.UEContextModificationRequestIEValue
				decoded, err := s46.BridgeUEContextModificationRequestIEValueMethodDecode(zero, s00.ProtocolIEID(307), raw)
				if err != nil {
					var empty s19.NRUESidelinkAggregateMaximumBitrate
					return empty, runtime.WrapDecodePath(err, "NRUESidelinkAggregateMaximumBitrate")
				}
				value, ok := decoded.AsNRUESidelinkAggregateMaximumBitrate()
				if !ok {
					var empty s19.NRUESidelinkAggregateMaximumBitrate
					return empty, fmt.Errorf("binding UEContextModificationRequestIEs.id-NRUESidelinkAggregateMaximumBitrate: no selected value")
				}
				return *value, nil
			}
			*s19.BridgeNRUESidelinkAggregateMaximumBitrateValueCodecFieldEncode(&sealed) = func(value s19.NRUESidelinkAggregateMaximumBitrate, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
				return s46.BridgeUEContextModificationRequestIEValueMethodEncodeFresh((func() s46.UEContextModificationRequestIEValue {
					sealed := s46.UEContextModificationRequestIEValue{}
					*s46.BridgeUEContextModificationRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(307)
					*s46.BridgeUEContextModificationRequestIEValueFieldRowNRUESidelinkAggregateMaximumBitrate(&sealed) = &value
					return sealed
				}()), fresh, budget)
			}
			*s19.BridgeNRUESidelinkAggregateMaximumBitrateValueCodecFieldCapture(&sealed) = func(v s19.NRUESidelinkAggregateMaximumBitrate, options aper.DecodeState) (s19.NRUESidelinkAggregateMaximumBitrate, aper.Snapshot,
			) {
				s := aper.SemanticCaptureFor(options)
				f := s.Begin()
				s19.BridgeCaptureS1APNRUESidelinkAggregateMaximumBitrate(&v, &s)
				var root aper.Snapshot
				s.End(f, &root, false)
				return v, root

			}
			*s19.BridgeNRUESidelinkAggregateMaximumBitrateValueCodecFieldCompare(&sealed) = func(v s19.NRUESidelinkAggregateMaximumBitrate, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

			) {
				s := aper.NewSemanticComparison(root, budget)
				f := s.Begin()
				s19.BridgeCompareS1APNRUESidelinkAggregateMaximumBitrate(&v, &s)
				s.End(f, root, false)
				return s.Plan(), s.BudgetValue()
			}
			*s19.BridgeNRUESidelinkAggregateMaximumBitrateValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
				sealed := s00.BridgeCodecContext{}
				*s00.BridgecodecContextFieldSource(&sealed) = "source-value:NRUESidelinkAggregateMaximumBitrate"
				*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
				return sealed
			}()
			return sealed
		}()
		*s46.BridgeUEContextModificationRequestNRUESidelinkAggregateMaximumBitrateIEBindingFieldInject(&sealed) = func(value s19.NRUESidelinkAggregateMaximumBitrate) s46.UEContextModificationRequestIEValue {
			return func() s46.UEContextModificationRequestIEValue {
				sealed := s46.UEContextModificationRequestIEValue{}
				*s46.BridgeUEContextModificationRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(307)
				*s46.BridgeUEContextModificationRequestIEValueFieldRowNRUESidelinkAggregateMaximumBitrate(&sealed) = &value
				return sealed
			}()
		}
		*s46.BridgeUEContextModificationRequestNRUESidelinkAggregateMaximumBitrateIEBindingFieldGet(&sealed) = func(value *s46.UEContextModificationRequestIEValue) (*s19.NRUESidelinkAggregateMaximumBitrate, bool) {
			return value.AsNRUESidelinkAggregateMaximumBitrate()
		}
		return sealed
	}()
}
func (UEContextModificationRequestIETable) infoPC5QoSParameters() s00.FieldInfo {
	return s00.FieldInfo{Table: UEContextModificationRequestIEs().ID(), ID: s00.ProtocolIEID(308), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "PC5QoSParameters"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "UEContextModificationRequestIEs", Row: "id-PC5QoSParameters"}}}
}

// PC5QoSParameters returns the typed binding for the PC5QoSParameters row of UEContextModificationRequestIETable.
func (t UEContextModificationRequestIETable) PC5QoSParameters() s46.UEContextModificationRequestPC5QoSParametersIEBinding {
	return func() s46.UEContextModificationRequestPC5QoSParametersIEBinding {
		sealed := s46.UEContextModificationRequestPC5QoSParametersIEBinding{}
		*s46.BridgeUEContextModificationRequestPC5QoSParametersIEBindingFieldInfo(&sealed) = t.infoPC5QoSParameters()
		*s46.BridgeUEContextModificationRequestPC5QoSParametersIEBindingFieldCodec(&sealed) = func() s24.PC5QoSParametersValueCodec {
			sealed := s24.PC5QoSParametersValueCodec{}
			*s24.BridgePC5QoSParametersValueCodecFieldPath(&sealed) = "PC5QoSParameters"
			*s24.BridgePC5QoSParametersValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s24.PC5QoSParameters, error) {
				raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
				if err != nil {
					var empty s24.PC5QoSParameters
					return empty, err
				}
				raw.BudgetBuffer().EnterComponent("PC5QoSParameters")
				var zero s46.UEContextModificationRequestIEValue
				decoded, err := s46.BridgeUEContextModificationRequestIEValueMethodDecode(zero, s00.ProtocolIEID(308), raw)
				if err != nil {
					var empty s24.PC5QoSParameters
					return empty, runtime.WrapDecodePath(err, "PC5QoSParameters")
				}
				value, ok := decoded.AsPC5QoSParameters()
				if !ok {
					var empty s24.PC5QoSParameters
					return empty, fmt.Errorf("binding UEContextModificationRequestIEs.id-PC5QoSParameters: no selected value")
				}
				return *value, nil
			}
			*s24.BridgePC5QoSParametersValueCodecFieldEncode(&sealed) = func(value s24.PC5QoSParameters, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
				return s46.BridgeUEContextModificationRequestIEValueMethodEncodeFresh((func() s46.UEContextModificationRequestIEValue {
					sealed := s46.UEContextModificationRequestIEValue{}
					*s46.BridgeUEContextModificationRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(308)
					*s46.BridgeUEContextModificationRequestIEValueFieldRowPC5QoSParameters(&sealed) = &value
					return sealed
				}()), fresh, budget)
			}
			*s24.BridgePC5QoSParametersValueCodecFieldCapture(&sealed) = func(v s24.PC5QoSParameters, options aper.DecodeState) (s24.PC5QoSParameters, aper.Snapshot) {
				s := aper.SemanticCaptureFor(
					options)
				f := s.Begin()
				s24.BridgeCaptureS1APPC5QoSParameters(&v, &s)
				var root aper.Snapshot
				s.End(f, &root, false)
				return v, root
			}
			*s24.BridgePC5QoSParametersValueCodecFieldCompare(&sealed) = func(v s24.PC5QoSParameters, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
				s := aper.NewSemanticComparison(root, budget)
				f := s.Begin()
				s24.BridgeCompareS1APPC5QoSParameters(&v, &s)
				s.End(f, root, false)
				return s.
					Plan(), s.BudgetValue()
			}
			*s24.BridgePC5QoSParametersValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
				sealed := s00.BridgeCodecContext{}
				*s00.BridgecodecContextFieldSource(&sealed) = "source-value:PC5QoSParameters"
				*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
				return sealed
			}()
			return sealed
		}()
		*s46.BridgeUEContextModificationRequestPC5QoSParametersIEBindingFieldInject(&sealed) = func(value s24.PC5QoSParameters) s46.UEContextModificationRequestIEValue {
			return func() s46.UEContextModificationRequestIEValue {
				sealed := s46.UEContextModificationRequestIEValue{}
				*s46.BridgeUEContextModificationRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(308)
				*s46.BridgeUEContextModificationRequestIEValueFieldRowPC5QoSParameters(&sealed) = &value
				return sealed
			}()
		}
		*s46.BridgeUEContextModificationRequestPC5QoSParametersIEBindingFieldGet(&sealed) = func(value *s46.UEContextModificationRequestIEValue) (*s24.PC5QoSParameters, bool) {
			return value.AsPC5QoSParameters()
		}
		return sealed
	}()
}
func (UEContextModificationRequestIETable) infoUERadioCapabilityID() s00.FieldInfo {
	return s00.FieldInfo{Table: UEContextModificationRequestIEs().ID(), ID: s00.ProtocolIEID(314), Criticality: s00.CriticalityReject, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "UERadioCapabilityID"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "UEContextModificationRequestIEs", Row: "id-UERadioCapabilityID"}}}
}

// UERadioCapabilityID returns the typed binding for the UERadioCapabilityID row of UEContextModificationRequestIETable.
func (t UEContextModificationRequestIETable) UERadioCapabilityID() s46.UEContextModificationRequestUERadioCapabilityIDIEBinding {
	return func() s46.UEContextModificationRequestUERadioCapabilityIDIEBinding {
		sealed := s46.UEContextModificationRequestUERadioCapabilityIDIEBinding{}
		*s46.BridgeUEContextModificationRequestUERadioCapabilityIDIEBindingFieldInfo(&sealed) = t.infoUERadioCapabilityID()
		*s46.BridgeUEContextModificationRequestUERadioCapabilityIDIEBindingFieldCodec(&sealed) = func() s02.UERadioCapabilityIDValueCodec {
			sealed := s02.UERadioCapabilityIDValueCodec{}
			*s02.BridgeUERadioCapabilityIDValueCodecFieldPath(&sealed) = "UERadioCapabilityID"
			*s02.BridgeUERadioCapabilityIDValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.UERadioCapabilityID, error) {
				raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
				if err != nil {
					var empty s00.UERadioCapabilityID
					return empty, err
				}
				raw.BudgetBuffer().EnterComponent("UERadioCapabilityID")
				var zero s46.UEContextModificationRequestIEValue
				decoded, err := s46.BridgeUEContextModificationRequestIEValueMethodDecode(zero, s00.ProtocolIEID(314), raw)
				if err != nil {
					var empty s00.UERadioCapabilityID
					return empty, runtime.WrapDecodePath(err, "UERadioCapabilityID")
				}
				value, ok := decoded.AsUERadioCapabilityID()
				if !ok {
					var empty s00.UERadioCapabilityID
					return empty, fmt.Errorf("binding UEContextModificationRequestIEs.id-UERadioCapabilityID: no selected value")
				}
				return *value, nil
			}
			*s02.BridgeUERadioCapabilityIDValueCodecFieldEncode(&sealed) = func(value s00.UERadioCapabilityID, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
				return s46.BridgeUEContextModificationRequestIEValueMethodEncodeFresh((func() s46.UEContextModificationRequestIEValue {
					sealed := s46.UEContextModificationRequestIEValue{}
					*s46.BridgeUEContextModificationRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(314)
					*s46.BridgeUEContextModificationRequestIEValueFieldRowUERadioCapabilityID(&sealed) = &value
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
		}()
		*s46.BridgeUEContextModificationRequestUERadioCapabilityIDIEBindingFieldInject(&sealed) = func(value s00.UERadioCapabilityID) s46.UEContextModificationRequestIEValue {
			return func() s46.UEContextModificationRequestIEValue {
				sealed := s46.UEContextModificationRequestIEValue{}
				*s46.BridgeUEContextModificationRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(314)
				*s46.BridgeUEContextModificationRequestIEValueFieldRowUERadioCapabilityID(&sealed) = &value
				return sealed
			}()
		}
		*s46.BridgeUEContextModificationRequestUERadioCapabilityIDIEBindingFieldGet(&sealed) = func(value *s46.UEContextModificationRequestIEValue) (*s00.UERadioCapabilityID, bool) {
			return value.AsUERadioCapabilityID()
		}
		return sealed
	}()
}
func (UEContextModificationRequestIETable) infoTimeRefDistribution() s00.FieldInfo {
	return s00.FieldInfo{Table: UEContextModificationRequestIEs().ID(), ID: s00.ProtocolIEID(355), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "TimeRefDistribution"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "UEContextModificationRequestIEs", Row: "id-TimeRefDistribution"}}}
}

// TimeRefDistribution returns the typed binding for the TimeRefDistribution row of UEContextModificationRequestIETable.
func (t UEContextModificationRequestIETable) TimeRefDistribution() s46.UEContextModificationRequestTimeRefDistributionIEBinding {
	return func() s46.UEContextModificationRequestTimeRefDistributionIEBinding {
		sealed := s46.UEContextModificationRequestTimeRefDistributionIEBinding{}
		*s46.BridgeUEContextModificationRequestTimeRefDistributionIEBindingFieldInfo(&sealed) = t.infoTimeRefDistribution()
		*s46.BridgeUEContextModificationRequestTimeRefDistributionIEBindingFieldCodec(&sealed) = func() s02.TimeRefDistributionValueCodec {
			sealed := s02.TimeRefDistributionValueCodec{}
			*s02.BridgeTimeRefDistributionValueCodecFieldPath(&sealed) = "TimeRefDistribution"
			*s02.BridgeTimeRefDistributionValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.TimeRefDistribution, error) {
				raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
				if err != nil {
					var empty s00.TimeRefDistribution
					return empty, err
				}
				raw.BudgetBuffer().EnterComponent("TimeRefDistribution")
				var zero s46.UEContextModificationRequestIEValue
				decoded, err := s46.BridgeUEContextModificationRequestIEValueMethodDecode(zero, s00.ProtocolIEID(355), raw)
				if err != nil {
					var empty s00.TimeRefDistribution
					return empty, runtime.WrapDecodePath(err, "TimeRefDistribution")
				}
				value, ok := decoded.AsTimeRefDistribution()
				if !ok {
					var empty s00.TimeRefDistribution
					return empty, fmt.Errorf("binding UEContextModificationRequestIEs.id-TimeRefDistribution: no selected value")
				}
				return *value, nil
			}
			*s02.BridgeTimeRefDistributionValueCodecFieldEncode(&sealed) = func(value s00.TimeRefDistribution, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
				return s46.BridgeUEContextModificationRequestIEValueMethodEncodeFresh((func() s46.UEContextModificationRequestIEValue {
					sealed := s46.UEContextModificationRequestIEValue{}
					*s46.BridgeUEContextModificationRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(355)
					*s46.BridgeUEContextModificationRequestIEValueFieldRowTimeRefDistribution(&sealed) = &value
					return sealed
				}()), fresh, budget)
			}
			*s02.BridgeTimeRefDistributionValueCodecFieldCapture(&sealed) = func(v s00.TimeRefDistribution, options aper.DecodeState) (s00.TimeRefDistribution, aper.Snapshot,
			) {
				s := aper.SemanticCaptureFor(options)
				f := s.Begin()
				s00.BridgeCaptureS1APTimeRefDistribution(&v, &s)
				var root aper.Snapshot
				s.End(f, &root, false)
				return v, root
			}
			*s02.BridgeTimeRefDistributionValueCodecFieldCompare(&sealed) = func(v s00.TimeRefDistribution, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
			) {
				s := aper.NewSemanticComparison(root, budget)
				f := s.Begin()
				s07.BridgeCompareS1APTimeRefDistribution(&v, &s)
				s.End(f, root, false)
				return s.Plan(), s.BudgetValue()
			}
			*s02.BridgeTimeRefDistributionValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
				sealed := s00.BridgeCodecContext{}
				*s00.BridgecodecContextFieldSource(&sealed) = "source-value:TimeRefDistribution"
				*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
				return sealed
			}()
			return sealed
		}()
		*s46.BridgeUEContextModificationRequestTimeRefDistributionIEBindingFieldInject(&sealed) = func(value s00.TimeRefDistribution) s46.UEContextModificationRequestIEValue {
			return func() s46.UEContextModificationRequestIEValue {
				sealed := s46.UEContextModificationRequestIEValue{}
				*s46.BridgeUEContextModificationRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(355)
				*s46.BridgeUEContextModificationRequestIEValueFieldRowTimeRefDistribution(&sealed) = &value
				return sealed
			}()
		}
		*s46.BridgeUEContextModificationRequestTimeRefDistributionIEBindingFieldGet(&sealed) = func(value *s46.UEContextModificationRequestIEValue) (*s00.TimeRefDistribution, bool) {
			return value.AsTimeRefDistribution()
		}
		return sealed
	}()
}

// NewOpaque constructs an owned opaque field for an identifier without a typed row in UEContextModificationRequestIETable.
func (t UEContextModificationRequestIETable) NewOpaque(id s00.ProtocolIEID, criticality s00.Criticality, data []byte) (s46.UEContextModificationRequestIEField, error) {
	if id < 0 || id > 65535 || criticality < 0 || criticality > 2 {
		return s46.UEContextModificationRequestIEField{}, aper.OperationError(fmt.Errorf("invalid opaque IE selector or criticality"), "Opaque")
	}
	switch id {
	case s00.ProtocolIEID(0):
		return s46.UEContextModificationRequestIEField{}, aper.OperationError(fmt.Errorf("known IE id-MME-UE-S1AP-ID requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(8):
		return s46.UEContextModificationRequestIEField{}, aper.OperationError(fmt.Errorf("known IE id-eNB-UE-S1AP-ID requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(73):
		return s46.UEContextModificationRequestIEField{}, aper.OperationError(fmt.Errorf("known IE id-SecurityKey requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(106):
		return s46.UEContextModificationRequestIEField{}, aper.OperationError(fmt.Errorf("known IE id-SubscriberProfileIDforRFP requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(66):
		return s46.UEContextModificationRequestIEField{}, aper.OperationError(fmt.Errorf("known IE id-uEaggregateMaximumBitrate requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(108):
		return s46.UEContextModificationRequestIEField{}, aper.OperationError(fmt.Errorf("known IE id-CSFallbackIndicator requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(107):
		return s46.UEContextModificationRequestIEField{}, aper.OperationError(fmt.Errorf("known IE id-UESecurityCapabilities requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(146):
		return s46.UEContextModificationRequestIEField{}, aper.OperationError(fmt.Errorf("known IE id-CSGMembershipStatus requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(159):
		return s46.UEContextModificationRequestIEField{}, aper.OperationError(fmt.Errorf("known IE id-RegisteredLAI requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(187):
		return s46.UEContextModificationRequestIEField{}, aper.OperationError(fmt.Errorf("known IE id-AdditionalCSFallbackIndicator requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(195):
		return s46.UEContextModificationRequestIEField{}, aper.OperationError(fmt.Errorf("known IE id-ProSeAuthorized requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(124):
		return s46.UEContextModificationRequestIEField{}, aper.OperationError(fmt.Errorf("known IE id-SRVCCOperationPossible requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(243):
		return s46.UEContextModificationRequestIEField{}, aper.OperationError(fmt.Errorf("known IE id-SRVCCOperationNotPossible requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(240):
		return s46.UEContextModificationRequestIEField{}, aper.OperationError(fmt.Errorf("known IE id-V2XServicesAuthorized requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(248):
		return s46.UEContextModificationRequestIEField{}, aper.OperationError(fmt.Errorf("known IE id-UESidelinkAggregateMaximumBitrate requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(269):
		return s46.UEContextModificationRequestIEField{}, aper.OperationError(fmt.Errorf("known IE id-NRUESecurityCapabilities requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(277):
		return s46.UEContextModificationRequestIEField{}, aper.OperationError(fmt.Errorf("known IE id-AerialUEsubscriptionInformation requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(299):
		return s46.UEContextModificationRequestIEField{}, aper.OperationError(fmt.Errorf("known IE id-AdditionalRRMPriorityIndex requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(301):
		return s46.UEContextModificationRequestIEField{}, aper.OperationError(fmt.Errorf("known IE id-IAB-Authorized requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(306):
		return s46.UEContextModificationRequestIEField{}, aper.OperationError(fmt.Errorf("known IE id-NRV2XServicesAuthorized requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(307):
		return s46.UEContextModificationRequestIEField{}, aper.OperationError(fmt.Errorf("known IE id-NRUESidelinkAggregateMaximumBitrate requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(308):
		return s46.UEContextModificationRequestIEField{}, aper.OperationError(fmt.Errorf("known IE id-PC5QoSParameters requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(314):
		return s46.UEContextModificationRequestIEField{}, aper.OperationError(fmt.Errorf("known IE id-UERadioCapabilityID requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(355):
		return s46.UEContextModificationRequestIEField{}, aper.OperationError(fmt.Errorf("known IE id-TimeRefDistribution requires its typed binding"), "Opaque")
	default:
		budget, err := aper.BuildBudget()
		if err != nil {
			return s46.UEContextModificationRequestIEField{}, aper.OperationError(err, "Opaque")
		}
		opaque, err := aper.BuildOpaqueOpenType(data, budget)
		if err != nil {
			return s46.UEContextModificationRequestIEField{}, aper.OperationError(err, "Opaque")
		}
		return s46.UEContextModificationRequestIEField{Id: id, Criticality: criticality, Value: func() s46.UEContextModificationRequestIEValue {
			sealed := s46.UEContextModificationRequestIEValue{}
			*s46.BridgeUEContextModificationRequestIEValueFieldId(&sealed) = id
			*s46.BridgeUEContextModificationRequestIEValueFieldOpaque(&sealed) = opaque
			*s46.BridgeUEContextModificationRequestIEValueFieldIsOpaque(&sealed) = true
			return sealed
		}()}, aper.OperationError(nil, "Opaque")
	}
}

// BluetoothMeasurementConfigurationCodec binds the complete APER value type.
func BluetoothMeasurementConfigurationCodec() s14.BluetoothMeasurementConfigurationValueCodec {
	return ImmediateMDTExtIEs().BluetoothMeasurementConfiguration().Codec()
}

// ERABToBeSwitchedULListCodec binds the complete APER value type.
func ERABToBeSwitchedULListCodec() s17.ERABToBeSwitchedULListValueCodec {
	return PathSwitchRequestAcknowledgeIEs().ERABToBeSwitchedULList().Codec()
}

// ERABToBeUpdatedListCodec binds the complete APER value type.
func ERABToBeUpdatedListCodec() s29.ERABToBeUpdatedListValueCodec {
	return PathSwitchRequestAcknowledgeIEs().ERABToBeUpdatedList().Codec()
}

// ImmediateMDTCodec binds the complete source value type.
func ImmediateMDTCodec() ImmediateMDTValueCodec {
	return ImmediateMDTValueCodec{path: "ImmediateMDT", decode: func(data []byte, options aper.DecodeState) (ImmediateMDT, error) {
		var value ImmediateMDT
		if err := value.unmarshalAPERWithOptions(data, options); err != nil {
			return ImmediateMDT{}, err
		}
		value.received = true
		value.receivedAbsolute = true
		value.receivedBytes = aper.OriginalWire(data)
		return value, nil
	}, encode: func(value ImmediateMDT, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return (&value).marshalAPERBudget(budget, fresh)
	}, capture: func(v ImmediateMDT, options aper.DecodeState) (ImmediateMDT, aper.Snapshot) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeCaptureS1APImmediateMDT(&v, &s)
		var root aper.Snapshot
		s.End(f, &root, false)
		return v, root
	}, compare: func(v ImmediateMDT, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		BridgeCompareS1APImmediateMDT(&v, &s)
		s.End(f, root, false)
		return s.Plan(),
			s.
				BudgetValue()
	}, context: func() s00.BridgeCodecContext {
		sealed := s00.BridgeCodecContext{}
		*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ImmediateMDT"
		*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
		return sealed
	}(),
	}
}

// LoggedMDTCodec binds the complete source value type.
func LoggedMDTCodec() LoggedMDTValueCodec {
	return LoggedMDTValueCodec{path: "LoggedMDT", decode: func(data []byte, options aper.DecodeState) (LoggedMDT, error) {
		var value LoggedMDT
		if err := value.unmarshalAPERWithOptions(data, options); err != nil {
			return LoggedMDT{}, err
		}
		value.received = true
		value.receivedAbsolute = true
		value.receivedBytes = aper.OriginalWire(data)
		return value, nil
	}, encode: func(value LoggedMDT, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return (&value).marshalAPERBudget(budget, fresh)
	}, capture: func(v LoggedMDT, options aper.DecodeState) (LoggedMDT, aper.Snapshot) {
		s := aper.SemanticCaptureFor(options)
		f := s.
			Begin()
		BridgeCaptureS1APLoggedMDT(&v, &s)
		var root aper.Snapshot
		s.End(f, &root, false)
		return v, root
	}, compare: func(v LoggedMDT, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

	) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		BridgeCompareS1APLoggedMDT(&v, &s)
		s.End(f, root, false)
		return s.Plan(), s.BudgetValue()
	}, context: func() s00.BridgeCodecContext {
		sealed := s00.BridgeCodecContext{}
		*s00.BridgecodecContextFieldSource(&sealed) = "source-value:LoggedMDT"
		*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
		return sealed
	}(),
	}
}

// LoggedMDTTriggerCodec binds the complete APER value type.
func LoggedMDTTriggerCodec() s19.LoggedMDTTriggerValueCodec {
	return LoggedMDTExtIEs().LoggedMDTTrigger().Codec()
}

// M3ConfigurationCodec binds the complete APER value type.
func M3ConfigurationCodec() s19.M3ConfigurationValueCodec {
	return ImmediateMDTExtIEs().M3Configuration().Codec()
}

// M4ConfigurationCodec binds the complete APER value type.
func M4ConfigurationCodec() s19.M4ConfigurationValueCodec {
	return ImmediateMDTExtIEs().M4Configuration().Codec()
}

// M5ConfigurationCodec binds the complete APER value type.
func M5ConfigurationCodec() s19.M5ConfigurationValueCodec {
	return ImmediateMDTExtIEs().M5Configuration().Codec()
}

// M6ConfigurationCodec binds the complete APER value type.
func M6ConfigurationCodec() s19.M6ConfigurationValueCodec {
	return ImmediateMDTExtIEs().M6Configuration().Codec()
}

// M7ConfigurationCodec binds the complete APER value type.
func M7ConfigurationCodec() s19.M7ConfigurationValueCodec {
	return ImmediateMDTExtIEs().M7Configuration().Codec()
}

// MDTConfigurationCodec binds the complete APER value type.
func MDTConfigurationCodec() MDTConfigurationValueCodec {
	return TraceActivationExtIEs().MDTConfiguration().Codec()
}

// MDTConfigurationNRCodec binds the complete APER value type.
func MDTConfigurationNRCodec() s01.MDTConfigurationNRValueCodec {
	return TraceActivationExtIEs().MDTConfigurationNR().Codec()
}

// MDTLocationInfoCodec binds the complete APER value type.
func MDTLocationInfoCodec() s01.MDTLocationInfoValueCodec {
	return ImmediateMDTExtIEs().MDTLocationInfo().Codec()
}

// MDTModeCodec binds the complete source value type.
func MDTModeCodec() MDTModeValueCodec {
	return MDTModeValueCodec{path: "MDTMode", decode: func(data []byte, options aper.DecodeState) (MDTMode, error) {
		var value MDTMode
		if err := value.unmarshalAPERWithOptions(data, options); err != nil {
			return MDTMode{}, err
		}
		value.received = true
		value.receivedAbsolute = true
		value.receivedBytes = aper.OriginalWire(data)
		return value, nil
	}, encode: func(value MDTMode, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return (&value).marshalAPERBudget(budget, fresh)
	}, capture: func(v MDTMode, options aper.DecodeState) (MDTMode, aper.Snapshot) {
		s := aper.SemanticCaptureFor(options)
		f :=
			s.Begin()
		BridgeCaptureS1APMDTMode(&v, &s)
		var root aper.Snapshot
		s.
			End(f, &root, false)
		return v, root
	}, compare: func(v MDTMode, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
	) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		BridgeCompareS1APMDTMode(&v, &s)
		s.End(f, root, false)
		return s.Plan(), s.BudgetValue()
	}, context: func() s00.BridgeCodecContext {
		sealed := s00.BridgeCodecContext{}
		*s00.BridgecodecContextFieldSource(&sealed) = "source-value:MDTMode"
		*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
		return sealed
	}(),
	}
}

// SRVCCOperationNotPossibleCodec binds the complete APER value type.
func SRVCCOperationNotPossibleCodec() s01.SRVCCOperationNotPossibleValueCodec {
	return UEContextModificationRequestIEs().SRVCCOperationNotPossible().Codec()
}

// SensorMeasurementConfigurationCodec binds the complete APER value type.
func SensorMeasurementConfigurationCodec() s30.SensorMeasurementConfigurationValueCodec {
	return ImmediateMDTExtIEs().SensorMeasurementConfiguration().Codec()
}

// UEAppLayerMeasConfigCodec binds the complete APER value type.
func UEAppLayerMeasConfigCodec() s35.UEAppLayerMeasConfigValueCodec {
	return TraceActivationExtIEs().UEAppLayerMeasConfig().Codec()
}

// URIAddressCodec binds the complete APER value type.
func URIAddressCodec() s02.URIAddressValueCodec {
	return TraceActivationExtIEs().TraceCollectionEntityURI().Codec()
}

// WLANMeasurementConfigurationCodec binds the complete APER value type.
func WLANMeasurementConfigurationCodec() WLANMeasurementConfigurationValueCodec {
	return ImmediateMDTExtIEs().WLANMeasurementConfiguration().Codec()
}
func BridgeValidationHasValueMismatch(report s21.ValidationReport) bool {
	for _, issue := range report.Issues {
		if issue.Code == s00.ValueIDMismatch {
			return true
		}
	}
	return false
}
func BridgeValidatePrivateMessageBudget(v *s26.PrivateMessage, budget *aper.DecodeBudget,

) (s21.ValidationReport, error) {
	if v == nil {
		return func() s21.ValidationReport {
			sealed := s21.ValidationReport{}
			*s21.BridgeValidationReportFieldBudget(&sealed) = budget
			return sealed
		}(), fmt.Errorf("nil PrivateMessage")
	}
	report := func() s21.ValidationReport {
		report := func() s21.ValidationReport {
			sealed := s21.ValidationReport{Complete: false}
			*s21.BridgeValidationReportFieldBudget(&sealed) = budget
			return sealed
		}()
		s21.BridgeValidationReportMethodAddUnchecked(&report, aper.Location{Path: "PrivateMessage.privateIEs"})
		return report
	}()
	for i, field := range v.PrivateIEs {
		if *s21.BridgeValidationReportFieldErr(&report) != nil {
			return report, *s21.BridgeValidationReportFieldErr(&report)
		}
		if !s25.BridgePrivateMessageIEsValueMethodMatchesID(field.Value, field.Id, budget) {
			id := field.Id
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.ValueIDMismatch, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: aper.Path(fmt.Sprintf("PrivateMessage.privateIEs[%d].id", i))}, PrivateID: &id, Rule: s26.BridgeS1apValidationRule(s00.ValueIDMismatch), RelatedRules: []aper.SourceRule{s25.BridgePrivateMessageIEsValueMethodRule(field.Value)}})
		}
	}
	return report, nil
}
func ValidatePrivateMessage(v *s26.PrivateMessage, options ...aper.ValidationOption) (s21.ValidationReport, error) {
	budget, err := aper.ValidationBudget(options...)
	if err != nil {
		return s21.ValidationReport{}, aper.OperationError(err, "PrivateMessage")
	}
	report, err := BridgeValidatePrivateMessageBudget(v, budget)
	if err == nil && !BridgeValidationHasValueMismatch(report) {
		_, err = s26.BridgePrivateMessageMethodMarshalAPERBudget(v, budget, false)
	}
	if *s21.BridgeValidationReportFieldErr(&report) != nil {
		err = *s21.BridgeValidationReportFieldErr(&report)
	}
	*s21.BridgeValidationReportFieldBudget(&report) = nil
	*s21.BridgeValidationReportFieldErr(&report) = nil
	return report, aper.OperationError(err, "PrivateMessage")
}
func BridgeImmediateMDTAPERValueFieldContext(v *ImmediateMDTAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeImmediateMDTAPERValueFieldReceived(v *ImmediateMDTAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeImmediateMDTAPERValueFieldReplay(v *ImmediateMDTAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeImmediateMDTAPERValueFieldWithoutReplay(v *ImmediateMDTAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeImmediateMDTExtIETableMethodInfoBluetoothMeasurementConfiguration(v ImmediateMDTExtIETable) s00.ExtensionInfo {
	return v.infoBluetoothMeasurementConfiguration()
}
func BridgeImmediateMDTExtIETableMethodInfoM3Configuration(v ImmediateMDTExtIETable) s00.ExtensionInfo {
	return v.infoM3Configuration()
}
func BridgeImmediateMDTExtIETableMethodInfoM4Configuration(v ImmediateMDTExtIETable) s00.ExtensionInfo {
	return v.infoM4Configuration()
}
func BridgeImmediateMDTExtIETableMethodInfoM5Configuration(v ImmediateMDTExtIETable) s00.ExtensionInfo {
	return v.infoM5Configuration()
}
func BridgeImmediateMDTExtIETableMethodInfoM6Configuration(v ImmediateMDTExtIETable) s00.ExtensionInfo {
	return v.infoM6Configuration()
}
func BridgeImmediateMDTExtIETableMethodInfoM7Configuration(v ImmediateMDTExtIETable) s00.ExtensionInfo {
	return v.infoM7Configuration()
}
func BridgeImmediateMDTExtIETableMethodInfoMDTLocationInfo(v ImmediateMDTExtIETable) s00.ExtensionInfo {
	return v.infoMDTLocationInfo()
}
func BridgeImmediateMDTExtIETableMethodInfoSensorMeasurementConfiguration(v ImmediateMDTExtIETable) s00.ExtensionInfo {
	return v.infoSensorMeasurementConfiguration()
}
func BridgeImmediateMDTExtIETableMethodInfoWLANMeasurementConfiguration(v ImmediateMDTExtIETable) s00.ExtensionInfo {
	return v.infoWLANMeasurementConfiguration()
}
func BridgeImmediateMDTExtIEsBluetoothMeasurementConfigurationExtBindingFieldCodec(v *ImmediateMDTExtIEsBluetoothMeasurementConfigurationExtBinding) *s14.BluetoothMeasurementConfigurationValueCodec {
	return &v.codec
}
func BridgeImmediateMDTExtIEsBluetoothMeasurementConfigurationExtBindingFieldGet(v *ImmediateMDTExtIEsBluetoothMeasurementConfigurationExtBinding) *func(*ImmediateMDTExtIEsValue) (*s14.BluetoothMeasurementConfiguration, bool) {
	return &v.get
}
func BridgeImmediateMDTExtIEsBluetoothMeasurementConfigurationExtBindingFieldInfo(v *ImmediateMDTExtIEsBluetoothMeasurementConfigurationExtBinding) *s00.ExtensionInfo {
	return &v.info
}
func BridgeImmediateMDTExtIEsBluetoothMeasurementConfigurationExtBindingFieldInject(v *ImmediateMDTExtIEsBluetoothMeasurementConfigurationExtBinding) *func(s14.BluetoothMeasurementConfiguration) ImmediateMDTExtIEsValue {
	return &v.inject
}
func BridgeImmediateMDTExtIEsExtContainerAPERValueFieldContext(v *ImmediateMDTExtIEsExtContainerAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeImmediateMDTExtIEsExtContainerAPERValueFieldReceived(v *ImmediateMDTExtIEsExtContainerAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeImmediateMDTExtIEsExtContainerAPERValueFieldReplay(v *ImmediateMDTExtIEsExtContainerAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeImmediateMDTExtIEsExtContainerAPERValueFieldWithoutReplay(v *ImmediateMDTExtIEsExtContainerAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeImmediateMDTExtIEsExtContainerValueCodecFieldCapture(v *ImmediateMDTExtIEsExtContainerValueCodec) *func(ImmediateMDTExtIEsExtContainer, aper.DecodeState) (ImmediateMDTExtIEsExtContainer, aper.Snapshot) {
	return &v.capture
}
func BridgeImmediateMDTExtIEsExtContainerValueCodecFieldCompare(v *ImmediateMDTExtIEsExtContainerValueCodec) *func(ImmediateMDTExtIEsExtContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeImmediateMDTExtIEsExtContainerValueCodecFieldContext(v *ImmediateMDTExtIEsExtContainerValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeImmediateMDTExtIEsExtContainerValueCodecFieldDecode(v *ImmediateMDTExtIEsExtContainerValueCodec) *func([]byte, aper.DecodeState) (ImmediateMDTExtIEsExtContainer, error) {
	return &v.decode
}
func BridgeImmediateMDTExtIEsExtContainerValueCodecFieldEncode(v *ImmediateMDTExtIEsExtContainerValueCodec) *func(ImmediateMDTExtIEsExtContainer, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeImmediateMDTExtIEsExtContainerValueCodecFieldPath(v *ImmediateMDTExtIEsExtContainerValueCodec) *aper.Path {
	return &v.path
}
func BridgeImmediateMDTExtIEsExtContainerValueCodecMethodEncodeBudgetValue(v ImmediateMDTExtIEsExtContainerValueCodec, a0 ImmediateMDTExtIEsExtContainer, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeImmediateMDTExtIEsExtContainerValueCodecMethodEncodeChanged(v ImmediateMDTExtIEsExtContainerValueCodec, a0 ImmediateMDTExtIEsExtContainer, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeImmediateMDTExtIEsExtFieldAPERValueFieldContext(v *ImmediateMDTExtIEsExtFieldAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeImmediateMDTExtIEsExtFieldAPERValueFieldReceived(v *ImmediateMDTExtIEsExtFieldAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeImmediateMDTExtIEsExtFieldAPERValueFieldReplay(v *ImmediateMDTExtIEsExtFieldAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeImmediateMDTExtIEsExtFieldAPERValueFieldWithoutReplay(v *ImmediateMDTExtIEsExtFieldAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeImmediateMDTExtIEsExtFieldFieldReceived(v *ImmediateMDTExtIEsExtField) *aper.CompletePadding {
	return &v.received
}
func BridgeImmediateMDTExtIEsExtFieldFieldReplay(v *ImmediateMDTExtIEsExtField) *aper.Snapshot {
	return &v.replay
}
func BridgeImmediateMDTExtIEsExtFieldFieldStream(v *ImmediateMDTExtIEsExtField) *aper.WireSpan {
	return &v.stream
}
func BridgeImmediateMDTExtIEsExtFieldFieldWithoutReplay(v *ImmediateMDTExtIEsExtField) *bool {
	return &v.withoutReplay
}
func BridgeImmediateMDTExtIEsExtFieldMethodMarshalAPERTo(v *ImmediateMDTExtIEsExtField, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeImmediateMDTExtIEsExtFieldMethodUnmarshalAPERFrom(v *ImmediateMDTExtIEsExtField, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeImmediateMDTExtIEsExtFieldValueCodecFieldCapture(v *ImmediateMDTExtIEsExtFieldValueCodec) *func(ImmediateMDTExtIEsExtField, aper.DecodeState) (ImmediateMDTExtIEsExtField, aper.Snapshot) {
	return &v.capture
}
func BridgeImmediateMDTExtIEsExtFieldValueCodecFieldCompare(v *ImmediateMDTExtIEsExtFieldValueCodec) *func(ImmediateMDTExtIEsExtField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeImmediateMDTExtIEsExtFieldValueCodecFieldContext(v *ImmediateMDTExtIEsExtFieldValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeImmediateMDTExtIEsExtFieldValueCodecFieldDecode(v *ImmediateMDTExtIEsExtFieldValueCodec) *func([]byte, aper.DecodeState) (ImmediateMDTExtIEsExtField, error) {
	return &v.decode
}
func BridgeImmediateMDTExtIEsExtFieldValueCodecFieldEncode(v *ImmediateMDTExtIEsExtFieldValueCodec) *func(ImmediateMDTExtIEsExtField, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeImmediateMDTExtIEsExtFieldValueCodecFieldPath(v *ImmediateMDTExtIEsExtFieldValueCodec) *aper.Path {
	return &v.path
}
func BridgeImmediateMDTExtIEsExtFieldValueCodecMethodEncodeBudgetValue(v ImmediateMDTExtIEsExtFieldValueCodec, a0 ImmediateMDTExtIEsExtField, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeImmediateMDTExtIEsExtFieldValueCodecMethodEncodeChanged(v ImmediateMDTExtIEsExtFieldValueCodec, a0 ImmediateMDTExtIEsExtField, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeImmediateMDTExtIEsIEFieldFieldReceived(v *ImmediateMDTExtIEsIEField) *aper.CompletePadding {
	return &v.received
}
func BridgeImmediateMDTExtIEsIEFieldFieldReplay(v *ImmediateMDTExtIEsIEField) *aper.Snapshot {
	return &v.replay
}
func BridgeImmediateMDTExtIEsIEFieldFieldStream(v *ImmediateMDTExtIEsIEField) *aper.WireSpan {
	return &v.stream
}
func BridgeImmediateMDTExtIEsIEFieldFieldWithoutReplay(v *ImmediateMDTExtIEsIEField) *bool {
	return &v.withoutReplay
}
func BridgeImmediateMDTExtIEsIEFieldMethodMarshalAPERTo(v *ImmediateMDTExtIEsIEField, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeImmediateMDTExtIEsIEFieldMethodUnmarshalAPERFrom(v *ImmediateMDTExtIEsIEField, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeImmediateMDTExtIEsM3ConfigurationExtBindingFieldCodec(v *ImmediateMDTExtIEsM3ConfigurationExtBinding) *s19.M3ConfigurationValueCodec {
	return &v.codec
}
func BridgeImmediateMDTExtIEsM3ConfigurationExtBindingFieldGet(v *ImmediateMDTExtIEsM3ConfigurationExtBinding) *func(*ImmediateMDTExtIEsValue) (*s19.M3Configuration, bool) {
	return &v.get
}
func BridgeImmediateMDTExtIEsM3ConfigurationExtBindingFieldInfo(v *ImmediateMDTExtIEsM3ConfigurationExtBinding) *s00.ExtensionInfo {
	return &v.info
}
func BridgeImmediateMDTExtIEsM3ConfigurationExtBindingFieldInject(v *ImmediateMDTExtIEsM3ConfigurationExtBinding) *func(s19.M3Configuration) ImmediateMDTExtIEsValue {
	return &v.inject
}
func BridgeImmediateMDTExtIEsM4ConfigurationExtBindingFieldCodec(v *ImmediateMDTExtIEsM4ConfigurationExtBinding) *s19.M4ConfigurationValueCodec {
	return &v.codec
}
func BridgeImmediateMDTExtIEsM4ConfigurationExtBindingFieldGet(v *ImmediateMDTExtIEsM4ConfigurationExtBinding) *func(*ImmediateMDTExtIEsValue) (*s19.M4Configuration, bool) {
	return &v.get
}
func BridgeImmediateMDTExtIEsM4ConfigurationExtBindingFieldInfo(v *ImmediateMDTExtIEsM4ConfigurationExtBinding) *s00.ExtensionInfo {
	return &v.info
}
func BridgeImmediateMDTExtIEsM4ConfigurationExtBindingFieldInject(v *ImmediateMDTExtIEsM4ConfigurationExtBinding) *func(s19.M4Configuration) ImmediateMDTExtIEsValue {
	return &v.inject
}
func BridgeImmediateMDTExtIEsM5ConfigurationExtBindingFieldCodec(v *ImmediateMDTExtIEsM5ConfigurationExtBinding) *s19.M5ConfigurationValueCodec {
	return &v.codec
}
func BridgeImmediateMDTExtIEsM5ConfigurationExtBindingFieldGet(v *ImmediateMDTExtIEsM5ConfigurationExtBinding) *func(*ImmediateMDTExtIEsValue) (*s19.M5Configuration, bool) {
	return &v.get
}
func BridgeImmediateMDTExtIEsM5ConfigurationExtBindingFieldInfo(v *ImmediateMDTExtIEsM5ConfigurationExtBinding) *s00.ExtensionInfo {
	return &v.info
}
func BridgeImmediateMDTExtIEsM5ConfigurationExtBindingFieldInject(v *ImmediateMDTExtIEsM5ConfigurationExtBinding) *func(s19.M5Configuration) ImmediateMDTExtIEsValue {
	return &v.inject
}
func BridgeImmediateMDTExtIEsM6ConfigurationExtBindingFieldCodec(v *ImmediateMDTExtIEsM6ConfigurationExtBinding) *s19.M6ConfigurationValueCodec {
	return &v.codec
}
func BridgeImmediateMDTExtIEsM6ConfigurationExtBindingFieldGet(v *ImmediateMDTExtIEsM6ConfigurationExtBinding) *func(*ImmediateMDTExtIEsValue) (*s19.M6Configuration, bool) {
	return &v.get
}
func BridgeImmediateMDTExtIEsM6ConfigurationExtBindingFieldInfo(v *ImmediateMDTExtIEsM6ConfigurationExtBinding) *s00.ExtensionInfo {
	return &v.info
}
func BridgeImmediateMDTExtIEsM6ConfigurationExtBindingFieldInject(v *ImmediateMDTExtIEsM6ConfigurationExtBinding) *func(s19.M6Configuration) ImmediateMDTExtIEsValue {
	return &v.inject
}
func BridgeImmediateMDTExtIEsM7ConfigurationExtBindingFieldCodec(v *ImmediateMDTExtIEsM7ConfigurationExtBinding) *s19.M7ConfigurationValueCodec {
	return &v.codec
}
func BridgeImmediateMDTExtIEsM7ConfigurationExtBindingFieldGet(v *ImmediateMDTExtIEsM7ConfigurationExtBinding) *func(*ImmediateMDTExtIEsValue) (*s19.M7Configuration, bool) {
	return &v.get
}
func BridgeImmediateMDTExtIEsM7ConfigurationExtBindingFieldInfo(v *ImmediateMDTExtIEsM7ConfigurationExtBinding) *s00.ExtensionInfo {
	return &v.info
}
func BridgeImmediateMDTExtIEsM7ConfigurationExtBindingFieldInject(v *ImmediateMDTExtIEsM7ConfigurationExtBinding) *func(s19.M7Configuration) ImmediateMDTExtIEsValue {
	return &v.inject
}
func BridgeImmediateMDTExtIEsMDTLocationInfoExtBindingFieldCodec(v *ImmediateMDTExtIEsMDTLocationInfoExtBinding) *s01.MDTLocationInfoValueCodec {
	return &v.codec
}
func BridgeImmediateMDTExtIEsMDTLocationInfoExtBindingFieldGet(v *ImmediateMDTExtIEsMDTLocationInfoExtBinding) *func(*ImmediateMDTExtIEsValue) (*s00.MDTLocationInfo, bool) {
	return &v.get
}
func BridgeImmediateMDTExtIEsMDTLocationInfoExtBindingFieldInfo(v *ImmediateMDTExtIEsMDTLocationInfoExtBinding) *s00.ExtensionInfo {
	return &v.info
}
func BridgeImmediateMDTExtIEsMDTLocationInfoExtBindingFieldInject(v *ImmediateMDTExtIEsMDTLocationInfoExtBinding) *func(s00.MDTLocationInfo) ImmediateMDTExtIEsValue {
	return &v.inject
}
func BridgeImmediateMDTExtIEsSensorMeasurementConfigurationExtBindingFieldCodec(v *ImmediateMDTExtIEsSensorMeasurementConfigurationExtBinding) *s30.SensorMeasurementConfigurationValueCodec {
	return &v.codec
}
func BridgeImmediateMDTExtIEsSensorMeasurementConfigurationExtBindingFieldGet(v *ImmediateMDTExtIEsSensorMeasurementConfigurationExtBinding) *func(*ImmediateMDTExtIEsValue) (*s30.SensorMeasurementConfiguration, bool) {
	return &v.get
}
func BridgeImmediateMDTExtIEsSensorMeasurementConfigurationExtBindingFieldInfo(v *ImmediateMDTExtIEsSensorMeasurementConfigurationExtBinding) *s00.ExtensionInfo {
	return &v.info
}
func BridgeImmediateMDTExtIEsSensorMeasurementConfigurationExtBindingFieldInject(v *ImmediateMDTExtIEsSensorMeasurementConfigurationExtBinding) *func(s30.SensorMeasurementConfiguration) ImmediateMDTExtIEsValue {
	return &v.inject
}
func BridgeImmediateMDTExtIEsValueFieldId(v *ImmediateMDTExtIEsValue) *s00.ProtocolIEID { return &v.id }
func BridgeImmediateMDTExtIEsValueFieldIsOpaque(v *ImmediateMDTExtIEsValue) *bool       { return &v.isOpaque }
func BridgeImmediateMDTExtIEsValueFieldOpaque(v *ImmediateMDTExtIEsValue) *aper.OpaqueOpenType {
	return &v.opaque
}
func BridgeImmediateMDTExtIEsValueFieldReceived(v *ImmediateMDTExtIEsValue) *aper.WireSpan {
	return &v.received
}
func BridgeImmediateMDTExtIEsValueFieldReplay(v *ImmediateMDTExtIEsValue) *aper.Snapshot {
	return &v.replay
}
func BridgeImmediateMDTExtIEsValueFieldRowBluetoothMeasurementConfiguration(v *ImmediateMDTExtIEsValue) **s14.BluetoothMeasurementConfiguration {
	return &v.rowBluetoothMeasurementConfiguration
}
func BridgeImmediateMDTExtIEsValueFieldRowM3Configuration(v *ImmediateMDTExtIEsValue) **s19.M3Configuration {
	return &v.rowM3Configuration
}
func BridgeImmediateMDTExtIEsValueFieldRowM4Configuration(v *ImmediateMDTExtIEsValue) **s19.M4Configuration {
	return &v.rowM4Configuration
}
func BridgeImmediateMDTExtIEsValueFieldRowM5Configuration(v *ImmediateMDTExtIEsValue) **s19.M5Configuration {
	return &v.rowM5Configuration
}
func BridgeImmediateMDTExtIEsValueFieldRowM6Configuration(v *ImmediateMDTExtIEsValue) **s19.M6Configuration {
	return &v.rowM6Configuration
}
func BridgeImmediateMDTExtIEsValueFieldRowM7Configuration(v *ImmediateMDTExtIEsValue) **s19.M7Configuration {
	return &v.rowM7Configuration
}
func BridgeImmediateMDTExtIEsValueFieldRowMDTLocationInfo(v *ImmediateMDTExtIEsValue) **s00.MDTLocationInfo {
	return &v.rowMDTLocationInfo
}
func BridgeImmediateMDTExtIEsValueFieldRowSensorMeasurementConfiguration(v *ImmediateMDTExtIEsValue) **s30.SensorMeasurementConfiguration {
	return &v.rowSensorMeasurementConfiguration
}
func BridgeImmediateMDTExtIEsValueFieldRowWLANMeasurementConfiguration(v *ImmediateMDTExtIEsValue) **WLANMeasurementConfiguration {
	return &v.rowWLANMeasurementConfiguration
}
func BridgeImmediateMDTExtIEsValueMethodCaptureSemantics(v ImmediateMDTExtIEsValue, a0 aper.SemanticCapture) ImmediateMDTExtIEsValue {
	return v.captureSemantics(a0)
}
func BridgeImmediateMDTExtIEsValueMethodCompareSemantics(v ImmediateMDTExtIEsValue, a0 aper.SemanticComparison) aper.SemanticComparison {
	return v.compareSemantics(a0)
}
func BridgeImmediateMDTExtIEsValueMethodDecode(v ImmediateMDTExtIEsValue, a0 s00.ProtocolIEID, a1 aper.OpaqueOpenType) (ImmediateMDTExtIEsValue, error) {
	return v.decode(a0, a1)
}
func BridgeImmediateMDTExtIEsValueMethodEncode(v ImmediateMDTExtIEsValue) ([]byte, error) {
	return v.encode()
}
func BridgeImmediateMDTExtIEsValueMethodEncodeFresh(v ImmediateMDTExtIEsValue, a0 bool, a1 *aper.DecodeBudget) ([]byte, error) {
	return v.encodeFresh(a0, a1)
}
func BridgeImmediateMDTExtIEsValueMethodMatchesID(v ImmediateMDTExtIEsValue, a0 s00.ProtocolIEID, a1 ...*aper.DecodeBudget) bool {
	return v.matchesID(a0, a1...)
}
func BridgeImmediateMDTExtIEsValueMethodReason(v ImmediateMDTExtIEsValue, a0 s00.ProtocolIEID) aper.OpaqueReason {
	return v.reason(a0)
}
func BridgeImmediateMDTExtIEsValueMethodRule(v ImmediateMDTExtIEsValue) aper.SourceRule {
	return v.rule()
}
func BridgeImmediateMDTExtIEsWLANMeasurementConfigurationExtBindingFieldCodec(v *ImmediateMDTExtIEsWLANMeasurementConfigurationExtBinding) *WLANMeasurementConfigurationValueCodec {
	return &v.codec
}
func BridgeImmediateMDTExtIEsWLANMeasurementConfigurationExtBindingFieldGet(v *ImmediateMDTExtIEsWLANMeasurementConfigurationExtBinding) *func(*ImmediateMDTExtIEsValue) (*WLANMeasurementConfiguration, bool) {
	return &v.get
}
func BridgeImmediateMDTExtIEsWLANMeasurementConfigurationExtBindingFieldInfo(v *ImmediateMDTExtIEsWLANMeasurementConfigurationExtBinding) *s00.ExtensionInfo {
	return &v.info
}
func BridgeImmediateMDTExtIEsWLANMeasurementConfigurationExtBindingFieldInject(v *ImmediateMDTExtIEsWLANMeasurementConfigurationExtBinding) *func(WLANMeasurementConfiguration) ImmediateMDTExtIEsValue {
	return &v.inject
}
func BridgeImmediateMDTFieldExtCount(v *ImmediateMDT) *int64                { return &v.extCount }
func BridgeImmediateMDTFieldExtData(v *ImmediateMDT) *[][]byte              { return &v.extData }
func BridgeImmediateMDTFieldExtOrigin(v *ImmediateMDT) *[]aper.OpaqueOrigin { return &v.extOrigin }
func BridgeImmediateMDTFieldExtPresent(v *ImmediateMDT) *[]bool             { return &v.extPresent }
func BridgeImmediateMDTFieldExtWire(v *ImmediateMDT) *[]aper.WireSpan       { return &v.extWire }
func BridgeImmediateMDTFieldIEExtensionsIndef(v *ImmediateMDT) *bool        { return &v.iEExtensionsIndef }
func BridgeImmediateMDTFieldPerExtPadding(v *ImmediateMDT) *[]aper.CompletePadding {
	return &v.perExtPadding
}
func BridgeImmediateMDTFieldPerPadding(v *ImmediateMDT) *aper.FinalPadding { return &v.perPadding }
func BridgeImmediateMDTFieldReceived(v *ImmediateMDT) *bool                { return &v.received }
func BridgeImmediateMDTFieldReceivedAbsolute(v *ImmediateMDT) *bool        { return &v.receivedAbsolute }
func BridgeImmediateMDTFieldReceivedBytes(v *ImmediateMDT) *aper.WireSpan  { return &v.receivedBytes }
func BridgeImmediateMDTFieldReceivedLocation(v *ImmediateMDT) *aper.Location {
	return &v.receivedLocation
}
func BridgeImmediateMDTFieldReplay(v *ImmediateMDT) *aper.Snapshot { return &v.replay }
func BridgeImmediateMDTFieldStream(v *ImmediateMDT) *aper.WireSpan { return &v.stream }
func BridgeImmediateMDTFieldWithoutReplay(v *ImmediateMDT) *bool   { return &v.withoutReplay }
func BridgeImmediateMDTMethodMarshalAPERBudget(v *ImmediateMDT, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeImmediateMDTMethodMarshalAPERBudgetValue(v *ImmediateMDT, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudgetValue(a0, a1)
}
func BridgeImmediateMDTMethodMarshalAPERChanged(v *ImmediateMDT, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeImmediateMDTMethodMarshalAPERChangedValue(v *ImmediateMDT, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeImmediateMDTMethodMarshalAPERLegacy(v *ImmediateMDT) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeImmediateMDTMethodMarshalAPERNewValue(v *ImmediateMDT, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERNewValue(a0, a1)
}
func BridgeImmediateMDTMethodMarshalAPERPlanned(v *ImmediateMDT, a0 *aper.DecodeBudget, a1 bool, a2 *aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1, a2)
}
func BridgeImmediateMDTMethodMarshalAPERTo(v *ImmediateMDT, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeImmediateMDTMethodUnmarshalAPERFrom(v *ImmediateMDT, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeImmediateMDTMethodUnmarshalAPERLegacy(v *ImmediateMDT, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeImmediateMDTMethodUnmarshalAPERWithOptions(v *ImmediateMDT, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeImmediateMDTValueCodecFieldCapture(v *ImmediateMDTValueCodec) *func(ImmediateMDT, aper.DecodeState) (ImmediateMDT, aper.Snapshot) {
	return &v.capture
}
func BridgeImmediateMDTValueCodecFieldCompare(v *ImmediateMDTValueCodec) *func(ImmediateMDT, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeImmediateMDTValueCodecFieldContext(v *ImmediateMDTValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeImmediateMDTValueCodecFieldDecode(v *ImmediateMDTValueCodec) *func([]byte, aper.DecodeState) (ImmediateMDT, error) {
	return &v.decode
}
func BridgeImmediateMDTValueCodecFieldEncode(v *ImmediateMDTValueCodec) *func(ImmediateMDT, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeImmediateMDTValueCodecFieldPath(v *ImmediateMDTValueCodec) *aper.Path { return &v.path }
func BridgeImmediateMDTValueCodecMethodEncodeBudgetValue(v ImmediateMDTValueCodec, a0 ImmediateMDT, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeImmediateMDTValueCodecMethodEncodeChanged(v ImmediateMDTValueCodec, a0 ImmediateMDT, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeLoggedMDTAPERValueFieldContext(v *LoggedMDTAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeLoggedMDTAPERValueFieldReceived(v *LoggedMDTAPERValue) *aper.WireSpan { return &v.received }
func BridgeLoggedMDTAPERValueFieldReplay(v *LoggedMDTAPERValue) *aper.Snapshot   { return &v.replay }
func BridgeLoggedMDTAPERValueFieldWithoutReplay(v *LoggedMDTAPERValue) *bool     { return &v.withoutReplay }
func BridgeLoggedMDTExtIETableMethodInfoBluetoothMeasurementConfiguration(v LoggedMDTExtIETable) s00.ExtensionInfo {
	return v.infoBluetoothMeasurementConfiguration()
}
func BridgeLoggedMDTExtIETableMethodInfoLoggedMDTTrigger(v LoggedMDTExtIETable) s00.ExtensionInfo {
	return v.infoLoggedMDTTrigger()
}
func BridgeLoggedMDTExtIETableMethodInfoSensorMeasurementConfiguration(v LoggedMDTExtIETable) s00.ExtensionInfo {
	return v.infoSensorMeasurementConfiguration()
}
func BridgeLoggedMDTExtIETableMethodInfoWLANMeasurementConfiguration(v LoggedMDTExtIETable) s00.ExtensionInfo {
	return v.infoWLANMeasurementConfiguration()
}
func BridgeLoggedMDTExtIEsBluetoothMeasurementConfigurationExtBindingFieldCodec(v *LoggedMDTExtIEsBluetoothMeasurementConfigurationExtBinding) *s14.BluetoothMeasurementConfigurationValueCodec {
	return &v.codec
}
func BridgeLoggedMDTExtIEsBluetoothMeasurementConfigurationExtBindingFieldGet(v *LoggedMDTExtIEsBluetoothMeasurementConfigurationExtBinding) *func(*LoggedMDTExtIEsValue) (*s14.BluetoothMeasurementConfiguration, bool) {
	return &v.get
}
func BridgeLoggedMDTExtIEsBluetoothMeasurementConfigurationExtBindingFieldInfo(v *LoggedMDTExtIEsBluetoothMeasurementConfigurationExtBinding) *s00.ExtensionInfo {
	return &v.info
}
func BridgeLoggedMDTExtIEsBluetoothMeasurementConfigurationExtBindingFieldInject(v *LoggedMDTExtIEsBluetoothMeasurementConfigurationExtBinding) *func(s14.BluetoothMeasurementConfiguration) LoggedMDTExtIEsValue {
	return &v.inject
}
func BridgeLoggedMDTExtIEsExtContainerAPERValueFieldContext(v *LoggedMDTExtIEsExtContainerAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeLoggedMDTExtIEsExtContainerAPERValueFieldReceived(v *LoggedMDTExtIEsExtContainerAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeLoggedMDTExtIEsExtContainerAPERValueFieldReplay(v *LoggedMDTExtIEsExtContainerAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeLoggedMDTExtIEsExtContainerAPERValueFieldWithoutReplay(v *LoggedMDTExtIEsExtContainerAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeLoggedMDTExtIEsExtContainerValueCodecFieldCapture(v *LoggedMDTExtIEsExtContainerValueCodec) *func(LoggedMDTExtIEsExtContainer, aper.DecodeState) (LoggedMDTExtIEsExtContainer, aper.Snapshot) {
	return &v.capture
}
func BridgeLoggedMDTExtIEsExtContainerValueCodecFieldCompare(v *LoggedMDTExtIEsExtContainerValueCodec) *func(LoggedMDTExtIEsExtContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeLoggedMDTExtIEsExtContainerValueCodecFieldContext(v *LoggedMDTExtIEsExtContainerValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeLoggedMDTExtIEsExtContainerValueCodecFieldDecode(v *LoggedMDTExtIEsExtContainerValueCodec) *func([]byte, aper.DecodeState) (LoggedMDTExtIEsExtContainer, error) {
	return &v.decode
}
func BridgeLoggedMDTExtIEsExtContainerValueCodecFieldEncode(v *LoggedMDTExtIEsExtContainerValueCodec) *func(LoggedMDTExtIEsExtContainer, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeLoggedMDTExtIEsExtContainerValueCodecFieldPath(v *LoggedMDTExtIEsExtContainerValueCodec) *aper.Path {
	return &v.path
}
func BridgeLoggedMDTExtIEsExtContainerValueCodecMethodEncodeBudgetValue(v LoggedMDTExtIEsExtContainerValueCodec, a0 LoggedMDTExtIEsExtContainer, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeLoggedMDTExtIEsExtContainerValueCodecMethodEncodeChanged(v LoggedMDTExtIEsExtContainerValueCodec, a0 LoggedMDTExtIEsExtContainer, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeLoggedMDTExtIEsExtFieldAPERValueFieldContext(v *LoggedMDTExtIEsExtFieldAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeLoggedMDTExtIEsExtFieldAPERValueFieldReceived(v *LoggedMDTExtIEsExtFieldAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeLoggedMDTExtIEsExtFieldAPERValueFieldReplay(v *LoggedMDTExtIEsExtFieldAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeLoggedMDTExtIEsExtFieldAPERValueFieldWithoutReplay(v *LoggedMDTExtIEsExtFieldAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeLoggedMDTExtIEsExtFieldFieldReceived(v *LoggedMDTExtIEsExtField) *aper.CompletePadding {
	return &v.received
}
func BridgeLoggedMDTExtIEsExtFieldFieldReplay(v *LoggedMDTExtIEsExtField) *aper.Snapshot {
	return &v.replay
}
func BridgeLoggedMDTExtIEsExtFieldFieldStream(v *LoggedMDTExtIEsExtField) *aper.WireSpan {
	return &v.stream
}
func BridgeLoggedMDTExtIEsExtFieldFieldWithoutReplay(v *LoggedMDTExtIEsExtField) *bool {
	return &v.withoutReplay
}
func BridgeLoggedMDTExtIEsExtFieldMethodMarshalAPERTo(v *LoggedMDTExtIEsExtField, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeLoggedMDTExtIEsExtFieldMethodUnmarshalAPERFrom(v *LoggedMDTExtIEsExtField, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeLoggedMDTExtIEsExtFieldValueCodecFieldCapture(v *LoggedMDTExtIEsExtFieldValueCodec) *func(LoggedMDTExtIEsExtField, aper.DecodeState) (LoggedMDTExtIEsExtField, aper.Snapshot) {
	return &v.capture
}
func BridgeLoggedMDTExtIEsExtFieldValueCodecFieldCompare(v *LoggedMDTExtIEsExtFieldValueCodec) *func(LoggedMDTExtIEsExtField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeLoggedMDTExtIEsExtFieldValueCodecFieldContext(v *LoggedMDTExtIEsExtFieldValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeLoggedMDTExtIEsExtFieldValueCodecFieldDecode(v *LoggedMDTExtIEsExtFieldValueCodec) *func([]byte, aper.DecodeState) (LoggedMDTExtIEsExtField, error) {
	return &v.decode
}
func BridgeLoggedMDTExtIEsExtFieldValueCodecFieldEncode(v *LoggedMDTExtIEsExtFieldValueCodec) *func(LoggedMDTExtIEsExtField, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeLoggedMDTExtIEsExtFieldValueCodecFieldPath(v *LoggedMDTExtIEsExtFieldValueCodec) *aper.Path {
	return &v.path
}
func BridgeLoggedMDTExtIEsExtFieldValueCodecMethodEncodeBudgetValue(v LoggedMDTExtIEsExtFieldValueCodec, a0 LoggedMDTExtIEsExtField, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeLoggedMDTExtIEsExtFieldValueCodecMethodEncodeChanged(v LoggedMDTExtIEsExtFieldValueCodec, a0 LoggedMDTExtIEsExtField, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeLoggedMDTExtIEsIEFieldFieldReceived(v *LoggedMDTExtIEsIEField) *aper.CompletePadding {
	return &v.received
}
func BridgeLoggedMDTExtIEsIEFieldFieldReplay(v *LoggedMDTExtIEsIEField) *aper.Snapshot {
	return &v.replay
}
func BridgeLoggedMDTExtIEsIEFieldFieldStream(v *LoggedMDTExtIEsIEField) *aper.WireSpan {
	return &v.stream
}
func BridgeLoggedMDTExtIEsIEFieldFieldWithoutReplay(v *LoggedMDTExtIEsIEField) *bool {
	return &v.withoutReplay
}
func BridgeLoggedMDTExtIEsIEFieldMethodMarshalAPERTo(v *LoggedMDTExtIEsIEField, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeLoggedMDTExtIEsIEFieldMethodUnmarshalAPERFrom(v *LoggedMDTExtIEsIEField, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeLoggedMDTExtIEsLoggedMDTTriggerExtBindingFieldCodec(v *LoggedMDTExtIEsLoggedMDTTriggerExtBinding) *s19.LoggedMDTTriggerValueCodec {
	return &v.codec
}
func BridgeLoggedMDTExtIEsLoggedMDTTriggerExtBindingFieldGet(v *LoggedMDTExtIEsLoggedMDTTriggerExtBinding) *func(*LoggedMDTExtIEsValue) (*s19.LoggedMDTTrigger, bool) {
	return &v.get
}
func BridgeLoggedMDTExtIEsLoggedMDTTriggerExtBindingFieldInfo(v *LoggedMDTExtIEsLoggedMDTTriggerExtBinding) *s00.ExtensionInfo {
	return &v.info
}
func BridgeLoggedMDTExtIEsLoggedMDTTriggerExtBindingFieldInject(v *LoggedMDTExtIEsLoggedMDTTriggerExtBinding) *func(s19.LoggedMDTTrigger) LoggedMDTExtIEsValue {
	return &v.inject
}
func BridgeLoggedMDTExtIEsSensorMeasurementConfigurationExtBindingFieldCodec(v *LoggedMDTExtIEsSensorMeasurementConfigurationExtBinding) *s30.SensorMeasurementConfigurationValueCodec {
	return &v.codec
}
func BridgeLoggedMDTExtIEsSensorMeasurementConfigurationExtBindingFieldGet(v *LoggedMDTExtIEsSensorMeasurementConfigurationExtBinding) *func(*LoggedMDTExtIEsValue) (*s30.SensorMeasurementConfiguration, bool) {
	return &v.get
}
func BridgeLoggedMDTExtIEsSensorMeasurementConfigurationExtBindingFieldInfo(v *LoggedMDTExtIEsSensorMeasurementConfigurationExtBinding) *s00.ExtensionInfo {
	return &v.info
}
func BridgeLoggedMDTExtIEsSensorMeasurementConfigurationExtBindingFieldInject(v *LoggedMDTExtIEsSensorMeasurementConfigurationExtBinding) *func(s30.SensorMeasurementConfiguration) LoggedMDTExtIEsValue {
	return &v.inject
}
func BridgeLoggedMDTExtIEsValueFieldId(v *LoggedMDTExtIEsValue) *s00.ProtocolIEID { return &v.id }
func BridgeLoggedMDTExtIEsValueFieldIsOpaque(v *LoggedMDTExtIEsValue) *bool       { return &v.isOpaque }
func BridgeLoggedMDTExtIEsValueFieldOpaque(v *LoggedMDTExtIEsValue) *aper.OpaqueOpenType {
	return &v.opaque
}
func BridgeLoggedMDTExtIEsValueFieldReceived(v *LoggedMDTExtIEsValue) *aper.WireSpan {
	return &v.received
}
func BridgeLoggedMDTExtIEsValueFieldReplay(v *LoggedMDTExtIEsValue) *aper.Snapshot { return &v.replay }
func BridgeLoggedMDTExtIEsValueFieldRowBluetoothMeasurementConfiguration(v *LoggedMDTExtIEsValue) **s14.BluetoothMeasurementConfiguration {
	return &v.rowBluetoothMeasurementConfiguration
}
func BridgeLoggedMDTExtIEsValueFieldRowLoggedMDTTrigger(v *LoggedMDTExtIEsValue) **s19.LoggedMDTTrigger {
	return &v.rowLoggedMDTTrigger
}
func BridgeLoggedMDTExtIEsValueFieldRowSensorMeasurementConfiguration(v *LoggedMDTExtIEsValue) **s30.SensorMeasurementConfiguration {
	return &v.rowSensorMeasurementConfiguration
}
func BridgeLoggedMDTExtIEsValueFieldRowWLANMeasurementConfiguration(v *LoggedMDTExtIEsValue) **WLANMeasurementConfiguration {
	return &v.rowWLANMeasurementConfiguration
}
func BridgeLoggedMDTExtIEsValueMethodCaptureSemantics(v LoggedMDTExtIEsValue, a0 aper.SemanticCapture) LoggedMDTExtIEsValue {
	return v.captureSemantics(a0)
}
func BridgeLoggedMDTExtIEsValueMethodCompareSemantics(v LoggedMDTExtIEsValue, a0 aper.SemanticComparison) aper.SemanticComparison {
	return v.compareSemantics(a0)
}
func BridgeLoggedMDTExtIEsValueMethodDecode(v LoggedMDTExtIEsValue, a0 s00.ProtocolIEID, a1 aper.OpaqueOpenType) (LoggedMDTExtIEsValue, error) {
	return v.decode(a0, a1)
}
func BridgeLoggedMDTExtIEsValueMethodEncode(v LoggedMDTExtIEsValue) ([]byte, error) {
	return v.encode()
}
func BridgeLoggedMDTExtIEsValueMethodEncodeFresh(v LoggedMDTExtIEsValue, a0 bool, a1 *aper.DecodeBudget) ([]byte, error) {
	return v.encodeFresh(a0, a1)
}
func BridgeLoggedMDTExtIEsValueMethodMatchesID(v LoggedMDTExtIEsValue, a0 s00.ProtocolIEID, a1 ...*aper.DecodeBudget) bool {
	return v.matchesID(a0, a1...)
}
func BridgeLoggedMDTExtIEsValueMethodReason(v LoggedMDTExtIEsValue, a0 s00.ProtocolIEID) aper.OpaqueReason {
	return v.reason(a0)
}
func BridgeLoggedMDTExtIEsValueMethodRule(v LoggedMDTExtIEsValue) aper.SourceRule { return v.rule() }
func BridgeLoggedMDTExtIEsWLANMeasurementConfigurationExtBindingFieldCodec(v *LoggedMDTExtIEsWLANMeasurementConfigurationExtBinding) *WLANMeasurementConfigurationValueCodec {
	return &v.codec
}
func BridgeLoggedMDTExtIEsWLANMeasurementConfigurationExtBindingFieldGet(v *LoggedMDTExtIEsWLANMeasurementConfigurationExtBinding) *func(*LoggedMDTExtIEsValue) (*WLANMeasurementConfiguration, bool) {
	return &v.get
}
func BridgeLoggedMDTExtIEsWLANMeasurementConfigurationExtBindingFieldInfo(v *LoggedMDTExtIEsWLANMeasurementConfigurationExtBinding) *s00.ExtensionInfo {
	return &v.info
}
func BridgeLoggedMDTExtIEsWLANMeasurementConfigurationExtBindingFieldInject(v *LoggedMDTExtIEsWLANMeasurementConfigurationExtBinding) *func(WLANMeasurementConfiguration) LoggedMDTExtIEsValue {
	return &v.inject
}
func BridgeLoggedMDTFieldExtCount(v *LoggedMDT) *int64                       { return &v.extCount }
func BridgeLoggedMDTFieldExtData(v *LoggedMDT) *[][]byte                     { return &v.extData }
func BridgeLoggedMDTFieldExtOrigin(v *LoggedMDT) *[]aper.OpaqueOrigin        { return &v.extOrigin }
func BridgeLoggedMDTFieldExtPresent(v *LoggedMDT) *[]bool                    { return &v.extPresent }
func BridgeLoggedMDTFieldExtWire(v *LoggedMDT) *[]aper.WireSpan              { return &v.extWire }
func BridgeLoggedMDTFieldIEExtensionsIndef(v *LoggedMDT) *bool               { return &v.iEExtensionsIndef }
func BridgeLoggedMDTFieldPerExtPadding(v *LoggedMDT) *[]aper.CompletePadding { return &v.perExtPadding }
func BridgeLoggedMDTFieldPerPadding(v *LoggedMDT) *aper.FinalPadding         { return &v.perPadding }
func BridgeLoggedMDTFieldReceived(v *LoggedMDT) *bool                        { return &v.received }
func BridgeLoggedMDTFieldReceivedAbsolute(v *LoggedMDT) *bool                { return &v.receivedAbsolute }
func BridgeLoggedMDTFieldReceivedBytes(v *LoggedMDT) *aper.WireSpan          { return &v.receivedBytes }
func BridgeLoggedMDTFieldReceivedLocation(v *LoggedMDT) *aper.Location       { return &v.receivedLocation }
func BridgeLoggedMDTFieldReplay(v *LoggedMDT) *aper.Snapshot                 { return &v.replay }
func BridgeLoggedMDTFieldStream(v *LoggedMDT) *aper.WireSpan                 { return &v.stream }
func BridgeLoggedMDTFieldWithoutReplay(v *LoggedMDT) *bool                   { return &v.withoutReplay }
func BridgeLoggedMDTMethodMarshalAPERBudget(v *LoggedMDT, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeLoggedMDTMethodMarshalAPERBudgetValue(v *LoggedMDT, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudgetValue(a0, a1)
}
func BridgeLoggedMDTMethodMarshalAPERChanged(v *LoggedMDT, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeLoggedMDTMethodMarshalAPERChangedValue(v *LoggedMDT, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeLoggedMDTMethodMarshalAPERLegacy(v *LoggedMDT) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeLoggedMDTMethodMarshalAPERNewValue(v *LoggedMDT, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERNewValue(a0, a1)
}
func BridgeLoggedMDTMethodMarshalAPERPlanned(v *LoggedMDT, a0 *aper.DecodeBudget, a1 bool, a2 *aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1, a2)
}
func BridgeLoggedMDTMethodMarshalAPERTo(v *LoggedMDT, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeLoggedMDTMethodUnmarshalAPERFrom(v *LoggedMDT, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeLoggedMDTMethodUnmarshalAPERLegacy(v *LoggedMDT, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeLoggedMDTMethodUnmarshalAPERWithOptions(v *LoggedMDT, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeLoggedMDTValueCodecFieldCapture(v *LoggedMDTValueCodec) *func(LoggedMDT, aper.DecodeState) (LoggedMDT, aper.Snapshot) {
	return &v.capture
}
func BridgeLoggedMDTValueCodecFieldCompare(v *LoggedMDTValueCodec) *func(LoggedMDT, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeLoggedMDTValueCodecFieldContext(v *LoggedMDTValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeLoggedMDTValueCodecFieldDecode(v *LoggedMDTValueCodec) *func([]byte, aper.DecodeState) (LoggedMDT, error) {
	return &v.decode
}
func BridgeLoggedMDTValueCodecFieldEncode(v *LoggedMDTValueCodec) *func(LoggedMDT, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeLoggedMDTValueCodecFieldPath(v *LoggedMDTValueCodec) *aper.Path { return &v.path }
func BridgeLoggedMDTValueCodecMethodEncodeBudgetValue(v LoggedMDTValueCodec, a0 LoggedMDT, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeLoggedMDTValueCodecMethodEncodeChanged(v LoggedMDTValueCodec, a0 LoggedMDT, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeMDTConfigurationAPERValueFieldContext(v *MDTConfigurationAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeMDTConfigurationAPERValueFieldReceived(v *MDTConfigurationAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeMDTConfigurationAPERValueFieldReplay(v *MDTConfigurationAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeMDTConfigurationAPERValueFieldWithoutReplay(v *MDTConfigurationAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeMDTConfigurationFieldExtCount(v *MDTConfiguration) *int64   { return &v.extCount }
func BridgeMDTConfigurationFieldExtData(v *MDTConfiguration) *[][]byte { return &v.extData }
func BridgeMDTConfigurationFieldExtOrigin(v *MDTConfiguration) *[]aper.OpaqueOrigin {
	return &v.extOrigin
}
func BridgeMDTConfigurationFieldExtPresent(v *MDTConfiguration) *[]bool       { return &v.extPresent }
func BridgeMDTConfigurationFieldExtWire(v *MDTConfiguration) *[]aper.WireSpan { return &v.extWire }
func BridgeMDTConfigurationFieldIEExtensionsIndef(v *MDTConfiguration) *bool {
	return &v.iEExtensionsIndef
}
func BridgeMDTConfigurationFieldPerExtPadding(v *MDTConfiguration) *[]aper.CompletePadding {
	return &v.perExtPadding
}
func BridgeMDTConfigurationFieldPerPadding(v *MDTConfiguration) *aper.FinalPadding {
	return &v.perPadding
}
func BridgeMDTConfigurationFieldReceived(v *MDTConfiguration) *bool { return &v.received }
func BridgeMDTConfigurationFieldReceivedAbsolute(v *MDTConfiguration) *bool {
	return &v.receivedAbsolute
}
func BridgeMDTConfigurationFieldReceivedBytes(v *MDTConfiguration) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeMDTConfigurationFieldReceivedLocation(v *MDTConfiguration) *aper.Location {
	return &v.receivedLocation
}
func BridgeMDTConfigurationFieldReplay(v *MDTConfiguration) *aper.Snapshot { return &v.replay }
func BridgeMDTConfigurationFieldStream(v *MDTConfiguration) *aper.WireSpan { return &v.stream }
func BridgeMDTConfigurationFieldWithoutReplay(v *MDTConfiguration) *bool   { return &v.withoutReplay }
func BridgeMDTConfigurationMethodMarshalAPERBudget(v *MDTConfiguration, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeMDTConfigurationMethodMarshalAPERBudgetValue(v *MDTConfiguration, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudgetValue(a0, a1)
}
func BridgeMDTConfigurationMethodMarshalAPERChanged(v *MDTConfiguration, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeMDTConfigurationMethodMarshalAPERChangedValue(v *MDTConfiguration, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeMDTConfigurationMethodMarshalAPERLegacy(v *MDTConfiguration) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeMDTConfigurationMethodMarshalAPERNewValue(v *MDTConfiguration, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERNewValue(a0, a1)
}
func BridgeMDTConfigurationMethodMarshalAPERPlanned(v *MDTConfiguration, a0 *aper.DecodeBudget, a1 bool, a2 *aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1, a2)
}
func BridgeMDTConfigurationMethodMarshalAPERTo(v *MDTConfiguration, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeMDTConfigurationMethodUnmarshalAPERFrom(v *MDTConfiguration, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeMDTConfigurationMethodUnmarshalAPERLegacy(v *MDTConfiguration, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeMDTConfigurationMethodUnmarshalAPERWithOptions(v *MDTConfiguration, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeMDTConfigurationValueCodecFieldCapture(v *MDTConfigurationValueCodec) *func(MDTConfiguration, aper.DecodeState) (MDTConfiguration, aper.Snapshot) {
	return &v.capture
}
func BridgeMDTConfigurationValueCodecFieldCompare(v *MDTConfigurationValueCodec) *func(MDTConfiguration, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeMDTConfigurationValueCodecFieldContext(v *MDTConfigurationValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeMDTConfigurationValueCodecFieldDecode(v *MDTConfigurationValueCodec) *func([]byte, aper.DecodeState) (MDTConfiguration, error) {
	return &v.decode
}
func BridgeMDTConfigurationValueCodecFieldEncode(v *MDTConfigurationValueCodec) *func(MDTConfiguration, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeMDTConfigurationValueCodecFieldPath(v *MDTConfigurationValueCodec) *aper.Path {
	return &v.path
}
func BridgeMDTConfigurationValueCodecMethodEncodeBudgetValue(v MDTConfigurationValueCodec, a0 MDTConfiguration, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeMDTConfigurationValueCodecMethodEncodeChanged(v MDTConfigurationValueCodec, a0 MDTConfiguration, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeMDTModeAPERValueFieldContext(v *MDTModeAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeMDTModeAPERValueFieldReceived(v *MDTModeAPERValue) *aper.WireSpan { return &v.received }
func BridgeMDTModeAPERValueFieldReplay(v *MDTModeAPERValue) *aper.Snapshot   { return &v.replay }
func BridgeMDTModeAPERValueFieldWithoutReplay(v *MDTModeAPERValue) *bool     { return &v.withoutReplay }
func BridgeMDTModeFieldPerOpenTypePadding(v *MDTMode) *aper.CompletePadding {
	return &v.perOpenTypePadding
}
func BridgeMDTModeFieldPerPadding(v *MDTMode) *aper.CompletePadding { return &v.perPadding }
func BridgeMDTModeFieldReceived(v *MDTMode) *bool                   { return &v.received }
func BridgeMDTModeFieldReceivedAbsolute(v *MDTMode) *bool           { return &v.receivedAbsolute }
func BridgeMDTModeFieldReceivedBytes(v *MDTMode) *aper.WireSpan     { return &v.receivedBytes }
func BridgeMDTModeFieldReceivedLocation(v *MDTMode) *aper.Location  { return &v.receivedLocation }
func BridgeMDTModeFieldReplay(v *MDTMode) *aper.Snapshot            { return &v.replay }
func BridgeMDTModeFieldStream(v *MDTMode) *aper.WireSpan            { return &v.stream }
func BridgeMDTModeFieldWithoutReplay(v *MDTMode) *bool              { return &v.withoutReplay }
func BridgeMDTModeMethodMarshalAPERBudget(v *MDTMode, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeMDTModeMethodMarshalAPERBudgetValue(v *MDTMode, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudgetValue(a0, a1)
}
func BridgeMDTModeMethodMarshalAPERChanged(v *MDTMode, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeMDTModeMethodMarshalAPERChangedValue(v *MDTMode, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeMDTModeMethodMarshalAPERLegacy(v *MDTMode) ([]byte, error) { return v.marshalAPERLegacy() }
func BridgeMDTModeMethodMarshalAPERNewValue(v *MDTMode, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERNewValue(a0, a1)
}
func BridgeMDTModeMethodMarshalAPERPlanned(v *MDTMode, a0 *aper.DecodeBudget, a1 bool, a2 *aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1, a2)
}
func BridgeMDTModeMethodMarshalAPERTo(v *MDTMode, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeMDTModeMethodUnmarshalAPERFrom(v *MDTMode, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeMDTModeMethodUnmarshalAPERLegacy(v *MDTMode, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeMDTModeMethodUnmarshalAPERWithOptions(v *MDTMode, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeMDTModeValueCodecFieldCapture(v *MDTModeValueCodec) *func(MDTMode, aper.DecodeState) (MDTMode, aper.Snapshot) {
	return &v.capture
}
func BridgeMDTModeValueCodecFieldCompare(v *MDTModeValueCodec) *func(MDTMode, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeMDTModeValueCodecFieldContext(v *MDTModeValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeMDTModeValueCodecFieldDecode(v *MDTModeValueCodec) *func([]byte, aper.DecodeState) (MDTMode, error) {
	return &v.decode
}
func BridgeMDTModeValueCodecFieldEncode(v *MDTModeValueCodec) *func(MDTMode, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeMDTModeValueCodecFieldPath(v *MDTModeValueCodec) *aper.Path { return &v.path }
func BridgeMDTModeValueCodecMethodEncodeBudgetValue(v MDTModeValueCodec, a0 MDTMode, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeMDTModeValueCodecMethodEncodeChanged(v MDTModeValueCodec, a0 MDTMode, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgePathSwitchRequestAcknowledgeAPERValueFieldContext(v *PathSwitchRequestAcknowledgeAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgePathSwitchRequestAcknowledgeAPERValueFieldReceived(v *PathSwitchRequestAcknowledgeAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgePathSwitchRequestAcknowledgeAPERValueFieldReplay(v *PathSwitchRequestAcknowledgeAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgePathSwitchRequestAcknowledgeAPERValueFieldWithoutReplay(v *PathSwitchRequestAcknowledgeAPERValue) *bool {
	return &v.withoutReplay
}
func BridgePathSwitchRequestAcknowledgeFieldExtCount(v *PathSwitchRequestAcknowledge) *int64 {
	return &v.extCount
}
func BridgePathSwitchRequestAcknowledgeFieldExtData(v *PathSwitchRequestAcknowledge) *[][]byte {
	return &v.extData
}
func BridgePathSwitchRequestAcknowledgeFieldExtOrigin(v *PathSwitchRequestAcknowledge) *[]aper.OpaqueOrigin {
	return &v.extOrigin
}
func BridgePathSwitchRequestAcknowledgeFieldExtPresent(v *PathSwitchRequestAcknowledge) *[]bool {
	return &v.extPresent
}
func BridgePathSwitchRequestAcknowledgeFieldExtWire(v *PathSwitchRequestAcknowledge) *[]aper.WireSpan {
	return &v.extWire
}
func BridgePathSwitchRequestAcknowledgeFieldPerExtPadding(v *PathSwitchRequestAcknowledge) *[]aper.CompletePadding {
	return &v.perExtPadding
}
func BridgePathSwitchRequestAcknowledgeFieldPerPadding(v *PathSwitchRequestAcknowledge) *aper.FinalPadding {
	return &v.perPadding
}
func BridgePathSwitchRequestAcknowledgeFieldProtocolIEsIndef(v *PathSwitchRequestAcknowledge) *bool {
	return &v.protocolIEsIndef
}
func BridgePathSwitchRequestAcknowledgeFieldReceived(v *PathSwitchRequestAcknowledge) *bool {
	return &v.received
}
func BridgePathSwitchRequestAcknowledgeFieldReceivedAbsolute(v *PathSwitchRequestAcknowledge) *bool {
	return &v.receivedAbsolute
}
func BridgePathSwitchRequestAcknowledgeFieldReceivedBytes(v *PathSwitchRequestAcknowledge) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgePathSwitchRequestAcknowledgeFieldReceivedLocation(v *PathSwitchRequestAcknowledge) *aper.Location {
	return &v.receivedLocation
}
func BridgePathSwitchRequestAcknowledgeFieldReplay(v *PathSwitchRequestAcknowledge) *aper.Snapshot {
	return &v.replay
}
func BridgePathSwitchRequestAcknowledgeFieldStream(v *PathSwitchRequestAcknowledge) *aper.WireSpan {
	return &v.stream
}
func BridgePathSwitchRequestAcknowledgeFieldWithoutReplay(v *PathSwitchRequestAcknowledge) *bool {
	return &v.withoutReplay
}
func BridgePathSwitchRequestAcknowledgeIETableMethodInfoAdditionalRRMPriorityIndex(v PathSwitchRequestAcknowledgeIETable) s00.FieldInfo {
	return v.infoAdditionalRRMPriorityIndex()
}
func BridgePathSwitchRequestAcknowledgeIETableMethodInfoAerialUEsubscriptionInformation(v PathSwitchRequestAcknowledgeIETable) s00.FieldInfo {
	return v.infoAerialUEsubscriptionInformation()
}
func BridgePathSwitchRequestAcknowledgeIETableMethodInfoCEModeBRestricted(v PathSwitchRequestAcknowledgeIETable) s00.FieldInfo {
	return v.infoCEModeBRestricted()
}
func BridgePathSwitchRequestAcknowledgeIETableMethodInfoCSGMembershipStatus(v PathSwitchRequestAcknowledgeIETable) s00.FieldInfo {
	return v.infoCSGMembershipStatus()
}
func BridgePathSwitchRequestAcknowledgeIETableMethodInfoCriticalityDiagnostics(v PathSwitchRequestAcknowledgeIETable) s00.FieldInfo {
	return v.infoCriticalityDiagnostics()
}
func BridgePathSwitchRequestAcknowledgeIETableMethodInfoENBUES1APID(v PathSwitchRequestAcknowledgeIETable) s00.FieldInfo {
	return v.infoENBUES1APID()
}
func BridgePathSwitchRequestAcknowledgeIETableMethodInfoERABToBeReleasedList(v PathSwitchRequestAcknowledgeIETable) s00.FieldInfo {
	return v.infoERABToBeReleasedList()
}
func BridgePathSwitchRequestAcknowledgeIETableMethodInfoERABToBeSwitchedULList(v PathSwitchRequestAcknowledgeIETable) s00.FieldInfo {
	return v.infoERABToBeSwitchedULList()
}
func BridgePathSwitchRequestAcknowledgeIETableMethodInfoERABToBeUpdatedList(v PathSwitchRequestAcknowledgeIETable) s00.FieldInfo {
	return v.infoERABToBeUpdatedList()
}
func BridgePathSwitchRequestAcknowledgeIETableMethodInfoEnhancedCoverageRestricted(v PathSwitchRequestAcknowledgeIETable) s00.FieldInfo {
	return v.infoEnhancedCoverageRestricted()
}
func BridgePathSwitchRequestAcknowledgeIETableMethodInfoHandoverRestrictionList(v PathSwitchRequestAcknowledgeIETable) s00.FieldInfo {
	return v.infoHandoverRestrictionList()
}
func BridgePathSwitchRequestAcknowledgeIETableMethodInfoMMEUES1APID(v PathSwitchRequestAcknowledgeIETable) s00.FieldInfo {
	return v.infoMMEUES1APID()
}
func BridgePathSwitchRequestAcknowledgeIETableMethodInfoMMEUES1APID2(v PathSwitchRequestAcknowledgeIETable) s00.FieldInfo {
	return v.infoMMEUES1APID2()
}
func BridgePathSwitchRequestAcknowledgeIETableMethodInfoNRUESecurityCapabilities(v PathSwitchRequestAcknowledgeIETable) s00.FieldInfo {
	return v.infoNRUESecurityCapabilities()
}
func BridgePathSwitchRequestAcknowledgeIETableMethodInfoNRUESidelinkAggregateMaximumBitrate(v PathSwitchRequestAcknowledgeIETable) s00.FieldInfo {
	return v.infoNRUESidelinkAggregateMaximumBitrate()
}
func BridgePathSwitchRequestAcknowledgeIETableMethodInfoNRV2XServicesAuthorized(v PathSwitchRequestAcknowledgeIETable) s00.FieldInfo {
	return v.infoNRV2XServicesAuthorized()
}
func BridgePathSwitchRequestAcknowledgeIETableMethodInfoPC5QoSParameters(v PathSwitchRequestAcknowledgeIETable) s00.FieldInfo {
	return v.infoPC5QoSParameters()
}
func BridgePathSwitchRequestAcknowledgeIETableMethodInfoPendingDataIndication(v PathSwitchRequestAcknowledgeIETable) s00.FieldInfo {
	return v.infoPendingDataIndication()
}
func BridgePathSwitchRequestAcknowledgeIETableMethodInfoProSeAuthorized(v PathSwitchRequestAcknowledgeIETable) s00.FieldInfo {
	return v.infoProSeAuthorized()
}
func BridgePathSwitchRequestAcknowledgeIETableMethodInfoSecurityContext(v PathSwitchRequestAcknowledgeIETable) s00.FieldInfo {
	return v.infoSecurityContext()
}
func BridgePathSwitchRequestAcknowledgeIETableMethodInfoSubscriptionBasedUEDifferentiationInfo(v PathSwitchRequestAcknowledgeIETable) s00.FieldInfo {
	return v.infoSubscriptionBasedUEDifferentiationInfo()
}
func BridgePathSwitchRequestAcknowledgeIETableMethodInfoTimeRefDistribution(v PathSwitchRequestAcknowledgeIETable) s00.FieldInfo {
	return v.infoTimeRefDistribution()
}
func BridgePathSwitchRequestAcknowledgeIETableMethodInfoUERadioCapabilityID(v PathSwitchRequestAcknowledgeIETable) s00.FieldInfo {
	return v.infoUERadioCapabilityID()
}
func BridgePathSwitchRequestAcknowledgeIETableMethodInfoUESecurityCapabilities(v PathSwitchRequestAcknowledgeIETable) s00.FieldInfo {
	return v.infoUESecurityCapabilities()
}
func BridgePathSwitchRequestAcknowledgeIETableMethodInfoUESidelinkAggregateMaximumBitrate(v PathSwitchRequestAcknowledgeIETable) s00.FieldInfo {
	return v.infoUESidelinkAggregateMaximumBitrate()
}
func BridgePathSwitchRequestAcknowledgeIETableMethodInfoUEUserPlaneCIoTSupportIndicator(v PathSwitchRequestAcknowledgeIETable) s00.FieldInfo {
	return v.infoUEUserPlaneCIoTSupportIndicator()
}
func BridgePathSwitchRequestAcknowledgeIETableMethodInfoUEaggregateMaximumBitrate(v PathSwitchRequestAcknowledgeIETable) s00.FieldInfo {
	return v.infoUEaggregateMaximumBitrate()
}
func BridgePathSwitchRequestAcknowledgeIETableMethodInfoV2XServicesAuthorized(v PathSwitchRequestAcknowledgeIETable) s00.FieldInfo {
	return v.infoV2XServicesAuthorized()
}
func BridgePathSwitchRequestAcknowledgeMethodMarshalAPERBudget(v *PathSwitchRequestAcknowledge, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgePathSwitchRequestAcknowledgeMethodMarshalAPERBudgetValue(v *PathSwitchRequestAcknowledge, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudgetValue(a0, a1)
}
func BridgePathSwitchRequestAcknowledgeMethodMarshalAPERChanged(v *PathSwitchRequestAcknowledge, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgePathSwitchRequestAcknowledgeMethodMarshalAPERChangedValue(v *PathSwitchRequestAcknowledge, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgePathSwitchRequestAcknowledgeMethodMarshalAPERLegacy(v *PathSwitchRequestAcknowledge) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgePathSwitchRequestAcknowledgeMethodMarshalAPERNewValue(v *PathSwitchRequestAcknowledge, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERNewValue(a0, a1)
}
func BridgePathSwitchRequestAcknowledgeMethodMarshalAPERPlanned(v *PathSwitchRequestAcknowledge, a0 *aper.DecodeBudget, a1 bool, a2 *aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1, a2)
}
func BridgePathSwitchRequestAcknowledgeMethodMarshalAPERTo(v *PathSwitchRequestAcknowledge, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgePathSwitchRequestAcknowledgeMethodUnmarshalAPERFrom(v *PathSwitchRequestAcknowledge, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgePathSwitchRequestAcknowledgeMethodUnmarshalAPERLegacy(v *PathSwitchRequestAcknowledge, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgePathSwitchRequestAcknowledgeMethodUnmarshalAPERWithOptions(v *PathSwitchRequestAcknowledge, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgePathSwitchRequestAcknowledgeValueCodecFieldCapture(v *PathSwitchRequestAcknowledgeValueCodec) *func(PathSwitchRequestAcknowledge, aper.DecodeState) (PathSwitchRequestAcknowledge, aper.Snapshot) {
	return &v.capture
}
func BridgePathSwitchRequestAcknowledgeValueCodecFieldCompare(v *PathSwitchRequestAcknowledgeValueCodec) *func(PathSwitchRequestAcknowledge, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgePathSwitchRequestAcknowledgeValueCodecFieldContext(v *PathSwitchRequestAcknowledgeValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgePathSwitchRequestAcknowledgeValueCodecFieldDecode(v *PathSwitchRequestAcknowledgeValueCodec) *func([]byte, aper.DecodeState) (PathSwitchRequestAcknowledge, error) {
	return &v.decode
}
func BridgePathSwitchRequestAcknowledgeValueCodecFieldEncode(v *PathSwitchRequestAcknowledgeValueCodec) *func(PathSwitchRequestAcknowledge, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgePathSwitchRequestAcknowledgeValueCodecFieldPath(v *PathSwitchRequestAcknowledgeValueCodec) *aper.Path {
	return &v.path
}
func BridgePathSwitchRequestAcknowledgeValueCodecMethodEncodeBudgetValue(v PathSwitchRequestAcknowledgeValueCodec, a0 PathSwitchRequestAcknowledge, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgePathSwitchRequestAcknowledgeValueCodecMethodEncodeChanged(v PathSwitchRequestAcknowledgeValueCodec, a0 PathSwitchRequestAcknowledge, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeTraceActivationExtIETableMethodInfoMDTConfiguration(v TraceActivationExtIETable) s00.ExtensionInfo {
	return v.infoMDTConfiguration()
}
func BridgeTraceActivationExtIETableMethodInfoMDTConfigurationNR(v TraceActivationExtIETable) s00.ExtensionInfo {
	return v.infoMDTConfigurationNR()
}
func BridgeTraceActivationExtIETableMethodInfoTraceCollectionEntityURI(v TraceActivationExtIETable) s00.ExtensionInfo {
	return v.infoTraceCollectionEntityURI()
}
func BridgeTraceActivationExtIETableMethodInfoUEAppLayerMeasConfig(v TraceActivationExtIETable) s00.ExtensionInfo {
	return v.infoUEAppLayerMeasConfig()
}
func BridgeTraceActivationExtIEsExtContainerAPERValueFieldContext(v *TraceActivationExtIEsExtContainerAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeTraceActivationExtIEsExtContainerAPERValueFieldReceived(v *TraceActivationExtIEsExtContainerAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeTraceActivationExtIEsExtContainerAPERValueFieldReplay(v *TraceActivationExtIEsExtContainerAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeTraceActivationExtIEsExtContainerAPERValueFieldWithoutReplay(v *TraceActivationExtIEsExtContainerAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeTraceActivationExtIEsExtContainerValueCodecFieldCapture(v *TraceActivationExtIEsExtContainerValueCodec) *func(TraceActivationExtIEsExtContainer, aper.DecodeState) (TraceActivationExtIEsExtContainer, aper.Snapshot) {
	return &v.capture
}
func BridgeTraceActivationExtIEsExtContainerValueCodecFieldCompare(v *TraceActivationExtIEsExtContainerValueCodec) *func(TraceActivationExtIEsExtContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeTraceActivationExtIEsExtContainerValueCodecFieldContext(v *TraceActivationExtIEsExtContainerValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeTraceActivationExtIEsExtContainerValueCodecFieldDecode(v *TraceActivationExtIEsExtContainerValueCodec) *func([]byte, aper.DecodeState) (TraceActivationExtIEsExtContainer, error) {
	return &v.decode
}
func BridgeTraceActivationExtIEsExtContainerValueCodecFieldEncode(v *TraceActivationExtIEsExtContainerValueCodec) *func(TraceActivationExtIEsExtContainer, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeTraceActivationExtIEsExtContainerValueCodecFieldPath(v *TraceActivationExtIEsExtContainerValueCodec) *aper.Path {
	return &v.path
}
func BridgeTraceActivationExtIEsExtContainerValueCodecMethodEncodeBudgetValue(v TraceActivationExtIEsExtContainerValueCodec, a0 TraceActivationExtIEsExtContainer, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeTraceActivationExtIEsExtContainerValueCodecMethodEncodeChanged(v TraceActivationExtIEsExtContainerValueCodec, a0 TraceActivationExtIEsExtContainer, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeTraceActivationExtIEsExtFieldAPERValueFieldContext(v *TraceActivationExtIEsExtFieldAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeTraceActivationExtIEsExtFieldAPERValueFieldReceived(v *TraceActivationExtIEsExtFieldAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeTraceActivationExtIEsExtFieldAPERValueFieldReplay(v *TraceActivationExtIEsExtFieldAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeTraceActivationExtIEsExtFieldAPERValueFieldWithoutReplay(v *TraceActivationExtIEsExtFieldAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeTraceActivationExtIEsExtFieldFieldReceived(v *TraceActivationExtIEsExtField) *aper.CompletePadding {
	return &v.received
}
func BridgeTraceActivationExtIEsExtFieldFieldReplay(v *TraceActivationExtIEsExtField) *aper.Snapshot {
	return &v.replay
}
func BridgeTraceActivationExtIEsExtFieldFieldStream(v *TraceActivationExtIEsExtField) *aper.WireSpan {
	return &v.stream
}
func BridgeTraceActivationExtIEsExtFieldFieldWithoutReplay(v *TraceActivationExtIEsExtField) *bool {
	return &v.withoutReplay
}
func BridgeTraceActivationExtIEsExtFieldMethodMarshalAPERTo(v *TraceActivationExtIEsExtField, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeTraceActivationExtIEsExtFieldMethodUnmarshalAPERFrom(v *TraceActivationExtIEsExtField, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeTraceActivationExtIEsExtFieldValueCodecFieldCapture(v *TraceActivationExtIEsExtFieldValueCodec) *func(TraceActivationExtIEsExtField, aper.DecodeState) (TraceActivationExtIEsExtField, aper.Snapshot) {
	return &v.capture
}
func BridgeTraceActivationExtIEsExtFieldValueCodecFieldCompare(v *TraceActivationExtIEsExtFieldValueCodec) *func(TraceActivationExtIEsExtField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeTraceActivationExtIEsExtFieldValueCodecFieldContext(v *TraceActivationExtIEsExtFieldValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeTraceActivationExtIEsExtFieldValueCodecFieldDecode(v *TraceActivationExtIEsExtFieldValueCodec) *func([]byte, aper.DecodeState) (TraceActivationExtIEsExtField, error) {
	return &v.decode
}
func BridgeTraceActivationExtIEsExtFieldValueCodecFieldEncode(v *TraceActivationExtIEsExtFieldValueCodec) *func(TraceActivationExtIEsExtField, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeTraceActivationExtIEsExtFieldValueCodecFieldPath(v *TraceActivationExtIEsExtFieldValueCodec) *aper.Path {
	return &v.path
}
func BridgeTraceActivationExtIEsExtFieldValueCodecMethodEncodeBudgetValue(v TraceActivationExtIEsExtFieldValueCodec, a0 TraceActivationExtIEsExtField, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeTraceActivationExtIEsExtFieldValueCodecMethodEncodeChanged(v TraceActivationExtIEsExtFieldValueCodec, a0 TraceActivationExtIEsExtField, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeTraceActivationExtIEsIEFieldFieldReceived(v *TraceActivationExtIEsIEField) *aper.CompletePadding {
	return &v.received
}
func BridgeTraceActivationExtIEsIEFieldFieldReplay(v *TraceActivationExtIEsIEField) *aper.Snapshot {
	return &v.replay
}
func BridgeTraceActivationExtIEsIEFieldFieldStream(v *TraceActivationExtIEsIEField) *aper.WireSpan {
	return &v.stream
}
func BridgeTraceActivationExtIEsIEFieldFieldWithoutReplay(v *TraceActivationExtIEsIEField) *bool {
	return &v.withoutReplay
}
func BridgeTraceActivationExtIEsIEFieldMethodMarshalAPERTo(v *TraceActivationExtIEsIEField, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeTraceActivationExtIEsIEFieldMethodUnmarshalAPERFrom(v *TraceActivationExtIEsIEField, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeTraceActivationExtIEsMDTConfigurationExtBindingFieldCodec(v *TraceActivationExtIEsMDTConfigurationExtBinding) *MDTConfigurationValueCodec {
	return &v.codec
}
func BridgeTraceActivationExtIEsMDTConfigurationExtBindingFieldGet(v *TraceActivationExtIEsMDTConfigurationExtBinding) *func(*TraceActivationExtIEsValue) (*MDTConfiguration, bool) {
	return &v.get
}
func BridgeTraceActivationExtIEsMDTConfigurationExtBindingFieldInfo(v *TraceActivationExtIEsMDTConfigurationExtBinding) *s00.ExtensionInfo {
	return &v.info
}
func BridgeTraceActivationExtIEsMDTConfigurationExtBindingFieldInject(v *TraceActivationExtIEsMDTConfigurationExtBinding) *func(MDTConfiguration) TraceActivationExtIEsValue {
	return &v.inject
}
func BridgeTraceActivationExtIEsMDTConfigurationNRExtBindingFieldCodec(v *TraceActivationExtIEsMDTConfigurationNRExtBinding) *s01.MDTConfigurationNRValueCodec {
	return &v.codec
}
func BridgeTraceActivationExtIEsMDTConfigurationNRExtBindingFieldGet(v *TraceActivationExtIEsMDTConfigurationNRExtBinding) *func(*TraceActivationExtIEsValue) (*s00.MDTConfigurationNR, bool) {
	return &v.get
}
func BridgeTraceActivationExtIEsMDTConfigurationNRExtBindingFieldInfo(v *TraceActivationExtIEsMDTConfigurationNRExtBinding) *s00.ExtensionInfo {
	return &v.info
}
func BridgeTraceActivationExtIEsMDTConfigurationNRExtBindingFieldInject(v *TraceActivationExtIEsMDTConfigurationNRExtBinding) *func(s00.MDTConfigurationNR) TraceActivationExtIEsValue {
	return &v.inject
}
func BridgeTraceActivationExtIEsUEAppLayerMeasConfigExtBindingFieldCodec(v *TraceActivationExtIEsUEAppLayerMeasConfigExtBinding) *s35.UEAppLayerMeasConfigValueCodec {
	return &v.codec
}
func BridgeTraceActivationExtIEsUEAppLayerMeasConfigExtBindingFieldGet(v *TraceActivationExtIEsUEAppLayerMeasConfigExtBinding) *func(*TraceActivationExtIEsValue) (*s35.UEAppLayerMeasConfig, bool) {
	return &v.get
}
func BridgeTraceActivationExtIEsUEAppLayerMeasConfigExtBindingFieldInfo(v *TraceActivationExtIEsUEAppLayerMeasConfigExtBinding) *s00.ExtensionInfo {
	return &v.info
}
func BridgeTraceActivationExtIEsUEAppLayerMeasConfigExtBindingFieldInject(v *TraceActivationExtIEsUEAppLayerMeasConfigExtBinding) *func(s35.UEAppLayerMeasConfig) TraceActivationExtIEsValue {
	return &v.inject
}
func BridgeTraceActivationExtIEsURIAddressExtBindingFieldCodec(v *TraceActivationExtIEsURIAddressExtBinding) *s02.URIAddressValueCodec {
	return &v.codec
}
func BridgeTraceActivationExtIEsURIAddressExtBindingFieldGet(v *TraceActivationExtIEsURIAddressExtBinding) *func(*TraceActivationExtIEsValue) (*s00.URIAddress, bool) {
	return &v.get
}
func BridgeTraceActivationExtIEsURIAddressExtBindingFieldInfo(v *TraceActivationExtIEsURIAddressExtBinding) *s00.ExtensionInfo {
	return &v.info
}
func BridgeTraceActivationExtIEsURIAddressExtBindingFieldInject(v *TraceActivationExtIEsURIAddressExtBinding) *func(s00.URIAddress) TraceActivationExtIEsValue {
	return &v.inject
}
func BridgeTraceActivationExtIEsValueFieldId(v *TraceActivationExtIEsValue) *s00.ProtocolIEID {
	return &v.id
}
func BridgeTraceActivationExtIEsValueFieldIsOpaque(v *TraceActivationExtIEsValue) *bool {
	return &v.isOpaque
}
func BridgeTraceActivationExtIEsValueFieldOpaque(v *TraceActivationExtIEsValue) *aper.OpaqueOpenType {
	return &v.opaque
}
func BridgeTraceActivationExtIEsValueFieldReceived(v *TraceActivationExtIEsValue) *aper.WireSpan {
	return &v.received
}
func BridgeTraceActivationExtIEsValueFieldReplay(v *TraceActivationExtIEsValue) *aper.Snapshot {
	return &v.replay
}
func BridgeTraceActivationExtIEsValueFieldRowMDTConfiguration(v *TraceActivationExtIEsValue) **MDTConfiguration {
	return &v.rowMDTConfiguration
}
func BridgeTraceActivationExtIEsValueFieldRowMDTConfigurationNR(v *TraceActivationExtIEsValue) **s00.MDTConfigurationNR {
	return &v.rowMDTConfigurationNR
}
func BridgeTraceActivationExtIEsValueFieldRowTraceCollectionEntityURI(v *TraceActivationExtIEsValue) **s00.URIAddress {
	return &v.rowTraceCollectionEntityURI
}
func BridgeTraceActivationExtIEsValueFieldRowUEAppLayerMeasConfig(v *TraceActivationExtIEsValue) **s35.UEAppLayerMeasConfig {
	return &v.rowUEAppLayerMeasConfig
}
func BridgeTraceActivationExtIEsValueMethodCaptureSemantics(v TraceActivationExtIEsValue, a0 aper.SemanticCapture) TraceActivationExtIEsValue {
	return v.captureSemantics(a0)
}
func BridgeTraceActivationExtIEsValueMethodCompareSemantics(v TraceActivationExtIEsValue, a0 aper.SemanticComparison) aper.SemanticComparison {
	return v.compareSemantics(a0)
}
func BridgeTraceActivationExtIEsValueMethodDecode(v TraceActivationExtIEsValue, a0 s00.ProtocolIEID, a1 aper.OpaqueOpenType) (TraceActivationExtIEsValue, error) {
	return v.decode(a0, a1)
}
func BridgeTraceActivationExtIEsValueMethodEncode(v TraceActivationExtIEsValue) ([]byte, error) {
	return v.encode()
}
func BridgeTraceActivationExtIEsValueMethodEncodeFresh(v TraceActivationExtIEsValue, a0 bool, a1 *aper.DecodeBudget) ([]byte, error) {
	return v.encodeFresh(a0, a1)
}
func BridgeTraceActivationExtIEsValueMethodMatchesID(v TraceActivationExtIEsValue, a0 s00.ProtocolIEID, a1 ...*aper.DecodeBudget) bool {
	return v.matchesID(a0, a1...)
}
func BridgeTraceActivationExtIEsValueMethodReason(v TraceActivationExtIEsValue, a0 s00.ProtocolIEID) aper.OpaqueReason {
	return v.reason(a0)
}
func BridgeTraceActivationExtIEsValueMethodRule(v TraceActivationExtIEsValue) aper.SourceRule {
	return v.rule()
}
func BridgeTraceActivationFieldExtCount(v *TraceActivation) *int64   { return &v.extCount }
func BridgeTraceActivationFieldExtData(v *TraceActivation) *[][]byte { return &v.extData }
func BridgeTraceActivationFieldExtOrigin(v *TraceActivation) *[]aper.OpaqueOrigin {
	return &v.extOrigin
}
func BridgeTraceActivationFieldExtPresent(v *TraceActivation) *[]bool       { return &v.extPresent }
func BridgeTraceActivationFieldExtWire(v *TraceActivation) *[]aper.WireSpan { return &v.extWire }
func BridgeTraceActivationFieldIEExtensionsIndef(v *TraceActivation) *bool {
	return &v.iEExtensionsIndef
}
func BridgeTraceActivationFieldPerExtPadding(v *TraceActivation) *[]aper.CompletePadding {
	return &v.perExtPadding
}
func BridgeTraceActivationFieldPerPadding(v *TraceActivation) *aper.FinalPadding {
	return &v.perPadding
}
func BridgeTraceActivationFieldReceived(v *TraceActivation) *bool         { return &v.received }
func BridgeTraceActivationFieldReceivedAbsolute(v *TraceActivation) *bool { return &v.receivedAbsolute }
func BridgeTraceActivationFieldReceivedBytes(v *TraceActivation) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeTraceActivationFieldReceivedLocation(v *TraceActivation) *aper.Location {
	return &v.receivedLocation
}
func BridgeTraceActivationFieldReplay(v *TraceActivation) *aper.Snapshot { return &v.replay }
func BridgeTraceActivationFieldStream(v *TraceActivation) *aper.WireSpan { return &v.stream }
func BridgeTraceActivationFieldWithoutReplay(v *TraceActivation) *bool   { return &v.withoutReplay }
func BridgeTraceActivationMethodMarshalAPERBudget(v *TraceActivation, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeTraceActivationMethodMarshalAPERBudgetValue(v *TraceActivation, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudgetValue(a0, a1)
}
func BridgeTraceActivationMethodMarshalAPERChanged(v *TraceActivation, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeTraceActivationMethodMarshalAPERChangedValue(v *TraceActivation, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeTraceActivationMethodMarshalAPERLegacy(v *TraceActivation) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeTraceActivationMethodMarshalAPERNewValue(v *TraceActivation, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERNewValue(a0, a1)
}
func BridgeTraceActivationMethodMarshalAPERPlanned(v *TraceActivation, a0 *aper.DecodeBudget, a1 bool, a2 *aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1, a2)
}
func BridgeTraceActivationMethodMarshalAPERTo(v *TraceActivation, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeTraceActivationMethodUnmarshalAPERFrom(v *TraceActivation, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeTraceActivationMethodUnmarshalAPERLegacy(v *TraceActivation, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeTraceActivationMethodUnmarshalAPERWithOptions(v *TraceActivation, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeUEContextModificationRequestAPERValueFieldContext(v *UEContextModificationRequestAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeUEContextModificationRequestAPERValueFieldReceived(v *UEContextModificationRequestAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeUEContextModificationRequestAPERValueFieldReplay(v *UEContextModificationRequestAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeUEContextModificationRequestAPERValueFieldWithoutReplay(v *UEContextModificationRequestAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeUEContextModificationRequestFieldExtCount(v *UEContextModificationRequest) *int64 {
	return &v.extCount
}
func BridgeUEContextModificationRequestFieldExtData(v *UEContextModificationRequest) *[][]byte {
	return &v.extData
}
func BridgeUEContextModificationRequestFieldExtOrigin(v *UEContextModificationRequest) *[]aper.OpaqueOrigin {
	return &v.extOrigin
}
func BridgeUEContextModificationRequestFieldExtPresent(v *UEContextModificationRequest) *[]bool {
	return &v.extPresent
}
func BridgeUEContextModificationRequestFieldExtWire(v *UEContextModificationRequest) *[]aper.WireSpan {
	return &v.extWire
}
func BridgeUEContextModificationRequestFieldPerExtPadding(v *UEContextModificationRequest) *[]aper.CompletePadding {
	return &v.perExtPadding
}
func BridgeUEContextModificationRequestFieldPerPadding(v *UEContextModificationRequest) *aper.FinalPadding {
	return &v.perPadding
}
func BridgeUEContextModificationRequestFieldProtocolIEsIndef(v *UEContextModificationRequest) *bool {
	return &v.protocolIEsIndef
}
func BridgeUEContextModificationRequestFieldReceived(v *UEContextModificationRequest) *bool {
	return &v.received
}
func BridgeUEContextModificationRequestFieldReceivedAbsolute(v *UEContextModificationRequest) *bool {
	return &v.receivedAbsolute
}
func BridgeUEContextModificationRequestFieldReceivedBytes(v *UEContextModificationRequest) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeUEContextModificationRequestFieldReceivedLocation(v *UEContextModificationRequest) *aper.Location {
	return &v.receivedLocation
}
func BridgeUEContextModificationRequestFieldReplay(v *UEContextModificationRequest) *aper.Snapshot {
	return &v.replay
}
func BridgeUEContextModificationRequestFieldStream(v *UEContextModificationRequest) *aper.WireSpan {
	return &v.stream
}
func BridgeUEContextModificationRequestFieldWithoutReplay(v *UEContextModificationRequest) *bool {
	return &v.withoutReplay
}
func BridgeUEContextModificationRequestIETableMethodInfoAdditionalCSFallbackIndicator(v UEContextModificationRequestIETable) s00.FieldInfo {
	return v.infoAdditionalCSFallbackIndicator()
}
func BridgeUEContextModificationRequestIETableMethodInfoAdditionalRRMPriorityIndex(v UEContextModificationRequestIETable) s00.FieldInfo {
	return v.infoAdditionalRRMPriorityIndex()
}
func BridgeUEContextModificationRequestIETableMethodInfoAerialUEsubscriptionInformation(v UEContextModificationRequestIETable) s00.FieldInfo {
	return v.infoAerialUEsubscriptionInformation()
}
func BridgeUEContextModificationRequestIETableMethodInfoCSFallbackIndicator(v UEContextModificationRequestIETable) s00.FieldInfo {
	return v.infoCSFallbackIndicator()
}
func BridgeUEContextModificationRequestIETableMethodInfoCSGMembershipStatus(v UEContextModificationRequestIETable) s00.FieldInfo {
	return v.infoCSGMembershipStatus()
}
func BridgeUEContextModificationRequestIETableMethodInfoENBUES1APID(v UEContextModificationRequestIETable) s00.FieldInfo {
	return v.infoENBUES1APID()
}
func BridgeUEContextModificationRequestIETableMethodInfoIABAuthorized(v UEContextModificationRequestIETable) s00.FieldInfo {
	return v.infoIABAuthorized()
}
func BridgeUEContextModificationRequestIETableMethodInfoMMEUES1APID(v UEContextModificationRequestIETable) s00.FieldInfo {
	return v.infoMMEUES1APID()
}
func BridgeUEContextModificationRequestIETableMethodInfoNRUESecurityCapabilities(v UEContextModificationRequestIETable) s00.FieldInfo {
	return v.infoNRUESecurityCapabilities()
}
func BridgeUEContextModificationRequestIETableMethodInfoNRUESidelinkAggregateMaximumBitrate(v UEContextModificationRequestIETable) s00.FieldInfo {
	return v.infoNRUESidelinkAggregateMaximumBitrate()
}
func BridgeUEContextModificationRequestIETableMethodInfoNRV2XServicesAuthorized(v UEContextModificationRequestIETable) s00.FieldInfo {
	return v.infoNRV2XServicesAuthorized()
}
func BridgeUEContextModificationRequestIETableMethodInfoPC5QoSParameters(v UEContextModificationRequestIETable) s00.FieldInfo {
	return v.infoPC5QoSParameters()
}
func BridgeUEContextModificationRequestIETableMethodInfoProSeAuthorized(v UEContextModificationRequestIETable) s00.FieldInfo {
	return v.infoProSeAuthorized()
}
func BridgeUEContextModificationRequestIETableMethodInfoRegisteredLAI(v UEContextModificationRequestIETable) s00.FieldInfo {
	return v.infoRegisteredLAI()
}
func BridgeUEContextModificationRequestIETableMethodInfoSRVCCOperationNotPossible(v UEContextModificationRequestIETable) s00.FieldInfo {
	return v.infoSRVCCOperationNotPossible()
}
func BridgeUEContextModificationRequestIETableMethodInfoSRVCCOperationPossible(v UEContextModificationRequestIETable) s00.FieldInfo {
	return v.infoSRVCCOperationPossible()
}
func BridgeUEContextModificationRequestIETableMethodInfoSecurityKey(v UEContextModificationRequestIETable) s00.FieldInfo {
	return v.infoSecurityKey()
}
func BridgeUEContextModificationRequestIETableMethodInfoSubscriberProfileIDforRFP(v UEContextModificationRequestIETable) s00.FieldInfo {
	return v.infoSubscriberProfileIDforRFP()
}
func BridgeUEContextModificationRequestIETableMethodInfoTimeRefDistribution(v UEContextModificationRequestIETable) s00.FieldInfo {
	return v.infoTimeRefDistribution()
}
func BridgeUEContextModificationRequestIETableMethodInfoUERadioCapabilityID(v UEContextModificationRequestIETable) s00.FieldInfo {
	return v.infoUERadioCapabilityID()
}
func BridgeUEContextModificationRequestIETableMethodInfoUESecurityCapabilities(v UEContextModificationRequestIETable) s00.FieldInfo {
	return v.infoUESecurityCapabilities()
}
func BridgeUEContextModificationRequestIETableMethodInfoUESidelinkAggregateMaximumBitrate(v UEContextModificationRequestIETable) s00.FieldInfo {
	return v.infoUESidelinkAggregateMaximumBitrate()
}
func BridgeUEContextModificationRequestIETableMethodInfoUEaggregateMaximumBitrate(v UEContextModificationRequestIETable) s00.FieldInfo {
	return v.infoUEaggregateMaximumBitrate()
}
func BridgeUEContextModificationRequestIETableMethodInfoV2XServicesAuthorized(v UEContextModificationRequestIETable) s00.FieldInfo {
	return v.infoV2XServicesAuthorized()
}
func BridgeUEContextModificationRequestMethodMarshalAPERBudget(v *UEContextModificationRequest, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeUEContextModificationRequestMethodMarshalAPERBudgetValue(v *UEContextModificationRequest, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudgetValue(a0, a1)
}
func BridgeUEContextModificationRequestMethodMarshalAPERChanged(v *UEContextModificationRequest, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeUEContextModificationRequestMethodMarshalAPERChangedValue(v *UEContextModificationRequest, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeUEContextModificationRequestMethodMarshalAPERLegacy(v *UEContextModificationRequest) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeUEContextModificationRequestMethodMarshalAPERNewValue(v *UEContextModificationRequest, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERNewValue(a0, a1)
}
func BridgeUEContextModificationRequestMethodMarshalAPERPlanned(v *UEContextModificationRequest, a0 *aper.DecodeBudget, a1 bool, a2 *aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1, a2)
}
func BridgeUEContextModificationRequestMethodMarshalAPERTo(v *UEContextModificationRequest, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeUEContextModificationRequestMethodUnmarshalAPERFrom(v *UEContextModificationRequest, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeUEContextModificationRequestMethodUnmarshalAPERLegacy(v *UEContextModificationRequest, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeUEContextModificationRequestMethodUnmarshalAPERWithOptions(v *UEContextModificationRequest, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeUEContextModificationRequestV2XServicesAuthorizedIEBindingFieldCodec(v *UEContextModificationRequestV2XServicesAuthorizedIEBinding) *s46.V2XServicesAuthorizedValueCodec {
	return &v.codec
}
func BridgeUEContextModificationRequestV2XServicesAuthorizedIEBindingFieldGet(v *UEContextModificationRequestV2XServicesAuthorizedIEBinding) *func(*s46.UEContextModificationRequestIEValue) (*s46.V2XServicesAuthorized, bool) {
	return &v.get
}
func BridgeUEContextModificationRequestV2XServicesAuthorizedIEBindingFieldInfo(v *UEContextModificationRequestV2XServicesAuthorizedIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeUEContextModificationRequestV2XServicesAuthorizedIEBindingFieldInject(v *UEContextModificationRequestV2XServicesAuthorizedIEBinding) *func(s46.V2XServicesAuthorized) s46.UEContextModificationRequestIEValue {
	return &v.inject
}
func BridgeUEContextModificationRequestValueCodecFieldCapture(v *UEContextModificationRequestValueCodec) *func(UEContextModificationRequest, aper.DecodeState) (UEContextModificationRequest, aper.Snapshot) {
	return &v.capture
}
func BridgeUEContextModificationRequestValueCodecFieldCompare(v *UEContextModificationRequestValueCodec) *func(UEContextModificationRequest, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeUEContextModificationRequestValueCodecFieldContext(v *UEContextModificationRequestValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeUEContextModificationRequestValueCodecFieldDecode(v *UEContextModificationRequestValueCodec) *func([]byte, aper.DecodeState) (UEContextModificationRequest, error) {
	return &v.decode
}
func BridgeUEContextModificationRequestValueCodecFieldEncode(v *UEContextModificationRequestValueCodec) *func(UEContextModificationRequest, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeUEContextModificationRequestValueCodecFieldPath(v *UEContextModificationRequestValueCodec) *aper.Path {
	return &v.path
}
func BridgeUEContextModificationRequestValueCodecMethodEncodeBudgetValue(v UEContextModificationRequestValueCodec, a0 UEContextModificationRequest, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeUEContextModificationRequestValueCodecMethodEncodeChanged(v UEContextModificationRequestValueCodec, a0 UEContextModificationRequest, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeWLANMeasurementConfigurationAPERValueFieldContext(v *WLANMeasurementConfigurationAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeWLANMeasurementConfigurationAPERValueFieldReceived(v *WLANMeasurementConfigurationAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeWLANMeasurementConfigurationAPERValueFieldReplay(v *WLANMeasurementConfigurationAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeWLANMeasurementConfigurationAPERValueFieldWithoutReplay(v *WLANMeasurementConfigurationAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeWLANMeasurementConfigurationFieldExtCount(v *WLANMeasurementConfiguration) *int64 {
	return &v.extCount
}
func BridgeWLANMeasurementConfigurationFieldExtData(v *WLANMeasurementConfiguration) *[][]byte {
	return &v.extData
}
func BridgeWLANMeasurementConfigurationFieldExtOrigin(v *WLANMeasurementConfiguration) *[]aper.OpaqueOrigin {
	return &v.extOrigin
}
func BridgeWLANMeasurementConfigurationFieldExtPresent(v *WLANMeasurementConfiguration) *[]bool {
	return &v.extPresent
}
func BridgeWLANMeasurementConfigurationFieldExtWire(v *WLANMeasurementConfiguration) *[]aper.WireSpan {
	return &v.extWire
}
func BridgeWLANMeasurementConfigurationFieldIEExtensionsIndef(v *WLANMeasurementConfiguration) *bool {
	return &v.iEExtensionsIndef
}
func BridgeWLANMeasurementConfigurationFieldPerExtPadding(v *WLANMeasurementConfiguration) *[]aper.CompletePadding {
	return &v.perExtPadding
}
func BridgeWLANMeasurementConfigurationFieldPerPadding(v *WLANMeasurementConfiguration) *aper.FinalPadding {
	return &v.perPadding
}
func BridgeWLANMeasurementConfigurationFieldReceived(v *WLANMeasurementConfiguration) *bool {
	return &v.received
}
func BridgeWLANMeasurementConfigurationFieldReceivedAbsolute(v *WLANMeasurementConfiguration) *bool {
	return &v.receivedAbsolute
}
func BridgeWLANMeasurementConfigurationFieldReceivedBytes(v *WLANMeasurementConfiguration) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeWLANMeasurementConfigurationFieldReceivedLocation(v *WLANMeasurementConfiguration) *aper.Location {
	return &v.receivedLocation
}
func BridgeWLANMeasurementConfigurationFieldReplay(v *WLANMeasurementConfiguration) *aper.Snapshot {
	return &v.replay
}
func BridgeWLANMeasurementConfigurationFieldStream(v *WLANMeasurementConfiguration) *aper.WireSpan {
	return &v.stream
}
func BridgeWLANMeasurementConfigurationFieldWithoutReplay(v *WLANMeasurementConfiguration) *bool {
	return &v.withoutReplay
}
func BridgeWLANMeasurementConfigurationFieldWlanMeasConfigNameListIndef(v *WLANMeasurementConfiguration) *bool {
	return &v.wlanMeasConfigNameListIndef
}
func BridgeWLANMeasurementConfigurationMethodMarshalAPERBudget(v *WLANMeasurementConfiguration, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeWLANMeasurementConfigurationMethodMarshalAPERBudgetValue(v *WLANMeasurementConfiguration, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudgetValue(a0, a1)
}
func BridgeWLANMeasurementConfigurationMethodMarshalAPERChanged(v *WLANMeasurementConfiguration, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeWLANMeasurementConfigurationMethodMarshalAPERChangedValue(v *WLANMeasurementConfiguration, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeWLANMeasurementConfigurationMethodMarshalAPERLegacy(v *WLANMeasurementConfiguration) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeWLANMeasurementConfigurationMethodMarshalAPERNewValue(v *WLANMeasurementConfiguration, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERNewValue(a0, a1)
}
func BridgeWLANMeasurementConfigurationMethodMarshalAPERPlanned(v *WLANMeasurementConfiguration, a0 *aper.DecodeBudget, a1 bool, a2 *aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1, a2)
}
func BridgeWLANMeasurementConfigurationMethodMarshalAPERTo(v *WLANMeasurementConfiguration, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeWLANMeasurementConfigurationMethodUnmarshalAPERFrom(v *WLANMeasurementConfiguration, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeWLANMeasurementConfigurationMethodUnmarshalAPERLegacy(v *WLANMeasurementConfiguration, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeWLANMeasurementConfigurationMethodUnmarshalAPERWithOptions(v *WLANMeasurementConfiguration, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeWLANMeasurementConfigurationValueCodecFieldCapture(v *WLANMeasurementConfigurationValueCodec) *func(WLANMeasurementConfiguration, aper.DecodeState) (WLANMeasurementConfiguration, aper.Snapshot) {
	return &v.capture
}
func BridgeWLANMeasurementConfigurationValueCodecFieldCompare(v *WLANMeasurementConfigurationValueCodec) *func(WLANMeasurementConfiguration, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeWLANMeasurementConfigurationValueCodecFieldContext(v *WLANMeasurementConfigurationValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeWLANMeasurementConfigurationValueCodecFieldDecode(v *WLANMeasurementConfigurationValueCodec) *func([]byte, aper.DecodeState) (WLANMeasurementConfiguration, error) {
	return &v.decode
}
func BridgeWLANMeasurementConfigurationValueCodecFieldEncode(v *WLANMeasurementConfigurationValueCodec) *func(WLANMeasurementConfiguration, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeWLANMeasurementConfigurationValueCodecFieldPath(v *WLANMeasurementConfigurationValueCodec) *aper.Path {
	return &v.path
}
func BridgeWLANMeasurementConfigurationValueCodecMethodEncodeBudgetValue(v WLANMeasurementConfigurationValueCodec, a0 WLANMeasurementConfiguration, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeWLANMeasurementConfigurationValueCodecMethodEncodeChanged(v WLANMeasurementConfigurationValueCodec, a0 WLANMeasurementConfiguration, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}

// Selected returns the decoded value of the active alternative, as the matching As method returns it, or false when the value is opaque or empty.
func (v *ImmediateMDTExtIEsValue) Selected() (any, bool) {
	if v == nil || v.isOpaque {
		return nil, false
	}
	switch v.id {
	case 171:
		if value, ok := v.AsM3Configuration(); ok {
			return value, true
		}
	case 172:
		if value, ok := v.AsM4Configuration(); ok {
			return value, true
		}
	case 173:
		if value, ok := v.AsM5Configuration(); ok {
			return value, true
		}
	case 174:
		if value, ok := v.AsMDTLocationInfo(); ok {
			return value, true
		}
	case 220:
		if value, ok := v.AsM6Configuration(); ok {
			return value, true
		}
	case 221:
		if value, ok := v.AsM7Configuration(); ok {
			return value, true
		}
	case 284:
		if value, ok := v.AsBluetoothMeasurementConfiguration(); ok {
			return value, true
		}
	case 285:
		if value, ok := v.AsWLANMeasurementConfiguration(); ok {
			return value, true
		}
	case 345:
		if value, ok := v.AsSensorMeasurementConfiguration(); ok {
			return value, true
		}
	}
	return nil, false
}

// Selected returns the decoded value of the active alternative, as the matching As method returns it, or false when the value is opaque or empty.
func (v *LoggedMDTExtIEsValue) Selected() (any, bool) {
	if v == nil || v.isOpaque {
		return nil, false
	}
	switch v.id {
	case 284:
		if value, ok := v.AsBluetoothMeasurementConfiguration(); ok {
			return value, true
		}
	case 285:
		if value, ok := v.AsWLANMeasurementConfiguration(); ok {
			return value, true
		}
	case 344:
		if value, ok := v.AsLoggedMDTTrigger(); ok {
			return value, true
		}
	case 345:
		if value, ok := v.AsSensorMeasurementConfiguration(); ok {
			return value, true
		}
	}
	return nil, false
}

// Selected returns the decoded value of the active alternative, as the matching As method returns it, or false when the value is opaque or empty.
func (v *TraceActivationExtIEsValue) Selected() (any, bool) {
	if v == nil || v.isOpaque {
		return nil, false
	}
	switch v.id {
	case 162:
		if value, ok := v.AsMDTConfiguration(); ok {
			return value, true
		}
	case 262:
		if value, ok := v.AsUEAppLayerMeasConfig(); ok {
			return value, true
		}
	case 316:
		if value, ok := v.AsMDTConfigurationNR(); ok {
			return value, true
		}
	case 325:
		if value, ok := v.AsTraceCollectionEntityURI(); ok {
			return value, true
		}
	}
	return nil, false
}
