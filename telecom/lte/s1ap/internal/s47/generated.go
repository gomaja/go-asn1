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
	s18 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s18"
	s19 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s19"
	s20 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s20"
	s21 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s21"
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
	s40 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s40"
	s41 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s41"
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

// HandoverRequestIEContainer is the concrete ProtocolIEContainer[HandoverRequestIEValue].
type HandoverRequestIEContainer []HandoverRequestIEField

// HandoverRequestIEField is the concrete ProtocolIEField[HandoverRequestIEValue].
type HandoverRequestIEField struct {
	withoutReplay bool
	replay        aper.Snapshot
	stream        aper.WireSpan
	Id            s00.ProtocolIEID
	Criticality   s00.Criticality
	Value         HandoverRequestIEValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v HandoverRequestIEField) WithoutReplay() HandoverRequestIEField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *HandoverRequestIEField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *HandoverRequestIEField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
func (v *HandoverRequestIEField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolIEField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = HandoverRequestIEField{}
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
	var zero HandoverRequestIEValue

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

// ImmediateMDTExtIEsExtContainer is the concrete ProtocolExtensionContainer[ImmediateMDTExtIEsValue].
type ImmediateMDTExtIEsExtContainer []ImmediateMDTExtIEsExtField

// LoggedMDTExtIEsExtContainer is the concrete ProtocolExtensionContainer[LoggedMDTExtIEsValue].
type LoggedMDTExtIEsExtContainer []LoggedMDTExtIEsExtField

// TraceActivationExtIEsExtContainer is the concrete ProtocolExtensionContainer[TraceActivationExtIEsValue].
type TraceActivationExtIEsExtContainer []TraceActivationExtIEsExtField

// ImmediateMDTExtIEsExtField is the concrete ProtocolExtensionField[ImmediateMDTExtIEsValue].
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
	value, err := zero.decode(v.Id, raw)
	if err != nil {
		return runtime.WrapDecodePath(fmt.Errorf("extension %d: %w", v.Id, err), "ExtensionValue")
	}
	v.ExtensionValue = value
	v.stream = bb.CaptureWireSpan(replayStart)

	return nil
}

// LoggedMDTExtIEsExtField is the concrete ProtocolExtensionField[LoggedMDTExtIEsValue].
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
	value, err := zero.decode(v.Id, raw)
	if err != nil {
		return runtime.WrapDecodePath(fmt.Errorf("extension %d: %w", v.Id, err), "ExtensionValue")
	}
	v.ExtensionValue = value
	v.stream = bb.CaptureWireSpan(replayStart)

	return nil
}

// TraceActivationExtIEsExtField is the concrete ProtocolExtensionField[TraceActivationExtIEsValue].
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
	value, err := zero.decode(v.Id, raw)
	if err != nil {
		return runtime.WrapDecodePath(fmt.Errorf("extension %d: %w", v.Id, err), "ExtensionValue")
	}
	v.ExtensionValue = value
	v.stream = bb.CaptureWireSpan(replayStart)

	return nil
}

// ImmediateMDTExtIEsM3ConfigurationExtBinding is the concrete ExtensionBinding[M3Configuration, ImmediateMDTExtIEsValue].
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

// ImmediateMDTExtIEsM4ConfigurationExtBinding is the concrete ExtensionBinding[M4Configuration, ImmediateMDTExtIEsValue].
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

// ImmediateMDTExtIEsM5ConfigurationExtBinding is the concrete ExtensionBinding[M5Configuration, ImmediateMDTExtIEsValue].
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

// ImmediateMDTExtIEsMDTLocationInfoExtBinding is the concrete ExtensionBinding[MDTLocationInfo, ImmediateMDTExtIEsValue].
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

// ImmediateMDTExtIEsM6ConfigurationExtBinding is the concrete ExtensionBinding[M6Configuration, ImmediateMDTExtIEsValue].
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

// ImmediateMDTExtIEsM7ConfigurationExtBinding is the concrete ExtensionBinding[M7Configuration, ImmediateMDTExtIEsValue].
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

// ImmediateMDTExtIEsBluetoothMeasurementConfigurationExtBinding is the concrete ExtensionBinding[BluetoothMeasurementConfiguration, ImmediateMDTExtIEsValue].
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

// ImmediateMDTExtIEsWLANMeasurementConfigurationExtBinding is the concrete ExtensionBinding[WLANMeasurementConfiguration, ImmediateMDTExtIEsValue].
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

// ImmediateMDTExtIEsSensorMeasurementConfigurationExtBinding is the concrete ExtensionBinding[SensorMeasurementConfiguration, ImmediateMDTExtIEsValue].
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

// LoggedMDTExtIEsBluetoothMeasurementConfigurationExtBinding is the concrete ExtensionBinding[BluetoothMeasurementConfiguration, LoggedMDTExtIEsValue].
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

// LoggedMDTExtIEsWLANMeasurementConfigurationExtBinding is the concrete ExtensionBinding[WLANMeasurementConfiguration, LoggedMDTExtIEsValue].
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

// LoggedMDTExtIEsLoggedMDTTriggerExtBinding is the concrete ExtensionBinding[LoggedMDTTrigger, LoggedMDTExtIEsValue].
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

// LoggedMDTExtIEsSensorMeasurementConfigurationExtBinding is the concrete ExtensionBinding[SensorMeasurementConfiguration, LoggedMDTExtIEsValue].
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

// TraceActivationExtIEsMDTConfigurationExtBinding is the concrete ExtensionBinding[MDTConfiguration, TraceActivationExtIEsValue].
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

// TraceActivationExtIEsUEAppLayerMeasConfigExtBinding is the concrete ExtensionBinding[UEAppLayerMeasConfig, TraceActivationExtIEsValue].
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

// TraceActivationExtIEsMDTConfigurationNRExtBinding is the concrete ExtensionBinding[MDTConfigurationNR, TraceActivationExtIEsValue].
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

// TraceActivationExtIEsURIAddressExtBinding is the concrete ExtensionBinding[URIAddress, TraceActivationExtIEsValue].
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

// HandoverRequestMMEUES1APIDIEBinding is the concrete IEBinding[MMEUES1APID, HandoverRequestIEValue].
type HandoverRequestMMEUES1APIDIEBinding struct {
	info   s00.FieldInfo
	codec  s01.MMEUES1APIDValueCodec
	inject func(s00.MMEUES1APID,

	) HandoverRequestIEValue

	get func(*HandoverRequestIEValue,

	) (*s00.MMEUES1APID,

		bool)
}

// Info returns the source descriptor for this binding.
func (b HandoverRequestMMEUES1APIDIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b HandoverRequestMMEUES1APIDIEBinding) Codec() s01.MMEUES1APIDValueCodec { return b.codec }

// New validates a source value and constructs its bound field.
func (b HandoverRequestMMEUES1APIDIEBinding) New(value s00.MMEUES1APID,

) (HandoverRequestIEField, error) {
	if b.inject == nil {
		return HandoverRequestIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return HandoverRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s01.BridgeMMEUES1APIDValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return HandoverRequestIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return HandoverRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	return HandoverRequestIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b HandoverRequestMMEUES1APIDIEBinding) Get(field *HandoverRequestIEField) (*s00.MMEUES1APID,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// HandoverRequestHandoverTypeIEBinding is the concrete IEBinding[HandoverType, HandoverRequestIEValue].
type HandoverRequestHandoverTypeIEBinding struct {
	info   s00.FieldInfo
	codec  s00.HandoverTypeValueCodec
	inject func(s00.HandoverType,

	) HandoverRequestIEValue

	get func(*HandoverRequestIEValue,

	) (*s00.HandoverType,

		bool)
}

// Info returns the source descriptor for this binding.
func (b HandoverRequestHandoverTypeIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b HandoverRequestHandoverTypeIEBinding) Codec() s00.HandoverTypeValueCodec { return b.codec }

// New validates a source value and constructs its bound field.
func (b HandoverRequestHandoverTypeIEBinding) New(value s00.HandoverType,

) (HandoverRequestIEField, error) {
	if b.inject == nil {
		return HandoverRequestIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return HandoverRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s00.BridgeHandoverTypeValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return HandoverRequestIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return HandoverRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	return HandoverRequestIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b HandoverRequestHandoverTypeIEBinding) Get(field *HandoverRequestIEField) (*s00.HandoverType,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// HandoverRequestCauseIEBinding is the concrete IEBinding[Cause, HandoverRequestIEValue].
type HandoverRequestCauseIEBinding struct {
	info   s00.FieldInfo
	codec  s14.CauseValueCodec
	inject func(s14.Cause,

	) HandoverRequestIEValue

	get func(*HandoverRequestIEValue,

	) (*s14.Cause,

		bool)
}

// Info returns the source descriptor for this binding.
func (b HandoverRequestCauseIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b HandoverRequestCauseIEBinding) Codec() s14.CauseValueCodec { return b.codec }

// New validates a source value and constructs its bound field.
func (b HandoverRequestCauseIEBinding) New(value s14.Cause,

) (HandoverRequestIEField, error) {
	if b.inject == nil {
		return HandoverRequestIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return HandoverRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s14.BridgeCauseValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return HandoverRequestIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return HandoverRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	return HandoverRequestIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b HandoverRequestCauseIEBinding) Get(field *HandoverRequestIEField) (*s14.Cause,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// HandoverRequestUEAggregateMaximumBitrateIEBinding is the concrete IEBinding[UEAggregateMaximumBitrate, HandoverRequestIEValue].
type HandoverRequestUEAggregateMaximumBitrateIEBinding struct {
	info   s00.FieldInfo
	codec  s35.UEAggregateMaximumBitrateValueCodec
	inject func(s35.UEAggregateMaximumBitrate,

	) HandoverRequestIEValue

	get func(*HandoverRequestIEValue,

	) (*s35.UEAggregateMaximumBitrate,

		bool)
}

// Info returns the source descriptor for this binding.
func (b HandoverRequestUEAggregateMaximumBitrateIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b HandoverRequestUEAggregateMaximumBitrateIEBinding) Codec() s35.UEAggregateMaximumBitrateValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b HandoverRequestUEAggregateMaximumBitrateIEBinding) New(value s35.UEAggregateMaximumBitrate,

) (HandoverRequestIEField, error) {
	if b.inject == nil {
		return HandoverRequestIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return HandoverRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s35.BridgeUEAggregateMaximumBitrateValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return HandoverRequestIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return HandoverRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	return HandoverRequestIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b HandoverRequestUEAggregateMaximumBitrateIEBinding) Get(field *HandoverRequestIEField) (*s35.UEAggregateMaximumBitrate,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// HandoverRequestERABToBeSetupListHOReqIEBinding is the concrete IEBinding[ERABToBeSetupListHOReq, HandoverRequestIEValue].
type HandoverRequestERABToBeSetupListHOReqIEBinding struct {
	info   s00.FieldInfo
	codec  s30.ERABToBeSetupListHOReqValueCodec
	inject func(s29.ERABToBeSetupListHOReq,

	) HandoverRequestIEValue

	get func(*HandoverRequestIEValue,

	) (*s29.ERABToBeSetupListHOReq,

		bool)
}

// Info returns the source descriptor for this binding.
func (b HandoverRequestERABToBeSetupListHOReqIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b HandoverRequestERABToBeSetupListHOReqIEBinding) Codec() s30.ERABToBeSetupListHOReqValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b HandoverRequestERABToBeSetupListHOReqIEBinding) New(value s29.ERABToBeSetupListHOReq,

) (HandoverRequestIEField, error) {
	if b.inject == nil {
		return HandoverRequestIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return HandoverRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s30.BridgeERABToBeSetupListHOReqValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return HandoverRequestIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return HandoverRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	return HandoverRequestIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b HandoverRequestERABToBeSetupListHOReqIEBinding) Get(field *HandoverRequestIEField) (*s29.ERABToBeSetupListHOReq,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// HandoverRequestSourceToTargetTransparentContainerIEBinding is the concrete IEBinding[SourceToTargetTransparentContainer, HandoverRequestIEValue].
type HandoverRequestSourceToTargetTransparentContainerIEBinding struct {
	info   s00.FieldInfo
	codec  s01.SourceToTargetTransparentContainerValueCodec
	inject func(s00.SourceToTargetTransparentContainer,

	) HandoverRequestIEValue

	get func(*HandoverRequestIEValue,

	) (*s00.SourceToTargetTransparentContainer,

		bool)
}

// Info returns the source descriptor for this binding.
func (b HandoverRequestSourceToTargetTransparentContainerIEBinding) Info() s00.FieldInfo {
	return b.info
}

// Codec returns the complete value codec for this binding.
func (b HandoverRequestSourceToTargetTransparentContainerIEBinding) Codec() s01.SourceToTargetTransparentContainerValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b HandoverRequestSourceToTargetTransparentContainerIEBinding) New(value s00.SourceToTargetTransparentContainer,

) (HandoverRequestIEField, error) {
	if b.inject == nil {
		return HandoverRequestIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return HandoverRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s01.BridgeSourceToTargetTransparentContainerValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return HandoverRequestIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return HandoverRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	return HandoverRequestIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b HandoverRequestSourceToTargetTransparentContainerIEBinding) Get(field *HandoverRequestIEField) (*s00.SourceToTargetTransparentContainer,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// HandoverRequestUESecurityCapabilitiesIEBinding is the concrete IEBinding[UESecurityCapabilities, HandoverRequestIEValue].
type HandoverRequestUESecurityCapabilitiesIEBinding struct {
	info   s00.FieldInfo
	codec  s37.UESecurityCapabilitiesValueCodec
	inject func(s37.UESecurityCapabilities,

	) HandoverRequestIEValue

	get func(*HandoverRequestIEValue,

	) (*s37.UESecurityCapabilities,

		bool)
}

// Info returns the source descriptor for this binding.
func (b HandoverRequestUESecurityCapabilitiesIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b HandoverRequestUESecurityCapabilitiesIEBinding) Codec() s37.UESecurityCapabilitiesValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b HandoverRequestUESecurityCapabilitiesIEBinding) New(value s37.UESecurityCapabilities,

) (HandoverRequestIEField, error) {
	if b.inject == nil {
		return HandoverRequestIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return HandoverRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s37.BridgeUESecurityCapabilitiesValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return HandoverRequestIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return HandoverRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	return HandoverRequestIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b HandoverRequestUESecurityCapabilitiesIEBinding) Get(field *HandoverRequestIEField) (*s37.UESecurityCapabilities,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// HandoverRequestHandoverRestrictionListIEBinding is the concrete IEBinding[HandoverRestrictionList, HandoverRequestIEValue].
type HandoverRequestHandoverRestrictionListIEBinding struct {
	info   s00.FieldInfo
	codec  s42.HandoverRestrictionListValueCodec
	inject func(s42.HandoverRestrictionList,

	) HandoverRequestIEValue

	get func(*HandoverRequestIEValue,

	) (*s42.HandoverRestrictionList,

		bool)
}

// Info returns the source descriptor for this binding.
func (b HandoverRequestHandoverRestrictionListIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b HandoverRequestHandoverRestrictionListIEBinding) Codec() s42.HandoverRestrictionListValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b HandoverRequestHandoverRestrictionListIEBinding) New(value s42.HandoverRestrictionList,

) (HandoverRequestIEField, error) {
	if b.inject == nil {
		return HandoverRequestIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return HandoverRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s42.BridgeHandoverRestrictionListValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return HandoverRequestIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return HandoverRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	return HandoverRequestIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b HandoverRequestHandoverRestrictionListIEBinding) Get(field *HandoverRequestIEField) (*s42.HandoverRestrictionList,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// HandoverRequestRequestTypeIEBinding is the concrete IEBinding[RequestType, HandoverRequestIEValue].
type HandoverRequestRequestTypeIEBinding struct {
	info   s00.FieldInfo
	codec  s26.RequestTypeValueCodec
	inject func(s26.RequestType,

	) HandoverRequestIEValue

	get func(*HandoverRequestIEValue,

	) (*s26.RequestType,

		bool)
}

// Info returns the source descriptor for this binding.
func (b HandoverRequestRequestTypeIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b HandoverRequestRequestTypeIEBinding) Codec() s26.RequestTypeValueCodec { return b.codec }

// New validates a source value and constructs its bound field.
func (b HandoverRequestRequestTypeIEBinding) New(value s26.RequestType,

) (HandoverRequestIEField, error) {
	if b.inject == nil {
		return HandoverRequestIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return HandoverRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s26.BridgeRequestTypeValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return HandoverRequestIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return HandoverRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	return HandoverRequestIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b HandoverRequestRequestTypeIEBinding) Get(field *HandoverRequestIEField) (*s26.RequestType,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// HandoverRequestSRVCCOperationPossibleIEBinding is the concrete IEBinding[SRVCCOperationPossible, HandoverRequestIEValue].
type HandoverRequestSRVCCOperationPossibleIEBinding struct {
	info   s00.FieldInfo
	codec  s01.SRVCCOperationPossibleValueCodec
	inject func(s00.SRVCCOperationPossible,

	) HandoverRequestIEValue

	get func(*HandoverRequestIEValue,

	) (*s00.SRVCCOperationPossible,

		bool)
}

// Info returns the source descriptor for this binding.
func (b HandoverRequestSRVCCOperationPossibleIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b HandoverRequestSRVCCOperationPossibleIEBinding) Codec() s01.SRVCCOperationPossibleValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b HandoverRequestSRVCCOperationPossibleIEBinding) New(value s00.SRVCCOperationPossible,

) (HandoverRequestIEField, error) {
	if b.inject == nil {
		return HandoverRequestIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return HandoverRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s01.BridgeSRVCCOperationPossibleValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return HandoverRequestIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return HandoverRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	return HandoverRequestIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b HandoverRequestSRVCCOperationPossibleIEBinding) Get(field *HandoverRequestIEField) (*s00.SRVCCOperationPossible,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// HandoverRequestSecurityContextIEBinding is the concrete IEBinding[SecurityContext, HandoverRequestIEValue].
type HandoverRequestSecurityContextIEBinding struct {
	info   s00.FieldInfo
	codec  s28.SecurityContextValueCodec
	inject func(s28.SecurityContext,

	) HandoverRequestIEValue

	get func(*HandoverRequestIEValue,

	) (*s28.SecurityContext,

		bool)
}

// Info returns the source descriptor for this binding.
func (b HandoverRequestSecurityContextIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b HandoverRequestSecurityContextIEBinding) Codec() s28.SecurityContextValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b HandoverRequestSecurityContextIEBinding) New(value s28.SecurityContext,

) (HandoverRequestIEField, error) {
	if b.inject == nil {
		return HandoverRequestIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return HandoverRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s28.BridgeSecurityContextValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return HandoverRequestIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return HandoverRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	return HandoverRequestIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b HandoverRequestSecurityContextIEBinding) Get(field *HandoverRequestIEField) (*s28.SecurityContext,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// HandoverRequestNASSecurityParameterstoEUTRANIEBinding is the concrete IEBinding[NASSecurityParameterstoEUTRAN, HandoverRequestIEValue].
type HandoverRequestNASSecurityParameterstoEUTRANIEBinding struct {
	info   s00.FieldInfo
	codec  s01.NASSecurityParameterstoEUTRANValueCodec
	inject func(s00.NASSecurityParameterstoEUTRAN,

	) HandoverRequestIEValue

	get func(*HandoverRequestIEValue,

	) (*s00.NASSecurityParameterstoEUTRAN,

		bool)
}

// Info returns the source descriptor for this binding.
func (b HandoverRequestNASSecurityParameterstoEUTRANIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b HandoverRequestNASSecurityParameterstoEUTRANIEBinding) Codec() s01.NASSecurityParameterstoEUTRANValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b HandoverRequestNASSecurityParameterstoEUTRANIEBinding) New(value s00.NASSecurityParameterstoEUTRAN,

) (HandoverRequestIEField, error) {
	if b.inject == nil {
		return HandoverRequestIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return HandoverRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s01.BridgeNASSecurityParameterstoEUTRANValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return HandoverRequestIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return HandoverRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	return HandoverRequestIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b HandoverRequestNASSecurityParameterstoEUTRANIEBinding) Get(field *HandoverRequestIEField) (*s00.NASSecurityParameterstoEUTRAN,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// HandoverRequestCSGIdIEBinding is the concrete IEBinding[CSGId, HandoverRequestIEValue].
type HandoverRequestCSGIdIEBinding struct {
	info   s00.FieldInfo
	codec  s00.CSGIdValueCodec
	inject func(s00.CSGId,

	) HandoverRequestIEValue

	get func(*HandoverRequestIEValue,

	) (*s00.CSGId,

		bool)
}

// Info returns the source descriptor for this binding.
func (b HandoverRequestCSGIdIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b HandoverRequestCSGIdIEBinding) Codec() s00.CSGIdValueCodec { return b.codec }

// New validates a source value and constructs its bound field.
func (b HandoverRequestCSGIdIEBinding) New(value s00.CSGId,

) (HandoverRequestIEField, error) {
	if b.inject == nil {
		return HandoverRequestIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return HandoverRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s00.BridgeCSGIdValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return HandoverRequestIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return HandoverRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	return HandoverRequestIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b HandoverRequestCSGIdIEBinding) Get(field *HandoverRequestIEField) (*s00.CSGId,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// HandoverRequestCSGMembershipStatusIEBinding is the concrete IEBinding[CSGMembershipStatus, HandoverRequestIEValue].
type HandoverRequestCSGMembershipStatusIEBinding struct {
	info   s00.FieldInfo
	codec  s00.CSGMembershipStatusValueCodec
	inject func(s00.CSGMembershipStatus,

	) HandoverRequestIEValue

	get func(*HandoverRequestIEValue,

	) (*s00.CSGMembershipStatus,

		bool)
}

// Info returns the source descriptor for this binding.
func (b HandoverRequestCSGMembershipStatusIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b HandoverRequestCSGMembershipStatusIEBinding) Codec() s00.CSGMembershipStatusValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b HandoverRequestCSGMembershipStatusIEBinding) New(value s00.CSGMembershipStatus,

) (HandoverRequestIEField, error) {
	if b.inject == nil {
		return HandoverRequestIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return HandoverRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s00.BridgeCSGMembershipStatusValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return HandoverRequestIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return HandoverRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	return HandoverRequestIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b HandoverRequestCSGMembershipStatusIEBinding) Get(field *HandoverRequestIEField) (*s00.CSGMembershipStatus,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// HandoverRequestGUMMEIIEBinding is the concrete IEBinding[GUMMEI, HandoverRequestIEValue].
type HandoverRequestGUMMEIIEBinding struct {
	info   s00.FieldInfo
	codec  s18.GUMMEIValueCodec
	inject func(s18.GUMMEI,

	) HandoverRequestIEValue

	get func(*HandoverRequestIEValue,

	) (*s18.GUMMEI,

		bool)
}

// Info returns the source descriptor for this binding.
func (b HandoverRequestGUMMEIIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b HandoverRequestGUMMEIIEBinding) Codec() s18.GUMMEIValueCodec { return b.codec }

// New validates a source value and constructs its bound field.
func (b HandoverRequestGUMMEIIEBinding) New(value s18.GUMMEI,

) (HandoverRequestIEField, error) {
	if b.inject == nil {
		return HandoverRequestIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return HandoverRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s18.BridgeGUMMEIValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return HandoverRequestIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return HandoverRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	return HandoverRequestIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b HandoverRequestGUMMEIIEBinding) Get(field *HandoverRequestIEField) (*s18.GUMMEI,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// HandoverRequestManagementBasedMDTAllowedIEBinding is the concrete IEBinding[ManagementBasedMDTAllowed, HandoverRequestIEValue].
type HandoverRequestManagementBasedMDTAllowedIEBinding struct {
	info   s00.FieldInfo
	codec  s01.ManagementBasedMDTAllowedValueCodec
	inject func(s00.ManagementBasedMDTAllowed,

	) HandoverRequestIEValue

	get func(*HandoverRequestIEValue,

	) (*s00.ManagementBasedMDTAllowed,

		bool)
}

// Info returns the source descriptor for this binding.
func (b HandoverRequestManagementBasedMDTAllowedIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b HandoverRequestManagementBasedMDTAllowedIEBinding) Codec() s01.ManagementBasedMDTAllowedValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b HandoverRequestManagementBasedMDTAllowedIEBinding) New(value s00.ManagementBasedMDTAllowed,

) (HandoverRequestIEField, error) {
	if b.inject == nil {
		return HandoverRequestIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return HandoverRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s01.BridgeManagementBasedMDTAllowedValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return HandoverRequestIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return HandoverRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	return HandoverRequestIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b HandoverRequestManagementBasedMDTAllowedIEBinding) Get(field *HandoverRequestIEField) (*s00.ManagementBasedMDTAllowed,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// HandoverRequestMDTPLMNListIEBinding is the concrete IEBinding[MDTPLMNList, HandoverRequestIEValue].
type HandoverRequestMDTPLMNListIEBinding struct {
	info   s00.FieldInfo
	codec  s01.MDTPLMNListValueCodec
	inject func(s00.MDTPLMNList,

	) HandoverRequestIEValue

	get func(*HandoverRequestIEValue,

	) (*s00.MDTPLMNList,

		bool)
}

// Info returns the source descriptor for this binding.
func (b HandoverRequestMDTPLMNListIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b HandoverRequestMDTPLMNListIEBinding) Codec() s01.MDTPLMNListValueCodec { return b.codec }

// New validates a source value and constructs its bound field.
func (b HandoverRequestMDTPLMNListIEBinding) New(value s00.MDTPLMNList,

) (HandoverRequestIEField, error) {
	if b.inject == nil {
		return HandoverRequestIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return HandoverRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s01.BridgeMDTPLMNListValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return HandoverRequestIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return HandoverRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	return HandoverRequestIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b HandoverRequestMDTPLMNListIEBinding) Get(field *HandoverRequestIEField) (*s00.MDTPLMNList,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// HandoverRequestMaskedIMEISVIEBinding is the concrete IEBinding[MaskedIMEISV, HandoverRequestIEValue].
type HandoverRequestMaskedIMEISVIEBinding struct {
	info   s00.FieldInfo
	codec  s01.MaskedIMEISVValueCodec
	inject func(s00.MaskedIMEISV,

	) HandoverRequestIEValue

	get func(*HandoverRequestIEValue,

	) (*s00.MaskedIMEISV,

		bool)
}

// Info returns the source descriptor for this binding.
func (b HandoverRequestMaskedIMEISVIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b HandoverRequestMaskedIMEISVIEBinding) Codec() s01.MaskedIMEISVValueCodec { return b.codec }

// New validates a source value and constructs its bound field.
func (b HandoverRequestMaskedIMEISVIEBinding) New(value s00.MaskedIMEISV,

) (HandoverRequestIEField, error) {
	if b.inject == nil {
		return HandoverRequestIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return HandoverRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s01.BridgeMaskedIMEISVValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return HandoverRequestIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return HandoverRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	return HandoverRequestIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b HandoverRequestMaskedIMEISVIEBinding) Get(field *HandoverRequestIEField) (*s00.MaskedIMEISV,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// HandoverRequestExpectedUEBehaviourIEBinding is the concrete IEBinding[ExpectedUEBehaviour, HandoverRequestIEValue].
type HandoverRequestExpectedUEBehaviourIEBinding struct {
	info   s00.FieldInfo
	codec  s18.ExpectedUEBehaviourValueCodec
	inject func(s18.ExpectedUEBehaviour,

	) HandoverRequestIEValue

	get func(*HandoverRequestIEValue,

	) (*s18.ExpectedUEBehaviour,

		bool)
}

// Info returns the source descriptor for this binding.
func (b HandoverRequestExpectedUEBehaviourIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b HandoverRequestExpectedUEBehaviourIEBinding) Codec() s18.ExpectedUEBehaviourValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b HandoverRequestExpectedUEBehaviourIEBinding) New(value s18.ExpectedUEBehaviour,

) (HandoverRequestIEField, error) {
	if b.inject == nil {
		return HandoverRequestIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return HandoverRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s18.BridgeExpectedUEBehaviourValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return HandoverRequestIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return HandoverRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	return HandoverRequestIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b HandoverRequestExpectedUEBehaviourIEBinding) Get(field *HandoverRequestIEField) (*s18.ExpectedUEBehaviour,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// HandoverRequestProSeAuthorizedIEBinding is the concrete IEBinding[ProSeAuthorized, HandoverRequestIEValue].
type HandoverRequestProSeAuthorizedIEBinding struct {
	info   s00.FieldInfo
	codec  s20.ProSeAuthorizedValueCodec
	inject func(s20.ProSeAuthorized,

	) HandoverRequestIEValue

	get func(*HandoverRequestIEValue,

	) (*s20.ProSeAuthorized,

		bool)
}

// Info returns the source descriptor for this binding.
func (b HandoverRequestProSeAuthorizedIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b HandoverRequestProSeAuthorizedIEBinding) Codec() s20.ProSeAuthorizedValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b HandoverRequestProSeAuthorizedIEBinding) New(value s20.ProSeAuthorized,

) (HandoverRequestIEField, error) {
	if b.inject == nil {
		return HandoverRequestIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return HandoverRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s20.BridgeProSeAuthorizedValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return HandoverRequestIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return HandoverRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	return HandoverRequestIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b HandoverRequestProSeAuthorizedIEBinding) Get(field *HandoverRequestIEField) (*s20.ProSeAuthorized,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// HandoverRequestUEUserPlaneCIoTSupportIndicatorIEBinding is the concrete IEBinding[UEUserPlaneCIoTSupportIndicator, HandoverRequestIEValue].
type HandoverRequestUEUserPlaneCIoTSupportIndicatorIEBinding struct {
	info   s00.FieldInfo
	codec  s02.UEUserPlaneCIoTSupportIndicatorValueCodec
	inject func(s00.UEUserPlaneCIoTSupportIndicator,

	) HandoverRequestIEValue

	get func(*HandoverRequestIEValue,

	) (*s00.UEUserPlaneCIoTSupportIndicator,

		bool)
}

// Info returns the source descriptor for this binding.
func (b HandoverRequestUEUserPlaneCIoTSupportIndicatorIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b HandoverRequestUEUserPlaneCIoTSupportIndicatorIEBinding) Codec() s02.UEUserPlaneCIoTSupportIndicatorValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b HandoverRequestUEUserPlaneCIoTSupportIndicatorIEBinding) New(value s00.UEUserPlaneCIoTSupportIndicator,

) (HandoverRequestIEField, error) {
	if b.inject == nil {
		return HandoverRequestIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return HandoverRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s02.BridgeUEUserPlaneCIoTSupportIndicatorValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return HandoverRequestIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return HandoverRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	return HandoverRequestIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b HandoverRequestUEUserPlaneCIoTSupportIndicatorIEBinding) Get(field *HandoverRequestIEField) (*s00.UEUserPlaneCIoTSupportIndicator,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// HandoverRequestV2XServicesAuthorizedIEBinding is the concrete IEBinding[V2XServicesAuthorized, HandoverRequestIEValue].
type HandoverRequestV2XServicesAuthorizedIEBinding struct {
	info   s00.FieldInfo
	codec  s46.V2XServicesAuthorizedValueCodec
	inject func(s46.V2XServicesAuthorized,

	) HandoverRequestIEValue

	get func(*HandoverRequestIEValue,

	) (*s46.V2XServicesAuthorized,

		bool)
}

// Info returns the source descriptor for this binding.
func (b HandoverRequestV2XServicesAuthorizedIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b HandoverRequestV2XServicesAuthorizedIEBinding) Codec() s46.V2XServicesAuthorizedValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b HandoverRequestV2XServicesAuthorizedIEBinding) New(value s46.V2XServicesAuthorized,

) (HandoverRequestIEField, error) {
	if b.inject == nil {
		return HandoverRequestIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return HandoverRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s46.BridgeV2XServicesAuthorizedValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return HandoverRequestIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return HandoverRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	return HandoverRequestIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b HandoverRequestV2XServicesAuthorizedIEBinding) Get(field *HandoverRequestIEField) (*s46.V2XServicesAuthorized,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// HandoverRequestUESidelinkAggregateMaximumBitrateIEBinding is the concrete IEBinding[UESidelinkAggregateMaximumBitrate, HandoverRequestIEValue].
type HandoverRequestUESidelinkAggregateMaximumBitrateIEBinding struct {
	info   s00.FieldInfo
	codec  s37.UESidelinkAggregateMaximumBitrateValueCodec
	inject func(s37.UESidelinkAggregateMaximumBitrate,

	) HandoverRequestIEValue

	get func(*HandoverRequestIEValue,

	) (*s37.UESidelinkAggregateMaximumBitrate,

		bool)
}

// Info returns the source descriptor for this binding.
func (b HandoverRequestUESidelinkAggregateMaximumBitrateIEBinding) Info() s00.FieldInfo {
	return b.info
}

// Codec returns the complete value codec for this binding.
func (b HandoverRequestUESidelinkAggregateMaximumBitrateIEBinding) Codec() s37.UESidelinkAggregateMaximumBitrateValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b HandoverRequestUESidelinkAggregateMaximumBitrateIEBinding) New(value s37.UESidelinkAggregateMaximumBitrate,

) (HandoverRequestIEField, error) {
	if b.inject == nil {
		return HandoverRequestIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return HandoverRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s37.BridgeUESidelinkAggregateMaximumBitrateValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return HandoverRequestIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return HandoverRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	return HandoverRequestIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b HandoverRequestUESidelinkAggregateMaximumBitrateIEBinding) Get(field *HandoverRequestIEField) (*s37.UESidelinkAggregateMaximumBitrate,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// HandoverRequestEnhancedCoverageRestrictedIEBinding is the concrete IEBinding[EnhancedCoverageRestricted, HandoverRequestIEValue].
type HandoverRequestEnhancedCoverageRestrictedIEBinding struct {
	info   s00.FieldInfo
	codec  s00.EnhancedCoverageRestrictedValueCodec
	inject func(s00.EnhancedCoverageRestricted,

	) HandoverRequestIEValue

	get func(*HandoverRequestIEValue,

	) (*s00.EnhancedCoverageRestricted,

		bool)
}

// Info returns the source descriptor for this binding.
func (b HandoverRequestEnhancedCoverageRestrictedIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b HandoverRequestEnhancedCoverageRestrictedIEBinding) Codec() s00.EnhancedCoverageRestrictedValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b HandoverRequestEnhancedCoverageRestrictedIEBinding) New(value s00.EnhancedCoverageRestricted,

) (HandoverRequestIEField, error) {
	if b.inject == nil {
		return HandoverRequestIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return HandoverRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s00.BridgeEnhancedCoverageRestrictedValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return HandoverRequestIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return HandoverRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	return HandoverRequestIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b HandoverRequestEnhancedCoverageRestrictedIEBinding) Get(field *HandoverRequestIEField) (*s00.EnhancedCoverageRestricted,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// HandoverRequestNRUESecurityCapabilitiesIEBinding is the concrete IEBinding[NRUESecurityCapabilities, HandoverRequestIEValue].
type HandoverRequestNRUESecurityCapabilitiesIEBinding struct {
	info   s00.FieldInfo
	codec  s19.NRUESecurityCapabilitiesValueCodec
	inject func(s19.NRUESecurityCapabilities,

	) HandoverRequestIEValue

	get func(*HandoverRequestIEValue,

	) (*s19.NRUESecurityCapabilities,

		bool)
}

// Info returns the source descriptor for this binding.
func (b HandoverRequestNRUESecurityCapabilitiesIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b HandoverRequestNRUESecurityCapabilitiesIEBinding) Codec() s19.NRUESecurityCapabilitiesValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b HandoverRequestNRUESecurityCapabilitiesIEBinding) New(value s19.NRUESecurityCapabilities,

) (HandoverRequestIEField, error) {
	if b.inject == nil {
		return HandoverRequestIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return HandoverRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s19.BridgeNRUESecurityCapabilitiesValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return HandoverRequestIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return HandoverRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	return HandoverRequestIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b HandoverRequestNRUESecurityCapabilitiesIEBinding) Get(field *HandoverRequestIEField) (*s19.NRUESecurityCapabilities,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// HandoverRequestCEModeBRestrictedIEBinding is the concrete IEBinding[CEModeBRestricted, HandoverRequestIEValue].
type HandoverRequestCEModeBRestrictedIEBinding struct {
	info   s00.FieldInfo
	codec  s00.CEModeBRestrictedValueCodec
	inject func(s00.CEModeBRestricted,

	) HandoverRequestIEValue

	get func(*HandoverRequestIEValue,

	) (*s00.CEModeBRestricted,

		bool)
}

// Info returns the source descriptor for this binding.
func (b HandoverRequestCEModeBRestrictedIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b HandoverRequestCEModeBRestrictedIEBinding) Codec() s00.CEModeBRestrictedValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b HandoverRequestCEModeBRestrictedIEBinding) New(value s00.CEModeBRestricted,

) (HandoverRequestIEField, error) {
	if b.inject == nil {
		return HandoverRequestIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return HandoverRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s00.BridgeCEModeBRestrictedValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return HandoverRequestIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return HandoverRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	return HandoverRequestIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b HandoverRequestCEModeBRestrictedIEBinding) Get(field *HandoverRequestIEField) (*s00.CEModeBRestricted,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// HandoverRequestAerialUEsubscriptionInformationIEBinding is the concrete IEBinding[AerialUEsubscriptionInformation, HandoverRequestIEValue].
type HandoverRequestAerialUEsubscriptionInformationIEBinding struct {
	info   s00.FieldInfo
	codec  s00.AerialUEsubscriptionInformationValueCodec
	inject func(s00.AerialUEsubscriptionInformation,

	) HandoverRequestIEValue

	get func(*HandoverRequestIEValue,

	) (*s00.AerialUEsubscriptionInformation,

		bool)
}

// Info returns the source descriptor for this binding.
func (b HandoverRequestAerialUEsubscriptionInformationIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b HandoverRequestAerialUEsubscriptionInformationIEBinding) Codec() s00.AerialUEsubscriptionInformationValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b HandoverRequestAerialUEsubscriptionInformationIEBinding) New(value s00.AerialUEsubscriptionInformation,

) (HandoverRequestIEField, error) {
	if b.inject == nil {
		return HandoverRequestIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return HandoverRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s00.BridgeAerialUEsubscriptionInformationValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return HandoverRequestIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return HandoverRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	return HandoverRequestIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b HandoverRequestAerialUEsubscriptionInformationIEBinding) Get(field *HandoverRequestIEField) (*s00.AerialUEsubscriptionInformation,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// HandoverRequestPendingDataIndicationIEBinding is the concrete IEBinding[PendingDataIndication, HandoverRequestIEValue].
type HandoverRequestPendingDataIndicationIEBinding struct {
	info   s00.FieldInfo
	codec  s01.PendingDataIndicationValueCodec
	inject func(s00.PendingDataIndication,

	) HandoverRequestIEValue

	get func(*HandoverRequestIEValue,

	) (*s00.PendingDataIndication,

		bool)
}

// Info returns the source descriptor for this binding.
func (b HandoverRequestPendingDataIndicationIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b HandoverRequestPendingDataIndicationIEBinding) Codec() s01.PendingDataIndicationValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b HandoverRequestPendingDataIndicationIEBinding) New(value s00.PendingDataIndication,

) (HandoverRequestIEField, error) {
	if b.inject == nil {
		return HandoverRequestIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return HandoverRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s01.BridgePendingDataIndicationValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return HandoverRequestIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return HandoverRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	return HandoverRequestIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b HandoverRequestPendingDataIndicationIEBinding) Get(field *HandoverRequestIEField) (*s00.PendingDataIndication,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// HandoverRequestSubscriptionBasedUEDifferentiationInfoIEBinding is the concrete IEBinding[SubscriptionBasedUEDifferentiationInfo, HandoverRequestIEValue].
type HandoverRequestSubscriptionBasedUEDifferentiationInfoIEBinding struct {
	info   s00.FieldInfo
	codec  s31.SubscriptionBasedUEDifferentiationInfoValueCodec
	inject func(s30.SubscriptionBasedUEDifferentiationInfo,

	) HandoverRequestIEValue

	get func(*HandoverRequestIEValue,

	) (*s30.SubscriptionBasedUEDifferentiationInfo,

		bool)
}

// Info returns the source descriptor for this binding.
func (b HandoverRequestSubscriptionBasedUEDifferentiationInfoIEBinding) Info() s00.FieldInfo {
	return b.info
}

// Codec returns the complete value codec for this binding.
func (b HandoverRequestSubscriptionBasedUEDifferentiationInfoIEBinding) Codec() s31.SubscriptionBasedUEDifferentiationInfoValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b HandoverRequestSubscriptionBasedUEDifferentiationInfoIEBinding) New(value s30.SubscriptionBasedUEDifferentiationInfo,

) (HandoverRequestIEField, error) {
	if b.inject == nil {
		return HandoverRequestIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return HandoverRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s31.BridgeSubscriptionBasedUEDifferentiationInfoValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return HandoverRequestIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return HandoverRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	return HandoverRequestIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b HandoverRequestSubscriptionBasedUEDifferentiationInfoIEBinding) Get(field *HandoverRequestIEField) (*s30.SubscriptionBasedUEDifferentiationInfo,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// HandoverRequestAdditionalRRMPriorityIndexIEBinding is the concrete IEBinding[AdditionalRRMPriorityIndex, HandoverRequestIEValue].
type HandoverRequestAdditionalRRMPriorityIndexIEBinding struct {
	info   s00.FieldInfo
	codec  s00.AdditionalRRMPriorityIndexValueCodec
	inject func(s00.AdditionalRRMPriorityIndex,

	) HandoverRequestIEValue

	get func(*HandoverRequestIEValue,

	) (*s00.AdditionalRRMPriorityIndex,

		bool)
}

// Info returns the source descriptor for this binding.
func (b HandoverRequestAdditionalRRMPriorityIndexIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b HandoverRequestAdditionalRRMPriorityIndexIEBinding) Codec() s00.AdditionalRRMPriorityIndexValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b HandoverRequestAdditionalRRMPriorityIndexIEBinding) New(value s00.AdditionalRRMPriorityIndex,

) (HandoverRequestIEField, error) {
	if b.inject == nil {
		return HandoverRequestIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return HandoverRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s00.BridgeAdditionalRRMPriorityIndexValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return HandoverRequestIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return HandoverRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	return HandoverRequestIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b HandoverRequestAdditionalRRMPriorityIndexIEBinding) Get(field *HandoverRequestIEField) (*s00.AdditionalRRMPriorityIndex,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// HandoverRequestIABAuthorizedIEBinding is the concrete IEBinding[IABAuthorized, HandoverRequestIEValue].
type HandoverRequestIABAuthorizedIEBinding struct {
	info   s00.FieldInfo
	codec  s00.IABAuthorizedValueCodec
	inject func(s00.IABAuthorized,

	) HandoverRequestIEValue

	get func(*HandoverRequestIEValue,

	) (*s00.IABAuthorized,

		bool)
}

// Info returns the source descriptor for this binding.
func (b HandoverRequestIABAuthorizedIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b HandoverRequestIABAuthorizedIEBinding) Codec() s00.IABAuthorizedValueCodec { return b.codec }

// New validates a source value and constructs its bound field.
func (b HandoverRequestIABAuthorizedIEBinding) New(value s00.IABAuthorized,

) (HandoverRequestIEField, error) {
	if b.inject == nil {
		return HandoverRequestIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return HandoverRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s00.BridgeIABAuthorizedValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return HandoverRequestIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return HandoverRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	return HandoverRequestIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b HandoverRequestIABAuthorizedIEBinding) Get(field *HandoverRequestIEField) (*s00.IABAuthorized,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// HandoverRequestNRV2XServicesAuthorizedIEBinding is the concrete IEBinding[NRV2XServicesAuthorized, HandoverRequestIEValue].
type HandoverRequestNRV2XServicesAuthorizedIEBinding struct {
	info   s00.FieldInfo
	codec  s19.NRV2XServicesAuthorizedValueCodec
	inject func(s19.NRV2XServicesAuthorized,

	) HandoverRequestIEValue

	get func(*HandoverRequestIEValue,

	) (*s19.NRV2XServicesAuthorized,

		bool)
}

// Info returns the source descriptor for this binding.
func (b HandoverRequestNRV2XServicesAuthorizedIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b HandoverRequestNRV2XServicesAuthorizedIEBinding) Codec() s19.NRV2XServicesAuthorizedValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b HandoverRequestNRV2XServicesAuthorizedIEBinding) New(value s19.NRV2XServicesAuthorized,

) (HandoverRequestIEField, error) {
	if b.inject == nil {
		return HandoverRequestIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return HandoverRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s19.BridgeNRV2XServicesAuthorizedValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return HandoverRequestIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return HandoverRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	return HandoverRequestIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b HandoverRequestNRV2XServicesAuthorizedIEBinding) Get(field *HandoverRequestIEField) (*s19.NRV2XServicesAuthorized,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// HandoverRequestNRUESidelinkAggregateMaximumBitrateIEBinding is the concrete IEBinding[NRUESidelinkAggregateMaximumBitrate, HandoverRequestIEValue].
type HandoverRequestNRUESidelinkAggregateMaximumBitrateIEBinding struct {
	info   s00.FieldInfo
	codec  s19.NRUESidelinkAggregateMaximumBitrateValueCodec
	inject func(s19.NRUESidelinkAggregateMaximumBitrate,

	) HandoverRequestIEValue

	get func(*HandoverRequestIEValue,

	) (*s19.NRUESidelinkAggregateMaximumBitrate,

		bool)
}

// Info returns the source descriptor for this binding.
func (b HandoverRequestNRUESidelinkAggregateMaximumBitrateIEBinding) Info() s00.FieldInfo {
	return b.info
}

// Codec returns the complete value codec for this binding.
func (b HandoverRequestNRUESidelinkAggregateMaximumBitrateIEBinding) Codec() s19.NRUESidelinkAggregateMaximumBitrateValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b HandoverRequestNRUESidelinkAggregateMaximumBitrateIEBinding) New(value s19.NRUESidelinkAggregateMaximumBitrate,

) (HandoverRequestIEField, error) {
	if b.inject == nil {
		return HandoverRequestIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return HandoverRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s19.BridgeNRUESidelinkAggregateMaximumBitrateValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return HandoverRequestIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return HandoverRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	return HandoverRequestIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b HandoverRequestNRUESidelinkAggregateMaximumBitrateIEBinding) Get(field *HandoverRequestIEField) (*s19.NRUESidelinkAggregateMaximumBitrate,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// HandoverRequestPC5QoSParametersIEBinding is the concrete IEBinding[PC5QoSParameters, HandoverRequestIEValue].
type HandoverRequestPC5QoSParametersIEBinding struct {
	info   s00.FieldInfo
	codec  s24.PC5QoSParametersValueCodec
	inject func(s24.PC5QoSParameters,

	) HandoverRequestIEValue

	get func(*HandoverRequestIEValue,

	) (*s24.PC5QoSParameters,

		bool)
}

// Info returns the source descriptor for this binding.
func (b HandoverRequestPC5QoSParametersIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b HandoverRequestPC5QoSParametersIEBinding) Codec() s24.PC5QoSParametersValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b HandoverRequestPC5QoSParametersIEBinding) New(value s24.PC5QoSParameters,

) (HandoverRequestIEField, error) {
	if b.inject == nil {
		return HandoverRequestIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return HandoverRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s24.BridgePC5QoSParametersValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return HandoverRequestIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return HandoverRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	return HandoverRequestIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b HandoverRequestPC5QoSParametersIEBinding) Get(field *HandoverRequestIEField) (*s24.PC5QoSParameters,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// HandoverRequestUERadioCapabilityIDIEBinding is the concrete IEBinding[UERadioCapabilityID, HandoverRequestIEValue].
type HandoverRequestUERadioCapabilityIDIEBinding struct {
	info   s00.FieldInfo
	codec  s02.UERadioCapabilityIDValueCodec
	inject func(s00.UERadioCapabilityID,

	) HandoverRequestIEValue

	get func(*HandoverRequestIEValue,

	) (*s00.UERadioCapabilityID,

		bool)
}

// Info returns the source descriptor for this binding.
func (b HandoverRequestUERadioCapabilityIDIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b HandoverRequestUERadioCapabilityIDIEBinding) Codec() s02.UERadioCapabilityIDValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b HandoverRequestUERadioCapabilityIDIEBinding) New(value s00.UERadioCapabilityID,

) (HandoverRequestIEField, error) {
	if b.inject == nil {
		return HandoverRequestIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return HandoverRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s02.BridgeUERadioCapabilityIDValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return HandoverRequestIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return HandoverRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	return HandoverRequestIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b HandoverRequestUERadioCapabilityIDIEBinding) Get(field *HandoverRequestIEField) (*s00.UERadioCapabilityID,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// HandoverRequestTimeRefDistributionIEBinding is the concrete IEBinding[TimeRefDistribution, HandoverRequestIEValue].
type HandoverRequestTimeRefDistributionIEBinding struct {
	info   s00.FieldInfo
	codec  s02.TimeRefDistributionValueCodec
	inject func(s00.TimeRefDistribution,

	) HandoverRequestIEValue

	get func(*HandoverRequestIEValue,

	) (*s00.TimeRefDistribution,

		bool)
}

// Info returns the source descriptor for this binding.
func (b HandoverRequestTimeRefDistributionIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b HandoverRequestTimeRefDistributionIEBinding) Codec() s02.TimeRefDistributionValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b HandoverRequestTimeRefDistributionIEBinding) New(value s00.TimeRefDistribution,

) (HandoverRequestIEField, error) {
	if b.inject == nil {
		return HandoverRequestIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return HandoverRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s02.BridgeTimeRefDistributionValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return HandoverRequestIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return HandoverRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	return HandoverRequestIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b HandoverRequestTimeRefDistributionIEBinding) Get(field *HandoverRequestIEField) (*s00.TimeRefDistribution,

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
func UEContextModificationRequestIEValueERABIEContainerListCodec(table s00.UEContextModificationRequestIEValueIETable) s46.UEContextModificationRequestIEValueERABIEContainerListValueCodec {
	codec := s46.UEContextModificationRequestIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
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
			s46.BridgeUEContextModificationRequestIEValueCaptureS1APERABIEContainerList(&v, &s)
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
func UEContextModificationRequestIEValueProtocolErrorIEContainerListCodec(table s00.UEContextModificationRequestIEValueIETable) s46.UEContextModificationRequestIEValueProtocolErrorIEContainerListValueCodec {
	codec := s46.UEContextModificationRequestIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
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
			s46.BridgeUEContextModificationRequestIEValueCaptureS1APProtocolErrorIEContainerList(&v, &s)
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
func UEContextModificationRequestIEValueProtocolIEContainerListCodec(table s00.UEContextModificationRequestIEValueIETable, bounds aper.ListBounds) s46.UEContextModificationRequestIEValueProtocolIEContainerListValueCodec {
	codec := s46.UEContextModificationRequestIEValueIETableCodec(table, bounds)
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
			s46.BridgeUEContextModificationRequestIEValueCaptureS1APProtocolIEContainerList(&v, &s)
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

// ImmediateMDTExtIEsIEField is the concrete ProtocolIEField[ImmediateMDTExtIEsValue].
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
	value, err := zero.decode(v.Id, raw)
	if err != nil {
		return runtime.WrapDecodePath(err, "Value")
	}
	v.Value = value
	v.stream = bb.CaptureWireSpan(replayStart)

	return nil
}

// ImmediateMDTExtIEsIEContainer is the concrete ProtocolIEContainer[ImmediateMDTExtIEsValue].
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

// LoggedMDTExtIEsIEField is the concrete ProtocolIEField[LoggedMDTExtIEsValue].
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
	value, err := zero.decode(v.Id, raw)
	if err != nil {
		return runtime.WrapDecodePath(err, "Value")
	}
	v.Value = value
	v.stream = bb.CaptureWireSpan(replayStart)

	return nil
}

// LoggedMDTExtIEsIEContainer is the concrete ProtocolIEContainer[LoggedMDTExtIEsValue].
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

// TraceActivationExtIEsIEField is the concrete ProtocolIEField[TraceActivationExtIEsValue].
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
	value, err := zero.decode(v.Id, raw)
	if err != nil {
		return runtime.WrapDecodePath(err, "Value")
	}
	v.Value = value
	v.stream = bb.CaptureWireSpan(replayStart)

	return nil
}

// TraceActivationExtIEsIEContainer is the concrete ProtocolIEContainer[TraceActivationExtIEsValue].
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

// HandoverRequestIEValueERABIEContainerListValueCodec is the concrete ValueCodec[ERABIEContainerList[HandoverRequestIEValue]].
type HandoverRequestIEValueERABIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (HandoverRequestIEValueERABIEContainerList, error)
	encode  func(HandoverRequestIEValueERABIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(HandoverRequestIEValueERABIEContainerList, aper.DecodeState) (HandoverRequestIEValueERABIEContainerList, aper.Snapshot)
	compare func(HandoverRequestIEValueERABIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c HandoverRequestIEValueERABIEContainerListValueCodec) New(value HandoverRequestIEValueERABIEContainerList) (HandoverRequestIEValueERABIEContainerListAPERValue, error) {
	if c.encode == nil {
		return HandoverRequestIEValueERABIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return HandoverRequestIEValueERABIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return HandoverRequestIEValueERABIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return HandoverRequestIEValueERABIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c HandoverRequestIEValueERABIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (HandoverRequestIEValueERABIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return HandoverRequestIEValueERABIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return HandoverRequestIEValueERABIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return HandoverRequestIEValueERABIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return HandoverRequestIEValueERABIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c HandoverRequestIEValueERABIEContainerListValueCodec) EncodeAPER(value HandoverRequestIEValueERABIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c HandoverRequestIEValueERABIEContainerListValueCodec) encodeBudgetValue(value HandoverRequestIEValueERABIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c HandoverRequestIEValueERABIEContainerListValueCodec) encodeChanged(value HandoverRequestIEValueERABIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// HandoverRequestIEValueERABIEContainerList is the concrete ERABIEContainerList[HandoverRequestIEValue].
type HandoverRequestIEValueERABIEContainerList []HandoverRequestIEValueProtocolIESingleContainer

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

// ImmediateMDTExtIEsExtFieldValueCodec is the concrete ValueCodec[ProtocolExtensionField[ImmediateMDTExtIEsValue]].
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

// LoggedMDTExtIEsExtFieldValueCodec is the concrete ValueCodec[ProtocolExtensionField[LoggedMDTExtIEsValue]].
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

// TraceActivationExtIEsExtFieldValueCodec is the concrete ValueCodec[ProtocolExtensionField[TraceActivationExtIEsValue]].
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

// ImmediateMDTExtIEsExtContainerValueCodec is the concrete ValueCodec[ProtocolExtensionContainer[ImmediateMDTExtIEsValue]].
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

// LoggedMDTExtIEsExtContainerValueCodec is the concrete ValueCodec[ProtocolExtensionContainer[LoggedMDTExtIEsValue]].
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

// TraceActivationExtIEsExtContainerValueCodec is the concrete ValueCodec[ProtocolExtensionContainer[TraceActivationExtIEsValue]].
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

// HandoverRequestIEFieldValueCodec is the concrete ValueCodec[ProtocolIEField[HandoverRequestIEValue]].
type HandoverRequestIEFieldValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (HandoverRequestIEField, error)
	encode  func(HandoverRequestIEField, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(HandoverRequestIEField, aper.DecodeState) (HandoverRequestIEField, aper.Snapshot)
	compare func(HandoverRequestIEField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c HandoverRequestIEFieldValueCodec) New(value HandoverRequestIEField) (HandoverRequestIEFieldAPERValue, error) {
	if c.encode == nil {
		return HandoverRequestIEFieldAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return HandoverRequestIEFieldAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return HandoverRequestIEFieldAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return HandoverRequestIEFieldAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c HandoverRequestIEFieldValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (HandoverRequestIEFieldAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return HandoverRequestIEFieldAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return HandoverRequestIEFieldAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return HandoverRequestIEFieldAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return HandoverRequestIEFieldAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c HandoverRequestIEFieldValueCodec) EncodeAPER(value HandoverRequestIEFieldAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c HandoverRequestIEFieldValueCodec) encodeBudgetValue(value HandoverRequestIEField, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c HandoverRequestIEFieldValueCodec) encodeChanged(value HandoverRequestIEField, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// HandoverRequestIEContainerValueCodec is the concrete ValueCodec[ProtocolIEContainer[HandoverRequestIEValue]].
type HandoverRequestIEContainerValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (HandoverRequestIEContainer, error)
	encode  func(HandoverRequestIEContainer, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(HandoverRequestIEContainer, aper.DecodeState) (HandoverRequestIEContainer, aper.Snapshot)
	compare func(HandoverRequestIEContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c HandoverRequestIEContainerValueCodec) New(value HandoverRequestIEContainer) (HandoverRequestIEContainerAPERValue, error) {
	if c.encode == nil {
		return HandoverRequestIEContainerAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return HandoverRequestIEContainerAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return HandoverRequestIEContainerAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return HandoverRequestIEContainerAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c HandoverRequestIEContainerValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (HandoverRequestIEContainerAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return HandoverRequestIEContainerAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return HandoverRequestIEContainerAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return HandoverRequestIEContainerAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return HandoverRequestIEContainerAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c HandoverRequestIEContainerValueCodec) EncodeAPER(value HandoverRequestIEContainerAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c HandoverRequestIEContainerValueCodec) encodeBudgetValue(value HandoverRequestIEContainer, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c HandoverRequestIEContainerValueCodec) encodeChanged(value HandoverRequestIEContainer, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// HandoverRequestIEValueProtocolErrorIEContainerListValueCodec is the concrete ValueCodec[ProtocolErrorIEContainerList[HandoverRequestIEValue]].
type HandoverRequestIEValueProtocolErrorIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (HandoverRequestIEValueProtocolErrorIEContainerList, error)
	encode  func(HandoverRequestIEValueProtocolErrorIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(HandoverRequestIEValueProtocolErrorIEContainerList, aper.DecodeState) (HandoverRequestIEValueProtocolErrorIEContainerList, aper.Snapshot)
	compare func(HandoverRequestIEValueProtocolErrorIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c HandoverRequestIEValueProtocolErrorIEContainerListValueCodec) New(value HandoverRequestIEValueProtocolErrorIEContainerList) (HandoverRequestIEValueProtocolErrorIEContainerListAPERValue, error) {
	if c.encode == nil {
		return HandoverRequestIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return HandoverRequestIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return HandoverRequestIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return HandoverRequestIEValueProtocolErrorIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c HandoverRequestIEValueProtocolErrorIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (HandoverRequestIEValueProtocolErrorIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return HandoverRequestIEValueProtocolErrorIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return HandoverRequestIEValueProtocolErrorIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return HandoverRequestIEValueProtocolErrorIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return HandoverRequestIEValueProtocolErrorIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c HandoverRequestIEValueProtocolErrorIEContainerListValueCodec) EncodeAPER(value HandoverRequestIEValueProtocolErrorIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c HandoverRequestIEValueProtocolErrorIEContainerListValueCodec) encodeBudgetValue(value HandoverRequestIEValueProtocolErrorIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c HandoverRequestIEValueProtocolErrorIEContainerListValueCodec) encodeChanged(value HandoverRequestIEValueProtocolErrorIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// HandoverRequestIEValueProtocolErrorIEContainerList is the concrete ProtocolErrorIEContainerList[HandoverRequestIEValue].
type HandoverRequestIEValueProtocolErrorIEContainerList []HandoverRequestIEValueProtocolIESingleContainer

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

// HandoverRequestIEValueProtocolIEContainerListValueCodec is the concrete ValueCodec[ProtocolIEContainerList[HandoverRequestIEValue]].
type HandoverRequestIEValueProtocolIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (HandoverRequestIEValueProtocolIEContainerList, error)
	encode  func(HandoverRequestIEValueProtocolIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(HandoverRequestIEValueProtocolIEContainerList, aper.DecodeState) (HandoverRequestIEValueProtocolIEContainerList, aper.Snapshot)
	compare func(HandoverRequestIEValueProtocolIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c HandoverRequestIEValueProtocolIEContainerListValueCodec) New(value HandoverRequestIEValueProtocolIEContainerList) (HandoverRequestIEValueProtocolIEContainerListAPERValue, error) {
	if c.encode == nil {
		return HandoverRequestIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return HandoverRequestIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return HandoverRequestIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return HandoverRequestIEValueProtocolIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c HandoverRequestIEValueProtocolIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (HandoverRequestIEValueProtocolIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return HandoverRequestIEValueProtocolIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return HandoverRequestIEValueProtocolIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return HandoverRequestIEValueProtocolIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return HandoverRequestIEValueProtocolIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c HandoverRequestIEValueProtocolIEContainerListValueCodec) EncodeAPER(value HandoverRequestIEValueProtocolIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c HandoverRequestIEValueProtocolIEContainerListValueCodec) encodeBudgetValue(value HandoverRequestIEValueProtocolIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c HandoverRequestIEValueProtocolIEContainerListValueCodec) encodeChanged(value HandoverRequestIEValueProtocolIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// HandoverRequestIEValueProtocolIEContainerList is the concrete ProtocolIEContainerList[HandoverRequestIEValue].
type HandoverRequestIEValueProtocolIEContainerList []HandoverRequestIEValueProtocolIESingleContainer

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

// HandoverRequestIEValueERABIEContainerListAPERValue is the concrete APERValue[ERABIEContainerList[HandoverRequestIEValue]].
type HandoverRequestIEValueERABIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         HandoverRequestIEValueERABIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v HandoverRequestIEValueERABIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v HandoverRequestIEValueERABIEContainerListAPERValue) WithoutReplay() HandoverRequestIEValueERABIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// HandoverRequestIEValueProtocolIESingleContainer is the concrete ProtocolIESingleContainer[HandoverRequestIEValue].
type HandoverRequestIEValueProtocolIESingleContainer = HandoverRequestIEField

func BridgeUEContextModificationRequestIEValueCompareS1APProtocolIESingleContainer(v *s46.UEContextModificationRequestIEValueProtocolIESingleContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s46.BridgeUEContextModificationRequestIEValueCompareS1APProtocolIEField(v, s)
	s.End(f, aper.Snapshot{}, false)
}

// ImmediateMDTExtIEsExtFieldAPERValue is the concrete APERValue[ProtocolExtensionField[ImmediateMDTExtIEsValue]].
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

// LoggedMDTExtIEsExtFieldAPERValue is the concrete APERValue[ProtocolExtensionField[LoggedMDTExtIEsValue]].
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

// TraceActivationExtIEsExtFieldAPERValue is the concrete APERValue[ProtocolExtensionField[TraceActivationExtIEsValue]].
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

// ImmediateMDTExtIEsExtContainerAPERValue is the concrete APERValue[ProtocolExtensionContainer[ImmediateMDTExtIEsValue]].
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

// LoggedMDTExtIEsExtContainerAPERValue is the concrete APERValue[ProtocolExtensionContainer[LoggedMDTExtIEsValue]].
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

// TraceActivationExtIEsExtContainerAPERValue is the concrete APERValue[ProtocolExtensionContainer[TraceActivationExtIEsValue]].
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

// HandoverRequestIEFieldAPERValue is the concrete APERValue[ProtocolIEField[HandoverRequestIEValue]].
type HandoverRequestIEFieldAPERValue struct {
	context       s00.BridgeCodecContext
	Value         HandoverRequestIEField
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v HandoverRequestIEFieldAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v HandoverRequestIEFieldAPERValue) WithoutReplay() HandoverRequestIEFieldAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// HandoverRequestIEContainerAPERValue is the concrete APERValue[ProtocolIEContainer[HandoverRequestIEValue]].
type HandoverRequestIEContainerAPERValue struct {
	context       s00.BridgeCodecContext
	Value         HandoverRequestIEContainer
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v HandoverRequestIEContainerAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v HandoverRequestIEContainerAPERValue) WithoutReplay() HandoverRequestIEContainerAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// HandoverRequestIEValueProtocolErrorIEContainerListAPERValue is the concrete APERValue[ProtocolErrorIEContainerList[HandoverRequestIEValue]].
type HandoverRequestIEValueProtocolErrorIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         HandoverRequestIEValueProtocolErrorIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v HandoverRequestIEValueProtocolErrorIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v HandoverRequestIEValueProtocolErrorIEContainerListAPERValue) WithoutReplay() HandoverRequestIEValueProtocolErrorIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// HandoverRequestIEValueProtocolIEContainerListAPERValue is the concrete APERValue[ProtocolIEContainerList[HandoverRequestIEValue]].
type HandoverRequestIEValueProtocolIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         HandoverRequestIEValueProtocolIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v HandoverRequestIEValueProtocolIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v HandoverRequestIEValueProtocolIEContainerListAPERValue) WithoutReplay() HandoverRequestIEValueProtocolIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}
func BridgeCaptureS1APHandoverRequestIEValue(v *HandoverRequestIEValue, s *aper.SemanticCapture) {
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
		case s00.ProtocolIEID(1):
			{
				f := s.Begin()
				s.Bool(v.rowHandoverType == nil)
				if v.rowHandoverType != nil {
					s00.BridgeCaptureS1APHandoverType(v.rowHandoverType, s)
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
		case s00.ProtocolIEID(66):
			{
				f := s.Begin()
				s.Bool(v.rowUEaggregateMaximumBitrate == nil)
				if v.rowUEaggregateMaximumBitrate != nil {
					s35.BridgeCaptureS1APUEAggregateMaximumBitrate(v.rowUEaggregateMaximumBitrate, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(53):
			{
				f := s.Begin()
				s.Bool(v.rowERABToBeSetupListHOReq == nil)
				if v.rowERABToBeSetupListHOReq != nil {
					s30.BridgeCaptureS1APERABToBeSetupListHOReq(v.rowERABToBeSetupListHOReq, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(104):
			{
				f := s.Begin()
				s.Bool(v.rowSourceToTargetTransparentContainer == nil)
				if v.rowSourceToTargetTransparentContainer != nil {
					s00.BridgeCaptureS1APSourceToTargetTransparentContainer(v.rowSourceToTargetTransparentContainer, s)
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
		case s00.ProtocolIEID(41):
			{
				f := s.Begin()
				s.Bool(v.rowHandoverRestrictionList == nil)
				if v.rowHandoverRestrictionList != nil {
					s42.BridgeCaptureS1APHandoverRestrictionList(v.rowHandoverRestrictionList, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(25):
			{
				f := s.Begin()
				s.Bool(v.rowTraceActivation == nil)
				if v.rowTraceActivation != nil {
					BridgeCaptureS1APTraceActivation(v.rowTraceActivation, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(98):
			{
				f := s.Begin()
				s.Bool(v.rowRequestType == nil)
				if v.rowRequestType != nil {
					s26.BridgeCaptureS1APRequestType(v.rowRequestType, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(124):
			{
				f := s.Begin()
				s.Bool(v.rowSRVCCOperationPossible == nil)
				if v.rowSRVCCOperationPossible != nil {
					s00.BridgeCaptureS1APSRVCCOperationPossible(v.rowSRVCCOperationPossible, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(40):
			{
				f := s.Begin()
				s.Bool(v.rowSecurityContext == nil)
				if v.rowSecurityContext != nil {
					s28.BridgeCaptureS1APSecurityContext(v.rowSecurityContext, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(136):
			{
				f := s.Begin()
				s.Bool(v.rowNASSecurityParameterstoEUTRAN == nil)
				if v.rowNASSecurityParameterstoEUTRAN != nil {
					s00.BridgeCaptureS1APNASSecurityParameterstoEUTRAN(v.rowNASSecurityParameterstoEUTRAN, s)
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
		case s00.ProtocolIEID(146):
			{
				f := s.Begin()
				s.Bool(v.rowCSGMembershipStatus == nil)
				if v.rowCSGMembershipStatus != nil {
					s00.BridgeCaptureS1APCSGMembershipStatus(v.rowCSGMembershipStatus, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(75):
			{
				f := s.Begin()
				s.Bool(v.rowGUMMEIID == nil)
				if v.rowGUMMEIID != nil {
					s18.BridgeCaptureS1APGUMMEI(v.rowGUMMEIID, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(158):
			{
				f := s.Begin()
				s.Bool(v.rowMMEUES1APID2 == nil)
				if v.rowMMEUES1APID2 != nil {
					s00.BridgeCaptureS1APMMEUES1APID(v.rowMMEUES1APID2, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(165):
			{
				f := s.Begin()
				s.Bool(v.rowManagementBasedMDTAllowed == nil)
				if v.rowManagementBasedMDTAllowed != nil {
					s00.BridgeCaptureS1APManagementBasedMDTAllowed(v.rowManagementBasedMDTAllowed, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(177):
			{
				f := s.Begin()
				s.Bool(v.rowManagementBasedMDTPLMNList == nil)
				if v.rowManagementBasedMDTPLMNList != nil {
					s00.BridgeCaptureS1APMDTPLMNList(v.rowManagementBasedMDTPLMNList, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(192):
			{
				f := s.Begin()
				s.Bool(v.rowMaskedIMEISV == nil)
				if v.rowMaskedIMEISV != nil {
					s00.BridgeCaptureS1APMaskedIMEISV(v.rowMaskedIMEISV, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(196):
			{
				f := s.Begin()
				s.Bool(v.rowExpectedUEBehaviour == nil)
				if v.rowExpectedUEBehaviour != nil {
					s18.BridgeCaptureS1APExpectedUEBehaviour(v.rowExpectedUEBehaviour, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(195):
			{
				f := s.Begin()
				s.Bool(v.rowProSeAuthorized == nil)
				if v.rowProSeAuthorized != nil {
					s20.BridgeCaptureS1APProSeAuthorized(v.rowProSeAuthorized, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(241):
			{
				f := s.Begin()
				s.Bool(v.rowUEUserPlaneCIoTSupportIndicator == nil)
				if v.rowUEUserPlaneCIoTSupportIndicator != nil {
					s00.BridgeCaptureS1APUEUserPlaneCIoTSupportIndicator(v.rowUEUserPlaneCIoTSupportIndicator, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(240):
			{
				f := s.Begin()
				s.Bool(v.rowV2XServicesAuthorized == nil)
				if v.rowV2XServicesAuthorized != nil {
					s46.BridgeCaptureS1APV2XServicesAuthorized(v.rowV2XServicesAuthorized, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(248):
			{
				f := s.Begin()
				s.Bool(v.rowUESidelinkAggregateMaximumBitrate == nil)
				if v.rowUESidelinkAggregateMaximumBitrate != nil {
					s37.BridgeCaptureS1APUESidelinkAggregateMaximumBitrate(v.rowUESidelinkAggregateMaximumBitrate, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(251):
			{
				f := s.Begin()
				s.Bool(v.rowEnhancedCoverageRestricted == nil)
				if v.rowEnhancedCoverageRestricted != nil {
					s00.BridgeCaptureS1APEnhancedCoverageRestricted(v.rowEnhancedCoverageRestricted, s)
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
		case s00.ProtocolIEID(271):
			{
				f := s.Begin()
				s.Bool(v.rowCEModeBRestricted == nil)
				if v.rowCEModeBRestricted != nil {
					s00.BridgeCaptureS1APCEModeBRestricted(v.rowCEModeBRestricted, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(277):
			{
				f := s.Begin()
				s.Bool(v.rowAerialUEsubscriptionInformation == nil)
				if v.rowAerialUEsubscriptionInformation != nil {
					s00.BridgeCaptureS1APAerialUEsubscriptionInformation(v.rowAerialUEsubscriptionInformation, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(283):
			{
				f := s.Begin()
				s.Bool(v.rowPendingDataIndication == nil)
				if v.rowPendingDataIndication != nil {
					s00.BridgeCaptureS1APPendingDataIndication(v.rowPendingDataIndication, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(278):
			{
				f := s.Begin()
				s.Bool(v.rowSubscriptionBasedUEDifferentiationInfo == nil)
				if v.rowSubscriptionBasedUEDifferentiationInfo != nil {
					s30.BridgeCaptureS1APSubscriptionBasedUEDifferentiationInfo(v.rowSubscriptionBasedUEDifferentiationInfo, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(299):
			{
				f := s.Begin()
				s.Bool(v.rowAdditionalRRMPriorityIndex == nil)
				if v.rowAdditionalRRMPriorityIndex != nil {
					s00.BridgeCaptureS1APAdditionalRRMPriorityIndex(v.rowAdditionalRRMPriorityIndex, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(301):
			{
				f := s.Begin()
				s.Bool(v.rowIABAuthorized == nil)
				if v.rowIABAuthorized != nil {
					s00.BridgeCaptureS1APIABAuthorized(v.rowIABAuthorized, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(306):
			{
				f := s.Begin()
				s.Bool(v.rowNRV2XServicesAuthorized == nil)
				if v.rowNRV2XServicesAuthorized != nil {
					s19.BridgeCaptureS1APNRV2XServicesAuthorized(v.rowNRV2XServicesAuthorized, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(307):
			{
				f := s.Begin()
				s.Bool(v.rowNRUESidelinkAggregateMaximumBitrate == nil)
				if v.rowNRUESidelinkAggregateMaximumBitrate != nil {
					s19.BridgeCaptureS1APNRUESidelinkAggregateMaximumBitrate(v.rowNRUESidelinkAggregateMaximumBitrate, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(308):
			{
				f := s.Begin()
				s.Bool(v.rowPC5QoSParameters == nil)
				if v.rowPC5QoSParameters != nil {
					s24.BridgeCaptureS1APPC5QoSParameters(v.rowPC5QoSParameters, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(314):
			{
				f := s.Begin()
				s.Bool(v.rowUERadioCapabilityID == nil)
				if v.rowUERadioCapabilityID != nil {
					s00.BridgeCaptureS1APUERadioCapabilityID(v.rowUERadioCapabilityID, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(355):
			{
				f := s.Begin()
				s.Bool(v.rowTimeRefDistribution == nil)
				if v.rowTimeRefDistribution != nil {
					s00.BridgeCaptureS1APTimeRefDistribution(v.rowTimeRefDistribution, s)
				}
				s.End(f, nil, false)
			}
		}
	}
	s.End(f, &v.replay, false)
	s.CheckReceived(v.replay, v.received)
}
func (v HandoverRequestIEValue) captureSemantics(s aper.SemanticCapture) HandoverRequestIEValue {
	BridgeCaptureS1APHandoverRequestIEValue(&v, &s)
	return v
}
func BridgeCompareS1APHandoverRequestIEValue(v *HandoverRequestIEValue, s *aper.SemanticComparison) {
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
		case s00.ProtocolIEID(1):
			{
				f := s.Begin()
				s.Bool(v.rowHandoverType == nil)
				if v.rowHandoverType != nil {
					s02.BridgeCompareS1APHandoverType(v.rowHandoverType, s)
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
		case s00.ProtocolIEID(66):
			{
				f := s.Begin()
				s.Bool(v.rowUEaggregateMaximumBitrate == nil)
				if v.rowUEaggregateMaximumBitrate != nil {
					s35.BridgeCompareS1APUEAggregateMaximumBitrate(v.rowUEaggregateMaximumBitrate, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(53):
			{
				f := s.Begin()
				s.Bool(v.rowERABToBeSetupListHOReq == nil)
				if v.rowERABToBeSetupListHOReq != nil {
					s30.BridgeCompareS1APERABToBeSetupListHOReq(v.rowERABToBeSetupListHOReq, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(104):
			{
				f := s.Begin()
				s.Bool(v.rowSourceToTargetTransparentContainer == nil)
				if v.rowSourceToTargetTransparentContainer != nil {
					s07.BridgeCompareS1APSourceToTargetTransparentContainer(v.rowSourceToTargetTransparentContainer, s)
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
		case s00.ProtocolIEID(41):
			{
				f := s.Begin()
				s.Bool(v.rowHandoverRestrictionList == nil)
				if v.rowHandoverRestrictionList != nil {
					s42.BridgeCompareS1APHandoverRestrictionList(v.rowHandoverRestrictionList, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(25):
			{
				f := s.Begin()
				s.Bool(v.rowTraceActivation == nil)
				if v.rowTraceActivation != nil {
					BridgeCompareS1APTraceActivation(v.rowTraceActivation, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(98):
			{
				f := s.Begin()
				s.Bool(v.rowRequestType == nil)
				if v.rowRequestType != nil {
					s26.BridgeCompareS1APRequestType(v.rowRequestType, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(124):
			{
				f := s.Begin()
				s.Bool(v.rowSRVCCOperationPossible == nil)
				if v.rowSRVCCOperationPossible != nil {
					s06.BridgeCompareS1APSRVCCOperationPossible(v.rowSRVCCOperationPossible, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(40):
			{
				f := s.Begin()
				s.Bool(v.rowSecurityContext == nil)
				if v.rowSecurityContext != nil {
					s28.BridgeCompareS1APSecurityContext(v.rowSecurityContext, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(136):
			{
				f := s.Begin()
				s.Bool(v.rowNASSecurityParameterstoEUTRAN == nil)
				if v.rowNASSecurityParameterstoEUTRAN != nil {
					s02.BridgeCompareS1APNASSecurityParameterstoEUTRAN(v.rowNASSecurityParameterstoEUTRAN, s)
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
		case s00.ProtocolIEID(146):
			{
				f := s.Begin()
				s.Bool(v.rowCSGMembershipStatus == nil)
				if v.rowCSGMembershipStatus != nil {
					s02.BridgeCompareS1APCSGMembershipStatus(v.rowCSGMembershipStatus, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(75):
			{
				f := s.Begin()
				s.Bool(v.rowGUMMEIID == nil)
				if v.rowGUMMEIID != nil {
					s18.BridgeCompareS1APGUMMEI(v.rowGUMMEIID, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(158):
			{
				f := s.Begin()
				s.Bool(v.rowMMEUES1APID2 == nil)
				if v.rowMMEUES1APID2 != nil {
					s02.BridgeCompareS1APMMEUES1APID(v.rowMMEUES1APID2, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(165):
			{
				f := s.Begin()
				s.Bool(v.rowManagementBasedMDTAllowed == nil)
				if v.rowManagementBasedMDTAllowed != nil {
					s02.BridgeCompareS1APManagementBasedMDTAllowed(v.rowManagementBasedMDTAllowed, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(177):
			{
				f := s.Begin()
				s.Bool(v.rowManagementBasedMDTPLMNList == nil)
				if v.rowManagementBasedMDTPLMNList != nil {
					s07.BridgeCompareS1APMDTPLMNList(v.rowManagementBasedMDTPLMNList, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(192):
			{
				f := s.Begin()
				s.Bool(v.rowMaskedIMEISV == nil)
				if v.rowMaskedIMEISV != nil {
					s02.BridgeCompareS1APMaskedIMEISV(v.rowMaskedIMEISV, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(196):
			{
				f := s.Begin()
				s.Bool(v.rowExpectedUEBehaviour == nil)
				if v.rowExpectedUEBehaviour != nil {
					s18.BridgeCompareS1APExpectedUEBehaviour(v.rowExpectedUEBehaviour, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(195):
			{
				f := s.Begin()
				s.Bool(v.rowProSeAuthorized == nil)
				if v.rowProSeAuthorized != nil {
					s20.BridgeCompareS1APProSeAuthorized(v.rowProSeAuthorized, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(241):
			{
				f := s.Begin()
				s.Bool(v.rowUEUserPlaneCIoTSupportIndicator == nil)
				if v.rowUEUserPlaneCIoTSupportIndicator != nil {
					s07.BridgeCompareS1APUEUserPlaneCIoTSupportIndicator(v.rowUEUserPlaneCIoTSupportIndicator, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(240):
			{
				f := s.Begin()
				s.Bool(v.rowV2XServicesAuthorized == nil)
				if v.rowV2XServicesAuthorized != nil {
					s46.BridgeCompareS1APV2XServicesAuthorized(v.rowV2XServicesAuthorized, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(248):
			{
				f := s.Begin()
				s.Bool(v.rowUESidelinkAggregateMaximumBitrate == nil)
				if v.rowUESidelinkAggregateMaximumBitrate != nil {
					s37.BridgeCompareS1APUESidelinkAggregateMaximumBitrate(v.rowUESidelinkAggregateMaximumBitrate, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(251):
			{
				f := s.Begin()
				s.Bool(v.rowEnhancedCoverageRestricted == nil)
				if v.rowEnhancedCoverageRestricted != nil {
					s02.BridgeCompareS1APEnhancedCoverageRestricted(v.rowEnhancedCoverageRestricted, s)
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
		case s00.ProtocolIEID(271):
			{
				f := s.Begin()
				s.Bool(v.rowCEModeBRestricted == nil)
				if v.rowCEModeBRestricted != nil {
					s02.BridgeCompareS1APCEModeBRestricted(v.rowCEModeBRestricted, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(277):
			{
				f := s.Begin()
				s.Bool(v.rowAerialUEsubscriptionInformation == nil)
				if v.rowAerialUEsubscriptionInformation != nil {
					s02.BridgeCompareS1APAerialUEsubscriptionInformation(v.rowAerialUEsubscriptionInformation, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(283):
			{
				f := s.Begin()
				s.Bool(v.rowPendingDataIndication == nil)
				if v.rowPendingDataIndication != nil {
					s02.BridgeCompareS1APPendingDataIndication(v.rowPendingDataIndication, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(278):
			{
				f := s.Begin()
				s.Bool(v.rowSubscriptionBasedUEDifferentiationInfo == nil)
				if v.rowSubscriptionBasedUEDifferentiationInfo != nil {
					s30.BridgeCompareS1APSubscriptionBasedUEDifferentiationInfo(v.rowSubscriptionBasedUEDifferentiationInfo, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(299):
			{
				f := s.Begin()
				s.Bool(v.rowAdditionalRRMPriorityIndex == nil)
				if v.rowAdditionalRRMPriorityIndex != nil {
					s02.BridgeCompareS1APAdditionalRRMPriorityIndex(v.rowAdditionalRRMPriorityIndex, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(301):
			{
				f := s.Begin()
				s.Bool(v.rowIABAuthorized == nil)
				if v.rowIABAuthorized != nil {
					s02.BridgeCompareS1APIABAuthorized(v.rowIABAuthorized, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(306):
			{
				f := s.Begin()
				s.Bool(v.rowNRV2XServicesAuthorized == nil)
				if v.rowNRV2XServicesAuthorized != nil {
					s19.BridgeCompareS1APNRV2XServicesAuthorized(v.rowNRV2XServicesAuthorized, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(307):
			{
				f := s.Begin()
				s.Bool(v.rowNRUESidelinkAggregateMaximumBitrate == nil)
				if v.rowNRUESidelinkAggregateMaximumBitrate != nil {
					s19.BridgeCompareS1APNRUESidelinkAggregateMaximumBitrate(v.rowNRUESidelinkAggregateMaximumBitrate, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(308):
			{
				f := s.Begin()
				s.Bool(v.rowPC5QoSParameters == nil)
				if v.rowPC5QoSParameters != nil {
					s24.BridgeCompareS1APPC5QoSParameters(v.rowPC5QoSParameters, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(314):
			{
				f := s.Begin()
				s.Bool(v.rowUERadioCapabilityID == nil)
				if v.rowUERadioCapabilityID != nil {
					s07.BridgeCompareS1APUERadioCapabilityID(v.rowUERadioCapabilityID, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(355):
			{
				f := s.Begin()
				s.Bool(v.rowTimeRefDistribution == nil)
				if v.rowTimeRefDistribution != nil {
					s07.BridgeCompareS1APTimeRefDistribution(v.rowTimeRefDistribution, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		}
	}
	s.End(f, v.replay, false)
	s.CheckReceived(v.replay, v.received)
}
func (v HandoverRequestIEValue) compareSemantics(s aper.SemanticComparison) aper.SemanticComparison {
	BridgeCompareS1APHandoverRequestIEValue(&v, &s)
	return s
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
			s18.BridgeCaptureS1APM1PeriodicReporting(v.M1periodicReporting, s)
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
			s18.BridgeCompareS1APM1PeriodicReporting(v.M1periodicReporting, s)
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
	s41.BridgeMDTConfigurationExtIEsValueCaptureS1APProtocolExtensionContainer(&v.IEExtensions, s)
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
	s41.BridgeMDTConfigurationExtIEsValueCompareS1APProtocolExtensionContainer(&v.IEExtensions, s)
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
	M1periodicReporting    *s18.M1PeriodicReporting       `asn1:"tag:3,context,implicit,optional" json:"M1periodicReporting,omitempty"`
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
	IEExtensions      s41.MDTConfigurationExtIEsExtContainer `asn1:"tag:3,context,implicit,optional" json:"IEExtensions,omitzero"`
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
		if err := s18.BridgeM1PeriodicReportingMethodMarshalAPERTo(v.M1periodicReporting, bb, len(fresh) != 0 && fresh[0]); err != nil {
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
		var dec_m1periodicreporting s18.M1PeriodicReporting
		if err := s18.BridgeM1PeriodicReportingMethodUnmarshalAPERFrom(&dec_m1periodicreporting, bb); err != nil {
			return runtime.WrapDecodePath(err, "M1periodicReporting")
		}
		if err := aper.ChargeValue(bb, dec_m1periodicreporting); err != nil {
			return err
		}
		v.M1periodicReporting = &dec_m1periodicreporting
		bb.LeaveComponent(toleranceMark_m1periodicreporting)
	}
	if opt_ieextensions {
		tmp_ieextensions := make(ImmediateMDTExtIEsExtContainer, 0)
		_, errCollection_ieextensions := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1128
			if fragmentOffset_ieextensions < 0 || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(^uint(0)>>1) || fragmentOffset_ieextensions > int64(^uint(0)>>1)-fragmentLength_ieextensions {
				return fmt.Errorf("collection fragment count out of range")
			}
			for i := int64(0); i < fragmentLength_ieextensions; i++ {
				var elem ImmediateMDTExtIEsExtField
				if err := elem.unmarshalAPERFrom(bb); err != nil {
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
		tmp_ieextensions := make(LoggedMDTExtIEsExtContainer, 0)
		_, errCollection_ieextensions := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1128
			if fragmentOffset_ieextensions < 0 || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(^uint(0)>>1) || fragmentOffset_ieextensions > int64(^uint(0)>>1)-fragmentLength_ieextensions {
				return fmt.Errorf("collection fragment count out of range")
			}
			for i := int64(0); i < fragmentLength_ieextensions; i++ {
				var elem LoggedMDTExtIEsExtField
				if err := elem.unmarshalAPERFrom(bb); err != nil {
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
				if err := s41.BridgeMDTConfigurationExtIEsExtFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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
		tmp_ieextensions := make(s41.MDTConfigurationExtIEsExtContainer, 0)
		_, errCollection_ieextensions := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1128
			if fragmentOffset_ieextensions < 0 || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(^uint(0)>>1) || fragmentOffset_ieextensions > int64(^uint(0)>>1)-fragmentLength_ieextensions {
				return fmt.Errorf("collection fragment count out of range")
			}
			for i := int64(0); i < fragmentLength_ieextensions; i++ {
				var elem s41.MDTConfigurationExtIEsExtField
				if err := s41.BridgeMDTConfigurationExtIEsExtFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
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
			var dec_mdtmodeextension s19.MDTModeExtension
			if err := s19.BridgeMDTModeExtensionMethodUnmarshalAPERFrom(&dec_mdtmodeextension, inner); err != nil {
				return runtime.WrapDecodePath(err, "MDTModeExtension")
			}
			if err := aper.ChargeValue(inner, dec_mdtmodeextension); err != nil {
				return err
			}
			v.MDTModeExtension = &dec_mdtmodeextension
		}
		padding, err := aper.CaptureOpenTypePadding(inner)
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
		tmp_ieextensions := make(TraceActivationExtIEsExtContainer, 0)
		_, errCollection_ieextensions := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1128
			if fragmentOffset_ieextensions < 0 || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(^uint(0)>>1) || fragmentOffset_ieextensions > int64(^uint(0)>>1)-fragmentLength_ieextensions {
				return fmt.Errorf("collection fragment count out of range")
			}
			for i := int64(0); i < fragmentLength_ieextensions; i++ {
				var elem TraceActivationExtIEsExtField
				if err := elem.unmarshalAPERFrom(bb); err != nil {
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
		tmp_ieextensions := make(s12.WLANMeasurementConfigurationExtIEsExtContainer, 0)
		_, errCollection_ieextensions := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1128
			if fragmentOffset_ieextensions < 0 || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(^uint(0)>>1) || fragmentOffset_ieextensions > int64(^uint(0)>>1)-fragmentLength_ieextensions {
				return fmt.Errorf("collection fragment count out of range")
			}
			for i := int64(0); i < fragmentLength_ieextensions; i++ {
				var elem s12.WLANMeasurementConfigurationExtIEsExtField
				if err := s12.BridgeWLANMeasurementConfigurationExtIEsExtFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
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
func (v *ImmediateMDTExtIEsValue) AsM3Configuration() (*s19.M3Configuration, bool) {
	if v == nil || v.id != s00.ProtocolIEID(171) || v.rowM3Configuration == nil {
		return nil, false
	}
	return v.rowM3Configuration, true
}
func (v *ImmediateMDTExtIEsValue) AsM4Configuration() (*s19.M4Configuration, bool) {
	if v == nil || v.id != s00.ProtocolIEID(172) || v.rowM4Configuration == nil {
		return nil, false
	}
	return v.rowM4Configuration, true
}
func (v *ImmediateMDTExtIEsValue) AsM5Configuration() (*s19.M5Configuration, bool) {
	if v == nil || v.id != s00.ProtocolIEID(173) || v.rowM5Configuration == nil {
		return nil, false
	}
	return v.rowM5Configuration, true
}
func (v *ImmediateMDTExtIEsValue) AsMDTLocationInfo() (*s00.MDTLocationInfo, bool) {
	if v == nil || v.id != s00.ProtocolIEID(174) || v.rowMDTLocationInfo == nil {
		return nil, false
	}
	return v.rowMDTLocationInfo, true
}
func (v *ImmediateMDTExtIEsValue) AsM6Configuration() (*s19.M6Configuration, bool) {
	if v == nil || v.id != s00.ProtocolIEID(220) || v.rowM6Configuration == nil {
		return nil, false
	}
	return v.rowM6Configuration, true
}
func (v *ImmediateMDTExtIEsValue) AsM7Configuration() (*s19.M7Configuration, bool) {
	if v == nil || v.id != s00.ProtocolIEID(221) || v.rowM7Configuration == nil {
		return nil, false
	}
	return v.rowM7Configuration, true
}
func (v *ImmediateMDTExtIEsValue) AsBluetoothMeasurementConfiguration() (*s14.BluetoothMeasurementConfiguration, bool) {
	if v == nil || v.id != s00.ProtocolIEID(284) || v.rowBluetoothMeasurementConfiguration == nil {
		return nil, false
	}
	return v.rowBluetoothMeasurementConfiguration, true
}
func (v *ImmediateMDTExtIEsValue) AsWLANMeasurementConfiguration() (*WLANMeasurementConfiguration, bool) {
	if v == nil || v.id != s00.ProtocolIEID(285) || v.rowWLANMeasurementConfiguration == nil {
		return nil, false
	}
	return v.rowWLANMeasurementConfiguration, true
}
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
func (v *LoggedMDTExtIEsValue) AsBluetoothMeasurementConfiguration() (*s14.BluetoothMeasurementConfiguration, bool) {
	if v == nil || v.id != s00.ProtocolIEID(284) || v.rowBluetoothMeasurementConfiguration == nil {
		return nil, false
	}
	return v.rowBluetoothMeasurementConfiguration, true
}
func (v *LoggedMDTExtIEsValue) AsWLANMeasurementConfiguration() (*WLANMeasurementConfiguration, bool) {
	if v == nil || v.id != s00.ProtocolIEID(285) || v.rowWLANMeasurementConfiguration == nil {
		return nil, false
	}
	return v.rowWLANMeasurementConfiguration, true
}
func (v *LoggedMDTExtIEsValue) AsLoggedMDTTrigger() (*s19.LoggedMDTTrigger, bool) {
	if v == nil || v.id != s00.ProtocolIEID(344) || v.rowLoggedMDTTrigger == nil {
		return nil, false
	}
	return v.rowLoggedMDTTrigger, true
}
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
func (v *TraceActivationExtIEsValue) AsMDTConfiguration() (*MDTConfiguration, bool) {
	if v == nil || v.id != s00.ProtocolIEID(162) || v.rowMDTConfiguration == nil {
		return nil, false
	}
	return v.rowMDTConfiguration, true
}
func (v *TraceActivationExtIEsValue) AsUEAppLayerMeasConfig() (*s35.UEAppLayerMeasConfig, bool) {
	if v == nil || v.id != s00.ProtocolIEID(262) || v.rowUEAppLayerMeasConfig == nil {
		return nil, false
	}
	return v.rowUEAppLayerMeasConfig, true
}
func (v *TraceActivationExtIEsValue) AsMDTConfigurationNR() (*s00.MDTConfigurationNR, bool) {
	if v == nil || v.id != s00.ProtocolIEID(316) || v.rowMDTConfigurationNR == nil {
		return nil, false
	}
	return v.rowMDTConfigurationNR, true
}
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

type HandoverRequestIEValue struct {
	id                                        s00.ProtocolIEID
	received                                  aper.WireSpan
	replay                                    aper.Snapshot
	opaque                                    aper.OpaqueOpenType
	isOpaque                                  bool
	rowMMEUES1APID                            *s00.MMEUES1APID
	rowHandoverType                           *s00.HandoverType
	rowCause                                  *s14.Cause
	rowUEaggregateMaximumBitrate              *s35.UEAggregateMaximumBitrate
	rowERABToBeSetupListHOReq                 *s29.ERABToBeSetupListHOReq
	rowSourceToTargetTransparentContainer     *s00.SourceToTargetTransparentContainer
	rowUESecurityCapabilities                 *s37.UESecurityCapabilities
	rowHandoverRestrictionList                *s42.HandoverRestrictionList
	rowTraceActivation                        *TraceActivation
	rowRequestType                            *s26.RequestType
	rowSRVCCOperationPossible                 *s00.SRVCCOperationPossible
	rowSecurityContext                        *s28.SecurityContext
	rowNASSecurityParameterstoEUTRAN          *s00.NASSecurityParameterstoEUTRAN
	rowCSGId                                  *s00.CSGId
	rowCSGMembershipStatus                    *s00.CSGMembershipStatus
	rowGUMMEIID                               *s18.GUMMEI
	rowMMEUES1APID2                           *s00.MMEUES1APID
	rowManagementBasedMDTAllowed              *s00.ManagementBasedMDTAllowed
	rowManagementBasedMDTPLMNList             *s00.MDTPLMNList
	rowMaskedIMEISV                           *s00.MaskedIMEISV
	rowExpectedUEBehaviour                    *s18.ExpectedUEBehaviour
	rowProSeAuthorized                        *s20.ProSeAuthorized
	rowUEUserPlaneCIoTSupportIndicator        *s00.UEUserPlaneCIoTSupportIndicator
	rowV2XServicesAuthorized                  *s46.V2XServicesAuthorized
	rowUESidelinkAggregateMaximumBitrate      *s37.UESidelinkAggregateMaximumBitrate
	rowEnhancedCoverageRestricted             *s00.EnhancedCoverageRestricted
	rowNRUESecurityCapabilities               *s19.NRUESecurityCapabilities
	rowCEModeBRestricted                      *s00.CEModeBRestricted
	rowAerialUEsubscriptionInformation        *s00.AerialUEsubscriptionInformation
	rowPendingDataIndication                  *s00.PendingDataIndication
	rowSubscriptionBasedUEDifferentiationInfo *s30.SubscriptionBasedUEDifferentiationInfo
	rowAdditionalRRMPriorityIndex             *s00.AdditionalRRMPriorityIndex
	rowIABAuthorized                          *s00.IABAuthorized
	rowNRV2XServicesAuthorized                *s19.NRV2XServicesAuthorized
	rowNRUESidelinkAggregateMaximumBitrate    *s19.NRUESidelinkAggregateMaximumBitrate
	rowPC5QoSParameters                       *s24.PC5QoSParameters
	rowUERadioCapabilityID                    *s00.UERadioCapabilityID
	rowTimeRefDistribution                    *s00.TimeRefDistribution
}

func (v HandoverRequestIEValue) matchesID(id s00.ProtocolIEID, _ ...*aper.DecodeBudget) bool {
	if v.id != id {
		return false
	}
	if v.isOpaque {
		return true
	}
	switch id {
	case s00.ProtocolIEID(0):
		return v.rowMMEUES1APID != nil
	case s00.ProtocolIEID(1):
		return v.rowHandoverType != nil
	case s00.ProtocolIEID(2):
		return v.rowCause != nil
	case s00.ProtocolIEID(66):
		return v.rowUEaggregateMaximumBitrate != nil
	case s00.ProtocolIEID(53):
		return v.rowERABToBeSetupListHOReq != nil
	case s00.ProtocolIEID(104):
		return v.rowSourceToTargetTransparentContainer != nil
	case s00.ProtocolIEID(107):
		return v.rowUESecurityCapabilities != nil
	case s00.ProtocolIEID(41):
		return v.rowHandoverRestrictionList != nil
	case s00.ProtocolIEID(25):
		return v.rowTraceActivation != nil
	case s00.ProtocolIEID(98):
		return v.rowRequestType != nil
	case s00.ProtocolIEID(124):
		return v.rowSRVCCOperationPossible != nil
	case s00.ProtocolIEID(40):
		return v.rowSecurityContext != nil
	case s00.ProtocolIEID(136):
		return v.rowNASSecurityParameterstoEUTRAN != nil
	case s00.ProtocolIEID(127):
		return v.rowCSGId != nil
	case s00.ProtocolIEID(146):
		return v.rowCSGMembershipStatus != nil
	case s00.ProtocolIEID(75):
		return v.rowGUMMEIID != nil
	case s00.ProtocolIEID(158):
		return v.rowMMEUES1APID2 != nil
	case s00.ProtocolIEID(165):
		return v.rowManagementBasedMDTAllowed != nil
	case s00.ProtocolIEID(177):
		return v.rowManagementBasedMDTPLMNList != nil
	case s00.ProtocolIEID(192):
		return v.rowMaskedIMEISV != nil
	case s00.ProtocolIEID(196):
		return v.rowExpectedUEBehaviour != nil
	case s00.ProtocolIEID(195):
		return v.rowProSeAuthorized != nil
	case s00.ProtocolIEID(241):
		return v.rowUEUserPlaneCIoTSupportIndicator != nil
	case s00.ProtocolIEID(240):
		return v.rowV2XServicesAuthorized != nil
	case s00.ProtocolIEID(248):
		return v.rowUESidelinkAggregateMaximumBitrate != nil
	case s00.ProtocolIEID(251):
		return v.rowEnhancedCoverageRestricted != nil
	case s00.ProtocolIEID(269):
		return v.rowNRUESecurityCapabilities != nil
	case s00.ProtocolIEID(271):
		return v.rowCEModeBRestricted != nil
	case s00.ProtocolIEID(277):
		return v.rowAerialUEsubscriptionInformation != nil
	case s00.ProtocolIEID(283):
		return v.rowPendingDataIndication != nil
	case s00.ProtocolIEID(278):
		return v.rowSubscriptionBasedUEDifferentiationInfo != nil
	case s00.ProtocolIEID(299):
		return v.rowAdditionalRRMPriorityIndex != nil
	case s00.ProtocolIEID(301):
		return v.rowIABAuthorized != nil
	case s00.ProtocolIEID(306):
		return v.rowNRV2XServicesAuthorized != nil
	case s00.ProtocolIEID(307):
		return v.rowNRUESidelinkAggregateMaximumBitrate != nil
	case s00.ProtocolIEID(308):
		return v.rowPC5QoSParameters != nil
	case s00.ProtocolIEID(314):
		return v.rowUERadioCapabilityID != nil
	case s00.ProtocolIEID(355):
		return v.rowTimeRefDistribution != nil
	}
	return false
}
func (v *HandoverRequestIEValue) Opaque() (aper.OpaqueOpenType, bool) {
	if v == nil || !v.isOpaque {
		return aper.OpaqueOpenType{}, false
	}
	return v.opaque, true
}
func (HandoverRequestIEValue) rule() aper.SourceRule {
	return aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "HandoverRequestIEs"}}
}
func (HandoverRequestIEValue) reason(id s00.ProtocolIEID) aper.OpaqueReason {
	switch id {
	case s00.ProtocolIEID(0):
		return aper.UnknownSelector
	case s00.ProtocolIEID(1):
		return aper.UnknownSelector
	case s00.ProtocolIEID(2):
		return aper.UnknownSelector
	case s00.ProtocolIEID(66):
		return aper.UnknownSelector
	case s00.ProtocolIEID(53):
		return aper.UnknownSelector
	case s00.ProtocolIEID(104):
		return aper.UnknownSelector
	case s00.ProtocolIEID(107):
		return aper.UnknownSelector
	case s00.ProtocolIEID(41):
		return aper.UnknownSelector
	case s00.ProtocolIEID(25):
		return aper.UnknownSelector
	case s00.ProtocolIEID(98):
		return aper.UnknownSelector
	case s00.ProtocolIEID(124):
		return aper.UnknownSelector
	case s00.ProtocolIEID(40):
		return aper.UnknownSelector
	case s00.ProtocolIEID(136):
		return aper.UnknownSelector
	case s00.ProtocolIEID(127):
		return aper.UnknownSelector
	case s00.ProtocolIEID(146):
		return aper.UnknownSelector
	case s00.ProtocolIEID(75):
		return aper.UnknownSelector
	case s00.ProtocolIEID(158):
		return aper.UnknownSelector
	case s00.ProtocolIEID(165):
		return aper.UnknownSelector
	case s00.ProtocolIEID(177):
		return aper.UnknownSelector
	case s00.ProtocolIEID(192):
		return aper.UnknownSelector
	case s00.ProtocolIEID(196):
		return aper.UnknownSelector
	case s00.ProtocolIEID(195):
		return aper.UnknownSelector
	case s00.ProtocolIEID(241):
		return aper.UnknownSelector
	case s00.ProtocolIEID(240):
		return aper.UnknownSelector
	case s00.ProtocolIEID(248):
		return aper.UnknownSelector
	case s00.ProtocolIEID(251):
		return aper.UnknownSelector
	case s00.ProtocolIEID(269):
		return aper.UnknownSelector
	case s00.ProtocolIEID(271):
		return aper.UnknownSelector
	case s00.ProtocolIEID(277):
		return aper.UnknownSelector
	case s00.ProtocolIEID(283):
		return aper.UnknownSelector
	case s00.ProtocolIEID(278):
		return aper.UnknownSelector
	case s00.ProtocolIEID(299):
		return aper.UnknownSelector
	case s00.ProtocolIEID(301):
		return aper.UnknownSelector
	case s00.ProtocolIEID(306):
		return aper.UnknownSelector
	case s00.ProtocolIEID(307):
		return aper.UnknownSelector
	case s00.ProtocolIEID(308):
		return aper.UnknownSelector
	case s00.ProtocolIEID(314):
		return aper.UnknownSelector
	case s00.ProtocolIEID(355):
		return aper.UnknownSelector
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
	case s00.ProtocolIEID(99):
		return aper.NotInTable
	case s00.ProtocolIEID(100):
		return aper.NotInTable
	case s00.ProtocolIEID(101):
		return aper.NotInTable
	case s00.ProtocolIEID(102):
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
	case s00.ProtocolIEID(193):
		return aper.NotInTable
	case s00.ProtocolIEID(194):
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
	case s00.ProtocolIEID(249):
		return aper.NotInTable
	case s00.ProtocolIEID(250):
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
	case s00.ProtocolIEID(280):
		return aper.NotInTable
	case s00.ProtocolIEID(281):
		return aper.NotInTable
	case s00.ProtocolIEID(282):
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
	case s00.ProtocolIEID(300):
		return aper.NotInTable
	case s00.ProtocolIEID(302):
		return aper.NotInTable
	case s00.ProtocolIEID(303):
		return aper.NotInTable
	case s00.ProtocolIEID(304):
		return aper.NotInTable
	case s00.ProtocolIEID(305):
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
	case s00.ProtocolIEID(356):
		return aper.NotInTable
	default:
		return aper.UnknownSelector
	}
}
func (v *HandoverRequestIEValue) AsMMEUES1APID() (*s00.MMEUES1APID, bool) {
	if v == nil || v.id != s00.ProtocolIEID(0) || v.rowMMEUES1APID == nil {
		return nil, false
	}
	return v.rowMMEUES1APID, true
}
func (v *HandoverRequestIEValue) AsHandoverType() (*s00.HandoverType, bool) {
	if v == nil || v.id != s00.ProtocolIEID(1) || v.rowHandoverType == nil {
		return nil, false
	}
	return v.rowHandoverType, true
}
func (v *HandoverRequestIEValue) AsCause() (*s14.Cause, bool) {
	if v == nil || v.id != s00.ProtocolIEID(2) || v.rowCause == nil {
		return nil, false
	}
	return v.rowCause, true
}
func (v *HandoverRequestIEValue) AsUEaggregateMaximumBitrate() (*s35.UEAggregateMaximumBitrate, bool) {
	if v == nil || v.id != s00.ProtocolIEID(66) || v.rowUEaggregateMaximumBitrate == nil {
		return nil, false
	}
	return v.rowUEaggregateMaximumBitrate, true
}
func (v *HandoverRequestIEValue) AsERABToBeSetupListHOReq() (*s29.ERABToBeSetupListHOReq, bool) {
	if v == nil || v.id != s00.ProtocolIEID(53) || v.rowERABToBeSetupListHOReq == nil {
		return nil, false
	}
	return v.rowERABToBeSetupListHOReq, true
}
func (v *HandoverRequestIEValue) AsSourceToTargetTransparentContainer() (*s00.SourceToTargetTransparentContainer, bool) {
	if v == nil || v.id != s00.ProtocolIEID(104) || v.rowSourceToTargetTransparentContainer == nil {
		return nil, false
	}
	return v.rowSourceToTargetTransparentContainer, true
}
func (v *HandoverRequestIEValue) AsUESecurityCapabilities() (*s37.UESecurityCapabilities, bool) {
	if v == nil || v.id != s00.ProtocolIEID(107) || v.rowUESecurityCapabilities == nil {
		return nil, false
	}
	return v.rowUESecurityCapabilities, true
}
func (v *HandoverRequestIEValue) AsHandoverRestrictionList() (*s42.HandoverRestrictionList, bool) {
	if v == nil || v.id != s00.ProtocolIEID(41) || v.rowHandoverRestrictionList == nil {
		return nil, false
	}
	return v.rowHandoverRestrictionList, true
}
func (v *HandoverRequestIEValue) AsTraceActivation() (*TraceActivation, bool) {
	if v == nil || v.id != s00.ProtocolIEID(25) || v.rowTraceActivation == nil {
		return nil, false
	}
	return v.rowTraceActivation, true
}
func (v *HandoverRequestIEValue) AsRequestType() (*s26.RequestType, bool) {
	if v == nil || v.id != s00.ProtocolIEID(98) || v.rowRequestType == nil {
		return nil, false
	}
	return v.rowRequestType, true
}
func (v *HandoverRequestIEValue) AsSRVCCOperationPossible() (*s00.SRVCCOperationPossible, bool) {
	if v == nil || v.id != s00.ProtocolIEID(124) || v.rowSRVCCOperationPossible == nil {
		return nil, false
	}
	return v.rowSRVCCOperationPossible, true
}
func (v *HandoverRequestIEValue) AsSecurityContext() (*s28.SecurityContext, bool) {
	if v == nil || v.id != s00.ProtocolIEID(40) || v.rowSecurityContext == nil {
		return nil, false
	}
	return v.rowSecurityContext, true
}
func (v *HandoverRequestIEValue) AsNASSecurityParameterstoEUTRAN() (*s00.NASSecurityParameterstoEUTRAN, bool) {
	if v == nil || v.id != s00.ProtocolIEID(136) || v.rowNASSecurityParameterstoEUTRAN == nil {
		return nil, false
	}
	return v.rowNASSecurityParameterstoEUTRAN, true
}
func (v *HandoverRequestIEValue) AsCSGId() (*s00.CSGId, bool) {
	if v == nil || v.id != s00.ProtocolIEID(127) || v.rowCSGId == nil {
		return nil, false
	}
	return v.rowCSGId, true
}
func (v *HandoverRequestIEValue) AsCSGMembershipStatus() (*s00.CSGMembershipStatus, bool) {
	if v == nil || v.id != s00.ProtocolIEID(146) || v.rowCSGMembershipStatus == nil {
		return nil, false
	}
	return v.rowCSGMembershipStatus, true
}
func (v *HandoverRequestIEValue) AsGUMMEIID() (*s18.GUMMEI, bool) {
	if v == nil || v.id != s00.ProtocolIEID(75) || v.rowGUMMEIID == nil {
		return nil, false
	}
	return v.rowGUMMEIID, true
}
func (v *HandoverRequestIEValue) AsMMEUES1APID2() (*s00.MMEUES1APID, bool) {
	if v == nil || v.id != s00.ProtocolIEID(158) || v.rowMMEUES1APID2 == nil {
		return nil, false
	}
	return v.rowMMEUES1APID2, true
}
func (v *HandoverRequestIEValue) AsManagementBasedMDTAllowed() (*s00.ManagementBasedMDTAllowed, bool) {
	if v == nil || v.id != s00.ProtocolIEID(165) || v.rowManagementBasedMDTAllowed == nil {
		return nil, false
	}
	return v.rowManagementBasedMDTAllowed, true
}
func (v *HandoverRequestIEValue) AsManagementBasedMDTPLMNList() (*s00.MDTPLMNList, bool) {
	if v == nil || v.id != s00.ProtocolIEID(177) || v.rowManagementBasedMDTPLMNList == nil {
		return nil, false
	}
	return v.rowManagementBasedMDTPLMNList, true
}
func (v *HandoverRequestIEValue) AsMaskedIMEISV() (*s00.MaskedIMEISV, bool) {
	if v == nil || v.id != s00.ProtocolIEID(192) || v.rowMaskedIMEISV == nil {
		return nil, false
	}
	return v.rowMaskedIMEISV, true
}
func (v *HandoverRequestIEValue) AsExpectedUEBehaviour() (*s18.ExpectedUEBehaviour, bool) {
	if v == nil || v.id != s00.ProtocolIEID(196) || v.rowExpectedUEBehaviour == nil {
		return nil, false
	}
	return v.rowExpectedUEBehaviour, true
}
func (v *HandoverRequestIEValue) AsProSeAuthorized() (*s20.ProSeAuthorized, bool) {
	if v == nil || v.id != s00.ProtocolIEID(195) || v.rowProSeAuthorized == nil {
		return nil, false
	}
	return v.rowProSeAuthorized, true
}
func (v *HandoverRequestIEValue) AsUEUserPlaneCIoTSupportIndicator() (*s00.UEUserPlaneCIoTSupportIndicator, bool) {
	if v == nil || v.id != s00.ProtocolIEID(241) || v.rowUEUserPlaneCIoTSupportIndicator == nil {
		return nil, false
	}
	return v.rowUEUserPlaneCIoTSupportIndicator, true
}
func (v *HandoverRequestIEValue) AsV2XServicesAuthorized() (*s46.V2XServicesAuthorized, bool) {
	if v == nil || v.id != s00.ProtocolIEID(240) || v.rowV2XServicesAuthorized == nil {
		return nil, false
	}
	return v.rowV2XServicesAuthorized, true
}
func (v *HandoverRequestIEValue) AsUESidelinkAggregateMaximumBitrate() (*s37.UESidelinkAggregateMaximumBitrate, bool) {
	if v == nil || v.id != s00.ProtocolIEID(248) || v.rowUESidelinkAggregateMaximumBitrate == nil {
		return nil, false
	}
	return v.rowUESidelinkAggregateMaximumBitrate, true
}
func (v *HandoverRequestIEValue) AsEnhancedCoverageRestricted() (*s00.EnhancedCoverageRestricted, bool) {
	if v == nil || v.id != s00.ProtocolIEID(251) || v.rowEnhancedCoverageRestricted == nil {
		return nil, false
	}
	return v.rowEnhancedCoverageRestricted, true
}
func (v *HandoverRequestIEValue) AsNRUESecurityCapabilities() (*s19.NRUESecurityCapabilities, bool) {
	if v == nil || v.id != s00.ProtocolIEID(269) || v.rowNRUESecurityCapabilities == nil {
		return nil, false
	}
	return v.rowNRUESecurityCapabilities, true
}
func (v *HandoverRequestIEValue) AsCEModeBRestricted() (*s00.CEModeBRestricted, bool) {
	if v == nil || v.id != s00.ProtocolIEID(271) || v.rowCEModeBRestricted == nil {
		return nil, false
	}
	return v.rowCEModeBRestricted, true
}
func (v *HandoverRequestIEValue) AsAerialUEsubscriptionInformation() (*s00.AerialUEsubscriptionInformation, bool) {
	if v == nil || v.id != s00.ProtocolIEID(277) || v.rowAerialUEsubscriptionInformation == nil {
		return nil, false
	}
	return v.rowAerialUEsubscriptionInformation, true
}
func (v *HandoverRequestIEValue) AsPendingDataIndication() (*s00.PendingDataIndication, bool) {
	if v == nil || v.id != s00.ProtocolIEID(283) || v.rowPendingDataIndication == nil {
		return nil, false
	}
	return v.rowPendingDataIndication, true
}
func (v *HandoverRequestIEValue) AsSubscriptionBasedUEDifferentiationInfo() (*s30.SubscriptionBasedUEDifferentiationInfo, bool) {
	if v == nil || v.id != s00.ProtocolIEID(278) || v.rowSubscriptionBasedUEDifferentiationInfo == nil {
		return nil, false
	}
	return v.rowSubscriptionBasedUEDifferentiationInfo, true
}
func (v *HandoverRequestIEValue) AsAdditionalRRMPriorityIndex() (*s00.AdditionalRRMPriorityIndex, bool) {
	if v == nil || v.id != s00.ProtocolIEID(299) || v.rowAdditionalRRMPriorityIndex == nil {
		return nil, false
	}
	return v.rowAdditionalRRMPriorityIndex, true
}
func (v *HandoverRequestIEValue) AsIABAuthorized() (*s00.IABAuthorized, bool) {
	if v == nil || v.id != s00.ProtocolIEID(301) || v.rowIABAuthorized == nil {
		return nil, false
	}
	return v.rowIABAuthorized, true
}
func (v *HandoverRequestIEValue) AsNRV2XServicesAuthorized() (*s19.NRV2XServicesAuthorized, bool) {
	if v == nil || v.id != s00.ProtocolIEID(306) || v.rowNRV2XServicesAuthorized == nil {
		return nil, false
	}
	return v.rowNRV2XServicesAuthorized, true
}
func (v *HandoverRequestIEValue) AsNRUESidelinkAggregateMaximumBitrate() (*s19.NRUESidelinkAggregateMaximumBitrate, bool) {
	if v == nil || v.id != s00.ProtocolIEID(307) || v.rowNRUESidelinkAggregateMaximumBitrate == nil {
		return nil, false
	}
	return v.rowNRUESidelinkAggregateMaximumBitrate, true
}
func (v *HandoverRequestIEValue) AsPC5QoSParameters() (*s24.PC5QoSParameters, bool) {
	if v == nil || v.id != s00.ProtocolIEID(308) || v.rowPC5QoSParameters == nil {
		return nil, false
	}
	return v.rowPC5QoSParameters, true
}
func (v *HandoverRequestIEValue) AsUERadioCapabilityID() (*s00.UERadioCapabilityID, bool) {
	if v == nil || v.id != s00.ProtocolIEID(314) || v.rowUERadioCapabilityID == nil {
		return nil, false
	}
	return v.rowUERadioCapabilityID, true
}
func (v *HandoverRequestIEValue) AsTimeRefDistribution() (*s00.TimeRefDistribution, bool) {
	if v == nil || v.id != s00.ProtocolIEID(355) || v.rowTimeRefDistribution == nil {
		return nil, false
	}
	return v.rowTimeRefDistribution, true
}
func (v HandoverRequestIEValue) decode(id s00.ProtocolIEID, raw aper.OpaqueOpenType) (HandoverRequestIEValue, error) {
	out := HandoverRequestIEValue{id: id}
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
	case s00.ProtocolIEID(1):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		bb := scope
		decoded, err := aper.DecodeEnumeratedAligned(bb, 5, true, aper.EnumerationSource{KnownExtensions: 2, Path: "HandoverType"})
		value := s00.HandoverType(decoded)
		if err != nil {
			return out, fmt.Errorf("%s %w", "HandoverType:", err)
		}
		if _, err := aper.CompleteOpenTypeValue(bb, value); err != nil {
			return out, err
		}
		out.rowHandoverType = &value
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
	case s00.ProtocolIEID(53):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		child := scope
		list, err := s40.BridgeUnmarshalAPERERABToBeSetupListHOReqFrom(child)
		if err != nil {
			return out, fmt.Errorf("%s %w", "ERABToBeSetupListHOReq:", err)
		}
		padding, err := aper.CaptureOpenTypePadding(child)
		if err != nil {
			return out, err
		}
		_ = padding
		value := list
		out.rowERABToBeSetupListHOReq = &value
		raw.RetainContents(&out.received)
	case s00.ProtocolIEID(104):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		child := scope
		value, err := (func(bb *aper.BitBuffer) (s00.SourceToTargetTransparentContainer, error) {
			var v struct {
				Value s00.SourceToTargetTransparentContainer
			}
			err := func() error {
				val_value, err := aper.DecodeOctetStringAligned(bb, 0, 0, false)
				if err != nil {
					return runtime.WrapDecodePath(err, "Value")
				}
				v.Value = s00.SourceToTargetTransparentContainer(val_value)
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
		out.rowSourceToTargetTransparentContainer = &value
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
	case s00.ProtocolIEID(41):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		var value s42.HandoverRestrictionList
		child := scope
		if err := s42.BridgeHandoverRestrictionListMethodUnmarshalAPERFrom(&value, child); err != nil {
			return out, fmt.Errorf("%s %w", "HandoverRestrictionList:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "HandoverRestrictionList")
		if err != nil {
			return out, err
		}
		*s42.BridgeHandoverRestrictionListFieldPerPadding(&value) = padding
		*s42.BridgeHandoverRestrictionListFieldReceived(&value) = true
		raw.RetainContents(s42.BridgeHandoverRestrictionListFieldReceivedBytes(&value))
		*s42.BridgeHandoverRestrictionListFieldReceivedLocation(&value) = raw.ContentLocation()
		out.rowHandoverRestrictionList = &value
		raw.RetainContents(&out.received)
	case s00.ProtocolIEID(25):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		var value TraceActivation
		child := scope
		if err := value.unmarshalAPERFrom(child); err != nil {
			return out, fmt.Errorf("%s %w", "TraceActivation:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "TraceActivation")
		if err != nil {
			return out, err
		}
		value.perPadding = padding
		value.received = true
		raw.RetainContents(&value.receivedBytes)
		value.receivedLocation = raw.ContentLocation()
		out.rowTraceActivation = &value
		raw.RetainContents(&out.received)
	case s00.ProtocolIEID(98):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		var value s26.RequestType
		child := scope
		if err := s26.BridgeRequestTypeMethodUnmarshalAPERFrom(&value, child); err != nil {
			return out, fmt.Errorf("%s %w", "RequestType:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "RequestType")
		if err != nil {
			return out, err
		}
		*s26.BridgeRequestTypeFieldPerPadding(&value) = padding
		*s26.BridgeRequestTypeFieldReceived(&value) = true
		raw.RetainContents(s26.BridgeRequestTypeFieldReceivedBytes(&value))
		*s26.BridgeRequestTypeFieldReceivedLocation(&value) = raw.ContentLocation()
		out.rowRequestType = &value
		raw.RetainContents(&out.received)
	case s00.ProtocolIEID(124):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		bb := scope
		decoded, err := aper.DecodeEnumeratedAligned(bb, 1, true, aper.EnumerationSource{KnownExtensions: 0, Path: "SRVCCOperationPossible"})
		value := s00.SRVCCOperationPossible(decoded)
		if err != nil {
			return out, fmt.Errorf("%s %w", "SRVCCOperationPossible:", err)
		}
		if _, err := aper.CompleteOpenTypeValue(bb, value); err != nil {
			return out, err
		}
		out.rowSRVCCOperationPossible = &value
		raw.RetainContents(&out.received)
	case s00.ProtocolIEID(40):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		var value s28.SecurityContext
		child := scope
		if err := s28.BridgeSecurityContextMethodUnmarshalAPERFrom(&value, child); err != nil {
			return out, fmt.Errorf("%s %w", "SecurityContext:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "SecurityContext")
		if err != nil {
			return out, err
		}
		*s28.BridgeSecurityContextFieldPerPadding(&value) = padding
		*s28.BridgeSecurityContextFieldReceived(&value) = true
		raw.RetainContents(s28.BridgeSecurityContextFieldReceivedBytes(&value))
		*s28.BridgeSecurityContextFieldReceivedLocation(&value) = raw.ContentLocation()
		out.rowSecurityContext = &value
		raw.RetainContents(&out.received)
	case s00.ProtocolIEID(136):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		child := scope
		value, err := (func(bb *aper.BitBuffer) (s00.NASSecurityParameterstoEUTRAN, error) {
			var v struct {
				Value s00.NASSecurityParameterstoEUTRAN
			}
			err := func() error {
				val_value, err := aper.DecodeOctetStringAligned(bb, 0, 0, false)
				if err != nil {
					return runtime.WrapDecodePath(err, "Value")
				}
				v.Value = s00.NASSecurityParameterstoEUTRAN(val_value)
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
		out.rowNASSecurityParameterstoEUTRAN = &value
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
	case s00.ProtocolIEID(75):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		var value s18.GUMMEI
		child := scope
		if err := s18.BridgeGUMMEIMethodUnmarshalAPERFrom(&value, child); err != nil {
			return out, fmt.Errorf("%s %w", "GUMMEIID:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "GUMMEI")
		if err != nil {
			return out, err
		}
		*s18.BridgeGUMMEIFieldPerPadding(&value) = padding
		*s18.BridgeGUMMEIFieldReceived(&value) = true
		raw.RetainContents(s18.BridgeGUMMEIFieldReceivedBytes(&value))
		*s18.BridgeGUMMEIFieldReceivedLocation(&value) = raw.ContentLocation()
		out.rowGUMMEIID = &value
		raw.RetainContents(&out.received)
	case s00.ProtocolIEID(158):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		bb := scope
		decoded, err := aper.DecodeIntegerAligned(bb, s07.BridgeInt64Ptr(0), s07.BridgeInt64Ptr(4294967295), false)
		value := s00.MMEUES1APID(decoded)
		if err != nil {
			return out, fmt.Errorf("%s %w", "MMEUES1APID2:", err)
		}
		if _, err := aper.CompleteOpenTypeValue(bb, value); err != nil {
			return out, err
		}
		out.rowMMEUES1APID2 = &value
		raw.RetainContents(&out.received)
	case s00.ProtocolIEID(165):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		bb := scope
		decoded, err := aper.DecodeEnumeratedAligned(bb, 1, true, aper.EnumerationSource{KnownExtensions: 0, Path: "ManagementBasedMDTAllowed"})
		value := s00.ManagementBasedMDTAllowed(decoded)
		if err != nil {
			return out, fmt.Errorf("%s %w", "ManagementBasedMDTAllowed:", err)
		}
		if _, err := aper.CompleteOpenTypeValue(bb, value); err != nil {
			return out, err
		}
		out.rowManagementBasedMDTAllowed = &value
		raw.RetainContents(&out.received)
	case s00.ProtocolIEID(177):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		child := scope
		list, err := s41.BridgeUnmarshalAPERMDTPLMNListFrom(child)
		if err != nil {
			return out, fmt.Errorf("%s %w", "ManagementBasedMDTPLMNList:", err)
		}
		padding, err := aper.CaptureOpenTypePadding(child)
		if err != nil {
			return out, err
		}
		_ = padding
		value := list
		out.rowManagementBasedMDTPLMNList = &value
		raw.RetainContents(&out.received)
	case s00.ProtocolIEID(192):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		child := scope
		value, err := (func(bb *aper.BitBuffer) (s00.MaskedIMEISV, error) {
			var v struct{ Value s00.MaskedIMEISV }
			err := func() error {
				bsBytes_value, bsBitLen_value, err := aper.DecodeBitStringAligned(bb, 64, 64, true)
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
		out.rowMaskedIMEISV = &value
		raw.RetainContents(&out.received)
	case s00.ProtocolIEID(196):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		var value s18.ExpectedUEBehaviour
		child := scope
		if err := s18.BridgeExpectedUEBehaviourMethodUnmarshalAPERFrom(&value, child); err != nil {
			return out, fmt.Errorf("%s %w", "ExpectedUEBehaviour:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "ExpectedUEBehaviour")
		if err != nil {
			return out, err
		}
		*s18.BridgeExpectedUEBehaviourFieldPerPadding(&value) = padding
		*s18.BridgeExpectedUEBehaviourFieldReceived(&value) = true
		raw.RetainContents(s18.BridgeExpectedUEBehaviourFieldReceivedBytes(&value))
		*s18.BridgeExpectedUEBehaviourFieldReceivedLocation(&value) = raw.ContentLocation()
		out.rowExpectedUEBehaviour = &value
		raw.RetainContents(&out.received)
	case s00.ProtocolIEID(195):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		var value s20.ProSeAuthorized
		child := scope
		if err := s20.BridgeProSeAuthorizedMethodUnmarshalAPERFrom(&value, child); err != nil {
			return out, fmt.Errorf("%s %w", "ProSeAuthorized:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "ProSeAuthorized")
		if err != nil {
			return out, err
		}
		*s20.BridgeProSeAuthorizedFieldPerPadding(&value) = padding
		*s20.BridgeProSeAuthorizedFieldReceived(&value) = true
		raw.RetainContents(s20.BridgeProSeAuthorizedFieldReceivedBytes(&value))
		*s20.BridgeProSeAuthorizedFieldReceivedLocation(&value) = raw.ContentLocation()
		out.rowProSeAuthorized = &value
		raw.RetainContents(&out.received)
	case s00.ProtocolIEID(241):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		bb := scope
		decoded, err := aper.DecodeEnumeratedAligned(bb, 1, true, aper.EnumerationSource{KnownExtensions: 0, Path: "UEUserPlaneCIoTSupportIndicator"})
		value := s00.UEUserPlaneCIoTSupportIndicator(decoded)
		if err != nil {
			return out, fmt.Errorf("%s %w", "UEUserPlaneCIoTSupportIndicator:", err)
		}
		if _, err := aper.CompleteOpenTypeValue(bb, value); err != nil {
			return out, err
		}
		out.rowUEUserPlaneCIoTSupportIndicator = &value
		raw.RetainContents(&out.received)
	case s00.ProtocolIEID(240):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		var value s46.V2XServicesAuthorized
		child := scope
		if err := s46.BridgeV2XServicesAuthorizedMethodUnmarshalAPERFrom(&value, child); err != nil {
			return out, fmt.Errorf("%s %w", "V2XServicesAuthorized:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "V2XServicesAuthorized")
		if err != nil {
			return out, err
		}
		*s46.BridgeV2XServicesAuthorizedFieldPerPadding(&value) = padding
		*s46.BridgeV2XServicesAuthorizedFieldReceived(&value) = true
		raw.RetainContents(s46.BridgeV2XServicesAuthorizedFieldReceivedBytes(&value))
		*s46.BridgeV2XServicesAuthorizedFieldReceivedLocation(&value) = raw.ContentLocation()
		out.rowV2XServicesAuthorized = &value
		raw.RetainContents(&out.received)
	case s00.ProtocolIEID(248):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		var value s37.UESidelinkAggregateMaximumBitrate
		child := scope
		if err := s37.BridgeUESidelinkAggregateMaximumBitrateMethodUnmarshalAPERFrom(&value, child); err != nil {
			return out, fmt.Errorf("%s %w", "UESidelinkAggregateMaximumBitrate:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "UESidelinkAggregateMaximumBitrate")
		if err != nil {
			return out, err
		}
		*s37.BridgeUESidelinkAggregateMaximumBitrateFieldPerPadding(&value) = padding
		*s37.BridgeUESidelinkAggregateMaximumBitrateFieldReceived(&value) = true
		raw.RetainContents(s37.BridgeUESidelinkAggregateMaximumBitrateFieldReceivedBytes(&value))
		*s37.BridgeUESidelinkAggregateMaximumBitrateFieldReceivedLocation(&value) = raw.ContentLocation()
		out.rowUESidelinkAggregateMaximumBitrate = &value
		raw.RetainContents(&out.received)
	case s00.ProtocolIEID(251):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		bb := scope
		decoded, err := aper.DecodeEnumeratedAligned(bb, 1, true, aper.EnumerationSource{KnownExtensions: 0, Path: "EnhancedCoverageRestricted"})
		value := s00.EnhancedCoverageRestricted(decoded)
		if err != nil {
			return out, fmt.Errorf("%s %w", "EnhancedCoverageRestricted:", err)
		}
		if _, err := aper.CompleteOpenTypeValue(bb, value); err != nil {
			return out, err
		}
		out.rowEnhancedCoverageRestricted = &value
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
	case s00.ProtocolIEID(271):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		bb := scope
		decoded, err := aper.DecodeEnumeratedAligned(bb, 2, true, aper.EnumerationSource{KnownExtensions: 0, Path: "CEModeBRestricted"})
		value := s00.CEModeBRestricted(decoded)
		if err != nil {
			return out, fmt.Errorf("%s %w", "CEModeBRestricted:", err)
		}
		if _, err := aper.CompleteOpenTypeValue(bb, value); err != nil {
			return out, err
		}
		out.rowCEModeBRestricted = &value
		raw.RetainContents(&out.received)
	case s00.ProtocolIEID(277):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		bb := scope
		decoded, err := aper.DecodeEnumeratedAligned(bb, 2, true, aper.EnumerationSource{KnownExtensions: 0, Path: "AerialUEsubscriptionInformation"})
		value := s00.AerialUEsubscriptionInformation(decoded)
		if err != nil {
			return out, fmt.Errorf("%s %w", "AerialUEsubscriptionInformation:", err)
		}
		if _, err := aper.CompleteOpenTypeValue(bb, value); err != nil {
			return out, err
		}
		out.rowAerialUEsubscriptionInformation = &value
		raw.RetainContents(&out.received)
	case s00.ProtocolIEID(283):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		bb := scope
		decoded, err := aper.DecodeEnumeratedAligned(bb, 1, true, aper.EnumerationSource{KnownExtensions: 0, Path: "PendingDataIndication"})
		value := s00.PendingDataIndication(decoded)
		if err != nil {
			return out, fmt.Errorf("%s %w", "PendingDataIndication:", err)
		}
		if _, err := aper.CompleteOpenTypeValue(bb, value); err != nil {
			return out, err
		}
		out.rowPendingDataIndication = &value
		raw.RetainContents(&out.received)
	case s00.ProtocolIEID(278):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		var value s30.SubscriptionBasedUEDifferentiationInfo
		child := scope
		if err := s30.BridgeSubscriptionBasedUEDifferentiationInfoMethodUnmarshalAPERFrom(&value, child); err != nil {
			return out, fmt.Errorf("%s %w", "SubscriptionBasedUEDifferentiationInfo:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "SubscriptionBasedUEDifferentiationInfo")
		if err != nil {
			return out, err
		}
		*s30.BridgeSubscriptionBasedUEDifferentiationInfoFieldPerPadding(&value) = padding
		*s30.BridgeSubscriptionBasedUEDifferentiationInfoFieldReceived(&value) = true
		raw.RetainContents(s30.BridgeSubscriptionBasedUEDifferentiationInfoFieldReceivedBytes(&value))
		*s30.BridgeSubscriptionBasedUEDifferentiationInfoFieldReceivedLocation(&value) = raw.ContentLocation()
		out.rowSubscriptionBasedUEDifferentiationInfo = &value
		raw.RetainContents(&out.received)
	case s00.ProtocolIEID(299):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		child := scope
		value, err := (func(bb *aper.BitBuffer) (s00.AdditionalRRMPriorityIndex, error) {
			var v struct {
				Value s00.AdditionalRRMPriorityIndex
			}
			err := func() error {
				bsBytes_value, bsBitLen_value, err := aper.DecodeBitStringAligned(bb, 32, 32, true)
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
		out.rowAdditionalRRMPriorityIndex = &value
		raw.RetainContents(&out.received)
	case s00.ProtocolIEID(301):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		bb := scope
		decoded, err := aper.DecodeEnumeratedAligned(bb, 2, true, aper.EnumerationSource{KnownExtensions: 0, Path: "IABAuthorized"})
		value := s00.IABAuthorized(decoded)
		if err != nil {
			return out, fmt.Errorf("%s %w", "IABAuthorized:", err)
		}
		if _, err := aper.CompleteOpenTypeValue(bb, value); err != nil {
			return out, err
		}
		out.rowIABAuthorized = &value
		raw.RetainContents(&out.received)
	case s00.ProtocolIEID(306):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		var value s19.NRV2XServicesAuthorized
		child := scope
		if err := s19.BridgeNRV2XServicesAuthorizedMethodUnmarshalAPERFrom(&value, child); err != nil {
			return out, fmt.Errorf("%s %w", "NRV2XServicesAuthorized:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "NRV2XServicesAuthorized")
		if err != nil {
			return out, err
		}
		*s19.BridgeNRV2XServicesAuthorizedFieldPerPadding(&value) = padding
		*s19.BridgeNRV2XServicesAuthorizedFieldReceived(&value) = true
		raw.RetainContents(s19.BridgeNRV2XServicesAuthorizedFieldReceivedBytes(&value))
		*s19.BridgeNRV2XServicesAuthorizedFieldReceivedLocation(&value) = raw.ContentLocation()
		out.rowNRV2XServicesAuthorized = &value
		raw.RetainContents(&out.received)
	case s00.ProtocolIEID(307):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		var value s19.NRUESidelinkAggregateMaximumBitrate
		child := scope
		if err := s19.BridgeNRUESidelinkAggregateMaximumBitrateMethodUnmarshalAPERFrom(&value, child); err != nil {
			return out, fmt.Errorf("%s %w", "NRUESidelinkAggregateMaximumBitrate:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "NRUESidelinkAggregateMaximumBitrate")
		if err != nil {
			return out, err
		}
		*s19.BridgeNRUESidelinkAggregateMaximumBitrateFieldPerPadding(&value) = padding
		*s19.BridgeNRUESidelinkAggregateMaximumBitrateFieldReceived(&value) = true
		raw.RetainContents(s19.BridgeNRUESidelinkAggregateMaximumBitrateFieldReceivedBytes(&value))
		*s19.BridgeNRUESidelinkAggregateMaximumBitrateFieldReceivedLocation(&value) = raw.ContentLocation()
		out.rowNRUESidelinkAggregateMaximumBitrate = &value
		raw.RetainContents(&out.received)
	case s00.ProtocolIEID(308):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		var value s24.PC5QoSParameters
		child := scope
		if err := s24.BridgePC5QoSParametersMethodUnmarshalAPERFrom(&value, child); err != nil {
			return out, fmt.Errorf("%s %w", "PC5QoSParameters:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "PC5QoSParameters")
		if err != nil {
			return out, err
		}
		*s24.BridgePC5QoSParametersFieldPerPadding(&value) = padding
		*s24.BridgePC5QoSParametersFieldReceived(&value) = true
		raw.RetainContents(s24.BridgePC5QoSParametersFieldReceivedBytes(&value))
		*s24.BridgePC5QoSParametersFieldReceivedLocation(&value) = raw.ContentLocation()
		out.rowPC5QoSParameters = &value
		raw.RetainContents(&out.received)
	case s00.ProtocolIEID(314):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		child := scope
		value, err := (func(bb *aper.BitBuffer) (s00.UERadioCapabilityID, error) {
			var v struct{ Value s00.UERadioCapabilityID }
			err := func() error {
				val_value, err := aper.DecodeOctetStringAligned(bb, 0, 0, false)
				if err != nil {
					return runtime.WrapDecodePath(err, "Value")
				}
				v.Value = s00.UERadioCapabilityID(val_value)
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
		out.rowUERadioCapabilityID = &value
		raw.RetainContents(&out.received)
	case s00.ProtocolIEID(355):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		bb := scope
		decoded, err := aper.DecodeEnumeratedAligned(bb, 1, true, aper.EnumerationSource{KnownExtensions: 0, Path: "TimeRefDistribution"})
		value := s00.TimeRefDistribution(decoded)
		if err != nil {
			return out, fmt.Errorf("%s %w", "TimeRefDistribution:", err)
		}
		if _, err := aper.CompleteOpenTypeValue(bb, value); err != nil {
			return out, err
		}
		out.rowTimeRefDistribution = &value
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
func (v HandoverRequestIEValue) encode() ([]byte, error) { return v.encodeFresh(false, nil) }
func (v HandoverRequestIEValue) encodeFresh(fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
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
			return nil, fmt.Errorf("%s missing value", "HandoverRequestIEs.id-MME-UE-S1AP-ID:")
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
	case s00.ProtocolIEID(1):
		if v.rowHandoverType == nil {
			return nil, fmt.Errorf("%s missing value", "HandoverRequestIEs.id-HandoverType:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		encodeBB := aper.NewBudgetBuffer(budget)
		if err := aper.EncodeEnumeratedAligned(encodeBB, int64(*v.rowHandoverType), 5, true); err != nil {
			return nil, err
		}
		candidate := encodeBB.CompleteBytes()
		return candidate, nil
	case s00.ProtocolIEID(2):
		if v.rowCause == nil {
			return nil, fmt.Errorf("%s missing value", "HandoverRequestIEs.id-Cause:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		candidate, err := s14.BridgeCauseMethodMarshalAPERBudget(v.rowCause, budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	case s00.ProtocolIEID(66):
		if v.rowUEaggregateMaximumBitrate == nil {
			return nil, fmt.Errorf("%s missing value", "HandoverRequestIEs.id-uEaggregateMaximumBitrate:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		candidate, err := s35.BridgeUEAggregateMaximumBitrateMethodMarshalAPERBudget(v.rowUEaggregateMaximumBitrate, budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	case s00.ProtocolIEID(53):
		if v.rowERABToBeSetupListHOReq == nil {
			return nil, fmt.Errorf("%s missing value", "HandoverRequestIEs.id-E-RABToBeSetupListHOReq:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		complete := s40.ERABToBeSetupListHOReqComplete{Value: *v.rowERABToBeSetupListHOReq}
		candidate, err := s40.BridgeERABToBeSetupListHOReqCompleteMethodMarshalAPERBudget(&complete, budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	case s00.ProtocolIEID(104):
		if v.rowSourceToTargetTransparentContainer == nil {
			return nil, fmt.Errorf("%s missing value", "HandoverRequestIEs.id-Source-ToTarget-TransparentContainer:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		candidate, err := (func(value s00.SourceToTargetTransparentContainer, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			v := struct {
				Value s00.SourceToTargetTransparentContainer
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
		})(*v.rowSourceToTargetTransparentContainer, budget)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	case s00.ProtocolIEID(107):
		if v.rowUESecurityCapabilities == nil {
			return nil, fmt.Errorf("%s missing value", "HandoverRequestIEs.id-UESecurityCapabilities:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		candidate, err := s37.BridgeUESecurityCapabilitiesMethodMarshalAPERBudget(v.rowUESecurityCapabilities, budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	case s00.ProtocolIEID(41):
		if v.rowHandoverRestrictionList == nil {
			return nil, fmt.Errorf("%s missing value", "HandoverRequestIEs.id-HandoverRestrictionList:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		candidate, err := s42.BridgeHandoverRestrictionListMethodMarshalAPERBudget(v.rowHandoverRestrictionList, budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	case s00.ProtocolIEID(25):
		if v.rowTraceActivation == nil {
			return nil, fmt.Errorf("%s missing value", "HandoverRequestIEs.id-TraceActivation:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		candidate, err := v.rowTraceActivation.marshalAPERBudget(budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	case s00.ProtocolIEID(98):
		if v.rowRequestType == nil {
			return nil, fmt.Errorf("%s missing value", "HandoverRequestIEs.id-RequestType:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		candidate, err := s26.BridgeRequestTypeMethodMarshalAPERBudget(v.rowRequestType, budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	case s00.ProtocolIEID(124):
		if v.rowSRVCCOperationPossible == nil {
			return nil, fmt.Errorf("%s missing value", "HandoverRequestIEs.id-SRVCCOperationPossible:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		encodeBB := aper.NewBudgetBuffer(budget)
		if err := aper.EncodeEnumeratedAligned(encodeBB, int64(*v.rowSRVCCOperationPossible), 1, true); err != nil {
			return nil, err
		}
		candidate := encodeBB.CompleteBytes()
		return candidate, nil
	case s00.ProtocolIEID(40):
		if v.rowSecurityContext == nil {
			return nil, fmt.Errorf("%s missing value", "HandoverRequestIEs.id-SecurityContext:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		candidate, err := s28.BridgeSecurityContextMethodMarshalAPERBudget(v.rowSecurityContext, budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	case s00.ProtocolIEID(136):
		if v.rowNASSecurityParameterstoEUTRAN == nil {
			return nil, fmt.Errorf("%s missing value", "HandoverRequestIEs.id-NASSecurityParameterstoE-UTRAN:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		candidate, err := (func(value s00.NASSecurityParameterstoEUTRAN, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			v := struct {
				Value s00.NASSecurityParameterstoEUTRAN
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
		})(*v.rowNASSecurityParameterstoEUTRAN, budget)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	case s00.ProtocolIEID(127):
		if v.rowCSGId == nil {
			return nil, fmt.Errorf("%s missing value", "HandoverRequestIEs.id-CSG-Id:")
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
	case s00.ProtocolIEID(146):
		if v.rowCSGMembershipStatus == nil {
			return nil, fmt.Errorf("%s missing value", "HandoverRequestIEs.id-CSGMembershipStatus:")
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
	case s00.ProtocolIEID(75):
		if v.rowGUMMEIID == nil {
			return nil, fmt.Errorf("%s missing value", "HandoverRequestIEs.id-GUMMEI-ID:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		candidate, err := s18.BridgeGUMMEIMethodMarshalAPERBudget(v.rowGUMMEIID, budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	case s00.ProtocolIEID(158):
		if v.rowMMEUES1APID2 == nil {
			return nil, fmt.Errorf("%s missing value", "HandoverRequestIEs.id-MME-UE-S1AP-ID-2:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		encodeBB := aper.NewBudgetBuffer(budget)
		if err := aper.EncodeIntegerAligned(encodeBB, int64(*v.rowMMEUES1APID2), s07.BridgeInt64Ptr(0), s07.BridgeInt64Ptr(4294967295), false); err != nil {
			return nil, err
		}
		candidate := encodeBB.CompleteBytes()
		return candidate, nil
	case s00.ProtocolIEID(165):
		if v.rowManagementBasedMDTAllowed == nil {
			return nil, fmt.Errorf("%s missing value", "HandoverRequestIEs.id-ManagementBasedMDTAllowed:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		encodeBB := aper.NewBudgetBuffer(budget)
		if err := aper.EncodeEnumeratedAligned(encodeBB, int64(*v.rowManagementBasedMDTAllowed), 1, true); err != nil {
			return nil, err
		}
		candidate := encodeBB.CompleteBytes()
		return candidate, nil
	case s00.ProtocolIEID(177):
		if v.rowManagementBasedMDTPLMNList == nil {
			return nil, fmt.Errorf("%s missing value", "HandoverRequestIEs.id-ManagementBasedMDTPLMNList:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		complete := s41.MDTPLMNListComplete{Value: *v.rowManagementBasedMDTPLMNList}
		candidate, err := s41.BridgeMDTPLMNListCompleteMethodMarshalAPERBudget(&complete, budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	case s00.ProtocolIEID(192):
		if v.rowMaskedIMEISV == nil {
			return nil, fmt.Errorf("%s missing value", "HandoverRequestIEs.id-Masked-IMEISV:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		candidate, err := (func(value s00.MaskedIMEISV, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			v := struct{ Value s00.MaskedIMEISV }{Value: value}
			_ = v
			err := func() error {
				if err := aper.EncodeBitStringAligned(bb, v.Value.Bytes, v.Value.BitLength, 64, 64, true); err != nil {
					return fmt.Errorf("encoding value: %w", err)
				}
				return nil
			}()
			if err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		})(*v.rowMaskedIMEISV, budget)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	case s00.ProtocolIEID(196):
		if v.rowExpectedUEBehaviour == nil {
			return nil, fmt.Errorf("%s missing value", "HandoverRequestIEs.id-ExpectedUEBehaviour:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		candidate, err := s18.BridgeExpectedUEBehaviourMethodMarshalAPERBudget(v.rowExpectedUEBehaviour, budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	case s00.ProtocolIEID(195):
		if v.rowProSeAuthorized == nil {
			return nil, fmt.Errorf("%s missing value", "HandoverRequestIEs.id-ProSeAuthorized:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		candidate, err := s20.BridgeProSeAuthorizedMethodMarshalAPERBudget(v.rowProSeAuthorized, budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	case s00.ProtocolIEID(241):
		if v.rowUEUserPlaneCIoTSupportIndicator == nil {
			return nil, fmt.Errorf("%s missing value", "HandoverRequestIEs.id-UEUserPlaneCIoTSupportIndicator:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		encodeBB := aper.NewBudgetBuffer(budget)
		if err := aper.EncodeEnumeratedAligned(encodeBB, int64(*v.rowUEUserPlaneCIoTSupportIndicator), 1, true); err != nil {
			return nil, err
		}
		candidate := encodeBB.CompleteBytes()
		return candidate, nil
	case s00.ProtocolIEID(240):
		if v.rowV2XServicesAuthorized == nil {
			return nil, fmt.Errorf("%s missing value", "HandoverRequestIEs.id-V2XServicesAuthorized:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		candidate, err := s46.BridgeV2XServicesAuthorizedMethodMarshalAPERBudget(v.rowV2XServicesAuthorized, budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	case s00.ProtocolIEID(248):
		if v.rowUESidelinkAggregateMaximumBitrate == nil {
			return nil, fmt.Errorf("%s missing value", "HandoverRequestIEs.id-UESidelinkAggregateMaximumBitrate:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		candidate, err := s37.BridgeUESidelinkAggregateMaximumBitrateMethodMarshalAPERBudget(v.rowUESidelinkAggregateMaximumBitrate, budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	case s00.ProtocolIEID(251):
		if v.rowEnhancedCoverageRestricted == nil {
			return nil, fmt.Errorf("%s missing value", "HandoverRequestIEs.id-EnhancedCoverageRestricted:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		encodeBB := aper.NewBudgetBuffer(budget)
		if err := aper.EncodeEnumeratedAligned(encodeBB, int64(*v.rowEnhancedCoverageRestricted), 1, true); err != nil {
			return nil, err
		}
		candidate := encodeBB.CompleteBytes()
		return candidate, nil
	case s00.ProtocolIEID(269):
		if v.rowNRUESecurityCapabilities == nil {
			return nil, fmt.Errorf("%s missing value", "HandoverRequestIEs.id-NRUESecurityCapabilities:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		candidate, err := s19.BridgeNRUESecurityCapabilitiesMethodMarshalAPERBudget(v.rowNRUESecurityCapabilities, budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	case s00.ProtocolIEID(271):
		if v.rowCEModeBRestricted == nil {
			return nil, fmt.Errorf("%s missing value", "HandoverRequestIEs.id-CE-ModeBRestricted:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		encodeBB := aper.NewBudgetBuffer(budget)
		if err := aper.EncodeEnumeratedAligned(encodeBB, int64(*v.rowCEModeBRestricted), 2, true); err != nil {
			return nil, err
		}
		candidate := encodeBB.CompleteBytes()
		return candidate, nil
	case s00.ProtocolIEID(277):
		if v.rowAerialUEsubscriptionInformation == nil {
			return nil, fmt.Errorf("%s missing value", "HandoverRequestIEs.id-AerialUEsubscriptionInformation:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		encodeBB := aper.NewBudgetBuffer(budget)
		if err := aper.EncodeEnumeratedAligned(encodeBB, int64(*v.rowAerialUEsubscriptionInformation), 2, true); err != nil {
			return nil, err
		}
		candidate := encodeBB.CompleteBytes()
		return candidate, nil
	case s00.ProtocolIEID(283):
		if v.rowPendingDataIndication == nil {
			return nil, fmt.Errorf("%s missing value", "HandoverRequestIEs.id-PendingDataIndication:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		encodeBB := aper.NewBudgetBuffer(budget)
		if err := aper.EncodeEnumeratedAligned(encodeBB, int64(*v.rowPendingDataIndication), 1, true); err != nil {
			return nil, err
		}
		candidate := encodeBB.CompleteBytes()
		return candidate, nil
	case s00.ProtocolIEID(278):
		if v.rowSubscriptionBasedUEDifferentiationInfo == nil {
			return nil, fmt.Errorf("%s missing value", "HandoverRequestIEs.id-Subscription-Based-UE-DifferentiationInfo:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		candidate, err := s30.BridgeSubscriptionBasedUEDifferentiationInfoMethodMarshalAPERBudget(v.rowSubscriptionBasedUEDifferentiationInfo, budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	case s00.ProtocolIEID(299):
		if v.rowAdditionalRRMPriorityIndex == nil {
			return nil, fmt.Errorf("%s missing value", "HandoverRequestIEs.id-AdditionalRRMPriorityIndex:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		candidate, err := (func(value s00.AdditionalRRMPriorityIndex, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			v := struct {
				Value s00.AdditionalRRMPriorityIndex
			}{Value: value}
			_ = v
			err := func() error {
				if err := aper.EncodeBitStringAligned(bb, v.Value.Bytes, v.Value.BitLength, 32, 32, true); err != nil {
					return fmt.Errorf("encoding value: %w", err)
				}
				return nil
			}()
			if err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		})(*v.rowAdditionalRRMPriorityIndex, budget)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	case s00.ProtocolIEID(301):
		if v.rowIABAuthorized == nil {
			return nil, fmt.Errorf("%s missing value", "HandoverRequestIEs.id-IAB-Authorized:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		encodeBB := aper.NewBudgetBuffer(budget)
		if err := aper.EncodeEnumeratedAligned(encodeBB, int64(*v.rowIABAuthorized), 2, true); err != nil {
			return nil, err
		}
		candidate := encodeBB.CompleteBytes()
		return candidate, nil
	case s00.ProtocolIEID(306):
		if v.rowNRV2XServicesAuthorized == nil {
			return nil, fmt.Errorf("%s missing value", "HandoverRequestIEs.id-NRV2XServicesAuthorized:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		candidate, err := s19.BridgeNRV2XServicesAuthorizedMethodMarshalAPERBudget(v.rowNRV2XServicesAuthorized, budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	case s00.ProtocolIEID(307):
		if v.rowNRUESidelinkAggregateMaximumBitrate == nil {
			return nil, fmt.Errorf("%s missing value", "HandoverRequestIEs.id-NRUESidelinkAggregateMaximumBitrate:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		candidate, err := s19.BridgeNRUESidelinkAggregateMaximumBitrateMethodMarshalAPERBudget(v.rowNRUESidelinkAggregateMaximumBitrate, budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	case s00.ProtocolIEID(308):
		if v.rowPC5QoSParameters == nil {
			return nil, fmt.Errorf("%s missing value", "HandoverRequestIEs.id-PC5QoSParameters:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		candidate, err := s24.BridgePC5QoSParametersMethodMarshalAPERBudget(v.rowPC5QoSParameters, budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	case s00.ProtocolIEID(314):
		if v.rowUERadioCapabilityID == nil {
			return nil, fmt.Errorf("%s missing value", "HandoverRequestIEs.id-UERadioCapabilityID:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		candidate, err := (func(value s00.UERadioCapabilityID, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			v := struct{ Value s00.UERadioCapabilityID }{Value: value}
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
		})(*v.rowUERadioCapabilityID, budget)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	case s00.ProtocolIEID(355):
		if v.rowTimeRefDistribution == nil {
			return nil, fmt.Errorf("%s missing value", "HandoverRequestIEs.id-TimeRefDistribution:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		encodeBB := aper.NewBudgetBuffer(budget)
		if err := aper.EncodeEnumeratedAligned(encodeBB, int64(*v.rowTimeRefDistribution), 1, true); err != nil {
			return nil, err
		}
		candidate := encodeBB.CompleteBytes()
		return candidate, nil
	default:
		return nil, fmt.Errorf("%s id %d has no value", "HandoverRequestIEValue:", v.id)
	}
}

type ImmediateMDTExtIETable struct{}

func ImmediateMDTExtIEs() ImmediateMDTExtIETable { return ImmediateMDTExtIETable{} }
func (ImmediateMDTExtIETable) ID() s00.TableID {
	return func() s00.TableID {
		sealed := s00.TableID{}
		*s00.BridgeTableIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "ImmediateMDT-ExtIEs"}
		return sealed
	}()
}
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
			var zero ImmediateMDTExtIEsValue
			decoded, err := zero.decode(s00.ProtocolIEID(171), raw)
			if err != nil {
				var empty s19.M3Configuration
				return empty, err
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
			var zero ImmediateMDTExtIEsValue
			decoded, err := zero.decode(s00.ProtocolIEID(172), raw)
			if err != nil {
				var empty s19.M4Configuration
				return empty, err
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
			var zero ImmediateMDTExtIEsValue
			decoded, err := zero.decode(s00.ProtocolIEID(173), raw)
			if err != nil {
				var empty s19.M5Configuration
				return empty, err
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
			var zero ImmediateMDTExtIEsValue
			decoded, err := zero.decode(s00.ProtocolIEID(174), raw)
			if err != nil {
				var empty s00.MDTLocationInfo
				return empty, err
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
			var zero ImmediateMDTExtIEsValue
			decoded, err := zero.decode(s00.ProtocolIEID(220), raw)
			if err != nil {
				var empty s19.M6Configuration
				return empty, err
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
			var zero ImmediateMDTExtIEsValue
			decoded, err := zero.decode(s00.ProtocolIEID(221), raw)
			if err != nil {
				var empty s19.M7Configuration
				return empty, err
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
			var zero ImmediateMDTExtIEsValue
			decoded, err := zero.decode(s00.ProtocolIEID(284), raw)
			if err != nil {
				var empty s14.BluetoothMeasurementConfiguration
				return empty, err
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
func (t ImmediateMDTExtIETable) WLANMeasurementConfiguration() ImmediateMDTExtIEsWLANMeasurementConfigurationExtBinding {
	return ImmediateMDTExtIEsWLANMeasurementConfigurationExtBinding{info: t.infoWLANMeasurementConfiguration(), codec: WLANMeasurementConfigurationValueCodec{path: "WLANMeasurementConfiguration",
		decode: func(data []byte, options aper.DecodeState) (WLANMeasurementConfiguration, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty WLANMeasurementConfiguration
				return empty, err
			}
			var zero ImmediateMDTExtIEsValue
			decoded, err := zero.decode(s00.ProtocolIEID(285), raw)
			if err != nil {
				var empty WLANMeasurementConfiguration
				return empty, err
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
			var zero ImmediateMDTExtIEsValue
			decoded, err := zero.decode(s00.ProtocolIEID(345), raw)
			if err != nil {
				var empty s30.SensorMeasurementConfiguration
				return empty, err
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
func (LoggedMDTExtIETable) ID() s00.TableID {
	return func() s00.TableID {
		sealed := s00.TableID{}
		*s00.BridgeTableIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "LoggedMDT-ExtIEs"}
		return sealed
	}()
}
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
			var zero LoggedMDTExtIEsValue
			decoded, err := zero.decode(s00.ProtocolIEID(284), raw)
			if err != nil {
				var empty s14.BluetoothMeasurementConfiguration
				return empty, err
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
func (t LoggedMDTExtIETable) WLANMeasurementConfiguration() LoggedMDTExtIEsWLANMeasurementConfigurationExtBinding {
	return LoggedMDTExtIEsWLANMeasurementConfigurationExtBinding{info: t.infoWLANMeasurementConfiguration(), codec: WLANMeasurementConfigurationValueCodec{path: "WLANMeasurementConfiguration",
		decode: func(data []byte, options aper.DecodeState) (WLANMeasurementConfiguration, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty WLANMeasurementConfiguration
				return empty, err
			}
			var zero LoggedMDTExtIEsValue
			decoded, err := zero.decode(s00.ProtocolIEID(285), raw)
			if err != nil {
				var empty WLANMeasurementConfiguration
				return empty, err
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
			var zero LoggedMDTExtIEsValue
			decoded, err := zero.decode(s00.ProtocolIEID(344), raw)
			if err != nil {
				var empty s19.LoggedMDTTrigger
				return empty, err
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
			var zero LoggedMDTExtIEsValue
			decoded, err := zero.decode(s00.ProtocolIEID(345), raw)
			if err != nil {
				var empty s30.SensorMeasurementConfiguration
				return empty, err
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
func (TraceActivationExtIETable) ID() s00.TableID {
	return func() s00.TableID {
		sealed := s00.TableID{}
		*s00.BridgeTableIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "TraceActivation-ExtIEs"}
		return sealed
	}()
}
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
func (t TraceActivationExtIETable) MDTConfiguration() TraceActivationExtIEsMDTConfigurationExtBinding {
	return TraceActivationExtIEsMDTConfigurationExtBinding{info: t.infoMDTConfiguration(), codec: MDTConfigurationValueCodec{path: "MDTConfiguration",
		decode: func(data []byte, options aper.DecodeState) (MDTConfiguration, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty MDTConfiguration
				return empty, err
			}
			var zero TraceActivationExtIEsValue
			decoded, err := zero.decode(s00.ProtocolIEID(162), raw)
			if err != nil {
				var empty MDTConfiguration
				return empty, err
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
			var zero TraceActivationExtIEsValue
			decoded, err := zero.decode(s00.ProtocolIEID(262), raw)
			if err != nil {
				var empty s35.UEAppLayerMeasConfig
				return empty, err
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
			var zero TraceActivationExtIEsValue
			decoded, err := zero.decode(s00.ProtocolIEID(316), raw)
			if err != nil {
				var empty s00.MDTConfigurationNR
				return empty, err
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
			var zero TraceActivationExtIEsValue
			decoded, err := zero.decode(s00.ProtocolIEID(325), raw)
			if err != nil {
				var empty s00.URIAddress
				return empty, err
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

// BluetoothMeasurementConfigurationCodec binds the complete APER value type.
func BluetoothMeasurementConfigurationCodec() s14.BluetoothMeasurementConfigurationValueCodec {
	return ImmediateMDTExtIEs().BluetoothMeasurementConfiguration().Codec()
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
func BridgeHandoverRequestAdditionalRRMPriorityIndexIEBindingFieldCodec(v *HandoverRequestAdditionalRRMPriorityIndexIEBinding) *s00.AdditionalRRMPriorityIndexValueCodec {
	return &v.codec
}
func BridgeHandoverRequestAdditionalRRMPriorityIndexIEBindingFieldGet(v *HandoverRequestAdditionalRRMPriorityIndexIEBinding) *func(*HandoverRequestIEValue) (*s00.AdditionalRRMPriorityIndex, bool) {
	return &v.get
}
func BridgeHandoverRequestAdditionalRRMPriorityIndexIEBindingFieldInfo(v *HandoverRequestAdditionalRRMPriorityIndexIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeHandoverRequestAdditionalRRMPriorityIndexIEBindingFieldInject(v *HandoverRequestAdditionalRRMPriorityIndexIEBinding) *func(s00.AdditionalRRMPriorityIndex) HandoverRequestIEValue {
	return &v.inject
}
func BridgeHandoverRequestAerialUEsubscriptionInformationIEBindingFieldCodec(v *HandoverRequestAerialUEsubscriptionInformationIEBinding) *s00.AerialUEsubscriptionInformationValueCodec {
	return &v.codec
}
func BridgeHandoverRequestAerialUEsubscriptionInformationIEBindingFieldGet(v *HandoverRequestAerialUEsubscriptionInformationIEBinding) *func(*HandoverRequestIEValue) (*s00.AerialUEsubscriptionInformation, bool) {
	return &v.get
}
func BridgeHandoverRequestAerialUEsubscriptionInformationIEBindingFieldInfo(v *HandoverRequestAerialUEsubscriptionInformationIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeHandoverRequestAerialUEsubscriptionInformationIEBindingFieldInject(v *HandoverRequestAerialUEsubscriptionInformationIEBinding) *func(s00.AerialUEsubscriptionInformation) HandoverRequestIEValue {
	return &v.inject
}
func BridgeHandoverRequestCEModeBRestrictedIEBindingFieldCodec(v *HandoverRequestCEModeBRestrictedIEBinding) *s00.CEModeBRestrictedValueCodec {
	return &v.codec
}
func BridgeHandoverRequestCEModeBRestrictedIEBindingFieldGet(v *HandoverRequestCEModeBRestrictedIEBinding) *func(*HandoverRequestIEValue) (*s00.CEModeBRestricted, bool) {
	return &v.get
}
func BridgeHandoverRequestCEModeBRestrictedIEBindingFieldInfo(v *HandoverRequestCEModeBRestrictedIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeHandoverRequestCEModeBRestrictedIEBindingFieldInject(v *HandoverRequestCEModeBRestrictedIEBinding) *func(s00.CEModeBRestricted) HandoverRequestIEValue {
	return &v.inject
}
func BridgeHandoverRequestCSGIdIEBindingFieldCodec(v *HandoverRequestCSGIdIEBinding) *s00.CSGIdValueCodec {
	return &v.codec
}
func BridgeHandoverRequestCSGIdIEBindingFieldGet(v *HandoverRequestCSGIdIEBinding) *func(*HandoverRequestIEValue) (*s00.CSGId, bool) {
	return &v.get
}
func BridgeHandoverRequestCSGIdIEBindingFieldInfo(v *HandoverRequestCSGIdIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeHandoverRequestCSGIdIEBindingFieldInject(v *HandoverRequestCSGIdIEBinding) *func(s00.CSGId) HandoverRequestIEValue {
	return &v.inject
}
func BridgeHandoverRequestCSGMembershipStatusIEBindingFieldCodec(v *HandoverRequestCSGMembershipStatusIEBinding) *s00.CSGMembershipStatusValueCodec {
	return &v.codec
}
func BridgeHandoverRequestCSGMembershipStatusIEBindingFieldGet(v *HandoverRequestCSGMembershipStatusIEBinding) *func(*HandoverRequestIEValue) (*s00.CSGMembershipStatus, bool) {
	return &v.get
}
func BridgeHandoverRequestCSGMembershipStatusIEBindingFieldInfo(v *HandoverRequestCSGMembershipStatusIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeHandoverRequestCSGMembershipStatusIEBindingFieldInject(v *HandoverRequestCSGMembershipStatusIEBinding) *func(s00.CSGMembershipStatus) HandoverRequestIEValue {
	return &v.inject
}
func BridgeHandoverRequestCauseIEBindingFieldCodec(v *HandoverRequestCauseIEBinding) *s14.CauseValueCodec {
	return &v.codec
}
func BridgeHandoverRequestCauseIEBindingFieldGet(v *HandoverRequestCauseIEBinding) *func(*HandoverRequestIEValue) (*s14.Cause, bool) {
	return &v.get
}
func BridgeHandoverRequestCauseIEBindingFieldInfo(v *HandoverRequestCauseIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeHandoverRequestCauseIEBindingFieldInject(v *HandoverRequestCauseIEBinding) *func(s14.Cause) HandoverRequestIEValue {
	return &v.inject
}
func BridgeHandoverRequestERABToBeSetupListHOReqIEBindingFieldCodec(v *HandoverRequestERABToBeSetupListHOReqIEBinding) *s30.ERABToBeSetupListHOReqValueCodec {
	return &v.codec
}
func BridgeHandoverRequestERABToBeSetupListHOReqIEBindingFieldGet(v *HandoverRequestERABToBeSetupListHOReqIEBinding) *func(*HandoverRequestIEValue) (*s29.ERABToBeSetupListHOReq, bool) {
	return &v.get
}
func BridgeHandoverRequestERABToBeSetupListHOReqIEBindingFieldInfo(v *HandoverRequestERABToBeSetupListHOReqIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeHandoverRequestERABToBeSetupListHOReqIEBindingFieldInject(v *HandoverRequestERABToBeSetupListHOReqIEBinding) *func(s29.ERABToBeSetupListHOReq) HandoverRequestIEValue {
	return &v.inject
}
func BridgeHandoverRequestEnhancedCoverageRestrictedIEBindingFieldCodec(v *HandoverRequestEnhancedCoverageRestrictedIEBinding) *s00.EnhancedCoverageRestrictedValueCodec {
	return &v.codec
}
func BridgeHandoverRequestEnhancedCoverageRestrictedIEBindingFieldGet(v *HandoverRequestEnhancedCoverageRestrictedIEBinding) *func(*HandoverRequestIEValue) (*s00.EnhancedCoverageRestricted, bool) {
	return &v.get
}
func BridgeHandoverRequestEnhancedCoverageRestrictedIEBindingFieldInfo(v *HandoverRequestEnhancedCoverageRestrictedIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeHandoverRequestEnhancedCoverageRestrictedIEBindingFieldInject(v *HandoverRequestEnhancedCoverageRestrictedIEBinding) *func(s00.EnhancedCoverageRestricted) HandoverRequestIEValue {
	return &v.inject
}
func BridgeHandoverRequestExpectedUEBehaviourIEBindingFieldCodec(v *HandoverRequestExpectedUEBehaviourIEBinding) *s18.ExpectedUEBehaviourValueCodec {
	return &v.codec
}
func BridgeHandoverRequestExpectedUEBehaviourIEBindingFieldGet(v *HandoverRequestExpectedUEBehaviourIEBinding) *func(*HandoverRequestIEValue) (*s18.ExpectedUEBehaviour, bool) {
	return &v.get
}
func BridgeHandoverRequestExpectedUEBehaviourIEBindingFieldInfo(v *HandoverRequestExpectedUEBehaviourIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeHandoverRequestExpectedUEBehaviourIEBindingFieldInject(v *HandoverRequestExpectedUEBehaviourIEBinding) *func(s18.ExpectedUEBehaviour) HandoverRequestIEValue {
	return &v.inject
}
func BridgeHandoverRequestGUMMEIIEBindingFieldCodec(v *HandoverRequestGUMMEIIEBinding) *s18.GUMMEIValueCodec {
	return &v.codec
}
func BridgeHandoverRequestGUMMEIIEBindingFieldGet(v *HandoverRequestGUMMEIIEBinding) *func(*HandoverRequestIEValue) (*s18.GUMMEI, bool) {
	return &v.get
}
func BridgeHandoverRequestGUMMEIIEBindingFieldInfo(v *HandoverRequestGUMMEIIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeHandoverRequestGUMMEIIEBindingFieldInject(v *HandoverRequestGUMMEIIEBinding) *func(s18.GUMMEI) HandoverRequestIEValue {
	return &v.inject
}
func BridgeHandoverRequestHandoverRestrictionListIEBindingFieldCodec(v *HandoverRequestHandoverRestrictionListIEBinding) *s42.HandoverRestrictionListValueCodec {
	return &v.codec
}
func BridgeHandoverRequestHandoverRestrictionListIEBindingFieldGet(v *HandoverRequestHandoverRestrictionListIEBinding) *func(*HandoverRequestIEValue) (*s42.HandoverRestrictionList, bool) {
	return &v.get
}
func BridgeHandoverRequestHandoverRestrictionListIEBindingFieldInfo(v *HandoverRequestHandoverRestrictionListIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeHandoverRequestHandoverRestrictionListIEBindingFieldInject(v *HandoverRequestHandoverRestrictionListIEBinding) *func(s42.HandoverRestrictionList) HandoverRequestIEValue {
	return &v.inject
}
func BridgeHandoverRequestHandoverTypeIEBindingFieldCodec(v *HandoverRequestHandoverTypeIEBinding) *s00.HandoverTypeValueCodec {
	return &v.codec
}
func BridgeHandoverRequestHandoverTypeIEBindingFieldGet(v *HandoverRequestHandoverTypeIEBinding) *func(*HandoverRequestIEValue) (*s00.HandoverType, bool) {
	return &v.get
}
func BridgeHandoverRequestHandoverTypeIEBindingFieldInfo(v *HandoverRequestHandoverTypeIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeHandoverRequestHandoverTypeIEBindingFieldInject(v *HandoverRequestHandoverTypeIEBinding) *func(s00.HandoverType) HandoverRequestIEValue {
	return &v.inject
}
func BridgeHandoverRequestIABAuthorizedIEBindingFieldCodec(v *HandoverRequestIABAuthorizedIEBinding) *s00.IABAuthorizedValueCodec {
	return &v.codec
}
func BridgeHandoverRequestIABAuthorizedIEBindingFieldGet(v *HandoverRequestIABAuthorizedIEBinding) *func(*HandoverRequestIEValue) (*s00.IABAuthorized, bool) {
	return &v.get
}
func BridgeHandoverRequestIABAuthorizedIEBindingFieldInfo(v *HandoverRequestIABAuthorizedIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeHandoverRequestIABAuthorizedIEBindingFieldInject(v *HandoverRequestIABAuthorizedIEBinding) *func(s00.IABAuthorized) HandoverRequestIEValue {
	return &v.inject
}
func BridgeHandoverRequestIEContainerAPERValueFieldContext(v *HandoverRequestIEContainerAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeHandoverRequestIEContainerAPERValueFieldReceived(v *HandoverRequestIEContainerAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeHandoverRequestIEContainerAPERValueFieldReplay(v *HandoverRequestIEContainerAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeHandoverRequestIEContainerAPERValueFieldWithoutReplay(v *HandoverRequestIEContainerAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeHandoverRequestIEContainerValueCodecFieldCapture(v *HandoverRequestIEContainerValueCodec) *func(HandoverRequestIEContainer, aper.DecodeState) (HandoverRequestIEContainer, aper.Snapshot) {
	return &v.capture
}
func BridgeHandoverRequestIEContainerValueCodecFieldCompare(v *HandoverRequestIEContainerValueCodec) *func(HandoverRequestIEContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeHandoverRequestIEContainerValueCodecFieldContext(v *HandoverRequestIEContainerValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeHandoverRequestIEContainerValueCodecFieldDecode(v *HandoverRequestIEContainerValueCodec) *func([]byte, aper.DecodeState) (HandoverRequestIEContainer, error) {
	return &v.decode
}
func BridgeHandoverRequestIEContainerValueCodecFieldEncode(v *HandoverRequestIEContainerValueCodec) *func(HandoverRequestIEContainer, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeHandoverRequestIEContainerValueCodecFieldPath(v *HandoverRequestIEContainerValueCodec) *aper.Path {
	return &v.path
}
func BridgeHandoverRequestIEContainerValueCodecMethodEncodeBudgetValue(v HandoverRequestIEContainerValueCodec, a0 HandoverRequestIEContainer, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeHandoverRequestIEContainerValueCodecMethodEncodeChanged(v HandoverRequestIEContainerValueCodec, a0 HandoverRequestIEContainer, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeHandoverRequestIEFieldAPERValueFieldContext(v *HandoverRequestIEFieldAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeHandoverRequestIEFieldAPERValueFieldReceived(v *HandoverRequestIEFieldAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeHandoverRequestIEFieldAPERValueFieldReplay(v *HandoverRequestIEFieldAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeHandoverRequestIEFieldAPERValueFieldWithoutReplay(v *HandoverRequestIEFieldAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeHandoverRequestIEFieldFieldReceived(v *HandoverRequestIEField) *aper.CompletePadding {
	return &v.received
}
func BridgeHandoverRequestIEFieldFieldReplay(v *HandoverRequestIEField) *aper.Snapshot {
	return &v.replay
}
func BridgeHandoverRequestIEFieldFieldStream(v *HandoverRequestIEField) *aper.WireSpan {
	return &v.stream
}
func BridgeHandoverRequestIEFieldFieldWithoutReplay(v *HandoverRequestIEField) *bool {
	return &v.withoutReplay
}
func BridgeHandoverRequestIEFieldMethodMarshalAPERTo(v *HandoverRequestIEField, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeHandoverRequestIEFieldMethodUnmarshalAPERFrom(v *HandoverRequestIEField, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeHandoverRequestIEFieldValueCodecFieldCapture(v *HandoverRequestIEFieldValueCodec) *func(HandoverRequestIEField, aper.DecodeState) (HandoverRequestIEField, aper.Snapshot) {
	return &v.capture
}
func BridgeHandoverRequestIEFieldValueCodecFieldCompare(v *HandoverRequestIEFieldValueCodec) *func(HandoverRequestIEField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeHandoverRequestIEFieldValueCodecFieldContext(v *HandoverRequestIEFieldValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeHandoverRequestIEFieldValueCodecFieldDecode(v *HandoverRequestIEFieldValueCodec) *func([]byte, aper.DecodeState) (HandoverRequestIEField, error) {
	return &v.decode
}
func BridgeHandoverRequestIEFieldValueCodecFieldEncode(v *HandoverRequestIEFieldValueCodec) *func(HandoverRequestIEField, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeHandoverRequestIEFieldValueCodecFieldPath(v *HandoverRequestIEFieldValueCodec) *aper.Path {
	return &v.path
}
func BridgeHandoverRequestIEFieldValueCodecMethodEncodeBudgetValue(v HandoverRequestIEFieldValueCodec, a0 HandoverRequestIEField, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeHandoverRequestIEFieldValueCodecMethodEncodeChanged(v HandoverRequestIEFieldValueCodec, a0 HandoverRequestIEField, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeHandoverRequestIEValueERABIEContainerListAPERValueFieldContext(v *HandoverRequestIEValueERABIEContainerListAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeHandoverRequestIEValueERABIEContainerListAPERValueFieldReceived(v *HandoverRequestIEValueERABIEContainerListAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeHandoverRequestIEValueERABIEContainerListAPERValueFieldReplay(v *HandoverRequestIEValueERABIEContainerListAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeHandoverRequestIEValueERABIEContainerListAPERValueFieldWithoutReplay(v *HandoverRequestIEValueERABIEContainerListAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeHandoverRequestIEValueERABIEContainerListValueCodecFieldCapture(v *HandoverRequestIEValueERABIEContainerListValueCodec) *func(HandoverRequestIEValueERABIEContainerList, aper.DecodeState) (HandoverRequestIEValueERABIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgeHandoverRequestIEValueERABIEContainerListValueCodecFieldCompare(v *HandoverRequestIEValueERABIEContainerListValueCodec) *func(HandoverRequestIEValueERABIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeHandoverRequestIEValueERABIEContainerListValueCodecFieldContext(v *HandoverRequestIEValueERABIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeHandoverRequestIEValueERABIEContainerListValueCodecFieldDecode(v *HandoverRequestIEValueERABIEContainerListValueCodec) *func([]byte, aper.DecodeState) (HandoverRequestIEValueERABIEContainerList, error) {
	return &v.decode
}
func BridgeHandoverRequestIEValueERABIEContainerListValueCodecFieldEncode(v *HandoverRequestIEValueERABIEContainerListValueCodec) *func(HandoverRequestIEValueERABIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeHandoverRequestIEValueERABIEContainerListValueCodecFieldPath(v *HandoverRequestIEValueERABIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgeHandoverRequestIEValueERABIEContainerListValueCodecMethodEncodeBudgetValue(v HandoverRequestIEValueERABIEContainerListValueCodec, a0 HandoverRequestIEValueERABIEContainerList, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeHandoverRequestIEValueERABIEContainerListValueCodecMethodEncodeChanged(v HandoverRequestIEValueERABIEContainerListValueCodec, a0 HandoverRequestIEValueERABIEContainerList, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeHandoverRequestIEValueFieldId(v *HandoverRequestIEValue) *s00.ProtocolIEID { return &v.id }
func BridgeHandoverRequestIEValueFieldIsOpaque(v *HandoverRequestIEValue) *bool       { return &v.isOpaque }
func BridgeHandoverRequestIEValueFieldOpaque(v *HandoverRequestIEValue) *aper.OpaqueOpenType {
	return &v.opaque
}
func BridgeHandoverRequestIEValueFieldReceived(v *HandoverRequestIEValue) *aper.WireSpan {
	return &v.received
}
func BridgeHandoverRequestIEValueFieldReplay(v *HandoverRequestIEValue) *aper.Snapshot {
	return &v.replay
}
func BridgeHandoverRequestIEValueFieldRowAdditionalRRMPriorityIndex(v *HandoverRequestIEValue) **s00.AdditionalRRMPriorityIndex {
	return &v.rowAdditionalRRMPriorityIndex
}
func BridgeHandoverRequestIEValueFieldRowAerialUEsubscriptionInformation(v *HandoverRequestIEValue) **s00.AerialUEsubscriptionInformation {
	return &v.rowAerialUEsubscriptionInformation
}
func BridgeHandoverRequestIEValueFieldRowCEModeBRestricted(v *HandoverRequestIEValue) **s00.CEModeBRestricted {
	return &v.rowCEModeBRestricted
}
func BridgeHandoverRequestIEValueFieldRowCSGId(v *HandoverRequestIEValue) **s00.CSGId {
	return &v.rowCSGId
}
func BridgeHandoverRequestIEValueFieldRowCSGMembershipStatus(v *HandoverRequestIEValue) **s00.CSGMembershipStatus {
	return &v.rowCSGMembershipStatus
}
func BridgeHandoverRequestIEValueFieldRowCause(v *HandoverRequestIEValue) **s14.Cause {
	return &v.rowCause
}
func BridgeHandoverRequestIEValueFieldRowERABToBeSetupListHOReq(v *HandoverRequestIEValue) **s29.ERABToBeSetupListHOReq {
	return &v.rowERABToBeSetupListHOReq
}
func BridgeHandoverRequestIEValueFieldRowEnhancedCoverageRestricted(v *HandoverRequestIEValue) **s00.EnhancedCoverageRestricted {
	return &v.rowEnhancedCoverageRestricted
}
func BridgeHandoverRequestIEValueFieldRowExpectedUEBehaviour(v *HandoverRequestIEValue) **s18.ExpectedUEBehaviour {
	return &v.rowExpectedUEBehaviour
}
func BridgeHandoverRequestIEValueFieldRowGUMMEIID(v *HandoverRequestIEValue) **s18.GUMMEI {
	return &v.rowGUMMEIID
}
func BridgeHandoverRequestIEValueFieldRowHandoverRestrictionList(v *HandoverRequestIEValue) **s42.HandoverRestrictionList {
	return &v.rowHandoverRestrictionList
}
func BridgeHandoverRequestIEValueFieldRowHandoverType(v *HandoverRequestIEValue) **s00.HandoverType {
	return &v.rowHandoverType
}
func BridgeHandoverRequestIEValueFieldRowIABAuthorized(v *HandoverRequestIEValue) **s00.IABAuthorized {
	return &v.rowIABAuthorized
}
func BridgeHandoverRequestIEValueFieldRowMMEUES1APID(v *HandoverRequestIEValue) **s00.MMEUES1APID {
	return &v.rowMMEUES1APID
}
func BridgeHandoverRequestIEValueFieldRowMMEUES1APID2(v *HandoverRequestIEValue) **s00.MMEUES1APID {
	return &v.rowMMEUES1APID2
}
func BridgeHandoverRequestIEValueFieldRowManagementBasedMDTAllowed(v *HandoverRequestIEValue) **s00.ManagementBasedMDTAllowed {
	return &v.rowManagementBasedMDTAllowed
}
func BridgeHandoverRequestIEValueFieldRowManagementBasedMDTPLMNList(v *HandoverRequestIEValue) **s00.MDTPLMNList {
	return &v.rowManagementBasedMDTPLMNList
}
func BridgeHandoverRequestIEValueFieldRowMaskedIMEISV(v *HandoverRequestIEValue) **s00.MaskedIMEISV {
	return &v.rowMaskedIMEISV
}
func BridgeHandoverRequestIEValueFieldRowNASSecurityParameterstoEUTRAN(v *HandoverRequestIEValue) **s00.NASSecurityParameterstoEUTRAN {
	return &v.rowNASSecurityParameterstoEUTRAN
}
func BridgeHandoverRequestIEValueFieldRowNRUESecurityCapabilities(v *HandoverRequestIEValue) **s19.NRUESecurityCapabilities {
	return &v.rowNRUESecurityCapabilities
}
func BridgeHandoverRequestIEValueFieldRowNRUESidelinkAggregateMaximumBitrate(v *HandoverRequestIEValue) **s19.NRUESidelinkAggregateMaximumBitrate {
	return &v.rowNRUESidelinkAggregateMaximumBitrate
}
func BridgeHandoverRequestIEValueFieldRowNRV2XServicesAuthorized(v *HandoverRequestIEValue) **s19.NRV2XServicesAuthorized {
	return &v.rowNRV2XServicesAuthorized
}
func BridgeHandoverRequestIEValueFieldRowPC5QoSParameters(v *HandoverRequestIEValue) **s24.PC5QoSParameters {
	return &v.rowPC5QoSParameters
}
func BridgeHandoverRequestIEValueFieldRowPendingDataIndication(v *HandoverRequestIEValue) **s00.PendingDataIndication {
	return &v.rowPendingDataIndication
}
func BridgeHandoverRequestIEValueFieldRowProSeAuthorized(v *HandoverRequestIEValue) **s20.ProSeAuthorized {
	return &v.rowProSeAuthorized
}
func BridgeHandoverRequestIEValueFieldRowRequestType(v *HandoverRequestIEValue) **s26.RequestType {
	return &v.rowRequestType
}
func BridgeHandoverRequestIEValueFieldRowSRVCCOperationPossible(v *HandoverRequestIEValue) **s00.SRVCCOperationPossible {
	return &v.rowSRVCCOperationPossible
}
func BridgeHandoverRequestIEValueFieldRowSecurityContext(v *HandoverRequestIEValue) **s28.SecurityContext {
	return &v.rowSecurityContext
}
func BridgeHandoverRequestIEValueFieldRowSourceToTargetTransparentContainer(v *HandoverRequestIEValue) **s00.SourceToTargetTransparentContainer {
	return &v.rowSourceToTargetTransparentContainer
}
func BridgeHandoverRequestIEValueFieldRowSubscriptionBasedUEDifferentiationInfo(v *HandoverRequestIEValue) **s30.SubscriptionBasedUEDifferentiationInfo {
	return &v.rowSubscriptionBasedUEDifferentiationInfo
}
func BridgeHandoverRequestIEValueFieldRowTimeRefDistribution(v *HandoverRequestIEValue) **s00.TimeRefDistribution {
	return &v.rowTimeRefDistribution
}
func BridgeHandoverRequestIEValueFieldRowTraceActivation(v *HandoverRequestIEValue) **TraceActivation {
	return &v.rowTraceActivation
}
func BridgeHandoverRequestIEValueFieldRowUERadioCapabilityID(v *HandoverRequestIEValue) **s00.UERadioCapabilityID {
	return &v.rowUERadioCapabilityID
}
func BridgeHandoverRequestIEValueFieldRowUESecurityCapabilities(v *HandoverRequestIEValue) **s37.UESecurityCapabilities {
	return &v.rowUESecurityCapabilities
}
func BridgeHandoverRequestIEValueFieldRowUESidelinkAggregateMaximumBitrate(v *HandoverRequestIEValue) **s37.UESidelinkAggregateMaximumBitrate {
	return &v.rowUESidelinkAggregateMaximumBitrate
}
func BridgeHandoverRequestIEValueFieldRowUEUserPlaneCIoTSupportIndicator(v *HandoverRequestIEValue) **s00.UEUserPlaneCIoTSupportIndicator {
	return &v.rowUEUserPlaneCIoTSupportIndicator
}
func BridgeHandoverRequestIEValueFieldRowUEaggregateMaximumBitrate(v *HandoverRequestIEValue) **s35.UEAggregateMaximumBitrate {
	return &v.rowUEaggregateMaximumBitrate
}
func BridgeHandoverRequestIEValueFieldRowV2XServicesAuthorized(v *HandoverRequestIEValue) **s46.V2XServicesAuthorized {
	return &v.rowV2XServicesAuthorized
}
func BridgeHandoverRequestIEValueMethodCaptureSemantics(v HandoverRequestIEValue, a0 aper.SemanticCapture) HandoverRequestIEValue {
	return v.captureSemantics(a0)
}
func BridgeHandoverRequestIEValueMethodCompareSemantics(v HandoverRequestIEValue, a0 aper.SemanticComparison) aper.SemanticComparison {
	return v.compareSemantics(a0)
}
func BridgeHandoverRequestIEValueMethodDecode(v HandoverRequestIEValue, a0 s00.ProtocolIEID, a1 aper.OpaqueOpenType) (HandoverRequestIEValue, error) {
	return v.decode(a0, a1)
}
func BridgeHandoverRequestIEValueMethodEncode(v HandoverRequestIEValue) ([]byte, error) {
	return v.encode()
}
func BridgeHandoverRequestIEValueMethodEncodeFresh(v HandoverRequestIEValue, a0 bool, a1 *aper.DecodeBudget) ([]byte, error) {
	return v.encodeFresh(a0, a1)
}
func BridgeHandoverRequestIEValueMethodMatchesID(v HandoverRequestIEValue, a0 s00.ProtocolIEID, a1 ...*aper.DecodeBudget) bool {
	return v.matchesID(a0, a1...)
}
func BridgeHandoverRequestIEValueMethodReason(v HandoverRequestIEValue, a0 s00.ProtocolIEID) aper.OpaqueReason {
	return v.reason(a0)
}
func BridgeHandoverRequestIEValueMethodRule(v HandoverRequestIEValue) aper.SourceRule {
	return v.rule()
}
func BridgeHandoverRequestIEValueProtocolErrorIEContainerListAPERValueFieldContext(v *HandoverRequestIEValueProtocolErrorIEContainerListAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeHandoverRequestIEValueProtocolErrorIEContainerListAPERValueFieldReceived(v *HandoverRequestIEValueProtocolErrorIEContainerListAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeHandoverRequestIEValueProtocolErrorIEContainerListAPERValueFieldReplay(v *HandoverRequestIEValueProtocolErrorIEContainerListAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeHandoverRequestIEValueProtocolErrorIEContainerListAPERValueFieldWithoutReplay(v *HandoverRequestIEValueProtocolErrorIEContainerListAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeHandoverRequestIEValueProtocolErrorIEContainerListValueCodecFieldCapture(v *HandoverRequestIEValueProtocolErrorIEContainerListValueCodec) *func(HandoverRequestIEValueProtocolErrorIEContainerList, aper.DecodeState) (HandoverRequestIEValueProtocolErrorIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgeHandoverRequestIEValueProtocolErrorIEContainerListValueCodecFieldCompare(v *HandoverRequestIEValueProtocolErrorIEContainerListValueCodec) *func(HandoverRequestIEValueProtocolErrorIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeHandoverRequestIEValueProtocolErrorIEContainerListValueCodecFieldContext(v *HandoverRequestIEValueProtocolErrorIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeHandoverRequestIEValueProtocolErrorIEContainerListValueCodecFieldDecode(v *HandoverRequestIEValueProtocolErrorIEContainerListValueCodec) *func([]byte, aper.DecodeState) (HandoverRequestIEValueProtocolErrorIEContainerList, error) {
	return &v.decode
}
func BridgeHandoverRequestIEValueProtocolErrorIEContainerListValueCodecFieldEncode(v *HandoverRequestIEValueProtocolErrorIEContainerListValueCodec) *func(HandoverRequestIEValueProtocolErrorIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeHandoverRequestIEValueProtocolErrorIEContainerListValueCodecFieldPath(v *HandoverRequestIEValueProtocolErrorIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgeHandoverRequestIEValueProtocolErrorIEContainerListValueCodecMethodEncodeBudgetValue(v HandoverRequestIEValueProtocolErrorIEContainerListValueCodec, a0 HandoverRequestIEValueProtocolErrorIEContainerList, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeHandoverRequestIEValueProtocolErrorIEContainerListValueCodecMethodEncodeChanged(v HandoverRequestIEValueProtocolErrorIEContainerListValueCodec, a0 HandoverRequestIEValueProtocolErrorIEContainerList, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeHandoverRequestIEValueProtocolIEContainerListAPERValueFieldContext(v *HandoverRequestIEValueProtocolIEContainerListAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeHandoverRequestIEValueProtocolIEContainerListAPERValueFieldReceived(v *HandoverRequestIEValueProtocolIEContainerListAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeHandoverRequestIEValueProtocolIEContainerListAPERValueFieldReplay(v *HandoverRequestIEValueProtocolIEContainerListAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeHandoverRequestIEValueProtocolIEContainerListAPERValueFieldWithoutReplay(v *HandoverRequestIEValueProtocolIEContainerListAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeHandoverRequestIEValueProtocolIEContainerListValueCodecFieldCapture(v *HandoverRequestIEValueProtocolIEContainerListValueCodec) *func(HandoverRequestIEValueProtocolIEContainerList, aper.DecodeState) (HandoverRequestIEValueProtocolIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgeHandoverRequestIEValueProtocolIEContainerListValueCodecFieldCompare(v *HandoverRequestIEValueProtocolIEContainerListValueCodec) *func(HandoverRequestIEValueProtocolIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeHandoverRequestIEValueProtocolIEContainerListValueCodecFieldContext(v *HandoverRequestIEValueProtocolIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeHandoverRequestIEValueProtocolIEContainerListValueCodecFieldDecode(v *HandoverRequestIEValueProtocolIEContainerListValueCodec) *func([]byte, aper.DecodeState) (HandoverRequestIEValueProtocolIEContainerList, error) {
	return &v.decode
}
func BridgeHandoverRequestIEValueProtocolIEContainerListValueCodecFieldEncode(v *HandoverRequestIEValueProtocolIEContainerListValueCodec) *func(HandoverRequestIEValueProtocolIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeHandoverRequestIEValueProtocolIEContainerListValueCodecFieldPath(v *HandoverRequestIEValueProtocolIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgeHandoverRequestIEValueProtocolIEContainerListValueCodecMethodEncodeBudgetValue(v HandoverRequestIEValueProtocolIEContainerListValueCodec, a0 HandoverRequestIEValueProtocolIEContainerList, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeHandoverRequestIEValueProtocolIEContainerListValueCodecMethodEncodeChanged(v HandoverRequestIEValueProtocolIEContainerListValueCodec, a0 HandoverRequestIEValueProtocolIEContainerList, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeHandoverRequestMDTPLMNListIEBindingFieldCodec(v *HandoverRequestMDTPLMNListIEBinding) *s01.MDTPLMNListValueCodec {
	return &v.codec
}
func BridgeHandoverRequestMDTPLMNListIEBindingFieldGet(v *HandoverRequestMDTPLMNListIEBinding) *func(*HandoverRequestIEValue) (*s00.MDTPLMNList, bool) {
	return &v.get
}
func BridgeHandoverRequestMDTPLMNListIEBindingFieldInfo(v *HandoverRequestMDTPLMNListIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeHandoverRequestMDTPLMNListIEBindingFieldInject(v *HandoverRequestMDTPLMNListIEBinding) *func(s00.MDTPLMNList) HandoverRequestIEValue {
	return &v.inject
}
func BridgeHandoverRequestMMEUES1APIDIEBindingFieldCodec(v *HandoverRequestMMEUES1APIDIEBinding) *s01.MMEUES1APIDValueCodec {
	return &v.codec
}
func BridgeHandoverRequestMMEUES1APIDIEBindingFieldGet(v *HandoverRequestMMEUES1APIDIEBinding) *func(*HandoverRequestIEValue) (*s00.MMEUES1APID, bool) {
	return &v.get
}
func BridgeHandoverRequestMMEUES1APIDIEBindingFieldInfo(v *HandoverRequestMMEUES1APIDIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeHandoverRequestMMEUES1APIDIEBindingFieldInject(v *HandoverRequestMMEUES1APIDIEBinding) *func(s00.MMEUES1APID) HandoverRequestIEValue {
	return &v.inject
}
func BridgeHandoverRequestManagementBasedMDTAllowedIEBindingFieldCodec(v *HandoverRequestManagementBasedMDTAllowedIEBinding) *s01.ManagementBasedMDTAllowedValueCodec {
	return &v.codec
}
func BridgeHandoverRequestManagementBasedMDTAllowedIEBindingFieldGet(v *HandoverRequestManagementBasedMDTAllowedIEBinding) *func(*HandoverRequestIEValue) (*s00.ManagementBasedMDTAllowed, bool) {
	return &v.get
}
func BridgeHandoverRequestManagementBasedMDTAllowedIEBindingFieldInfo(v *HandoverRequestManagementBasedMDTAllowedIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeHandoverRequestManagementBasedMDTAllowedIEBindingFieldInject(v *HandoverRequestManagementBasedMDTAllowedIEBinding) *func(s00.ManagementBasedMDTAllowed) HandoverRequestIEValue {
	return &v.inject
}
func BridgeHandoverRequestMaskedIMEISVIEBindingFieldCodec(v *HandoverRequestMaskedIMEISVIEBinding) *s01.MaskedIMEISVValueCodec {
	return &v.codec
}
func BridgeHandoverRequestMaskedIMEISVIEBindingFieldGet(v *HandoverRequestMaskedIMEISVIEBinding) *func(*HandoverRequestIEValue) (*s00.MaskedIMEISV, bool) {
	return &v.get
}
func BridgeHandoverRequestMaskedIMEISVIEBindingFieldInfo(v *HandoverRequestMaskedIMEISVIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeHandoverRequestMaskedIMEISVIEBindingFieldInject(v *HandoverRequestMaskedIMEISVIEBinding) *func(s00.MaskedIMEISV) HandoverRequestIEValue {
	return &v.inject
}
func BridgeHandoverRequestNASSecurityParameterstoEUTRANIEBindingFieldCodec(v *HandoverRequestNASSecurityParameterstoEUTRANIEBinding) *s01.NASSecurityParameterstoEUTRANValueCodec {
	return &v.codec
}
func BridgeHandoverRequestNASSecurityParameterstoEUTRANIEBindingFieldGet(v *HandoverRequestNASSecurityParameterstoEUTRANIEBinding) *func(*HandoverRequestIEValue) (*s00.NASSecurityParameterstoEUTRAN, bool) {
	return &v.get
}
func BridgeHandoverRequestNASSecurityParameterstoEUTRANIEBindingFieldInfo(v *HandoverRequestNASSecurityParameterstoEUTRANIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeHandoverRequestNASSecurityParameterstoEUTRANIEBindingFieldInject(v *HandoverRequestNASSecurityParameterstoEUTRANIEBinding) *func(s00.NASSecurityParameterstoEUTRAN) HandoverRequestIEValue {
	return &v.inject
}
func BridgeHandoverRequestNRUESecurityCapabilitiesIEBindingFieldCodec(v *HandoverRequestNRUESecurityCapabilitiesIEBinding) *s19.NRUESecurityCapabilitiesValueCodec {
	return &v.codec
}
func BridgeHandoverRequestNRUESecurityCapabilitiesIEBindingFieldGet(v *HandoverRequestNRUESecurityCapabilitiesIEBinding) *func(*HandoverRequestIEValue) (*s19.NRUESecurityCapabilities, bool) {
	return &v.get
}
func BridgeHandoverRequestNRUESecurityCapabilitiesIEBindingFieldInfo(v *HandoverRequestNRUESecurityCapabilitiesIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeHandoverRequestNRUESecurityCapabilitiesIEBindingFieldInject(v *HandoverRequestNRUESecurityCapabilitiesIEBinding) *func(s19.NRUESecurityCapabilities) HandoverRequestIEValue {
	return &v.inject
}
func BridgeHandoverRequestNRUESidelinkAggregateMaximumBitrateIEBindingFieldCodec(v *HandoverRequestNRUESidelinkAggregateMaximumBitrateIEBinding) *s19.NRUESidelinkAggregateMaximumBitrateValueCodec {
	return &v.codec
}
func BridgeHandoverRequestNRUESidelinkAggregateMaximumBitrateIEBindingFieldGet(v *HandoverRequestNRUESidelinkAggregateMaximumBitrateIEBinding) *func(*HandoverRequestIEValue) (*s19.NRUESidelinkAggregateMaximumBitrate, bool) {
	return &v.get
}
func BridgeHandoverRequestNRUESidelinkAggregateMaximumBitrateIEBindingFieldInfo(v *HandoverRequestNRUESidelinkAggregateMaximumBitrateIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeHandoverRequestNRUESidelinkAggregateMaximumBitrateIEBindingFieldInject(v *HandoverRequestNRUESidelinkAggregateMaximumBitrateIEBinding) *func(s19.NRUESidelinkAggregateMaximumBitrate) HandoverRequestIEValue {
	return &v.inject
}
func BridgeHandoverRequestNRV2XServicesAuthorizedIEBindingFieldCodec(v *HandoverRequestNRV2XServicesAuthorizedIEBinding) *s19.NRV2XServicesAuthorizedValueCodec {
	return &v.codec
}
func BridgeHandoverRequestNRV2XServicesAuthorizedIEBindingFieldGet(v *HandoverRequestNRV2XServicesAuthorizedIEBinding) *func(*HandoverRequestIEValue) (*s19.NRV2XServicesAuthorized, bool) {
	return &v.get
}
func BridgeHandoverRequestNRV2XServicesAuthorizedIEBindingFieldInfo(v *HandoverRequestNRV2XServicesAuthorizedIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeHandoverRequestNRV2XServicesAuthorizedIEBindingFieldInject(v *HandoverRequestNRV2XServicesAuthorizedIEBinding) *func(s19.NRV2XServicesAuthorized) HandoverRequestIEValue {
	return &v.inject
}
func BridgeHandoverRequestPC5QoSParametersIEBindingFieldCodec(v *HandoverRequestPC5QoSParametersIEBinding) *s24.PC5QoSParametersValueCodec {
	return &v.codec
}
func BridgeHandoverRequestPC5QoSParametersIEBindingFieldGet(v *HandoverRequestPC5QoSParametersIEBinding) *func(*HandoverRequestIEValue) (*s24.PC5QoSParameters, bool) {
	return &v.get
}
func BridgeHandoverRequestPC5QoSParametersIEBindingFieldInfo(v *HandoverRequestPC5QoSParametersIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeHandoverRequestPC5QoSParametersIEBindingFieldInject(v *HandoverRequestPC5QoSParametersIEBinding) *func(s24.PC5QoSParameters) HandoverRequestIEValue {
	return &v.inject
}
func BridgeHandoverRequestPendingDataIndicationIEBindingFieldCodec(v *HandoverRequestPendingDataIndicationIEBinding) *s01.PendingDataIndicationValueCodec {
	return &v.codec
}
func BridgeHandoverRequestPendingDataIndicationIEBindingFieldGet(v *HandoverRequestPendingDataIndicationIEBinding) *func(*HandoverRequestIEValue) (*s00.PendingDataIndication, bool) {
	return &v.get
}
func BridgeHandoverRequestPendingDataIndicationIEBindingFieldInfo(v *HandoverRequestPendingDataIndicationIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeHandoverRequestPendingDataIndicationIEBindingFieldInject(v *HandoverRequestPendingDataIndicationIEBinding) *func(s00.PendingDataIndication) HandoverRequestIEValue {
	return &v.inject
}
func BridgeHandoverRequestProSeAuthorizedIEBindingFieldCodec(v *HandoverRequestProSeAuthorizedIEBinding) *s20.ProSeAuthorizedValueCodec {
	return &v.codec
}
func BridgeHandoverRequestProSeAuthorizedIEBindingFieldGet(v *HandoverRequestProSeAuthorizedIEBinding) *func(*HandoverRequestIEValue) (*s20.ProSeAuthorized, bool) {
	return &v.get
}
func BridgeHandoverRequestProSeAuthorizedIEBindingFieldInfo(v *HandoverRequestProSeAuthorizedIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeHandoverRequestProSeAuthorizedIEBindingFieldInject(v *HandoverRequestProSeAuthorizedIEBinding) *func(s20.ProSeAuthorized) HandoverRequestIEValue {
	return &v.inject
}
func BridgeHandoverRequestRequestTypeIEBindingFieldCodec(v *HandoverRequestRequestTypeIEBinding) *s26.RequestTypeValueCodec {
	return &v.codec
}
func BridgeHandoverRequestRequestTypeIEBindingFieldGet(v *HandoverRequestRequestTypeIEBinding) *func(*HandoverRequestIEValue) (*s26.RequestType, bool) {
	return &v.get
}
func BridgeHandoverRequestRequestTypeIEBindingFieldInfo(v *HandoverRequestRequestTypeIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeHandoverRequestRequestTypeIEBindingFieldInject(v *HandoverRequestRequestTypeIEBinding) *func(s26.RequestType) HandoverRequestIEValue {
	return &v.inject
}
func BridgeHandoverRequestSRVCCOperationPossibleIEBindingFieldCodec(v *HandoverRequestSRVCCOperationPossibleIEBinding) *s01.SRVCCOperationPossibleValueCodec {
	return &v.codec
}
func BridgeHandoverRequestSRVCCOperationPossibleIEBindingFieldGet(v *HandoverRequestSRVCCOperationPossibleIEBinding) *func(*HandoverRequestIEValue) (*s00.SRVCCOperationPossible, bool) {
	return &v.get
}
func BridgeHandoverRequestSRVCCOperationPossibleIEBindingFieldInfo(v *HandoverRequestSRVCCOperationPossibleIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeHandoverRequestSRVCCOperationPossibleIEBindingFieldInject(v *HandoverRequestSRVCCOperationPossibleIEBinding) *func(s00.SRVCCOperationPossible) HandoverRequestIEValue {
	return &v.inject
}
func BridgeHandoverRequestSecurityContextIEBindingFieldCodec(v *HandoverRequestSecurityContextIEBinding) *s28.SecurityContextValueCodec {
	return &v.codec
}
func BridgeHandoverRequestSecurityContextIEBindingFieldGet(v *HandoverRequestSecurityContextIEBinding) *func(*HandoverRequestIEValue) (*s28.SecurityContext, bool) {
	return &v.get
}
func BridgeHandoverRequestSecurityContextIEBindingFieldInfo(v *HandoverRequestSecurityContextIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeHandoverRequestSecurityContextIEBindingFieldInject(v *HandoverRequestSecurityContextIEBinding) *func(s28.SecurityContext) HandoverRequestIEValue {
	return &v.inject
}
func BridgeHandoverRequestSourceToTargetTransparentContainerIEBindingFieldCodec(v *HandoverRequestSourceToTargetTransparentContainerIEBinding) *s01.SourceToTargetTransparentContainerValueCodec {
	return &v.codec
}
func BridgeHandoverRequestSourceToTargetTransparentContainerIEBindingFieldGet(v *HandoverRequestSourceToTargetTransparentContainerIEBinding) *func(*HandoverRequestIEValue) (*s00.SourceToTargetTransparentContainer, bool) {
	return &v.get
}
func BridgeHandoverRequestSourceToTargetTransparentContainerIEBindingFieldInfo(v *HandoverRequestSourceToTargetTransparentContainerIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeHandoverRequestSourceToTargetTransparentContainerIEBindingFieldInject(v *HandoverRequestSourceToTargetTransparentContainerIEBinding) *func(s00.SourceToTargetTransparentContainer) HandoverRequestIEValue {
	return &v.inject
}
func BridgeHandoverRequestSubscriptionBasedUEDifferentiationInfoIEBindingFieldCodec(v *HandoverRequestSubscriptionBasedUEDifferentiationInfoIEBinding) *s31.SubscriptionBasedUEDifferentiationInfoValueCodec {
	return &v.codec
}
func BridgeHandoverRequestSubscriptionBasedUEDifferentiationInfoIEBindingFieldGet(v *HandoverRequestSubscriptionBasedUEDifferentiationInfoIEBinding) *func(*HandoverRequestIEValue) (*s30.SubscriptionBasedUEDifferentiationInfo, bool) {
	return &v.get
}
func BridgeHandoverRequestSubscriptionBasedUEDifferentiationInfoIEBindingFieldInfo(v *HandoverRequestSubscriptionBasedUEDifferentiationInfoIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeHandoverRequestSubscriptionBasedUEDifferentiationInfoIEBindingFieldInject(v *HandoverRequestSubscriptionBasedUEDifferentiationInfoIEBinding) *func(s30.SubscriptionBasedUEDifferentiationInfo) HandoverRequestIEValue {
	return &v.inject
}
func BridgeHandoverRequestTimeRefDistributionIEBindingFieldCodec(v *HandoverRequestTimeRefDistributionIEBinding) *s02.TimeRefDistributionValueCodec {
	return &v.codec
}
func BridgeHandoverRequestTimeRefDistributionIEBindingFieldGet(v *HandoverRequestTimeRefDistributionIEBinding) *func(*HandoverRequestIEValue) (*s00.TimeRefDistribution, bool) {
	return &v.get
}
func BridgeHandoverRequestTimeRefDistributionIEBindingFieldInfo(v *HandoverRequestTimeRefDistributionIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeHandoverRequestTimeRefDistributionIEBindingFieldInject(v *HandoverRequestTimeRefDistributionIEBinding) *func(s00.TimeRefDistribution) HandoverRequestIEValue {
	return &v.inject
}
func BridgeHandoverRequestUEAggregateMaximumBitrateIEBindingFieldCodec(v *HandoverRequestUEAggregateMaximumBitrateIEBinding) *s35.UEAggregateMaximumBitrateValueCodec {
	return &v.codec
}
func BridgeHandoverRequestUEAggregateMaximumBitrateIEBindingFieldGet(v *HandoverRequestUEAggregateMaximumBitrateIEBinding) *func(*HandoverRequestIEValue) (*s35.UEAggregateMaximumBitrate, bool) {
	return &v.get
}
func BridgeHandoverRequestUEAggregateMaximumBitrateIEBindingFieldInfo(v *HandoverRequestUEAggregateMaximumBitrateIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeHandoverRequestUEAggregateMaximumBitrateIEBindingFieldInject(v *HandoverRequestUEAggregateMaximumBitrateIEBinding) *func(s35.UEAggregateMaximumBitrate) HandoverRequestIEValue {
	return &v.inject
}
func BridgeHandoverRequestUERadioCapabilityIDIEBindingFieldCodec(v *HandoverRequestUERadioCapabilityIDIEBinding) *s02.UERadioCapabilityIDValueCodec {
	return &v.codec
}
func BridgeHandoverRequestUERadioCapabilityIDIEBindingFieldGet(v *HandoverRequestUERadioCapabilityIDIEBinding) *func(*HandoverRequestIEValue) (*s00.UERadioCapabilityID, bool) {
	return &v.get
}
func BridgeHandoverRequestUERadioCapabilityIDIEBindingFieldInfo(v *HandoverRequestUERadioCapabilityIDIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeHandoverRequestUERadioCapabilityIDIEBindingFieldInject(v *HandoverRequestUERadioCapabilityIDIEBinding) *func(s00.UERadioCapabilityID) HandoverRequestIEValue {
	return &v.inject
}
func BridgeHandoverRequestUESecurityCapabilitiesIEBindingFieldCodec(v *HandoverRequestUESecurityCapabilitiesIEBinding) *s37.UESecurityCapabilitiesValueCodec {
	return &v.codec
}
func BridgeHandoverRequestUESecurityCapabilitiesIEBindingFieldGet(v *HandoverRequestUESecurityCapabilitiesIEBinding) *func(*HandoverRequestIEValue) (*s37.UESecurityCapabilities, bool) {
	return &v.get
}
func BridgeHandoverRequestUESecurityCapabilitiesIEBindingFieldInfo(v *HandoverRequestUESecurityCapabilitiesIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeHandoverRequestUESecurityCapabilitiesIEBindingFieldInject(v *HandoverRequestUESecurityCapabilitiesIEBinding) *func(s37.UESecurityCapabilities) HandoverRequestIEValue {
	return &v.inject
}
func BridgeHandoverRequestUESidelinkAggregateMaximumBitrateIEBindingFieldCodec(v *HandoverRequestUESidelinkAggregateMaximumBitrateIEBinding) *s37.UESidelinkAggregateMaximumBitrateValueCodec {
	return &v.codec
}
func BridgeHandoverRequestUESidelinkAggregateMaximumBitrateIEBindingFieldGet(v *HandoverRequestUESidelinkAggregateMaximumBitrateIEBinding) *func(*HandoverRequestIEValue) (*s37.UESidelinkAggregateMaximumBitrate, bool) {
	return &v.get
}
func BridgeHandoverRequestUESidelinkAggregateMaximumBitrateIEBindingFieldInfo(v *HandoverRequestUESidelinkAggregateMaximumBitrateIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeHandoverRequestUESidelinkAggregateMaximumBitrateIEBindingFieldInject(v *HandoverRequestUESidelinkAggregateMaximumBitrateIEBinding) *func(s37.UESidelinkAggregateMaximumBitrate) HandoverRequestIEValue {
	return &v.inject
}
func BridgeHandoverRequestUEUserPlaneCIoTSupportIndicatorIEBindingFieldCodec(v *HandoverRequestUEUserPlaneCIoTSupportIndicatorIEBinding) *s02.UEUserPlaneCIoTSupportIndicatorValueCodec {
	return &v.codec
}
func BridgeHandoverRequestUEUserPlaneCIoTSupportIndicatorIEBindingFieldGet(v *HandoverRequestUEUserPlaneCIoTSupportIndicatorIEBinding) *func(*HandoverRequestIEValue) (*s00.UEUserPlaneCIoTSupportIndicator, bool) {
	return &v.get
}
func BridgeHandoverRequestUEUserPlaneCIoTSupportIndicatorIEBindingFieldInfo(v *HandoverRequestUEUserPlaneCIoTSupportIndicatorIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeHandoverRequestUEUserPlaneCIoTSupportIndicatorIEBindingFieldInject(v *HandoverRequestUEUserPlaneCIoTSupportIndicatorIEBinding) *func(s00.UEUserPlaneCIoTSupportIndicator) HandoverRequestIEValue {
	return &v.inject
}
func BridgeHandoverRequestV2XServicesAuthorizedIEBindingFieldCodec(v *HandoverRequestV2XServicesAuthorizedIEBinding) *s46.V2XServicesAuthorizedValueCodec {
	return &v.codec
}
func BridgeHandoverRequestV2XServicesAuthorizedIEBindingFieldGet(v *HandoverRequestV2XServicesAuthorizedIEBinding) *func(*HandoverRequestIEValue) (*s46.V2XServicesAuthorized, bool) {
	return &v.get
}
func BridgeHandoverRequestV2XServicesAuthorizedIEBindingFieldInfo(v *HandoverRequestV2XServicesAuthorizedIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeHandoverRequestV2XServicesAuthorizedIEBindingFieldInject(v *HandoverRequestV2XServicesAuthorizedIEBinding) *func(s46.V2XServicesAuthorized) HandoverRequestIEValue {
	return &v.inject
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
